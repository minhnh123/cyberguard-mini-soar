import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import desc

from app.core.database import get_db
from app.models.models import PendingApproval, Incident, ActionLog, PlaybookExecution
from app.schemas.schemas import PendingApprovalResponse, ApprovalDecisionRequest, ApprovalRollbackRequest
from app.services.response_service import ResponseService
from app.services.websocket_manager import ws_manager

router = APIRouter(prefix="/approvals", tags=["Approvals"])

@router.get("", response_model=List[PendingApprovalResponse])
async def list_approvals(
    status: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    query = select(PendingApproval).order_by(desc(PendingApproval.created_at))
    if status:
        query = query.where(PendingApproval.status == status.lower())
    
    result = await db.execute(query)
    return result.scalars().all()

@router.post("/{approval_id}/decision")
async def handle_approval_decision(
    approval_id: int,
    request: ApprovalDecisionRequest,
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(PendingApproval).where(PendingApproval.id == approval_id))
    approval = result.scalars().first()
    if not approval:
        raise HTTPException(status_code=404, detail="Approval request not found")

    if approval.status not in ["pending"]:
        raise HTTPException(status_code=400, detail=f"Approval is already resolved with status '{approval.status}'")

    approval.analyst_note = request.analyst_note
    approval.resolved_at = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

    # 1. Safety Guardrails MUST be validated FIRST on approve!
    if request.decision.lower() == "approve":
        from app.services.guardrail_service import GuardrailService
        safety_check = await GuardrailService.validate_action_safety(
            target=approval.target,
            action_type=approval.action_type,
            connector=approval.connector,
            db=db
        )
        if not safety_check.get("allowed", True):
            raise HTTPException(
                status_code=400,
                detail=safety_check.get("reason", f"Action on target {approval.target} violated Safety Guardrails.")
            )

    # 2. RBAC & Dual-Custody Evaluation
    from app.services.rbac_service import RBACService
    approver = request.approver or "analyst"
    approver_role = request.approver_role or "tier2_responder"

    rbac_eval = RBACService.evaluate_dual_custody(
        approval=approval,
        approver=approver,
        approver_role=approver_role,
        decision=request.decision
    )

    if not rbac_eval.get("allowed", False):
        raise HTTPException(status_code=403, detail=rbac_eval.get("reason", "Permission denied"))

    if not rbac_eval.get("is_final", False):
        # First signature recorded, awaiting second signature (Dual-Custody)
        await db.commit()
        await db.refresh(approval)
        try:
            await ws_manager.broadcast("APPROVAL_FIRST_SIGNATURE", {
                "approval_id": approval.id,
                "first_approver": approval.first_approver,
                "first_approver_role": approval.first_approver_role,
                "dual_custody_status": approval.dual_custody_status,
                "message": rbac_eval.get("message")
            })
        except Exception:
            pass
        return {
            "status": "awaiting_second_approval",
            "message": rbac_eval.get("message"),
            "approval_id": approval.id,
            "dual_custody_status": approval.dual_custody_status,
            "first_approver": approval.first_approver
        }

    if request.decision.lower() == "reject":
        approval.status = "rejected"
        await db.commit()
        try:
            await ws_manager.broadcast("APPROVAL_RESOLVED", {
                "approval_id": approval.id,
                "incident_id": approval.incident_id,
                "decision": "reject",
                "status": "rejected",
                "target": approval.target,
                "connector": approval.connector
            })
        except Exception:
            pass
        return {
            "status": "rejected",
            "message": f"Action {approval.action_type} on {approval.target} was rejected by {approver}.",
            "approval_id": approval.id
        }

    elif request.decision.lower() == "approve":
        # Calculate TTL & Expiration
        ttl_minutes = request.ttl_minutes if (request.ttl_minutes is not None and request.ttl_minutes > 0) else None
        expires_at = (approval.resolved_at + datetime.timedelta(minutes=ttl_minutes)) if ttl_minutes else None

        approval.status = "approved"
        approval.ttl_minutes = ttl_minutes
        approval.expires_at = expires_at
        approval.is_expired = False
        await db.commit()

        # Execute response connector
        exec_res = await ResponseService.execute_action(
            connector=approval.connector,
            action_type=approval.action_type,
            target=approval.target,
            parameters=approval.parameters or {},
            db=db
        )

        exec_status = exec_res.get("status", "success")
        approval.status = "executed" if exec_status in ["success", "dry_run", "live_success", "live", "info"] else "failed"

        # Record in ActionLog with TTL info
        action_log = ActionLog(
            incident_id=approval.incident_id,
            action_type=approval.action_type,
            connector=approval.connector,
            target=approval.target,
            status=exec_status,
            output_message=exec_res.get("message"),
            executed_by=f"Approved by {approval.first_approver or approver}" + (f" & {approval.second_approver}" if approval.second_approver else ""),
            ttl_minutes=ttl_minutes,
            expires_at=expires_at,
            is_expired=False,
            rollback_status="active" if (ttl_minutes and exec_status in ["success", "live", "dry_run"]) else None
        )
        db.add(action_log)

        # Record Desired Security State for Closed-Loop Reconciliation
        if exec_status in ["success", "live", "dry_run", "live_success"]:
            from app.services.reconciliation_service import ReconciliationService
            try:
                await ReconciliationService.record_desired_state(
                    incident_id=approval.incident_id,
                    action_type=approval.action_type,
                    connector=approval.connector,
                    target=approval.target,
                    expected_status="BLOCKED" if "block" in approval.action_type else "ISOLATED",
                    parameters=approval.parameters or {},
                    auto_heal=True,
                    db=db
                )
            except Exception as rc_err:
                print(f"[Reconciler Warning] Could not record desired state: {rc_err}")

        # If incident status was open/investigating, and this was an isolation or block, update incident
        inc_res = await db.execute(select(Incident).where(Incident.id == approval.incident_id))
        incident = inc_res.scalars().first()
        if incident and incident.status in ["open", "investigating"]:
            incident.status = "contained"

        # Durable Workflow Checkpointing: Resume playbook execution with analyst decision
        if approval.playbook_execution_id:
            try:
                from app.services.playbook_engine import PlaybookEngine
                await PlaybookEngine.resume_execution(
                    execution_id=approval.playbook_execution_id,
                    approval_decision={
                        "decision": "approve",
                        "status": exec_status,
                        "output": exec_res,
                        "analyst_note": approval.analyst_note,
                        "target": approval.target
                    },
                    db=db
                )
            except Exception as pb_ex:
                print(f"[Approval Warning] Could not resume playbook execution: {pb_ex}")

        await db.commit()

        try:
            await ws_manager.broadcast("APPROVAL_RESOLVED", {
                "approval_id": approval.id,
                "incident_id": approval.incident_id,
                "decision": "approve",
                "status": approval.status,
                "target": approval.target,
                "connector": approval.connector,
                "ttl_minutes": ttl_minutes,
                "expires_at": expires_at.isoformat() if expires_at else None,
                "execution_result": exec_res
            })
        except Exception:
            pass

        return {
            "status": approval.status,
            "execution_result": exec_res,
            "ttl_minutes": ttl_minutes,
            "expires_at": expires_at.isoformat() if expires_at else None,
            "approval_id": approval.id
        }

    else:
        raise HTTPException(status_code=400, detail="Invalid decision. Must be 'approve' or 'reject'.")

@router.post("/{approval_id}/rollback")
async def handle_approval_rollback(
    approval_id: int,
    request: Optional[ApprovalRollbackRequest] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Rollback/Undo an already executed approval action (e.g., unblock an IP on Kali Linux VM or Windows Firewall).
    """
    result = await db.execute(select(PendingApproval).where(PendingApproval.id == approval_id))
    approval = result.scalars().first()
    if not approval:
        raise HTTPException(status_code=404, detail="Approval request not found")

    if approval.status == "reverted":
        return {
            "status": "already_reverted",
            "message": "Yêu cầu này đã được hoàn tác trước đó.",
            "approval_id": approval.id
        }

    if approval.status not in ["executed", "approved"]:
        raise HTTPException(
            status_code=400, 
            detail=f"Không thể hoàn tác yêu cầu với trạng thái '{approval.status}'. Chỉ có thể hoàn tác yêu cầu đã thực thi (executed)."
        )

    analyst_note = request.analyst_note if request else "Hoàn tác bởi SOC Analyst"

    # Determine rollback action
    rollback_action = "unblock_ip"
    if approval.connector == "identity" or approval.action_type in ["disable_user_account", "suspend_user", "revoke_user_sessions"]:
        rollback_action = "enable_user_account"
    elif approval.connector in ["edr", "wazuh_ar"] or approval.action_type in ["isolate_wazuh_agent", "isolate", "isolate_endpoint", "isolate_host"]:
        rollback_action = "reconnect_endpoint"

    # Execute rollback via ResponseService
    exec_res = await ResponseService.execute_action(
        connector=approval.connector,
        action_type=rollback_action,
        target=approval.target,
        parameters=approval.parameters or {},
        db=db
    )

    exec_status = exec_res.get("status", "success")

    # Record in ActionLog for complete auditability
    action_log = ActionLog(
        incident_id=approval.incident_id,
        action_type=rollback_action,
        connector=approval.connector,
        target=approval.target,
        status=exec_status,
        output_message=exec_res.get("message") or f"Rollback executed for approval #{approval.id}",
        executed_by=f"Analyst Rollback ({analyst_note})" if analyst_note else "Analyst Rollback"
    )
    db.add(action_log)

    approval.status = "reverted"
    existing_note = approval.analyst_note or ""
    approval.analyst_note = f"{existing_note} | Hoàn tác: {analyst_note}".strip(" |")
    approval.resolved_at = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

    # Deactivate Desired Security State in Reconciliation Engine
    from app.services.reconciliation_service import ReconciliationService
    try:
        await ReconciliationService.deactivate_desired_state(
            target=approval.target,
            connector=approval.connector,
            action_type=approval.action_type,
            db=db
        )
    except Exception as rc_err:
        print(f"[Reconciler Warning] Could not deactivate desired state: {rc_err}")

    await db.commit()

    # Broadcast real-time updates via WebSocket
    try:
        await ws_manager.broadcast("TARGET_UNBLOCKED", {
            "approval_id": approval.id,
            "incident_id": approval.incident_id,
            "target": approval.target,
            "connector": approval.connector,
            "status": "reverted",
            "message": exec_res.get("message")
        })
        await ws_manager.broadcast("APPROVAL_RESOLVED", {
            "approval_id": approval.id,
            "incident_id": approval.incident_id,
            "decision": "rollback",
            "status": "reverted",
            "target": approval.target,
            "connector": approval.connector
        })
    except Exception:
        pass

    return {
        "status": "success",
        "approval_status": "reverted",
        "message": exec_res.get("message") or f"Đã hoàn tác và gỡ chặn {approval.target} trên {approval.connector} thành công.",
        "execution_result": exec_res,
        "approval_id": approval.id
    }
