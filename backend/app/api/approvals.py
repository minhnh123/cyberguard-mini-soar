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
    approval.resolved_at = datetime.datetime.utcnow()

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
            "message": f"Action {approval.action_type} on {approval.target} was rejected by Analyst.",
            "approval_id": approval.id
        }

    elif request.decision.lower() == "approve":
        # Check Safety Guardrails before approving
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
            executed_by="Analyst Approved",
            ttl_minutes=ttl_minutes,
            expires_at=expires_at,
            is_expired=False,
            rollback_status="active" if (ttl_minutes and exec_status in ["success", "live", "dry_run"]) else None
        )
        db.add(action_log)

        # If incident status was open/investigating, and this was an isolation or block, update incident
        inc_res = await db.execute(select(Incident).where(Incident.id == approval.incident_id))
        incident = inc_res.scalars().first()
        if incident and incident.status in ["open", "investigating"]:
            incident.status = "contained"

        # If there was an associated playbook execution waiting on this approval, resume it
        if approval.playbook_execution_id:
            pb_exec_res = await db.execute(select(PlaybookExecution).where(PlaybookExecution.id == approval.playbook_execution_id))
            pb_exec = pb_exec_res.scalars().first()
            if pb_exec and pb_exec.status == "waiting_approval":
                pb_exec.status = "completed"
                pb_exec.finished_at = datetime.datetime.utcnow()
                logs = list(pb_exec.logs or [])
                logs.append({
                    "time": datetime.datetime.utcnow().isoformat(),
                    "step": "human_approval",
                    "status": "approved",
                    "output": exec_res
                })
                pb_exec.logs = logs

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
    if approval.action_type in ["isolate_wazuh_agent", "isolate"]:
        rollback_action = "reconnect_wazuh_agent"

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

    # Update approval record status
    approval.status = "reverted"
    existing_note = approval.analyst_note or ""
    approval.analyst_note = f"{existing_note} | Hoàn tác: {analyst_note}".strip(" |")
    approval.resolved_at = datetime.datetime.utcnow()

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
