import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import desc

from app.core.database import get_db
from app.models.models import PendingApproval, Incident, ActionLog, PlaybookExecution
from app.schemas.schemas import PendingApprovalResponse, ApprovalDecisionRequest
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
        approval.status = "approved"
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

        # Record in ActionLog
        action_log = ActionLog(
            incident_id=approval.incident_id,
            action_type=approval.action_type,
            connector=approval.connector,
            target=approval.target,
            status=exec_status,
            output_message=exec_res.get("message"),
            executed_by="Analyst Approved"
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
                "execution_result": exec_res
            })
        except Exception:
            pass

        return {
            "status": approval.status,
            "execution_result": exec_res,
            "approval_id": approval.id
        }

    else:
        raise HTTPException(status_code=400, detail="Invalid decision. Must be 'approve' or 'reject'.")
