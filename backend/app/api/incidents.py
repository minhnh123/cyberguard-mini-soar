import datetime
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import desc, func

from app.core.database import get_db
from app.models.models import Incident, Alert, PendingApproval, ActionLog, PlaybookExecution
from app.schemas.schemas import IncidentResponse
from app.services.ai_service import AIService
from app.services.enrichment_service import EnrichmentService
from app.services.response_service import ResponseService
from app.services.websocket_manager import ws_manager

router = APIRouter(prefix="/incidents", tags=["Incidents"])

@router.get("")
async def list_incidents(
    skip: int = 0,
    limit: int = 50,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    query = select(Incident).options(
        selectinload(Incident.alerts),
        selectinload(Incident.approvals),
        selectinload(Incident.actions)
    ).order_by(desc(Incident.created_at)).offset(skip).limit(limit)

    if status:
        query = query.where(Incident.status == status.lower())
    if severity:
        query = query.where(Incident.severity == severity.lower())

    result = await db.execute(query)
    incidents = result.scalars().all()

    response_list = []
    for inc in incidents:
        response_list.append({
            "id": inc.id,
            "incident_number": inc.incident_number,
            "title": inc.title,
            "severity": inc.severity,
            "status": inc.status,
            "summary": inc.summary,
            "false_positive_score": inc.false_positive_score,
            "confidence_score": inc.confidence_score,
            "mitre_tactics": inc.mitre_tactics or [],
            "mitre_techniques": inc.mitre_techniques or [],
            "ai_analysis": inc.ai_analysis,
            "assigned_to": inc.assigned_to,
            "created_at": inc.created_at,
            "updated_at": inc.updated_at,
            "alert_count": len(inc.alerts),
            "pending_approvals_count": len([a for a in inc.approvals if a.status == "pending"]),
            "executed_actions_count": len(inc.actions)
        })

    return response_list

@router.get("/{incident_id}")
async def get_incident_detail(incident_id: int, db: AsyncSession = Depends(get_db)):
    query = select(Incident).where(Incident.id == incident_id).options(
        selectinload(Incident.alerts),
        selectinload(Incident.approvals),
        selectinload(Incident.actions),
        selectinload(Incident.executions).selectinload(PlaybookExecution.playbook)
    )
    result = await db.execute(query)
    inc = result.scalars().first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    return {
        "id": inc.id,
        "incident_number": inc.incident_number,
        "title": inc.title,
        "severity": inc.severity,
        "status": inc.status,
        "summary": inc.summary,
        "false_positive_score": inc.false_positive_score,
        "confidence_score": inc.confidence_score,
        "mitre_tactics": inc.mitre_tactics or [],
        "mitre_techniques": inc.mitre_techniques or [],
        "ai_analysis": inc.ai_analysis,
        "assigned_to": inc.assigned_to,
        "created_at": inc.created_at,
        "updated_at": inc.updated_at,
        "alerts": [
            {
                "id": a.id,
                "alert_id": a.alert_id,
                "title": a.title,
                "source": a.source,
                "severity": a.severity,
                "source_ip": a.source_ip,
                "destination_ip": a.destination_ip,
                "file_hash": a.file_hash,
                "domain": a.domain,
                "agent_id": a.agent_id,
                "hostname": a.hostname,
                "raw_payload": a.raw_payload,
                "created_at": a.created_at
            }
            for a in inc.alerts
        ],
        "approvals": [
            {
                "id": app.id,
                "action_type": app.action_type,
                "connector": app.connector,
                "target": app.target,
                "parameters": app.parameters,
                "reason": app.reason,
                "risk_level": app.risk_level,
                "status": app.status,
                "analyst_note": app.analyst_note,
                "created_at": app.created_at,
                "resolved_at": app.resolved_at
            }
            for app in inc.approvals
        ],
        "actions": [
            {
                "id": act.id,
                "action_type": act.action_type,
                "connector": act.connector,
                "target": act.target,
                "status": act.status,
                "output_message": act.output_message,
                "executed_by": act.executed_by,
                "created_at": act.created_at
            }
            for act in inc.actions
        ],
        "playbook_executions": [
            {
                "id": ex.id,
                "playbook_id": ex.playbook_id,
                "playbook_name": ex.playbook.name if ex.playbook else "Unnamed Playbook",
                "status": ex.status,
                "current_step": ex.current_step,
                "logs": ex.logs,
                "created_at": ex.created_at,
                "finished_at": ex.finished_at
            }
            for ex in inc.executions
        ]
    }

@router.patch("/{incident_id}")
async def update_incident(
    incident_id: int,
    payload: Dict[str, Any],
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    inc = result.scalars().first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    if "status" in payload:
        inc.status = payload["status"]
    if "severity" in payload:
        inc.severity = payload["severity"]
    if "assigned_to" in payload:
        inc.assigned_to = payload["assigned_to"]
    if "summary" in payload:
        inc.summary = payload["summary"]

    inc.updated_at = datetime.datetime.utcnow()
    await db.commit()
    await db.refresh(inc)
    return inc

@router.post("/{incident_id}/reanalyze")
async def reanalyze_incident_ai(incident_id: int, db: AsyncSession = Depends(get_db)):
    """
    Trigger manual AI re-triage and threat intel enrichment for this incident.
    """
    result = await db.execute(
        select(Incident).where(Incident.id == incident_id).options(selectinload(Incident.alerts))
    )
    inc = result.scalars().first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    first_alert = inc.alerts[0] if inc.alerts else None
    if not first_alert:
        raise HTTPException(status_code=400, detail="No alerts attached to incident")

    # Enrich
    enrichment = {}
    if first_alert.source_ip:
        enrichment["ip_geo"] = await EnrichmentService.lookup_ip_geo(first_alert.source_ip, db=db)
        enrichment["virustotal"] = await EnrichmentService.lookup_virustotal("ip", first_alert.source_ip, db=db)
    if first_alert.file_hash:
        enrichment["virustotal_file"] = await EnrichmentService.lookup_virustotal("hash", first_alert.file_hash, db=db)

    alert_dict = {
        "title": first_alert.title,
        "source": first_alert.source,
        "severity": first_alert.severity,
        "source_ip": first_alert.source_ip,
        "destination_ip": first_alert.destination_ip,
        "file_hash": first_alert.file_hash,
        "domain": first_alert.domain,
        "agent_id": first_alert.agent_id,
        "hostname": first_alert.hostname,
        "description": first_alert.description,
        "raw_payload": first_alert.raw_payload
    }

    ai_res = await AIService.triage_alert(alert_dict, enrichment, db=db)

    inc.severity = ai_res.get("severity", inc.severity)
    inc.summary = ai_res.get("attack_narrative")
    inc.confidence_score = ai_res.get("confidence_score", 1.0)
    inc.false_positive_score = ai_res.get("false_positive_score", 0.0)
    inc.mitre_tactics = ai_res.get("mitre_tactics", [])
    inc.mitre_techniques = ai_res.get("mitre_techniques", [])
    inc.ai_analysis = ai_res
    inc.updated_at = datetime.datetime.utcnow()

    await db.commit()
    await db.refresh(inc)
    return inc

@router.post("/{incident_id}/unblock")
async def unblock_incident_target(
    incident_id: int,
    payload: Dict[str, Any] = {},
    db: AsyncSession = Depends(get_db)
):
    """
    Rollback / Unblock IP or target on firewalls (Linux SSH iptables, Windows Firewall, Cloudflare WAF).
    """
    result = await db.execute(
        select(Incident).where(Incident.id == incident_id).options(
            selectinload(Incident.actions),
            selectinload(Incident.alerts)
        )
    )
    inc = result.scalars().first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    target = payload.get("target")
    connector = payload.get("connector")
    analyst_note = payload.get("analyst_note", "Unblocked by SOC Analyst")

    # Tự động tìm target và connector từ danh sách action log nếu không truyền vào
    if not target:
        for act in inc.actions:
            if act.action_type in ["block_ip", "isolate_wazuh_agent"] and act.status in ["success", "live", "executed"]:
                target = act.target
                connector = connector or act.connector
                break
        if not target and inc.alerts:
            target = inc.alerts[0].source_ip

    if not target:
        raise HTTPException(status_code=400, detail="No target IP found to unblock")

    connector = connector or "linux_ssh"

    # Thực thi unblock qua ResponseService
    exec_res = await ResponseService.execute_action(
        connector=connector,
        action_type="unblock_ip",
        target=target,
        parameters=payload.get("parameters", {}),
        db=db
    )

    exec_status = exec_res.get("status", "success")

    # Ghi lại ActionLog
    action_log = ActionLog(
        incident_id=inc.id,
        action_type="unblock_ip",
        connector=connector,
        target=target,
        status=exec_status,
        output_message=exec_res.get("message") or f"Unblock executed for {target}",
        executed_by=f"Analyst Unblocked ({analyst_note})" if analyst_note else "Analyst Unblocked",
        is_expired=True,
        rollback_status="manual_unblocked"
    )
    db.add(action_log)

    # Đánh dấu các action log và approval liên quan là đã hoàn tác
    for act in inc.actions:
        if act.target == target and act.status in ["success", "live"]:
            act.is_expired = True
            act.rollback_status = "manual_unblocked"
    
    appr_res = await db.execute(
        select(PendingApproval).where(
            PendingApproval.incident_id == inc.id,
            PendingApproval.target == target,
            PendingApproval.status.in_(["executed", "approved"])
        )
    )
    for app_item in appr_res.scalars().all():
        app_item.status = "reverted"
        app_item.is_expired = True
        app_item.analyst_note = f"{app_item.analyst_note or ''} | Đã gỡ chặn thủ công".strip(" |")

    # Chuyển trạng thái sự cố sang closed nếu đang contained
    if inc.status == "contained":
        inc.status = "closed"
    inc.updated_at = datetime.datetime.utcnow()

    await db.commit()
    await db.refresh(inc)

    try:
        await ws_manager.broadcast("TARGET_UNBLOCKED", {
            "incident_id": inc.id,
            "incident_number": inc.incident_number,
            "target": target,
            "connector": connector,
            "status": "unblocked",
            "message": exec_res.get("message")
        })
    except Exception:
        pass

    return {
        "status": "success" if exec_status in ["success", "live"] else "failed",
        "incident_id": inc.id,
        "target": target,
        "connector": connector,
        "execution_result": exec_res
    }

@router.delete("/{incident_id}")
async def delete_incident(incident_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    inc = result.scalars().first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    await db.delete(inc)
    await db.commit()
    return {"status": "deleted", "id": incident_id}
