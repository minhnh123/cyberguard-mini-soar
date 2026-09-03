from typing import Dict, Any
from fastapi import APIRouter, Depends
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import func, desc

from app.core.database import get_db
from app.models.models import Alert, Incident, PendingApproval, ActionLog, Playbook

router = APIRouter(prefix="/stats", tags=["Stats"])

@router.get("/dashboard")
async def get_dashboard_kpis(db: AsyncSession = Depends(get_db)):
    # 1. Total counts
    alerts_total_res = await db.execute(select(func.count(Alert.id)))
    total_alerts = alerts_total_res.scalar() or 0

    incidents_total_res = await db.execute(select(func.count(Incident.id)))
    total_incidents = incidents_total_res.scalar() or 0

    open_incidents_res = await db.execute(select(func.count(Incident.id)).where(Incident.status.in_(["open", "investigating"])))
    open_incidents = open_incidents_res.scalar() or 0

    contained_incidents_res = await db.execute(select(func.count(Incident.id)).where(Incident.status == "contained"))
    contained_incidents = contained_incidents_res.scalar() or 0

    pending_approvals_res = await db.execute(select(func.count(PendingApproval.id)).where(PendingApproval.status == "pending"))
    pending_approvals = pending_approvals_res.scalar() or 0

    executed_actions_res = await db.execute(select(func.count(ActionLog.id)))
    executed_actions = executed_actions_res.scalar() or 0

    active_playbooks_res = await db.execute(select(func.count(Playbook.id)).where(Playbook.is_active == True))
    active_playbooks = active_playbooks_res.scalar() or 0

    # 2. Incidents by Severity
    sev_query = select(Incident.severity, func.count(Incident.id)).group_by(Incident.severity)
    sev_res = await db.execute(sev_query)
    severity_breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for sev, count in sev_res.all():
        if sev:
            severity_breakdown[sev.lower()] = count

    # 3. Top Attacking Source IPs
    ip_query = select(Alert.source_ip, func.count(Alert.id)).where(Alert.source_ip.isnot(None)).group_by(Alert.source_ip).order_by(desc(func.count(Alert.id))).limit(5)
    ip_res = await db.execute(ip_query)
    top_source_ips = [{"ip": row[0], "count": row[1]} for row in ip_res.all()]

    # 4. Recent Incidents
    recent_inc_query = select(Incident).order_by(desc(Incident.created_at)).limit(5)
    recent_inc_res = await db.execute(recent_inc_query)
    recent_incidents = [
        {
            "id": inc.id,
            "incident_number": inc.incident_number,
            "title": inc.title,
            "severity": inc.severity,
            "status": inc.status,
            "confidence_score": inc.confidence_score,
            "mitre_tactics": inc.mitre_tactics or [],
            "created_at": inc.created_at
        }
        for inc in recent_inc_res.scalars().all()
    ]

    return {
        "kpis": {
            "total_alerts": total_alerts,
            "total_incidents": total_incidents,
            "open_incidents": open_incidents,
            "contained_incidents": contained_incidents,
            "pending_approvals": pending_approvals,
            "executed_actions": executed_actions,
            "active_playbooks": active_playbooks,
            "mttr_minutes": 1.8  # Mean Time To Respond (minutes)
        },
        "severity_breakdown": severity_breakdown,
        "top_source_ips": top_source_ips,
        "recent_incidents": recent_incidents
    }
