import datetime
from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from app.core.database import get_db
from app.models.models import PendingApproval, ActionLog
from app.services.response_service import ResponseService
from app.services.websocket_manager import ws_manager

router = APIRouter(prefix="/connectors", tags=["Connectors"])

class TestConnectorRequest(BaseModel):
    connector: str  # windows_firewall, linux_ssh, cloudflare, wazuh, webhook, identity, edr
    action_type: str = "test"
    target: str
    parameters: Dict[str, Any] = {}

class IdentityActionRequest(BaseModel):
    action_type: str = "revoke_user_sessions"  # revoke_user_sessions, disable_user_account, force_password_reset, enable_user_account
    target: str  # user email or ID (e.g. alex.morgan@cyberguard.corp)
    parameters: Dict[str, Any] = {}

class EdrActionRequest(BaseModel):
    action_type: str = "isolate_endpoint"  # isolate_endpoint, reconnect_endpoint, kill_process, quarantine_file
    target: str  # host ID or hostname (e.g. AGENT-004, SRV-FINANCE-01)
    parameters: Dict[str, Any] = {}

class WazuhScanRequest(BaseModel):
    scan_type: str = "syscheck"  # syscheck (FIM), sca, vulnerability

class WazuhActionRequest(BaseModel):
    command: str = "firewall-drop"  # firewall-drop, host-deny, custom
    custom: bool = False

@router.post("/test")
async def test_connector_action(payload: TestConnectorRequest, db: AsyncSession = Depends(get_db)):
    """
    Test a response connector with a simulated or live dry-run action.
    """
    result = await ResponseService.execute_action(
        connector=payload.connector,
        action_type=payload.action_type,
        target=payload.target,
        parameters=payload.parameters,
        db=db
    )
    return result

@router.post("/identity/action")
async def trigger_identity_action(
    payload: IdentityActionRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Trigger an Identity Provider action (revoke sessions, suspend account, force password reset)
    with safety guardrails enforcement and live/enterprise simulation dispatch.
    """
    return await ResponseService.execute_action(
        connector="identity",
        action_type=payload.action_type,
        target=payload.target,
        parameters=payload.parameters,
        db=db
    )

@router.post("/edr/action")
async def trigger_edr_action(
    payload: EdrActionRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Trigger an EDR controller action (isolate endpoint, kill process, quarantine file)
    with safety guardrails enforcement and live/enterprise simulation dispatch.
    """
    return await ResponseService.execute_action(
        connector="edr",
        action_type=payload.action_type,
        target=payload.target,
        parameters=payload.parameters,
        db=db
    )

@router.get("/wazuh/agents")
async def list_wazuh_agents(db: AsyncSession = Depends(get_db)):
    """
    Retrieve live agents registered to the Wazuh Manager VM.
    """
    return await ResponseService.get_wazuh_agents(db=db)

@router.post("/wazuh/agents/{agent_id}/scan")
async def trigger_agent_scan(
    agent_id: str,
    payload: WazuhScanRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Trigger live Syscheck (FIM), SCA, or Vulnerability scan on a Wazuh VM Agent.
    """
    return await ResponseService.trigger_wazuh_scan(agent_id, payload.scan_type, db=db)

@router.post("/wazuh/agents/{agent_id}/action")
async def trigger_agent_action(
    agent_id: str,
    payload: WazuhActionRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Trigger live Active Response (isolate / firewall-drop) on a Wazuh VM Agent.
    """
    return await ResponseService.execute_wazuh_action(
        target=agent_id,
        action_type="active_response",
        parameters={"command": payload.command, "custom": payload.custom},
        db=db
    )

class DeleteFirewallRuleRequest(BaseModel):
    connector: str = "linux_ssh"
    target: str
    parameters: Dict[str, Any] = {}

@router.get("/firewall-rules")
async def get_firewall_rules(
    connector: str = Query("linux_ssh", description="linux_ssh or windows_firewall"),
    db: AsyncSession = Depends(get_db)
):
    """
    Retrieve live firewall rules configured on the target VM (iptables on Linux VM or Windows Firewall).
    """
    return await ResponseService.list_firewall_rules(connector=connector, db=db)

@router.post("/firewall-rules/delete")
async def delete_firewall_rule_endpoint(
    payload: DeleteFirewallRuleRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Delete / unblock a specific firewall rule from VM iptables or Windows Firewall,
    synchronizing pending approvals and broadcasting real-time updates.
    """
    res = await ResponseService.delete_firewall_rule(
        connector=payload.connector,
        target=payload.target,
        parameters=payload.parameters,
        db=db
    )

    if res.get("status") == "failed":
        raise HTTPException(status_code=400, detail=res.get("message", "Lỗi khi gỡ rule tường lửa"))

    # Also synchronize any active executed approval for this target & connector to 'reverted'
    target_clean = payload.target.strip()
    result = await db.execute(
        select(PendingApproval).where(
            PendingApproval.target == target_clean,
            PendingApproval.status.in_(["executed", "approved"])
        )
    )
    approvals = result.scalars().all()
    for appr in approvals:
        appr.status = "reverted"
        existing_note = appr.analyst_note or ""
        appr.analyst_note = f"{existing_note} | Gỡ bỏ trực tiếp từ VM Rules Inspector".strip(" |")
        appr.resolved_at = datetime.datetime.utcnow()

        # Add ActionLog for complete SOC auditability
        action_log = ActionLog(
            incident_id=appr.incident_id,
            action_type="unblock_ip",
            connector=payload.connector,
            target=payload.target,
            status="success",
            output_message=res.get("message") or f"Rule {payload.target} deleted from VM Rules Inspector",
            executed_by="Analyst (VM Rules Inspector)"
        )
        db.add(action_log)

    if approvals:
        await db.commit()

    # Broadcast WebSocket events
    try:
        await ws_manager.broadcast("TARGET_UNBLOCKED", {
            "target": payload.target,
            "connector": payload.connector,
            "status": "reverted",
            "message": res.get("message")
        })
        await ws_manager.broadcast("APPROVAL_RESOLVED", {
            "target": payload.target,
            "connector": payload.connector,
            "decision": "rollback",
            "status": "reverted"
        })
    except Exception:
        pass

    return res
