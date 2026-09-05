from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from app.core.database import get_db
from app.services.response_service import ResponseService

router = APIRouter(prefix="/connectors", tags=["Connectors"])

class TestConnectorRequest(BaseModel):
    connector: str  # windows_firewall, linux_ssh, cloudflare, wazuh, webhook
    action_type: str = "test"
    target: str
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
    Delete / unblock a specific firewall rule from VM iptables or Windows Firewall.
    """
    return await ResponseService.delete_firewall_rule(
        connector=payload.connector,
        target=payload.target,
        parameters=payload.parameters,
        db=db
    )
