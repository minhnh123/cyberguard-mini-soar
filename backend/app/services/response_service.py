from typing import Dict, Any, Optional
from app.services.connectors import (
    BaseConnector,
    LinuxSSHConnector,
    WindowsConnector,
    CloudflareConnector,
    WazuhConnector,
    IdentityConnector,
    EDRConnector,
    WebhookConnector,
    sanitize_ip,
)


class ResponseService:
    """
    Unified Response & Containment Orchestration Service.
    Acts as a facade delegating specialized tasks to connector modules in app.services.connectors.
    """
    _edr_mock_status: Dict[str, str] = EDRConnector._edr_mock_status
    _simulated_iptables: Dict[str, Any] = {}

    # Delegate core connector settings and helpers
    get_connector_settings = BaseConnector.get_connector_settings
    get_linux_ssh_config = LinuxSSHConnector.get_linux_ssh_config
    _connect_ssh_client = LinuxSSHConnector.connect_ssh_client
    _execute_sudo_command = LinuxSSHConnector.execute_sudo_command

    # SSH methods
    test_linux_ssh = LinuxSSHConnector.test_linux_ssh
    block_ip_linux_ssh = LinuxSSHConnector.block_ip_linux_ssh
    unblock_ip_linux_ssh = LinuxSSHConnector.unblock_ip_linux_ssh
    delete_rule_linux_ssh_by_num = LinuxSSHConnector.delete_rule_linux_ssh_by_num
    list_firewall_rules_linux_ssh = LinuxSSHConnector.list_firewall_rules_linux_ssh

    # Windows methods
    block_ip_windows = WindowsConnector.block_ip_windows
    unblock_ip_windows = WindowsConnector.unblock_ip_windows
    list_firewall_rules_windows = WindowsConnector.list_firewall_rules_windows

    # Cloudflare methods
    block_ip_cloudflare = CloudflareConnector.block_ip_cloudflare
    unblock_ip_cloudflare = CloudflareConnector.unblock_ip_cloudflare

    # Wazuh methods
    _get_wazuh_auth = WazuhConnector.get_wazuh_auth
    get_wazuh_agents = WazuhConnector.get_wazuh_agents
    trigger_wazuh_scan = WazuhConnector.trigger_wazuh_scan
    execute_wazuh_action = WazuhConnector.execute_wazuh_action

    # Webhook methods
    send_webhook_notification = WebhookConnector.send_webhook_notification

    # Identity & EDR methods
    execute_identity_action = IdentityConnector.execute_identity_action
    execute_edr_action = EDRConnector.execute_edr_action

    @classmethod
    async def list_firewall_rules(cls, connector: str = "linux_ssh", db=None) -> Dict[str, Any]:
        connector = connector.lower()
        if connector == "linux_ssh":
            return await cls.list_firewall_rules_linux_ssh(db=db)
        elif connector == "windows_firewall":
            return await cls.list_firewall_rules_windows()
        else:
            return {
                "status": "success",
                "connector": connector,
                "rules_count": 0,
                "rules": [],
                "raw_output": f"Connector '{connector}' does not support active rule listing."
            }

    @classmethod
    async def delete_firewall_rule(
        cls, connector: str, target: str, parameters: Optional[Dict[str, Any]] = None, db=None
    ) -> Dict[str, Any]:
        connector = connector.lower()
        parameters = parameters or {}
        if connector == "linux_ssh":
            clean_ip = sanitize_ip(target)
            if clean_ip:
                return await cls.unblock_ip_linux_ssh(clean_ip, parameters, db)
            else:
                return await cls.delete_rule_linux_ssh_by_num(target, parameters, db)
        elif connector == "windows_firewall":
            return await cls.unblock_ip_windows(target, parameters)
        else:
            return {"status": "success", "mode": "simulated", "message": f"Deleted rule {target} on {connector}"}

    @classmethod
    async def execute_action(
        cls,
        connector: str,
        action_type: str,
        target: str,
        parameters: Dict[str, Any],
        db=None
    ) -> Dict[str, Any]:
        """
        Main dispatcher to execute containment & response actions safely.
        Validates safety guardrails and tracks desired state in database.
        """
        connector = connector.lower()
        action_lower = action_type.lower()

        # Handle unblock / rollback actions
        if action_lower in ["unblock_ip", "rollback_ip", "unblock", "enable_user_account", "reconnect_endpoint", "reconnect_wazuh_agent"]:
            if connector == "windows_firewall":
                return await cls.unblock_ip_windows(target, parameters)
            elif connector == "linux_ssh":
                return await cls.unblock_ip_linux_ssh(target, parameters, db)
            elif connector == "cloudflare":
                return await cls.unblock_ip_cloudflare(target, parameters, db)
            elif connector == "identity":
                return await cls.execute_identity_action(target, "enable_user_account", parameters, db)
            elif connector in ["edr", "wazuh", "wazuh_ar"]:
                return await cls.execute_edr_action(target, "reconnect_endpoint", parameters, db)
            else:
                return {
                    "status": "success",
                    "mode": "dry_run",
                    "message": f"Simulated unblock execution for connector '{connector}' targeting '{target}'."
                }

        # Check Safety Guardrails for restrictive containment actions
        from app.services.guardrail_service import GuardrailService
        safety_check = await GuardrailService.validate_action_safety(target, action_type, connector, db=db)
        if not safety_check.get("allowed", True):
            return {
                "status": "failed",
                "violation": True,
                "mode": "guardrail_blocked",
                "message": safety_check.get("reason", f"Action on {target} blocked by Safety Guardrails.")
            }

        res = None
        if connector == "windows_firewall":
            res = await cls.block_ip_windows(target, parameters)
        elif connector == "linux_ssh":
            if action_type == "test_connection":
                return await cls.test_linux_ssh(parameters, db)
            res = await cls.block_ip_linux_ssh(target, parameters, db)
        elif connector == "cloudflare":
            res = await cls.block_ip_cloudflare(target, parameters, db)
        elif connector == "identity":
            res = await cls.execute_identity_action(target, action_type, parameters, db)
        elif connector in ["edr", "wazuh_ar"]:
            res = await cls.execute_edr_action(target, action_type, parameters, db)
        elif connector == "wazuh":
            res = await cls.execute_wazuh_action(target, action_type, parameters, db)
        elif connector == "webhook":
            return await cls.send_webhook_notification(target, parameters)
        else:
            return {
                "status": "success",
                "mode": "dry_run",
                "message": f"Simulated execution for connector '{connector}' targeting '{target}'."
            }

        # Automatically record Desired Security State if action is containment
        if res and res.get("status") in ["success", "live", "dry_run", "live_success"] and db:
            if action_lower in ["block_ip", "isolate_endpoint", "isolate_wazuh_agent", "isolate_host"]:
                try:
                    from app.services.reconciliation_service import ReconciliationService
                    await ReconciliationService.record_desired_state(
                        incident_id=parameters.get("incident_id") if isinstance(parameters, dict) else None,
                        action_type=action_type,
                        connector=connector,
                        target=target,
                        expected_status="BLOCKED" if "block" in action_lower else "ISOLATED",
                        parameters=parameters or {},
                        auto_heal=True,
                        db=db
                    )
                except Exception:
                    pass

        return res
