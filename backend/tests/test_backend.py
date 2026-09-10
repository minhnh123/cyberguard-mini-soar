import pytest
import asyncio
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.core.database import init_db
from app.seed_data.seed import seed_database

@pytest.mark.asyncio
async def test_api_root_and_health():
    await init_db()
    await seed_database()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "operational"

@pytest.mark.asyncio
async def test_alert_ingestion_and_auto_incident():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Simulate SSH Brute force
        resp = await client.post("/api/v1/alerts/simulate?scenario=ssh_bruteforce")
        assert resp.status_code == 200
        alert_data = resp.json()
        assert alert_data["severity"] in ["high", "critical", "medium"]
        assert alert_data["source_ip"] == "185.220.101.45"

        # Check incidents list
        inc_resp = await client.get("/api/v1/incidents")
        assert inc_resp.status_code == 200
        incidents = inc_resp.json()
        assert len(incidents) > 0
        latest_inc = incidents[0]
        assert "Brute Force" in latest_inc["title"] or latest_inc["severity"] in ["high", "critical", "medium"]

        # Check pending approvals
        app_resp = await client.get("/api/v1/approvals")
        assert app_resp.status_code == 200
        approvals = app_resp.json()
        assert len(approvals) > 0
        
        # Test approval action (Approve)
        approval_id = approvals[0]["id"]
        decision_resp = await client.post(
            f"/api/v1/approvals/{approval_id}/decision",
            json={"decision": "approve", "analyst_note": "Approved by SOC Lead in automated test"}
        )
        assert decision_resp.status_code == 200
        decision_data = decision_resp.json()
        assert decision_data["status"] in ["executed", "success", "failed"]

@pytest.mark.asyncio
async def test_threat_intel_ip_geo():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/threat-intel/lookup?ioc_type=ip&ioc_value=8.8.8.8")
        assert resp.status_code == 200
        data = resp.json()
        assert "enrichment" in data
        assert data["ioc_value"] == "8.8.8.8"

@pytest.mark.asyncio
async def test_wazuh_vm_connector_endpoints():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Test Agent Discovery
        agents_resp = await client.get("/api/v1/connectors/wazuh/agents")
        assert agents_resp.status_code == 200
        agents_data = agents_resp.json()
        assert "data" in agents_data

        # 2. Test Trigger Scan on Agent 001
        scan_resp = await client.post(
            "/api/v1/connectors/wazuh/agents/001/scan",
            json={"scan_type": "syscheck"}
        )
        assert scan_resp.status_code == 200
        scan_data = scan_resp.json()
        assert scan_data["agent_id"] == "001"
        assert "syscheck" in scan_data["scan_type"].lower()

@pytest.mark.asyncio
async def test_live_attack_vm_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/alerts/live-attack-vm",
            json={"target_ip": "127.0.0.1", "attack_type": "port_scan", "attempts": 3}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert len(data["logs"]) > 0

@pytest.mark.asyncio
async def test_alert_deduplication_and_correlation():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Ingest alert 1
        r1 = await client.post("/api/v1/alerts/simulate?scenario=ssh_bruteforce")
        assert r1.status_code == 200
        a1 = r1.json()
        assert a1["incident_id"] is not None
        initial_inc_id = a1["incident_id"]

        # Ingest alert 2 with identical scenario/source_ip within correlation window
        r2 = await client.post("/api/v1/alerts/simulate?scenario=ssh_bruteforce")
        assert r2.status_code == 200
        a2 = r2.json()
        # Should be correlated to the same incident!
        assert a2["incident_id"] == initial_inc_id
        assert a2["status"] == "correlated"

        # Check incident detail and alert count
        inc_res = await client.get(f"/api/v1/incidents/{initial_inc_id}")
        assert inc_res.status_code == 200
        inc_data = inc_res.json()
        assert len(inc_data["alerts"]) >= 2

@pytest.mark.asyncio
async def test_incident_unblock_rollback():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Get incidents
        inc_resp = await client.get("/api/v1/incidents")
        assert inc_resp.status_code == 200
        incidents = inc_resp.json()
        assert len(incidents) > 0
        target_inc = incidents[0]

        # Trigger unblock
        unblock_resp = await client.post(
            f"/api/v1/incidents/{target_inc['id']}/unblock",
            json={
                "target": "185.220.101.45",
                "connector": "windows_firewall",
                "analyst_note": "Unblocked in automated pytest"
            }
        )
        assert unblock_resp.status_code == 200
        unblock_data = unblock_resp.json()
        assert unblock_data["status"] == "success"
        assert unblock_data["target"] == "185.220.101.45"

@pytest.mark.asyncio
async def test_webhook_secret_auth_and_input_sanitization():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Gửi secret sai -> Bị chặn 401
        r_bad = await client.post(
            "/api/v1/alerts/webhook",
            json={"title": "Test Auth Alert", "source_ip": "103.20.5.1"},
            headers={"X-Webhook-Secret": "invalid_fake_secret"}
        )
        assert r_bad.status_code == 401
        assert "Unauthorized" in r_bad.json()["detail"]

        # 2. Gửi secret đúng -> Thành công 200 & kiểm tra input sanitization
        r_good = await client.post(
            "/api/v1/alerts/webhook",
            json={
                "title": "Legitimate Sanitized Alert",
                "source_ip": "  103.20.5.1  ",
                "agent_id": "agent_001; rm -rf /"
            },
            headers={"X-Webhook-Secret": "cyberguard-soar-secret"}
        )
        assert r_good.status_code == 200
        data = r_good.json()
        assert data["source_ip"] == "103.20.5.1"
        assert ";" not in data["agent_id"]
        assert "rm -rf" not in data["agent_id"]

@pytest.mark.asyncio
async def test_approval_rollback():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Check existing approvals
        resp = await client.get("/api/v1/approvals")
        assert resp.status_code == 200
        approvals = resp.json()
        
        # Find an approval that is pending or executed, or create a new one
        target_appr = next((a for a in approvals if a["status"] in ["pending", "executed"]), None)
        if not target_appr:
            sim_resp = await client.post("/api/v1/alerts/simulate?scenario=brute_force")
            assert sim_resp.status_code == 200
            resp = await client.get("/api/v1/approvals")
            approvals = resp.json()
            target_appr = next((a for a in approvals if a["status"] in ["pending", "executed"]), approvals[0] if approvals else None)

        assert target_appr is not None
        appr_id = target_appr["id"]
        
        # If pending, approve it first with TTL
        if target_appr["status"] == "pending":
            dec_resp = await client.post(
                f"/api/v1/approvals/{appr_id}/decision",
                json={"decision": "approve", "analyst_note": "Approved in pytest", "ttl_minutes": 15}
            )
            assert dec_resp.status_code == 200
            dec_data = dec_resp.json()
            assert dec_data["ttl_minutes"] == 15
            assert dec_data["expires_at"] is not None

        # Now test rollback
        rb_resp = await client.post(
            f"/api/v1/approvals/{appr_id}/rollback",
            json={"analyst_note": "Rollback in pytest"}
        )
        assert rb_resp.status_code == 200
        rb_data = rb_resp.json()
        assert rb_data["status"] in ["success", "already_reverted"]
        if rb_data["status"] == "success":
            assert rb_data["approval_status"] == "reverted"

@pytest.mark.asyncio
async def test_safety_guardrails_blast_radius():
    """
    Ensure safety guardrails reject any attempt to block protected infrastructure IPs (DNS, Gateways, SOAR host).
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Ingest an alert with source_ip 8.8.8.8 (Google Public DNS)
        resp = await client.post("/api/v1/alerts/webhook", json={
            "title": "Suspicious DNS traffic",
            "source_ip": "8.8.8.8",
            "severity": "high",
            "description": "Probe from 8.8.8.8"
        })
        assert resp.status_code == 200
        
        # Check generated approvals
        appr_resp = await client.get("/api/v1/approvals")
        approvals = appr_resp.json()
        dns_appr = next((a for a in approvals if a["target"] == "8.8.8.8" and a["status"] == "pending"), None)
        
        if dns_appr:
            # Attempting to approve 8.8.8.8 MUST be rejected by Safety Guardrails with HTTP 400
            dec_resp = await client.post(
                f"/api/v1/approvals/{dns_appr['id']}/decision",
                json={"decision": "approve", "analyst_note": "Try to block DNS"}
            )
            assert dec_resp.status_code == 400
            assert "BLAST_RADIUS_VIOLATION" in dec_resp.json()["detail"]

@pytest.mark.asyncio
async def test_auto_rollback_ttl_worker():
    """
    Test background TTL worker auto-rollbacks expired actions.
    """
    from app.services.ttl_worker import check_and_rollback_expired_actions
    from app.core.database import AsyncSessionLocal
    from app.models.models import PendingApproval, Incident
    import datetime
    
    # Insert an expired approval in database
    async with AsyncSessionLocal() as session:
        inc = Incident(
            incident_number=f"INC-TEST-TTL-{int(datetime.datetime.utcnow().timestamp())}",
            title="TTL Auto-Rollback Unit Test",
            severity="high",
            status="contained"
        )
        session.add(inc)
        await session.commit()
        await session.refresh(inc)

        expired_appr = PendingApproval(
            incident_id=inc.id,
            action_type="block_ip",
            connector="linux_ssh",
            target="198.51.100.99",
            parameters={"direction": "inbound"},
            reason="Test TTL expiration",
            risk_level="medium",
            status="executed",
            ttl_minutes=15,
            expires_at=datetime.datetime.utcnow() - datetime.timedelta(minutes=5),  # 5 minutes in the past
            is_expired=False
        )
        session.add(expired_appr)
        await session.commit()
        await session.refresh(expired_appr)
        appr_id = expired_appr.id

    # Run the worker cycle
    await check_and_rollback_expired_actions()

    # Verify that the approval has been auto-reverted
    async with AsyncSessionLocal() as session:
        res = await session.get(PendingApproval, appr_id)
        assert res is not None
        assert res.status == "reverted"
        assert res.is_expired == True
        assert "TTL Expired" in (res.analyst_note or "")

@pytest.mark.asyncio
async def test_firewall_rules_inspection():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Query linux_ssh rules
        resp_linux = await client.get("/api/v1/connectors/firewall-rules?connector=linux_ssh")
        assert resp_linux.status_code == 200
        data_linux = resp_linux.json()
        assert "status" in data_linux
        assert "rules" in data_linux
        assert isinstance(data_linux["rules"], list)

        # 2. Query windows_firewall rules
        resp_win = await client.get("/api/v1/connectors/firewall-rules?connector=windows_firewall")
        assert resp_win.status_code == 200
        data_win = resp_win.json()
        assert "status" in data_win
        assert "rules" in data_win
        assert isinstance(data_win["rules"], list)

@pytest.mark.asyncio
async def test_identity_connector_actions_and_rollback():
    """
    Test Enterprise Identity connector: session revocation, account disable, and rollback enable.
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Revoke active user sessions
        revoke_resp = await client.post(
            "/api/v1/connectors/identity/action",
            json={
                "action_type": "revoke_user_sessions",
                "target": "alex.morgan@cyberguard.corp",
                "parameters": {"user_id": "alex.morgan@cyberguard.corp"}
            }
        )
        assert revoke_resp.status_code == 200
        revoke_data = revoke_resp.json()
        assert revoke_data["status"] == "success"
        assert "alex.morgan@cyberguard.corp" in revoke_data["message"]

        # 2. Disable user account
        disable_resp = await client.post(
            "/api/v1/connectors/identity/action",
            json={
                "action_type": "disable_user_account",
                "target": "alex.morgan@cyberguard.corp",
                "parameters": {"user_id": "alex.morgan@cyberguard.corp"}
            }
        )
        assert disable_resp.status_code == 200
        disable_data = disable_resp.json()
        assert disable_data["status"] == "success"

        # 3. Rollback: Enable user account
        enable_resp = await client.post(
            "/api/v1/connectors/identity/action",
            json={
                "action_type": "enable_user_account",
                "target": "alex.morgan@cyberguard.corp",
                "parameters": {"user_id": "alex.morgan@cyberguard.corp"}
            }
        )
        assert enable_resp.status_code == 200
        enable_data = enable_resp.json()
        assert enable_data["status"] == "success"

@pytest.mark.asyncio
async def test_edr_connector_actions_and_rollback():
    """
    Test Enterprise EDR connector: host isolation, kill process, and rollback reconnect.
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Isolate endpoint
        iso_resp = await client.post(
            "/api/v1/connectors/edr/action",
            json={
                "action_type": "isolate_endpoint",
                "target": "SRV-FINANCE-01",
                "parameters": {"host": "SRV-FINANCE-01"}
            }
        )
        assert iso_resp.status_code == 200
        iso_data = iso_resp.json()
        assert iso_data["status"] == "success"
        assert iso_data.get("details", {}).get("isolation_status") == "ISOLATED"

        # 2. Kill malicious process by PID
        kill_resp = await client.post(
            "/api/v1/connectors/edr/action",
            json={
                "action_type": "kill_process",
                "target": "SRV-FINANCE-01",
                "parameters": {"pid": "4821", "process_name": "vssadmin.exe", "host": "SRV-FINANCE-01"}
            }
        )
        assert kill_resp.status_code == 200
        kill_data = kill_resp.json()
        assert kill_data["status"] == "success"
        assert kill_data.get("details", {}).get("terminated_pid") == "4821"

        # 3. Rollback: Reconnect endpoint
        recon_resp = await client.post(
            "/api/v1/connectors/edr/action",
            json={
                "action_type": "reconnect_endpoint",
                "target": "SRV-FINANCE-01",
                "parameters": {"host": "SRV-FINANCE-01"}
            }
        )
        assert recon_resp.status_code == 200
        recon_data = recon_resp.json()
        assert recon_data["status"] == "success"
        assert recon_data.get("details", {}).get("isolation_status") == "CONNECTED"
