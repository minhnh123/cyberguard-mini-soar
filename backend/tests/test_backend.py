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
        app_resp = await client.get("/api/v1/approvals?status=pending")
        assert app_resp.status_code == 200
        approvals = app_resp.json()
        assert len(approvals) > 0
        
        # Test approval action (Approve)
        approval_id = approvals[0]["id"]
        decision_resp = await client.post(
            f"/api/v1/approvals/{approval_id}/decision",
            json={"decision": "approve", "analyst_note": "Approved by SOC Lead in automated test"}
        )
        assert decision_resp.status_code == 200, f"Error: {decision_resp.text}"
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

@pytest.mark.asyncio
async def test_react_investigation_trail():
    """
    Test autonomous multi-turn ReAct investigation trail generation during alert triage.
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Trigger ransomware detection scenario
        resp = await client.post("/api/v1/alerts/simulate?scenario=ransomware")
        assert resp.status_code == 200
        alert_data = resp.json()
        assert alert_data["severity"] in ["high", "critical"]
        incident_id = alert_data.get("incident_id")
        assert incident_id is not None

        # 2. Retrieve the exact incident generated for this alert
        inc_resp = await client.get(f"/api/v1/incidents/{incident_id}")
        assert inc_resp.status_code == 200
        latest_inc = inc_resp.json()

        # 3. Assert ReAct investigation trail presence and structure
        ai_analysis = latest_inc.get("ai_analysis") or {}
        trail = ai_analysis.get("investigation_trail", [])
        assert len(trail) >= 2, f"Expected at least 2 ReAct investigation rounds, got {len(trail)}"

        for step in trail:
            assert "round" in step
            assert "thought" in step and len(step["thought"]) > 0
            assert "action" in step and len(step["action"]) > 0
            assert "observation" in step

@pytest.mark.asyncio
async def test_incident_reinvestigate_endpoint():
    """
    Test interactive deep investigation endpoint with analyst query.
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Trigger an alert to ensure an incident with attached alerts exists
        resp = await client.post("/api/v1/alerts/simulate?scenario=ssh_bruteforce")
        assert resp.status_code == 200
        alert_data = resp.json()
        inc_id = alert_data.get("incident_id")
        assert inc_id is not None

        # 2. Trigger reanalyze with custom analyst inquiry
        analyst_question = "Kiểm tra sâu hơn về tiến trình cha và trạng thái tài khoản liên quan"
        reanalyze_resp = await client.post(
            f"/api/v1/incidents/{inc_id}/reanalyze",
            json={"analyst_query": analyst_question}
        )
        assert reanalyze_resp.status_code == 200
        updated_inc = reanalyze_resp.json()

        # 3. Verify that investigation trail includes the analyst inquiry
        trail = updated_inc.get("ai_analysis", {}).get("investigation_trail", [])
        assert len(trail) >= 3, f"Expected at least 3 rounds after analyst query, got {len(trail)}"
        
        # Verify that analyst inquiry is present in the trail
        has_analyst_round = any(step.get("action") == "analyst_inquiry" for step in trail)
        assert has_analyst_round, "Expected an 'analyst_inquiry' action in the investigation trail"

@pytest.mark.asyncio
async def test_ingestion_queue_buffer_high_throughput():
    """
    Test High-Throughput Async Ingestion Queue Buffer under burst webhook traffic.
    Verifies that webhook responds immediately with 202 Accepted and queues alerts safely.
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Check initial queue health
        status_resp = await client.get("/api/v1/alerts/queue-status")
        assert status_resp.status_code == 200
        initial_status = status_resp.json()
        assert "queue_depth" in initial_status
        assert initial_status["is_healthy"] is True

        # 2. Burst enqueue 10 alerts
        for i in range(10):
            payload = {
                "title": f"Burst Test Alert #{i}",
                "source": "Wazuh",
                "severity": "medium",
                "source_ip": f"198.51.100.{10 + i}",
                "description": f"Simulated high-throughput burst alert item #{i}"
            }
            resp = await client.post("/api/v1/alerts/buffered-webhook", json=payload)
            assert resp.status_code == 202
            data = resp.json()
            assert data["status"] == "queued"
            assert "task_id" in data
            assert data["task_id"].startswith("QTSK-")

        # 3. Verify queue depth increased or was processed
        status_after = await client.get("/api/v1/alerts/queue-status")
        assert status_after.status_code == 200
        stats = status_after.json()["stats"]
        assert stats["ingested_count"] >= 10

@pytest.mark.asyncio
async def test_durable_playbook_checkpointing_and_resume():
    """
    Test durable execution state machine: validates per-node checkpointing,
    paused_waiting_approval state persistence, and successful workflow resumption.
    """
    from app.core.database import AsyncSessionLocal, init_db
    from app.models.models import Playbook, PlaybookExecution, Incident, Alert
    from app.services.playbook_engine import PlaybookEngine

    await init_db()
    import uuid
    async with AsyncSessionLocal() as session:
        # Create a test incident and alert
        uid = uuid.uuid4().hex[:6].upper()
        inc = Incident(
            incident_number=f"INC-TEST-DURABLE-{uid}",
            title="Durable Execution Test Incident",
            severity="high",
            status="investigating"
        )
        session.add(inc)
        await session.commit()
        await session.refresh(inc)

        alt = Alert(
            alert_id=f"ALT-DURABLE-{uid}",
            incident_id=inc.id,
            title="Durable Workflow Trigger Alert",
            severity="high",
            source="EDR",
            source_ip="203.0.113.88",
            description="Testing checkpoint persistence"
        )
        session.add(alt)
        await session.commit()
        await session.refresh(alt)

        # Create a playbook with 3 nodes: Enrich -> Approval -> Response Action
        test_pb = Playbook(
            name=f"Durable Checkpointing Test Playbook {uid}",
            category="generic",
            is_active=True,
            graph_data={
                "nodes": [
                    {"id": "node_1", "type": "enrichment", "data": {"label": "Enrich Threat Intel"}},
                    {"id": "node_2", "type": "human_approval", "data": {"label": "Human Approval Gate"}},
                    {"id": "node_3", "type": "response_action", "data": {"label": "Contain Host", "actionType": "block_ip"}}
                ]
            }
        )
        session.add(test_pb)
        await session.commit()
        await session.refresh(test_pb)

        # Initialize execution
        execution = PlaybookExecution(
            playbook_id=test_pb.id,
            incident_id=inc.id,
            status="running",
            current_step="start",
            current_step_index=0,
            context_state={},
            checkpoint_history=[]
        )
        session.add(execution)
        await session.commit()
        await session.refresh(execution)
        exec_id = execution.id

        # Run playbook up to approval node
        await PlaybookEngine.execute_playbook(test_pb, execution, inc, alt, session, start_index=0)

        # Assert that execution is paused at checkpoint
        await session.refresh(execution)
        assert execution.status == "paused_waiting_approval"
        assert execution.current_step_index == 2  # Set to index of next node (node_3)
        assert len(execution.checkpoint_history) >= 2
        assert "enrichment" in execution.context_state

        # Now simulate analyst decision and resume execution
        resumed_exec = await PlaybookEngine.resume_execution(
            execution_id=exec_id,
            approval_decision={"decision": "approve", "analyst": "lead_soc_analyst"},
            db=session
        )
        assert resumed_exec is not None
        assert resumed_exec.status == "completed"
        assert resumed_exec.context_state.get("approval_decision", {}).get("decision") == "approve"

@pytest.mark.asyncio
async def test_server_restart_execution_recovery():
    """
    Test recovery of interrupted executions when the SOAR server restarts unexpectedly.
    """
    from app.core.database import AsyncSessionLocal, init_db
    from app.models.models import Playbook, PlaybookExecution, Incident
    from app.services.playbook_engine import PlaybookEngine
    import uuid

    await init_db()
    async with AsyncSessionLocal() as session:
        uid = uuid.uuid4().hex[:6].upper()
        # Create an execution left in 'running' state (interrupted by server crash)
        inc = Incident(
            incident_number=f"INC-TEST-RECOVERY-{uid}",
            title="Recovery Incident",
            severity="medium",
            status="investigating"
        )
        session.add(inc)

        pb = Playbook(name=f"Recovery Test Playbook {uid}", category="generic", is_active=True)
        session.add(pb)
        await session.commit()
        await session.refresh(inc)
        await session.refresh(pb)

        stuck_exec = PlaybookExecution(
            playbook_id=pb.id,
            incident_id=inc.id,
            status="running",
            current_step="executing",
            current_step_index=1,
            context_state={"step_1": "done"}
        )
        session.add(stuck_exec)
        await session.commit()
        stuck_id = stuck_exec.id

        # Run recovery process
        recovered_count = await PlaybookEngine.recover_interrupted_executions(session)
        assert recovered_count >= 1

        # Verify execution was safely recovered
        res = await session.get(PlaybookExecution, stuck_id)
        assert res.status in ["paused_waiting_approval", "completed"]
        assert "Interrupted by system restart" in res.error_message

@pytest.mark.asyncio
async def test_vault_aes256_gcm_and_redaction():
    """
    Test AES-256-GCM envelope encryption, decryption, tampering detection, and credential redaction.
    """
    from app.core.vault import VaultService

    raw_secret = "UltraSecretPassword_9999!"
    encrypted = VaultService.encrypt(raw_secret)

    # 1. Verify encrypted format
    assert encrypted.startswith("enc:v1:")
    assert VaultService.is_encrypted(encrypted) is True

    # 2. Verify decryption
    decrypted = VaultService.decrypt(encrypted)
    assert decrypted == raw_secret

    # 3. Verify unencrypted string fallback (backward compatibility)
    legacy_string = "legacy_unencrypted_secret"
    assert VaultService.decrypt(legacy_string) == legacy_string

    # 4. Verify tampering detection
    tampered = encrypted[:-4] + "AAAA"
    bad_res = VaultService.decrypt(tampered)
    assert "[VAULT_DECRYPTION_ERROR" in bad_res

    # 5. Verify secret masking
    masked = VaultService.mask_secret(encrypted, visible_suffix=4)
    assert masked.startswith("••••••••")
    assert masked.endswith("999!")

    # 6. Verify sensitive string redaction
    sample_text = (
        "User tried: echo 'KaliP@ssw0rd!' | sudo -S iptables -I INPUT -s 1.2.3.4 -j DROP "
        "with header Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token123 and key: "
        "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA\n-----END OPENSSH PRIVATE KEY-----"
    )
    redacted = VaultService.redact_sensitive_strings(sample_text, extra_secrets=["KaliP@ssw0rd!"])
    assert "[PASSWORD_SUPPRESSED]" in redacted
    assert "[REDACTED_BEARER_TOKEN]" in redacted
    assert "[REDACTED_PRIVATE_KEY]" in redacted
    assert "KaliP@ssw0rd!" not in redacted

@pytest.mark.asyncio
async def test_vault_ssh_ed25519_keypair_lifecycle():
    """
    Test Ed25519 SSH keypair generation, in-vault encrypted persistence, and paramiko loading.
    """
    import io
    import paramiko
    from app.core.vault import VaultService
    from app.core.database import AsyncSessionLocal, init_db
    from app.models.models import SystemSetting
    from sqlalchemy.future import select

    await init_db()
    async with AsyncSessionLocal() as session:
        # Generate or load SOAR keypair
        keypair_info = await VaultService.get_or_create_soar_ssh_keypair(db=session)
        assert keypair_info.get("status") in ["ready", "generated"]
        assert keypair_info.get("public_key", "").startswith("ssh-ed25519 ")
        assert keypair_info.get("has_private_key") is True

        # Verify in DB: private key MUST be encrypted with AES-256-GCM
        res = await session.execute(select(SystemSetting).where(SystemSetting.key == "LINUX_SSH_PRIVATE_KEY"))
        priv_row = res.scalars().first()
        assert priv_row is not None
        assert priv_row.value.startswith("enc:v1:")
        assert priv_row.is_secret is True

        # Verify decryption and Paramiko Ed25519Key compatibility
        plain_priv_pem = VaultService.decrypt(priv_row.value)
        assert "-----BEGIN OPENSSH PRIVATE KEY-----" in plain_priv_pem
        pkey = paramiko.Ed25519Key.from_private_key(io.StringIO(plain_priv_pem))
        assert pkey.get_name() == "ssh-ed25519"
        assert pkey.get_bits() == 256

@pytest.mark.asyncio
async def test_settings_api_vault_encryption_and_actionlog_redaction():
    """
    Test that saving secrets via API encrypts in DB, displays masked bullets on GET,
    and ActionLog automatically sanitizes credentials.
    """
    from app.core.database import AsyncSessionLocal, init_db
    from app.models.models import SystemSetting, ActionLog
    from sqlalchemy.future import select

    await init_db()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        test_secret = "SecretKey_TestVault_2026_XYZ"

        # 1. Save secret setting via API
        resp = await ac.post("/api/v1/settings", json=[
            {
                "key": "TEST_VAULT_SSH_PASS",
                "value": test_secret,
                "category": "connectors",
                "is_secret": True,
                "description": "Test Secret Password in Vault"
            }
        ])
        assert resp.status_code == 200

        # 2. Verify in DB directly: Must be stored encrypted!
        async with AsyncSessionLocal() as session:
            res = await session.execute(select(SystemSetting).where(SystemSetting.key == "TEST_VAULT_SSH_PASS"))
            row = res.scalars().first()
            assert row is not None
            assert row.value.startswith("enc:v1:")
            assert test_secret not in row.value  # Plaintext MUST NOT appear in DB

            # 3. Test ActionLog @validates automatic redaction
            test_log = ActionLog(
                action_type="block_ip",
                connector="linux_ssh",
                target="192.168.1.99",
                status="success",
                output_message=f"Connected using echo '{test_secret}' | sudo -S and Bearer abcdef1234567890"
            )
            session.add(test_log)
            await session.commit()
            await session.refresh(test_log)

            # Verified: Output message redacted
            assert "[PASSWORD_SUPPRESSED]" in test_log.output_message
            assert "[REDACTED_BEARER_TOKEN]" in test_log.output_message
            assert test_secret not in test_log.output_message

        # 4. Check GET /api/v1/settings/ssh-keypair
        kp_resp = await ac.get("/api/v1/settings/ssh-keypair")
        assert kp_resp.status_code == 200
        kp_data = kp_resp.json()
        assert kp_data["status"] == "success"
        assert kp_data["public_key"].startswith("ssh-ed25519 ")

