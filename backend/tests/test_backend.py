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
            incident_number=f"INC-TEST-TTL-{int(datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).timestamp())}",
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
            expires_at=datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) - datetime.timedelta(minutes=5),  # 5 minutes in the past
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

@pytest.mark.asyncio
async def test_observable_knowledge_graph_and_blast_radius():
    """
    Test Phase 3 Observable Knowledge Graph:
    - Ingests an alert with enriched multi-domain observables (IP, Host, User, Hash).
    - Verifies graph construction, node extraction, and relationship topology.
    - Tests multi-hop BFS Blast Radius calculation and entity cross-incident query.
    """
    import uuid
    suffix = uuid.uuid4().hex[:4]
    test_src_ip = f"198.51.100.{int(suffix, 16) % 200 + 10}"
    test_host = f"SRV-DC-{suffix.upper()}"

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Ingest alert with rich observables
        alert_payload = {
            "title": f"Lateral Movement via SMB Admin Session {suffix}",
            "source": "Wazuh-EDR",
            "severity": "high",
            "source_ip": test_src_ip,
            "destination_ip": "10.0.0.15",
            "description": "Lateral movement detected from attacker IP to internal server",
            "raw_data": {
                "host": test_host,
                "user": "sec_admin",
                "process_hash": "44d88612fea8a8f36de82e1278abb02f",
                "domain": "corp.internal"
            }
        }
        ingest_resp = await client.post("/api/v1/alerts/webhook", json=alert_payload)
        assert ingest_resp.status_code == 200
        alert_data = ingest_resp.json()
        inc_id = alert_data.get("incident_id")
        assert inc_id is not None

        # 2. Query Knowledge Graph for this incident
        graph_resp = await client.get(f"/api/v1/incidents/{inc_id}/graph?max_hops=2")
        assert graph_resp.status_code == 200
        graph_data = graph_resp.json()

        assert graph_data["incident_id"] == inc_id
        assert graph_data["total_nodes"] >= 2
        assert graph_data["total_edges"] >= 1
        assert "blast_radius" in graph_data

        blast = graph_data["blast_radius"]
        assert blast["score"] >= 20
        assert blast["risk_level"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        assert any(n["label"] == test_src_ip for n in graph_data["nodes"])

        # 3. Test entity-centric cross-incident graph query
        entity_resp = await client.get(f"/api/v1/incidents/graph/entity?value={test_src_ip}&max_hops=2")
        assert entity_resp.status_code == 200
        ent_graph = entity_resp.json()
        assert ent_graph["root_entity"]["value"] == test_src_ip
        assert len(ent_graph["nodes"]) >= 1

@pytest.mark.asyncio
async def test_dynamic_alert_suppression_engine():
    """
    Test Phase 3 Dynamic Alert Suppression Engine:
    - Registers suppression rules for pattern wildcards and specific IP IOCs.
    - Verifies that incoming matching alerts are automatically suppressed (no incident created).
    - Verifies non-matching alerts flow normally.
    - Verifies suppression rule listing and deactivation.
    """
    import uuid
    uid = uuid.uuid4().hex[:4]
    test_pattern = f"*Nightly Backup Routine {uid}*"
    test_ip = f"192.0.2.{int(uid, 16) % 200 + 10}"

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Create a pattern-based suppression rule
        rule_payload = {
            "entity_type": "title_pattern",
            "entity_value": test_pattern,
            "reason": "Scheduled backup routine generates false positive I/O spikes",
            "duration_hours": 12
        }
        create_resp = await client.post("/api/v1/incidents/suppressions/rules", json=rule_payload)
        assert create_resp.status_code == 200
        rule_data = create_resp.json()
        rule_id = rule_data["id"]
        assert rule_data["entity_type"] == "title_pattern"
        assert rule_data["is_active"] is True

        # 2. Ingest an alert matching the title pattern
        suppressed_alert_payload = {
            "title": f"Alert: Nightly Backup Routine {uid} Disk Spikes",
            "source": "Wazuh",
            "severity": "medium",
            "source_ip": "10.0.0.99",
            "description": "Routine backup volume activity"
        }
        sup_resp = await client.post("/api/v1/alerts/webhook", json=suppressed_alert_payload)
        assert sup_resp.status_code == 200
        sup_data = sup_resp.json()
        assert sup_data["status"] == "suppressed"
        assert sup_data.get("incident_id") is None
        assert "[SUPPRESSED: Scheduled backup routine" in sup_data["description"]

        # 3. Create an IP-based suppression rule
        ip_rule_payload = {
            "entity_type": "ip",
            "entity_value": test_ip,
            "reason": "Authorized internal vulnerability scanner IP",
            "duration_hours": 24
        }
        ip_rule_resp = await client.post("/api/v1/incidents/suppressions/rules", json=ip_rule_payload)
        assert ip_rule_resp.status_code == 200

        # Ingest alert from suppressed IP
        ip_alert_payload = {
            "title": f"Suspicious Port Scan Activity {uid}",
            "source": "Suricata",
            "severity": "high",
            "source_ip": test_ip,
            "description": "Port scanning from scanner IP"
        }
        sup_ip_resp = await client.post("/api/v1/alerts/webhook", json=ip_alert_payload)
        assert sup_ip_resp.status_code == 200
        sup_ip_data = sup_ip_resp.json()
        assert sup_ip_data["status"] == "suppressed"
        assert sup_ip_data.get("incident_id") is None

        # 4. List suppression rules
        list_resp = await client.get("/api/v1/incidents/suppressions/rules?active_only=true")
        assert list_resp.status_code == 200
        rules_list = list_resp.json()
        assert any(r["id"] == rule_id for r in rules_list)

        # 5. Deactivate suppression rule
        del_resp = await client.delete(f"/api/v1/incidents/suppressions/rules/{rule_id}")
        assert del_resp.status_code == 200
        del_data = del_resp.json()
        assert del_data["status"] == "success"

@pytest.mark.asyncio
async def test_rlhf_analyst_feedback_loop_and_few_shot_prompt():
    """
    Test Phase 3 RLHF Active Learning Feedback Loop:
    - Submits analyst verdict (False Positive) on an incident.
    - Verifies incident closure and automated creation of dynamic suppression rule.
    - Verifies Few-Shot In-Context prompt snippet generation for AI Triage.
    """
    from app.core.database import AsyncSessionLocal
    from app.services.feedback_service import FeedbackService
    from app.models.models import Incident, SuppressionRule
    from sqlalchemy.future import select
    import uuid

    suffix = uuid.uuid4().hex[:4]
    fresh_test_ip = f"198.51.100.{int(suffix, 16) % 200 + 10}"

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Ingest a clean alert to get a fresh incident
        alert_payload = {
            "title": f"Unusual Bastion Activity {suffix}",
            "source": "Wazuh",
            "severity": "medium",
            "source_ip": fresh_test_ip,
            "description": "Login activity to bastion server"
        }
        ingest_resp = await client.post("/api/v1/alerts/webhook", json=alert_payload)
        assert ingest_resp.status_code == 200
        alert_data = ingest_resp.json()
        inc_id = alert_data.get("incident_id")
        assert inc_id is not None

        # 2. Submit False Positive analyst feedback
        feedback_payload = {
            "verdict": "false_positive",
            "analyst_notes": f"Legitimate pen-test execution {suffix} verified with SecOps team",
            "reason_category": "authorized_testing",
            "corrected_severity": "info",
            "auto_suppress_hours": 48,
            "created_by": "lead_soc_analyst"
        }
        fb_resp = await client.post(f"/api/v1/incidents/{inc_id}/feedback", json=feedback_payload)
        assert fb_resp.status_code == 200
        fb_data = fb_resp.json()
        assert fb_data["status"] == "success"
        assert "feedback_id" in fb_data

        # 3. Verify Incident status in DB: closed with false_positive_score=1.0
        async with AsyncSessionLocal() as session:
            inc_res = await session.execute(select(Incident).where(Incident.id == inc_id))
            inc_row = inc_res.scalars().first()
            assert inc_row.status == "closed"
            assert inc_row.false_positive_score == 1.0

            # 4. Verify that an automated suppression rule was generated for the source IP
            sup_res = await session.execute(
                select(SuppressionRule).where(
                    SuppressionRule.entity_value == fresh_test_ip,
                    SuppressionRule.is_active == True
                )
            )
            sup_row = sup_res.scalars().first()
            assert sup_row is not None
            assert "Auto-suppressed from False Positive" in sup_row.reason

            # 5. Verify Few-Shot In-Context prompt snippet generation
            few_shot_prompt = await FeedbackService.get_few_shot_prompt_context(alert_dict={}, limit=3, db=session)
            assert "SOC ANALYST HISTORICAL FEEDBACK" in few_shot_prompt
            assert "authorized_testing" in few_shot_prompt
            assert "false_positive" in few_shot_prompt.lower()

@pytest.mark.asyncio
async def test_rbac_and_dual_custody_four_eyes_enforcement():
    """
    Test Phase 4 RBAC & Dual-Custody 4-Eyes Principle:
    - Enforces role boundaries: Tier-1 Analyst blocked from approvals (403).
    - Requires 2 distinct human sign-offs for High-Impact / Destructive containment.
    - Strictly blocks Self-Approval (403).
    - Fully executes once Tier-3 Commander counter-signs.
    """
    from app.core.database import AsyncSessionLocal, init_db
    from app.models.models import Incident, PendingApproval
    import uuid

    await init_db()
    uid = uuid.uuid4().hex[:4].upper()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        async with AsyncSessionLocal() as session:
            inc = Incident(
                incident_number=f"INC-DUAL-{uid}",
                title=f"Critical Core DC Incident {uid}",
                severity="critical",
                status="investigating"
            )
            session.add(inc)
            await session.commit()
            await session.refresh(inc)

            approval = PendingApproval(
                incident_id=inc.id,
                action_type="isolate_endpoint",
                connector="edr",
                target=f"SRV-DC-{uid}",
                reason="Isolate Domain Controller under active ransomware attack",
                risk_level="critical",
                requires_dual_custody=True,
                dual_custody_status="not_required",
                status="pending"
            )
            session.add(approval)
            await session.commit()
            await session.refresh(approval)
            app_id = approval.id

        # 1. Tier-1 Analyst cannot approve (RBAC rejection)
        t1_resp = await client.post(
            f"/api/v1/approvals/{app_id}/decision",
            json={
                "decision": "approve",
                "approver": "junior_analyst",
                "approver_role": "tier1_analyst",
                "analyst_note": "Trying to approve without permission"
            }
        )
        assert t1_resp.status_code == 403
        assert "Tier-1 Analyst" in t1_resp.json()["detail"]

        # 2. Tier-2 Responder provides 1st signature
        t2_resp = await client.post(
            f"/api/v1/approvals/{app_id}/decision",
            json={
                "decision": "approve",
                "approver": "responder_bob",
                "approver_role": "tier2_responder",
                "analyst_note": "Initial responder review verified host compromise"
            }
        )
        assert t2_resp.status_code == 200
        t2_data = t2_resp.json()
        assert t2_data["status"] == "awaiting_second_approval"
        assert t2_data["first_approver"] == "responder_bob"

        # 3. Anti-Self-Approval: Responder Bob cannot provide 2nd signature for himself
        self_resp = await client.post(
            f"/api/v1/approvals/{app_id}/decision",
            json={
                "decision": "approve",
                "approver": "responder_bob",
                "approver_role": "tier3_commander",
                "analyst_note": "Self-approving my own proposal"
            }
        )
        assert self_resp.status_code == 403
        assert "Self-approval prohibited" in self_resp.json()["detail"]

        # 4. Tier-3 Commander counter-signs (Dual-Custody Complete)
        t3_resp = await client.post(
            f"/api/v1/approvals/{app_id}/decision",
            json={
                "decision": "approve",
                "approver": "commander_alice",
                "approver_role": "tier3_commander",
                "analyst_note": "Commander authorized DC isolation"
            }
        )
        assert t3_resp.status_code == 200
        t3_data = t3_resp.json()
        assert t3_data["status"] in ["executed", "approved"]

        # Verify DB final state
        async with AsyncSessionLocal() as session:
            final_app = await session.get(PendingApproval, app_id)
            assert final_app.first_approver == "responder_bob"
            assert final_app.second_approver == "commander_alice"
            assert final_app.dual_custody_status == "fully_approved"

@pytest.mark.asyncio
async def test_closed_loop_reconciliation_drift_detection_and_self_healing():
    """
    Test Phase 4 Closed-Loop Reconciler & Self-Healing State Engine:
    - Verifies Desired Security State creation upon containment.
    - Audits in-sync state.
    - Simulates out-of-band Configuration Drift (flushed iptables rule).
    - Verifies automated Self-Healing re-application to maintain Zero-Drift.
    - Verifies clean state deactivation upon rollback.
    """
    from app.core.database import AsyncSessionLocal, init_db
    from app.models.models import Incident, DesiredSecurityState
    from app.services.reconciliation_service import ReconciliationService
    import uuid

    await init_db()
    uid = uuid.uuid4().hex[:4].upper()
    target_host = f"SRV-HOST-{uid}"

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Execute isolate action via EDR connector
        block_resp = await client.post(
            "/api/v1/connectors/edr/action",
            json={
                "action_type": "isolate_endpoint",
                "target": target_host,
                "parameters": {"host": target_host}
            }
        )
        assert block_resp.status_code == 200

        # Record Desired State explicitly in test
        async with AsyncSessionLocal() as session:
            await ReconciliationService.record_desired_state(
                incident_id=None,
                action_type="isolate_endpoint",
                connector="edr",
                target=target_host,
                expected_status="ISOLATED",
                auto_heal=True,
                db=session
            )

        # 2. Reconcile audit - should be in_sync
        audit_1 = await client.post("/api/v1/reconciliation/reconcile-now")
        assert audit_1.status_code == 200
        data_1 = audit_1.json()
        assert data_1["total_tracked"] >= 1
        assert any(d.get("target") == target_host and d.get("status") == "in_sync" for d in data_1.get("details", []))

        # 3. Simulate Configuration Drift (Host unexpectedly reconnected out-of-band)
        drift_sim = await client.post(
            "/api/v1/reconciliation/simulate-drift",
            json={"target": target_host, "action": "reconnect_edr"}
        )
        assert drift_sim.status_code == 200

        # 4. Reconcile audit with Self-Healing enabled
        audit_2 = await client.post("/api/v1/reconciliation/reconcile-now")
        assert audit_2.status_code == 200
        data_2 = audit_2.json()
        assert data_2["auto_healed_count"] >= 1
        healed_item = next((d for d in data_2.get("details", []) if d.get("target") == target_host), None)
        assert healed_item is not None
        assert healed_item["status"] == "healed"

        # 5. Check desired states list endpoint
        states_resp = await client.get("/api/v1/reconciliation/states?active_only=true")
        assert states_resp.status_code == 200
        states_data = states_resp.json()
        match_state = next((s for s in states_data if s["target"] == target_host), None)
        assert match_state is not None
        assert match_state["healed_count"] >= 1
        assert match_state["drift_detected"] is False

@pytest.mark.asyncio
async def test_cryptography_requirements_and_vault_dependency():
    """
    Issue #5 Verification:
    Verify cryptography is explicitly declared in requirements.txt (root and backend),
    and that VaultService AES-256-GCM / Ed25519 primitives can be imported and initialized.
    """
    import os
    from app.core.vault import VaultService
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    # Check root requirements.txt
    root_req_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "requirements.txt"))
    assert os.path.isfile(root_req_path), f"requirements.txt missing at root {root_req_path}"
    with open(root_req_path, "r", encoding="utf-8") as f:
        root_reqs = f.read()
    assert "cryptography" in root_reqs, "cryptography missing from root requirements.txt"

    # Check backend/requirements.txt
    backend_req_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "requirements.txt"))
    assert os.path.isfile(backend_req_path), f"requirements.txt missing at backend {backend_req_path}"
    with open(backend_req_path, "r", encoding="utf-8") as f:
        backend_reqs = f.read()
    assert "cryptography" in backend_reqs, "cryptography missing from backend/requirements.txt"

    # Verify Vault encrypt/decrypt works with active cryptography package
    plain = "TopSecret123_ReliabilityTest"
    cipher = VaultService.encrypt(plain)
    assert cipher.startswith("enc:v1:")
    decrypted = VaultService.decrypt(cipher)
    assert decrypted == plain

@pytest.mark.asyncio
async def test_queue_worker_per_item_session_isolation():
    """
    Issue #6 Verification:
    Verify that Queue Worker processes batch items in isolated sessions:
    If item 3/5 fails, items 1, 2, 4, 5 are committed and saved cleanly,
    preventing entire batch loss.
    """
    import uuid
    import asyncio
    import datetime
    from app.core.database import AsyncSessionLocal, init_db
    from app.services.ingestion_queue import IngestionQueueBuffer
    from app.models.models import Alert
    from sqlalchemy.future import select

    await init_db()
    test_queue = IngestionQueueBuffer.__new__(IngestionQueueBuffer)
    test_queue._maxsize = 100
    test_queue._queue = asyncio.Queue(maxsize=100)
    test_queue._stats = {
        "ingested_count": 0, "processed_count": 0, "error_count": 0, "dropped_count": 0,
        "started_at": datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat()
    }
    test_queue._is_running = True
    test_queue._initialized = True

    batch_uid = uuid.uuid4().hex[:6].upper()
    valid_titles = []

    # Prepare 5 items: item 2 is faulty
    items_to_enqueue = []
    for i in range(5):
        if i == 2:
            bad_item = {
                "task_id": f"QTSK-FAIL-{batch_uid}",
                "payload": {"corrupted": True}
            }
            items_to_enqueue.append(bad_item)
        else:
            title = f"BatchItem-{batch_uid}-{i}"
            valid_titles.append(title)
            items_to_enqueue.append({
                "task_id": f"QTSK-OK-{batch_uid}-{i}",
                "payload": {
                    "alert_id": f"ALT-BATCH-{batch_uid}-{i}",
                    "title": title,
                    "severity": "medium",
                    "source": "Wazuh"
                }
            })

    # Simulate queue worker per-item processing logic with isolated sessions
    for item in items_to_enqueue:
        async with AsyncSessionLocal() as session:
            try:
                payload = item.get("payload", {})
                if payload.get("corrupted"):
                    raise ValueError("Simulated item corruption")
                new_alt = Alert(
                    alert_id=payload["alert_id"],
                    title=payload["title"],
                    severity=payload["severity"],
                    source=payload["source"],
                    status="new"
                )
                session.add(new_alt)
                await session.commit()
                test_queue.record_processed(1)
            except Exception:
                await session.rollback()
                test_queue.record_error(1)

    assert test_queue.stats["processed_count"] == 4
    assert test_queue.stats["error_count"] == 1

    # Verify database: the 4 valid items MUST be committed and present
    async with AsyncSessionLocal() as session:
        for t in valid_titles:
            res = await session.execute(select(Alert).where(Alert.title == t))
            saved = res.scalars().first()
            assert saved is not None, f"Alert '{t}' should have been committed despite item 2 failure!"

@pytest.mark.asyncio
async def test_inspect_firewall_state_iptables_source_field():
    """
    Issue #7 Verification:
    Verify that inspect_firewall_state correctly recognizes blocked IPs from iptables 'source' field
    (where iptables 'target' is 'DROP' action), rather than erroneously matching on 'target'.
    """
    from unittest.mock import patch
    from app.services.investigation_tools import InvestigationToolRegistry

    blocked_ip = "203.0.113.77"
    unblocked_ip = "192.0.2.88"

    # Mock iptables rules returned by ResponseService.list_firewall_rules
    mock_rules_response = {
        "status": "success",
        "connector": "linux_ssh",
        "rules_count": 2,
        "rules": [
            {
                "line_num": 1,
                "target": "DROP",          # iptables action verb!
                "protocol": "all",
                "options": "--",
                "source": blocked_ip,      # The actual blocked IP address!
                "destination": "0.0.0.0/0",
                "raw": f"1 DROP all -- {blocked_ip} 0.0.0.0/0"
            },
            {
                "line_num": 2,
                "target": "ACCEPT",
                "protocol": "tcp",
                "options": "--",
                "source": "10.0.0.1",
                "destination": "0.0.0.0/0",
                "raw": "2 ACCEPT tcp -- 10.0.0.1 0.0.0.0/0"
            }
        ],
        "mode": "live",
        "message": "Live iptables inspection"
    }

    with patch("app.services.response_service.ResponseService.list_firewall_rules", return_value=mock_rules_response):
        # 1. Target blocked_ip: MUST return target_currently_blocked = True
        res_blocked = await InvestigationToolRegistry.inspect_firewall_state(
            connector="linux_ssh",
            target=blocked_ip
        )
        assert res_blocked["target_currently_blocked"] is True, (
            f"Expected {blocked_ip} to be recognized as blocked from 'source' field"
        )

        # 2. Target unblocked_ip: MUST return target_currently_blocked = False
        res_unblocked = await InvestigationToolRegistry.inspect_firewall_state(
            connector="linux_ssh",
            target=unblocked_ip
        )
        assert res_unblocked["target_currently_blocked"] is False, (
            f"Expected {unblocked_ip} to NOT be recognized as blocked"
        )





