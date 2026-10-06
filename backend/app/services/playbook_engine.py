import json
import datetime
from typing import Dict, Any, List, Optional
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from sqlalchemy.orm.attributes import flag_modified
from app.models.models import (
    Playbook, PlaybookExecution, Incident, Alert, PendingApproval, ActionLog
)
from app.services.enrichment_service import EnrichmentService
from app.services.ai_service import AIService
from app.services.response_service import ResponseService

class PlaybookEngine:
    @classmethod
    async def match_and_trigger(cls, alert: Alert, incident: Incident, db) -> List[PlaybookExecution]:
        """
        Find all active playbooks that match the alert/incident triggers and execute them.
        """
        result = await db.execute(select(Playbook).where(Playbook.is_active == True))
        playbooks = result.scalars().all()

        triggered_executions = []
        for pb in playbooks:
            if cls._check_trigger_match(pb, alert, incident):
                execution = PlaybookExecution(
                    playbook_id=pb.id,
                    incident_id=incident.id,
                    status="running",
                    current_step="start",
                    current_step_index=0,
                    current_node_id=None,
                    context_state={},
                    checkpoint_history=[],
                    is_resumable=True,
                    logs=[{
                        "time": datetime.datetime.utcnow().isoformat(),
                        "step": "start",
                        "message": f"Playbook '{pb.name}' triggered for Incident {incident.incident_number}"
                    }]
                )
                db.add(execution)
                await db.commit()
                await db.refresh(execution)

                # Run the execution asynchronously with checkpointing
                await cls.execute_playbook(pb, execution, incident, alert, db, start_index=0)
                triggered_executions.append(execution)

        return triggered_executions

    @classmethod
    def _check_trigger_match(cls, playbook: Playbook, alert: Alert, incident: Incident) -> bool:
        conds = playbook.trigger_conditions or {}
        if not conds:
            return True

        # Check severity match
        if "severity" in conds:
            allowed_sevs = [s.lower() for s in conds["severity"]]
            alert_sev = alert.severity.lower()
            inc_sev = incident.severity.lower()
            if alert_sev not in allowed_sevs and inc_sev not in allowed_sevs:
                if alert_sev in ["medium", "high", "critical"] and any(s in allowed_sevs for s in ["high", "critical"]):
                    pass
                else:
                    return False

        # Check source match
        if "sources" in conds:
            allowed_sources = [s.lower() for s in conds["sources"]]
            if alert.source.lower() not in allowed_sources and "webhook" not in allowed_sources:
                return False

        # Check category match
        if playbook.category and playbook.category != "generic":
            alert_text = f"{alert.title} {alert.description or ''}".lower()
            if playbook.category == "brute_force" and not any(k in alert_text for k in ["brute", "ssh", "rdp", "login", "password"]):
                return False
            if playbook.category == "malware" and not any(k in alert_text for k in ["malware", "virus", "trojan", "ransomware", "hash", "shadow"]):
                return False
            if playbook.category == "web_attack" and not any(k in alert_text for k in ["web", "sql", "injection", "url", "http", "traversal", "xss", "rce"]):
                return False

        return True

    @classmethod
    async def execute_playbook(
        cls,
        playbook: Playbook,
        execution: PlaybookExecution,
        incident: Incident,
        alert: Alert,
        db,
        start_index: int = 0,
        initial_context: Optional[Dict[str, Any]] = None
    ):
        """
        Durable workflow execution with per-node checkpointing.
        Saves context state and execution progression into the database after every step.
        """
        graph = playbook.graph_data or {}
        nodes = graph.get("nodes", [])

        logs = list(execution.logs or [])
        checkpoint_history = list(execution.checkpoint_history or [])

        # Recover context from initial_context or execution.context_state or bootstrap new
        context_data = initial_context or dict(execution.context_state or {})
        if not context_data.get("alert"):
            context_data["alert"] = {
                "id": alert.id,
                "title": alert.title,
                "source": alert.source,
                "severity": alert.severity,
                "source_ip": alert.source_ip,
                "destination_ip": alert.destination_ip,
                "file_hash": alert.file_hash,
                "agent_id": alert.agent_id,
                "hostname": alert.hostname,
                "raw_payload": alert.raw_payload
            }
        if "enrichment" not in context_data:
            context_data["enrichment"] = {}
        if "ai_triage" not in context_data:
            context_data["ai_triage"] = {}

        # Default fallback linear graph if empty
        if not nodes:
            nodes = [
                {"id": "node_enrich", "type": "enrichment", "data": {"label": "Enrich Threat Intel"}},
                {"id": "node_ai", "type": "ai_triage", "data": {"label": "AI Incident Triage & MITRE Mapping"}},
                {"id": "node_approval", "type": "human_approval", "data": {"label": "Human-in-the-loop Approval Gateway"}},
            ]

        for idx in range(start_index, len(nodes)):
            node = nodes[idx]
            node_id = node.get("id")
            node_type = node.get("type") or node.get("data", {}).get("nodeType", "action")
            node_data = node.get("data", {})
            step_name = node_data.get("label", node_type)

            execution.current_step = step_name
            execution.current_step_index = idx
            execution.current_node_id = node_id

            logs.append({
                "time": datetime.datetime.utcnow().isoformat(),
                "node_id": node_id,
                "step_index": idx,
                "step": step_name,
                "type": node_type,
                "status": "executing"
            })

            try:
                # 1. Enrichment Node
                if node_type in ["enrichment", "threat_intel"]:
                    enrich_results = dict(context_data.get("enrichment", {}))
                    if alert.source_ip:
                        geo_info = await EnrichmentService.lookup_ip_geo(alert.source_ip, db=db)
                        enrich_results["ip_geo"] = geo_info
                        vt_ip = await EnrichmentService.lookup_virustotal("ip", alert.source_ip, db=db)
                        enrich_results["virustotal"] = vt_ip
                    if alert.file_hash:
                        vt_hash = await EnrichmentService.lookup_virustotal("hash", alert.file_hash, db=db)
                        enrich_results["virustotal_file"] = vt_hash

                    context_data["enrichment"] = enrich_results
                    logs.append({
                        "time": datetime.datetime.utcnow().isoformat(),
                        "node_id": node_id,
                        "step": step_name,
                        "status": "success",
                        "output": enrich_results
                    })

                # 2. AI Triage Node
                elif node_type in ["ai_triage", "ai_reasoning"]:
                    ai_result = await AIService.triage_alert(context_data["alert"], context_data.get("enrichment", {}), db=db)
                    context_data["ai_triage"] = ai_result

                    # Update Incident fields with AI findings
                    incident.severity = ai_result.get("severity", incident.severity)
                    incident.summary = ai_result.get("attack_narrative")
                    incident.confidence_score = ai_result.get("confidence_score", 1.0)
                    incident.false_positive_score = ai_result.get("false_positive_score", 0.0)
                    incident.mitre_tactics = ai_result.get("mitre_tactics", [])
                    incident.mitre_techniques = ai_result.get("mitre_techniques", [])
                    incident.ai_analysis = ai_result

                    logs.append({
                        "time": datetime.datetime.utcnow().isoformat(),
                        "node_id": node_id,
                        "step": step_name,
                        "status": "success",
                        "output": {
                            "severity": ai_result.get("severity"),
                            "confidence": ai_result.get("confidence_score"),
                            "recommended_actions_count": len(ai_result.get("recommended_actions", []))
                        }
                    })

                # 3. Human-in-the-Loop Approval Node (Durable Pause Point)
                elif node_type in ["human_approval", "approval"]:
                    recommended = context_data.get("ai_triage", {}).get("recommended_actions", [])
                    created_approvals = []

                    if not recommended and alert.source_ip:
                        recommended = [{
                            "action_type": "block_ip",
                            "connector": "windows_firewall",
                            "target": alert.source_ip,
                            "parameters": {"direction": "inbound", "action": "block"},
                            "reason": f"Block source IP {alert.source_ip} to contain potential hostile activity.",
                            "risk_level": "low"
                        }]

                    from app.services.guardrail_service import GuardrailService
                    for rec in recommended:
                        target = rec.get("target", alert.source_ip or "N/A")
                        action_type = rec.get("action_type", "block_ip")
                        connector = rec.get("connector", "windows_firewall")
                        reason = rec.get("reason", "Automated Playbook Proposal")
                        risk_level = rec.get("risk_level", "medium")

                        guardrail_check = await GuardrailService.validate_action_safety(target, action_type, connector, db=db)
                        if not guardrail_check.get("allowed", True):
                            reason = f"[GUARDRAIL WARNING: Protected Critical IP] {reason} - {guardrail_check.get('reason')}"
                            risk_level = "critical"

                        approval = PendingApproval(
                            incident_id=incident.id,
                            playbook_execution_id=execution.id,
                            action_type=action_type,
                            connector=connector,
                            target=target,
                            parameters=rec.get("parameters", {}),
                            reason=reason,
                            risk_level=risk_level,
                            ttl_minutes=60,
                            status="pending"
                        )
                        db.add(approval)
                        created_approvals.append(approval)

                    # Durable State Checkpointing before pause
                    execution.status = "paused_waiting_approval"
                    execution.current_step_index = idx + 1  # Resume next step after approval
                    execution.context_state = context_data

                    checkpoint_history.append({
                        "node_id": node_id,
                        "step": step_name,
                        "time": datetime.datetime.utcnow().isoformat(),
                        "status": "paused_waiting_approval"
                    })
                    execution.checkpoint_history = list(checkpoint_history)
                    execution.context_state = context_data

                    logs.append({
                        "time": datetime.datetime.utcnow().isoformat(),
                        "node_id": node_id,
                        "step": step_name,
                        "status": "paused_waiting_approval",
                        "message": f"Durable checkpoint saved. Generated {len(created_approvals)} pending response action(s) for analyst review."
                    })

                    execution.logs = list(logs)
                    flag_modified(execution, "checkpoint_history")
                    flag_modified(execution, "context_state")
                    flag_modified(execution, "logs")
                    await db.commit()

                    for app_item in created_approvals:
                        try:
                            from app.services.websocket_manager import ws_manager
                            await ws_manager.broadcast("PENDING_APPROVAL", {
                                "approval_id": app_item.id,
                                "incident_id": incident.id,
                                "incident_number": incident.incident_number,
                                "action_type": app_item.action_type,
                                "target": app_item.target,
                                "connector": app_item.connector,
                                "risk_level": app_item.risk_level,
                                "reason": app_item.reason
                            })
                        except Exception:
                            pass

                    return  # Workflow paused safely in durable state

                # 4. Direct Response Action Node
                elif node_type in ["response_action", "action"]:
                    action_type = node_data.get("actionType") or "block_ip"
                    connector = node_data.get("connector") or "windows_firewall"
                    target = node_data.get("target") or alert.source_ip

                    exec_res = await ResponseService.execute_action(
                        connector=connector,
                        action_type=action_type,
                        target=target,
                        parameters=node_data.get("parameters", {}),
                        db=db
                    )

                    action_log = ActionLog(
                        incident_id=incident.id,
                        action_type=action_type,
                        connector=connector,
                        target=target,
                        status=exec_res.get("status", "success"),
                        output_message=exec_res.get("message"),
                        executed_by="Playbook-Auto"
                    )
                    db.add(action_log)

                    logs.append({
                        "time": datetime.datetime.utcnow().isoformat(),
                        "node_id": node_id,
                        "step": step_name,
                        "status": exec_res.get("status", "success"),
                        "output": exec_res
                    })

                # Checkpoint after successful step
                checkpoint_history.append({
                    "node_id": node_id,
                    "step": step_name,
                    "time": datetime.datetime.utcnow().isoformat(),
                    "status": "success"
                })
                execution.checkpoint_history = list(checkpoint_history)
                execution.context_state = context_data
                flag_modified(execution, "checkpoint_history")
                flag_modified(execution, "context_state")
                flag_modified(execution, "logs")
                await db.commit()

            except Exception as e:
                logs.append({
                    "time": datetime.datetime.utcnow().isoformat(),
                    "node_id": node_id,
                    "step": step_name,
                    "status": "failed",
                    "error": str(e)
                })
                execution.status = "failed"
                execution.error_message = str(e)
                execution.logs = logs
                await db.commit()
                return

        # Completed all steps
        if execution.status != "paused_waiting_approval":
            execution.status = "completed"
            execution.finished_at = datetime.datetime.utcnow()

        execution.logs = logs
        await db.commit()

    @classmethod
    async def resume_execution(
        cls,
        execution_id: int,
        approval_decision: Dict[str, Any],
        db
    ) -> Optional[PlaybookExecution]:
        """
        Resumes a paused execution from its persisted checkpoint after analyst approval/decision.
        """
        query = select(PlaybookExecution).where(PlaybookExecution.id == execution_id)
        result = await db.execute(query)
        execution = result.scalars().first()
        if not execution:
            return None

        # Fetch Playbook, Incident, Alert
        pb_res = await db.execute(select(Playbook).where(Playbook.id == execution.playbook_id))
        playbook = pb_res.scalars().first()

        inc_res = await db.execute(
            select(Incident).options(selectinload(Incident.alerts)).where(Incident.id == execution.incident_id)
        )
        incident = inc_res.scalars().first()
        if not playbook or not incident:
            return None

        alert = incident.alerts[0] if incident.alerts else None
        if not alert:
            return None

        # Load persisted context and inject approval decision
        context_data = dict(execution.context_state or {})
        context_data["approval_decision"] = approval_decision

        logs = list(execution.logs or [])
        logs.append({
            "time": datetime.datetime.utcnow().isoformat(),
            "step": "workflow_resumed",
            "status": "resumed",
            "message": f"Analyst decision '{approval_decision.get('decision')}' received. Resuming workflow from step index {execution.current_step_index}."
        })
        execution.logs = logs
        execution.status = "resumed"
        await db.commit()

        start_index = execution.current_step_index or 0
        await cls.execute_playbook(
            playbook=playbook,
            execution=execution,
            incident=incident,
            alert=alert,
            db=db,
            start_index=start_index,
            initial_context=context_data
        )

        return execution

    @classmethod
    async def recover_interrupted_executions(cls, db) -> int:
        """
        Scans for executions left in 'running' or 'resumed' status due to unexpected server restart.
        Ensures resilience and state consistency on boot.
        """
        query = select(PlaybookExecution).where(PlaybookExecution.status.in_(["running", "resumed"]))
        res = await db.execute(query)
        stuck = res.scalars().all()
        count = 0

        for ex in stuck:
            logs = list(ex.logs or [])
            logs.append({
                "time": datetime.datetime.utcnow().isoformat(),
                "step": "server_boot_recovery",
                "status": "recovered",
                "message": "System restart detected. Preserved durable checkpoint."
            })
            ex.logs = logs
            ex.status = "paused_waiting_approval" if ex.current_step_index > 0 else "failed"
            ex.error_message = "Interrupted by system restart; checkpoint preserved."
            count += 1

        if count > 0:
            await db.commit()

        return count
