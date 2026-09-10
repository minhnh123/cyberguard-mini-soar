import asyncio
import datetime
from sqlalchemy.future import select
from app.core.database import AsyncSessionLocal
from app.models.models import PendingApproval, ActionLog, Incident
from app.services.response_service import ResponseService
from app.services.websocket_manager import ws_manager

async def check_and_rollback_expired_actions():
    """
    Scans for expired containment actions (where expires_at <= utcnow and is_expired is False)
    and executes automatic rollback (unblock/reconnect).
    """
    async with AsyncSessionLocal() as session:
        try:
            now = datetime.datetime.utcnow()
            
            # 1. Check PendingApproval records with TTL expiration
            query = (
                select(PendingApproval)
                .where(
                    PendingApproval.status.in_(["executed", "approved"]),
                    PendingApproval.expires_at.isnot(None),
                    PendingApproval.expires_at <= now,
                    PendingApproval.is_expired == False
                )
            )
            result = await session.execute(query)
            expired_approvals = result.scalars().all()
            
            for approval in expired_approvals:
                rollback_action = "unblock_ip"
                if approval.connector == "identity" or approval.action_type in ["disable_user_account", "suspend_user", "revoke_user_sessions"]:
                    rollback_action = "enable_user_account"
                elif approval.connector in ["edr", "wazuh_ar"] or approval.action_type in ["isolate_wazuh_agent", "isolate", "isolate_endpoint", "isolate_host"]:
                    rollback_action = "reconnect_endpoint"
                    
                # Execute rollback via ResponseService
                exec_res = await ResponseService.execute_action(
                    connector=approval.connector,
                    action_type=rollback_action,
                    target=approval.target,
                    parameters=approval.parameters or {},
                    db=session
                )
                
                # Mark approval as reverted and expired
                approval.is_expired = True
                approval.status = "reverted"
                note = approval.analyst_note or ""
                approval.analyst_note = f"{note} | [TTL Expired] Tự động hoàn tác theo thời hạn TTL ({approval.ttl_minutes}m)".strip(" |")
                approval.resolved_at = now
                
                # Record in ActionLog
                rollback_log = ActionLog(
                    incident_id=approval.incident_id,
                    action_type=rollback_action,
                    connector=approval.connector,
                    target=approval.target,
                    status=exec_res.get("status", "success"),
                    output_message=f"[TTL Expired] Tự động hoàn tác và gỡ chặn {approval.target} sau {approval.ttl_minutes} phút: {exec_res.get('message', '')}",
                    executed_by="System Auto-Rollback (TTL)",
                    is_expired=True,
                    rollback_status="auto_unblocked"
                )
                session.add(rollback_log)
                
                # Update original ActionLog for this target
                act_query = select(ActionLog).where(
                    ActionLog.incident_id == approval.incident_id,
                    ActionLog.target == approval.target,
                    ActionLog.is_expired == False
                )
                act_res = await session.execute(act_query)
                for orig_act in act_res.scalars().all():
                    orig_act.is_expired = True
                    orig_act.rollback_status = "auto_unblocked"
                
                # If incident was contained, we can update or leave note
                inc_query = select(Incident).where(Incident.id == approval.incident_id)
                inc_res = await session.execute(inc_query)
                inc = inc_res.scalars().first()
                if inc and inc.status == "contained":
                    inc.updated_at = now
                
                await session.commit()
                
                # Broadcast real-time WebSocket notification to UI
                try:
                    await ws_manager.broadcast("AUTO_ROLLBACK_EXECUTED", {
                        "approval_id": approval.id,
                        "incident_id": approval.incident_id,
                        "target": approval.target,
                        "connector": approval.connector,
                        "ttl_minutes": approval.ttl_minutes,
                        "status": "reverted",
                        "message": f"Đã tự động gỡ chặn {approval.target} trên {approval.connector} do hết thời hạn TTL ({approval.ttl_minutes} phút)."
                    })
                    await ws_manager.broadcast("TARGET_UNBLOCKED", {
                        "approval_id": approval.id,
                        "incident_id": approval.incident_id,
                        "target": approval.target,
                        "connector": approval.connector,
                        "status": "reverted",
                        "message": f"[Auto-Rollback] Đã mở khóa {approval.target}"
                    })
                except Exception:
                    pass

        except Exception as e:
            # Avoid crashing the background worker
            print(f"[TTL Worker] Error processing expired actions: {e}")

async def start_ttl_worker(interval_seconds: int = 15):
    """
    Background loop executing check_and_rollback_expired_actions periodically.
    """
    print(f"[CyberGuard SOAR] Auto-Rollback TTL Worker started (Polling every {interval_seconds}s).")
    try:
        while True:
            await check_and_rollback_expired_actions()
            await asyncio.sleep(interval_seconds)
    except asyncio.CancelledError:
        print("[CyberGuard SOAR] Auto-Rollback TTL Worker stopping.")
    except Exception as e:
        print(f"[CyberGuard SOAR] Auto-Rollback TTL Worker unhandled exception: {e}")
