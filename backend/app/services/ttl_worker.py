import asyncio
import datetime
import logging
from sqlalchemy.future import select
from app.core.database import AsyncSessionLocal
from app.models.models import PendingApproval, ActionLog, Incident
from app.services.response_service import ResponseService
from app.services.websocket_manager import ws_manager

logger = logging.getLogger("soar.ttl_worker")


async def _rollback_single_approval(approval_id: int) -> bool:
    """
    Processes a single expired PendingApproval in its own isolated DB session.
    Returns True if successfully reverted, False on error.

    Using per-approval sessions ensures that a failure on one item does NOT
    affect the rollback of other expired approvals in the same cycle.
    """
    async with AsyncSessionLocal() as session:
        try:
            now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

            # Re-fetch the approval inside this session
            result = await session.get(PendingApproval, approval_id)
            if not result or result.is_expired:
                return True  # Already handled by another cycle

            approval = result

            # Determine rollback action based on connector / action type
            rollback_action = "unblock_ip"
            if approval.connector == "identity" or approval.action_type in [
                "disable_user_account", "suspend_user", "revoke_user_sessions"
            ]:
                rollback_action = "enable_user_account"
            elif approval.connector in ["edr", "wazuh_ar"] or approval.action_type in [
                "isolate_wazuh_agent", "isolate", "isolate_endpoint", "isolate_host"
            ]:
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
            approval.analyst_note = (
                f"{note} | [TTL Expired] Tự động hoàn tác theo thời hạn TTL ({approval.ttl_minutes}m)"
            ).strip(" |")
            approval.resolved_at = now

            # Record rollback in ActionLog
            rollback_log = ActionLog(
                incident_id=approval.incident_id,
                action_type=rollback_action,
                connector=approval.connector,
                target=approval.target,
                status=exec_res.get("status", "success"),
                output_message=(
                    f"[TTL Expired] Tự động hoàn tác và gỡ chặn {approval.target} "
                    f"sau {approval.ttl_minutes} phút: {exec_res.get('message', '')}"
                ),
                executed_by="System Auto-Rollback (TTL)",
                is_expired=True,
                rollback_status="auto_unblocked"
            )
            session.add(rollback_log)

            # Mark original ActionLogs for this target as expired
            act_query = select(ActionLog).where(
                ActionLog.incident_id == approval.incident_id,
                ActionLog.target == approval.target,
                ActionLog.is_expired == False  # noqa: E712
            )
            act_res = await session.execute(act_query)
            for orig_act in act_res.scalars().all():
                orig_act.is_expired = True
                orig_act.rollback_status = "auto_unblocked"

            # Update incident timestamp if still contained
            if approval.incident_id:
                inc = await session.get(Incident, approval.incident_id)
                if inc and inc.status == "contained":
                    inc.updated_at = now

            # Commit everything atomically for this single approval
            await session.commit()

            # Broadcast WebSocket AFTER successful commit
            try:
                await ws_manager.broadcast("AUTO_ROLLBACK_EXECUTED", {
                    "approval_id": approval.id,
                    "incident_id": approval.incident_id,
                    "target": approval.target,
                    "connector": approval.connector,
                    "ttl_minutes": approval.ttl_minutes,
                    "status": "reverted",
                    "message": (
                        f"Đã tự động gỡ chặn {approval.target} trên {approval.connector} "
                        f"do hết thời hạn TTL ({approval.ttl_minutes} phút)."
                    )
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
                pass  # WebSocket errors must not fail the rollback

            logger.info(
                f"[TTL Worker] Auto-reverted approval #{approval.id}: "
                f"{approval.target} on {approval.connector} (TTL={approval.ttl_minutes}m)"
            )
            return True

        except Exception as e:
            await session.rollback()
            logger.error(f"[TTL Worker] Failed to rollback approval #{approval_id}: {e}")
            return False


async def check_and_rollback_expired_actions():
    """
    Scans for expired containment actions (where expires_at <= now and is_expired is False)
    and dispatches each one to _rollback_single_approval for isolated atomic processing.
    """
    async with AsyncSessionLocal() as session:
        try:
            now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

            query = (
                select(PendingApproval.id)
                .where(
                    PendingApproval.status.in_(["executed", "approved"]),
                    PendingApproval.expires_at.isnot(None),
                    PendingApproval.expires_at <= now,
                    PendingApproval.is_expired == False  # noqa: E712
                )
            )
            result = await session.execute(query)
            expired_ids = [row[0] for row in result.all()]

        except Exception as e:
            logger.error(f"[TTL Worker] Error querying expired approvals: {e}")
            return

    # Process each expired approval in its own isolated session
    for appr_id in expired_ids:
        await _rollback_single_approval(appr_id)


async def start_ttl_worker(interval_seconds: int = 15):
    """
    Background loop executing check_and_rollback_expired_actions periodically.
    """
    logger.info(f"[CyberGuard SOAR] Auto-Rollback TTL Worker started (Polling every {interval_seconds}s).")
    try:
        while True:
            await check_and_rollback_expired_actions()
            await asyncio.sleep(interval_seconds)
    except asyncio.CancelledError:
        logger.info("[CyberGuard SOAR] Auto-Rollback TTL Worker stopping.")
    except Exception as e:
        logger.error(f"[CyberGuard SOAR] Auto-Rollback TTL Worker unhandled exception: {e}")
