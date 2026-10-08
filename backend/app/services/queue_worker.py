import asyncio
import logging
from app.core.database import AsyncSessionLocal
from app.services.ingestion_queue import ingestion_queue
from app.services.worker_health import worker_health

logger = logging.getLogger("soar.queue_worker")

async def run_queue_consumer_worker():
    """
    Background worker that continuously drains the IngestionQueueBuffer
    and processes alerts in controlled batches using dedicated database sessions.
    Protects the primary database from race conditions and locks during alert storms.

    IMPORTANT: Each alert item is processed in its own isolated DB session so that
    a failure in one item does NOT roll back or affect other items in the same batch.
    """
    # Import locally to avoid circular dependency
    from app.api.alerts import process_alert_ingestion

    worker_health.register("queue_worker", "Alert Ingestion Queue Consumer Worker for batch processing")
    logger.info("[Queue Worker] Ingestion Queue Consumer Worker started.")

    while True:
        try:
            worker_health.record_heartbeat(
                "queue_worker",
                metrics={
                    "current_queue_size": ingestion_queue.get_metrics().get("current_queue_size", 0),
                    "total_enqueued": ingestion_queue.get_metrics().get("total_enqueued", 0),
                    "total_processed": ingestion_queue.get_metrics().get("total_processed", 0),
                    "total_errors": ingestion_queue.get_metrics().get("total_errors", 0)
                },
                status="healthy"
            )

            items = await ingestion_queue.dequeue_batch(batch_size=15, timeout=1.0)
            if not items:
                await asyncio.sleep(0.1)
                continue

            # Process each item in its own isolated session for fault isolation.
            # If item N fails, items 1..N-1 are already committed and safe.
            for item in items:
                async with AsyncSessionLocal() as session:
                    try:
                        payload = item.get("payload", {})
                        await process_alert_ingestion(payload, session)
                        await session.commit()
                        ingestion_queue.record_processed(1)
                    except Exception as ex:
                        await session.rollback()
                        ingestion_queue.record_error(1)
                        logger.error(
                            f"[Queue Worker Error] Failed processing task "
                            f"{item.get('task_id')} — rolled back cleanly. Error: {ex}"
                        )

        except asyncio.CancelledError:
            worker_health.record_stop("queue_worker")
            logger.info("[Queue Worker] Ingestion worker cancelled. Exiting cleanly.")
            break
        except Exception as e:
            worker_health.record_error("queue_worker", str(e))
            logger.error(f"[Queue Worker Exception] Unexpected error in worker loop: {e}")
            await asyncio.sleep(1.0)
