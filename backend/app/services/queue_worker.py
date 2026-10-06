import asyncio
import logging
from app.core.database import AsyncSessionLocal
from app.services.ingestion_queue import ingestion_queue

logger = logging.getLogger("soar.queue_worker")

async def run_queue_consumer_worker():
    """
    Background worker that continuously drains the IngestionQueueBuffer
    and processes alerts in controlled batches using dedicated database sessions.
    Protects the primary database from race conditions and locks during alert storms.
    """
    # Import locally to avoid circular dependency
    from app.api.alerts import process_alert_ingestion

    logger.info("[Queue Worker] Ingestion Queue Consumer Worker started.")

    while True:
        try:
            items = await ingestion_queue.dequeue_batch(batch_size=15, timeout=1.0)
            if not items:
                await asyncio.sleep(0.1)
                continue

            async with AsyncSessionLocal() as session:
                for item in items:
                    try:
                        payload = item.get("payload", {})
                        await process_alert_ingestion(payload, session)
                        ingestion_queue.record_processed(1)
                    except Exception as ex:
                        ingestion_queue.record_error(1)
                        logger.error(f"[Queue Worker Error] Failed processing task {item.get('task_id')}: {ex}")

        except asyncio.CancelledError:
            logger.info("[Queue Worker] Ingestion worker cancelled. Exiting cleanly.")
            break
        except Exception as e:
            logger.error(f"[Queue Worker Exception] Unexpected error in worker loop: {e}")
            await asyncio.sleep(1.0)
