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

    IMPORTANT: Each alert item is processed in its own isolated DB session so that
    a failure in one item does NOT roll back or affect other items in the same batch.
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
            logger.info("[Queue Worker] Ingestion worker cancelled. Exiting cleanly.")
            break
        except Exception as e:
            logger.error(f"[Queue Worker Exception] Unexpected error in worker loop: {e}")
            await asyncio.sleep(1.0)
