import asyncio
import datetime
import uuid
from typing import Dict, Any, List, Optional

class IngestionQueueBuffer:
    """
    High-Throughput Asynchronous Ingestion Queue Buffer.
    Decouples raw alert/webhook reception from heavy database operations,
    enrichments, and AI reasoning. Prevents database write locks and drops under event storms.
    """
    _instance: Optional['IngestionQueueBuffer'] = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, maxsize: int = 10000):
        if getattr(self, "_initialized", False):
            return
        self._maxsize = maxsize
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=maxsize)
        self._stats = {
            "ingested_count": 0,
            "processed_count": 0,
            "error_count": 0,
            "dropped_count": 0,
            "started_at": datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat()
        }
        self._is_running = True
        self._initialized = True

    @property
    def queue_depth(self) -> int:
        return self._queue.qsize()

    @property
    def stats(self) -> Dict[str, Any]:
        return self._stats

    @property
    def is_healthy(self) -> bool:
        # Healthy if queue usage is below 90%
        return self.queue_depth < int(self._maxsize * 0.9)

    async def enqueue(self, raw_payload: Dict[str, Any], client_ip: str = "unknown") -> Dict[str, Any]:
        """
        Enqueues an incoming raw alert payload. Returns immediately with task tracking metadata.
        """
        task_id = f"QTSK-{datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"
        item = {
            "task_id": task_id,
            "payload": raw_payload,
            "enqueued_at": datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat(),
            "client_ip": client_ip
        }

        try:
            self._queue.put_nowait(item)
            self._stats["ingested_count"] += 1
            return {
                "status": "queued",
                "task_id": task_id,
                "queue_depth": self._queue.qsize(),
                "enqueued_at": item["enqueued_at"]
            }
        except asyncio.QueueFull:
            self._stats["dropped_count"] += 1
            raise RuntimeError("Ingestion queue buffer is full. Event storm backpressure triggered.")

    async def dequeue_batch(self, batch_size: int = 20, timeout: float = 0.5) -> List[Dict[str, Any]]:
        """
        Retrieves a batch of alert items for batched/ordered processing.
        """
        items = []
        try:
            # Wait for at least one item
            first_item = await asyncio.wait_for(self._queue.get(), timeout=timeout)
            items.append(first_item)
            self._queue.task_done()

            # Drain up to batch_size without blocking
            while len(items) < batch_size and not self._queue.empty():
                try:
                    item = self._queue.get_nowait()
                    items.append(item)
                    self._queue.task_done()
                except asyncio.QueueEmpty:
                    break
        except asyncio.TimeoutError:
            pass

        return items

    def record_processed(self, count: int = 1):
        self._stats["processed_count"] += count

    def record_error(self, count: int = 1):
        self._stats["error_count"] += count

    def get_metrics(self) -> Dict[str, Any]:
        return {
            "queue_depth": self.queue_depth,
            "max_capacity": self._maxsize,
            "capacity_used_pct": round((self.queue_depth / self._maxsize) * 100, 2) if self._maxsize > 0 else 0,
            "is_healthy": self.is_healthy,
            "stats": dict(self._stats),
            "current_time": datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat()
        }

# Global singleton buffer instance
ingestion_queue = IngestionQueueBuffer()
