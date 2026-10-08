import datetime
from typing import Dict, Any, Optional


class WorkerHealthTracker:
    """
    In-memory registry and health monitor for background workers
    (TTL Auto-Rollback Worker, Alert Ingestion Queue Consumer Worker, etc.).
    """

    def __init__(self):
        self._workers: Dict[str, Dict[str, Any]] = {}

    def register(self, worker_name: str, description: str = "") -> None:
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self._workers[worker_name] = {
            "name": worker_name,
            "description": description,
            "status": "starting",
            "started_at": now_iso,
            "last_heartbeat": now_iso,
            "heartbeat_count": 0,
            "metrics": {},
            "last_error": None
        }

    def record_heartbeat(self, worker_name: str, metrics: Optional[Dict[str, Any]] = None, status: str = "running") -> None:
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        if worker_name not in self._workers:
            self.register(worker_name)
        worker = self._workers[worker_name]
        worker["status"] = status
        worker["last_heartbeat"] = now_iso
        worker["heartbeat_count"] = worker.get("heartbeat_count", 0) + 1
        if metrics:
            worker["metrics"].update(metrics)

    def record_error(self, worker_name: str, error_message: str) -> None:
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        if worker_name not in self._workers:
            self.register(worker_name)
        worker = self._workers[worker_name]
        worker["status"] = "degraded"
        worker["last_error"] = {
            "timestamp": now_iso,
            "message": error_message
        }

    def record_stop(self, worker_name: str) -> None:
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        if worker_name in self._workers:
            self._workers[worker_name]["status"] = "stopped"
            self._workers[worker_name]["stopped_at"] = now_iso

    def get_worker(self, worker_name: str) -> Optional[Dict[str, Any]]:
        return self._workers.get(worker_name)

    def get_all_health(self) -> Dict[str, Any]:
        return {name: dict(info) for name, info in self._workers.items()}


# Singleton instance
worker_health = WorkerHealthTracker()
