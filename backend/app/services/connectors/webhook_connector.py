from typing import Dict, Any
import httpx


class WebhookConnector:
    @classmethod
    async def send_webhook_notification(cls, webhook_url: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        if not webhook_url:
            return {"status": "failed", "message": "No webhook URL specified"}

        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.post(webhook_url, json=payload)
                return {
                    "status": "success" if resp.status_code in [200, 201, 204] else "failed",
                    "status_code": resp.status_code,
                    "message": f"Notification delivered with status {resp.status_code}"
                }
        except Exception as e:
            return {"status": "failed", "message": str(e)}
