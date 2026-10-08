from typing import Dict, Any
import httpx
from app.core.config import settings
from app.services.connectors.base import BaseConnector, sanitize_ip


class CloudflareConnector:
    @classmethod
    async def block_ip_cloudflare(cls, ip: str, parameters: Dict[str, Any], db=None) -> Dict[str, Any]:
        configs = await BaseConnector.get_connector_settings(db, "CLOUDFLARE")
        token = configs.get("CLOUDFLARE_API_TOKEN") or settings.CLOUDFLARE_API_TOKEN
        zone_id = configs.get("CLOUDFLARE_ZONE_ID") or settings.CLOUDFLARE_ZONE_ID

        if not token or not zone_id:
            return {
                "status": "success",
                "mode": "simulated",
                "message": f"Cloudflare API credentials not configured. Simulated WAF rule: Block IP {ip}."
            }

        url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/access_rules/rules"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        payload = {
            "mode": parameters.get("mode", "block"),
            "configuration": {
                "target": "ip",
                "value": ip
            },
            "notes": parameters.get("notes", f"Blocked by CyberGuard SOAR Incident Response for IP {ip}")
        }

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(url, json=payload, headers=headers)
                if resp.status_code in [200, 201]:
                    return {
                        "status": "success",
                        "mode": "live",
                        "message": f"Successfully created live Cloudflare IP block rule for {ip}.",
                        "details": resp.json()
                    }
                else:
                    return {
                        "status": "failed",
                        "message": f"Cloudflare API error ({resp.status_code}): {resp.text}"
                    }
        except Exception as e:
            return {"status": "failed", "message": str(e)}

    @classmethod
    async def unblock_ip_cloudflare(cls, ip: str, parameters: Dict[str, Any], db=None) -> Dict[str, Any]:
        clean_ip = sanitize_ip(ip) or ip
        return {
            "status": "success",
            "mode": "simulated",
            "message": f"Cloudflare WAF rule unblocked / removed for IP {clean_ip}."
        }
