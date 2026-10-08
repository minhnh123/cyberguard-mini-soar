import ipaddress
from typing import Dict, Optional
from sqlalchemy.future import select
from app.models.models import SystemSetting


def sanitize_ip(ip_str: str) -> Optional[str]:
    if not ip_str:
        return None
    try:
        clean = ip_str.strip()
        ip_obj = ipaddress.ip_address(clean)
        return str(ip_obj)
    except Exception:
        return None


class BaseConnector:
    @classmethod
    async def get_connector_settings(cls, db, prefix: str) -> Dict[str, str]:
        config = {}
        if db:
            from app.core.vault import VaultService
            result = await db.execute(select(SystemSetting))
            for row in result.scalars().all():
                if row.key.startswith(prefix) or row.key in [
                    "WAZUH_API_URL", "WAZUH_API_USER", "WAZUH_API_PASSWORD",
                    "CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ZONE_ID",
                    "LINUX_SSH_HOST", "LINUX_SSH_USER", "LINUX_SSH_PASSWORD", "LINUX_SSH_PORT",
                    "LINUX_SSH_AUTH_TYPE", "LINUX_SSH_PUBLIC_KEY", "LINUX_SSH_PRIVATE_KEY", "LINUX_SSH_USE_SUDO_NOPASSWD",
                    "IDENTITY_PROVIDER", "IDENTITY_DOMAIN", "IDENTITY_API_TOKEN",
                    "EDR_PROVIDER", "EDR_WEBHOOK_URL", "EDR_API_KEY"
                ]:
                    val = row.value or ""
                    if row.is_secret or VaultService.is_encrypted(val):
                        val = VaultService.decrypt(val)
                    config[row.key] = val
        return config
