import ipaddress
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.future import select
from app.models.models import SystemSetting

# Default Critical Infrastructure Whitelist
DEFAULT_PROTECTED_ENTRIES = [
    # Loopback
    "127.0.0.0/8",
    "::1",
    
    # Public DNS Resolvers (Critical for DNS resolution & CTI lookups)
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "1.0.0.1",
    "9.9.9.9",
    
    # SOAR Host & VirtualBox Host-Only Adapter IP (Never self-block!)
    "192.168.56.1",
    "192.168.56.0",
    "192.168.56.255",
    
    # Common Default Gateways & Broadcast
    "10.0.0.1",
    "192.168.1.1",
    "172.16.0.1",
    "255.255.255.255",
    "224.0.0.0/4"  # Multicast
]

class GuardrailService:
    @classmethod
    async def get_whitelist_entries(cls, db=None) -> List[str]:
        entries = list(DEFAULT_PROTECTED_ENTRIES)
        if db:
            try:
                res = await db.execute(select(SystemSetting).where(SystemSetting.key == "SAFETY_WHITELIST_IPS"))
                row = res.scalars().first()
                if row and row.value:
                    custom_items = [x.strip() for x in row.value.replace("\n", ",").split(",") if x.strip()]
                    entries.extend(custom_items)
            except Exception:
                pass
        return list(set(entries))

    @classmethod
    async def is_guardrails_enabled(cls, db=None) -> bool:
        if db:
            try:
                res = await db.execute(select(SystemSetting).where(SystemSetting.key == "SAFETY_GUARDRAILS_ENABLED"))
                row = res.scalars().first()
                if row and row.value:
                    return row.value.strip().lower() in ["true", "1", "yes", "enabled"]
            except Exception:
                pass
        return True  # Default enabled

    @classmethod
    def is_ip_whitelisted(cls, ip_str: str, whitelist: List[str]) -> Tuple[bool, Optional[str]]:
        if not ip_str:
            return False, None
            
        clean_target = ip_str.strip().split(":")[0]  # strip port if present
        
        try:
            target_ip = ipaddress.ip_address(clean_target)
        except ValueError:
            # Check string exact match (e.g. localhost)
            if clean_target.lower() in ["localhost", "soar-server", "gateway"]:
                return True, f"Named host '{clean_target}' is protected."
            return False, None

        for item in whitelist:
            item_clean = item.strip()
            if not item_clean:
                continue
            try:
                if "/" in item_clean:
                    network = ipaddress.ip_network(item_clean, strict=False)
                    if target_ip in network:
                        return True, f"IP {clean_target} belongs to protected network subnet '{item_clean}'."
                else:
                    ref_ip = ipaddress.ip_address(item_clean)
                    if target_ip == ref_ip:
                        return True, f"IP {clean_target} matches protected infrastructure IP '{item_clean}'."
            except Exception:
                if item_clean.lower() == clean_target.lower():
                    return True, f"Matched protected entry '{item_clean}'."
                    
        return False, None

    @classmethod
    async def validate_action_safety(
        cls,
        target: str,
        action_type: str,
        connector: str = "",
        db=None
    ) -> Dict[str, Any]:
        """
        Validates whether executing an action against target violates Safety Guardrails.
        Returns:
            {"allowed": True} or {"allowed": False, "violation": True, "reason": "...", "target": target}
        """
        enabled = await cls.is_guardrails_enabled(db)
        if not enabled:
            return {"allowed": True, "guardrails_active": False}

        action_norm = (action_type or "").lower()
        
        # Only containment / blocking / isolation actions are restricted
        is_restrictive = any(k in action_norm for k in [
            "block", "drop", "isolate", "quarantine", "deny", "ban"
        ])
        
        if not is_restrictive:
            return {"allowed": True}

        whitelist = await cls.get_whitelist_entries(db)
        is_blocked, match_reason = cls.is_ip_whitelisted(target, whitelist)

        if is_blocked:
            return {
                "allowed": False,
                "violation": True,
                "target": target,
                "action_type": action_type,
                "connector": connector,
                "reason": f"[BLAST_RADIUS_VIOLATION] Ngăn chặn tự động: Mục tiêu '{target}' nằm trong danh sách Hạ tầng Trọng yếu được bảo vệ ({match_reason}). Lệnh chặn đã bị từ chối để tránh tự làm tê liệt dịch vụ hệ thống!"
            }

        return {"allowed": True, "violation": False}
