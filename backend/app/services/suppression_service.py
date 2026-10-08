import fnmatch
import datetime
from typing import Dict, Any, Optional, Tuple, List
from sqlalchemy.future import select
from app.models.models import SuppressionRule

class SuppressionService:
    """
    Dynamic Alert Suppression & Noise Reduction Engine:
    - Filters out repetitive false positives and authorized maintenance alerts.
    - Tracks hit metrics and handles auto-expiry TTLs.
    """

    @classmethod
    async def is_alert_suppressed(
        cls,
        alert_dict: Dict[str, Any],
        db
    ) -> Tuple[bool, Optional[SuppressionRule]]:
        if not alert_dict or not db:
            return False, None

        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

        # Query all active rules
        stmt = select(SuppressionRule).where(SuppressionRule.is_active == True)
        res = await db.execute(stmt)
        active_rules = res.scalars().all()

        src_ip = alert_dict.get("source_ip")
        user = alert_dict.get("user")
        file_hash = alert_dict.get("file_hash")
        domain = alert_dict.get("domain")
        title = alert_dict.get("title", "")

        for rule in active_rules:
            # Check expiration TTL
            if rule.expires_at and rule.expires_at < now:
                rule.is_active = False
                continue

            matched = False
            rule_val = (rule.entity_value or "").strip().lower()

            if rule.entity_type == "ip" and src_ip and src_ip.strip().lower() == rule_val:
                matched = True
            elif rule.entity_type == "user" and user and user.strip().lower() == rule_val:
                matched = True
            elif rule.entity_type == "hash" and file_hash and file_hash.strip().lower() == rule_val:
                matched = True
            elif rule.entity_type == "domain" and domain and domain.strip().lower() == rule_val:
                matched = True
            elif rule.entity_type == "title_pattern" and title:
                # Support glob wildcards like *backup* or *pentest*
                if fnmatch.fnmatch(title.lower(), rule_val.lower()):
                    matched = True

            if matched:
                rule.hit_count = (rule.hit_count or 0) + 1
                rule.last_hit_at = now
                await db.commit()
                return True, rule

        return False, None

    @classmethod
    async def create_suppression_rule(
        cls,
        entity_type: str,
        entity_value: str,
        reason: str,
        duration_hours: Optional[int] = 24,
        created_by: str = "SOC Analyst",
        db=None
    ) -> SuppressionRule:
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        expires_at = now + datetime.timedelta(hours=duration_hours) if duration_hours else None

        rule = SuppressionRule(
            entity_type=entity_type.lower(),
            entity_value=entity_value.strip(),
            reason=reason,
            created_by=created_by,
            created_at=now,
            expires_at=expires_at,
            is_active=True,
            hit_count=0
        )
        db.add(rule)
        await db.commit()
        await db.refresh(rule)
        return rule

    @classmethod
    async def list_rules(cls, active_only: bool = True, db=None) -> List[SuppressionRule]:
        if not db:
            return []
        query = select(SuppressionRule).order_by(SuppressionRule.created_at.desc())
        if active_only:
            query = query.where(SuppressionRule.is_active == True)
        res = await db.execute(query)
        return res.scalars().all()

    @classmethod
    async def delete_rule(cls, rule_id: int, db=None) -> bool:
        if not db:
            return False
        res = await db.execute(select(SuppressionRule).where(SuppressionRule.id == rule_id))
        rule = res.scalars().first()
        if not rule:
            return False
        rule.is_active = False
        await db.commit()
        return True
