from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.models.models import SystemSetting
from app.schemas.schemas import SystemSettingUpdate

router = APIRouter(prefix="/settings", tags=["Settings"])

DEFAULT_SETTINGS = [
    {"key": "AI_PROVIDER", "value": "gemini", "category": "ai", "is_secret": False, "description": "LLM Provider: gemini, openai, deepseek, custom"},
    {"key": "AI_MODEL", "value": "gemini-1.5-flash", "category": "ai", "is_secret": False, "description": "Model Name (e.g. gemini-1.5-flash, gpt-4o-mini, deepseek-chat)"},
    {"key": "GEMINI_API_KEY", "value": "", "category": "ai", "is_secret": True, "description": "Google Gemini API Key"},
    {"key": "OPENAI_API_KEY", "value": "", "category": "ai", "is_secret": True, "description": "OpenAI API Key"},
    {"key": "DEEPSEEK_API_KEY", "value": "", "category": "ai", "is_secret": True, "description": "DeepSeek API Key"},
    {"key": "AI_CUSTOM_BASE_URL", "value": "", "category": "ai", "is_secret": False, "description": "Custom OpenAI-compatible API base URL"},
    {"key": "VIRUSTOTAL_API_KEY", "value": "", "category": "threat_intel", "is_secret": True, "description": "VirusTotal v3 API Key"},
    {"key": "WAZUH_API_URL", "value": "https://wazuh-manager.local:55000", "category": "connectors", "is_secret": False, "description": "Wazuh Manager REST API URL"},
    {"key": "WAZUH_API_USER", "value": "wazuh-wui", "category": "connectors", "is_secret": False, "description": "Wazuh API Username"},
    {"key": "WAZUH_API_PASSWORD", "value": "", "category": "connectors", "is_secret": True, "description": "Wazuh API Password"},
    {"key": "CLOUDFLARE_API_TOKEN", "value": "", "category": "connectors", "is_secret": True, "description": "Cloudflare WAF API Token"},
    {"key": "CLOUDFLARE_ZONE_ID", "value": "", "category": "connectors", "is_secret": False, "description": "Cloudflare Zone ID"},
    {"key": "LINUX_SSH_HOST", "value": "", "category": "connectors", "is_secret": False, "description": "Linux Gateway Host/IP for iptables/ufw block"},
    {"key": "LINUX_SSH_USER", "value": "root", "category": "connectors", "is_secret": False, "description": "Linux Gateway SSH Username"},
    {"key": "LINUX_SSH_PASSWORD", "value": "", "category": "connectors", "is_secret": True, "description": "Linux Gateway SSH Password"}
]

@router.get("")
async def get_all_settings(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(SystemSetting))
    db_settings = {s.key: s for s in result.scalars().all()}

    output = []
    for def_s in DEFAULT_SETTINGS:
        key = def_s["key"]
        if key in db_settings:
            item = db_settings[key]
            val = item.value or ""
            if item.is_secret and val:
                val = f"••••••••••••{val[-4:]}" if len(val) >= 4 else "••••••••"
            output.append({
                "key": item.key,
                "value": val,
                "is_set": bool(item.value),
                "category": item.category,
                "is_secret": item.is_secret,
                "description": item.description or def_s["description"]
            })
        else:
            output.append({
                "key": key,
                "value": def_s["value"],
                "is_set": bool(def_s["value"]),
                "category": def_s["category"],
                "is_secret": def_s["is_secret"],
                "description": def_s["description"]
            })

    return output

@router.post("")
async def save_settings(settings_list: List[SystemSettingUpdate], db: AsyncSession = Depends(get_db)):
    for item in settings_list:
        # Don't overwrite secret if it was sent as masked bullets
        if "••••" in item.value:
            continue

        res = await db.execute(select(SystemSetting).where(SystemSetting.key == item.key))
        existing = res.scalars().first()
        if existing:
            existing.value = item.value
            existing.category = item.category
            existing.is_secret = item.is_secret
            if item.description:
                existing.description = item.description
        else:
            new_setting = SystemSetting(
                key=item.key,
                value=item.value,
                category=item.category,
                is_secret=item.is_secret,
                description=item.description
            )
            db.add(new_setting)

    await db.commit()
    return {"status": "success", "message": "Settings saved successfully"}
