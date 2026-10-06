from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.core.vault import VaultService
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
    {"key": "LINUX_SSH_PASSWORD", "value": "", "category": "connectors", "is_secret": True, "description": "Linux Gateway SSH Password"},
    {"key": "LINUX_SSH_AUTH_TYPE", "value": "key", "category": "connectors", "is_secret": False, "description": "SSH Authentication Method: key (Ed25519) or password"},
    {"key": "LINUX_SSH_PUBLIC_KEY", "value": "", "category": "connectors", "is_secret": False, "description": "CyberGuard SOAR Ed25519 Public Key (Add this to ~/.ssh/authorized_keys on Linux VM)"},
    {"key": "LINUX_SSH_PRIVATE_KEY", "value": "", "category": "connectors", "is_secret": True, "description": "CyberGuard SOAR Ed25519 Private Key (AES-256-GCM Encrypted in Vault)"},
    {"key": "LINUX_SSH_USE_SUDO_NOPASSWD", "value": "false", "category": "connectors", "is_secret": False, "description": "Linux Sudo NOPASSWD configured for iptables (eliminates password piping)"},
    {"key": "IDENTITY_PROVIDER", "value": "mock", "category": "connectors", "is_secret": False, "description": "Identity Provider: okta, azure_ad, mock"},
    {"key": "IDENTITY_DOMAIN", "value": "dev-cyberguard.okta.com", "category": "connectors", "is_secret": False, "description": "Okta/Entra ID Tenant Domain"},
    {"key": "IDENTITY_API_TOKEN", "value": "", "category": "connectors", "is_secret": True, "description": "Okta SSWS API Token or Azure Bearer Token"},
    {"key": "EDR_PROVIDER", "value": "wazuh", "category": "connectors", "is_secret": False, "description": "EDR Provider: wazuh, crowdstrike, webhook"},
    {"key": "EDR_WEBHOOK_URL", "value": "http://127.0.0.1:8000/api/v1/connectors/edr/webhook", "category": "connectors", "is_secret": False, "description": "EDR Action Dispatcher Webhook URL"},
    {"key": "EDR_API_KEY", "value": "", "category": "connectors", "is_secret": True, "description": "EDR Central Controller API Key / Bearer Token"},
    {"key": "SAFETY_GUARDRAILS_ENABLED", "value": "true", "category": "safety", "is_secret": False, "description": "Enable Blast Radius Safety Guardrails (Blocks whitelisted IP actions)"},
    {"key": "SAFETY_WHITELIST_IPS", "value": "127.0.0.1, 8.8.8.8, 8.8.4.4, 1.1.1.1, 192.168.56.1, 10.0.0.1", "category": "safety", "is_secret": False, "description": "Critical Infrastructure Whitelist IPs/CIDRs (Separated by comma)"},
    {"key": "DEFAULT_BLOCK_TTL_MINUTES", "value": "60", "category": "safety", "is_secret": False, "description": "Default Auto-Rollback TTL duration in minutes (e.g. 15, 60, 1440)"}
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
                val = VaultService.mask_secret(val)
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

        # Encrypt secrets with AES-256-GCM Vault if secret and not already encrypted
        stored_value = item.value
        if item.is_secret and item.value and not VaultService.is_encrypted(item.value):
            stored_value = VaultService.encrypt(item.value)

        if existing:
            existing.value = stored_value
            existing.category = item.category
            existing.is_secret = item.is_secret
            if item.description:
                existing.description = item.description
        else:
            new_setting = SystemSetting(
                key=item.key,
                value=stored_value,
                category=item.category,
                is_secret=item.is_secret,
                description=item.description
            )
            db.add(new_setting)

    await db.commit()
    return {"status": "success", "message": "Settings saved successfully"}

@router.get("/ssh-keypair")
async def get_soar_ssh_keypair(db: AsyncSession = Depends(get_db)):
    """
    Returns the CyberGuard SOAR Ed25519 SSH Public Key for configuring authorized_keys on target VMs.
    """
    keypair_info = await VaultService.get_or_create_soar_ssh_keypair(db=db)
    return {
        "status": "success",
        "public_key": keypair_info.get("public_key"),
        "auth_type": "key",
        "has_private_key": keypair_info.get("has_private_key", False),
        "setup_instruction": (
            "Sao chép public key này và thêm vào tệp ~/.ssh/authorized_keys trên máy ảo Kali/Linux "
            "để cho phép SOAR kết nối SSH an toàn mà không cần nhập mật khẩu thô."
        )
    }

@router.post("/ssh-keypair/generate")
async def regenerate_soar_ssh_keypair(db: AsyncSession = Depends(get_db)):
    """
    Generates and stores a brand new Ed25519 SSH keypair into the AES-256-GCM Vault.
    """
    priv_pem, pub_ssh = VaultService.generate_ed25519_keypair()
    enc_priv = VaultService.encrypt(priv_pem)

    # Update or add public key
    res_pub = await db.execute(select(SystemSetting).where(SystemSetting.key == "LINUX_SSH_PUBLIC_KEY"))
    pub_row = res_pub.scalars().first()
    if pub_row:
        pub_row.value = pub_ssh
    else:
        db.add(SystemSetting(
            key="LINUX_SSH_PUBLIC_KEY",
            value=pub_ssh,
            category="connectors",
            is_secret=False,
            description="CyberGuard SOAR Ed25519 Public Key (Add this to ~/.ssh/authorized_keys on Linux VM)"
        ))

    # Update or add private key
    res_priv = await db.execute(select(SystemSetting).where(SystemSetting.key == "LINUX_SSH_PRIVATE_KEY"))
    priv_row = res_priv.scalars().first()
    if priv_row:
        priv_row.value = enc_priv
        priv_row.is_secret = True
    else:
        db.add(SystemSetting(
            key="LINUX_SSH_PRIVATE_KEY",
            value=enc_priv,
            category="connectors",
            is_secret=True,
            description="CyberGuard SOAR Ed25519 Private Key (AES-256-GCM Encrypted in Vault)"
        ))

    await db.commit()
    return {
        "status": "success",
        "message": "Cặp khóa SSH Ed25519 mới đã được tạo và lưu trữ an toàn trong Vault!",
        "public_key": pub_ssh
    }

