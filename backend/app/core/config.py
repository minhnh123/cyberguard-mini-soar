import os
from pathlib import Path
from pydantic_settings import BaseSettings

BASE_DIR = Path(__file__).resolve().parent.parent.parent

class Settings(BaseSettings):
    PROJECT_NAME: str = "CyberGuard Mini SOAR"
    API_V1_STR: str = "/api/v1"
    DATABASE_URL: str = f"sqlite+aiosqlite:///{BASE_DIR}/soar.db"
    
    # AI Default Settings (can be overridden via DB settings)
    DEFAULT_AI_PROVIDER: str = "gemini"  # gemini, openai, deepseek, custom
    DEFAULT_AI_API_KEY: str = ""
    DEFAULT_AI_MODEL: str = "gemini-1.5-flash"
    
    # VirusTotal
    VIRUSTOTAL_API_KEY: str = ""
    
    # Wazuh Manager API Default
    WAZUH_API_URL: str = ""
    WAZUH_API_USER: str = ""
    WAZUH_API_PASSWORD: str = ""
    
    # Cloudflare API Default
    CLOUDFLARE_API_TOKEN: str = ""
    CLOUDFLARE_ZONE_ID: str = ""
    
    # Webhook Secret Token for auth (optional)
    WEBHOOK_SECRET_KEY: str = "cyberguard-soar-secret"

    class Config:
        env_file = ".env"
        extra = "allow"

settings = Settings()
