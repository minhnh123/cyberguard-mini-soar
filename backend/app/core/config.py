import os
from pathlib import Path
from pydantic_settings import BaseSettings

BASE_DIR = Path(__file__).resolve().parent.parent.parent

class Settings(BaseSettings):
    PROJECT_NAME: str = "CyberGuard Mini SOAR"
    API_V1_STR: str = "/api/v1"
    DATABASE_URL: str = f"sqlite+aiosqlite:///{BASE_DIR}/soar.db"

    # CORS Allowed Origins (comma-separated). Defaults to dev origins.
    # Set ALLOWED_ORIGINS in .env for production, e.g.:
    #   ALLOWED_ORIGINS=https://soar.company.com,https://soc.company.com
    ALLOWED_ORIGINS: str = "http://localhost:5173,http://localhost:5174,http://192.168.56.1:5173,http://127.0.0.1:5173"

    # AI Default Settings (can be overridden via DB settings)
    DEFAULT_AI_PROVIDER: str = "gemini"  # gemini, openai, deepseek, custom
    DEFAULT_AI_API_KEY: str = ""
    DEFAULT_AI_MODEL: str = "gemini-2.0-flash"

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

    @property
    def allowed_origins_list(self) -> list[str]:
        """Parse ALLOWED_ORIGINS env string into a list."""
        return [o.strip() for o in self.ALLOWED_ORIGINS.split(",") if o.strip()]

    class Config:
        env_file = ".env"
        extra = "allow"

settings = Settings()

