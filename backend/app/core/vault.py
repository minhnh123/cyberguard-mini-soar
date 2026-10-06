import os
import io
import re
import base64
import secrets
import hashlib
from pathlib import Path
from typing import Optional, List, Tuple, Dict, Any
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from sqlalchemy.future import select

BASE_DIR = Path(__file__).resolve().parent.parent.parent

class VaultService:
    """
    Enterprise AES-256-GCM Vault Service for envelope encryption of secrets,
    SSH Ed25519 keypair management, and sensitive credential redaction.
    """
    _cached_master_key: Optional[bytes] = None

    @classmethod
    def get_master_key(cls) -> bytes:
        """
        Retrieves the 256-bit AES master key from:
        1. Environment variable SOAR_MASTER_KEY
        2. Local persisted keyfile (.soar_vault.key in backend root)
        3. If non-existent, generates a cryptographically secure 256-bit key and stores it.
        """
        if cls._cached_master_key is not None:
            return cls._cached_master_key

        # 1. Environment variable
        env_key = os.environ.get("SOAR_MASTER_KEY", "").strip()
        if env_key:
            try:
                # Try decoding base64 if 44 characters (32 bytes b64)
                if len(env_key) == 44:
                    raw = base64.b64decode(env_key)
                    if len(raw) == 32:
                        cls._cached_master_key = raw
                        return raw
            except Exception:
                pass
            # Derive 32-byte key using SHA-256
            raw = hashlib.sha256(env_key.encode("utf-8")).digest()
            cls._cached_master_key = raw
            return raw

        # 2. Keyfile in backend root
        keyfile_path = BASE_DIR / ".soar_vault.key"
        if keyfile_path.exists():
            try:
                raw_b64 = keyfile_path.read_text(encoding="utf-8").strip()
                raw = base64.b64decode(raw_b64)
                if len(raw) == 32:
                    cls._cached_master_key = raw
                    return raw
            except Exception:
                pass

        # 3. Generate new random 256-bit key
        new_key = secrets.token_bytes(32)
        try:
            b64_repr = base64.b64encode(new_key).decode("ascii")
            keyfile_path.write_text(b64_repr, encoding="utf-8")
            # Attempt restricting file permissions on Unix if applicable
            try:
                os.chmod(keyfile_path, 0o600)
            except Exception:
                pass
        except Exception:
            pass

        cls._cached_master_key = new_key
        return new_key

    @classmethod
    def encrypt(cls, plaintext: Optional[str]) -> str:
        """
        Encrypts a plaintext string using AES-256-GCM.
        Returns ciphertext string formatted as 'enc:v1:<nonce_b64>:<ciphertext_and_tag_b64>'.
        If already encrypted or empty, returns as-is.
        """
        if not plaintext:
            return ""
        if str(plaintext).startswith("enc:v1:"):
            return str(plaintext)

        key = cls.get_master_key()
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(12)  # Standard 96-bit nonce for GCM
        ct_bytes = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)

        nonce_b64 = base64.b64encode(nonce).decode("ascii")
        ct_b64 = base64.b64encode(ct_bytes).decode("ascii")
        return f"enc:v1:{nonce_b64}:{ct_b64}"

    @classmethod
    def decrypt(cls, ciphertext: Optional[str]) -> str:
        """
        Decrypts an AES-256-GCM ciphertext string.
        If not encrypted (does not start with 'enc:v1:'), returns as-is for backward compatibility.
        """
        if not ciphertext:
            return ""
        if not str(ciphertext).startswith("enc:v1:"):
            return str(ciphertext)

        parts = ciphertext.split(":")
        if len(parts) != 4:
            return ciphertext

        _, version, nonce_b64, ct_b64 = parts
        if version != "v1":
            return ciphertext

        try:
            nonce = base64.b64decode(nonce_b64)
            ct = base64.b64decode(ct_b64)
            key = cls.get_master_key()
            aesgcm = AESGCM(key)
            pt_bytes = aesgcm.decrypt(nonce, ct, None)
            return pt_bytes.decode("utf-8")
        except Exception as e:
            # Integrity check failed or invalid key
            return f"[VAULT_DECRYPTION_ERROR: {str(e)}]"

    @classmethod
    def is_encrypted(cls, value: Optional[str]) -> bool:
        """
        Checks whether a given string is in encrypted vault format.
        """
        return bool(value and str(value).startswith("enc:v1:"))

    @classmethod
    def mask_secret(cls, value: Optional[str], visible_suffix: int = 4) -> str:
        """
        Masks sensitive secrets for safe API display.
        Handles both encrypted vault strings and raw text.
        """
        if not value:
            return ""
        
        # If encrypted, decrypt to discover original length and suffix
        plain = cls.decrypt(value) if cls.is_encrypted(value) else value
        if not plain:
            return ""
        
        if len(plain) <= visible_suffix:
            return "••••••••"
        return f"••••••••{plain[-visible_suffix:]}"

    @classmethod
    def redact_sensitive_strings(cls, text: str, extra_secrets: Optional[List[str]] = None) -> str:
        """
        Sanitizes logs, command traces, and outputs by redacting private keys,
        tokens, passwords, and user-provided secret values.
        """
        if not text:
            return ""

        redacted = str(text)

        # 1. Redact PEM Private Keys
        redacted = re.sub(
            r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----",
            "[REDACTED_PRIVATE_KEY]",
            redacted
        )

        # 2. Redact Authorization Bearer headers
        redacted = re.sub(
            r"(?i)\bBearer\s+[A-Za-z0-9\-\._~+/]{8,}=*",
            "Bearer [REDACTED_BEARER_TOKEN]",
            redacted
        )

        # 3. Redact common inline password commands: echo 'pass' | sudo -S
        redacted = re.sub(
            r"echo\s+['\"][^'\"]+['\"]\s*\|\s*sudo\s+-S",
            "sudo -S [PASSWORD_SUPPRESSED]",
            redacted
        )

        # 4. Redact vault ciphertext tokens
        redacted = re.sub(
            r"enc:v1:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+",
            "[REDACTED_VAULT_CIPHERTEXT]",
            redacted
        )

        # 5. Redact extra secret strings passed explicitly
        if extra_secrets:
            for s in extra_secrets:
                if s and len(s.strip()) >= 3:
                    # Ignore common short tokens
                    clean_s = s.strip()
                    if clean_s not in ["root", "admin", "true", "false", "mock", "none"]:
                        redacted = redacted.replace(clean_s, "[REDACTED_SECRET]")

        return redacted

    @classmethod
    def generate_ed25519_keypair(cls, comment: str = "cyberguard-soar@local") -> Tuple[str, str]:
        """
        Generates an Ed25519 SSH keypair.
        Returns (private_key_pem, public_key_openssh).
        """
        private_key = ed25519.Ed25519PrivateKey.generate()
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption()
        ).decode("utf-8")

        public_ssh = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        ).decode("utf-8")

        public_ssh_with_comment = f"{public_ssh} {comment}"
        return private_pem, public_ssh_with_comment

    @classmethod
    async def get_or_create_soar_ssh_keypair(cls, db=None) -> Dict[str, Any]:
        """
        Retrieves existing SOAR SSH keypair from SystemSetting or generates a new one.
        Ensures the private key is stored encrypted in the database.
        """
        from app.models.models import SystemSetting

        pub_key = ""
        priv_key_encrypted = ""

        if db:
            res_pub = await db.execute(select(SystemSetting).where(SystemSetting.key == "LINUX_SSH_PUBLIC_KEY"))
            pub_row = res_pub.scalars().first()
            if pub_row:
                pub_key = pub_row.value or ""

            res_priv = await db.execute(select(SystemSetting).where(SystemSetting.key == "LINUX_SSH_PRIVATE_KEY"))
            priv_row = res_priv.scalars().first()
            if priv_row:
                priv_key_encrypted = priv_row.value or ""

        if pub_key and priv_key_encrypted:
            return {
                "public_key": pub_key,
                "has_private_key": True,
                "auth_type": "key",
                "status": "ready"
            }

        # Generate new keypair
        priv_pem, pub_ssh = cls.generate_ed25519_keypair()
        enc_priv = cls.encrypt(priv_pem)

        if db:
            # Save or update public key
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

            # Save or update private key (encrypted)
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
            "public_key": pub_ssh,
            "has_private_key": True,
            "auth_type": "key",
            "status": "generated"
        }
