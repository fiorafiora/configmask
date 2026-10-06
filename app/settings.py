from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass

from cryptography.fernet import Fernet


def hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)


@dataclass(frozen=True)
class Settings:
    password_hash: bytes
    password_salt: bytes
    secret_key: str
    fernet_key: str
    db_path: str
    cookie_secure: bool
    max_upload_bytes: int
    port: int

    def verify_password(self, password: str) -> bool:
        candidate = hash_password(password, self.password_salt)
        return hmac.compare_digest(candidate, self.password_hash)

    @classmethod
    def from_env(cls) -> "Settings":
        password = _required("CONFIGMASK_ADMIN_PASSWORD")
        secret = _required("CONFIGMASK_SECRET_KEY")
        fernet_key = _required("CONFIGMASK_FERNET_KEY").strip()
        if len(password) < 8:
            raise RuntimeError("CONFIGMASK_ADMIN_PASSWORD must be at least 8 characters.")
        if len(secret) < 16:
            raise RuntimeError("CONFIGMASK_SECRET_KEY must be at least 16 characters.")
        try:
            Fernet(fernet_key.encode("utf-8"))
        except Exception as exc:
            raise RuntimeError(
                "CONFIGMASK_FERNET_KEY is not a valid Fernet key. Generate one with: "
                'python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"'
            ) from exc
        salt = hashlib.sha256(b"configmask-password-salt:" + secret.encode("utf-8")).digest()
        password_hash = hash_password(password, salt)
        del password
        db_path = os.environ.get("CONFIGMASK_DB_PATH", "/data/configmask.db")
        secure = os.environ.get("CONFIGMASK_COOKIE_SECURE", "0").strip() in {"1", "true", "TRUE", "yes"}
        try:
            limit = int(os.environ.get("CONFIGMASK_MAX_UPLOAD_BYTES", str(10 * 1024 * 1024)))
        except ValueError as exc:
            raise RuntimeError("CONFIGMASK_MAX_UPLOAD_BYTES must be an integer.") from exc
        try:
            port = int(os.environ.get("CONFIGMASK_PORT", "8741"))
        except ValueError as exc:
            raise RuntimeError("CONFIGMASK_PORT must be an integer.") from exc
        return cls(
            password_hash=password_hash,
            password_salt=salt,
            secret_key=secret,
            fernet_key=fernet_key,
            db_path=db_path,
            cookie_secure=secure,
            max_upload_bytes=limit,
            port=port,
        )


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(
            f"{name} is required. ConfigMask will not start without it. See the README for setup."
        )
    return value
