from __future__ import annotations

from cryptography.fernet import Fernet


class Vault:
    """Encrypts mapping values and stored configurations at rest."""

    def __init__(self, key: str):
        self._fernet = Fernet(key.encode("utf-8"))

    def encrypt(self, text: str) -> bytes:
        return self._fernet.encrypt(text.encode("utf-8"))

    def decrypt(self, blob: bytes) -> str:
        return self._fernet.decrypt(blob).decode("utf-8")
