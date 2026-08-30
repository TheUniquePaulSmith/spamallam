"""Secrets-at-rest: AES-256-GCM envelope encryption.

Sensitive values (LLM API keys, PFX passwords, UniFi keys, ...) are stored in
the /data config files only as ciphertext dicts: {"$enc": "<b64 nonce+ct>"}.
The master key is derived from the SECRETS_KEY env value (supplied via Docker
secret or env at runtime) and is never written to /data — so the config volume
and its backups contain no plaintext secrets.
"""
from __future__ import annotations

import base64
import hashlib
import os
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..config import is_placeholder

_ENC_KEY = "$enc"


class SecretsBox:
    def __init__(self, master_key: str):
        if not master_key or is_placeholder(master_key):
            raise RuntimeError(
                "SECRETS_KEY is unset or still the placeholder — generate one with "
                "'openssl rand -hex 32' and set it in .env"
            )
        # normalize arbitrary passphrase material to a 256-bit key
        self._key = hashlib.sha256(b"spamallam-secrets-v1:" + master_key.encode()).digest()

    def encrypt(self, plaintext: str | bytes) -> dict[str, str]:
        data = plaintext.encode() if isinstance(plaintext, str) else plaintext
        nonce = os.urandom(12)
        ct = AESGCM(self._key).encrypt(nonce, data, b"spamallam")
        return {_ENC_KEY: base64.b64encode(nonce + ct).decode()}

    def decrypt(self, blob: Any) -> bytes:
        if not self.is_encrypted(blob):
            raise ValueError("not an encrypted blob")
        raw = base64.b64decode(blob[_ENC_KEY])
        return AESGCM(self._key).decrypt(raw[:12], raw[12:], b"spamallam")

    def decrypt_str(self, blob: Any) -> str:
        return self.decrypt(blob).decode()

    @staticmethod
    def is_encrypted(value: Any) -> bool:
        return isinstance(value, dict) and _ENC_KEY in value


def redact(value: Any) -> Any:
    """Replace encrypted blobs (and anything secret-shaped) for display/logs."""
    if SecretsBox.is_encrypted(value):
        return "•••••• (set)"
    if isinstance(value, dict):
        return {k: redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value
