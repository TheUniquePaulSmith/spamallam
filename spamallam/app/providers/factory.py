"""Build a configured provider from the settings store, decrypting secrets and
preparing the optional mTLS client-certificate context for custom providers.
"""
from __future__ import annotations

import os
import ssl
import tempfile
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from ..config import ENV
from ..store.secrets import SecretsBox
from .anthropic_provider import AnthropicProvider
from .base import BaseProvider, ProviderSettings
from .openai_provider import OpenAIProvider


def _mtls_context(box: SecretsBox, mtls_cfg: dict[str, Any]) -> ssl.SSLContext:
    """Decrypt the stored PFX (+password), load into an SSLContext via a
    short-lived file on the tmpfs scratch mount, then remove the file.

    The decrypted key exists on the memory-backed tmpfs for milliseconds and in
    process memory afterwards — never on the /data volume or image layers.
    """
    pfx_bytes = box.decrypt(mtls_cfg["pfx"])
    password = box.decrypt(mtls_cfg["pfx_password"]) if mtls_cfg.get("pfx_password") else None

    key, cert, chain = pkcs12.load_key_and_certificates(pfx_bytes, password)
    if key is None or cert is None:
        raise ValueError("PFX did not contain both a private key and a certificate")

    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pem += cert.public_bytes(serialization.Encoding.PEM)
    for extra in chain or []:
        pem += extra.public_bytes(serialization.Encoding.PEM)

    ENV.scratch_dir.mkdir(parents=True, exist_ok=True)
    fd, path = tempfile.mkstemp(dir=ENV.scratch_dir, prefix="mtls-", suffix=".pem")
    try:
        os.write(fd, pem)
        os.close(fd)
        ctx = ssl.create_default_context()
        ctx.load_cert_chain(path)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    return ctx


def load_provider(settings_all: dict[str, Any], box: SecretsBox) -> BaseProvider:
    cfg = settings_all["provider"]
    ptype = (cfg.get("type") or "openai").lower()

    api_key = ""
    if SecretsBox.is_encrypted(cfg.get("api_key")):
        api_key = box.decrypt_str(cfg["api_key"])

    ssl_ctx = None
    if ptype == "custom" and cfg.get("mtls", {}).get("enabled") and cfg["mtls"].get("pfx"):
        ssl_ctx = _mtls_context(box, cfg["mtls"])

    ps = ProviderSettings(
        type=ptype,
        model=cfg.get("model") or "",
        api_key=api_key,
        base_url=cfg.get("base_url") or "",
        timeout_seconds=float(cfg.get("timeout_seconds") or 60),
        max_tokens=int(cfg.get("max_tokens") or 1024),
        ssl_context=ssl_ctx,
    )

    if ptype == "anthropic":
        return AnthropicProvider(ps)
    if ptype in ("openai", "custom"):
        if ptype == "custom" and not ps.base_url:
            raise ValueError("custom provider requires a base_url")
        return OpenAIProvider(ps)
    raise ValueError(f"unknown provider type {ptype!r}")
