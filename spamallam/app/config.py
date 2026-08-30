"""Process-level configuration sourced from environment variables.

Everything an admin can change at runtime lives in the file-backed settings
store (app/store/settings.py) instead; env vars here are deployment-shaped
values that require a container restart to change.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


# Prefixes of the placeholder values shipped in .env.example. A deployment
# still carrying one of these is unconfigured, not merely weakly configured.
_PLACEHOLDER_PREFIXES = ("change-me", "changeme", "your-", "replace-me")

# "openssl rand -hex 32" is 64 chars; 32 is the floor for a hand-picked
# passphrase. The key derivation (store/secrets.py) is a plain SHA-256 rather
# than a slow KDF, so this length check is what makes offline brute force of a
# stolen /data volume infeasible -- don't lower it.
MIN_SECRET_LEN = 32


def is_placeholder(value: str) -> bool:
    return value.strip().lower().startswith(_PLACEHOLDER_PREFIXES)


def require_strong_secret(name: str, value: str | bytes, *, min_len: int = MIN_SECRET_LEN) -> None:
    """Raise RuntimeError unless `value` is a real, deployment-specific secret.

    Called at startup for every secret whose compromise breaks a trust
    boundary -- HEADER_HMAC_KEY (downstream verdict trust) and SECRETS_KEY
    (which also derives the admin session/CSRF/WebAuthn signing key, so a
    placeholder here is a full admin authentication bypass).
    """
    text = value.decode(errors="replace") if isinstance(value, bytes) else (value or "")
    text = text.strip()
    hint = "generate one with 'openssl rand -hex 32' and set it in .env"
    if not text:
        raise RuntimeError(f"{name} is unset — {hint}")
    if is_placeholder(text):
        raise RuntimeError(f"{name} is still the .env.example placeholder — {hint}")
    if len(text) < min_len:
        raise RuntimeError(
            f"{name} is only {len(text)} characters; at least {min_len} are required — {hint}"
        )


@dataclass(frozen=True)
class Env:
    data_dir: Path = field(default_factory=lambda: Path(_env("SPAMALLAM_DATA", "/data")))
    templates_dir: Path = field(default_factory=lambda: Path(_env("SPAMALLAM_TEMPLATES", "templates")))
    static_dir: Path = field(default_factory=lambda: Path(_env("SPAMALLAM_STATIC", "static")))

    mail_hostname: str = field(default_factory=lambda: _env("MAIL_HOSTNAME", "localhost"))
    mail_domains: tuple[str, ...] = field(
        default_factory=lambda: tuple(
            d.strip().lower() for d in _env("MAIL_DOMAINS").split(",") if d.strip()
        )
    )

    header_hmac_key: bytes = field(default_factory=lambda: _env("HEADER_HMAC_KEY").encode())
    secrets_key: str = field(default_factory=lambda: _env("SECRETS_KEY"))
    setup_token: str = field(default_factory=lambda: _env("SETUP_TOKEN"))

    smtp_listen_port: int = field(default_factory=lambda: int(_env("SMTP_LISTEN_PORT", "10026")))
    # Bind the content-filter listener to the filter network only, so the
    # scanning containers cannot reach it. "0.0.0.0" keeps the old behavior.
    smtp_listen_host: str = field(default_factory=lambda: _env("SMTP_LISTEN_HOST", "0.0.0.0"))
    reinject_host: str = field(default_factory=lambda: _env("REINJECT_HOST", "postfix"))
    reinject_port: int = field(default_factory=lambda: int(_env("REINJECT_PORT", "10025")))
    # Peers allowed to use XFORWARD (postfix's smtpd_authorized_xforward_hosts
    # equivalent). XFORWARD sets the client IP/HELO that rspamd scores SPF and
    # the RBLs against, so anyone who can send it can launder a verdict.
    # Empty = accept from any peer (pre-segmentation behavior).
    xforward_trusted_peers: frozenset[str] = field(
        default_factory=lambda: frozenset(
            p.strip() for p in _env("XFORWARD_TRUSTED_PEERS").split(",") if p.strip()
        )
    )

    rspamd_url: str = field(default_factory=lambda: _env("RSPAMD_URL", "http://rspamd:11333"))
    # DB 1: kept separate from rspamd's own bayes/fuzzy/greylist state on DB 0,
    # so clearing the netinfo tool cache can never touch rspamd's learned corpus.
    redis_url: str = field(default_factory=lambda: _env("REDIS_URL", "redis://redis:6379/1"))

    admin_port: int = field(default_factory=lambda: int(_env("ADMIN_PORT", "8443")))
    admin_external_host: str = field(
        default_factory=lambda: _env("ADMIN_EXTERNAL_HOST") or _env("MAIL_HOSTNAME", "localhost")
    )
    # The container always listens on admin_port internally; the host may publish
    # that under a different port (docker-compose ADMIN_BIND). Links shown to
    # users (setup/invite URLs) need the port reachable from outside, not the
    # container-internal one — set this to match whatever ADMIN_BIND uses.
    admin_external_port: int = field(
        default_factory=lambda: int(_env("ADMIN_EXTERNAL_PORT") or _env("ADMIN_PORT", "8443"))
    )
    tls_cert_name: str = field(
        default_factory=lambda: _env("TLS_CERT_NAME")
        or _env("ADMIN_EXTERNAL_HOST", "").split(":")[0]
        or _env("MAIL_HOSTNAME", "localhost")
    )
    certs_dir: Path = field(default_factory=lambda: Path(_env("CERTS_DIR", "/certs")))
    scratch_dir: Path = field(default_factory=lambda: Path(_env("TMPDIR", "/run/spamallam")))

    max_concurrent_analyses: int = field(
        default_factory=lambda: int(_env("MAX_CONCURRENT_ANALYSES", "4"))
    )
    ai_timeout_seconds: float = field(
        default_factory=lambda: float(_env("AI_TIMEOUT_SECONDS", "90"))
    )

    # Seed values for the tools settings (admin UI values win once saved)
    unifi_url: str = field(default_factory=lambda: _env("UNIFI_URL"))
    unifi_api_key: str = field(default_factory=lambda: _env("UNIFI_API_KEY"))
    unifi_network_list: str = field(
        default_factory=lambda: _env("UNIFI_NETWORK_LIST", "spamallam-blocked")
    )
    geoip_db_path: str = field(
        default_factory=lambda: _env("GEOIP_DB_PATH", "/data/geoip/GeoLite2-City.mmdb")
    )


    def admin_external_url(self, path: str = "") -> str:
        """Build a browser-facing admin UI URL, omitting :443 (the HTTPS default)."""
        port = "" if self.admin_external_port == 443 else f":{self.admin_external_port}"
        return f"https://{self.admin_external_host}{port}{path}"


ENV = Env()
