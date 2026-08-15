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
    reinject_host: str = field(default_factory=lambda: _env("REINJECT_HOST", "postfix"))
    reinject_port: int = field(default_factory=lambda: int(_env("REINJECT_PORT", "10025")))

    rspamd_url: str = field(default_factory=lambda: _env("RSPAMD_URL", "http://rspamd:11333"))

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
