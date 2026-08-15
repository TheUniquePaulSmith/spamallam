"""spamallam process entrypoint.

Runs, in one asyncio loop:
  * the SMTP content-filter listener (:10026)
  * the HTTPS admin UI (:8443), restarted automatically when the acme
    container rotates the certificate in the shared /certs volume
  * daily trace-log retention pruning
"""
from __future__ import annotations

import asyncio
import datetime
import hashlib
import logging
import ssl
import sys
from pathlib import Path

import uvicorn

from .admin.app import create_app
from .config import ENV
from .smtp.server import start_smtp_server
from .store import users as users_store
from .store.settings import SETTINGS
from .store.tracelog import prune

log = logging.getLogger("spamallam")

CERT_POLL_SECONDS = 60


# ---------------------------------------------------------------------------
# TLS material for the admin UI
# ---------------------------------------------------------------------------

def _acme_cert_paths() -> tuple[Path, Path]:
    base = ENV.certs_dir / ENV.tls_cert_name
    return base / "fullchain.pem", base / "key.pem"


def _selfsigned_paths() -> tuple[Path, Path]:
    base = ENV.data_dir / "tls"
    return base / "fullchain.pem", base / "key.pem"


def _ensure_selfsigned() -> tuple[Path, Path]:
    cert_path, key_path = _selfsigned_paths()
    if cert_path.exists() and key_path.exists():
        return cert_path, key_path
    log.warning("no acme certificate found; generating self-signed admin cert for %s",
                ENV.admin_external_host)
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ENV.admin_external_host.split(":")[0])])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName(
            [x509.DNSName(ENV.admin_external_host.split(":")[0])]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    key_path.chmod(0o600)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


def _pick_admin_certs() -> tuple[Path, Path]:
    cert, key = _acme_cert_paths()
    if cert.exists() and key.exists():
        return cert, key
    return _ensure_selfsigned()


def _cert_fingerprint(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return ""


# ---------------------------------------------------------------------------
# Admin server supervisor (restarts on cert rotation)
# ---------------------------------------------------------------------------

async def run_admin_server() -> None:
    app = create_app()
    while True:
        cert, key = _pick_admin_certs()
        fingerprint = _cert_fingerprint(cert)
        config = uvicorn.Config(
            app, host="0.0.0.0", port=ENV.admin_port,
            ssl_certfile=str(cert), ssl_keyfile=str(key),
            ssl_version=ssl.PROTOCOL_TLS_SERVER,
            log_level="warning", access_log=False,
        )
        server = uvicorn.Server(config)
        serve_task = asyncio.create_task(server.serve())
        log.info("admin UI serving on https://0.0.0.0:%d (cert: %s)", ENV.admin_port, cert)

        acme_cert = _acme_cert_paths()[0]
        while not serve_task.done():
            await asyncio.sleep(CERT_POLL_SECONDS)
            current = _cert_fingerprint(acme_cert) or fingerprint
            if current != fingerprint:
                log.info("admin certificate rotated; restarting HTTPS listener")
                server.should_exit = True
                break
        await serve_task


async def retention_loop() -> None:
    while True:
        try:
            days = int(SETTINGS.get("logging.retention_days", 30))
            removed = prune(days)
            if removed:
                log.info("pruned %d trace files older than %d days", removed, days)
        except Exception:  # noqa: BLE001
            log.exception("retention pruning failed")
        await asyncio.sleep(24 * 3600)


def bootstrap() -> None:
    for sub in ("config", "logs", "tls"):
        (ENV.data_dir / sub).mkdir(parents=True, exist_ok=True)
    if not ENV.header_hmac_key or ENV.header_hmac_key.startswith(b"change-me"):
        log.critical("HEADER_HMAC_KEY is unset/placeholder — set it in .env")
        sys.exit(1)

    token = users_store.bootstrap_setup_token()
    if token:
        banner = "=" * 72
        log.warning(
            "\n%s\nNo users enrolled. One-time admin enrollment token (24h validity):\n\n"
            "    https://%s:%d/setup?token=%s\n\n"
            "Open the URL and register your first passkey. There are no passwords.\n%s",
            banner, ENV.admin_external_host, ENV.admin_port, token, banner,
        )


async def async_main() -> None:
    bootstrap()
    smtp_server = await start_smtp_server()
    try:
        await asyncio.gather(run_admin_server(), retention_loop())
    finally:
        smtp_server.close()


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stdout,
    )
    asyncio.run(async_main())


if __name__ == "__main__":
    main()
