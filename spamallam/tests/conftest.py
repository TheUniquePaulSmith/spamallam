"""Test environment: point SPAMALLAM_DATA at a temp dir and provide the shared
secrets BEFORE any app module is imported (app.config.ENV freezes at import)."""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

_DATA = Path(tempfile.mkdtemp(prefix="spamallam-test-"))
os.environ.setdefault("SPAMALLAM_DATA", str(_DATA))
os.environ.setdefault("SECRETS_KEY", "test-secrets-key-0123456789abcdef")
os.environ.setdefault("HEADER_HMAC_KEY", "test-hmac-key-0123456789abcdef")
os.environ.setdefault("MAIL_HOSTNAME", "mail.test.example")
os.environ.setdefault("MAIL_DOMAINS", "test.example")
os.environ.setdefault("TMPDIR", str(_DATA / "tmp"))

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
