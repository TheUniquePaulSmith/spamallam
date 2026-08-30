"""Re-inject a message into postfix for delivery.

Shared by the SMTP content-filter path (smtp/server.py) and the quarantine
"release" action (admin/app.py). postfix :10025 is the post-filter re-injection
port: mail submitted here is NOT handed back to spamallam's content_filter and
there is no rspamd milter, so this is a straight delivery with no re-analysis --
exactly what releasing a false positive should do.
"""
from __future__ import annotations

import smtplib

from .config import ENV


def reinject(mail_from: str, rcpt_tos: list[str], message: bytes) -> None:
    with smtplib.SMTP(ENV.reinject_host, ENV.reinject_port, timeout=60) as smtp:
        smtp.sendmail(mail_from, rcpt_tos, message)
