"""Distill a raw RFC5322 message into a compact, model-friendly payload.

The FULL message is preserved through the pipeline; this summary is only what
the LLM sees (bounded size, no attachment bodies, URLs listed but clearly
marked as NEVER-FETCH).
"""
from __future__ import annotations

import email
import email.policy
import html
import re
from email.message import EmailMessage
from typing import Any

MAX_BODY_CHARS = 6000
MAX_URLS = 30
MAX_RECEIVED = 4

_URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)
_TAG_RE = re.compile(r"<[^>]+>")


def _html_to_text(markup: str) -> str:
    markup = re.sub(r"(?is)<(script|style).*?</\1>", " ", markup)
    markup = re.sub(r"(?i)<br\s*/?>|</p>|</div>|</tr>", "\n", markup)
    return html.unescape(_TAG_RE.sub(" ", markup))


def _body_and_attachments(msg: EmailMessage) -> tuple[str, list[dict[str, Any]]]:
    text_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[dict[str, Any]] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        ctype = part.get_content_type()
        if filename or part.get_content_disposition() == "attachment":
            try:
                size = len(part.get_payload(decode=True) or b"")
            except Exception:  # noqa: BLE001
                size = -1
            attachments.append({"filename": filename or "(unnamed)", "content_type": ctype, "size": size})
            continue
        try:
            content = part.get_content()
        except Exception:  # noqa: BLE001
            continue
        if not isinstance(content, str):
            continue
        if ctype == "text/plain":
            text_parts.append(content)
        elif ctype == "text/html":
            html_parts.append(_html_to_text(content))
    body = "\n".join(text_parts) or "\n".join(html_parts)
    body = re.sub(r"\n{3,}", "\n\n", body).strip()
    return body, attachments


def summarize(raw: bytes, envelope_from: str, rcpt_tos: list[str], client: dict[str, Any]) -> dict[str, Any]:
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    body, attachments = _body_and_attachments(msg)

    urls = []
    seen = set()
    for m in _URL_RE.finditer(body):
        u = m.group(0)
        if u not in seen:
            seen.add(u)
            urls.append(u)
        if len(urls) >= MAX_URLS:
            break

    received = [str(v)[:300] for v in (msg.get_all("Received") or [])[:MAX_RECEIVED]]

    return {
        "envelope_from": envelope_from,
        "rcpt_tos": rcpt_tos,
        "client_ip": client.get("addr", ""),
        "client_hostname": client.get("name", ""),
        "helo": client.get("helo", ""),
        "headers": {
            "from": str(msg.get("From", "")),
            "reply_to": str(msg.get("Reply-To", "")),
            "to": str(msg.get("To", "")),
            "subject": str(msg.get("Subject", "")),
            "date": str(msg.get("Date", "")),
            "message_id": str(msg.get("Message-ID", "")),
            "list_unsubscribe": str(msg.get("List-Unsubscribe", "")),
            "authentication_results": str(msg.get("Authentication-Results", ""))[:500],
        },
        "received_chain": received,
        "body_text": body[:MAX_BODY_CHARS],
        "body_truncated": len(body) > MAX_BODY_CHARS,
        "urls_in_body": urls,
        "attachments": attachments,
    }
