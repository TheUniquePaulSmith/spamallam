"""Attachment-stripped copy of a dropped message, for admin review.

Parses+reserializes via email.policy.default -- the same raw-byte-fidelity
trade-off body.py makes -- and keeps only headers plus text/plain and
text/html body parts. Never used on the delivery path: this only feeds the
admin logs UI so a human can see what a high-confidence drop actually
contained, without retaining attachments/images from an untrusted sender.
"""
from __future__ import annotations

import email
import email.policy
from email.message import EmailMessage

# S/MIME and PGP/MIME: parsing would just expose the opaque signed/encrypted
# blob anyway, so leave the structure alone rather than pretend to strip it.
_SKIP_CONTENT_TYPES = {"multipart/signed", "multipart/encrypted"}
_SKIP_COPY_HEADERS = {"content-type", "mime-version", "content-transfer-encoding"}
_TRUNCATE_BYTES = 64 * 1024


def strip_for_review(raw: bytes) -> bytes:
    """Best-effort attachment-stripped .eml for the dropped-mail archive.
    Fails open to a truncated copy of the original on any parse error --
    this is a review aid, not something delivery correctness depends on."""
    try:
        msg = email.message_from_bytes(raw, policy=email.policy.default)
    except Exception:  # noqa: BLE001 -- unparsable: best-effort truncated original
        return raw[:_TRUNCATE_BYTES]

    if msg.get_content_type() in _SKIP_CONTENT_TYPES:
        return raw[:_TRUNCATE_BYTES]

    text_part: str | None = None
    html_part: str | None = None
    for part in msg.walk():
        if part.is_multipart():
            continue
        if part.get_filename() or part.get_content_disposition() == "attachment":
            continue
        ctype = part.get_content_type()
        if ctype not in ("text/plain", "text/html"):
            continue
        try:
            content = part.get_content()
        except Exception:  # noqa: BLE001 -- undecodable part, skip it
            continue
        if not isinstance(content, str):
            continue
        if ctype == "text/plain" and text_part is None:
            text_part = content
        elif ctype == "text/html" and html_part is None:
            html_part = content

    try:
        out = EmailMessage(policy=email.policy.default)
        for key, value in msg.items():
            if key.lower() in _SKIP_COPY_HEADERS:
                continue
            out[key] = value

        if text_part is not None and html_part is not None:
            out.set_content(text_part)
            out.add_alternative(html_part, subtype="html")
        elif html_part is not None:
            out.set_content(html_part, subtype="html")
        elif text_part is not None:
            out.set_content(text_part)
        else:
            out.set_content(
                "[SpamAllam: no text/plain or text/html part found -- "
                "original message had only attachments/binary content]"
            )
        return out.as_bytes()
    except Exception:  # noqa: BLE001 -- rebuild failed: fall back to truncated original
        return raw[:_TRUNCATE_BYTES]
