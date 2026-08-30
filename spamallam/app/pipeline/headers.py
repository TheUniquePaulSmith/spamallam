"""Raw-bytes header manipulation.

The message body and untouched headers are preserved byte-for-byte: we split
the raw message at the header/body boundary, filter/prepend header lines, and
never re-serialize through an email parser (which can re-fold or re-encode).

Security: every X-SpamAllam-* / X-Spam-* header arriving from the internet is
stripped before analysis, and the headers we add carry an HMAC signature so
rspamd (and downstream mail rules) can distinguish ours from forgeries.
"""
from __future__ import annotations

import hmac
import hashlib
import re
import time
from dataclasses import dataclass, field

# Headers an attacker could pre-set to influence scoring/foldering downstream.
_STRIP_RE = re.compile(rb"^(?:x-spamallam-[\w-]*|x-spam-[\w-]*|x-spamd-[\w-]*)\s*:", re.IGNORECASE)

# Captures the separator so a stripped block can be rebuilt byte-for-byte.
_LINE_SPLIT_RE = re.compile(rb"(\r?\n)")


def split_message(raw: bytes) -> tuple[bytes, bytes]:
    """Return (header_block, rest) where rest starts with the blank-line separator."""
    for sep in (b"\r\n\r\n", b"\n\n"):
        idx = raw.find(sep)
        if idx != -1:
            return raw[:idx], raw[idx:]
    return raw, b""  # headers only (unusual but legal)


def _newline_style(head: bytes, rest: bytes) -> bytes:
    """CRLF vs bare-LF, robust even when the header block is a single line."""
    if rest.startswith(b"\r\n") or b"\r\n" in head:
        return b"\r\n"
    return b"\n"


def strip_spam_headers(raw: bytes) -> tuple[bytes, list[bytes]]:
    """Remove all X-SpamAllam-*/X-Spam-*/X-Spamd-* headers (with continuations).

    Returns (cleaned_message, removed_header_lines) — removed lines are logged
    as a spoofing signal.

    Splits on EITHER line ending, capturing the separators. Picking one
    separator for the whole block (the obvious implementation) lets a header
    block that mixes CRLF with bare LF smuggle an X-SpamAllam-* line through:
    the embedded LF stays inside what the split treats as a single "line", and
    _STRIP_RE is ^-anchored, so only the outer line's name is ever tested.
    Everything downstream trusts that this function is total.

    Re-emitting each kept line with its own original separator keeps an
    untouched message byte-identical — DKIM signatures cover these bytes.
    """
    head, rest = split_message(raw)
    default_newline = _newline_style(head, rest)
    # ["line", sep, "line", sep, ..., "line"] -- lines at even indices.
    parts = _LINE_SPLIT_RE.split(head)
    kept: list[tuple[bytes, bytes]] = []  # (separator that preceded it, line)
    removed: list[bytes] = []
    skipping = False
    for idx in range(0, len(parts), 2):
        line = parts[idx]
        sep_before = parts[idx - 1] if idx else b""
        if line[:1] in (b" ", b"\t"):  # continuation of previous header
            if skipping:
                removed.append(line)
            else:
                kept.append((sep_before, line))
            continue
        if _STRIP_RE.match(line):
            skipping = True
            removed.append(line)
        else:
            skipping = False
            kept.append((sep_before, line))

    out: list[bytes] = []
    for sep_before, line in kept:
        if out:  # the first surviving line never carries a leading separator
            out.append(sep_before or default_newline)
        out.append(line)
    return b"".join(out) + rest, removed


@dataclass
class SpamallamVerdict:
    verdict: str = "SKIPPED"       # HAM | SPAM | PHISHING | MALICIOUS | SKIPPED | ERROR
    confidence: float = 0.0
    category: str = ""
    reason: str = ""
    model: str = ""
    tools_used: list[str] = field(default_factory=list)
    whitelisted: str = ""          # e.g. "yes; rule=domain:example.com"
    labels: list[str] = field(default_factory=list)  # classification, e.g. ["newsletter"]


def _canonical(verdict: SpamallamVerdict, ts: int) -> bytes:
    # MUST match rspamd/lua/rspamd.local.lua (which lowercases Whitelisted and
    # uppercases Verdict before verifying).
    return "\n".join(
        [
            "v1",
            str(ts),
            verdict.verdict.upper(),
            f"{max(0.0, min(1.0, verdict.confidence)):.2f}",
            verdict.category,
            verdict.whitelisted.lower(),
        ]
    ).encode()


def sign(verdict: SpamallamVerdict, hmac_key: bytes, ts: int | None = None) -> str:
    ts = ts or int(time.time())
    sig = hmac.new(hmac_key, _canonical(verdict, ts), hashlib.sha256).hexdigest()
    return f"v=1; ts={ts}; sig={sig}"


def _fold(value: str, limit: int = 900) -> str:
    """Keep header values sane: single line, RFC-safe length, no CR/LF."""
    value = re.sub(r"[\r\n]+", " ", value).strip()
    return value[:limit]


def build_spamallam_headers(verdict: SpamallamVerdict, hmac_key: bytes) -> list[tuple[str, str]]:
    headers = [
        ("X-SpamAllam-Verdict", verdict.verdict.upper()),
        ("X-SpamAllam-Confidence", f"{max(0.0, min(1.0, verdict.confidence)):.2f}"),
    ]
    if verdict.category:
        headers.append(("X-SpamAllam-Category", _fold(verdict.category)))
    if verdict.reason:
        headers.append(("X-SpamAllam-Reason", _fold(verdict.reason)))
    if verdict.model:
        headers.append(("X-SpamAllam-Model", _fold(verdict.model)))
    if verdict.tools_used:
        headers.append(("X-SpamAllam-Tools", _fold(", ".join(verdict.tools_used))))
    if verdict.whitelisted:
        headers.append(("X-SpamAllam-Whitelisted", _fold(verdict.whitelisted)))
    if verdict.labels:
        # Informational only (not part of the HMAC canonical string / rspamd
        # scoring contract) — used for MailPlus filter rules, not trust decisions.
        headers.append(("X-SpamAllam-Labels", _fold(", ".join(verdict.labels))))
    headers.append(("X-SpamAllam-Signature", sign(verdict, hmac_key)))
    return headers


def prepend_headers(raw: bytes, headers: list[tuple[str, str]]) -> bytes:
    head, rest = split_message(raw)
    newline = _newline_style(head, rest)
    block = newline.join(f"{k}: {v}".encode() for k, v in headers)
    return block + newline + raw
