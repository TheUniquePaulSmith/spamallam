"""Whitelist/blocklist overrides.

Whitelisted sender domains or named recipients ALWAYS pass as HAM, carrying a
declarative X-SpamAllam-Whitelisted header. Blocklisted sender domains are
forced to a SPAM verdict (scored by rspamd's Lua plugin, not silently dropped).
"""
from __future__ import annotations

import re
from email.utils import parseaddr


def _domain_of(address: str) -> str:
    addr = parseaddr(address or "")[1]
    return addr.rsplit("@", 1)[-1].lower().strip() if "@" in addr else ""


def _base_recipient(address: str) -> str:
    """paul+lists@example.com -> paul@example.com (plus addressing)."""
    addr = parseaddr(address or "")[1].lower().strip()
    return re.sub(r"\+[^@]*@", "@", addr)


def _domain_matches(domain: str, patterns: list[str]) -> str | None:
    for pat in patterns or []:
        p = (pat or "").lower().strip().lstrip("@")
        if not p:
            continue
        if domain == p or domain.endswith("." + p):
            return p
    return None


def check_whitelist(
    overrides: dict,
    envelope_from: str,
    from_header: str,
    rcpt_tos: list[str],
) -> str | None:
    """Return a human-readable matched-rule string, or None."""
    for sender in (envelope_from, from_header):
        dom = _domain_of(sender)
        if dom:
            hit = _domain_matches(dom, overrides.get("whitelist_domains", []))
            if hit:
                return f"domain:{hit}"
    wl_rcpts = {_base_recipient(r) for r in overrides.get("whitelist_recipients", []) or []}
    for rcpt in rcpt_tos:
        if _base_recipient(rcpt) in wl_rcpts:
            return f"recipient:{_base_recipient(rcpt)}"
    return None


def check_blocklist(overrides: dict, envelope_from: str, from_header: str) -> str | None:
    for sender in (envelope_from, from_header):
        dom = _domain_of(sender)
        if dom:
            hit = _domain_matches(dom, overrides.get("blocklist_domains", []))
            if hit:
                return f"domain:{hit}"
    return None
