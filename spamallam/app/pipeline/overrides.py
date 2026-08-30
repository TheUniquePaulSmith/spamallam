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


def match_whitelist(
    overrides: dict,
    envelope_from: str,
    from_header: str,
    rcpt_tos: list[str],
) -> tuple[str | None, str]:
    """Return (matched-rule string, source) where source is "envelope", "header"
    or "recipient". The source decides which authentication signal can confirm
    a sender-domain rule -- see whitelist_is_authenticated."""
    for source, sender in (("envelope", envelope_from), ("header", from_header)):
        dom = _domain_of(sender)
        if dom:
            hit = _domain_matches(dom, overrides.get("whitelist_domains", []))
            if hit:
                return f"domain:{hit}", source
    wl_rcpts = {_base_recipient(r) for r in overrides.get("whitelist_recipients", []) or []}
    for rcpt in rcpt_tos:
        if _base_recipient(rcpt) in wl_rcpts:
            return f"recipient:{_base_recipient(rcpt)}", "recipient"
    return None, ""


def check_whitelist(
    overrides: dict,
    envelope_from: str,
    from_header: str,
    rcpt_tos: list[str],
) -> str | None:
    """Return a human-readable matched-rule string, or None."""
    return match_whitelist(overrides, envelope_from, from_header, rcpt_tos)[0]


# rspamd symbols that authenticate a sender. DMARC_POLICY_ALLOW is the only one
# that proves alignment with the From: header a human actually reads; R_SPF_ALLOW
# authenticates the envelope sender only, so it confirms an envelope match alone.
_DMARC_ALIGNED = "DMARC_POLICY_ALLOW"
_SPF_ALLOW = "R_SPF_ALLOW"


def whitelist_is_authenticated(rule: str, source: str, symbols: dict) -> bool:
    """Whether a whitelist match is backed by sender authentication.

    Both the envelope sender and the From: header are trivially forgeable, and a
    whitelist hit suppresses the AI drop, the rspamd reject and therefore ClamAV
    as well -- so an unauthenticated match is a total filter bypass available to
    anyone who knows one whitelisted domain. Recipient rules are unaffected:
    they match the envelope recipient, which the gateway itself supplies.
    """
    if source == "recipient" or not rule:
        return True
    if _DMARC_ALIGNED in (symbols or {}):
        return True
    return source == "envelope" and _SPF_ALLOW in (symbols or {})


def check_blocklist(overrides: dict, envelope_from: str, from_header: str) -> str | None:
    for sender in (envelope_from, from_header):
        dom = _domain_of(sender)
        if dom:
            hit = _domain_matches(dom, overrides.get("blocklist_domains", []))
            if hit:
                return f"domain:{hit}"
    return None
