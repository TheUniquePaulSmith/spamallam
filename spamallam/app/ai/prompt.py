"""Analysis prompt construction, including admin-provided organization context
and per-recipient expectations."""
from __future__ import annotations

import json
from email.utils import parseaddr
from typing import Any

SYSTEM_PROMPT = """You are SpamAllam, an e-mail security analyst protecting a small mail server.
You receive one inbound e-mail (summarized) and must classify it.

Classify into exactly one verdict:
- HAM: legitimate mail the recipient plausibly wants (including expected bulk/newsletter mail).
- SPAM: unsolicited bulk/commercial mail, irrelevant offers, scams of low sophistication.
- PHISHING: attempts to steal credentials/money by impersonating a person, brand or service.
- MALICIOUS: malware delivery, extortion, or other actively harmful content.

Rules:
1. Use the provided tools (if any) to gather evidence: sender IP reputation/geo,
   domain registration age, DNS/SPF alignment, brand-vs-sender mismatch, whether a
   shared bulk-mail provider (SendGrid, Amazon SES, Mailchimp, ACS...) was used.
2. NEVER request fetching of any URL that appears inside the e-mail body. Those links
   may be tracking or activation links. Validating a sender's official website found
   via search is allowed; clicking message links is not.
3. Mail claiming to be a well-known service must align: sending domain, return-path
   and infrastructure should belong to that service. Mismatch => PHISHING.
4. Newly registered sender domains and unusual origin countries increase suspicion.
5. Use the organization/recipient context to judge relevance: mail that looks like
   spam but matches the recipient's stated expectations may be HAM; polished mail
   that references the organization but does not fit its stated workflows may be
   spear-phishing.
6. Confidence is YOUR certainty in the verdict (0.0-1.0). Reserve >= 0.95 for
   unambiguous cases — the gateway silently drops high-confidence PHISHING/MALICIOUS.

When you have enough evidence, answer with ONLY a JSON object, no other text:
{"verdict": "HAM|SPAM|PHISHING|MALICIOUS", "confidence": 0.0-1.0,
 "category": "<short category, e.g. 'credential phishing', 'newsletter', 'timeshare offer'>",
 "reason": "<one or two sentences of evidence-based justification>"}
"""


def _context_block(context_cfg: dict[str, Any], rcpt_tos: list[str]) -> str:
    parts: list[str] = []
    org = (context_cfg.get("organization") or "").strip()
    expected = (context_cfg.get("expected_mail") or "").strip()
    if org:
        parts.append(f"About the organization receiving this mail:\n{org}")
    if expected:
        parts.append(f"Mail the organization expects to receive:\n{expected}")
    per_rcpt = context_cfg.get("per_recipient") or {}
    normalized = {k.lower().strip(): v for k, v in per_rcpt.items() if (v or "").strip()}
    for rcpt in rcpt_tos:
        addr = parseaddr(rcpt)[1].lower()
        base = addr.split("+", 1)[0] + "@" + addr.rsplit("@", 1)[-1] if "@" in addr else addr
        for candidate in (addr, base):
            if candidate in normalized:
                parts.append(f"Expectations for recipient {candidate}:\n{normalized[candidate]}")
                break
    return "\n\n".join(parts)


def build_user_message(summary: dict[str, Any], context_cfg: dict[str, Any]) -> str:
    ctx = _context_block(context_cfg, summary.get("rcpt_tos", []))
    blocks = []
    if ctx:
        blocks.append("=== RECIPIENT / ORGANIZATION CONTEXT ===\n" + ctx)
    blocks.append(
        "=== E-MAIL TO CLASSIFY (URLs listed are NEVER to be fetched) ===\n"
        + json.dumps(summary, indent=2, ensure_ascii=False)
    )
    return "\n\n".join(blocks)


# A deliberately obvious phishing sample used by the admin UI "Test" button.
SAMPLE_EMAIL = b"""\
From: "OpenSea Support" <security-alert@opensea-verify-wallet.xyz>
Reply-To: recover@opensea-verify-wallet.xyz
To: you@example.com
Subject: [Action Required] Your OpenSea wallet will be suspended in 24 hours
Date: Fri, 15 Aug 2025 09:00:00 -0400
Message-ID: <test-sample@opensea-verify-wallet.xyz>
Content-Type: text/plain; charset=utf-8

Dear customer,

We detected unusual activity on your OpenSea account. Your NFT wallet will be
permanently suspended within 24 hours unless you verify your seed phrase now:

    https://opensea-verify-wallet.xyz/recover?session=8f3a

Failure to act will result in loss of your assets.

OpenSea Trust & Safety
"""
