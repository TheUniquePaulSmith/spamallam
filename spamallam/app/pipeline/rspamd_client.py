"""HTTP client for rspamd's /checkv2 endpoint (no milter anywhere).

We pass the ORIGINAL client metadata (IP, HELO, envelope) as request headers so
rspamd evaluates SPF/RBL/etc. against the internet sender, not spamallam.
https://docs.rspamd.com/developers/protocol/
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx


@dataclass
class RspamdResult:
    ok: bool
    action: str = ""            # no action | greylist | add header | rewrite subject | reject ...
    score: float = 0.0
    required_score: float = 0.0
    symbols: dict[str, Any] = field(default_factory=dict)
    error: str = ""

    @property
    def is_reject(self) -> bool:
        return self.ok and self.action == "reject"

    @property
    def is_spam(self) -> bool:
        return self.ok and self.action in ("add header", "rewrite subject", "greylist", "reject")

    def spamd_result_header(self) -> str:
        """Compact X-Spamd-Result-style summary (we add headers ourselves since
        rspamd's milter_headers module is not in the path)."""
        parts = [f"default: {'True' if self.is_spam else 'False'} "
                 f"[{self.score:.2f} / {self.required_score:.2f}]"]
        for name, info in sorted(self.symbols.items()):
            sc = info.get("score", 0) if isinstance(info, dict) else 0
            parts.append(f"{name}({sc:.2f})")
        return "; ".join(parts)


async def check(
    rspamd_url: str,
    raw_message: bytes,
    *,
    client_ip: str = "",
    helo: str = "",
    hostname: str = "",
    envelope_from: str = "",
    rcpt_tos: list[str] | None = None,
    timeout: float = 30.0,
) -> RspamdResult:
    headers: list[tuple[str, str]] = [("Pass", "all")]
    if client_ip:
        headers.append(("IP", client_ip))
    if helo:
        headers.append(("Helo", helo))
    if hostname:
        headers.append(("Hostname", hostname))
    if envelope_from:
        headers.append(("From", envelope_from))
    for rcpt in rcpt_tos or []:
        headers.append(("Rcpt", rcpt))

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(
                f"{rspamd_url.rstrip('/')}/checkv2",
                content=raw_message,
                headers=headers,
            )
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:  # noqa: BLE001 — any failure means "rspamd unavailable"
        return RspamdResult(ok=False, error=f"{type(exc).__name__}: {exc}")

    return RspamdResult(
        ok=True,
        action=data.get("action", ""),
        score=float(data.get("score", 0.0)),
        required_score=float(data.get("required_score", 0.0)),
        symbols=data.get("symbols", {}) or {},
    )
