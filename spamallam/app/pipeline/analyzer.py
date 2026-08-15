"""The per-message pipeline: overrides -> AI analysis -> rspamd -> combined verdict.

postfix (content_filter) -> spamallam SMTP :10026 -> THIS -> re-inject :10025
"""
from __future__ import annotations

import asyncio
import email
import email.policy
from dataclasses import dataclass
from typing import Any

from ..config import ENV
from ..store.settings import SETTINGS
from ..store.tracelog import MessageTrace
from . import headers as hdr
from . import overrides as ovr
from . import rspamd_client

# Decision.action values
DELIVER = "deliver"
DROP = "drop"
TEMPFAIL = "tempfail"


@dataclass
class Decision:
    action: str
    message: bytes | None = None   # final bytes to re-inject when action == deliver
    reason: str = ""


def _from_header_of(raw: bytes) -> str:
    try:
        msg = email.message_from_bytes(
            hdr.split_message(raw)[0], policy=email.policy.default
        )
        return str(msg.get("From", ""))
    except Exception:  # noqa: BLE001 — malformed headers must not kill the pipeline
        return ""


class Pipeline:
    def __init__(self) -> None:
        self._sem = asyncio.Semaphore(ENV.max_concurrent_analyses)

    async def process(
        self,
        raw: bytes,
        envelope_from: str,
        rcpt_tos: list[str],
        client: dict[str, Any],
    ) -> tuple[Decision, MessageTrace]:
        trace = MessageTrace(envelope_from, rcpt_tos, client)
        cfg = SETTINGS.all()

        # 1. Anti-spoofing: remove any inbound spam-analysis headers
        cleaned, removed = hdr.strip_spam_headers(raw)
        if removed:
            trace.event(
                "headers_stripped",
                count=len(removed),
                headers=[line.decode("utf-8", "replace")[:200] for line in removed[:10]],
            )

        from_header = _from_header_of(cleaned)
        verdict = hdr.SpamallamVerdict()

        # 2. Overrides
        wl_rule = ovr.check_whitelist(cfg["overrides"], envelope_from, from_header, rcpt_tos)
        bl_rule = None
        if wl_rule:
            verdict.verdict = "HAM"
            verdict.confidence = 1.0
            verdict.category = "whitelisted"
            verdict.reason = f"admin whitelist override ({wl_rule})"
            verdict.whitelisted = f"yes; rule={wl_rule}"
            trace.event("whitelist", rule=wl_rule)
        else:
            bl_rule = ovr.check_blocklist(cfg["overrides"], envelope_from, from_header)
            if bl_rule:
                verdict.verdict = "SPAM"
                verdict.confidence = 1.0
                verdict.category = "blocklisted"
                verdict.reason = f"admin blocklist override ({bl_rule})"
                trace.event("blocklist", rule=bl_rule)

        # 3. AI analysis (skipped for overridden mail)
        if not wl_rule and not bl_rule:
            if cfg["ai"]["enabled"]:
                try:
                    async with self._sem:
                        verdict = await asyncio.wait_for(
                            self._analyze(cleaned, envelope_from, rcpt_tos, client, trace),
                            timeout=ENV.ai_timeout_seconds,
                        )
                except Exception as exc:  # noqa: BLE001 — provider/timeout errors -> failure mode
                    trace.event("ai_error", error=f"{type(exc).__name__}: {exc}")
                    if cfg["ai"]["failure_mode"] == "tempfail":
                        trace.finish(TEMPFAIL, {"error": str(exc)})
                        return Decision(TEMPFAIL, reason="AI analysis failed"), trace
                    verdict = hdr.SpamallamVerdict(verdict="ERROR", reason=str(exc)[:300])
            else:
                verdict = hdr.SpamallamVerdict(verdict="SKIPPED", reason="AI analysis disabled")
                trace.event("ai_skipped", reason="disabled")

        # 4. Add signed X-SpamAllam headers
        tagged = hdr.prepend_headers(
            cleaned, hdr.build_spamallam_headers(verdict, ENV.header_hmac_key)
        )

        # 5. rspamd scoring (always fail-open: rspamd outage must not lose mail)
        rres = await rspamd_client.check(
            ENV.rspamd_url,
            tagged,
            client_ip=client.get("addr", ""),
            helo=client.get("helo", ""),
            hostname=client.get("name", ""),
            envelope_from=envelope_from,
            rcpt_tos=rcpt_tos,
        )
        if rres.ok:
            trace.event("rspamd", action=rres.action, score=rres.score,
                        symbols={k: (v.get("score") if isinstance(v, dict) else v)
                                 for k, v in rres.symbols.items()})
        else:
            trace.event("rspamd_error", error=rres.error)

        # 6. Combined verdict
        drop_verdicts = {v.upper() for v in cfg["ai"]["drop_verdicts"]}
        ai_drop = (
            not wl_rule
            and verdict.verdict.upper() in drop_verdicts
            and verdict.confidence >= float(cfg["ai"]["drop_threshold"])
        )
        rspamd_drop = rres.is_reject and not wl_rule

        if ai_drop or rspamd_drop:
            why = "ai high-confidence threat" if ai_drop else f"rspamd reject (score {rres.score:.1f})"
            trace.finish(DROP, self._verdict_dict(verdict, rres, why))
            return Decision(DROP, reason=why), trace

        # 7. Result headers for downstream mail rules (MailPlus etc.)
        result_headers: list[tuple[str, str]] = []
        if rres.ok:
            spam = rres.is_spam
            result_headers += [
                ("X-Spamd-Result", rres.spamd_result_header()),
                ("X-Spam-Score", f"{rres.score:.2f}"),
                ("X-Spam-Status", f"{'Yes' if spam else 'No'}, score={rres.score:.2f} "
                                  f"required={rres.required_score:.2f}"),
            ]
            if spam:
                result_headers.append(("X-Spam-Flag", "YES"))
        else:
            result_headers.append(("X-SpamAllam-Rspamd", "error"))
        final = hdr.prepend_headers(tagged, result_headers)

        trace.finish(DELIVER, self._verdict_dict(verdict, rres, ""))
        return Decision(DELIVER, message=final), trace

    async def _analyze(self, cleaned, envelope_from, rcpt_tos, client, trace) -> hdr.SpamallamVerdict:
        # Imported lazily so the SMTP path works even if AI deps misbehave
        from ..ai.engine import analyze_message

        return await analyze_message(cleaned, envelope_from, rcpt_tos, client, trace)

    @staticmethod
    def _verdict_dict(verdict: hdr.SpamallamVerdict, rres: rspamd_client.RspamdResult,
                      drop_reason: str) -> dict[str, Any]:
        return {
            "ai_verdict": verdict.verdict,
            "ai_confidence": verdict.confidence,
            "ai_category": verdict.category,
            "ai_reason": verdict.reason,
            "model": verdict.model,
            "tools_used": verdict.tools_used,
            "whitelisted": verdict.whitelisted,
            "rspamd_action": rres.action if rres.ok else f"error: {rres.error}",
            "rspamd_score": rres.score,
            "drop_reason": drop_reason,
        }


PIPELINE = Pipeline()
