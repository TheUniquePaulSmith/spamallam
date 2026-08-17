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
from ..store import rawlog
from ..store.settings import SETTINGS
from ..store.tracelog import MessageTrace
from . import body
from . import headers as hdr
from . import overrides as ovr
from . import rawcopy
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


def _headers_of(raw: bytes) -> dict[str, str]:
    try:
        msg = email.message_from_bytes(
            hdr.split_message(raw)[0], policy=email.policy.default
        )
        return {
            "from": str(msg.get("From", "")),
            "subject": str(msg.get("Subject", "")),
            "message_id": str(msg.get("Message-ID", "")),
        }
    except Exception:  # noqa: BLE001 — malformed headers must not kill the pipeline
        return {"from": "", "subject": "", "message_id": ""}


class Pipeline:
    def __init__(self) -> None:
        self._sem = asyncio.Semaphore(ENV.max_concurrent_analyses)

    async def process(
        self,
        raw: bytes,
        envelope_from: str,
        rcpt_tos: list[str],
        client: dict[str, Any],
        trace: Any = None,
    ) -> tuple[Decision, Any]:
        if trace is None:
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

        msg_headers = _headers_of(cleaned)
        from_header = msg_headers["from"]
        if hasattr(trace, "data"):
            trace.data["message"] = msg_headers
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
                    timeout = cfg["ai"].get("timeout_seconds") or ENV.ai_timeout_seconds
                    async with self._sem:
                        verdict = await asyncio.wait_for(
                            self._analyze(cleaned, envelope_from, rcpt_tos, client, trace),
                            timeout=timeout,
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
            raw_saved = self._save_raw_copy(tagged, trace)
            trace.finish(DROP, self._verdict_dict(verdict, rres, why, raw_saved))
            return Decision(DROP, reason=why), trace

        # 6b. SPAM warning banner / plaintext->HTML / image breaking / classification
        # footer -- only for mail that's actually delivered (fails open on any error).
        tagged = body.rewrite(tagged, verdict, cfg, trace)

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
    def _save_raw_copy(tagged: bytes, trace: Any) -> bool:
        """Best-effort attachment-stripped .eml for admin review of a drop.
        Never blocks/affects the drop decision itself -- storage or parse
        failures are logged as a trace event and otherwise ignored."""
        trace_id = getattr(trace, "id", None)
        trace_day = getattr(trace, "day", None)
        if not trace_id or not trace_day:
            return False
        try:
            rawlog.save(trace_id, trace_day, rawcopy.strip_for_review(tagged))
            return True
        except Exception as exc:  # noqa: BLE001 -- logging aid, must not affect delivery
            trace.event("raw_save_error", error=f"{type(exc).__name__}: {exc}")
            return False

    @staticmethod
    def _verdict_dict(verdict: hdr.SpamallamVerdict, rres: rspamd_client.RspamdResult,
                      drop_reason: str, raw_saved: bool = False) -> dict[str, Any]:
        return {
            "ai_verdict": verdict.verdict,
            "ai_confidence": verdict.confidence,
            "ai_category": verdict.category,
            "ai_reason": verdict.reason,
            "model": verdict.model,
            "labels": verdict.labels,
            "tools_used": verdict.tools_used,
            "whitelisted": verdict.whitelisted,
            "rspamd_action": rres.action if rres.ok else f"error: {rres.error}",
            "rspamd_score": rres.score,
            "drop_reason": drop_reason,
            "raw_saved": raw_saved,
        }


PIPELINE = Pipeline()


class _TestRecorder:
    """In-memory stand-in for MessageTrace, for the admin UI message-test page:
    same .event()/.finish() interface, but never persisted to the trace log."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self.action = ""
        self.verdict: dict[str, Any] = {}

    def event(self, kind: str, **fields: Any) -> None:
        self.events.append({"kind": kind, **fields})

    def finish(self, action: str, verdict: dict[str, Any] | None = None) -> None:
        self.action = action
        self.verdict = verdict or {}


async def process_test(
    raw: bytes, envelope_from: str, rcpt_tos: list[str], client: dict[str, Any]
) -> dict[str, Any]:
    """Run a message through the full live pipeline (overrides -> AI -> rspamd ->
    combined decision) for the admin UI's message-test page, without writing a
    trace log entry. Uses the real configured provider/tools, so tool side
    effects (e.g. UniFi auto-block) still apply exactly as they would for mail."""
    recorder = _TestRecorder()
    decision, _ = await PIPELINE.process(raw, envelope_from, rcpt_tos, client, trace=recorder)
    return {
        "action": decision.action,
        "reason": decision.reason,
        "verdict": recorder.verdict,
        "events": recorder.events,
    }
