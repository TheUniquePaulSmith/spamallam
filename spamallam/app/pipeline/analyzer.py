"""The per-message pipeline: overrides -> (AI analysis <-> rspamd, order
admin-configurable via ai.pipeline_order) -> combined verdict.

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
from . import failure
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

        # 2. Overrides. A sender-domain whitelist hit is only honored once
        # rspamd confirms the sender is who it claims to be -- otherwise anyone
        # who knows one whitelisted domain can forge From: and skip AI, rspamd
        # and ClamAV in one step. That confirmation needs rspamd symbols, so
        # this pre-pass runs before the whitelist header (which would make
        # rspamd short-circuit with set_pre_result) is ever built.
        wl_rule, wl_source = ovr.match_whitelist(
            cfg["overrides"], envelope_from, from_header, rcpt_tos
        )
        pre_rres = None
        if wl_rule and wl_source != "recipient" and cfg["overrides"].get(
            "require_auth_for_whitelist", True
        ):
            # cfg matters here: this result can become the final rres (for
            # whitelisted mail, and in rspamd_first order), so it has to carry
            # the antivirus-failure detection too.
            pre_rres = await self._check_rspamd(
                cleaned, envelope_from, rcpt_tos, client, trace, cfg
            )
            if not ovr.whitelist_is_authenticated(wl_rule, wl_source, pre_rres.symbols):
                trace.event("whitelist_denied", rule=wl_rule, source=wl_source,
                            reason="sender domain failed SPF/DKIM/DMARC authentication",
                            rspamd_ok=pre_rres.ok)
                wl_rule = None

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

        # 3-5. AI analysis + rspamd scoring, order per cfg["ai"]["pipeline_order"]
        # (unrecognized/missing value falls back to "ai_first", today's default).
        if cfg["ai"].get("pipeline_order") == "rspamd_first":
            verdict, rres, tagged, ai_failed = await self._order_rspamd_first(
                cleaned, envelope_from, rcpt_tos, client, trace, cfg, wl_rule, bl_rule, verdict,
                pre_rres,
            )
        else:
            verdict, rres, tagged, ai_failed = await self._order_ai_first(
                cleaned, envelope_from, rcpt_tos, client, trace, cfg, wl_rule, bl_rule, verdict,
                pre_rres,
            )

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
            quarantined = self._save_quarantine(
                cleaned, trace, cfg, verdict, rres, why, envelope_from, rcpt_tos, client, msg_headers,
            )
            trace.finish(DROP, self._verdict_dict(verdict, rres, why, raw_saved, quarantined))
            return Decision(DROP, reason=why), trace

        # 6b. Controls that could not run at all. Deliberately AFTER the drop
        # block: a positive detection is more informative than a failure, and a
        # message rspamd already rejected needs no policy decision. Whitelisted
        # mail is exempt, consistent with ai_drop/rspamd_drop above.
        failed: set[str] = set()
        if cfg["ai"]["enabled"] and ai_failed:
            failed.add("ai")
        if not rres.ok:
            # rspamd being down means the antivirus behind it did not run either.
            failed |= {"rspamd", "antivirus"}
        elif rres.av_failed:
            failed.add("antivirus")

        if failed and not wl_rule:
            policy = failure.strictest(failure.resolve(cfg, c) for c in failed)
            enabled = {"rspamd", "antivirus"} | ({"ai"} if cfg["ai"]["enabled"] else set())
            if failed >= enabled:
                # Nothing inspected this message at all. all_down can only make
                # the outcome stricter, never weaker -- otherwise an operator who
                # set "rspamd: defer" would silently get delivery instead the
                # moment rspamd was the last control standing.
                policy = failure.strictest([policy, failure.resolve(cfg, "all_down")])
            early = self._apply_failure_policy(
                policy, sorted(failed), cleaned, tagged, trace, cfg, verdict, rres,
                envelope_from, rcpt_tos, client, msg_headers,
            )
            if early is not None:
                return early, trace

        # 6c. SPAM warning banner / plaintext->HTML / image breaking / classification
        # footer -- only for mail that's actually delivered (fails open on any error).
        tagged = body.rewrite(tagged, verdict, rres, cfg, trace)

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
        if failed:
            # Informational only, and deliberately NOT part of the HMAC canonical
            # string -- same as X-SpamAllam-Labels. Downstream rules can file on
            # it; nothing is allowed to trust it.
            result_headers.append(("X-SpamAllam-Control-Failure", ", ".join(sorted(failed))))
        final = hdr.prepend_headers(tagged, result_headers)

        trace.finish(DELIVER, self._verdict_dict(verdict, rres, "", failed=sorted(failed)))
        return Decision(DELIVER, message=final), trace

    async def _analyze(self, cleaned, envelope_from, rcpt_tos, client, trace) -> hdr.SpamallamVerdict:
        # Imported lazily so the SMTP path works even if AI deps misbehave
        from ..ai.engine import analyze_message

        return await analyze_message(cleaned, envelope_from, rcpt_tos, client, trace)

    async def _run_ai_with_failure_handling(
        self, cleaned: bytes, envelope_from: str, rcpt_tos: list[str], client: dict[str, Any],
        trace: Any, cfg: dict[str, Any],
    ) -> tuple[hdr.SpamallamVerdict, bool]:
        """Runs AI analysis (or the "disabled" stub) with the configured
        timeout/concurrency limit. Identical behavior regardless of pipeline
        order, since both orders call this one method.

        Returns (verdict, failed). It deliberately does NOT decide what a
        failure means -- that is one central decision in process() (step 6c),
        so that "the AI is down" and "rspamd is down too" can be weighed
        together instead of the first one to fail short-circuiting the rest."""
        if not cfg["ai"]["enabled"]:
            trace.event("ai_skipped", reason="disabled")
            return hdr.SpamallamVerdict(verdict="SKIPPED", reason="AI analysis disabled"), False
        try:
            timeout = cfg["ai"].get("timeout_seconds") or ENV.ai_timeout_seconds
            async with self._sem:
                verdict = await asyncio.wait_for(
                    self._analyze(cleaned, envelope_from, rcpt_tos, client, trace),
                    timeout=timeout,
                )
            return verdict, False
        except Exception as exc:  # noqa: BLE001 — provider/timeout errors -> failure policy
            trace.event("ai_error", error=f"{type(exc).__name__}: {exc}")
            return hdr.SpamallamVerdict(verdict="ERROR", reason=str(exc)[:300]), True

    @staticmethod
    async def _check_rspamd(message_bytes: bytes, envelope_from: str, rcpt_tos: list[str],
                            client: dict[str, Any], trace: Any,
                            cfg: dict[str, Any] | None = None) -> rspamd_client.RspamdResult:
        """rspamd scoring. Never raises -- an outage becomes ok=False, and what
        that MEANS for the message is decided by the failure policy (step 6c)."""
        fail_symbols = frozenset(
            ((cfg or {}).get("failure_policy") or {}).get("antivirus_fail_symbols") or ()
        )
        rres = await rspamd_client.check(
            ENV.rspamd_url,
            message_bytes,
            client_ip=client.get("addr", ""),
            helo=client.get("helo", ""),
            hostname=client.get("name", ""),
            envelope_from=envelope_from,
            rcpt_tos=rcpt_tos,
            av_fail_symbols=fail_symbols,
        )
        if rres.ok:
            trace.event("rspamd", action=rres.action, score=rres.score,
                        symbols={k: (v.get("score") if isinstance(v, dict) else v)
                                 for k, v in rres.symbols.items()})
            if rres.av_failed:
                trace.event("antivirus_error", error=rres.av_error)
        else:
            trace.event("rspamd_error", error=rres.error)
        return rres

    async def _order_ai_first(
        self, cleaned: bytes, envelope_from: str, rcpt_tos: list[str], client: dict[str, Any],
        trace: Any, cfg: dict[str, Any], wl_rule: str | None, bl_rule: str | None,
        verdict: hdr.SpamallamVerdict,
        pre_rres: rspamd_client.RspamdResult | None = None,
    ) -> tuple[hdr.SpamallamVerdict, rspamd_client.RspamdResult, bytes, bool]:
        """Today's default: AI analyzes (unless overridden), THEN rspamd scores
        the signed X-SpamAllam-* headers via its SPAMALLAM_* symbols."""
        ai_failed = False
        if not wl_rule and not bl_rule:
            verdict, ai_failed = await self._run_ai_with_failure_handling(
                cleaned, envelope_from, rcpt_tos, client, trace, cfg,
            )

        tagged = hdr.prepend_headers(cleaned, hdr.build_spamallam_headers(verdict, ENV.header_hmac_key))
        if wl_rule and pre_rres is not None:
            # The whitelist-authentication pre-pass already scored this message,
            # and re-scoring now would only get set_pre_result("no action") back
            # from the Lua plugin -- the pre-pass symbols are strictly more useful.
            return verdict, pre_rres, tagged, ai_failed
        rres = await self._check_rspamd(tagged, envelope_from, rcpt_tos, client, trace, cfg)
        return verdict, rres, tagged, ai_failed

    async def _order_rspamd_first(
        self, cleaned: bytes, envelope_from: str, rcpt_tos: list[str], client: dict[str, Any],
        trace: Any, cfg: dict[str, Any], wl_rule: str | None, bl_rule: str | None,
        verdict: hdr.SpamallamVerdict,
        pre_rres: rspamd_client.RspamdResult | None = None,
    ) -> tuple[hdr.SpamallamVerdict, rspamd_client.RspamdResult, bytes, bool]:
        """rspamd scores the raw message first -- it never sees the
        SPAMALLAM_* symbols for this pass, since the X-SpamAllam-* headers
        don't exist yet at this point. If ai.rspamd_bypass_on_reject is on
        and rspamd already rejects, AI is skipped entirely: the message is
        dropped either way (see rspamd_drop below), so this is a pure cost
        optimization with no effect on the final outcome."""
        ai_failed = False
        # The whitelist-authentication pre-pass scored exactly this message.
        rres = pre_rres or await self._check_rspamd(
            cleaned, envelope_from, rcpt_tos, client, trace, cfg
        )

        bypass = (
            not wl_rule and not bl_rule
            and cfg["ai"]["enabled"]
            and cfg["ai"].get("rspamd_bypass_on_reject")
            and rres.is_reject
        )
        if bypass:
            verdict = hdr.SpamallamVerdict(
                verdict="SKIPPED", category="rspamd_bypass",
                reason="AI analysis skipped: rspamd already rejected (bypass enabled)",
            )
            trace.event("ai_bypass", reason="rspamd_reject", rspamd_action=rres.action, rspamd_score=rres.score)
        elif not wl_rule and not bl_rule:
            verdict, ai_failed = await self._run_ai_with_failure_handling(
                cleaned, envelope_from, rcpt_tos, client, trace, cfg,
            )

        tagged = hdr.prepend_headers(cleaned, hdr.build_spamallam_headers(verdict, ENV.header_hmac_key))
        return verdict, rres, tagged, ai_failed

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
    def _save_quarantine(cleaned: bytes, trace: Any, cfg: dict[str, Any],
                         verdict: hdr.SpamallamVerdict, rres: rspamd_client.RspamdResult,
                         why: str, envelope_from: str, rcpt_tos: list[str],
                         client: dict[str, Any], msg_headers: dict[str, str]) -> bool:
        """Encrypt-at-rest a copy of a dropped message so an admin/user can
        preview, permanently delete, or release it. Best-effort: never blocks
        or changes the drop -- a storage failure is a trace event only.
        Stores `cleaned` (inbound anti-spoof headers removed, our signed
        X-SpamAllam-* headers not yet added) so a release delivers the message
        essentially as the sender sent it."""
        if not cfg.get("quarantine", {}).get("enabled", True):
            return False
        trace_id = getattr(trace, "id", None)
        trace_day = getattr(trace, "day", None)
        if not trace_id or not trace_day:
            return False
        try:
            from ..store import quarantine
            quarantine.save(trace_id, trace_day, {
                "envelope_from": envelope_from,
                "from_header": msg_headers.get("from", ""),
                "subject": msg_headers.get("subject", ""),
                "message_id": msg_headers.get("message_id", ""),
                "rcpt_tos": list(rcpt_tos),
                "client": {"addr": client.get("addr", ""), "name": client.get("name", "")},
                "drop_reason": why,
                "ai_verdict": verdict.verdict,
                "ai_confidence": verdict.confidence,
                "ai_category": verdict.category,
                "ai_reason": verdict.reason,
                "model": verdict.model,
                "rspamd_action": rres.action if rres.ok else f"error: {rres.error}",
                "rspamd_score": rres.score,
            }, cleaned)
            return True
        except Exception as exc:  # noqa: BLE001 -- review aid, must not affect delivery
            trace.event("quarantine_save_error", error=f"{type(exc).__name__}: {exc}")
            return False

    def _apply_failure_policy(
        self, policy: str, failed: list[str], cleaned: bytes, tagged: bytes, trace: Any,
        cfg: dict[str, Any], verdict: hdr.SpamallamVerdict, rres: rspamd_client.RspamdResult,
        envelope_from: str, rcpt_tos: list[str], client: dict[str, Any],
        msg_headers: dict[str, str],
    ) -> Decision | None:
        """Apply the admin's policy for unavailable controls.

        Returns None for deliver_tagged, meaning "carry on with normal
        delivery"; otherwise the Decision to return immediately."""
        why = f"security controls unavailable: {', '.join(failed)}"
        trace.event("control_failure", controls=failed, policy=policy)

        if policy == failure.DEFER:
            trace.finish(TEMPFAIL, self._verdict_dict(verdict, rres, why, failed=failed))
            return Decision(TEMPFAIL, reason=why)

        if policy == failure.QUARANTINE:
            raw_saved = self._save_raw_copy(tagged, trace)
            quarantined = self._save_quarantine(
                cleaned, trace, cfg, verdict, rres, why, envelope_from, rcpt_tos,
                client, msg_headers,
            )
            if not quarantined:
                # Quarantine is off, or this trace has no id/day (the admin Test
                # page). Dropping anyway would silently destroy a message that
                # nothing has inspected, so fall back to the safe direction.
                trace.event("quarantine_unavailable", fallback=failure.DEFER)
                trace.finish(TEMPFAIL, self._verdict_dict(verdict, rres, why, failed=failed))
                return Decision(TEMPFAIL, reason=why)
            trace.finish(DROP, self._verdict_dict(verdict, rres, why, raw_saved, quarantined,
                                                  failed=failed))
            return Decision(DROP, reason=why)

        return None  # deliver_tagged

    @staticmethod
    def _verdict_dict(verdict: hdr.SpamallamVerdict, rres: rspamd_client.RspamdResult,
                      drop_reason: str, raw_saved: bool = False,
                      quarantined: bool = False,
                      failed: list[str] | None = None) -> dict[str, Any]:
        return {
            "failed_controls": failed or [],
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
            "quarantined": quarantined,
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
    """Run a message through the full live pipeline (overrides -> AI/rspamd, in
    whichever order is configured -> combined decision) for the admin UI's
    message-test page, without writing a trace log entry. Uses the real
    configured provider/tools, so tool side effects (e.g. UniFi auto-block)
    still apply exactly as they would for mail."""
    recorder = _TestRecorder()
    decision, _ = await PIPELINE.process(raw, envelope_from, rcpt_tos, client, trace=recorder)
    return {
        "action": decision.action,
        "reason": decision.reason,
        "verdict": recorder.verdict,
        "events": recorder.events,
    }
