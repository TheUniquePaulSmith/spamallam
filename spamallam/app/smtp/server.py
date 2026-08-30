"""SMTP front/back door of spamallam.

postfix hands each queued message to us on :10026 (content_filter transport
with XFORWARD so we see the ORIGINAL internet client, not postfix). After the
pipeline runs we either re-inject the tagged message into postfix :10025 for
delivery, silently drop it, or tempfail so postfix retries later.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from aiosmtpd.smtp import SMTP, Session, syntax

from ..config import ENV
from ..deliver import reinject
from ..pipeline.analyzer import DELIVER, DROP, PIPELINE

log = logging.getLogger("spamallam.smtp")


def _xtext_decode(value: str) -> str:
    """Minimal xtext decoding for XFORWARD attribute values (+XX hex escapes)."""
    out, i = [], 0
    while i < len(value):
        if value[i] == "+" and i + 2 < len(value) + 1 and i + 3 <= len(value):
            try:
                out.append(chr(int(value[i + 1 : i + 3], 16)))
                i += 3
                continue
            except ValueError:
                pass
        out.append(value[i])
        i += 1
    return "".join(out)


def _peer_is_trusted(session: Any) -> bool:
    """Whether this connection came from the edge MTA.

    ENV.xforward_trusted_peers is normally the postfix container's address on
    the filter network. Empty means "trust any peer", which is the pre-
    segmentation behavior and is only safe when nothing else can reach this
    port at all.
    """
    trusted = ENV.xforward_trusted_peers
    if not trusted:
        return True
    peer = getattr(session, "peer", None)
    return bool(peer) and str(peer[0]) in trusted


class SpamallamSMTP(SMTP):
    """aiosmtpd SMTP with postfix XFORWARD support."""

    XFORWARD_ATTRS = {"NAME", "ADDR", "PORT", "PROTO", "HELO", "SOURCE", "IDENT"}

    @syntax("XFORWARD attr=value [attr=value ...]")
    async def smtp_XFORWARD(self, arg: str) -> None:
        # XFORWARD rewrites the client IP/HELO that rspamd evaluates SPF and the
        # RBLs against, and that the AI sees as the sender's origin -- postfix's
        # own equivalent (smtpd_authorized_xforward_hosts) exists for exactly
        # this reason. Only the edge MTA may use it.
        if not _peer_is_trusted(self.session):
            await self.push("550 5.7.1 XFORWARD not authorized from this client")
            return
        if not arg:
            await self.push("501 5.5.4 Syntax: XFORWARD attr=value")
            return
        session: Session = self.session
        store: dict[str, str] = getattr(session, "xforward", {})
        for pair in arg.split():
            if "=" not in pair:
                await self.push("501 5.5.4 Syntax: XFORWARD attr=value")
                return
            key, _, value = pair.partition("=")
            key = key.upper()
            if key not in self.XFORWARD_ATTRS:
                await self.push(f"501 5.5.4 Unknown XFORWARD attribute {key}")
                return
            if value.upper() != "[UNAVAILABLE]":
                store[key] = _xtext_decode(value)
        session.xforward = store
        await self.push("250 2.0.0 Ok")


class SpamallamHandler:
    async def handle_EHLO(self, server, session, envelope, hostname, responses):
        session.host_name = hostname
        # Advertise XFORWARD so postfix forwards the original client details
        return [*responses[:-1], "250-XFORWARD NAME ADDR PORT PROTO HELO SOURCE", responses[-1]]

    async def handle_DATA(self, server, session, envelope) -> str:
        xf: dict[str, str] = getattr(session, "xforward", {}) or {}
        client: dict[str, Any] = {
            "addr": xf.get("ADDR", ""),
            "name": xf.get("NAME", ""),
            "helo": xf.get("HELO", ""),
            "proto": xf.get("PROTO", ""),
            "source": xf.get("SOURCE", ""),
        }
        raw: bytes = envelope.original_content or envelope.content
        mail_from = envelope.mail_from or ""
        rcpt_tos = list(envelope.rcpt_tos)

        try:
            decision, trace = await PIPELINE.process(raw, mail_from, rcpt_tos, client)
        except Exception:  # noqa: BLE001 — never lose mail to a pipeline bug
            log.exception("pipeline crashed; tempfailing so postfix retries")
            return "451 4.3.0 Temporary internal error"

        if decision.action == DROP:
            # Accept then discard: sender gets no bounce (no backscatter),
            # postfix considers it delivered. The trace log has the details.
            log.warning("DROP %s from=%s rcpt=%s reason=%s",
                        trace.id, mail_from, rcpt_tos, decision.reason)
            return "250 2.0.0 Ok: queued"

        if decision.action != DELIVER:
            return "451 4.3.0 Analysis temporarily unavailable, try again later"

        try:
            await asyncio.get_running_loop().run_in_executor(
                None, reinject, mail_from, rcpt_tos, decision.message
            )
        except Exception as exc:  # noqa: BLE001
            log.error("re-injection failed (%s); tempfailing", exc)
            return "451 4.3.0 Re-injection failed, try again later"

        log.info("DELIVER %s from=%s rcpt=%s", trace.id, mail_from, rcpt_tos)
        return "250 2.0.0 Ok: queued"


async def start_smtp_server() -> asyncio.AbstractServer:
    handler = SpamallamHandler()

    def factory() -> SpamallamSMTP:
        return SpamallamSMTP(
            handler,
            hostname=ENV.mail_hostname,
            ident="spamallam",
            enable_SMTPUTF8=True,
            # postfix already enforces MESSAGE_SIZE_LIMIT; add headroom here
            data_size_limit=512 * 1024 * 1024,
        )

    server = await asyncio.get_running_loop().create_server(
        factory, host=ENV.smtp_listen_host, port=ENV.smtp_listen_port
    )
    log.info("SMTP content filter listening on %s:%d",
             ENV.smtp_listen_host, ENV.smtp_listen_port)
    return server
