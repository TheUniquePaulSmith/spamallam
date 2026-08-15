"""AI analysis engine: summarize -> provider tool-calling loop -> verdict."""
from __future__ import annotations

import json
import re
from typing import Any

from ..config import ENV
from ..pipeline.headers import SpamallamVerdict
from ..providers.factory import load_provider
from ..store.secrets import SecretsBox
from ..store.settings import SETTINGS
from .prompt import SAMPLE_EMAIL, build_user_message, system_prompt
from .summarize import summarize

_JSON_RE = re.compile(r"\{.*\}", re.DOTALL)
_VALID_VERDICTS = {"HAM", "SPAM", "PHISHING", "MALICIOUS"}


def parse_verdict(text: str, model_label: str, tools_used: list[str]) -> SpamallamVerdict:
    match = _JSON_RE.search(text or "")
    if not match:
        raise ValueError(f"provider returned no JSON verdict: {text[:200]!r}")
    data = json.loads(match.group(0))
    verdict = str(data.get("verdict", "")).upper()
    if verdict not in _VALID_VERDICTS:
        raise ValueError(f"provider returned invalid verdict {verdict!r}")
    confidence = max(0.0, min(1.0, float(data.get("confidence", 0.0))))
    return SpamallamVerdict(
        verdict=verdict,
        confidence=confidence,
        category=str(data.get("category", ""))[:120],
        reason=str(data.get("reason", ""))[:500],
        model=model_label,
        tools_used=tools_used,
    )


async def analyze_message(
    raw: bytes,
    envelope_from: str,
    rcpt_tos: list[str],
    client: dict[str, Any],
    recorder,
) -> SpamallamVerdict:
    from ..tools import registry  # lazy: tools pull in optional deps

    cfg = SETTINGS.all()
    box = SecretsBox(ENV.secrets_key)
    provider = load_provider(cfg, box)

    summary = summarize(raw, envelope_from, rcpt_tos, client)
    user = build_user_message(summary, cfg["context"])
    tools = registry.tool_definitions(cfg)
    tools_used: list[str] = []

    async def execute_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        tools_used.append(name)
        return await registry.execute(name, arguments, cfg, box, summary)

    text = await provider.run(
        system_prompt(cfg["ai"]),
        user,
        tools,
        execute_tool,
        recorder,
        log_prompts=bool(cfg["logging"].get("log_prompts", True)),
    )
    return parse_verdict(text, provider.label, sorted(set(tools_used)))


class ListRecorder:
    """Collects events for the admin UI Test button (same interface as MessageTrace)."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def event(self, kind: str, **fields: Any) -> None:
        self.events.append({"kind": kind, **fields})


async def run_provider_test() -> dict[str, Any]:
    """Connectivity check + full sample-email analysis, with the complete
    technical exchange, for the admin UI 'Test' button."""
    cfg = SETTINGS.all()
    box = SecretsBox(ENV.secrets_key)
    result: dict[str, Any] = {"provider": None, "ping": None, "analysis": None}

    provider = load_provider(cfg, box)
    result["provider"] = provider.label

    try:
        result["ping"] = {"ok": True, **await provider.ping()}
    except Exception as exc:  # noqa: BLE001 — the whole point is showing the error
        result["ping"] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        return result

    recorder = ListRecorder()
    try:
        verdict = await analyze_message(
            SAMPLE_EMAIL,
            "security-alert@opensea-verify-wallet.xyz",
            ["you@example.com"],
            {"addr": "203.0.113.66", "name": "", "helo": "mail.opensea-verify-wallet.xyz"},
            recorder,
        )
        result["analysis"] = {
            "ok": True,
            "verdict": verdict.verdict,
            "confidence": verdict.confidence,
            "category": verdict.category,
            "reason": verdict.reason,
            "tools_used": verdict.tools_used,
            "events": recorder.events,
        }
    except Exception as exc:  # noqa: BLE001
        result["analysis"] = {
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
            "events": recorder.events,
        }
    return result
