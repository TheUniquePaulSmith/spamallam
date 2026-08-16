"""Provider abstraction: OpenAI, Anthropic (Claude), or any OpenAI-compatible
custom endpoint (optionally with mTLS client-certificate auth).

Each provider implements the same tool-calling loop contract; the engine stays
wire-format agnostic.
"""
from __future__ import annotations

import abc
import json
import ssl
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Protocol


@dataclass
class ProviderSettings:
    type: str                       # openai | anthropic | custom
    model: str
    api_key: str = ""
    base_url: str = ""
    timeout_seconds: float = 60.0
    max_tokens: int = 1024
    ssl_context: ssl.SSLContext | None = None   # custom provider mTLS


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class ChatResponse:
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    raw: Any = None                 # provider-native response (for appending)
    usage: dict[str, Any] = field(default_factory=dict)


class Recorder(Protocol):
    def event(self, kind: str, **fields: Any) -> None: ...


ToolExecutor = Callable[[str, dict[str, Any]], Awaitable[dict[str, Any]]]

VERDICT_TOOL_NAME = "submit_verdict"

# Always appended to whatever real (admin-toggleable) tools are offered, so the
# model reports its final classification as a structured tool call — parsed by
# the wire protocol's own tool-call machinery — instead of free text we'd have
# to regex out of a chat message (fences, stray prose, etc).
VERDICT_TOOL: dict[str, Any] = {
    "name": VERDICT_TOOL_NAME,
    "description": (
        "Submit your final classification for this e-mail. Call this ONLY once "
        "your investigation is complete — do not call it in the same turn as any "
        "other tool. If you still need another tool's result, call that tool by "
        "itself, review the result, and call submit_verdict alone afterwards."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "verdict": {"type": "string", "enum": ["HAM", "SPAM", "PHISHING", "MALICIOUS"]},
            "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
            "category": {
                "type": "string",
                "description": "short label, e.g. 'credential phishing', 'newsletter', 'BEC gift-card', 'cold B2B'",
            },
            "reason": {
                "type": "string",
                "description": "one or two sentences citing the concrete evidence that decided the verdict",
            },
        },
        "required": ["verdict", "confidence", "category", "reason"],
    },
}


class BaseProvider(abc.ABC):
    def __init__(self, settings: ProviderSettings):
        self.settings = settings

    @property
    def label(self) -> str:
        return f"{self.settings.type}/{self.settings.model}"

    # ---- wire-format hooks -------------------------------------------------
    @abc.abstractmethod
    def _initial_messages(self, system: str, user: str) -> list[dict[str, Any]]: ...

    @abc.abstractmethod
    async def _request(self, messages: list[dict[str, Any]],
                       tools: list[dict[str, Any]], system: str) -> ChatResponse: ...

    @abc.abstractmethod
    def _append_assistant(self, messages: list[dict[str, Any]], resp: ChatResponse) -> None: ...

    @abc.abstractmethod
    def _append_tool_results(self, messages: list[dict[str, Any]], resp: ChatResponse,
                             results: list[tuple[ToolCall, str]]) -> None: ...

    @abc.abstractmethod
    async def ping(self) -> dict[str, Any]:
        """Cheap connectivity check; raises on failure, returns details on success."""

    async def list_models(self) -> list[str]:
        """Model IDs available to this provider/key, for the admin UI's model
        picker. Raises on failure (surfaced to the admin as-is)."""
        raise NotImplementedError(f"{self.settings.type} provider cannot list models")

    # ---- shared tool-calling loop ------------------------------------------
    async def run(
        self,
        system: str,
        user: str,
        tools: list[dict[str, Any]],
        execute_tool: ToolExecutor,
        recorder: Recorder,
        max_iterations: int = 8,
        log_prompts: bool = True,
    ) -> str:
        tools = [*tools, VERDICT_TOOL]
        messages = self._initial_messages(system, user)
        recorder.event(
            "ai_request", provider=self.label,
            system=system if log_prompts else f"<{len(system)} chars>",
            user=user if log_prompts else f"<{len(user)} chars>",
            tools=[t["name"] for t in tools],
        )
        for iteration in range(max_iterations):
            resp = await self._request(messages, tools, system)
            recorder.event(
                "ai_response", provider=self.label, iteration=iteration,
                text=resp.text if log_prompts else f"<{len(resp.text)} chars>",
                tool_calls=[{"name": c.name, "arguments": c.arguments} for c in resp.tool_calls],
                usage=resp.usage,
            )
            if not resp.tool_calls:
                # No tool call at all (model answered in plain text instead) — fall
                # back to whatever it wrote; parse_verdict's regex extraction is the
                # safety net for this case.
                return resp.text

            verdict_call = next((c for c in resp.tool_calls if c.name == VERDICT_TOOL_NAME), None)
            other_calls = [c for c in resp.tool_calls if c.name != VERDICT_TOOL_NAME]

            if verdict_call and not other_calls:
                # Clean final turn: submit_verdict called alone.
                return json.dumps(verdict_call.arguments, ensure_ascii=False, default=str)

            self._append_assistant(messages, resp)
            results: list[tuple[ToolCall, str]] = []
            for call in other_calls:
                try:
                    result = await execute_tool(call.name, call.arguments)
                except Exception as exc:  # noqa: BLE001 — surface tool errors to the model
                    result = {"error": f"{type(exc).__name__}: {exc}"}
                recorder.event("tool_call", tool=call.name, arguments=call.arguments, result=result)
                results.append((call, json.dumps(result, ensure_ascii=False, default=str)))

            if verdict_call:
                # Premature: submit_verdict was bundled with other tool calls in the
                # same turn. Every issued tool_call needs a matching result (the wire
                # protocols require it), so answer it with a nudge rather than
                # dropping it, and keep looping so the model can re-submit once it
                # has seen the other tools' results.
                nudge = {"note": "Ignored: you also requested other tool calls in this "
                                  "turn. Review their results, then call submit_verdict "
                                  "alone (with no other tool calls) to finalize."}
                recorder.event("tool_call", tool=VERDICT_TOOL_NAME,
                              arguments=verdict_call.arguments, result=nudge)
                results.append((verdict_call, json.dumps(nudge)))

            self._append_tool_results(messages, resp, results)

        raise RuntimeError(f"provider did not converge within {max_iterations} tool iterations")
