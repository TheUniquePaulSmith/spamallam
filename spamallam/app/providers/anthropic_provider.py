"""Anthropic (Claude) Messages API provider."""
from __future__ import annotations

from typing import Any

import httpx

from .base import BaseProvider, ChatResponse, ProviderSettings, ToolCall

BASE_URL = "https://api.anthropic.com/v1"
API_VERSION = "2023-06-01"


class AnthropicProvider(BaseProvider):
    def __init__(self, settings: ProviderSettings):
        super().__init__(settings)
        self.base_url = (settings.base_url or BASE_URL).rstrip("/")

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            timeout=self.settings.timeout_seconds,
            headers={
                "x-api-key": self.settings.api_key,
                "anthropic-version": API_VERSION,
            },
        )

    def _initial_messages(self, system: str, user: str) -> list[dict[str, Any]]:
        # system prompt travels as a top-level param, not a message
        return [{"role": "user", "content": user}]

    async def _request(self, messages, tools, system) -> ChatResponse:
        body: dict[str, Any] = {
            "model": self.settings.model,
            "system": system,
            "messages": messages,
            "max_tokens": self.settings.max_tokens,
            "temperature": 0,
        }
        if tools:
            body["tools"] = [
                {
                    "name": t["name"],
                    "description": t["description"],
                    "input_schema": t["parameters"],
                }
                for t in tools
            ]

        async with self._client() as client:
            resp = await client.post(f"{self.base_url}/messages", json=body)
            resp.raise_for_status()
            data = resp.json()

        text_parts: list[str] = []
        calls: list[ToolCall] = []
        for block in data.get("content", []):
            if block.get("type") == "text":
                text_parts.append(block.get("text", ""))
            elif block.get("type") == "tool_use":
                calls.append(ToolCall(id=block["id"], name=block["name"],
                                      arguments=block.get("input") or {}))
        return ChatResponse(
            text="\n".join(text_parts),
            tool_calls=calls,
            raw=data.get("content", []),
            usage=data.get("usage", {}),
        )

    def _append_assistant(self, messages, resp) -> None:
        messages.append({"role": "assistant", "content": resp.raw})

    def _append_tool_results(self, messages, resp, results) -> None:
        messages.append({
            "role": "user",
            "content": [
                {"type": "tool_result", "tool_use_id": call.id, "content": result_json}
                for call, result_json in results
            ],
        })

    async def ping(self) -> dict[str, Any]:
        async with self._client() as client:
            resp = await client.post(
                f"{self.base_url}/messages",
                json={
                    "model": self.settings.model,
                    "max_tokens": 8,
                    "messages": [{"role": "user", "content": "ping"}],
                },
            )
            resp.raise_for_status()
            data = resp.json()
        return {
            "endpoint": f"{self.base_url}/messages",
            "status": resp.status_code,
            "model": data.get("model"),
            "usage": data.get("usage", {}),
        }

    async def list_models(self) -> list[str]:
        async with self._client() as client:
            resp = await client.get(f"{self.base_url}/models", params={"limit": 100})
            resp.raise_for_status()
            data = resp.json()
        return sorted({m.get("id") for m in data.get("data", []) if m.get("id")})
