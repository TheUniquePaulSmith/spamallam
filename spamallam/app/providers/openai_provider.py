"""OpenAI chat-completions provider. Also the base for any OpenAI-compatible
custom endpoint (local Ollama/vLLM/LM Studio, gateways, ...)."""
from __future__ import annotations

import json
from typing import Any

import httpx

from .base import BaseProvider, ChatResponse, ProviderSettings, ToolCall

DEFAULT_BASE_URL = "https://api.openai.com/v1"


class OpenAIProvider(BaseProvider):
    def __init__(self, settings: ProviderSettings):
        super().__init__(settings)
        self.base_url = (settings.base_url or DEFAULT_BASE_URL).rstrip("/")

    def _client(self) -> httpx.AsyncClient:
        headers = {}
        if self.settings.api_key:
            headers["Authorization"] = f"Bearer {self.settings.api_key}"
        kwargs: dict[str, Any] = {
            "timeout": self.settings.timeout_seconds,
            "headers": headers,
        }
        if self.settings.ssl_context is not None:
            kwargs["verify"] = self.settings.ssl_context
        return httpx.AsyncClient(**kwargs)

    def _initial_messages(self, system: str, user: str) -> list[dict[str, Any]]:
        return [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]

    async def _request(self, messages, tools, system) -> ChatResponse:
        body: dict[str, Any] = {
            "model": self.settings.model,
            "messages": messages,
            "max_tokens": self.settings.max_tokens,
            "temperature": 0,
        }
        if tools:
            body["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": t["name"],
                        "description": t["description"],
                        "parameters": t["parameters"],
                    },
                }
                for t in tools
            ]
            body["tool_choice"] = "auto"

        async with self._client() as client:
            resp = await client.post(f"{self.base_url}/chat/completions", json=body)
            resp.raise_for_status()
            data = resp.json()

        message = data["choices"][0]["message"]
        calls = []
        for tc in message.get("tool_calls") or []:
            try:
                args = json.loads(tc["function"].get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}
            calls.append(ToolCall(id=tc.get("id", ""), name=tc["function"]["name"], arguments=args))
        return ChatResponse(
            text=message.get("content") or "",
            tool_calls=calls,
            raw=message,
            usage=data.get("usage", {}),
        )

    def _append_assistant(self, messages, resp) -> None:
        messages.append(resp.raw)

    def _append_tool_results(self, messages, resp, results) -> None:
        for call, result_json in results:
            messages.append({"role": "tool", "tool_call_id": call.id, "content": result_json})

    async def ping(self) -> dict[str, Any]:
        async with self._client() as client:
            resp = await client.get(f"{self.base_url}/models")
            resp.raise_for_status()
            data = resp.json()
        models = [m.get("id") for m in data.get("data", [])][:25]
        return {
            "endpoint": f"{self.base_url}/models",
            "status": resp.status_code,
            "models_visible": models,
            "configured_model_listed": self.settings.model in models if models else None,
        }
