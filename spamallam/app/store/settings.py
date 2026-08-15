"""Runtime settings store — /data/config/settings.yml.

Declarative, file-based, admin-editable. Secret values inside are encrypted
blobs ({"$enc": ...}) handled by SecretsBox; everything else is plain YAML so
a deployment can be reproduced by copying /data/config.
"""
from __future__ import annotations

import copy
import threading
from pathlib import Path
from typing import Any

from ..config import ENV
from .files import read_yaml, write_yaml

DEFAULTS: dict[str, Any] = {
    "ai": {
        "enabled": False,
        # fail_open  -> deliver with X-SpamAllam-Verdict: ERROR header
        # tempfail   -> 451 to postfix, message stays queued and retries
        "failure_mode": "fail_open",
        # DROP (silently discard) when the AI verdict is malicious/phishing at
        # or above this confidence
        "drop_threshold": 0.95,
        "drop_verdicts": ["MALICIOUS", "PHISHING"],
        # Custom system prompt for the analysis LLM; empty = use the built-in
        # default (app.ai.prompt.DEFAULT_SYSTEM_PROMPT)
        "system_prompt": "",
    },
    "provider": {
        # openai | anthropic | custom
        "type": "openai",
        "model": "gpt-4o-mini",
        "base_url": "",          # custom provider only (OpenAI-compatible)
        "api_key": None,         # encrypted blob once set
        "timeout_seconds": 60,
        "max_tokens": 1024,
        "mtls": {
            "enabled": False,
            "pfx": None,         # encrypted blob of the PFX file bytes
            "pfx_password": None,  # encrypted blob
        },
    },
    "context": {
        "organization": "",      # "tell me about your organization/business"
        "expected_mail": "",     # "tell me about the type of mail you expect"
        "per_recipient": {},     # email -> context text
    },
    "tools": {
        "ip_lookup": {"enabled": True, "non_us_note": True},
        "ip_ownership": {"enabled": True, "max_ips": 4},
        "domain_age": {"enabled": True, "young_domain_days": 90},
        "dns_verify": {"enabled": True},
        "web_search": {
            "enabled": False,
            # brave | searxng | custom | provider_native
            "backend": "brave",
            "endpoint": "",
            "api_key": None,     # encrypted blob
        },
        "web_fetch": {
            "enabled": False,
            # curl | playwright | lightpanda
            "backend": "curl",
            "endpoint": "",      # CDP endpoint for lightpanda/playwright-connect
        },
        "shared_provider_check": {"enabled": True},
        "unifi_block": {
            "enabled": False,
            # suggest | auto  (suggest: log + record recommendation only)
            "policy": "suggest",
            "url": "",
            "api_key": None,     # encrypted blob
            "network_list": "spamallam-blocked",
            "max_prefix": 24,    # never roll up wider than /24 (v4)
            "site": "default",
        },
    },
    "overrides": {
        "whitelist_domains": [],
        "whitelist_recipients": [],
        "blocklist_domains": [],
    },
    "logging": {
        "retention_days": 30,
        "log_prompts": True,     # include full prompt/response text in traces
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


class SettingsStore:
    def __init__(self, path: Path | None = None):
        self._path = path or (ENV.data_dir / "config" / "settings.yml")
        self._lock = threading.RLock()

    @property
    def path(self) -> Path:
        return self._path

    def all(self) -> dict[str, Any]:
        with self._lock:
            saved = read_yaml(self._path, {}) or {}
            return _deep_merge(DEFAULTS, saved)

    def get(self, dotted: str, default: Any = None) -> Any:
        node: Any = self.all()
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def set(self, dotted: str, value: Any) -> tuple[Any, Any]:
        """Set a value by dotted path; returns (old, new) for audit logging."""
        with self._lock:
            saved = read_yaml(self._path, {}) or {}
            node = saved
            parts = dotted.split(".")
            for part in parts[:-1]:
                node = node.setdefault(part, {})
                if not isinstance(node, dict):
                    raise ValueError(f"cannot set below non-dict at {part!r} in {dotted!r}")
            old = self.get(dotted)
            node[parts[-1]] = value
            write_yaml(self._path, saved)
            return old, value

    def update(self, values: dict[str, Any]) -> list[tuple[str, Any, Any]]:
        """Set several dotted paths; returns [(path, old, new), ...]."""
        changes = []
        for dotted, value in values.items():
            old, new = self.set(dotted, value)
            if old != new:
                changes.append((dotted, old, new))
        return changes


SETTINGS = SettingsStore()
