"""Append-only admin audit log: who changed what, when, old -> new.

Secret values are redacted before they reach this file — the log records THAT
a secret changed, never its value.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from ..config import ENV
from .files import append_jsonl
from .secrets import redact


def audit_path() -> Path:
    return ENV.data_dir / "logs" / "audit.jsonl"


def record(actor: str, action: str, detail: dict | None = None) -> None:
    entry = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "actor": actor,
        "action": action,
        "detail": redact(detail or {}),
    }
    append_jsonl(audit_path(), json.dumps(entry, ensure_ascii=False))


def record_changes(actor: str, changes: list[tuple[str, object, object]]) -> None:
    for path, old, new in changes:
        record(actor, "setting.change", {"setting": path, "old": old, "new": new})


def tail(limit: int = 500) -> list[dict]:
    try:
        lines = audit_path().read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return []
    out = []
    for line in lines[-limit:]:
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return list(reversed(out))
