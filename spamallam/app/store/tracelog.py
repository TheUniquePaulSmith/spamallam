"""Per-message technical trace log (JSONL, one file per day).

Each processed message produces one entry containing the provider called, the
prompt/response, every tool call with its result, the rspamd verdict, and the
final action — the "detailed technical logging" surface of the admin UI.
"""
from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ..config import ENV
from .files import append_jsonl


def _dir() -> Path:
    return ENV.data_dir / "logs" / "messages"


class MessageTrace:
    """Accumulates events for one message, then persists as one JSONL entry."""

    def __init__(self, envelope_from: str, rcpt_tos: list[str], client: dict[str, Any]):
        self.id = uuid.uuid4().hex[:16]
        self.started = time.time()
        self.day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        self.data: dict[str, Any] = {
            "id": self.id,
            "day": self.day,
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "envelope_from": envelope_from,
            "rcpt_tos": rcpt_tos,
            "client": client,
            "events": [],
        }

    def event(self, kind: str, **fields: Any) -> None:
        self.data["events"].append({"t": round(time.time() - self.started, 3), "kind": kind, **fields})

    def finish(self, action: str, verdict: dict[str, Any] | None = None) -> None:
        self.data["action"] = action
        self.data["verdict"] = verdict or {}
        self.data["duration"] = round(time.time() - self.started, 3)
        append_jsonl(_dir() / f"{self.day}.jsonl", json.dumps(self.data, ensure_ascii=False, default=str))


def read_recent(limit: int = 200, day: str | None = None) -> list[dict]:
    files = sorted(_dir().glob("*.jsonl"), reverse=True)
    if day:
        files = [f for f in files if f.stem == day]
    out: list[dict] = []
    for path in files:
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for line in reversed(lines):
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
            if len(out) >= limit:
                return out
    return out


def prune(retention_days: int) -> int:
    """Delete trace files older than the retention window. Returns count removed."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    removed = 0
    if not _dir().exists():
        return 0
    for path in _dir().glob("*.jsonl"):
        try:
            day = datetime.strptime(path.stem, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if day < cutoff:
            path.unlink(missing_ok=True)
            removed += 1
    return removed
