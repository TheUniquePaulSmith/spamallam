"""Per-message technical trace log (JSONL, one file per day).

Each processed message produces one entry containing the provider called, the
prompt/response, every tool call with its result, the rspamd verdict, and the
final action — the "detailed technical logging" surface of the admin UI.
"""
from __future__ import annotations

import json
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ..config import ENV
from .files import append_jsonl


def _dir() -> Path:
    return ENV.data_dir / "logs" / "messages"


# In-memory cache of the most recent trace entries (newest first). SpamAllam
# runs the SMTP listener and the admin UI in one process/event loop (see
# app/main.py), so a writer-updated cache stays consistent without needing
# cross-process invalidation — every finish() keeps this list in sync,
# sparing the dashboard/API hot path a JSONL re-read on every poll.
_CACHE_MAX = 200
_cache: list[dict] = []
_cache_loaded = False
_cache_lock = threading.Lock()


def _read_from_disk(limit: int, day: str | None) -> list[dict]:
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
        with _cache_lock:
            if _cache_loaded:
                _cache.insert(0, self.data)
                del _cache[_CACHE_MAX:]


def read_recent(limit: int = 200, day: str | None = None) -> list[dict]:
    global _cache_loaded
    if day is None and limit <= _CACHE_MAX:
        with _cache_lock:
            if not _cache_loaded:
                _cache[:] = _read_from_disk(_CACHE_MAX, None)
                _cache_loaded = True
            return _cache[:limit]
    return _read_from_disk(limit, day)


def _format_time(ts: str, tz_name: str = "UTC") -> str:
    from ..tools.timezones import friendly

    return friendly(ts, tz_name)


def summarize(trace: dict, tz_name: str = "UTC") -> dict:
    """Project a full trace entry down to what the dashboard table shows."""
    msg = trace.get("message") or {}
    verdict = trace.get("verdict") or {}
    return {
        "id": trace.get("id", ""),
        "time": _format_time(trace.get("ts", ""), tz_name),
        "envelope_from": trace.get("envelope_from") or "<>",
        "subject": msg.get("subject") or "(no subject)",
        "to": ", ".join(trace.get("rcpt_tos") or []),
        "ai_verdict": f"{verdict.get('ai_verdict', '')} {verdict.get('ai_confidence') or 0:.2f}".strip(),
        "rspamd": f"{verdict.get('rspamd_action', '')} ({verdict.get('rspamd_score') or 0:.1f})",
        "action": trace.get("action", ""),
    }


def read_recent_summary(limit: int = 200, day: str | None = None,
                        tz_name: str = "UTC") -> list[dict]:
    return [summarize(t, tz_name) for t in read_recent(limit=limit, day=day)]


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
