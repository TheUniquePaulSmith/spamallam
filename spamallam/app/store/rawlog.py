"""Attachment-stripped raw copies of dropped messages (see pipeline/rawcopy.py),
for the admin logs UI. One .eml file per dropped message, named by its trace
id, grouped into per-day directories so retention pruning lines up with
tracelog's day-based JSONL files.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from ..config import ENV


def _base() -> Path:
    return ENV.data_dir / "logs" / "raw"


def _dir(day: str) -> Path:
    return _base() / day


def save(trace_id: str, day: str, data: bytes) -> None:
    d = _dir(day)
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{trace_id}.eml").write_bytes(data)


def read(trace_id: str, day: str) -> bytes | None:
    try:
        return (_dir(day) / f"{trace_id}.eml").read_bytes()
    except OSError:
        return None


def prune(retention_days: int) -> int:
    """Delete raw-copy day-directories older than the retention window.
    Returns count of .eml files removed."""
    base = _base()
    if not base.exists():
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    removed = 0
    for d in base.iterdir():
        if not d.is_dir():
            continue
        try:
            day = datetime.strptime(d.name, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if day < cutoff:
            for f in d.glob("*.eml"):
                f.unlink(missing_ok=True)
                removed += 1
            try:
                d.rmdir()
            except OSError:
                pass
    return removed
