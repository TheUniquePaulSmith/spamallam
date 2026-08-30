"""Quarantine store: dropped messages held for admin/user review.

Every high-confidence DROP is written here (unless quarantine.enabled is off) so
a human can preview it, permanently delete it, or *release* it for delivery if
it was a false positive.

Layout mirrors store/rawlog.py -- one entry per dropped message, keyed by its
trace id, grouped into per-day directories so retention pruning is a directory
walk. Two files per entry:

  quarantine/<YYYY-MM-DD>/<trace_id>.json   plaintext metadata (no message body)
  quarantine/<YYYY-MM-DD>/<trace_id>.enc    AES-GCM ciphertext of the raw .eml

The message bytes are encrypted at rest with SecretsBox (SECRETS_KEY), so the
/data volume and its backups never hold quarantined mail in the clear. The
metadata JSON deliberately contains only envelope/header facts already present
in the trace log.
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ..config import ENV
from .secrets import SecretsBox

_LOCK = threading.RLock()

# Entry lifecycle. "quarantined" entries are the live queue; the other two are
# tombstones kept for the audit trail until retention pruning removes them
# (their .enc blob is deleted immediately when they leave "quarantined").
STATUS_QUARANTINED = "quarantined"
STATUS_RELEASED = "released"
STATUS_DELETED = "deleted"


def _base() -> Path:
    return ENV.data_dir / "quarantine"


def _dir(day: str) -> Path:
    return _base() / day


def _meta_path(day: str, entry_id: str) -> Path:
    return _dir(day) / f"{entry_id}.json"


def _blob_path(day: str, entry_id: str) -> Path:
    return _dir(day) / f"{entry_id}.enc"


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def save(entry_id: str, day: str, meta: dict[str, Any], original: bytes) -> None:
    """Persist one quarantined message: encrypted body + plaintext metadata.

    `meta` supplies the envelope/header facts; this function stamps id/day/ts/
    size/status. Raises on any I/O or crypto failure -- the caller
    (Pipeline._save_quarantine) swallows it so a storage problem can never
    affect the drop decision.
    """
    box = SecretsBox(ENV.secrets_key)
    blob = box.encrypt(original)["$enc"]  # "<b64 nonce+ciphertext>"
    record = {
        **meta,
        "id": entry_id,
        "day": day,
        "ts": meta.get("ts") or _now_iso(),
        "size": len(original),
        "status": STATUS_QUARANTINED,
    }
    with _LOCK:
        _atomic_write(_blob_path(day, entry_id), blob.encode("ascii"))
        _atomic_write(_meta_path(day, entry_id),
                      json.dumps(record, ensure_ascii=False, default=str).encode("utf-8"))


def get_meta(entry_id: str, day: str) -> dict[str, Any] | None:
    try:
        return json.loads(_meta_path(day, entry_id).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def get_original(entry_id: str, day: str) -> bytes | None:
    """Decrypt and return the stored raw message, or None if it's gone
    (released/deleted entries have their blob removed)."""
    try:
        text = _blob_path(day, entry_id).read_text(encoding="ascii")
    except OSError:
        return None
    try:
        return SecretsBox(ENV.secrets_key).decrypt({"$enc": text})
    except Exception:  # noqa: BLE001 -- corrupt/blob under a rotated key
        return None


def list_entries(limit: int = 500, day: str | None = None,
                 include_tombstones: bool = False) -> list[dict[str, Any]]:
    """All quarantine metadata, newest first. Reads only the .json sidecars."""
    base = _base()
    if not base.exists():
        return []
    day_dirs = [base / day] if day else sorted(
        (d for d in base.iterdir() if d.is_dir()), reverse=True
    )
    out: list[dict[str, Any]] = []
    for d in day_dirs:
        if not d.is_dir():
            continue
        for meta_file in d.glob("*.json"):
            try:
                rec = json.loads(meta_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not include_tombstones and rec.get("status") != STATUS_QUARANTINED:
                continue
            out.append(rec)
        out.sort(key=lambda r: r.get("ts", ""), reverse=True)
        if len(out) >= limit:
            return out[:limit]
    return out[:limit]


def mark(entry_id: str, day: str, status: str, actor: str) -> bool:
    """Move an entry out of the live queue (released/deleted). Rewrites the
    metadata with who/when and deletes the encrypted body."""
    with _LOCK:
        rec = get_meta(entry_id, day)
        if rec is None:
            return False
        rec["status"] = status
        rec["acted_by"] = actor
        rec["acted_ts"] = _now_iso()
        _atomic_write(_meta_path(day, entry_id),
                      json.dumps(rec, ensure_ascii=False, default=str).encode("utf-8"))
        _blob_path(day, entry_id).unlink(missing_ok=True)
        return True


def prune(retention_days: int) -> int:
    """Delete quarantine day-directories older than the retention window.
    Returns the count of entries (metadata files) removed."""
    base = _base()
    if not base.exists():
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    removed = 0
    with _LOCK:
        for d in base.iterdir():
            if not d.is_dir():
                continue
            try:
                day = datetime.strptime(d.name, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            if day < cutoff:
                for f in d.glob("*.json"):
                    f.unlink(missing_ok=True)
                    removed += 1
                for f in d.glob("*.enc"):
                    f.unlink(missing_ok=True)
                try:
                    d.rmdir()
                except OSError:
                    pass
    return removed
