"""Atomic file-based YAML storage. Everything spamallam persists is a plain
YAML/JSONL file under /data so deployments are declarative and backup-friendly."""
from __future__ import annotations

import os
import tempfile
import threading
from pathlib import Path
from typing import Any

import yaml

_LOCK = threading.RLock()


def read_yaml(path: Path, default: Any = None) -> Any:
    with _LOCK:
        try:
            with path.open("r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
                return data if data is not None else default
        except FileNotFoundError:
            return default


def write_yaml(path: Path, data: Any) -> None:
    """Write via tempfile + rename so readers never see a torn file."""
    with _LOCK:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                yaml.safe_dump(data, fh, default_flow_style=False, sort_keys=False)
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise


def append_jsonl(path: Path, line: str) -> None:
    with _LOCK:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(line.rstrip("\n") + "\n")
