"""Release identifier shown in the admin UI footer.

Resolution order (first hit wins, evaluated once per process):

  1. ``SPAMALLAM_VERSION`` env var — stamped into the image at build time
     (``ARG SPAMALLAM_VERSION`` in the Dockerfile, wired from docker-compose).
     This is what real deployments use: the container ships source only, with
     no ``.git`` directory to interrogate.
  2. git — when running from a source checkout (local dev): the tag pointing
     exactly at the current commit, else the short commit hash.
  3. the packaged project version (``pyproject.toml``) — always present in a
     pip-installed image even when no build arg was passed.
  4. ``"unknown"`` — nothing above resolved.
"""
from __future__ import annotations

import functools
import os
import subprocess
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parent.parent


def _git(*args: str) -> str | None:
    try:
        out = subprocess.run(
            ["git", "-C", str(_PKG_ROOT), *args],
            capture_output=True, text=True, timeout=2,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    return out.stdout.strip() or None


def _from_git() -> str | None:
    # Exact tag on HEAD, e.g. "v1.2.0"; otherwise the short hash, e.g. "288026e".
    return _git("describe", "--tags", "--exact-match") or _git("rev-parse", "--short", "HEAD")


def _from_package() -> str | None:
    try:
        from importlib.metadata import PackageNotFoundError, version
    except ImportError:  # pragma: no cover - importlib.metadata is stdlib on 3.12
        return None
    try:
        return f"v{version('spamallam')}"
    except PackageNotFoundError:
        return None


@functools.cache
def get_version() -> str:
    return (
        os.environ.get("SPAMALLAM_VERSION", "").strip()
        or _from_git()
        or _from_package()
        or "unknown"
    )
