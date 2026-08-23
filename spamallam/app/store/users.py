"""User + passkey + enrollment-token storage (file-based, declarative).

There are NO passwords anywhere. Users authenticate exclusively with FIDO2
WebAuthn passkeys; enrollment happens through single-use tokens (the first one
is generated at boot when no users exist).

/data/config/users.yml:
  users:
    paul:
      display: "Paul"
      is_admin: true
      created: "..."
      credentials:
        - id: <b64url credential id>
          public_key: <b64 cose public key>
          sign_count: 0
          label: "YubiKey 5"
          added: "..."

/data/config/tokens.yml:
  tokens:
    - hash: <sha256 of token>
      username: paul        # fixed for invites; chosen at setup for the first admin
      is_admin: true
      created: "..."
      expires: <epoch>
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from pathlib import Path
from typing import Any

from ..config import ENV
from .files import read_yaml, write_yaml

TOKEN_TTL_SECONDS = 24 * 3600


def _users_path() -> Path:
    return ENV.data_dir / "config" / "users.yml"


def _tokens_path() -> Path:
    return ENV.data_dir / "config" / "tokens.yml"


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------


def all_users() -> dict[str, Any]:
    return (read_yaml(_users_path(), {}) or {}).get("users", {})


def get_user(username: str) -> dict[str, Any] | None:
    return all_users().get(username)


def user_count() -> int:
    return len(all_users())


def save_user(username: str, user: dict[str, Any]) -> None:
    data = read_yaml(_users_path(), {}) or {}
    data.setdefault("users", {})[username] = user
    write_yaml(_users_path(), data)


def delete_user(username: str) -> bool:
    data = read_yaml(_users_path(), {}) or {}
    if username in data.get("users", {}):
        del data["users"][username]
        write_yaml(_users_path(), data)
        return True
    return False


def create_user(username: str, display: str, is_admin: bool) -> dict[str, Any]:
    user = {
        "display": display or username,
        "is_admin": bool(is_admin),
        "created": _now(),
        "credentials": [],
    }
    save_user(username, user)
    return user


def add_credential(username: str, cred_id_b64: str, public_key_b64: str,
                   sign_count: int, label: str) -> None:
    user = get_user(username)
    if user is None:
        raise KeyError(username)
    user.setdefault("credentials", []).append({
        "id": cred_id_b64,
        "public_key": public_key_b64,
        "sign_count": int(sign_count),
        "label": label or "passkey",
        "added": _now(),
    })
    save_user(username, user)


def remove_credential(username: str, cred_id_b64: str) -> bool:
    user = get_user(username)
    if user is None:
        return False
    before = len(user.get("credentials", []))
    user["credentials"] = [c for c in user.get("credentials", []) if c["id"] != cred_id_b64]
    save_user(username, user)
    return len(user["credentials"]) < before


def find_credential(cred_id_b64: str) -> tuple[str, dict[str, Any]] | None:
    for username, user in all_users().items():
        for cred in user.get("credentials", []):
            if cred["id"] == cred_id_b64:
                return username, cred
    return None


def update_sign_count(username: str, cred_id_b64: str, sign_count: int) -> None:
    user = get_user(username)
    if user is None:
        return
    for cred in user.get("credentials", []):
        if cred["id"] == cred_id_b64:
            cred["sign_count"] = int(sign_count)
    save_user(username, user)


# ---------------------------------------------------------------------------
# Enrollment tokens (setup + invites)
# ---------------------------------------------------------------------------


def create_token(username: str | None, is_admin: bool) -> str:
    token = secrets.token_urlsafe(24)
    data = read_yaml(_tokens_path(), {}) or {}
    data.setdefault("tokens", []).append({
        "hash": _token_hash(token),
        "username": username,
        "is_admin": bool(is_admin),
        "created": _now(),
        "expires": int(time.time()) + TOKEN_TTL_SECONDS,
    })
    write_yaml(_tokens_path(), data)
    return token


def consume_token(token: str) -> dict[str, Any] | None:
    """Validate + burn a token. Returns its record or None."""
    data = read_yaml(_tokens_path(), {}) or {}
    tokens = data.get("tokens", [])
    h = _token_hash(token)
    now = int(time.time())
    match = next(
        (t for t in tokens if hmac.compare_digest(t["hash"], h) and t.get("expires", 0) > now),
        None,
    )
    if match is None:
        return None
    data["tokens"] = [t for t in tokens if t["hash"] != h]
    write_yaml(_tokens_path(), data)
    return match


def peek_token(token: str) -> dict[str, Any] | None:
    """Validate without burning (used to render the enrollment page)."""
    data = read_yaml(_tokens_path(), {}) or {}
    h = _token_hash(token)
    now = int(time.time())
    return next(
        (t for t in data.get("tokens", [])
         if hmac.compare_digest(t["hash"], h) and t.get("expires", 0) > now),
        None,
    )


def bootstrap_setup_token() -> str | None:
    """On first boot with zero users, mint the one-time setup token
    (honoring a pre-set SETUP_TOKEN env value)."""
    if user_count() > 0:
        return None
    if ENV.setup_token:
        data = read_yaml(_tokens_path(), {}) or {}
        h = _token_hash(ENV.setup_token)
        if not any(hmac.compare_digest(t["hash"], h) for t in data.get("tokens", [])):
            data.setdefault("tokens", []).append({
                "hash": h,
                "username": None,
                "is_admin": True,
                "created": _now(),
                "expires": int(time.time()) + TOKEN_TTL_SECONDS,
            })
            write_yaml(_tokens_path(), data)
        return ENV.setup_token
    return create_token(None, is_admin=True)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64url(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)
