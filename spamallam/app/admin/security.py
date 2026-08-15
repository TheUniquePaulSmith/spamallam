"""Session + CSRF plumbing for the admin UI.

Cookies: signed (itsdangerous), HttpOnly, Secure, SameSite=Strict, short TTL.
CSRF: per-session signed token required on every state-changing POST.
"""
from __future__ import annotations

import hashlib
import urllib.parse

from fastapi import HTTPException, Request
from itsdangerous import BadSignature, URLSafeTimedSerializer

from ..config import ENV
from ..store import users as users_store

SESSION_COOKIE = "sa_session"
SESSION_TTL = 12 * 3600
CHALLENGE_TTL = 300

_secret = hashlib.sha256(b"spamallam-web-v1:" + ENV.secrets_key.encode()).hexdigest()
_sessions = URLSafeTimedSerializer(_secret, salt="session")
_challenges = URLSafeTimedSerializer(_secret, salt="webauthn-challenge")
_csrf = URLSafeTimedSerializer(_secret, salt="csrf")


def make_session_cookie(username: str) -> str:
    return _sessions.dumps({"u": username})


def read_session(request: Request) -> str | None:
    raw = request.cookies.get(SESSION_COOKIE)
    if not raw:
        return None
    try:
        data = _sessions.loads(raw, max_age=SESSION_TTL)
    except BadSignature:
        return None
    username = data.get("u")
    return username if users_store.get_user(username) else None


def require_user(request: Request) -> str:
    username = read_session(request)
    if not username:
        raise HTTPException(status_code=401, detail="authentication required",
                            headers={"Location": "/login"})
    return username


def require_admin(request: Request) -> str:
    username = require_user(request)
    user = users_store.get_user(username) or {}
    if not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="admin privileges required")
    return username


# ---- WebAuthn challenge transport (signed, short-lived, stateless) ---------

def seal_challenge(challenge: bytes, context: str) -> str:
    return _challenges.dumps({"c": users_store.b64url(challenge), "ctx": context})


def open_challenge(sealed: str, context: str) -> bytes:
    try:
        data = _challenges.loads(sealed, max_age=CHALLENGE_TTL)
    except BadSignature as exc:
        raise HTTPException(status_code=400, detail="challenge expired or invalid") from exc
    if data.get("ctx") != context:
        raise HTTPException(status_code=400, detail="challenge context mismatch")
    return users_store.unb64url(data["c"])


# ---- CSRF -------------------------------------------------------------------

def csrf_token(username: str) -> str:
    return _csrf.dumps({"u": username})


def check_csrf(username: str, token: str) -> None:
    try:
        data = _csrf.loads(token, max_age=SESSION_TTL)
    except BadSignature as exc:
        raise HTTPException(status_code=403, detail="bad CSRF token") from exc
    if data.get("u") != username:
        raise HTTPException(status_code=403, detail="bad CSRF token")


# ---- WebAuthn relying-party identity ---------------------------------------

def rp_id() -> str:
    return ENV.admin_external_host.split(":")[0]


def expected_origin(request: Request) -> str:
    """Accept the browser's Origin header only when it is https and its host
    matches the configured admin host (port may vary)."""
    origin = request.headers.get("origin", "")
    parsed = urllib.parse.urlsplit(origin)
    if parsed.scheme == "https" and parsed.hostname == rp_id():
        return origin
    # fall back to the canonical origin; verification fails if browser differs
    return f"https://{ENV.admin_external_host}"
