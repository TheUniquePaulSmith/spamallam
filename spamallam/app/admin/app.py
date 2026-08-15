"""SpamAllam admin web UI (FastAPI + Jinja2, HTTPS-only, passkey-only auth)."""
from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from ..ai.engine import run_provider_test
from ..config import ENV
from ..store import audit, tracelog
from ..store import users as users_store
from ..store.secrets import SecretsBox, redact
from ..store.settings import SETTINGS
from ..tools.unifi import read_suggestions
from . import security, webauthn_flow

log = logging.getLogger("spamallam.admin")

templates = Jinja2Templates(directory=str(ENV.templates_dir))


def _box() -> SecretsBox:
    return SecretsBox(ENV.secrets_key)


def render(request: Request, name: str, username: str | None = None, **ctx: Any) -> HTMLResponse:
    user = users_store.get_user(username) if username else None
    return templates.TemplateResponse(request, name, {
        "username": username,
        "is_admin": bool(user and user.get("is_admin")),
        "csrf": security.csrf_token(username) if username else "",
        **ctx,
    })


def _set_session(response, username: str) -> None:
    response.set_cookie(
        security.SESSION_COOKIE,
        security.make_session_cookie(username),
        max_age=security.SESSION_TTL,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/",
    )


def create_app() -> FastAPI:
    app = FastAPI(title="SpamAllam Admin", docs_url=None, redoc_url=None, openapi_url=None)
    app.mount("/static", StaticFiles(directory=str(ENV.static_dir)), name="static")

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'"
        )
        return response

    @app.exception_handler(HTTPException)
    async def http_exc(request: Request, exc: HTTPException):
        if exc.status_code == 401 and "text/html" in request.headers.get("accept", ""):
            return RedirectResponse("/login", status_code=303)
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

    # ------------------------------------------------------------------ auth
    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request):
        return render(request, "login.html")

    @app.post("/api/auth/options")
    async def auth_options():
        options, sealed = webauthn_flow.authentication_options()
        return {"options": json.loads(options), "sealed": sealed}

    @app.post("/api/auth/verify")
    async def auth_verify(request: Request):
        body = await request.json()
        username = webauthn_flow.verify_authentication(request, body)
        audit.record(username, "auth.login", {"ip": request.client.host if request.client else ""})
        response = JSONResponse({"ok": True, "redirect": "/"})
        _set_session(response, username)
        return response

    @app.get("/logout")
    async def logout(request: Request):
        username = security.read_session(request)
        if username:
            audit.record(username, "auth.logout", {})
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie(security.SESSION_COOKIE, path="/")
        return response

    # ------------------------------------------------------- enrollment/setup
    @app.get("/setup", response_class=HTMLResponse)
    async def setup_page(request: Request, token: str = ""):
        record = users_store.peek_token(token) if token else None
        return render(request, "setup.html", token=token,
                      valid=record is not None,
                      fixed_username=(record or {}).get("username"))

    @app.post("/api/setup/options")
    async def setup_options(request: Request):
        body = await request.json()
        record = users_store.peek_token(body.get("token", ""))
        if record is None:
            raise HTTPException(status_code=403, detail="invalid or expired enrollment token")
        username = (record.get("username") or body.get("username") or "").strip().lower()
        if not username or not username.replace("-", "").replace("_", "").replace(".", "").isalnum():
            raise HTTPException(status_code=400, detail="choose a username (letters/digits/._-)")
        existing = users_store.get_user(username)
        if existing and existing.get("credentials") and record.get("username") != username:
            raise HTTPException(status_code=400, detail="username already taken")
        options, sealed = webauthn_flow.registration_options(username)
        return {"options": json.loads(options), "sealed": sealed, "username": username}

    @app.post("/api/setup/verify")
    async def setup_verify(request: Request):
        body = await request.json()
        record = users_store.consume_token(body.get("token", ""))
        if record is None:
            raise HTTPException(status_code=403, detail="invalid or expired enrollment token")
        username = (record.get("username") or body.get("username") or "").strip().lower()
        if users_store.get_user(username) is None:
            users_store.create_user(username, body.get("display", username),
                                    is_admin=bool(record.get("is_admin")))
        webauthn_flow.verify_registration(request, username, body,
                                          body.get("label", "first passkey"))
        audit.record(username, "auth.enrolled", {"is_admin": bool(record.get("is_admin"))})
        response = JSONResponse({"ok": True, "redirect": "/"})
        _set_session(response, username)
        return response

    # -------------------------------------------------------------- dashboard
    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request):
        username = security.require_user(request)
        cfg = SETTINGS.all()
        traces = tracelog.read_recent(limit=10)
        return render(request, "dashboard.html", username,
                      cfg=cfg, provider_label=f"{cfg['provider']['type']}/{cfg['provider']['model']}",
                      users=users_store.all_users(), traces=traces)

    # ------------------------------------------------------------ settings: AI
    @app.get("/settings/ai", response_class=HTMLResponse)
    async def ai_page(request: Request):
        from ..ai.prompt import system_prompt

        username = security.require_user(request)
        cfg = SETTINGS.all()
        return render(request, "ai.html", username, cfg=cfg,
                      effective_prompt=system_prompt(cfg["ai"]),
                      prompt_customized=bool((cfg["ai"].get("system_prompt") or "").strip()))

    @app.post("/settings/ai")
    async def ai_save(request: Request, csrf: str = Form(...),
                      enabled: str = Form("off"), failure_mode: str = Form("fail_open"),
                      drop_threshold: float = Form(0.95), system_prompt: str = Form("")):
        from ..ai.prompt import DEFAULT_SYSTEM_PROMPT

        username = security.require_admin(request)
        security.check_csrf(username, csrf)
        if failure_mode not in ("fail_open", "tempfail"):
            raise HTTPException(status_code=400, detail="bad failure_mode")
        # Normalize: an empty box or unchanged default is stored as "" (use built-in)
        prompt_text = system_prompt.replace("\r\n", "\n").strip()
        if prompt_text == DEFAULT_SYSTEM_PROMPT.strip():
            prompt_text = ""
        changes = SETTINGS.update({
            "ai.enabled": enabled == "on",
            "ai.failure_mode": failure_mode,
            "ai.drop_threshold": max(0.5, min(1.0, drop_threshold)),
            "ai.system_prompt": prompt_text,
        })
        audit.record_changes(username, changes)
        return RedirectResponse("/settings/ai", status_code=303)

    # ------------------------------------------------------ settings: provider
    @app.get("/settings/provider", response_class=HTMLResponse)
    async def provider_page(request: Request):
        username = security.require_user(request)
        cfg = SETTINGS.all()
        return render(request, "provider.html", username, cfg=cfg,
                      provider=redact(cfg["provider"]))

    @app.post("/settings/provider")
    async def provider_save(request: Request, csrf: str = Form(...),
                            ptype: str = Form(...), model: str = Form(...),
                            base_url: str = Form(""), api_key: str = Form(""),
                            timeout_seconds: int = Form(60), max_tokens: int = Form(1024)):
        username = security.require_admin(request)
        security.check_csrf(username, csrf)
        if ptype not in ("openai", "anthropic", "custom"):
            raise HTTPException(status_code=400, detail="bad provider type")
        values: dict[str, Any] = {
            "provider.type": ptype,
            "provider.model": model.strip(),
            "provider.base_url": base_url.strip(),
            "provider.timeout_seconds": max(5, min(600, timeout_seconds)),
            "provider.max_tokens": max(64, min(32768, max_tokens)),
        }
        if api_key.strip():  # blank = keep existing
            values["provider.api_key"] = _box().encrypt(api_key.strip())
        changes = SETTINGS.update(values)
        audit.record_changes(username, changes)
        return RedirectResponse("/settings/provider", status_code=303)

    @app.post("/settings/provider/mtls")
    async def provider_mtls(request: Request, csrf: str = Form(...),
                            enabled: str = Form("off"),
                            pfx: UploadFile | None = File(None),
                            pfx_password: str = Form(""),
                            clear: str = Form("")):
        username = security.require_admin(request)
        security.check_csrf(username, csrf)
        box = _box()
        values: dict[str, Any] = {"provider.mtls.enabled": enabled == "on"}
        if clear == "on":
            values["provider.mtls.pfx"] = None
            values["provider.mtls.pfx_password"] = None
            values["provider.mtls.enabled"] = False
        else:
            if pfx is not None and pfx.filename:
                data = await pfx.read()
                if len(data) > 512 * 1024:
                    raise HTTPException(status_code=400, detail="PFX too large")
                values["provider.mtls.pfx"] = box.encrypt(data)
            if pfx_password:
                values["provider.mtls.pfx_password"] = box.encrypt(pfx_password)
        changes = SETTINGS.update(values)
        audit.record_changes(username, changes)
        return RedirectResponse("/settings/provider", status_code=303)

    @app.post("/api/provider/test")
    async def provider_test(request: Request):
        username = security.require_user(request)
        audit.record(username, "provider.test", {})
        return await run_provider_test()

    @app.post("/api/provider/models")
    async def provider_models(request: Request):
        from ..providers.anthropic_provider import AnthropicProvider
        from ..providers.base import ProviderSettings
        from ..providers.openai_provider import OpenAIProvider

        username = security.require_user(request)
        body = await request.json()
        ptype = str(body.get("ptype", "")).lower()
        base_url = str(body.get("base_url", "")).strip()
        api_key = str(body.get("api_key", "")).strip()
        if ptype not in ("openai", "anthropic", "custom"):
            raise HTTPException(status_code=400, detail="bad provider type")
        if ptype == "custom" and not base_url:
            raise HTTPException(status_code=400, detail="custom provider requires a base_url")
        if not api_key:
            # blank key in the (unsaved) form = use whatever is already stored
            saved = SETTINGS.all()["provider"]
            if saved.get("type") == ptype and SecretsBox.is_encrypted(saved.get("api_key")):
                api_key = _box().decrypt_str(saved["api_key"])

        ps = ProviderSettings(type=ptype, model="", api_key=api_key, base_url=base_url)
        provider = AnthropicProvider(ps) if ptype == "anthropic" else OpenAIProvider(ps)
        try:
            models = await provider.list_models()
        except Exception as exc:  # noqa: BLE001 — surfaced to the admin as-is
            raise HTTPException(status_code=502, detail=f"{type(exc).__name__}: {exc}")
        audit.record(username, "provider.models_fetch", {"ptype": ptype, "count": len(models)})
        return {"models": models}

    # ------------------------------------------------------- settings: context
    @app.get("/settings/context", response_class=HTMLResponse)
    async def context_page(request: Request):
        username = security.require_user(request)
        return render(request, "context.html", username, cfg=SETTINGS.all())

    @app.post("/settings/context")
    async def context_save(request: Request, csrf: str = Form(...),
                           organization: str = Form(""), expected_mail: str = Form("")):
        username = security.require_admin(request)
        security.check_csrf(username, csrf)
        changes = SETTINGS.update({
            "context.organization": organization.strip(),
            "context.expected_mail": expected_mail.strip(),
        })
        audit.record_changes(username, changes)
        return RedirectResponse("/settings/context", status_code=303)

    @app.post("/settings/context/recipient")
    async def context_recipient(request: Request, csrf: str = Form(...),
                                email: str = Form(...), text: str = Form(""),
                                delete: str = Form("")):
        username = security.require_admin(request)
        security.check_csrf(username, csrf)
        email_norm = email.strip().lower()
        per = SETTINGS.get("context.per_recipient", {}) or {}
        if delete == "on":
            per.pop(email_norm, None)
        else:
            per[email_norm] = text.strip()
        changes = SETTINGS.update({"context.per_recipient": per})
        audit.record_changes(username, changes)
        return RedirectResponse("/settings/context", status_code=303)

    # --------------------------------------------------------- settings: tools
    @app.get("/settings/tools", response_class=HTMLResponse)
    async def tools_page(request: Request):
        username = security.require_user(request)
        cfg = SETTINGS.all()
        return render(request, "tools.html", username, cfg=cfg, tools=redact(cfg["tools"]))

    @app.post("/settings/tools")
    async def tools_save(request: Request):
        username = security.require_admin(request)
        form = await request.form()
        security.check_csrf(username, str(form.get("csrf", "")))
        box = _box()

        def on(name: str) -> bool:
            return form.get(name) == "on"

        values: dict[str, Any] = {
            "tools.ip_lookup.enabled": on("ip_lookup_enabled"),
            "tools.ip_lookup.non_us_note": on("ip_lookup_non_us"),
            "tools.ip_ownership.enabled": on("ip_ownership_enabled"),
            "tools.ip_ownership.max_ips": int(form.get("ip_ownership_max_ips", 4) or 4),
            "tools.domain_age.enabled": on("domain_age_enabled"),
            "tools.domain_age.young_domain_days": int(form.get("young_domain_days", 90) or 90),
            "tools.dns_verify.enabled": on("dns_verify_enabled"),
            "tools.web_search.enabled": on("web_search_enabled"),
            "tools.web_search.backend": str(form.get("web_search_backend", "brave")),
            "tools.web_search.endpoint": str(form.get("web_search_endpoint", "")).strip(),
            "tools.web_fetch.enabled": on("web_fetch_enabled"),
            "tools.web_fetch.backend": str(form.get("web_fetch_backend", "curl")),
            "tools.web_fetch.endpoint": str(form.get("web_fetch_endpoint", "")).strip(),
            "tools.shared_provider_check.enabled": on("shared_provider_enabled"),
            "tools.unifi_block.enabled": on("unifi_enabled"),
            "tools.unifi_block.policy": ("auto" if form.get("unifi_policy") == "auto" else "suggest"),
            "tools.unifi_block.url": str(form.get("unifi_url", "")).strip(),
            "tools.unifi_block.network_list": str(form.get("unifi_network_list", "spamallam-blocked")).strip(),
            "tools.unifi_block.site": str(form.get("unifi_site", "default")).strip() or "default",
            "tools.unifi_block.max_prefix": max(16, min(32, int(form.get("unifi_max_prefix", 24) or 24))),
        }
        ws_key = str(form.get("web_search_api_key", "")).strip()
        if ws_key:
            values["tools.web_search.api_key"] = box.encrypt(ws_key)
        unifi_key = str(form.get("unifi_api_key", "")).strip()
        if unifi_key:
            values["tools.unifi_block.api_key"] = box.encrypt(unifi_key)

        changes = SETTINGS.update(values)
        audit.record_changes(username, changes)
        return RedirectResponse("/settings/tools", status_code=303)

    # ----------------------------------------------------- settings: overrides
    @app.get("/settings/overrides", response_class=HTMLResponse)
    async def overrides_page(request: Request):
        username = security.require_user(request)
        return render(request, "overrides.html", username, cfg=SETTINGS.all())

    @app.post("/settings/overrides")
    async def overrides_save(request: Request, csrf: str = Form(...),
                             whitelist_domains: str = Form(""),
                             whitelist_recipients: str = Form(""),
                             blocklist_domains: str = Form("")):
        username = security.require_admin(request)
        security.check_csrf(username, csrf)

        def lines(text: str) -> list[str]:
            return sorted({l.strip().lower() for l in text.splitlines() if l.strip()})

        changes = SETTINGS.update({
            "overrides.whitelist_domains": lines(whitelist_domains),
            "overrides.whitelist_recipients": lines(whitelist_recipients),
            "overrides.blocklist_domains": lines(blocklist_domains),
        })
        audit.record_changes(username, changes)
        return RedirectResponse("/settings/overrides", status_code=303)

    # -------------------------------------------------------------- test message
    @app.get("/test", response_class=HTMLResponse)
    async def test_page(request: Request):
        username = security.require_user(request)
        return render(request, "test.html", username)

    @app.post("/api/test/message")
    async def test_message(request: Request, csrf: str = Form(...),
                           raw_text: str = Form(""), envelope_from: str = Form(""),
                           rcpt_tos: str = Form(""), client_ip: str = Form(""),
                           client_helo: str = Form(""),
                           eml: UploadFile | None = File(None)):
        from ..pipeline.analyzer import process_test

        username = security.require_user(request)
        security.check_csrf(username, csrf)

        if eml is not None and eml.filename:
            data = await eml.read()
        else:
            data = raw_text.encode("utf-8")
        if not data.strip():
            raise HTTPException(status_code=400, detail="paste an e-mail or upload a .eml file")
        if len(data) > 10 * 1024 * 1024:
            raise HTTPException(status_code=400, detail="message too large (10 MiB limit)")

        rcpts = [r.strip() for r in rcpt_tos.split(",") if r.strip()] or ["test@example.com"]
        client = {"addr": client_ip.strip() or "203.0.113.10", "helo": client_helo.strip(), "name": ""}
        result = await process_test(data, envelope_from.strip() or "test@example.com", rcpts, client)
        audit.record(username, "test.message",
                     {"envelope_from": envelope_from, "action": result["action"]})
        return result

    # ------------------------------------------------------------------- logs
    @app.get("/logs", response_class=HTMLResponse)
    async def logs_page(request: Request, day: str = "", q: str = ""):
        username = security.require_user(request)
        traces = tracelog.read_recent(limit=200, day=day or None)
        if q:
            needle = q.lower()
            traces = [t for t in traces if needle in json.dumps(t).lower()]
        return render(request, "logs.html", username, traces=traces, day=day, q=q,
                      retention=SETTINGS.get("logging.retention_days"))

    @app.post("/settings/logging")
    async def logging_save(request: Request, csrf: str = Form(...),
                           retention_days: int = Form(30), log_prompts: str = Form("off")):
        username = security.require_admin(request)
        security.check_csrf(username, csrf)
        changes = SETTINGS.update({
            "logging.retention_days": max(1, min(3650, retention_days)),
            "logging.log_prompts": log_prompts == "on",
        })
        audit.record_changes(username, changes)
        return RedirectResponse("/logs", status_code=303)

    @app.get("/logs/audit", response_class=HTMLResponse)
    async def audit_page(request: Request):
        username = security.require_user(request)
        return render(request, "audit.html", username, entries=audit.tail())

    @app.get("/logs/blocks", response_class=HTMLResponse)
    async def blocks_page(request: Request):
        username = security.require_user(request)
        return render(request, "blocks.html", username, suggestions=read_suggestions())

    # ------------------------------------------------------------------ users
    @app.get("/users", response_class=HTMLResponse)
    async def users_page(request: Request, invite_token: str = ""):
        username = security.require_user(request)
        return render(request, "users.html", username,
                      users=users_store.all_users(), invite_token=invite_token,
                      invite_url=ENV.admin_external_url(f"/setup?token={invite_token}") if invite_token else "")

    @app.post("/users/invite")
    async def users_invite(request: Request, csrf: str = Form(...),
                           new_username: str = Form(...), is_admin: str = Form("off")):
        username = security.require_admin(request)
        security.check_csrf(username, csrf)
        token = users_store.create_token(new_username.strip().lower() or None, is_admin == "on")
        audit.record(username, "user.invite",
                     {"username": new_username, "is_admin": is_admin == "on"})
        return RedirectResponse(f"/users?invite_token={token}", status_code=303)

    @app.post("/users/delete")
    async def users_delete(request: Request, csrf: str = Form(...), target: str = Form(...)):
        username = security.require_admin(request)
        security.check_csrf(username, csrf)
        if target == username:
            raise HTTPException(status_code=400, detail="cannot delete yourself")
        if users_store.delete_user(target):
            audit.record(username, "user.delete", {"username": target})
        return RedirectResponse("/users", status_code=303)

    @app.post("/api/passkey/options")
    async def passkey_options(request: Request):
        username = security.require_user(request)
        options, sealed = webauthn_flow.registration_options(username)
        return {"options": json.loads(options), "sealed": sealed}

    @app.post("/api/passkey/verify")
    async def passkey_verify(request: Request):
        username = security.require_user(request)
        body = await request.json()
        webauthn_flow.verify_registration(request, username, body,
                                          body.get("label", "passkey"))
        audit.record(username, "user.passkey_added", {"label": body.get("label", "")})
        return {"ok": True}

    @app.post("/users/passkey/delete")
    async def passkey_delete(request: Request, csrf: str = Form(...),
                             cred_id: str = Form(...)):
        username = security.require_user(request)
        security.check_csrf(username, csrf)
        user = users_store.get_user(username) or {}
        if len(user.get("credentials", [])) <= 1:
            raise HTTPException(status_code=400,
                                detail="cannot remove your last passkey — add another first")
        if users_store.remove_credential(username, cred_id):
            audit.record(username, "user.passkey_removed", {"credential": cred_id[:16]})
        return RedirectResponse("/users", status_code=303)

    return app
