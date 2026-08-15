"""Web evidence tools.

HARD GUARDRAIL shared by both tools: URLs that appear inside the analyzed
message body are NEVER fetched — not by web_fetch, and web_search only sends
text queries. Message links may be tracking/activation links; touching them
can confirm the mailbox is live or trigger the attack. Only URLs derived from
search results or entered brand domains may be fetched.
"""
from __future__ import annotations

import asyncio
import html
import re
import urllib.parse
from typing import Any

import httpx

from ..store.secrets import SecretsBox

_TAG_RE = re.compile(r"<[^>]+>")


def _norm_url(url: str) -> str:
    try:
        p = urllib.parse.urlsplit(url.strip().lower())
        return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path.rstrip("/"), p.query, ""))
    except ValueError:
        return url.strip().lower()


def _host(url: str) -> str:
    try:
        return urllib.parse.urlsplit(url).hostname or ""
    except ValueError:
        return ""


def forbidden_reason(url: str, summary: dict[str, Any]) -> str | None:
    """Return why this URL must not be fetched, or None if allowed."""
    body_urls = summary.get("urls_in_body", []) or []
    norm = _norm_url(url)
    if any(_norm_url(u) == norm for u in body_urls):
        return "URL appears verbatim in the message body — never fetched (activation risk)"
    host = _host(url)
    if host and any(_host(u) == host for u in body_urls):
        return (f"host {host!r} appears in message-body URLs — never fetched "
                "(activation/tracking risk); use web_search evidence instead")
    return None


# ---------------------------------------------------------------------------
# web_search
# ---------------------------------------------------------------------------


async def web_search(args: dict[str, Any], cfg: dict[str, Any], box: SecretsBox) -> dict[str, Any]:
    query = str(args.get("query", "")).strip()
    if not query:
        return {"error": "query is required"}
    wcfg = cfg["tools"]["web_search"]
    backend = (wcfg.get("backend") or "brave").lower()
    api_key = box.decrypt_str(wcfg["api_key"]) if SecretsBox.is_encrypted(wcfg.get("api_key")) else ""

    try:
        if backend == "brave":
            if not api_key:
                return {"error": "web_search backend 'brave' requires an API key (tools settings)"}
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    "https://api.search.brave.com/res/v1/web/search",
                    params={"q": query, "count": 6},
                    headers={"X-Subscription-Token": api_key, "Accept": "application/json"},
                )
                resp.raise_for_status()
                data = resp.json()
            results = [
                {"title": r.get("title"), "url": r.get("url"),
                 "snippet": _TAG_RE.sub("", r.get("description") or "")}
                for r in (data.get("web", {}).get("results") or [])[:6]
            ]
        elif backend in ("searxng", "custom"):
            endpoint = (wcfg.get("endpoint") or "").rstrip("/")
            if not endpoint:
                return {"error": f"web_search backend {backend!r} requires an endpoint URL"}
            headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    f"{endpoint}/search", params={"q": query, "format": "json"}, headers=headers
                )
                resp.raise_for_status()
                data = resp.json()
            results = [
                {"title": r.get("title"), "url": r.get("url"),
                 "snippet": (r.get("content") or "")[:400]}
                for r in (data.get("results") or [])[:6]
            ]
        else:
            return {"error": f"unknown web_search backend {backend!r}"}
    except Exception as exc:  # noqa: BLE001
        return {"error": f"search failed: {type(exc).__name__}: {exc}"}

    return {"query": query, "results": results}


# ---------------------------------------------------------------------------
# web_fetch
# ---------------------------------------------------------------------------

_UA = "Mozilla/5.0 (compatible; SpamAllam-verifier/1.0)"
_MAX_BYTES = 1_500_000
_MAX_TEXT = 5000


def _to_text(markup: str) -> str:
    markup = re.sub(r"(?is)<(script|style).*?</\1>", " ", markup)
    text = html.unescape(_TAG_RE.sub(" ", markup))
    return re.sub(r"\s{2,}", " ", text).strip()


async def _fetch_curl(url: str) -> str:
    proc = await asyncio.create_subprocess_exec(
        "curl", "-sSL", "--max-time", "20", "--max-filesize", str(_MAX_BYTES),
        "--proto", "=https,http", "-A", _UA, url,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    out, err = await proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(f"curl exit {proc.returncode}: {err.decode(errors='replace')[:300]}")
    return out.decode(errors="replace")


async def _fetch_browser(url: str, backend: str, endpoint: str) -> str:
    try:
        from playwright.async_api import async_playwright
    except ImportError as exc:
        raise RuntimeError(
            "headless-browser fetch requires playwright "
            "(pip install playwright && playwright install chromium), "
            "or use the 'curl' backend"
        ) from exc
    async with async_playwright() as pw:
        if backend == "lightpanda" or endpoint:
            # Lightpanda (or remote chromium) exposes a CDP websocket endpoint
            browser = await pw.chromium.connect_over_cdp(endpoint)
        else:
            browser = await pw.chromium.launch()
        try:
            page = await browser.new_page(user_agent=_UA)
            await page.goto(url, timeout=20000, wait_until="domcontentloaded")
            return await page.content()
        finally:
            await browser.close()


async def web_fetch(args: dict[str, Any], cfg: dict[str, Any], summary: dict[str, Any]) -> dict[str, Any]:
    url = str(args.get("url", "")).strip()
    if not url.lower().startswith(("http://", "https://")):
        return {"error": "url must be http(s)"}

    reason = forbidden_reason(url, summary)
    if reason:
        return {"refused": True, "url": url, "reason": reason}

    wcfg = cfg["tools"]["web_fetch"]
    backend = (wcfg.get("backend") or "curl").lower()
    try:
        if backend == "curl":
            markup = await _fetch_curl(url)
        elif backend in ("playwright", "lightpanda"):
            markup = await _fetch_browser(url, backend, (wcfg.get("endpoint") or "").strip())
        else:
            return {"error": f"unknown web_fetch backend {backend!r}"}
    except Exception as exc:  # noqa: BLE001
        return {"error": f"fetch failed: {type(exc).__name__}: {exc}"}

    text = _to_text(markup)
    return {
        "url": url,
        "backend": backend,
        "text": text[:_MAX_TEXT],
        "truncated": len(text) > _MAX_TEXT,
    }
