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
import ipaddress
import re
import socket
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


def _is_unsafe_address(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return True
    return (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_multicast or ip.is_reserved or ip.is_unspecified
    )


async def _resolves_to_unsafe_address(host: str) -> bool:
    """True if `host` (hostname or IP literal) is, or resolves to, a
    private/loopback/link-local/multicast/reserved address — SSRF guard for
    web_fetch, which (unlike netinfo.py's lookups) actually contacts the
    target. Fails closed: unresolvable hosts are treated as unsafe."""
    try:
        ipaddress.ip_address(host)
        return _is_unsafe_address(host)
    except ValueError:
        pass
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.run_in_executor(None, socket.getaddrinfo, host, None)
    except OSError:
        return True
    addrs = {info[4][0] for info in infos}
    return not addrs or any(_is_unsafe_address(a) for a in addrs)


# Second-level labels that act as public suffixes, so "shop.co.uk" is a site but
# "co.uk" is not. Deliberately not a full public-suffix list: one bundled here
# would go stale, and the only cost of guessing "related" is refusing a fetch --
# which is always the safe direction for this guardrail.
_PSEUDO_TLDS = {"co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "gr"}


def _site_of(host: str) -> str:
    """Approximate registrable domain: t.evil.example and www.evil.example both
    reduce to evil.example."""
    host = host.strip(".").lower()
    try:
        ipaddress.ip_address(host)
        return host  # an IP literal has no domain structure to reduce
    except ValueError:
        pass
    labels = host.split(".")
    if len(labels) < 3:
        return host
    if labels[-2] in _PSEUDO_TLDS and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _host_related(a: str, b: str) -> bool:
    """True when two hosts belong to the same site. Exact-match alone let a
    sender put the tracker on t.evil.com and then name www.evil.com in an
    injected instruction, defeating the never-touch-message-links guardrail."""
    if not a or not b:
        return False
    return a == b or _site_of(a) == _site_of(b)


def forbidden_reason(url: str, summary: dict[str, Any]) -> str | None:
    """Return why this URL must not be fetched, or None if allowed."""
    body_urls = summary.get("urls_in_body", []) or []
    norm = _norm_url(url)
    if any(_norm_url(u) == norm for u in body_urls):
        return "URL appears verbatim in the message body — never fetched (activation risk)"
    host = _host(url)
    if host and any(_host_related(host, _host(u)) for u in body_urls):
        return (f"host {host!r} is the same site as a message-body URL — never fetched "
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
_MAX_REDIRECTS = 3


def _to_text(markup: str) -> str:
    markup = re.sub(r"(?is)<(script|style).*?</\1>", " ", markup)
    text = html.unescape(_TAG_RE.sub(" ", markup))
    return re.sub(r"\s{2,}", " ", text).strip()


async def _fetch_http(url: str) -> str:
    """GET `url`, re-running the SSRF guard on EVERY redirect hop.

    A pre-flight check on the first URL proves nothing on its own: any client
    that follows redirects internally (curl -L, a browser) will happily be sent
    from a public host to 169.254.169.254, or to rspamd/redis on the internal
    network, and hand the body back to the model. Redirects are therefore
    followed manually here, with the guard applied before each connection, and
    the response is capped as it streams rather than after it has been read.

    Residual risk, deliberately accepted: the target is resolved once for the
    check and again by the connection, so a 0-TTL record that answers public
    then private can still win the race. Closing that needs connect-time IP
    pinning; it is part of why web_fetch ships disabled by default.
    """
    current = url
    async with httpx.AsyncClient(
        timeout=20, follow_redirects=False, headers={"User-Agent": _UA}
    ) as client:
        for _ in range(_MAX_REDIRECTS + 1):
            host = _host(current)
            if not host or await _resolves_to_unsafe_address(host):
                raise RuntimeError(
                    f"refused: {current!r} is or resolves to a private/internal address"
                )
            async with client.stream("GET", current) as resp:
                if resp.is_redirect:
                    location = resp.headers.get("location", "")
                    if not location:
                        raise RuntimeError("redirect without a Location header")
                    current = str(httpx.URL(current).join(location))
                    if not current.lower().startswith(("http://", "https://")):
                        raise RuntimeError(f"refused redirect to non-http(s) target {current!r}")
                    continue
                resp.raise_for_status()
                chunks: list[bytes] = []
                total = 0
                async for chunk in resp.aiter_bytes():
                    chunks.append(chunk)
                    total += len(chunk)
                    if total >= _MAX_BYTES:
                        break
                return b"".join(chunks).decode(errors="replace")
    raise RuntimeError(f"too many redirects (more than {_MAX_REDIRECTS})")


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

            # The browser follows redirects and loads subresources on its own,
            # so the caller's pre-flight check covers only the first URL. Every
            # request the page makes is re-checked here instead.
            async def _guard(route: Any, request: Any) -> None:
                if await _resolves_to_unsafe_address(_host(request.url)):
                    await route.abort()
                else:
                    await route.continue_()

            await page.route("**/*", _guard)
            await page.goto(url, timeout=20000, wait_until="domcontentloaded")
            return (await page.content())[:_MAX_BYTES]
        finally:
            await browser.close()


async def web_fetch(args: dict[str, Any], cfg: dict[str, Any], summary: dict[str, Any]) -> dict[str, Any]:
    url = str(args.get("url", "")).strip()
    if not url.lower().startswith(("http://", "https://")):
        return {"error": "url must be http(s)"}

    reason = forbidden_reason(url, summary)
    if reason:
        return {"refused": True, "url": url, "reason": reason}

    host = _host(url)
    if not host or await _resolves_to_unsafe_address(host):
        return {"refused": True, "url": url,
                "reason": "target host is private/internal — refused (SSRF guard)"}

    wcfg = cfg["tools"]["web_fetch"]
    backend = (wcfg.get("backend") or "curl").lower()
    try:
        # "curl" is kept as the stored setting value for existing settings.yml
        # files; the fetch itself is in-process now (see _fetch_http).
        if backend in ("curl", "http"):
            markup = await _fetch_http(url)
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
