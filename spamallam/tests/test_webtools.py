import httpx
import pytest

from app.tools import webtools


async def _never_called(*args, **kwargs):
    raise AssertionError("fetch backend must not be called for a refused target")


def _mock_http(monkeypatch, handler):
    """Route _fetch_http's own AsyncClient through a MockTransport."""
    real = httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real(*args, **kwargs)

    monkeypatch.setattr(webtools.httpx, "AsyncClient", factory)


def _dns(monkeypatch, safe_hosts):
    """Resolve named hosts as public; everything else keeps the real IP rules."""
    async def fake(host):
        if host in safe_hosts:
            return False
        return webtools._is_unsafe_address(host)

    monkeypatch.setattr(webtools, "_resolves_to_unsafe_address", fake)


@pytest.mark.parametrize("host,expected", [
    ("127.0.0.1", True),
    ("169.254.169.254", True),   # cloud metadata endpoint
    ("10.0.0.5", True),
    ("192.168.1.1", True),
    ("::1", True),
    ("224.0.0.1", True),         # multicast
    ("8.8.8.8", False),
    ("1.1.1.1", False),
])
def test_is_unsafe_address(host, expected):
    assert webtools._is_unsafe_address(host) is expected


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/",
    "http://169.254.169.254/latest/meta-data/",
    "http://10.0.0.5:11333/stat",
    "http://[::1]/",
])
async def test_web_fetch_refuses_private_targets(monkeypatch, url):
    monkeypatch.setattr(webtools, "_fetch_http", _never_called)
    monkeypatch.setattr(webtools, "_fetch_browser", _never_called)

    result = await webtools.web_fetch({"url": url}, cfg={}, summary={})

    assert result["refused"] is True
    assert "SSRF" in result["reason"] or "private" in result["reason"]


async def test_web_fetch_body_url_guard_still_applies(monkeypatch):
    monkeypatch.setattr(webtools, "_fetch_http", _never_called)
    monkeypatch.setattr(webtools, "_fetch_browser", _never_called)

    summary = {"urls_in_body": ["http://example.com/track"]}
    result = await webtools.web_fetch(
        {"url": "http://example.com/track"}, cfg={}, summary=summary
    )

    assert result["refused"] is True
    assert "message body" in result["reason"]


async def test_web_fetch_body_url_guard_covers_subdomains(monkeypatch):
    """The tracker host and the host named in an injected instruction are often
    not string-equal; same-site is what matters."""
    monkeypatch.setattr(webtools, "_fetch_http", _never_called)
    summary = {"urls_in_body": ["http://t.evil.example/pixel.gif"]}

    for url in ("http://evil.example/", "http://www.evil.example/login"):
        result = await webtools.web_fetch({"url": url}, cfg={}, summary=summary)
        assert result["refused"] is True, url
        assert "same site" in result["reason"]


async def test_web_fetch_refuses_redirect_into_internal_network(monkeypatch):
    """The pre-flight check only sees the first URL. A public host that 302s to
    the cloud metadata endpoint (or rspamd/redis) must not be followed."""
    hops = []

    def handler(request):
        hops.append(str(request.url))
        if request.url.host == "public.example":
            return httpx.Response(
                302, headers={"location": "http://169.254.169.254/latest/meta-data/"}
            )
        return httpx.Response(200, text="INTERNAL SECRET")

    _mock_http(monkeypatch, handler)
    _dns(monkeypatch, {"public.example"})

    result = await webtools.web_fetch(
        {"url": "http://public.example/x"}, cfg={"tools": {"web_fetch": {"backend": "curl"}}},
        summary={},
    )

    assert "INTERNAL SECRET" not in str(result)
    assert "private/internal" in result["error"]
    assert hops == ["http://public.example/x"]  # the second hop never connected


async def test_web_fetch_follows_safe_redirect(monkeypatch):
    def handler(request):
        if request.url.host == "public.example":
            return httpx.Response(302, headers={"location": "http://other.example/final"})
        return httpx.Response(200, text="<p>hello world</p>")

    _mock_http(monkeypatch, handler)
    _dns(monkeypatch, {"public.example", "other.example"})

    result = await webtools.web_fetch(
        {"url": "http://public.example/x"}, cfg={"tools": {"web_fetch": {"backend": "curl"}}},
        summary={},
    )

    assert result["text"] == "hello world"


async def test_web_fetch_stops_at_redirect_limit(monkeypatch):
    def handler(request):
        return httpx.Response(302, headers={"location": "http://public.example/next"})

    _mock_http(monkeypatch, handler)
    _dns(monkeypatch, {"public.example"})

    result = await webtools.web_fetch(
        {"url": "http://public.example/x"}, cfg={"tools": {"web_fetch": {"backend": "curl"}}},
        summary={},
    )

    assert "too many redirects" in result["error"]
