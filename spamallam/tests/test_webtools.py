import pytest

from app.tools import webtools


async def _never_called(*args, **kwargs):
    raise AssertionError("fetch backend must not be called for a refused target")


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
    monkeypatch.setattr(webtools, "_fetch_curl", _never_called)
    monkeypatch.setattr(webtools, "_fetch_browser", _never_called)

    result = await webtools.web_fetch({"url": url}, cfg={}, summary={})

    assert result["refused"] is True
    assert "SSRF" in result["reason"] or "private" in result["reason"]


async def test_web_fetch_body_url_guard_still_applies(monkeypatch):
    monkeypatch.setattr(webtools, "_fetch_curl", _never_called)
    monkeypatch.setattr(webtools, "_fetch_browser", _never_called)

    summary = {"urls_in_body": ["http://example.com/track"]}
    result = await webtools.web_fetch(
        {"url": "http://example.com/track"}, cfg={}, summary=summary
    )

    assert result["refused"] is True
    assert "message body" in result["reason"]
