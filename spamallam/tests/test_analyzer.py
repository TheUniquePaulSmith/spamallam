import pytest

from app.pipeline import analyzer, rspamd_client
from app.pipeline.analyzer import DELIVER, DROP, Pipeline
from app.store.settings import SETTINGS

RAW = (
    b"From: sender@somewhere.example\r\n"
    b"Subject: hi\r\n"
    b"X-SpamAllam-Verdict: HAM\r\n"
    b"\r\n"
    b"hello\r\n"
)

CLIENT = {"addr": "203.0.113.9", "name": "mail.somewhere.example", "helo": "helo.host"}


@pytest.fixture(autouse=True)
def clean_settings():
    # reset the shared settings file between tests
    SETTINGS.path.unlink(missing_ok=True)
    yield
    SETTINGS.path.unlink(missing_ok=True)


def fake_rspamd(action="no action", score=1.0, ok=True):
    async def check(*args, **kwargs):
        if not ok:
            return rspamd_client.RspamdResult(ok=False, error="connect refused")
        return rspamd_client.RspamdResult(
            ok=True, action=action, score=score, required_score=15.0,
            symbols={"SOME_SYMBOL": {"score": score}},
        )
    return check


async def test_ai_disabled_delivers_with_skipped_header(monkeypatch):
    monkeypatch.setattr(analyzer.rspamd_client, "check", fake_rspamd())
    decision, trace = await Pipeline().process(RAW, "sender@somewhere.example",
                                               ["u@test.example"], CLIENT)
    assert decision.action == DELIVER
    assert b"X-SpamAllam-Verdict: SKIPPED" in decision.message
    assert b"X-SpamAllam-Signature: v=1;" in decision.message
    # spoofed inbound header was stripped; only our one Verdict header remains
    assert decision.message.count(b"X-SpamAllam-Verdict:") == 1
    assert b"X-Spam-Status: No" in decision.message


async def test_rspamd_reject_drops(monkeypatch):
    monkeypatch.setattr(analyzer.rspamd_client, "check",
                        fake_rspamd(action="reject", score=22.0))
    decision, trace = await Pipeline().process(RAW, "sender@somewhere.example",
                                               ["u@test.example"], CLIENT)
    assert decision.action == DROP
    assert "rspamd reject" in decision.reason


async def test_whitelist_always_delivers_even_on_reject(monkeypatch):
    SETTINGS.set("overrides.whitelist_domains", ["somewhere.example"])
    monkeypatch.setattr(analyzer.rspamd_client, "check",
                        fake_rspamd(action="reject", score=22.0))
    decision, trace = await Pipeline().process(RAW, "sender@somewhere.example",
                                               ["u@test.example"], CLIENT)
    assert decision.action == DELIVER
    assert b"X-SpamAllam-Whitelisted: yes; rule=domain:somewhere.example" in decision.message


async def test_rspamd_outage_fails_open(monkeypatch):
    monkeypatch.setattr(analyzer.rspamd_client, "check", fake_rspamd(ok=False))
    decision, trace = await Pipeline().process(RAW, "sender@somewhere.example",
                                               ["u@test.example"], CLIENT)
    assert decision.action == DELIVER
    assert b"X-SpamAllam-Rspamd: error" in decision.message


async def test_ai_error_fail_open_vs_tempfail(monkeypatch):
    SETTINGS.set("ai.enabled", True)
    monkeypatch.setattr(analyzer.rspamd_client, "check", fake_rspamd())

    async def boom(self, *a, **k):
        raise RuntimeError("provider exploded")

    monkeypatch.setattr(Pipeline, "_analyze", boom)

    decision, _ = await Pipeline().process(RAW, "s@x.example", ["u@test.example"], CLIENT)
    assert decision.action == DELIVER
    assert b"X-SpamAllam-Verdict: ERROR" in decision.message

    SETTINGS.set("ai.failure_mode", "tempfail")
    decision, _ = await Pipeline().process(RAW, "s@x.example", ["u@test.example"], CLIENT)
    assert decision.action == analyzer.TEMPFAIL


async def test_ai_high_confidence_phishing_drops(monkeypatch):
    from app.pipeline.headers import SpamallamVerdict

    SETTINGS.set("ai.enabled", True)
    monkeypatch.setattr(analyzer.rspamd_client, "check", fake_rspamd())

    async def phish(self, *a, **k):
        return SpamallamVerdict(verdict="PHISHING", confidence=0.99,
                                category="credential phishing", model="test/model")

    monkeypatch.setattr(Pipeline, "_analyze", phish)
    decision, _ = await Pipeline().process(RAW, "s@x.example", ["u@test.example"], CLIENT)
    assert decision.action == DROP

    # below threshold -> tagged delivery instead
    async def phish_low(self, *a, **k):
        return SpamallamVerdict(verdict="PHISHING", confidence=0.80,
                                category="credential phishing", model="test/model")

    monkeypatch.setattr(Pipeline, "_analyze", phish_low)
    decision, _ = await Pipeline().process(RAW, "s@x.example", ["u@test.example"], CLIENT)
    assert decision.action == DELIVER
    assert b"X-SpamAllam-Verdict: PHISHING" in decision.message
