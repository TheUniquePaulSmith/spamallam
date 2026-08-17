import pytest

from app.pipeline import analyzer, rspamd_client
from app.pipeline.analyzer import DELIVER, DROP, Pipeline
from app.store import rawlog
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


async def test_ai_high_confidence_drop_saves_raw_copy(monkeypatch):
    from app.pipeline.headers import SpamallamVerdict

    SETTINGS.set("ai.enabled", True)
    monkeypatch.setattr(analyzer.rspamd_client, "check", fake_rspamd())

    async def malicious(self, *a, **k):
        return SpamallamVerdict(verdict="MALICIOUS", confidence=0.99,
                                category="malware", model="test/model")

    monkeypatch.setattr(Pipeline, "_analyze", malicious)
    decision, trace = await Pipeline().process(RAW, "s@x.example", ["u@test.example"], CLIENT)
    assert decision.action == DROP
    assert trace.data["verdict"]["raw_saved"] is True

    saved = rawlog.read(trace.id, trace.day)
    assert saved is not None
    assert b"X-SpamAllam-Verdict: MALICIOUS" in saved
    assert b"hello" in saved  # original text/plain body preserved


async def test_test_message_path_skips_raw_copy(monkeypatch):
    """The admin message-test page uses _TestRecorder, which has no trace
    id/day -- raw copies must never be attempted (and never persisted) for
    ad-hoc test sends."""
    from app.pipeline.analyzer import process_test
    from app.pipeline.headers import SpamallamVerdict

    SETTINGS.set("ai.enabled", True)
    monkeypatch.setattr(analyzer.rspamd_client, "check", fake_rspamd())

    async def malicious(self, *a, **k):
        return SpamallamVerdict(verdict="MALICIOUS", confidence=0.99,
                                category="malware", model="test/model")

    monkeypatch.setattr(Pipeline, "_analyze", malicious)
    result = await process_test(RAW, "s@x.example", ["u@test.example"], CLIENT)
    assert result["action"] == DROP
    assert result["verdict"]["raw_saved"] is False


async def test_rspamd_first_bypass_skips_ai_on_reject(monkeypatch):
    SETTINGS.set("ai.enabled", True)
    SETTINGS.set("ai.pipeline_order", "rspamd_first")
    SETTINGS.set("ai.rspamd_bypass_on_reject", True)
    monkeypatch.setattr(analyzer.rspamd_client, "check", fake_rspamd(action="reject", score=22.0))

    calls = []

    async def spy(self, *a, **k):
        calls.append(1)
        raise AssertionError("AI must not be called when rspamd bypass triggers")

    monkeypatch.setattr(Pipeline, "_analyze", spy)
    decision, trace = await Pipeline().process(RAW, "s@x.example", ["u@test.example"], CLIENT)
    assert decision.action == DROP
    assert calls == []
    assert trace.data["verdict"]["ai_category"] == "rspamd_bypass"


async def test_rspamd_first_bypass_does_not_skip_on_non_reject(monkeypatch):
    from app.pipeline.headers import SpamallamVerdict

    SETTINGS.set("ai.enabled", True)
    SETTINGS.set("ai.pipeline_order", "rspamd_first")
    SETTINGS.set("ai.rspamd_bypass_on_reject", True)
    monkeypatch.setattr(analyzer.rspamd_client, "check", fake_rspamd(action="add header", score=8.0))

    async def ham(self, *a, **k):
        return SpamallamVerdict(verdict="HAM", confidence=0.9, model="test/model")

    monkeypatch.setattr(Pipeline, "_analyze", ham)
    decision, trace = await Pipeline().process(RAW, "s@x.example", ["u@test.example"], CLIENT)
    assert decision.action == DELIVER
    assert trace.data["verdict"]["ai_verdict"] == "HAM"


async def test_rspamd_first_without_bypass_still_runs_ai_on_reject(monkeypatch):
    from app.pipeline.headers import SpamallamVerdict

    SETTINGS.set("ai.enabled", True)
    SETTINGS.set("ai.pipeline_order", "rspamd_first")
    # rspamd_bypass_on_reject left at its default (False)
    monkeypatch.setattr(analyzer.rspamd_client, "check", fake_rspamd(action="reject", score=22.0))

    calls = []

    async def ham(self, *a, **k):
        calls.append(1)
        return SpamallamVerdict(verdict="HAM", confidence=0.9, model="test/model")

    monkeypatch.setattr(Pipeline, "_analyze", ham)
    decision, _ = await Pipeline().process(RAW, "s@x.example", ["u@test.example"], CLIENT)
    # rspamd_drop fires regardless of what AI said -- AI's HAM verdict never
    # changes the outcome, but it still ran since bypass is off
    assert decision.action == DROP
    assert "rspamd reject" in decision.reason
    assert calls == [1]


async def test_rspamd_called_exactly_once_per_order(monkeypatch):
    from app.pipeline.headers import SpamallamVerdict

    SETTINGS.set("ai.enabled", True)

    async def ham(self, *a, **k):
        return SpamallamVerdict(verdict="HAM", confidence=0.9)

    monkeypatch.setattr(Pipeline, "_analyze", ham)

    for order in ("ai_first", "rspamd_first"):
        SETTINGS.set("ai.pipeline_order", order)
        call_count = {"n": 0}

        async def counting_check(*args, **kwargs):
            call_count["n"] += 1
            return rspamd_client.RspamdResult(ok=True, action="no action", score=1.0, required_score=15.0)

        monkeypatch.setattr(analyzer.rspamd_client, "check", counting_check)
        decision, _ = await Pipeline().process(RAW, "s@x.example", ["u@test.example"], CLIENT)
        assert decision.action == DELIVER
        assert call_count["n"] == 1, f"rspamd called {call_count['n']} times for order={order}"
