"""Per-control failure policy: what happens when a security control can't run.

The threat these cover: an attacker who cannot beat the filters may instead try
to make them unavailable, so "control is down" must not silently mean "deliver".
"""
import pytest

from app.pipeline import analyzer, failure, rspamd_client
from app.pipeline.analyzer import DELIVER, DROP, TEMPFAIL, Pipeline
from app.store import quarantine
from app.store.settings import SETTINGS

RAW = b"From: sender@somewhere.example\r\nSubject: hi\r\n\r\nhello\r\n"
CLIENT = {"addr": "45.33.32.156", "name": "mail.somewhere.example", "helo": "helo.host"}


@pytest.fixture(autouse=True)
def clean_settings():
    SETTINGS.path.unlink(missing_ok=True)
    yield
    SETTINGS.path.unlink(missing_ok=True)


def rspamd_ok(av_fail=False):
    async def check(*args, **kwargs):
        symbols = {"SOME_SYMBOL": {"score": 1.0}}
        if av_fail:
            symbols["CLAM_VIRUS_FAIL"] = {"score": 0.0, "options": ["failed to scan"]}
        fail_syms = kwargs.get("av_fail_symbols", frozenset())
        hit = next((s for s in fail_syms if s in symbols), None)
        return rspamd_client.RspamdResult(
            ok=True, action="no action", score=1.0, required_score=15.0, symbols=symbols,
            av_failed=bool(hit), av_error=f"{hit}: failed to scan" if hit else "",
        )
    return check


def rspamd_down():
    async def check(*args, **kwargs):
        return rspamd_client.RspamdResult(ok=False, error="connect refused")
    return check


async def _run():
    return await Pipeline().process(RAW, "sender@somewhere.example", ["u@test.example"], CLIENT)


# ---- antivirus ------------------------------------------------------------

async def test_antivirus_failure_delivers_tagged_by_default(monkeypatch):
    monkeypatch.setattr(analyzer.rspamd_client, "check", rspamd_ok(av_fail=True))
    decision, trace = await _run()
    assert decision.action == DELIVER
    assert b"X-SpamAllam-Control-Failure: antivirus" in decision.message


async def test_antivirus_failure_can_defer(monkeypatch):
    SETTINGS.set("failure_policy.antivirus", failure.DEFER)
    monkeypatch.setattr(analyzer.rspamd_client, "check", rspamd_ok(av_fail=True))
    decision, _ = await _run()
    assert decision.action == TEMPFAIL
    assert "antivirus" in decision.reason


async def test_antivirus_failure_can_quarantine(monkeypatch):
    SETTINGS.set("failure_policy.antivirus", failure.QUARANTINE)
    SETTINGS.set("quarantine.enabled", True)
    monkeypatch.setattr(analyzer.rspamd_client, "check", rspamd_ok(av_fail=True))
    decision, trace = await _run()
    assert decision.action == DROP
    assert quarantine.get_meta(trace.id, trace.day) is not None


async def test_quarantine_policy_never_silently_drops(monkeypatch):
    """If the message cannot actually be stored, dropping it would destroy mail
    that nothing has inspected. Defer instead."""
    SETTINGS.set("failure_policy.antivirus", failure.QUARANTINE)
    SETTINGS.set("quarantine.enabled", False)
    monkeypatch.setattr(analyzer.rspamd_client, "check", rspamd_ok(av_fail=True))
    decision, _ = await _run()
    assert decision.action == TEMPFAIL


async def test_clean_scan_is_not_a_failure(monkeypatch):
    monkeypatch.setattr(analyzer.rspamd_client, "check", rspamd_ok(av_fail=False))
    decision, _ = await _run()
    assert decision.action == DELIVER
    assert b"X-SpamAllam-Control-Failure" not in decision.message


# ---- rspamd ---------------------------------------------------------------

async def test_rspamd_down_implies_antivirus_down(monkeypatch):
    monkeypatch.setattr(analyzer.rspamd_client, "check", rspamd_down())
    decision, _ = await _run()
    assert decision.action == DELIVER
    assert b"X-SpamAllam-Control-Failure: antivirus, rspamd" in decision.message


async def test_rspamd_failure_can_defer(monkeypatch):
    SETTINGS.set("failure_policy.rspamd", failure.DEFER)
    monkeypatch.setattr(analyzer.rspamd_client, "check", rspamd_down())
    decision, _ = await _run()
    assert decision.action == TEMPFAIL


# ---- combinations ---------------------------------------------------------

async def test_all_down_policy_escalates_when_nothing_inspected(monkeypatch):
    """Nothing inspected this message at all -- that is its own situation, and
    the admin gets to treat it more strictly than any single control failing."""
    SETTINGS.set("ai.enabled", True)
    SETTINGS.set("failure_policy.rspamd", failure.DELIVER_TAGGED)
    SETTINGS.set("failure_policy.antivirus", failure.DELIVER_TAGGED)
    SETTINGS.set("failure_policy.ai", failure.DELIVER_TAGGED)
    SETTINGS.set("failure_policy.all_down", failure.DEFER)
    monkeypatch.setattr(analyzer.rspamd_client, "check", rspamd_down())

    async def boom(*a, **k):
        raise RuntimeError("provider unreachable")
    monkeypatch.setattr(Pipeline, "_analyze", boom)

    decision, _ = await _run()
    assert decision.action == TEMPFAIL


async def test_strictest_policy_wins_when_several_fail(monkeypatch):
    SETTINGS.set("ai.enabled", True)
    SETTINGS.set("failure_policy.rspamd", failure.DELIVER_TAGGED)
    SETTINGS.set("failure_policy.antivirus", failure.DELIVER_TAGGED)
    SETTINGS.set("failure_policy.ai", failure.DEFER)
    SETTINGS.set("failure_policy.all_down", failure.DELIVER_TAGGED)
    monkeypatch.setattr(analyzer.rspamd_client, "check", rspamd_ok(av_fail=True))

    async def boom(*a, **k):
        raise RuntimeError("provider unreachable")
    monkeypatch.setattr(Pipeline, "_analyze", boom)

    decision, _ = await _run()
    assert decision.action == TEMPFAIL  # ai's defer beats antivirus's deliver


async def test_whitelisted_mail_is_exempt(monkeypatch):
    SETTINGS.set("overrides.whitelist_domains", ["somewhere.example"])
    SETTINGS.set("overrides.require_auth_for_whitelist", False)
    SETTINGS.set("failure_policy.rspamd", failure.DEFER)
    monkeypatch.setattr(analyzer.rspamd_client, "check", rspamd_down())
    decision, _ = await _run()
    assert decision.action == DELIVER


# ---- backwards compatibility ----------------------------------------------

def test_legacy_ai_failure_mode_is_inherited():
    """An existing settings.yml has ai.failure_mode and no failure_policy; it
    must keep behaving identically with no migration having run."""
    assert failure.resolve({"ai": {"failure_mode": "tempfail"}}, "ai") == failure.DEFER
    assert failure.resolve({"ai": {"failure_mode": "fail_open"}}, "ai") == failure.DELIVER_TAGGED
    # an explicit value wins over the legacy one
    cfg = {"ai": {"failure_mode": "tempfail"}, "failure_policy": {"ai": failure.QUARANTINE}}
    assert failure.resolve(cfg, "ai") == failure.QUARANTINE


async def test_legacy_tempfail_still_defers_end_to_end(monkeypatch):
    SETTINGS.set("ai.enabled", True)
    SETTINGS.set("ai.failure_mode", "tempfail")
    monkeypatch.setattr(analyzer.rspamd_client, "check", rspamd_ok())

    async def boom(*a, **k):
        raise RuntimeError("provider unreachable")
    monkeypatch.setattr(Pipeline, "_analyze", boom)

    decision, _ = await _run()
    assert decision.action == TEMPFAIL


async def test_all_down_never_weakens_a_per_control_policy(monkeypatch):
    """With AI disabled, an rspamd outage IS "everything down". An operator who
    asked for rspamd failures to defer must still get a defer, not the weaker
    all_down value."""
    SETTINGS.set("failure_policy.rspamd", failure.DEFER)
    SETTINGS.set("failure_policy.all_down", failure.DELIVER_TAGGED)
    monkeypatch.setattr(analyzer.rspamd_client, "check", rspamd_down())
    decision, _ = await _run()
    assert decision.action == TEMPFAIL


def test_strictest_ordering():
    assert failure.strictest([failure.DELIVER_TAGGED, failure.QUARANTINE]) == failure.QUARANTINE
    assert failure.strictest([failure.QUARANTINE, failure.DEFER]) == failure.DEFER
    assert failure.strictest([]) == failure.DELIVER_TAGGED


async def test_antivirus_failure_detected_on_the_whitelist_pre_pass(monkeypatch):
    """The whitelist-authentication pre-pass result becomes the final rspamd
    result in rspamd_first order, so it must carry antivirus-failure detection
    too -- otherwise a failed scan is invisible on exactly that path."""
    SETTINGS.set("ai.pipeline_order", "rspamd_first")
    # Matches, so the pre-pass runs; unauthenticated, so the whitelist is denied
    # and the failure policy applies to the pre-pass result.
    SETTINGS.set("overrides.whitelist_domains", ["somewhere.example"])
    SETTINGS.set("failure_policy.antivirus", failure.DEFER)
    monkeypatch.setattr(analyzer.rspamd_client, "check", rspamd_ok(av_fail=True))
    decision, trace = await _run()
    assert any(e.get("kind") == "whitelist_denied" for e in trace.data["events"])
    assert decision.action == TEMPFAIL
