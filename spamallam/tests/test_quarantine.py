import shutil
from datetime import datetime, timedelta, timezone

import pytest

from app.config import ENV
from app.store import quarantine
from app.store import users as users_store

RAW = (
    b"From: Bad Sender <bad@evil.example>\r\n"
    b"To: paul@fractalengine.com\r\n"
    b"Subject: You won\r\n\r\n"
    b"click here\r\n"
)

META = {
    "envelope_from": "bad@evil.example",
    "from_header": "Bad Sender <bad@evil.example>",
    "subject": "You won",
    "rcpt_tos": ["paul@fractalengine.com"],
    "client": {"addr": "203.0.113.5", "name": "evil.example"},
    "drop_reason": "ai high-confidence threat",
    "ai_verdict": "PHISHING",
    "ai_confidence": 0.99,
}


@pytest.fixture(autouse=True)
def clean_quarantine():
    base = ENV.data_dir / "quarantine"
    shutil.rmtree(base, ignore_errors=True)
    yield
    shutil.rmtree(base, ignore_errors=True)


def _today():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def test_save_list_get_roundtrip():
    day = _today()
    quarantine.save("a" * 16, day, META, RAW)

    entries = quarantine.list_entries()
    assert len(entries) == 1
    assert entries[0]["id"] == "a" * 16
    assert entries[0]["status"] == quarantine.STATUS_QUARANTINED
    assert entries[0]["size"] == len(RAW)

    assert quarantine.get_original("a" * 16, day) == RAW

    # blob on disk must not be plaintext
    blob = (ENV.data_dir / "quarantine" / day / ("a" * 16 + ".enc")).read_bytes()
    assert b"click here" not in blob
    assert b"evil.example" not in blob


def test_mark_released_removes_blob_keeps_tombstone():
    day = _today()
    quarantine.save("b" * 16, day, META, RAW)
    assert quarantine.mark("b" * 16, day, quarantine.STATUS_RELEASED, "paul")

    assert quarantine.get_original("b" * 16, day) is None
    assert quarantine.list_entries() == []  # tombstone hidden by default
    tomb = quarantine.list_entries(include_tombstones=True)
    assert tomb[0]["status"] == quarantine.STATUS_RELEASED
    assert tomb[0]["acted_by"] == "paul"


def test_prune_drops_old_day_dirs():
    old_day = (datetime.now(timezone.utc) - timedelta(days=120)).strftime("%Y-%m-%d")
    new_day = _today()
    quarantine.save("c" * 16, old_day, META, RAW)
    quarantine.save("d" * 16, new_day, META, RAW)

    removed = quarantine.prune(90)
    assert removed == 1
    assert not (ENV.data_dir / "quarantine" / old_day).exists()
    assert quarantine.get_original("d" * 16, new_day) == RAW


async def test_pipeline_drop_is_quarantined(monkeypatch):
    from app.pipeline import analyzer, rspamd_client
    from app.store.settings import SETTINGS

    SETTINGS.path.unlink(missing_ok=True)

    async def fake_check(*a, **k):
        return rspamd_client.RspamdResult(ok=True, action="reject", score=30.0,
                                          required_score=15.0, symbols={})
    monkeypatch.setattr(analyzer.rspamd_client, "check", fake_check)

    raw = (b"From: bad@evil.example\r\nTo: paul@fractalengine.com\r\n"
           b"Subject: hi\r\n\r\nbody\r\n")
    decision, trace = await analyzer.Pipeline().process(
        raw, "bad@evil.example", ["paul@fractalengine.com"],
        {"addr": "203.0.113.5", "name": "evil.example"},
    )
    assert decision.action == analyzer.DROP

    entries = quarantine.list_entries()
    assert len(entries) == 1
    assert entries[0]["envelope_from"] == "bad@evil.example"
    assert entries[0]["rcpt_tos"] == ["paul@fractalengine.com"]
    # stored body is the cleaned original (no X-SpamAllam headers), decrypts intact
    body = quarantine.get_original(entries[0]["id"], entries[0]["day"])
    assert b"Subject: hi" in body and b"X-SpamAllam-Verdict" not in body

    SETTINGS.path.unlink(missing_ok=True)


async def test_pipeline_drop_not_quarantined_when_disabled(monkeypatch):
    from app.pipeline import analyzer, rspamd_client
    from app.store.settings import SETTINGS

    SETTINGS.path.unlink(missing_ok=True)
    SETTINGS.set("quarantine.enabled", False)

    async def fake_check(*a, **k):
        return rspamd_client.RspamdResult(ok=True, action="reject", score=30.0,
                                          required_score=15.0, symbols={})
    monkeypatch.setattr(analyzer.rspamd_client, "check", fake_check)

    decision, _ = await analyzer.Pipeline().process(
        b"From: a@b.c\r\nTo: d@e.f\r\n\r\nx\r\n", "a@b.c", ["d@e.f"], {"addr": "1.2.3.4"},
    )
    assert decision.action == analyzer.DROP
    assert quarantine.list_entries() == []
    SETTINGS.path.unlink(missing_ok=True)


def test_visibility_normalizes_plus_addressing():
    owner = {"addresses": ["paul@fractalengine.com"]}
    stranger = {"addresses": ["bob@fractalengine.com"]}

    to_plus = {"rcpt_tos": ["paul+newsletter@FractalEngine.com"]}
    to_other = {"rcpt_tos": ["someoneelse@fractalengine.com"]}

    assert users_store.user_can_see_address(owner, to_plus["rcpt_tos"]) is True
    assert users_store.user_can_see_address(stranger, to_plus["rcpt_tos"]) is False
    assert users_store.user_can_see_address(owner, to_other["rcpt_tos"]) is False
    assert users_store.user_can_see_address({"addresses": []}, to_plus["rcpt_tos"]) is False
