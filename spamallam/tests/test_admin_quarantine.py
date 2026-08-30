"""Route-level tests for the quarantine UI + per-user scoping."""
import datetime
import shutil

import pytest
from starlette.testclient import TestClient

from app.admin import app as admin_app
from app.admin import security
from app.config import ENV
from app.store import quarantine
from app.store import users as users_store
from app.store.settings import SETTINGS


def _today():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")


@pytest.fixture
def env(monkeypatch):
    shutil.rmtree(ENV.data_dir / "quarantine", ignore_errors=True)
    for name in ("users.yml", "tokens.yml", "settings.yml"):
        (ENV.data_dir / "config" / name).unlink(missing_ok=True)
    sent: list = []
    monkeypatch.setattr(admin_app, "reinject", lambda mf, rt, msg: sent.append((mf, rt, msg)))

    users_store.create_user("adm", "Adm", is_admin=True)
    users_store.create_user("paul", "Paul", is_admin=False, addresses=["paul@fractalengine.com"])

    day = _today()
    quarantine.save("1" * 16, day, {
        "envelope_from": "s@sender.example", "from_header": "s@sender.example",
        "subject": "Mine", "rcpt_tos": ["paul+lists@fractalengine.com"],
        "client": {"addr": "1.2.3.4", "name": "x"}, "drop_reason": "ai",
        "ai_verdict": "PHISHING", "ai_confidence": 0.9,
    }, b"From: s@sender.example\r\nTo: paul@fractalengine.com\r\nSubject: Mine\r\n"
       b"Content-Type: text/html\r\n\r\n<body><p>hi<img src='http://t/p.gif'></p></body>")
    quarantine.save("2" * 16, day, {
        "envelope_from": "s@sender.example", "from_header": "s@sender.example",
        "subject": "NotMine", "rcpt_tos": ["someoneelse@fractalengine.com"],
        "client": {"addr": "1.2.3.4", "name": "x"}, "drop_reason": "ai",
        "ai_verdict": "PHISHING", "ai_confidence": 0.9,
    }, b"From: s@sender.example\r\nTo: someoneelse@fractalengine.com\r\n\r\nx\r\n")

    client = TestClient(admin_app.create_app())
    yield client, sent, day

    shutil.rmtree(ENV.data_dir / "quarantine", ignore_errors=True)
    for name in ("users.yml", "tokens.yml", "settings.yml"):
        (ENV.data_dir / "config" / name).unlink(missing_ok=True)


def _login(client, user):
    client.cookies.set(security.SESSION_COOKIE, security.make_session_cookie(user))
    return security.csrf_token(user)


def test_admin_sees_all_user_sees_own(env):
    client, _, _ = env
    _login(client, "adm")
    body = client.get("/quarantine").text
    assert "Mine" in body and "NotMine" in body

    _login(client, "paul")
    body = client.get("/quarantine").text
    assert "Mine" in body and "NotMine" not in body  # plus-addressing match


def test_non_admin_locked_out_of_admin_pages(env):
    client, _, _ = env
    _login(client, "paul")
    assert client.get("/settings/ai").status_code == 403
    assert client.get("/logs").status_code == 403
    assert client.get("/", follow_redirects=False).headers["location"] == "/quarantine"
    assert client.get("/settings/context").status_code == 200


def test_preview_strips_remote_and_sets_csp(env):
    client, _, day = env
    _login(client, "paul")
    r = client.get(f"/quarantine/{day}/{'1' * 16}/preview")
    assert r.status_code == 200
    assert "default-src 'none'" in r.headers["content-security-policy"]
    assert "http://t/p.gif" not in r.text
    assert "tracking pixels have been blocked" in r.text

    _login(client, "adm")  # admin can preview anything
    assert client.get(f"/quarantine/{day}/{'2' * 16}/preview").status_code == 200


def test_stranger_cannot_touch_others_entry(env):
    client, _, day = env
    csrf = _login(client, "paul")
    assert client.get(f"/quarantine/{day}/{'2' * 16}/preview").status_code == 403
    r = client.post("/quarantine/delete",
                    data={"csrf": csrf, "entry_id": "2" * 16, "day": day},
                    follow_redirects=False)
    assert r.status_code == 403
    assert quarantine.get_meta("2" * 16, day)["status"] == "quarantined"


def test_release_delivers_and_whitelists(env):
    client, sent, day = env
    csrf = _login(client, "adm")
    r = client.post("/quarantine/release",
                    data={"csrf": csrf, "entry_id": "1" * 16, "day": day,
                          "whitelist_sender": "on"},
                    follow_redirects=False)
    assert r.status_code == 303
    assert len(sent) == 1
    mail_from, rcpts, msg = sent[0]
    assert mail_from == "s@sender.example"
    assert rcpts == ["paul+lists@fractalengine.com"]
    assert b"X-SpamAllam-Released:" in msg
    assert "sender.example" in SETTINGS.get("overrides.whitelist_domains")
    assert quarantine.get_meta("1" * 16, day)["status"] == "released"
    assert quarantine.get_original("1" * 16, day) is None


def test_non_admin_can_delete_own(env):
    client, _, day = env
    csrf = _login(client, "paul")
    r = client.post("/quarantine/delete",
                    data={"csrf": csrf, "entry_id": "1" * 16, "day": day},
                    follow_redirects=False)
    assert r.status_code == 303
    assert quarantine.get_meta("1" * 16, day)["status"] == "deleted"


def test_quarantine_settings_admin_only(env):
    client, _, _ = env
    csrf = _login(client, "paul")
    assert client.post("/settings/quarantine",
                       data={"csrf": csrf, "enabled": "on", "retention_days": 30},
                       follow_redirects=False).status_code == 403

    csrf = _login(client, "adm")
    r = client.post("/settings/quarantine",
                    data={"csrf": csrf, "enabled": "on", "retention_days": 45},
                    follow_redirects=False)
    assert r.status_code == 303
    assert SETTINGS.get("quarantine.retention_days") == 45
