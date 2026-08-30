"""Route tests for the failure-policy settings page."""
import shutil

import pytest
from starlette.testclient import TestClient

from app.admin import app as admin_app
from app.admin import security
from app.config import ENV
from app.pipeline import failure
from app.store import users as users_store
from app.store.settings import SETTINGS


@pytest.fixture
def env():
    for name in ("users.yml", "tokens.yml", "settings.yml"):
        (ENV.data_dir / "config" / name).unlink(missing_ok=True)
    users_store.create_user("adm", "Adm", is_admin=True)
    users_store.create_user("paul", "Paul", is_admin=False, addresses=["paul@test.example"])
    yield TestClient(admin_app.create_app())
    for name in ("users.yml", "tokens.yml", "settings.yml"):
        (ENV.data_dir / "config" / name).unlink(missing_ok=True)


def _login(client, user):
    client.cookies.set(security.SESSION_COOKIE, security.make_session_cookie(user))
    return security.csrf_token(user)


def test_page_renders_with_resolved_defaults(env):
    _login(env, "adm")
    r = env.get("/settings/failure")
    assert r.status_code == 200
    assert 'value="deliver_tagged"' in r.text
    assert "CLAM_VIRUS_FAIL" in r.text


def test_save_round_trips(env):
    csrf = _login(env, "adm")
    r = env.post("/settings/failure",
                 data={"csrf": csrf, "ai": "defer", "rspamd": "quarantine",
                       "antivirus": "defer", "all_down": "defer"},
                 follow_redirects=False)
    assert r.status_code == 303
    cfg = SETTINGS.all()
    assert failure.resolve(cfg, "ai") == failure.DEFER
    assert failure.resolve(cfg, "rspamd") == failure.QUARANTINE
    assert failure.resolve(cfg, "all_down") == failure.DEFER


def test_bogus_policy_rejected(env):
    csrf = _login(env, "adm")
    r = env.post("/settings/failure",
                 data={"csrf": csrf, "ai": "ignore-everything", "rspamd": "defer",
                       "antivirus": "defer", "all_down": "defer"},
                 follow_redirects=False)
    assert r.status_code in (303, 400)
    assert failure.resolve(SETTINGS.all(), "ai") != "ignore-everything"


def test_non_admin_cannot_read_or_write(env):
    csrf = _login(env, "paul")
    assert env.get("/settings/failure").status_code == 403
    r = env.post("/settings/failure",
                 data={"csrf": csrf, "ai": "defer", "rspamd": "defer",
                       "antivirus": "defer", "all_down": "defer"},
                 follow_redirects=False)
    assert r.status_code == 403
