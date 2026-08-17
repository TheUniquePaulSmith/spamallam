from pathlib import Path

from app.store.settings import SettingsStore


def test_defaults_and_dotted_set(tmp_path: Path):
    store = SettingsStore(tmp_path / "settings.yml")
    assert store.get("ai.enabled") is False
    assert store.get("tools.unifi_block.policy") == "suggest"
    # pipeline order/bypass/rspamd-marking default to today's exact behavior
    assert store.get("ai.pipeline_order") == "ai_first"
    assert store.get("ai.rspamd_bypass_on_reject") is False
    assert store.get("marking.trigger_on_rspamd_spam") is False

    old, new = store.set("ai.enabled", True)
    assert (old, new) == (False, True)
    assert store.get("ai.enabled") is True

    # defaults still merged for untouched keys
    assert store.get("ai.failure_mode") == "fail_open"


def test_update_reports_changes(tmp_path: Path):
    store = SettingsStore(tmp_path / "settings.yml")
    changes = store.update({"ai.enabled": True, "ai.failure_mode": "fail_open"})
    # failure_mode unchanged from default -> only one real change
    assert [c[0] for c in changes] == ["ai.enabled"]
