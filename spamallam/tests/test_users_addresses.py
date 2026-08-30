import pytest

from app.config import ENV
from app.store import users as users_store


@pytest.fixture(autouse=True)
def clean_user_files():
    for name in ("users.yml", "tokens.yml"):
        (ENV.data_dir / "config" / name).unlink(missing_ok=True)
    yield
    for name in ("users.yml", "tokens.yml"):
        (ENV.data_dir / "config" / name).unlink(missing_ok=True)


def test_normalize_address():
    assert users_store.normalize_address("  Paul.Smith@Example.COM ") == "paul.smith@example.com"
    assert users_store.normalize_address("paul+newsletter@example.com") == "paul@example.com"
    assert users_store.normalize_address("Paul <paul@example.com>") == "paul@example.com"
    assert users_store.normalize_address("not-an-address") == ""  # no "@" -> not an address


def test_normalize_addresses_dedupes_and_drops_invalid():
    out = users_store.normalize_addresses(
        ["a@x.com", "A@X.com", "a+tag@x.com", "junk", "", "b@y.com"]
    )
    assert out == ["a@x.com", "b@y.com"]


def test_token_carries_addresses_into_created_user():
    token = users_store.create_token("alice", is_admin=False,
                                     addresses=["alice@x.com", "alice+lists@x.com"])
    record = users_store.consume_token(token)
    assert record["addresses"] == ["alice@x.com"]

    users_store.create_user("alice", "Alice", is_admin=False,
                            addresses=record["addresses"])
    assert users_store.get_user("alice")["addresses"] == ["alice@x.com"]


def test_set_addresses_replaces():
    users_store.create_user("bob", "Bob", is_admin=False, addresses=["bob@x.com"])
    assert users_store.set_addresses("bob", ["bob@x.com", "robert@x.com"])
    assert users_store.get_user("bob")["addresses"] == ["bob@x.com", "robert@x.com"]
    assert users_store.set_addresses("nobody", ["x@y.com"]) is False
