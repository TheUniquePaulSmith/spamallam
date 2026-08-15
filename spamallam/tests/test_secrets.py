import pytest

from app.store.secrets import SecretsBox, redact


def test_roundtrip_and_shape():
    box = SecretsBox("some-master-key")
    blob = box.encrypt("sk-super-secret")
    assert SecretsBox.is_encrypted(blob)
    assert "sk-super-secret" not in str(blob)
    assert box.decrypt_str(blob) == "sk-super-secret"


def test_wrong_key_fails():
    blob = SecretsBox("key-one").encrypt("value")
    with pytest.raises(Exception):
        SecretsBox("key-two").decrypt(blob)


def test_placeholder_key_rejected():
    with pytest.raises(RuntimeError):
        SecretsBox("change-me-openssl-rand-hex-32")


def test_redact_nested():
    box = SecretsBox("k")
    data = {"provider": {"api_key": box.encrypt("secret"), "model": "gpt"}}
    red = redact(data)
    assert red["provider"]["api_key"] == "•••••• (set)"
    assert red["provider"]["model"] == "gpt"
