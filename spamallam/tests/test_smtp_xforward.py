"""XFORWARD trust: only the edge MTA may rewrite the client identity."""
import dataclasses
from types import SimpleNamespace

from app.smtp import server


def _session(peer_ip):
    return SimpleNamespace(peer=(peer_ip, 54321))


def _with_peers(monkeypatch, peers):
    monkeypatch.setattr(
        server, "ENV",
        dataclasses.replace(server.ENV, xforward_trusted_peers=frozenset(peers)),
    )


def test_any_peer_trusted_when_unconfigured(monkeypatch):
    """Backwards-compatible default for deployments that have not segmented
    their networks yet -- the port itself is the only boundary there."""
    _with_peers(monkeypatch, set())
    assert server._peer_is_trusted(_session("172.28.2.99")) is True


def test_only_the_configured_edge_is_trusted(monkeypatch):
    """rspamd/redis/clamav must not be able to forge the client IP that rspamd
    then evaluates SPF and the RBLs against."""
    _with_peers(monkeypatch, {"172.28.1.2"})
    assert server._peer_is_trusted(_session("172.28.1.2")) is True
    assert server._peer_is_trusted(_session("172.28.2.99")) is False
    assert server._peer_is_trusted(SimpleNamespace(peer=None)) is False


def test_config_parses_a_comma_separated_list(monkeypatch):
    monkeypatch.setenv("XFORWARD_TRUSTED_PEERS", "10.0.0.1, 10.0.0.2 ,")
    from app.config import Env
    assert Env().xforward_trusted_peers == frozenset({"10.0.0.1", "10.0.0.2"})
