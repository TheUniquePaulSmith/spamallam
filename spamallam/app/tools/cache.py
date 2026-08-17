"""Best-effort Redis cache for expensive network lookups in netinfo.py.

Fails open on any Redis error (connection refused, timeout, unreachable
during startup, ...): callers always fall through to a fresh fetch, so a
down or unreachable cache can never break message analysis. Error results
from the wrapped fetch are never cached, so a transient RDAP/DNS outage
doesn't stick around for the full TTL.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Awaitable, Callable

import redis.asyncio as aioredis

from ..config import ENV

logger = logging.getLogger(__name__)

_client: aioredis.Redis | None = None


def _get_client() -> aioredis.Redis:
    global _client
    if _client is None:
        _client = aioredis.from_url(
            ENV.redis_url, decode_responses=True,
            socket_connect_timeout=2, socket_timeout=2,
        )
    return _client


async def cached(key: str, ttl: int, fetch: Callable[[], Awaitable[Any]]) -> Any:
    """Return the cached value for `key`, or call `fetch()` and cache the
    result for `ttl` seconds. Dict results containing an "error" key are
    passed through but never cached."""
    client = _get_client()
    try:
        hit = await client.get(key)
        if hit is not None:
            return json.loads(hit)
    except Exception as exc:  # noqa: BLE001 — cache is best-effort
        logger.warning("netinfo cache read failed (%s): %s: %s", key, type(exc).__name__, exc)

    value = await fetch()

    if isinstance(value, dict) and "error" in value:
        return value

    try:
        await client.set(key, json.dumps(value), ex=ttl)
    except Exception as exc:  # noqa: BLE001
        logger.warning("netinfo cache write failed (%s): %s: %s", key, type(exc).__name__, exc)

    return value
