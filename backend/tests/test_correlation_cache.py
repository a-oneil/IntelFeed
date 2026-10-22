"""Tests for correlation cache (unit tests that mock Redis)."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.intelligence.correlation_cache import (
    _graph_key,
    _pivot_key,
    get_cached_graph,
    get_cached_pivot,
    get_pivot_ttl,
    invalidate_entity_cache,
    refresh_top_entities_cache,
    set_cached_pivot,
)
from app.models.threat_actor import ThreatActor


@pytest.fixture
def mock_redis():
    """Create a mock Redis client."""
    redis = AsyncMock()
    redis.get = AsyncMock(return_value=None)
    redis.set = AsyncMock()
    redis.delete = AsyncMock()
    redis.scan_iter = MagicMock()

    async def empty_iter(*args, **kwargs):
        return
        yield  # Make it an async generator

    redis.scan_iter.return_value = empty_iter()
    return redis


@pytest.mark.asyncio
async def test_pivot_cache_miss(mock_redis):
    """Cache miss returns None."""
    with patch("app.intelligence.correlation_cache.get_redis", return_value=mock_redis):
        result = await get_cached_pivot("ioc", "some-id")
        assert result is None


@pytest.mark.asyncio
async def test_pivot_cache_hit(mock_redis):
    """Cache hit returns deserialized data."""
    data = {"entity": {"type": "ioc", "value": "1.2.3.4"}, "related": {}, "entries": []}
    mock_redis.get = AsyncMock(return_value=json.dumps(data))

    with patch("app.intelligence.correlation_cache.get_redis", return_value=mock_redis):
        result = await get_cached_pivot("ioc", "some-id")
        assert result == data


@pytest.mark.asyncio
async def test_set_cached_pivot(mock_redis):
    """Setting cache calls Redis SET with correct key and TTL."""
    data = {"entity": {"type": "ioc"}}
    with patch("app.intelligence.correlation_cache.get_redis", return_value=mock_redis):
        await set_cached_pivot("ioc", "abc", data, ttl=600)
        mock_redis.set.assert_called_once()
        args = mock_redis.set.call_args
        assert args[0][0] == _pivot_key("ioc", "abc")
        assert args[1]["ex"] == 600


@pytest.mark.asyncio
async def test_graph_cache_miss(mock_redis):
    """Graph cache miss returns None."""
    with patch("app.intelligence.correlation_cache.get_redis", return_value=mock_redis):
        result = await get_cached_graph("threat_actor", "some-id", 1)
        assert result is None


@pytest.mark.asyncio
async def test_graph_cache_hit(mock_redis):
    """Graph cache hit returns data."""
    data = {"nodes": [{"id": "threat_actor-1"}], "edges": []}
    mock_redis.get = AsyncMock(return_value=json.dumps(data))

    with patch("app.intelligence.correlation_cache.get_redis", return_value=mock_redis):
        result = await get_cached_graph("threat_actor", "some-id", 2)
        assert result == data


@pytest.mark.asyncio
async def test_invalidate_entity_cache(mock_redis):
    """Invalidation deletes pivot key and scans for graph keys."""

    async def fake_scan(*args, **kwargs):
        yield "intelfeed:corr:graph2:ioc:abc:1"
        yield "intelfeed:corr:graph2:ioc:abc:2"

    mock_redis.scan_iter = MagicMock(return_value=fake_scan())

    with patch("app.intelligence.correlation_cache.get_redis", return_value=mock_redis):
        await invalidate_entity_cache("ioc", "abc")
        mock_redis.delete.assert_called_once()
        deleted_keys = mock_redis.delete.call_args[0]
        assert _pivot_key("ioc", "abc") in deleted_keys
        assert len(deleted_keys) == 3  # pivot + 2 graph keys


@pytest.mark.asyncio
async def test_cache_graceful_on_redis_error(mock_redis):
    """Cache operations should not raise on Redis errors."""
    mock_redis.get = AsyncMock(side_effect=ConnectionError("Redis down"))

    with patch("app.intelligence.correlation_cache.get_redis", return_value=mock_redis):
        result = await get_cached_pivot("ioc", "abc")
        assert result is None  # Graceful degradation


def test_key_format():
    """Key format is correct."""
    assert _pivot_key("ioc", "abc") == "intelfeed:corr:pivot3:ioc:abc"
    assert _graph_key("threat_actor", "xyz", 2) == "intelfeed:corr:graph3:threat_actor:xyz:2"


@pytest.mark.asyncio
async def test_get_pivot_ttl_returns_redis_ttl(mock_redis):
    """get_pivot_ttl returns the raw Redis TTL for the pivot key."""
    mock_redis.ttl = AsyncMock(return_value=1800)
    with patch("app.intelligence.correlation_cache.get_redis", return_value=mock_redis):
        ttl = await get_pivot_ttl("ioc", "abc")
        assert ttl == 1800
        # The key carries the display-confidence / evidence-structure variant,
        # so the expectation has to compute it the same way.
        from app.intelligence.correlation_cache import confidence_cache_variant

        mock_redis.ttl.assert_awaited_once_with(_pivot_key("ioc", "abc", confidence_cache_variant()))


@pytest.mark.asyncio
async def test_get_pivot_ttl_graceful_on_error(mock_redis):
    """get_pivot_ttl reports 'absent' (-2) instead of raising on Redis errors."""
    mock_redis.ttl = AsyncMock(side_effect=ConnectionError("Redis down"))
    with patch("app.intelligence.correlation_cache.get_redis", return_value=mock_redis):
        assert await get_pivot_ttl("ioc", "abc") == -2


def _db_returning_ids(ids):
    """Build a mock AsyncSession whose execute().all() yields one-tuples of ids."""
    db = AsyncMock()
    result = MagicMock()
    result.all = MagicMock(return_value=[(i,) for i in ids])
    db.execute = AsyncMock(return_value=result)
    return db


@pytest.mark.asyncio
async def test_refresh_skips_cached_entities():
    """Entities that are still cached (ttl != -2) are not recomputed."""
    db = _db_returning_ids(["e1", "e2"])
    entity_config = {"threat_actor": (ThreatActor, None, None)}
    pivot = AsyncMock()

    with (
        patch("app.intelligence.correlation.ENTITY_CONFIG", entity_config),
        patch("app.intelligence.correlation.pivot_from_entity", pivot),
        patch("app.intelligence.correlation_cache.get_pivot_ttl", AsyncMock(return_value=1800)),
        patch("app.intelligence.correlation_cache.set_cached_pivot", AsyncMock()) as set_pivot,
    ):
        refreshed = await refresh_top_entities_cache(db, limit=10)

    assert refreshed == 0
    pivot.assert_not_awaited()
    set_pivot.assert_not_awaited()


@pytest.mark.asyncio
async def test_refresh_recomputes_missing_entities():
    """Entities whose pivot is absent (ttl == -2) are recomputed and cached."""
    db = _db_returning_ids(["e1", "e2"])
    entity_config = {"threat_actor": (ThreatActor, None, None)}
    pivot = AsyncMock(return_value={"entity": {}, "related": {}})

    with (
        patch("app.intelligence.correlation.ENTITY_CONFIG", entity_config),
        patch("app.intelligence.correlation.pivot_from_entity", pivot),
        patch("app.intelligence.correlation_cache.get_pivot_ttl", AsyncMock(return_value=-2)),
        patch("app.intelligence.correlation_cache.set_cached_pivot", AsyncMock()) as set_pivot,
    ):
        refreshed = await refresh_top_entities_cache(db, limit=10)

    assert refreshed == 2
    assert pivot.await_count == 2
    assert set_pivot.await_count == 2


@pytest.mark.asyncio
async def test_refresh_respects_time_budget():
    """A spent wall-clock budget stops the loop before computing any pivot."""
    db = _db_returning_ids(["e1", "e2", "e3"])
    entity_config = {"threat_actor": (ThreatActor, None, None)}
    pivot = AsyncMock(return_value={"entity": {}})

    with (
        patch("app.intelligence.correlation.ENTITY_CONFIG", entity_config),
        patch("app.intelligence.correlation.pivot_from_entity", pivot),
        patch("app.intelligence.correlation_cache.get_pivot_ttl", AsyncMock(return_value=-2)),
        patch("app.intelligence.correlation_cache.set_cached_pivot", AsyncMock()),
    ):
        # Negative budget => already exhausted on the first entity.
        refreshed = await refresh_top_entities_cache(db, limit=10, time_budget_seconds=-1)

    assert refreshed == 0
    pivot.assert_not_awaited()
