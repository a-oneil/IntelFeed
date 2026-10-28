"""SourceGateway: rate limit, daily budget and circuit breaker per HTTP request.

These run against real Redis (the test REDIS_URL; conftest gives each test its
own key prefix) with ``httpx.MockTransport`` standing in for the source.
"""

import asyncio
import re
import uuid
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
import redis.asyncio as aioredis
from sqlalchemy import select

from app.enrichment import gateway as gw
from app.enrichment.gateway import (
    USER_AGENT,
    BreakerOpen,
    BudgetExhausted,
    GatewayUnavailable,
    RateLimited,
    SourceGateway,
    parse_retry_after,
)
from app.models.enrichment import EnrichmentResult, EnrichmentSource


class _Source:
    """Serves canned responses and counts what reaches it."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        reply = self.responses.pop(0) if self.responses else httpx.Response(200, json={})
        if isinstance(reply, Exception):
            raise reply
        return reply


def _gateway(server: _Source, per=100, period=3600, budget=None, key=None, group=None, source="nvd"):
    return SourceGateway(
        source,
        rate_limit_config={"requests_per_period": per, "period_seconds": period},
        daily_budget=budget,
        api_key=key,
        shared_key_group=group,
        inner=httpx.MockTransport(server),
    )


async def _get(gateway: SourceGateway) -> httpx.Response:
    async with gateway.client() as client:
        return await client.get("https://example.test/x")


# ── Bucket and budget ────────────────────────────────────────────────


async def test_bucket_limits_requests():
    server = _Source()
    g = _gateway(server, per=3)
    for _ in range(3):
        await _get(g)
    with pytest.raises(RateLimited) as exc:
        await _get(g)
    assert exc.value.retry_after > gw.MAX_TOKEN_WAIT
    assert len(server.requests) == 3


async def test_refused_requests_consume_nothing():
    server = _Source()
    g = _gateway(server, per=2, budget=10)
    await _get(g)
    await _get(g)
    for _ in range(5):
        with pytest.raises(RateLimited):
            await _get(g)
    # A busy source can't lock itself out: refusals took no tokens and no budget.
    assert await g.remaining() == 0
    assert await g.used_today() == 2
    assert len(server.requests) == 2


async def test_budget_is_charged_only_for_sent_requests():
    server = _Source()
    g = _gateway(server, per=100, budget=2)
    await _get(g)
    await _get(g)
    with pytest.raises(BudgetExhausted):
        await _get(g)
    assert len(server.requests) == 2
    assert await g.used_today() == 2
    assert await g.remaining() == 98  # the refused request took no token


async def test_waits_briefly_for_the_next_token():
    server = _Source()
    g = _gateway(server, per=2, period=1)  # a token every 0.5 s
    await _get(g)
    await _get(g)
    start = asyncio.get_running_loop().time()
    await _get(g)
    assert 0.2 < asyncio.get_running_loop().time() - start < gw.MAX_TOKEN_WAIT
    assert len(server.requests) == 3


async def test_buckets_are_per_key():
    server = _Source()
    keyless, key_a, key_a_again, key_b = (
        _gateway(server, per=1),
        _gateway(server, per=1, key="key-a"),
        _gateway(server, per=1, key="key-a"),
        _gateway(server, per=1, key="key-b"),
    )
    await _get(keyless)
    await _get(key_a)
    await _get(key_b)  # a user's override key has its own allowance
    with pytest.raises(RateLimited):
        await _get(key_a_again)  # the same key shares one
    assert "key-a" not in key_a.scope
    assert len(server.requests) == 3


async def test_shared_key_group_shares_one_bucket():
    server = _Source()
    first = _gateway(server, per=1, key="shared", group="abuse_ch", source="urlhaus")
    second = _gateway(server, per=1, key="shared", group="abuse_ch", source="threatfox")
    await _get(first)
    with pytest.raises(RateLimited):
        await _get(second)
    assert len(server.requests) == 1


# ── Breaker ──────────────────────────────────────────────────────────


async def test_retry_after_seconds_opens_the_breaker():
    server = _Source(httpx.Response(429, headers={"Retry-After": "120"}))
    g = _gateway(server)
    with pytest.raises(RateLimited) as exc:
        await _get(g)
    assert exc.value.retry_after == 120
    with pytest.raises(BreakerOpen) as exc:
        await _get(g)
    assert 115 < exc.value.retry_after <= 120
    assert len(server.requests) == 1


async def test_retry_after_date_opens_the_breaker():
    when = format_datetime(datetime.now(UTC) + timedelta(seconds=300), usegmt=True)
    server = _Source(httpx.Response(503, headers={"Retry-After": when}))
    g = _gateway(server)
    with pytest.raises(RateLimited):
        await _get(g)
    with pytest.raises(BreakerOpen) as exc:
        await _get(g)
    assert 290 < exc.value.retry_after <= 300


async def test_throttle_without_retry_after_backs_off():
    server = _Source(httpx.Response(429))
    g = _gateway(server)
    with pytest.raises(RateLimited) as exc:
        await _get(g)
    assert exc.value.retry_after == gw.BACKOFF_BASE


async def test_three_server_errors_open_the_breaker():
    server = _Source(httpx.Response(500), httpx.Response(502), httpx.ConnectError("refused"))
    g = _gateway(server)
    assert (await _get(g)).status_code == 500
    assert (await _get(g)).status_code == 502
    with pytest.raises(httpx.ConnectError):
        await _get(g)
    with pytest.raises(BreakerOpen) as exc:
        await _get(g)
    assert exc.value.retry_after <= gw.BACKOFF_BASE
    assert len(server.requests) == 3


async def test_success_closes_the_breaker():
    server = _Source(
        httpx.Response(500),
        httpx.Response(500),
        httpx.Response(404),  # any answer that isn't a server error counts
        httpx.Response(500),
        httpx.Response(500),
    )
    g = _gateway(server)
    for _ in range(5):
        await _get(g)
    await _get(g)  # two failures since the success: still closed

    # An open breaker that has run out lets a probe through; its success
    # resets the backoff, so the next throttle starts from the base again.
    server.responses = [httpx.Response(429, headers={"Retry-After": "1"}), httpx.Response(200)]
    with pytest.raises(RateLimited):
        await _get(g)
    await asyncio.sleep(1.1)
    assert (await _get(g)).status_code == 200
    server.responses = [httpx.Response(429)]
    with pytest.raises(RateLimited) as exc:
        await _get(g)
    assert exc.value.retry_after == gw.BACKOFF_BASE


async def test_in_flight_success_does_not_close_an_open_breaker():
    """Another worker's request, sent before a 429 opened the breaker, answers
    200 afterwards: the source's Retry-After still stands."""
    server = _Source(httpx.Response(429, headers={"Retry-After": "120"}))
    g = _gateway(server)
    with pytest.raises(RateLimited):
        await _get(g)
    await g.record(httpx.Response(200))
    with pytest.raises(BreakerOpen) as exc:
        await _get(g)
    assert 115 < exc.value.retry_after <= 120
    assert len(server.requests) == 1


# ── Fail closed, User-Agent ──────────────────────────────────────────


async def test_redis_unreachable_sends_nothing():
    server = _Source()
    g = _gateway(server)
    dead = aioredis.from_url("redis://127.0.0.1:1/0", socket_connect_timeout=0.5)

    async def broken():
        return dead

    with patch.object(gw, "get_redis_bytes", broken), pytest.raises(GatewayUnavailable):
        await _get(g)
    assert server.requests == []


async def test_user_agent_is_set():
    server = _Source()
    g = _gateway(server)
    async with g.client(headers={"User-Agent": "python-httpx"}) as client:
        await client.get("https://example.test/x")
    assert server.requests[0].headers["User-Agent"] == USER_AGENT
    assert USER_AGENT.startswith("IntelFeed/") and "intelfeed.local" not in USER_AGENT


def test_parse_retry_after():
    assert parse_retry_after("30") == 30
    assert parse_retry_after(None) is None
    assert parse_retry_after("soon") is None
    assert parse_retry_after("9999999") == gw.RETRY_AFTER_CAP
    past = format_datetime(datetime.now(UTC) - timedelta(minutes=5), usegmt=True)
    assert parse_retry_after(past) == 0


def test_adapters_never_build_their_own_client():
    """Every adapter request must go through self.http() / the gateway."""
    adapters = Path(__file__).parents[1] / "app" / "enrichment" / "adapters"
    direct = re.compile(r"httpx\.(AsyncClient|Client|get|post|put|request|stream)\b|from httpx import")
    offenders = [
        f"{path.name}:{n}"
        for path in sorted(adapters.glob("*.py"))
        for n, line in enumerate(path.read_text().splitlines(), 1)
        if direct.search(line)
    ]
    assert offenders == []


async def test_adapter_without_a_gateway_cannot_make_requests():
    from app.enrichment.registry import get_adapter

    with pytest.raises(RuntimeError, match="no SourceGateway"):
        get_adapter("osv").http()


# ── Pipeline outcomes ────────────────────────────────────────────────


async def _source_row(db_session, **fields) -> EnrichmentSource:
    row = (
        await db_session.execute(select(EnrichmentSource).where(EnrichmentSource.source_type == "osv"))
    ).scalar_one_or_none()
    if row is None:
        row = EnrichmentSource(source_type="osv", display_name="OSV")
        db_session.add(row)
    row.is_enabled = True
    row.trigger_mode = "manual"
    row.config = {}
    row.daily_budget = None
    row.rate_limit_config = {"requests_per_period": 100, "period_seconds": 60}
    for k, v in fields.items():
        setattr(row, k, v)
    await db_session.flush()
    return row


async def _enrich(db_session, server: _Source):
    from app.enrichment import pipeline
    from app.enrichment.registry import get_adapter, source_gateway

    def wired(source, api_key):
        g = source_gateway(source, api_key)
        g._inner = httpx.MockTransport(server)
        return get_adapter(source.source_type, api_key=api_key, config=source.config, gateway=g)

    entity_id = uuid.uuid4()
    with patch.object(pipeline, "adapter_for_source", wired):
        results = await pipeline.enrich_entity(
            "cve", entity_id, "CVE-2021-44228", db_session, trigger="manual", source_types=["osv"]
        )
    stored = (await db_session.execute(select(EnrichmentResult).where(EnrichmentResult.entity_id == entity_id))).all()
    return results, stored


async def test_pipeline_success_through_the_gateway(db_session):
    await _source_row(db_session)
    server = _Source(httpx.Response(200, json={"id": "CVE-2021-44228", "aliases": []}))
    (result,), stored = await _enrich(db_session, server)
    assert result["status"] == "success"
    assert len(stored) == 1
    assert server.requests[0].headers["User-Agent"] == USER_AGENT


async def test_pipeline_rate_limited(db_session):
    source = await _source_row(db_session, rate_limit_config={"requests_per_period": 1, "period_seconds": 3600})
    from app.enrichment.registry import source_gateway

    await source_gateway(source, None).acquire()
    (result,), stored = await _enrich(db_session, _Source())
    assert result["status"] == "rate_limited" and result["retry_after"] > 0
    assert stored == []


async def test_pipeline_budget_exhausted(db_session):
    await _source_row(db_session, daily_budget=0)
    server = _Source()
    (result,), stored = await _enrich(db_session, server)
    assert result == {"source_type": "osv", "status": "budget_exhausted"}
    assert stored == [] and server.requests == []


async def test_pipeline_breaker_open(db_session):
    source = await _source_row(db_session)
    from app.enrichment.registry import source_gateway

    await source_gateway(source, None)._trip("throttle", 600)
    (result,), stored = await _enrich(db_session, _Source())
    assert result["status"] == "breaker_open" and 590 < result["retry_after"] <= 600
    assert stored == []


async def test_pipeline_gateway_unavailable(db_session):
    await _source_row(db_session)
    dead = aioredis.from_url("redis://127.0.0.1:1/0", socket_connect_timeout=0.5)

    async def broken():
        return dead

    server = _Source()
    with patch.object(gw, "get_redis_bytes", broken):
        (result,), stored = await _enrich(db_session, server)
    assert result == {"source_type": "osv", "status": "gateway_unavailable"}
    assert stored == [] and server.requests == []


async def test_pipeline_server_error_is_still_an_error_row(db_session):
    await _source_row(db_session)
    (result,), stored = await _enrich(db_session, _Source(httpx.Response(500)))
    assert result["status"] == "error"
    assert len(stored) == 1
