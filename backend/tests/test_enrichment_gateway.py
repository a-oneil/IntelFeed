"""SourceGateway: rate limit, daily budget and circuit breaker per HTTP request.

These run against real Redis (the test REDIS_URL; conftest gives each test its
own key prefix) with ``httpx.MockTransport`` standing in for the source.
"""

import asyncio
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
    AuthFailed,
    BackfillShareUsed,
    BreakerOpen,
    BudgetExhausted,
    GatewayUnavailable,
    Paused,
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


def _gateway(server: _Source, per=100, period=3600, budget=None, key=None, group=None, source="nvd", **kw):
    return SourceGateway(
        source,
        rate_limit_config={"requests_per_period": per, "period_seconds": period},
        daily_budget=budget,
        api_key=key,
        shared_key_group=group,
        inner=httpx.MockTransport(server),
        **kw,
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


async def test_no_window_ever_holds_more_than_the_rate():
    """A rolling window, not a token bucket: a burst at the end of one period
    can't be followed by a full period's worth at the start of the next."""
    server = _Source()
    sent: list[float] = []

    def stamp(request):
        sent.append(asyncio.get_running_loop().time())
        return server(request)

    g = SourceGateway(
        "nvd",
        rate_limit_config={"requests_per_period": 3, "period_seconds": 1},
        max_wait=5,
        inner=httpx.MockTransport(stamp),
    )
    for _ in range(7):
        await _get(g)
    # A full second apart in principle; a late stamp on a busy runner shaves a little off.
    assert all(sent[i + 3] - sent[i] >= 0.85 for i in range(len(sent) - 3))


async def test_a_full_window_names_when_the_next_slot_frees():
    g = _gateway(_Source(), per=2, period=60)
    await _get(g)
    await _get(g)
    with pytest.raises(RateLimited) as exc:
        await _get(g)
    assert 55 < exc.value.retry_after <= 60


# ── Concurrency ──────────────────────────────────────────────────────


class _Slow(httpx.AsyncBaseTransport):
    """Answers after a pause and records how many requests overlapped."""

    def __init__(self):
        self.active = self.peak = 0

    async def handle_async_request(self, request):
        self.active += 1
        self.peak = max(self.peak, self.active)
        await asyncio.sleep(0.5)  # long enough that waiting requests overlap on a busy runner
        self.active -= 1
        return httpx.Response(200, content=b"ok")


async def test_concurrency_caps_requests_in_flight_across_gateways():
    """Two gateways on one credential (two workers) share one in-flight cap."""
    slow = _Slow()
    gateways = [
        SourceGateway("osv", {"requests_per_period": 100, "period_seconds": 1}, inner=slow, concurrency=2, max_wait=10)
        for _ in range(2)
    ]
    await asyncio.gather(*(_get(gateways[i % 2]) for i in range(6)))
    assert slow.peak == 2
    assert await gateways[0].in_flight() == 0


async def test_the_in_flight_slot_is_freed_on_a_transport_error():
    g = _gateway(_Source(httpx.ConnectError("refused")), concurrency=1)
    with pytest.raises(httpx.ConnectError):
        await _get(g)
    assert await g.in_flight() == 0
    await _get(g)  # the slot is free


async def test_a_streamed_body_holds_its_slot_until_closed():
    class _Stream(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            class Body(httpx.AsyncByteStream):
                async def __aiter__(self):
                    yield b"abc"

            return httpx.Response(200, stream=Body())

    g = SourceGateway("osv", {"requests_per_period": 100, "period_seconds": 60}, inner=_Stream())
    async with g.client() as client, client.stream("GET", "https://example.test/x") as response:
        assert await g.in_flight() == 1
        await response.aread()
    assert await g.in_flight() == 0


async def test_an_unreleased_slot_expires_with_its_lease():
    g = _gateway(_Source(), concurrency=1)
    await g.acquire(lease=0.5)  # a worker that died mid-request
    assert await g.in_flight() == 1
    await asyncio.sleep(1.0)
    assert await g.in_flight() == 0
    await _get(g)


async def test_permit_wraps_a_request_made_without_httpx():
    g = _gateway(_Source(), concurrency=1)
    async with g.permit():
        assert await g.in_flight() == 1
        await g.record(httpx.Response(200), release=False)
    assert await g.in_flight() == 0


async def test_source_gateway_takes_the_quota_s_concurrency():
    from app.enrichment.registry import source_gateway

    g = source_gateway(EnrichmentSource(source_type="osv", rate_limit_config={}), None)
    assert g.concurrency == 2  # Quota's default


# ── Auth failures ────────────────────────────────────────────────────


async def test_a_401_is_an_auth_failure_not_a_throttle():
    server = _Source(httpx.Response(401, json={"message": "Invalid API key"}))
    g = _gateway(server, key="bad")
    with pytest.raises(AuthFailed) as exc:
        await _get(g)
    assert "rejected the API key (HTTP 401): Invalid API key" in str(exc.value)
    with pytest.raises(AuthFailed) as exc:
        await _get(g)  # refused without a request, and not backing off
    assert exc.value.retry_after > gw.AUTH_FAILED_TTL - 5
    assert len(server.requests) == 1
    assert await g.breaker_open_for() == 0

    auth = await g.auth_failure()
    assert auth["status"] == 401 and "Invalid API key" in auth["message"]


async def test_a_new_key_starts_clean_and_clearing_lets_a_key_retry():
    server = _Source(httpx.Response(401))
    bad = _gateway(server, key="bad")
    with pytest.raises(AuthFailed):
        await _get(bad)
    await _get(_gateway(server, key="good"))
    await bad.clear_auth_failure()
    await _get(bad)
    assert len(server.requests) == 3


async def test_a_403_on_the_window_s_first_request_with_a_key_is_an_auth_failure():
    server = _Source(httpx.Response(403, text="Forbidden"))
    g = _gateway(server, key="k", throttle_statuses=(403, 429, 503))
    with pytest.raises(AuthFailed):
        await _get(g)


async def test_a_403_with_a_rate_limit_signal_is_a_throttle():
    server = _Source(httpx.Response(403, headers={"X-RateLimit-Remaining": "0", "Retry-After": "30"}))
    g = _gateway(server, key="k", throttle_statuses=(403, 429, 503))
    with pytest.raises(RateLimited) as exc:
        await _get(g)
    assert exc.value.retry_after == 30
    assert await g.breaker_open_for() > 0


async def test_repeated_ambiguous_403s_become_an_auth_failure():
    """A keyed 403 with requests already in the window may be a throttle, so
    it backs off; AUTH_403_STREAK of them in a row mean the key."""
    server = _Source(httpx.Response(200), *[httpx.Response(403)] * gw.AUTH_403_STREAK)
    g = _gateway(server, key="k")  # 403 is an ordinary answer for this source
    await _get(g)
    for _ in range(gw.AUTH_403_STREAK - 1):
        assert (await _get(g)).status_code == 403
    with pytest.raises(AuthFailed):
        await _get(g)


# ── Backfill share, pause ────────────────────────────────────────────


async def test_backfill_lane_requests_stop_at_their_share_of_the_budget():
    server = _Source()
    g = _gateway(server, budget=10)
    sent = 0
    with gw.in_lane("backfill"), pytest.raises(BackfillShareUsed):
        for _ in range(10):
            await _get(g)
            sent += 1
    assert sent == 6  # 60% of 10
    await _get(g)  # outside the lane the rest of the budget is still there
    assert await g.used_today() == 7


async def test_a_gateway_built_for_the_backfill_lane_stops_there_too():
    g = _gateway(_Source(), budget=5, lane="backfill")
    for _ in range(3):
        await _get(g)
    with pytest.raises(BudgetExhausted) as exc:  # BackfillShareUsed is one
        await _get(g)
    assert exc.value.status == "backfill_share"


async def test_a_lost_pause_flag_falls_back_on_the_settings_cache(monkeypatch):
    """Redis lost the pause flag and its marker: the gateway asks the
    settings cache, and puts the flag back while paused."""
    import app.services.system_settings as ss

    g = _gateway(_Source())
    monkeypatch.setattr(ss, "get_setting_cached", lambda key: True if key == "enrichment_paused" else None)
    with pytest.raises(Paused):
        await _get(g)
    r = await gw.get_redis_bytes()
    assert await r.exists(gw.paused_key())

    # Once a sync has written the marker, the flag alone decides.
    await r.delete(gw.paused_key())
    await r.set(gw.pause_synced_key(), b"1")
    await _get(g)


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


async def test_throttle_statuses_are_per_source():
    from app.enrichment.registry import source_gateway

    server = _Source(httpx.Response(403), httpx.Response(403))
    assert (await _get(_gateway(server))).status_code == 403  # an ordinary answer by default

    nvd = source_gateway(EnrichmentSource(source_type="nvd", rate_limit_config={}), None)
    nvd._inner = httpx.MockTransport(server)
    with pytest.raises(RateLimited):
        await _get(nvd)  # NVD throttles with 403
    with pytest.raises(BreakerOpen):
        await _get(nvd)
    assert len(server.requests) == 2


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


#: HTTP calls that don't go through a gateway, by module: what builds or sends
#: a request directly. A call inside one of these is a direct request.
_DIRECT_HTTP = {
    "httpx": {"AsyncClient", "Client", "get", "post", "put", "patch", "delete", "head", "request", "stream"},
    "requests": {"get", "post", "put", "patch", "delete", "head", "request", "Session"},
    "aiohttp": {"ClientSession", "request"},
    "urllib.request": {"urlopen", "Request", "build_opener"},
}

#: The only places under the scanned trees that may make a direct request,
#: by (file, enclosing function). Each is not an enrichment source:
_DIRECT_HTTP_ALLOWED = {
    # The gateway itself: the one client every other request goes through.
    ("enrichment/gateway.py", "client"),
    ("enrichment/gateway.py", "client_for"),
    # Re-imports rule files from GitHub repos the rule importer already
    # tracks; part of detection-rule import, not an enrichment source.
    ("workers/maintenance.py", "_backfill_rule_attack_mappings"),
    # The Piper TTS sidecar on the compose network.
    ("workers/tts_tasks.py", "_synthesize"),
    # A publisher's own IOC file, linked from the article being read.
    ("intelligence/publisher_iocs.py", "fetch_publisher_file"),
}


def _direct_http_calls(path: Path, rel: str) -> list[tuple[str, str]]:
    """(file:line, enclosing function) of each direct HTTP call in ``path``."""
    import ast

    tree = ast.parse(path.read_text())
    aliases: dict[str, str] = {}  # local name -> "module" or "module.attr"
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name in _DIRECT_HTTP or a.name.split(".")[0] in {"httpx", "requests", "aiohttp", "urllib"}:
                    aliases[a.asname or a.name.split(".")[0]] = a.asname and a.name or a.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module in _DIRECT_HTTP:
            for a in node.names:
                if a.name in _DIRECT_HTTP[node.module]:
                    aliases[a.asname or a.name] = f"{node.module}.{a.name}"

    def dotted(expr) -> str | None:
        if isinstance(expr, ast.Name):
            return aliases.get(expr.id, expr.id)
        if isinstance(expr, ast.Attribute):
            base = dotted(expr.value)
            return f"{base}.{expr.attr}" if base else None
        return None

    def is_direct(name: str | None) -> bool:
        if not name:
            return False
        module, _, attr = name.rpartition(".")
        return attr in _DIRECT_HTTP.get(module, ())

    found = []

    def visit(node, func: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef):
                visit(child, child.name)
                continue
            if isinstance(child, ast.Call) and is_direct(dotted(child.func)):
                found.append((f"{rel}:{child.lineno}", func))
            visit(child, func)

    visit(tree, "<module>")
    return found


def test_enrichment_code_never_builds_its_own_client():
    """Every request from an adapter, an enrichment job or a helper they call
    goes through a gateway: self.http(), gateway.client(), or
    gateway.client_for() on a gateway transport. Scans every module under
    app/enrichment, app/workers and app/intelligence (plus the ransomware.live
    adapter the victim sync uses); only _DIRECT_HTTP_ALLOWED may call httpx,
    requests, aiohttp or urllib directly."""
    app_dir = Path(__file__).parents[1] / "app"
    paths = [
        p for tree in ("enrichment", "workers", "intelligence") for p in sorted((app_dir / tree).rglob("*.py"))
    ] + [app_dir / "adapters" / "ransomware_live.py"]
    calls = [
        (where, func)
        for path in paths
        for where, func in _direct_http_calls(path, path.relative_to(app_dir).as_posix())
    ]
    offenders = [
        f"{where} in {func}()" for where, func in calls if (where.split(":")[0], func) not in _DIRECT_HTTP_ALLOWED
    ]
    assert offenders == []
    # Every allowance is still used, so the list can't hold stale exemptions.
    used = {(where.split(":")[0], func) for where, func in calls}
    assert _DIRECT_HTTP_ALLOWED <= used


def test_the_direct_http_scan_catches_every_spelling(tmp_path):
    sample = tmp_path / "sample.py"
    sample.write_text(
        "import httpx\n"
        "import requests as rq\n"
        "from httpx import AsyncClient as AC\n"
        "import urllib.request\n"
        "async def f(transport):\n"
        "    httpx.AsyncClient(transport=transport)\n"
        "    AC()\n"
        "    rq.get('x')\n"
        "    urllib.request.urlopen('x')\n"
        "def g(client: httpx.AsyncClient) -> httpx.AsyncClient:\n"
        "    return client\n"
    )
    assert [where for where, _ in _direct_http_calls(sample, "sample.py")] == [
        "sample.py:6",
        "sample.py:7",
        "sample.py:8",
        "sample.py:9",
    ]


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


# ── Indicators sent off the box ──────────────────────────────────────
# ``record_ioc_sent`` / ``iocs_sent``: one HyperLogLog per UTC hour of the
# indicators lookups sent to a source that receives them (SHARES_IOC);
# ``pipeline.enrich_entity`` records one after such a source answers.


@pytest.fixture
async def _only_our_sources(db_session):
    from sqlalchemy import update

    await db_session.execute(update(EnrichmentSource).values(is_enabled=False))
    await db_session.flush()


async def _enabled_source(db, source_type: str) -> EnrichmentSource:
    row = (
        await db.execute(select(EnrichmentSource).where(EnrichmentSource.source_type == source_type))
    ).scalar_one_or_none()
    if row is None:
        row = EnrichmentSource(source_type=source_type, display_name=source_type, config={})
        db.add(row)
    row.is_enabled = True
    row.trigger_mode = "manual"
    row.min_confidence_threshold = "low"
    row.rate_limit_config = {"requests_per_period": 100, "period_seconds": 60}
    await db.flush()
    return row


async def _observable(db, value: str):
    from app.models.observable import Observable

    obs = Observable(kind="ipv4", value=value, base_confidence=0.8, current_confidence=0.8)
    db.add(obs)
    await db.flush()
    return obs


async def test_iocs_sent_counts_distinct_values():
    assert await gw.iocs_sent() == 0
    for value in ("198.51.100.1", "198.51.100.1", "198.51.100.2", "Evil.Example", "evil.example"):
        await gw.record_ioc_sent(value)
    # HyperLogLog is exact at this size; case doesn't make a second indicator.
    assert await gw.iocs_sent() == 3


async def test_iocs_sent_raises_when_redis_is_down(monkeypatch):
    import redis.asyncio as aioredis

    dead = aioredis.from_url("redis://127.0.0.1:1/0", socket_connect_timeout=0.5)

    async def broken():
        return dead

    monkeypatch.setattr(gw, "get_redis_bytes", broken)
    await gw.record_ioc_sent("198.51.100.1")  # only loses the count
    with pytest.raises(gw.GatewayUnavailable):
        await gw.iocs_sent()


def _adapter(answer=None, error=None):
    from unittest.mock import AsyncMock, MagicMock

    from app.enrichment.base import EnrichmentData

    adapter = MagicMock()
    adapter.supports_entity.return_value = True
    adapter.enrich = AsyncMock(
        return_value=answer or EnrichmentData(raw_response={}, parsed_data={"found": True}, ttl_hours=24),
        side_effect=error,
    )
    return adapter


async def _lookup(db, obs, source_type: str, adapter) -> list[dict]:
    from app.enrichment import pipeline

    with patch("app.enrichment.pipeline.adapter_for_source", return_value=adapter):
        return await pipeline.enrich_entity(
            "observable", obs.id, obs.value, db, trigger="manual", source_types=[source_type], refresh=True
        )


async def test_a_lookup_at_a_source_that_takes_the_indicator_counts_it(db_session, _only_our_sources):
    await _enabled_source(db_session, "shodan")  # SHARES_IOC
    await _enabled_source(db_session, "cymru")  # LOW: sends the IP to DNS, not to a threat-intel source
    first = await _observable(db_session, "198.51.100.10")
    second = await _observable(db_session, "198.51.100.11")

    await _lookup(db_session, first, "shodan", _adapter())
    await _lookup(db_session, first, "shodan", _adapter())  # the same IP again
    await _lookup(db_session, second, "cymru", _adapter())
    assert await gw.iocs_sent() == 1

    # A request the gateway refused sent nothing.
    results = await _lookup(db_session, second, "shodan", _adapter(error=RateLimited("shodan", 30)))
    assert results[0]["status"] == "rate_limited"
    assert await gw.iocs_sent() == 1

    await _lookup(db_session, second, "shodan", _adapter())
    assert await gw.iocs_sent() == 2


# ── User-Agent ───────────────────────────────────────────────────────


def test_wikimedia_requests_carry_the_contact_email(monkeypatch):
    """Wikipedia and Wikidata add the contact email Wikimedia's User-Agent
    policy asks for; other sources send the plain User-Agent."""
    from app.config import settings

    monkeypatch.setattr(settings, "wikimedia_contact_email", "ops@example.org")
    monkeypatch.setattr("app.services.system_settings.get_setting_cached", lambda key: None)
    expected = f"IntelFeed/{settings.app_version} ({gw.CONTACT_URL}; ops@example.org) httpx/{httpx.__version__}"
    assert gw.user_agent("wikipedia") == expected
    assert gw.user_agent("wikidata") == expected
    assert gw.user_agent("nvd") == gw.USER_AGENT
    monkeypatch.setattr(settings, "wikimedia_contact_email", "")
    assert gw.user_agent("wikipedia") == gw.USER_AGENT
