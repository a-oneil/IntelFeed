"""SourceGateway — the only way enrichment adapters reach the network.

Each enrichment source gets a gateway built from its ``EnrichmentSource`` row.
Adapters open clients with ``self.http(...)``; the client's transport
(``_GatewayTransport``) applies, to every HTTP request:

1. the circuit breaker: an open breaker refuses the request;
2. one atomic Redis script that takes a token from the source's bucket
   (``rate_limit_config``: ``requests_per_period`` per ``period_seconds``) and
   counts the request against ``daily_budget`` — both or neither, so a refused
   request costs nothing;
3. a wait for a token when one is about to refill, else ``RateLimited``: up to
   ``MAX_TOKEN_WAIT`` for a per-entity lookup, ``JOB_TOKEN_WAIT`` for a
   scheduled job, which the bucket paces through its backlog;
4. the enrichment User-Agent;
5. the response check: a throttle status (429/503, plus 403 for sources that
   throttle with it) opens the breaker for Retry-After (or an exponential
   backoff when there is none) and raises ``RateLimited``; three 5xx or
   transport errors in a row open it for a backoff; any other response
   closes it.

A source whose manifest requires an API key gets a gateway that refuses every
request with ``NeedsKey`` while it has none, before anything else: no path
(lookup, job or health check) can send such a source a keyless request.

Redis errors before the send raise ``GatewayUnavailable`` and nothing is sent:
the gateway fails closed. While enrichment is paused (``app/enrichment/pause.py``
sets a Redis flag) every request is refused with ``Paused``, checked in the same
script, so a pause reaches every worker on its next request.

Each sent request also counts toward ``stats:{source_type}:{YYYYMMDDHH}``, an
hourly per-source counter (kept 48h) the Enrichment console charts; it is
written in the same script as the token, so the two never disagree.

The bucket, budget and breaker are keyed per credential, not per source: by
the adapter's ``shared_key_group`` when it has one (siblings share one key's
allowance), else by ``source_type``, plus a short hash of the API key in use,
so a user's override key has its own allowance.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime

import httpx
from redis.exceptions import RedisError

from app.config import settings
from app.services.redis_client import get_redis_bytes

logger = logging.getLogger(__name__)

#: Every enrichment request carries this. Sources ask for a way to reach the
#: operator; the instance's public URL is that, else the project page.
USER_AGENT = f"IntelFeed/{settings.app_version} (+{settings.public_base_url or 'https://github.com/a-oneil/intelfeed'})"

KEY_PREFIX = "enrichment:gw:"

#: Longest a request waits for its next token before giving up as rate limited.
MAX_TOKEN_WAIT = 2.0
#: The same for scheduled jobs, which would rather wait than stop early.
JOB_TOKEN_WAIT = 120.0
#: Statuses that mean "slow down" unless a source says otherwise.
THROTTLE_STATUSES = (429, 503)
#: Consecutive 5xx / transport errors that open the breaker.
FAILURE_THRESHOLD = 3
#: Breaker backoff when the source gives no Retry-After: doubles per trip.
BACKOFF_BASE = 60
BACKOFF_CAP = 3600
#: Longest Retry-After honored, so one bad header can't park a source for weeks.
RETRY_AFTER_CAP = 86400

_DEFAULT_RATE = {"requests_per_period": 100, "period_seconds": 86400}

#: How long an hourly request counter is kept.
STATS_TTL = 48 * 3600

# Pause, breaker, then bucket + budget, in one step. Returns {code, seconds}:
# 0 = sent (token taken, request counted), 1 = no token yet (seconds until
# one refills), 2 = daily budget used up, 3 = breaker open (seconds left),
# 4 = enrichment paused. Only code 0 writes anything.
_ACQUIRE_LUA = """
local now = tonumber(ARGV[1])
if redis.call('EXISTS', KEYS[4]) == 1 then
    return {4, '0'}
end
local open_until = tonumber(redis.call('HGET', KEYS[3], 'open_until') or '0')
if open_until > now then
    return {3, tostring(open_until - now)}
end

local capacity = tonumber(ARGV[2])
local rate = tonumber(ARGV[3])
local budget = tonumber(ARGV[4])

if budget >= 0 and tonumber(redis.call('GET', KEYS[2]) or '0') >= budget then
    return {2, '0'}
end

local bucket = redis.call('HMGET', KEYS[1], 'tokens', 'ts')
local tokens = tonumber(bucket[1]) or capacity
local ts = tonumber(bucket[2]) or now
tokens = math.min(capacity, tokens + math.max(0, now - ts) * rate)
if tokens < 1 then
    return {1, tostring((1 - tokens) / rate)}
end

redis.call('HSET', KEYS[1], 'tokens', tostring(tokens - 1), 'ts', tostring(now))
redis.call('EXPIRE', KEYS[1], tonumber(ARGV[5]))
redis.call('INCR', KEYS[2])
redis.call('EXPIRE', KEYS[2], 90000)
redis.call('INCR', KEYS[5])
redis.call('EXPIRE', KEYS[5], tonumber(ARGV[6]))
return {0, '0'}
"""

# Records a throttle (429/503) or a failure (5xx / transport error) and opens
# the breaker when it should. Returns how long it opened for, '0' if it didn't.
_TRIP_LUA = """
local now = tonumber(ARGV[1])
local mode = ARGV[2]
local retry_after = tonumber(ARGV[3])
local base = tonumber(ARGV[4])
local cap = tonumber(ARGV[5])
local open_for = 0
if mode == 'throttle' then
    local trips = redis.call('HINCRBY', KEYS[1], 'trips', 1)
    if retry_after >= 0 then
        open_for = retry_after
    else
        open_for = math.min(cap, base * 2 ^ (trips - 1))
    end
elseif redis.call('HINCRBY', KEYS[1], 'failures', 1) >= tonumber(ARGV[6]) then
    local trips = redis.call('HINCRBY', KEYS[1], 'trips', 1)
    redis.call('HSET', KEYS[1], 'failures', 0)
    open_for = math.min(cap, base * 2 ^ (trips - 1))
end
if open_for > 0 then
    redis.call('HSET', KEYS[1], 'open_until', tostring(now + open_for))
end
redis.call('EXPIRE', KEYS[1], 86400 + math.ceil(open_for))
return tostring(open_for)
"""


class GatewayError(Exception):
    """A request the gateway refused. Nothing was sent, or the source said to
    back off; either way it is not the adapter's error."""

    status = "error"


class RateLimited(GatewayError):
    """No token in time, or the source answered with a throttle status."""

    status = "rate_limited"

    def __init__(self, source_type: str, retry_after: float):
        super().__init__(f"{source_type} rate limited, retry in {retry_after:.0f}s")
        self.retry_after = retry_after


class BudgetExhausted(GatewayError):
    status = "budget_exhausted"


class BreakerOpen(GatewayError):
    status = "breaker_open"

    def __init__(self, source_type: str, retry_after: float):
        super().__init__(f"{source_type} circuit breaker open for {retry_after:.0f}s")
        self.retry_after = retry_after


class GatewayUnavailable(GatewayError):
    """Redis is unreachable, so limits can't be checked: nothing is sent."""

    status = "gateway_unavailable"


class Paused(GatewayError):
    """An admin paused enrichment: no request leaves the box."""

    status = "paused"


class NeedsKey(GatewayError):
    """The source needs an API key and has none: nothing is sent."""

    status = "needs_key"


#: Refusals a scheduled job stops on, keeping what it has done. GatewayUnavailable
#: is not one: a job that can't check its limits fails.
SOURCE_REFUSALS = (RateLimited, BudgetExhausted, BreakerOpen, Paused)


def paused_key() -> str:
    """The Redis flag that pauses every gateway while it exists."""
    return f"{KEY_PREFIX}paused"


def stats_key(source_type: str, hour: datetime) -> str:
    """The counter of requests ``source_type`` sent in the UTC hour ``hour``."""
    return f"{KEY_PREFIX}stats:{source_type}:{hour.strftime('%Y%m%d%H')}"


async def hourly_requests(source_types: list[str], hours: int = 24) -> dict[str, list[int]]:
    """Requests each source sent per UTC hour, the last ``hours`` hours oldest
    first (the current hour last). Raises GatewayUnavailable when Redis can't
    answer."""
    now = datetime.now(UTC)
    stamps = [now - timedelta(hours=h) for h in range(hours - 1, -1, -1)]
    keys = [stats_key(st, t) for st in source_types for t in stamps]
    if not keys:
        return {}
    try:
        r = await get_redis_bytes()
        values = await r.mget(keys)
    except (RedisError, OSError) as e:
        raise GatewayUnavailable(str(e)) from e
    counts = [int(v) if v else 0 for v in values]
    return {st: counts[i * hours : (i + 1) * hours] for i, st in enumerate(source_types)}


def parse_retry_after(value: str | None) -> float | None:
    """Seconds to wait from a Retry-After header: delay-seconds or an HTTP-date."""
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return min(float(value), RETRY_AFTER_CAP)
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return min(max(0.0, (when - datetime.now(UTC)).total_seconds()), RETRY_AFTER_CAP)


class SourceGateway:
    """Rate limit, daily budget and circuit breaker for one source's credential."""

    def __init__(
        self,
        source_type: str,
        rate_limit_config: dict | None = None,
        daily_budget: int | None = None,
        api_key: str | None = None,
        shared_key_group: str | None = None,
        throttle_statuses: tuple[int, ...] = THROTTLE_STATUSES,
        max_wait: float = MAX_TOKEN_WAIT,
        inner: httpx.AsyncBaseTransport | None = None,
        requires_key: bool = False,
    ):
        rate = {**_DEFAULT_RATE, **(rate_limit_config or {})}
        self.source_type = source_type
        self.capacity = max(1, int(rate["requests_per_period"]))
        self.period = max(1, int(rate["period_seconds"]))
        self.daily_budget = daily_budget
        self.throttle_statuses = throttle_statuses
        self.max_wait = max_wait
        self.missing_key = requires_key and not api_key
        scope = shared_key_group or source_type
        if api_key:
            scope += ":" + hashlib.sha256(api_key.encode()).hexdigest()[:12]
        self.scope = scope
        self._inner = inner

    def transport(self) -> httpx.AsyncBaseTransport:
        """A transport that sends through this gateway. Each client gets its
        own, since closing a client closes its transport's connection pool."""
        return _GatewayTransport(self, self._inner or httpx.AsyncHTTPTransport())

    def client(self, timeout: float = 10, **kwargs) -> httpx.AsyncClient:
        """An httpx client whose every request passes through this gateway."""
        return httpx.AsyncClient(transport=self.transport(), timeout=timeout, **kwargs)

    def _key(self, name: str) -> str:
        return f"{KEY_PREFIX}{self.scope}:{name}"

    def _budget_key(self) -> str:
        return self._key("budget:" + datetime.now(UTC).strftime("%Y-%m-%d"))

    async def acquire(self) -> None:
        """Take a permit for one request, waiting up to ``max_wait`` for a
        token. Raises a GatewayError when the request must not be sent."""
        if self.missing_key:
            raise NeedsKey(f"{self.source_type} needs an API key")
        waited = 0.0
        while True:
            try:
                r = await get_redis_bytes()
                code, seconds = await r.eval(
                    _ACQUIRE_LUA,
                    5,
                    self._key("bucket"),
                    self._budget_key(),
                    self._key("breaker"),
                    paused_key(),
                    stats_key(self.source_type, datetime.now(UTC)),
                    repr(time.time()),
                    str(self.capacity),
                    repr(self.capacity / self.period),
                    str(self.daily_budget if self.daily_budget is not None else -1),
                    str(self.period + 60),
                    str(STATS_TTL),
                )
            except (RedisError, OSError) as e:
                raise GatewayUnavailable(f"{self.source_type}: rate limit store unavailable ({e})") from e
            code, seconds = int(code), float(seconds)
            if code == 0:
                return
            if code == 4:
                raise Paused(f"{self.source_type}: enrichment is paused")
            if code == 2:
                raise BudgetExhausted(f"{self.source_type} daily budget of {self.daily_budget} used up")
            if code == 3:
                raise BreakerOpen(self.source_type, seconds)
            if waited + seconds > self.max_wait:
                raise RateLimited(self.source_type, seconds)
            await asyncio.sleep(seconds)
            waited += seconds

    async def _trip(self, mode: str, retry_after: float | None = None) -> float:
        r = await get_redis_bytes()
        opened = await r.eval(
            _TRIP_LUA,
            1,
            self._key("breaker"),
            repr(time.time()),
            mode,
            repr(retry_after if retry_after is not None else -1),
            str(BACKOFF_BASE),
            str(BACKOFF_CAP),
            str(FAILURE_THRESHOLD),
        )
        return float(opened)

    async def record(self, response: httpx.Response | None) -> None:
        """Feed one outcome to the breaker: ``None`` for a transport error.
        Raises RateLimited for a throttle status. A Redis error here is logged,
        not raised: the request already went out and its answer is still good."""
        try:
            if response is not None and response.status_code in self.throttle_statuses:
                retry_after = parse_retry_after(response.headers.get("Retry-After"))
                opened = await self._trip("throttle", retry_after)
                raise RateLimited(self.source_type, opened)
            if response is None or response.status_code >= 500:
                opened = await self._trip("failure")
                if opened:
                    logger.warning("%s: breaker open for %.0fs after repeated failures", self.source_type, opened)
                return
            # A good answer resets the failure streak and backoff, but leaves
            # open_until alone: a response that was already in flight when
            # another worker's 429 opened the breaker must not close it early.
            r = await get_redis_bytes()
            await r.hdel(self._key("breaker"), "failures", "trips")
        except (RedisError, OSError) as e:
            logger.warning("%s: could not record the response in the gateway: %s", self.source_type, e)

    async def remaining(self) -> int:
        """Whole tokens in the bucket now (for display)."""
        try:
            r = await get_redis_bytes()
            tokens, ts = await r.hmget(self._key("bucket"), "tokens", "ts")
        except (RedisError, OSError) as e:
            raise GatewayUnavailable(str(e)) from e
        if tokens is None:
            return self.capacity
        refilled = float(tokens) + max(0.0, time.time() - float(ts)) * self.capacity / self.period
        return int(min(self.capacity, refilled))

    async def breaker_open_for(self) -> float:
        """Seconds until this credential's breaker closes; 0 when it is closed."""
        try:
            r = await get_redis_bytes()
            open_until = await r.hget(self._key("breaker"), "open_until")
        except (RedisError, OSError) as e:
            raise GatewayUnavailable(str(e)) from e
        return max(0.0, float(open_until) - time.time()) if open_until else 0.0

    async def used_today(self) -> int:
        """Requests sent today (UTC) under this credential."""
        try:
            r = await get_redis_bytes()
            value = await r.get(self._budget_key())
        except (RedisError, OSError) as e:
            raise GatewayUnavailable(str(e)) from e
        return int(value) if value else 0


class _GatewayTransport(httpx.AsyncBaseTransport):
    """Wraps the real transport so the gateway sees every request."""

    def __init__(self, gateway: SourceGateway, inner: httpx.AsyncBaseTransport):
        self._gateway = gateway
        self._inner = inner

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        await self._gateway.acquire()
        request.headers["User-Agent"] = USER_AGENT
        try:
            response = await self._inner.handle_async_request(request)
        except httpx.TransportError:
            await self._gateway.record(None)
            raise
        try:
            await self._gateway.record(response)
        except RateLimited:
            await response.aclose()
            raise
        return response

    async def aclose(self) -> None:
        await self._inner.aclose()
