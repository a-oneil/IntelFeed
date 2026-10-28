"""SourceGateway — the only way enrichment adapters reach the network.

Each enrichment source gets a gateway built from its ``EnrichmentSource`` row.
Adapters open clients with ``self.http(...)``; the client's transport
(``_GatewayTransport``) applies, to every HTTP request:

1. the circuit breaker: an open breaker refuses the request;
2. one atomic Redis script that takes a token from the source's bucket
   (``rate_limit_config``: ``requests_per_period`` per ``period_seconds``) and
   counts the request against ``daily_budget`` — both or neither, so a refused
   request costs nothing;
3. a short wait for a token when one is about to refill, else ``RateLimited``;
4. the enrichment User-Agent;
5. the response check: 429/503 open the breaker for Retry-After (or an
   exponential backoff when there is none) and raise ``RateLimited``; three
   5xx or transport errors in a row open it for a backoff; any other response
   closes it.

Redis errors before the send raise ``GatewayUnavailable`` and nothing is sent:
the gateway fails closed.

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
from datetime import UTC, datetime
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
#: Consecutive 5xx / transport errors that open the breaker.
FAILURE_THRESHOLD = 3
#: Breaker backoff when the source gives no Retry-After: doubles per trip.
BACKOFF_BASE = 60
BACKOFF_CAP = 3600
#: Longest Retry-After honored, so one bad header can't park a source for weeks.
RETRY_AFTER_CAP = 86400

_DEFAULT_RATE = {"requests_per_period": 100, "period_seconds": 86400}

# Breaker, then bucket + budget, in one step. Returns {code, seconds}:
# 0 = sent (token taken, request counted), 1 = no token yet (seconds until
# one refills), 2 = daily budget used up, 3 = breaker open (seconds left).
# Only code 0 writes anything.
_ACQUIRE_LUA = """
local now = tonumber(ARGV[1])
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
    """No token within MAX_TOKEN_WAIT, or the source answered 429/503."""

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
        inner: httpx.AsyncBaseTransport | None = None,
    ):
        rate = {**_DEFAULT_RATE, **(rate_limit_config or {})}
        self.source_type = source_type
        self.capacity = max(1, int(rate["requests_per_period"]))
        self.period = max(1, int(rate["period_seconds"]))
        self.daily_budget = daily_budget
        scope = shared_key_group or source_type
        if api_key:
            scope += ":" + hashlib.sha256(api_key.encode()).hexdigest()[:12]
        self.scope = scope
        self._inner = inner

    @classmethod
    def for_source(cls, source, api_key: str | None, shared_key_group: str | None = None) -> SourceGateway:
        """The gateway for an ``EnrichmentSource`` row and the key it will use."""
        return cls(
            source.source_type,
            rate_limit_config=source.rate_limit_config,
            daily_budget=source.daily_budget,
            api_key=api_key,
            shared_key_group=shared_key_group,
        )

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
        """Take a permit for one request, waiting up to MAX_TOKEN_WAIT for a
        token. Raises a GatewayError when the request must not be sent."""
        waited = 0.0
        while True:
            try:
                r = await get_redis_bytes()
                code, seconds = await r.eval(
                    _ACQUIRE_LUA,
                    3,
                    self._key("bucket"),
                    self._budget_key(),
                    self._key("breaker"),
                    repr(time.time()),
                    str(self.capacity),
                    repr(self.capacity / self.period),
                    str(self.daily_budget if self.daily_budget is not None else -1),
                    str(self.period + 60),
                )
            except (RedisError, OSError) as e:
                raise GatewayUnavailable(f"{self.source_type}: rate limit store unavailable ({e})") from e
            code, seconds = int(code), float(seconds)
            if code == 0:
                return
            if code == 2:
                raise BudgetExhausted(f"{self.source_type} daily budget of {self.daily_budget} used up")
            if code == 3:
                raise BreakerOpen(self.source_type, seconds)
            if waited + seconds > MAX_TOKEN_WAIT:
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
        Raises RateLimited for a 429/503. A Redis error here is logged, not
        raised: the request already went out and its answer is still good."""
        try:
            if response is not None and response.status_code in (429, 503):
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
