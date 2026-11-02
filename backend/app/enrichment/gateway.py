"""SourceGateway — the only way enrichment adapters reach the network.

Each enrichment source gets a gateway built from its ``EnrichmentSource`` row.
Adapters open clients with ``self.http(...)``; the client's transport
(``_GatewayTransport``) applies, to every HTTP request:

1. the pause and auth checks: while enrichment is paused, or the source
   rejected this credential (``auth_failed``), nothing is sent;
2. the circuit breaker: an open breaker refuses the request;
3. one atomic Redis script that checks the daily budget (and, for a
   backfill-lane request, BACKFILL_SHARE of it), the rolling window
   (``rate_limit_config``: never more than ``requests_per_period`` requests
   in any ``period_seconds``) and the concurrency cap (``concurrency``
   requests in flight at once), then takes a slot in all three — all or
   nothing, so a refused request costs nothing;
4. a wait for a free slot when one is about to open, else ``RateLimited``: up
   to ``MAX_TOKEN_WAIT`` for a per-entity lookup, ``JOB_TOKEN_WAIT`` for a
   scheduled job, which the window paces through its backlog;
5. the enrichment User-Agent;
6. the response check. A 401, or a 403 that means the key is bad, records an
   auth failure: the credential sends nothing more until its key changes or
   AUTH_FAILED_TTL passes, and the console shows the source's message. A
   throttle status (429/503, plus 403 for sources that throttle with it)
   opens the breaker for Retry-After (or an exponential backoff when there is
   none) and raises ``RateLimited``. Three 5xx or transport errors in a row
   open the breaker for a backoff. Any other response closes it.

The in-flight slot is held until the response body is closed, and expires on
its own after the request's timeout (plus a margin), so a worker that dies
mid-request strands nothing.

A 403 is an auth failure when a key is in use, the response carries no rate
limit signal (Retry-After, ``X-RateLimit-Remaining: 0``, "rate limit" in the
body), and either it answered the first request in the window — nothing was
sent that could have been throttled — or it is the AUTH_403_STREAK-th such
403 in a row.

A source whose manifest requires an API key gets a gateway that
refuses every request with ``NeedsKey`` while it has none, before anything
else: no path (lookup, job or health check) can send such a source a keyless
request.

Redis errors before the send raise ``GatewayUnavailable`` and nothing is sent:
the gateway fails closed. The pause (``app/enrichment/pause.py``) is a Redis
flag checked in the same script, so a pause reaches every worker on its next
request. Every sync of that flag also writes a marker; a gateway that finds no
marker (Redis lost its keys) asks the settings cache before sending. That is
the one deliberate fail-open window: a fresh worker with an empty cache sends
on the env default until the next ``enrichment-pause-sync`` run, at most a
minute later.

Each sent request also counts toward ``stats:{source_type}:{YYYYMMDDHH}``, an
hourly per-source counter (kept 48h) the Enrichment console charts; it is
written in the same script as the window slot, so the two never disagree.

The window, budget, in-flight set, breaker and auth flag are keyed per
credential, not per source: by the adapter's ``shared_key_group`` when it has
one (siblings share one key's allowance), else by ``source_type``, plus a
short hash of the API key in use, so a user's override key has its own
allowance.

A request runs in the ``backfill`` lane when the gateway was built with
``lane="backfill"`` or the code calling it runs inside ``in_lane("backfill")``
(the queue's backfill rows, and scheduled jobs declared with
``source_job(..., lane="backfill")``).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import math
import time
import uuid
from contextlib import asynccontextmanager, contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime

import httpx
from redis.exceptions import RedisError

from app.config import settings
from app.services.redis_client import get_redis_bytes

logger = logging.getLogger(__name__)

#: Every enrichment request carries this, in the shape Wikimedia's User-Agent
#: policy asks for and every other source accepts: ``client/version (contact)
#: library/version``. The contact is the instance's public URL, else the
#: project page.
CONTACT_URL = settings.public_base_url or "https://github.com/a-oneil/IntelFeed"
USER_AGENT = f"IntelFeed/{settings.app_version} ({CONTACT_URL}) httpx/{httpx.__version__}"

#: Sources whose operators ask for an email in the User-Agent (Wikimedia's
#: policy: https://foundation.wikimedia.org/wiki/Policy:Wikimedia_Foundation_User-Agent_Policy).
CONTACT_EMAIL_SETTING = {"wikipedia": "wikimedia_contact_email", "wikidata": "wikimedia_contact_email"}


def user_agent(source_type: str) -> str:
    """The User-Agent a source's requests carry: USER_AGENT, with the
    contact email its operator asks for added to the contact when one is set."""
    key = CONTACT_EMAIL_SETTING.get(source_type)
    email = str(settings.get(key) or "").strip() if key else ""
    if not email:
        return USER_AGENT
    return USER_AGENT.replace(f"({CONTACT_URL})", f"({CONTACT_URL}; {email})", 1)


KEY_PREFIX = "enrichment:gw:"

#: Longest a request waits for a free slot before giving up as rate limited.
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
#: Share of a source's daily budget backfill-lane requests may use, so bulk
#: catch-up never starves new entities or a person's request.
BACKFILL_SHARE = 0.6
#: Requests one credential may have in flight at once, unless its manifest's
#: Quota says otherwise.
DEFAULT_CONCURRENCY = 2
#: How long an in-flight slot outlives its request's timeout before it
#: expires on its own (a worker died holding it).
IN_FLIGHT_MARGIN = 30.0
#: The slot lease for a request with no timeout, or taken with acquire().
IN_FLIGHT_LEASE = 120.0
#: Seconds between checks for a free in-flight slot.
CONCURRENCY_POLL = 0.25
#: How long a credential the source rejected stays refused. Changing the key
#: starts a new credential, so this only matters for a key fixed upstream.
AUTH_FAILED_TTL = 86400
#: Ambiguous 403s in a row (a key in use, no rate limit signal) that are taken
#: as an auth failure.
AUTH_403_STREAK = 3

DEFAULT_RATE = {"requests_per_period": 100, "period_seconds": 86400}

#: How long an hourly request counter is kept.
STATS_TTL = 48 * 3600

#: The lane the running code sends in; see ``in_lane``.
_lane: ContextVar[str | None] = ContextVar("enrichment_lane", default=None)


@contextmanager
def in_lane(lane: str | None):
    """Send every gateway request made inside the block in ``lane``. Only
    ``"backfill"`` changes anything: its requests stop at BACKFILL_SHARE of
    the source's daily budget."""
    token = _lane.set(lane)
    try:
        yield
    finally:
        _lane.reset(token)


# Pause, auth, breaker, budget, rolling window and concurrency, in one step.
# ARGV: now, limit, period, budget (-1 none), backfill cap (-1 none), stats
# TTL, concurrency, lease (0 = take no in-flight slot), token, assume pause
# synced ('1'), concurrency poll seconds.
# Returns {code, seconds, count}:
# 0 = sent (slots taken, request counted; count = requests in the window,
#     this one included), 1 = window full (seconds until a slot frees),
# 2 = daily budget used up, 3 = breaker open (seconds left), 4 = paused,
# 5 = backfill share used up, 6 = concurrency cap reached (seconds to poll),
# 7 = no pause marker (Redis lost its keys), 8 = auth failed (seconds left).
# Only code 0 writes anything.
_ACQUIRE_LUA = """
local now = tonumber(ARGV[1])
if redis.call('EXISTS', KEYS[4]) == 1 then
    return {4, '0', '0'}
end
if ARGV[10] ~= '1' and redis.call('EXISTS', KEYS[8]) == 0 then
    return {7, '0', '0'}
end
local auth_ttl = redis.call('PTTL', KEYS[7])
if auth_ttl ~= -2 then
    return {8, tostring(math.max(auth_ttl, 0) / 1000), '0'}
end
local open_until = tonumber(redis.call('HGET', KEYS[3], 'open_until') or '0')
if open_until > now then
    return {3, tostring(open_until - now), '0'}
end

local used = tonumber(redis.call('GET', KEYS[2]) or '0')
local budget = tonumber(ARGV[4])
if budget >= 0 and used >= budget then
    return {2, '0', '0'}
end
local backfill_cap = tonumber(ARGV[5])
if backfill_cap >= 0 and used >= backfill_cap then
    return {5, '0', '0'}
end

local limit = tonumber(ARGV[2])
local period = tonumber(ARGV[3])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now - period)
local count = redis.call('ZCARD', KEYS[1])
if count >= limit then
    -- The request may go once the (count - limit + 1) oldest have aged out.
    local nth = redis.call('ZRANGE', KEYS[1], count - limit, count - limit, 'WITHSCORES')
    return {1, tostring(math.max(0.001, tonumber(nth[2]) + period - now)), '0'}
end

redis.call('ZREMRANGEBYSCORE', KEYS[6], '-inf', now)
if redis.call('ZCARD', KEYS[6]) >= tonumber(ARGV[7]) then
    return {6, ARGV[11], '0'}
end

local lease = tonumber(ARGV[8])
redis.call('ZADD', KEYS[1], now, ARGV[9])
redis.call('EXPIRE', KEYS[1], math.ceil(period) + 60)
if lease > 0 then
    redis.call('ZADD', KEYS[6], now + lease, ARGV[9])
    redis.call('EXPIRE', KEYS[6], math.ceil(lease) + 60)
end
redis.call('INCR', KEYS[2])
redis.call('EXPIRE', KEYS[2], 90000)
redis.call('INCR', KEYS[5])
redis.call('EXPIRE', KEYS[5], tonumber(ARGV[6]))
return {0, '0', tostring(count + 1)}
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
    """No free slot in time, or the source answered with a throttle status."""

    status = "rate_limited"

    def __init__(self, source_type: str, retry_after: float):
        super().__init__(f"{source_type} rate limited, retry in {retry_after:.0f}s")
        self.retry_after = retry_after


class BudgetExhausted(GatewayError):
    status = "budget_exhausted"


class BackfillShareUsed(BudgetExhausted):
    """A backfill-lane request past BACKFILL_SHARE of the daily budget: the
    rest is kept for new entities and people's requests."""

    status = "backfill_share"


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
    """The source needs an API key (or a setting) and has none: nothing is sent."""

    status = "needs_key"


class AuthFailed(GatewayError):
    """The source rejected this credential (401, or a 403 that means a bad
    key). Nothing more is sent with it until the key changes or
    ``retry_after`` passes; it is not retried with a backoff."""

    status = "auth_failed"

    def __init__(self, message: str, retry_after: float = AUTH_FAILED_TTL):
        super().__init__(message)
        self.message = message
        self.retry_after = retry_after


#: Refusals a scheduled job stops on, keeping what it has done. GatewayUnavailable
#: is not one: a job that can't check its limits fails. Nor is AuthFailed: a
#: job whose key is rejected fails, so Engine → Jobs shows why.
SOURCE_REFUSALS = (RateLimited, BudgetExhausted, BreakerOpen, Paused)


@dataclass(frozen=True)
class Permit:
    """One request's slots: its id in the window and in-flight sets, and how
    many requests the window held with it."""

    token: str
    window_count: int


def paused_key() -> str:
    """The Redis flag that pauses every gateway while it exists."""
    return f"{KEY_PREFIX}paused"


def pause_synced_key() -> str:
    """Written by every pause sync. Its absence means Redis lost its keys
    (and maybe the pause flag with them) since the last sync."""
    return f"{KEY_PREFIX}paused:synced"


def _pause_fallback() -> bool:
    """Whether enrichment is paused, from the in-process settings cache, for a
    gateway that found no pause marker. Not loaded: the env default."""
    from app.services.system_settings import get_setting_cached

    cached = get_setting_cached("enrichment_paused")
    stopped = get_setting_cached("engine_stopped")
    return bool(settings.enrichment_paused if cached is None else cached) or bool(
        settings.engine_stopped if stopped is None else stopped
    )


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


def _sent_key(hour: datetime) -> str:
    return f"{KEY_PREFIX}iocs_sent:{hour.strftime('%Y%m%d%H')}"


async def record_ioc_sent(value: str) -> None:
    """Count an indicator a lookup sent to an outside source (one HyperLogLog
    per UTC hour), so the console can say how many distinct ones left the box.
    A Redis failure only loses the count."""
    key = _sent_key(datetime.now(UTC))
    try:
        r = await get_redis_bytes()
        await r.pfadd(key, value.casefold())
        await r.expire(key, 25 * 3600)
    except (RedisError, OSError):
        logger.debug("Couldn't count an indicator sent", exc_info=True)


async def iocs_sent(hours: int = 24) -> int:
    """Distinct indicators sent off the box in the last ``hours`` UTC hours.
    Raises GatewayUnavailable when Redis can't answer."""
    now = datetime.now(UTC)
    keys = [_sent_key(now - timedelta(hours=h)) for h in range(hours)]
    try:
        r = await get_redis_bytes()
        return int(await r.pfcount(*keys))
    except (RedisError, OSError) as e:
        raise GatewayUnavailable(str(e)) from e


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
    """Rolling window, concurrency cap, daily budget, circuit breaker and auth
    state for one source's credential."""

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
        concurrency: int = DEFAULT_CONCURRENCY,
        lane: str | None = None,
    ):
        rate = {**DEFAULT_RATE, **(rate_limit_config or {})}
        self.source_type = source_type
        #: Requests allowed in any window of ``period`` seconds.
        self.capacity = max(1, int(rate["requests_per_period"]))
        self.period = max(1, int(rate["period_seconds"]))
        self.daily_budget = daily_budget
        self.concurrency = max(1, int(concurrency))
        self.throttle_statuses = throttle_statuses
        self.max_wait = max_wait
        self.has_key = bool(api_key)
        self.missing_key = requires_key and not api_key
        self.lane = lane
        scope = shared_key_group or source_type
        if api_key:
            scope += ":" + hashlib.sha256(api_key.encode()).hexdigest()[:12]
        self.scope = scope
        self._inner = inner
        #: Permits taken with acquire() and not yet released, per asyncio task,
        #: for callers that pair acquire() with record() (no httpx response).
        self._held: dict[int, list[str]] = {}

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

    def backfill_cap(self) -> int | None:
        """Requests a backfill-lane request may find already sent today before
        it is refused; None without a daily budget."""
        if self.daily_budget is None:
            return None
        return math.floor(BACKFILL_SHARE * self.daily_budget)

    def _lane_now(self) -> str | None:
        return self.lane or _lane.get()

    async def acquire(self, lease: float | None = None) -> Permit:
        """Take a window slot for one request, waiting up to ``max_wait`` for
        it and for the concurrency cap to have room. Raises a GatewayError
        when the request must not be sent.

        With ``lease`` it also takes an in-flight slot, held until
        ``release`` (or ``record``) frees it, else for ``lease`` seconds. The
        gateway transport and ``permit()`` always pass one; a bare
        ``acquire()`` takes none, so it counts toward the window but not the
        cap."""
        if self.missing_key:
            raise NeedsKey(f"{self.source_type} needs an API key")
        cap = self.backfill_cap() if self._lane_now() == "backfill" else None
        token = uuid.uuid4().hex
        waited = 0.0
        assume_synced = False
        while True:
            try:
                r = await get_redis_bytes()
                code, seconds, count = await r.eval(
                    _ACQUIRE_LUA,
                    8,
                    self._key("window"),
                    self._budget_key(),
                    self._key("breaker"),
                    paused_key(),
                    stats_key(self.source_type, datetime.now(UTC)),
                    self._key("inflight"),
                    self._key("auth"),
                    pause_synced_key(),
                    repr(time.time()),
                    str(self.capacity),
                    str(self.period),
                    str(self.daily_budget if self.daily_budget is not None else -1),
                    str(cap if cap is not None else -1),
                    str(STATS_TTL),
                    str(self.concurrency),
                    repr(float(lease or 0)),
                    token,
                    "1" if assume_synced else "0",
                    repr(CONCURRENCY_POLL),
                )
            except (RedisError, OSError) as e:
                raise GatewayUnavailable(f"{self.source_type}: rate limit store unavailable ({e})") from e
            code, seconds = int(code), float(seconds)
            if code == 0:
                if lease:
                    self._held.setdefault(_task_id(), []).append(token)
                return Permit(token, int(count))
            if code == 7:
                # Redis lost the pause marker: fall back on the settings cache
                # until the next sync writes the flag from the database.
                if _pause_fallback():
                    await self._write_pause_flag()
                    raise Paused(f"{self.source_type}: enrichment is paused")
                assume_synced = True
                continue
            if code == 4:
                raise Paused(f"{self.source_type}: enrichment is paused")
            if code == 8:
                raise AuthFailed(await self._auth_message(), seconds)
            if code == 2:
                raise BudgetExhausted(f"{self.source_type} daily budget of {self.daily_budget} used up")
            if code == 5:
                raise BackfillShareUsed(
                    f"{self.source_type}: backfill may use {BACKFILL_SHARE:.0%} of the daily budget ({cap}); used up"
                )
            if code == 3:
                raise BreakerOpen(self.source_type, seconds)
            if waited + seconds > self.max_wait:
                raise RateLimited(self.source_type, seconds)
            await asyncio.sleep(seconds)
            waited += seconds

    async def _write_pause_flag(self) -> None:
        try:
            r = await get_redis_bytes()
            await r.set(paused_key(), b"1")
        except (RedisError, OSError) as e:
            logger.warning("Could not restore the enrichment pause flag: %s", e)

    async def release(self, permit: Permit | None = None) -> None:
        """Free a request's in-flight slot: ``permit``'s, else the last one
        this task took with acquire(). Safe to call twice. A Redis error is
        logged; the slot then expires with its lease."""
        held = self._held.get(_task_id(), [])
        if permit is None:
            if not held:
                return
            token = held.pop()
        else:
            token = permit.token
            if token in held:
                held.remove(token)
        if not held:
            self._held.pop(_task_id(), None)
        try:
            r = await get_redis_bytes()
            await r.zrem(self._key("inflight"), token)
        except (RedisError, OSError) as e:
            logger.warning("%s: could not release an in-flight slot: %s", self.source_type, e)

    @asynccontextmanager
    async def permit(self, lease: float | None = None):
        """``async with gateway.permit():`` around a request made without
        httpx (DNS, whois): takes the slots, frees the in-flight one after.
        Report the outcome with ``record(..., release=False)`` inside."""
        taken = await self.acquire(lease or IN_FLIGHT_LEASE)
        try:
            yield taken
        finally:
            await self.release(taken)

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

    async def record(
        self,
        response: httpx.Response | None,
        *,
        permit: Permit | None = None,
        release: bool = True,
    ) -> None:
        """Feed one outcome to the breaker: ``None`` for a transport error.
        Raises AuthFailed for a rejected key and RateLimited for a throttle
        status. With ``release`` (the default, for callers of acquire()) it
        also frees the request's in-flight slot. A Redis error here is
        logged, not raised: the request already went out and its answer is
        still good.

        A 401/403 response must have been read (``aread``) for its body to be
        checked; one that wasn't is judged on its status and headers."""
        try:
            await self._judge(response, permit)
        finally:
            if release:
                await self.release(permit)

    async def _judge(self, response: httpx.Response | None, permit: Permit | None) -> None:
        try:
            if response is not None and response.status_code in (401, 403):
                verdict = await self._forbidden(response, permit)
                if verdict == "auth":
                    message = _auth_failure_message(self.source_type, response, self.has_key)
                    await self._mark_auth_failed(response.status_code, message)
                    raise AuthFailed(message)
                if verdict == "answer":
                    return
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
            await r.hdel(self._key("breaker"), "failures", "trips", "forbidden")
        except (RedisError, OSError) as e:
            logger.warning("%s: could not record the response in the gateway: %s", self.source_type, e)

    async def _forbidden(self, response: httpx.Response, permit: Permit | None) -> str:
        """What a 401/403 means: ``"auth"`` (the key is bad, or one is needed),
        ``"throttle"`` (fall through to the throttle check) or ``"answer"``
        (an ordinary response for the adapter)."""
        if response.status_code == 401:
            return "auth"
        if not self.has_key or rate_limit_signal(response):
            return "throttle" if 403 in self.throttle_statuses else "answer"
        if permit is not None and permit.window_count <= 1:
            # Nothing else was sent in the window: there was nothing to throttle.
            return "auth"
        r = await get_redis_bytes()
        streak = await r.hincrby(self._key("breaker"), "forbidden", 1)
        if streak >= AUTH_403_STREAK:
            return "auth"
        return "throttle" if 403 in self.throttle_statuses else "answer"

    async def _mark_auth_failed(self, status: int, message: str) -> None:
        r = await get_redis_bytes()
        key = self._key("auth")
        await r.hset(
            key,
            mapping={"status": str(status), "message": message, "at": datetime.now(UTC).isoformat()},
        )
        await r.expire(key, AUTH_FAILED_TTL)
        await r.hdel(self._key("breaker"), "forbidden")
        logger.warning("Auth failure recorded: %s", message)

    async def _auth_message(self) -> str:
        try:
            r = await get_redis_bytes()
            message = await r.hget(self._key("auth"), "message")
        except (RedisError, OSError):
            message = None
        return message.decode() if message else f"{self.source_type} rejected its API key"

    async def auth_failure(self) -> dict | None:
        """The credential's recorded auth failure: {status, message, at,
        expires_in}, or None. Raises GatewayUnavailable when Redis is down."""
        try:
            r = await get_redis_bytes()
            fields = await r.hgetall(self._key("auth"))
            ttl = await r.ttl(self._key("auth"))
        except (RedisError, OSError) as e:
            raise GatewayUnavailable(str(e)) from e
        if not fields:
            return None
        got = {k.decode(): v.decode() for k, v in fields.items()}
        return {
            "status": int(got.get("status") or 0),
            "message": got.get("message"),
            "at": got.get("at"),
            "expires_in": max(0, ttl),
        }

    async def clear_auth_failure(self) -> None:
        """Forget a recorded auth failure, e.g. when an admin tests the source
        after fixing the key upstream."""
        try:
            r = await get_redis_bytes()
            await r.delete(self._key("auth"))
        except (RedisError, OSError) as e:
            raise GatewayUnavailable(str(e)) from e

    async def remaining(self) -> int:
        """Requests the window would take now (for display)."""
        try:
            r = await get_redis_bytes()
            count = await r.zcount(self._key("window"), time.time() - self.period, "+inf")
        except (RedisError, OSError) as e:
            raise GatewayUnavailable(str(e)) from e
        return max(0, self.capacity - int(count))

    async def in_flight(self) -> int:
        """Requests in flight now under this credential."""
        try:
            r = await get_redis_bytes()
            return int(await r.zcount(self._key("inflight"), time.time(), "+inf"))
        except (RedisError, OSError) as e:
            raise GatewayUnavailable(str(e)) from e

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


def _task_id() -> int:
    task = asyncio.current_task()
    return id(task) if task else 0


def rate_limit_signal(response: httpx.Response) -> bool:
    """Whether a 403 says it is a rate limit (GitHub, NVD and most APIs
    send one of these)."""
    if response.headers.get("Retry-After") or response.headers.get("X-RateLimit-Remaining") == "0":
        return True
    body = _body_text(response)
    return "rate limit" in body.lower() or "too many requests" in body.lower()


def _body_text(response: httpx.Response) -> str:
    try:
        return response.text[:2000]
    except httpx.ResponseNotRead:
        return ""
    except Exception:
        return ""


def _auth_failure_message(source_type: str, response: httpx.Response, has_key: bool) -> str:
    """The console's line for a rejected credential: what the source said."""
    said = ""
    text = _body_text(response)
    try:
        body = json.loads(text) if text else None
    except ValueError:
        body = None
    if isinstance(body, dict):
        for k in ("message", "error_description", "error", "detail", "msg"):
            v = body.get(k)
            if isinstance(v, str) and v.strip():
                said = v.strip()
                break
            if isinstance(v, dict) and isinstance(v.get("message"), str):
                said = v["message"].strip()
                break
    elif text and "<" not in text[:50]:
        said = text.strip().splitlines()[0] if text.strip() else ""
    said = said[:200]
    what = "rejected the API key" if has_key else "needs an API key"
    line = f"{source_type} {what} (HTTP {response.status_code})"
    return f"{line}: {said}" if said else line


def _lease_for(request: httpx.Request) -> float:
    """How long a request's in-flight slot lives if nothing frees it: its
    timeouts plus a margin."""
    timeout = request.extensions.get("timeout") or {}
    parts = [v for v in (timeout.get("connect"), timeout.get("read"), timeout.get("write")) if v]
    return sum(parts) + IN_FLIGHT_MARGIN if parts else IN_FLIGHT_LEASE


class _ReleasingStream(httpx.AsyncByteStream):
    """A response body that frees the request's in-flight slot when closed."""

    def __init__(self, inner, gateway: SourceGateway, permit: Permit):
        self._inner = inner
        self._gateway = gateway
        self._permit = permit

    async def __aiter__(self):
        async for chunk in self._inner:
            yield chunk

    async def aclose(self) -> None:
        try:
            if hasattr(self._inner, "aclose"):
                await self._inner.aclose()
        finally:
            await self._gateway.release(self._permit)


class _GatewayTransport(httpx.AsyncBaseTransport):
    """Wraps the real transport so the gateway sees every request."""

    def __init__(self, gateway: SourceGateway, inner: httpx.AsyncBaseTransport):
        self._gateway = gateway
        self._inner = inner

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        gateway = self._gateway
        permit = await gateway.acquire(lease=_lease_for(request))
        request.headers["User-Agent"] = user_agent(gateway.source_type)
        try:
            response = await self._inner.handle_async_request(request)
        except httpx.TransportError:
            await gateway.record(None, permit=permit)
            raise
        except BaseException:
            await gateway.release(permit)
            raise
        try:
            if response.status_code in (401, 403):
                await response.aread()  # small; its body says whether the key is bad
            await gateway.record(response, permit=permit, release=False)
        except BaseException:
            await response.aclose()
            await gateway.release(permit)
            raise
        if response.status_code in (401, 403) or response.is_closed:
            # Already read (a 401/403 above, or a body given whole): done.
            await gateway.release(permit)
            return response
        response.stream = _ReleasingStream(response.stream, gateway, permit)
        return response

    async def aclose(self) -> None:
        await self._inner.aclose()


def client_for(transport: httpx.AsyncBaseTransport, timeout: float = 10, **kwargs) -> httpx.AsyncClient:
    """An httpx client on a gateway transport (``SourceGateway.transport()``),
    for helpers handed a transport instead of a gateway. Refuses any other
    transport, so a helper can't be handed a plain one."""
    if not isinstance(transport, _GatewayTransport):
        raise TypeError("client_for() needs a SourceGateway transport")
    return httpx.AsyncClient(transport=transport, timeout=timeout, **kwargs)
