import asyncio
import logging
import time
from urllib.parse import urlparse

from app.config import settings
from app.services.redis_client import get_redis_bytes

logger = logging.getLogger(__name__)


def _default_interval() -> float:
    """Seconds between requests to one domain: the Settings UI value when
    set, else the env default."""
    try:
        return float(settings.get("rate_limit_default_interval") or settings.rate_limit_default_interval)
    except (TypeError, ValueError):
        return float(settings.rate_limit_default_interval)


# Atomic rate limiter: claims the slot and returns when the request should fire.
# Returns 0 if it can go now, or the number of seconds the caller must wait.
# Either way, the slot is claimed (timestamp updated to now + wait_time).
_RATE_LIMIT_LUA = """
local key = KEYS[1]
local interval = tonumber(ARGV[1])
local now = tonumber(ARGV[2])
local ttl = tonumber(ARGV[3])

local last = redis.call('GET', key)
local next_allowed = now

if last then
    local last_ts = tonumber(last)
    next_allowed = math.max(now, last_ts + interval)
end

local wait = next_allowed - now
redis.call('SET', key, tostring(next_allowed), 'EX', ttl)
return tostring(wait)
"""


async def acquire_rate_limit(url: str, min_interval: float | None = None) -> bool:
    """Acquire a rate limit token for a domain using atomic Redis script.

    Returns True if the request can proceed, False if rate limited.
    Blocks until the token is available if within reasonable wait time.
    The slot is claimed atomically so concurrent workers queue up properly.
    """
    domain = _get_domain(url)
    interval = settings.rate_limit_overrides.get(domain, _default_interval())
    if min_interval and min_interval > interval:
        interval = min_interval
    key = f"ratelimit:{domain}"

    r = await get_redis_bytes()

    wait_time_str = await r.eval(
        _RATE_LIMIT_LUA,
        1,
        key,
        str(interval),
        str(time.time()),
        str(max(int(interval * 100), 60)),
    )
    wait_time = float(wait_time_str)

    if wait_time > 30:
        # Too long to wait — release our claim by not proceeding
        # (the timestamp is already advanced but that's fine, it'll expire)
        return False

    if wait_time > 0:
        await asyncio.sleep(wait_time)

    return True


def _get_domain(url: str) -> str:
    """Extract domain from URL for rate limiting."""
    parsed = urlparse(url)
    return parsed.netloc.lower()


async def check_rate_limit(url: str) -> float:
    """Check how long until the next request to this domain is allowed.

    Returns 0 if allowed now, or seconds to wait.
    """
    domain = _get_domain(url)
    interval = settings.rate_limit_overrides.get(domain, _default_interval())
    key = f"ratelimit:{domain}"

    r = await get_redis_bytes()
    last_request = await r.get(key)

    if last_request is None:
        return 0

    elapsed = time.time() - float(last_request)
    if elapsed >= interval:
        return 0

    return interval - elapsed
