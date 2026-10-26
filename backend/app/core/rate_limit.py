import ipaddress
import re
import secrets
import time

import redis.exceptions
import structlog
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

logger = structlog.get_logger("app.rate_limit")

# Paths exempt from rate limiting
EXEMPT_PATHS = {"/api/health", "/metrics"}

# AI read/config path prefixes exempt from the AI rate limit (not AI inference calls)
AI_EXEMPT_PREFIXES = ("/api/ai/tasks", "/api/ai/providers", "/api/ai/prompts", "/api/ai/copilot-auth")

# AI paths get a lower limit (applies to inference calls only)
AI_PATH_PREFIX = "/api/ai/"

# Auth paths get aggressive rate limiting to prevent brute force
AUTH_PATHS = {"/api/auth/login", "/api/auth/register", "/api/auth/refresh"}

# Chat streaming endpoint — protect against credit burn
CHAT_POST_PATH = "/api/chat"

# Limits: (max_requests, window_seconds)
AUTH_LIMIT = (10, 300)  # 10 req/5 min — prevents brute force
CHAT_LIMIT = (10, 60)  # 10 req/min — protects API credits
AI_LIMIT = (20, 60)  # 20 req/min

# Anonymous API traffic (public read-only mode, share pages) is budgeted per
# client IP, over a minute and over an hour. One article open in the reader
# is about 15 requests (the article, its entity lists, glossary, counts), so
# the minute window lets a person skim quickly and the hour window stops a
# steady crawl. Full article text costs a scraper one request per article
# but a person one in fifteen, so it has its own, much tighter budget. Reads
# that cost real database time (graphs, pivots, timelines, analytics) get
# a tighter one too.
ANON_LIMITS = ((180, 60), (1500, 3600))
ANON_ARTICLE_LIMITS = ((20, 60), (150, 3600))
ANON_HEAVY_LIMITS = ((20, 60), (200, 3600))
ANON_ARTICLE_PATH = re.compile(r"^/api/entries/[0-9a-fA-F-]{36}$")
ANON_HEAVY_PREFIXES = (
    "/api/intelligence/graph/",
    "/api/intelligence/pivot/",
    "/api/intelligence/timeline/",
    "/api/intelligence/entry-graph/",
    "/api/intelligence/temporal-clusters",
    "/api/analytics/",
    "/api/entries/map",
    "/api/entries/calendar",
    "/api/entries/priority-queue",
    "/api/entity-relationships",
    "/api/autolink/scan",
)
# TAXII and the EDL/lookup files are pulled by firewalls and SIEMs with
# their own publish token, not by people: they keep a plain per-minute
# budget so a visitor-sized hourly cap can't stall a sync.
INDICATOR_FEED_PREFIXES = ("/api/taxii2/", "/api/publish/")
INDICATOR_FEED_LIMIT = (240, 60)

# Buckets with more than one window; the rest enforce their single limit.
_BUCKET_WINDOWS = {
    "anon": ANON_LIMITS,
    "anon_article": ANON_ARTICLE_LIMITS,
    "anon_heavy": ANON_HEAVY_LIMITS,
}

_PROVIDER_TEST = re.compile(r"^/api/ai/providers/[0-9a-fA-F-]{36}/test$")


Windows = tuple[tuple[int, int], ...]


def _get_limits(path: str, method: str = "GET", *, anonymous: bool = False) -> tuple[str, Windows] | None:
    """Return (bucket_name, every (max_requests, window_seconds) window), or None to skip."""
    limit = _get_limit(path, method, anonymous=anonymous)
    if limit is None:
        return None
    return limit[2], _BUCKET_WINDOWS.get(limit[2], (limit[:2],))


def _get_limit(path: str, method: str = "GET", *, anonymous: bool = False) -> tuple[int, int, str] | None:
    """Return (max_requests, window_seconds, bucket_name), or None to skip rate limiting.

    The anonymous buckets also have an hourly window; ``_BUCKET_WINDOWS``
    lists every window a bucket enforces, and this returns the first.
    """
    if path in AUTH_PATHS:
        return (*AUTH_LIMIT, "auth")
    if method == "POST" and path == CHAT_POST_PATH:
        return (*CHAT_LIMIT, "chat")
    # Creating a provider with ?test=true and testing one make the server
    # open a connection to whatever address the row names, and any signed-in
    # person may do both for a personal key: budget them like inference.
    if method == "POST" and (path == "/api/ai/providers" or _PROVIDER_TEST.match(path)):
        return (*AI_LIMIT, "ai")
    if path.startswith(AI_PATH_PREFIX) and not path.startswith(AI_EXEMPT_PREFIXES):
        return (*AI_LIMIT, "ai")
    # The share page's AI calls need no login, so the only identity is the
    # client IP: give them the same per-minute budget as the signed-in AI
    # routes. The per-link daily limit is enforced in the route itself.
    if method == "POST" and path.startswith("/api/shared/") and path.endswith(("/ask-agent", "/run-ai-task")):
        return (*AI_LIMIT, "ai")
    if anonymous and path.startswith("/api/"):
        if path.startswith(INDICATOR_FEED_PREFIXES):
            return (*INDICATOR_FEED_LIMIT, "indicator_feeds")
        if method == "GET" and ANON_ARTICLE_PATH.match(path):
            return (*ANON_ARTICLE_LIMITS[0], "anon_article")
        if path.startswith(ANON_HEAVY_PREFIXES):
            return (*ANON_HEAVY_LIMITS[0], "anon_heavy")
        return (*ANON_LIMITS[0], "anon")
    # Authenticated read-only API traffic is not rate limited.
    # This is a self-hosted, single-user app — the default 600 req/min
    # limit was too low for normal operation with 200+ feeds triggering
    # SSE-driven query invalidations.
    return None


def _get_identity(request: Request) -> str:
    """Extract rate limit identity: the sub of a *verified* JWT, else the client IP.

    The signature is checked here, not just the payload: the share page's
    AI routes take no login, so an unverified bearer would let a caller
    mint a fresh bucket per request and never meet the per-minute limit.
    """
    from app.core.public_access import bearer_credential

    token = bearer_credential(request.headers.get("authorization"))
    if token:
        import jwt

        from app.config import settings
        from app.core.security import ALGORITHM

        try:
            payload = jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
            sub = payload.get("sub")
            if sub:
                return f"user:{sub}"
        except jwt.PyJWTError:
            pass

    return f"ip:{client_ip(request)}"


def client_ip(request: Request) -> str:
    """The address of whoever is really calling.

    In prod the direct peer is always the proxy on the Docker network, and
    nothing in the stack sets forwarded_allow_ips, so request.client is
    the proxy for every visitor and every anonymous bucket (login, the
    share page's AI calls) would be one shared bucket. When the direct
    peer is on a private network — our proxy, or the dev server — the
    first X-Forwarded-For hop is the client: Caddy strips the incoming
    header and writes its own peer there, so it can't be forged. Behind
    Cloudflare that hop is the edge node, shared by every visitor through
    it; the operator names the edge's own header (``CF-Connecting-IP``) in
    ``trusted_client_ip_header`` once the origin accepts the edge alone,
    and it is read first. A public direct peer is the client.
    """
    from app.config import settings
    from app.core.outbound import is_public

    client = request.client
    host = client.host if client else None
    if host:
        try:
            direct_is_proxy = not is_public(ipaddress.ip_address(host))
        except ValueError:
            direct_is_proxy = False
        if direct_is_proxy:
            trusted = (settings.trusted_client_ip_header or "").strip().lower()
            for header in (trusted, "x-forwarded-for") if trusted else ("x-forwarded-for",):
                first = request.headers.get(header, "").split(",")[0].strip()
                if first:
                    return first
    return host or "unknown"


# Every window a request must fit, checked and recorded in one atomic step:
# counting in one round trip and adding in a second let a burst of parallel
# requests all read the same count and all pass. Expired entries are trimmed
# first; if any window is full the request is refused and not recorded (so
# a visitor who hits the minute window is back as soon as their own earlier
# requests age out), and Retry-After is when enough entries leave that window
# for one more to fit. Otherwise the request is added to every window.
# KEYS: one sorted set per window. ARGV: now, member, then max, window pairs.
# Returns {allowed, retry_after, max of the tightest window, remaining}.
_SLIDING_WINDOWS = """
local now = tonumber(ARGV[1])
local retry, tight_max, tight_left = 0, 0, nil
for i, key in ipairs(KEYS) do
  local max = tonumber(ARGV[1 + 2 * i])
  local window = tonumber(ARGV[2 + 2 * i])
  redis.call('ZREMRANGEBYSCORE', key, 0, now - window)
  local count = redis.call('ZCARD', key)
  if count >= max then
    local entry = redis.call('ZRANGE', key, count - max, count - max, 'WITHSCORES')
    local wait = math.floor((tonumber(entry[2]) or now) + window - now) + 1
    if wait > retry then retry = wait end
  end
  local left = max - count - 1
  if tight_left == nil or left < tight_left then tight_max, tight_left = max, left end
end
if retry > 0 then return {0, retry, tight_max, 0} end
for i, key in ipairs(KEYS) do
  redis.call('ZADD', key, now, ARGV[2])
  redis.call('EXPIRE', key, tonumber(ARGV[2 + 2 * i]))
end
return {1, 0, tight_max, tight_left}
"""


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        path = request.url.path

        if path in EXEMPT_PATHS or request.method == "OPTIONS":
            return await call_next(request)

        identity = _get_identity(request)
        limits = _get_limits(path, request.method, anonymous=identity.startswith("ip:"))
        if limits is None:
            return await call_next(request)

        bucket, windows = limits
        keys = [f"ratelimit:{bucket}:{identity}:{window}" for _, window in windows]
        now = time.time()
        # Parallel requests can share a timestamp; the suffix keeps each one.
        member = f"{now}:{secrets.token_hex(4)}"
        args: list = [now, member]
        for max_requests, window in windows:
            args += [max_requests, window]
        try:
            from app.services.redis_client import get_redis_bytes

            r = await get_redis_bytes()
            allowed, retry_after, max_requests, left = await r.eval(_SLIDING_WINDOWS, len(keys), *keys, *args)
        except (TimeoutError, redis.exceptions.RedisError, ConnectionError, OSError, RuntimeError):
            # If Redis is down, allow the request but log
            logger.warning("Rate limiter Redis unavailable, allowing request", path=path)
            return await call_next(request)

        if not allowed:
            logger.warning("rate_limited", identity=identity, path=path, bucket=bucket)
            return JSONResponse(
                status_code=429,
                content={"error": {"code": "rate_limited", "message": "Too many requests", "details": []}},
                headers={"Retry-After": str(retry_after)},
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(max_requests)
        response.headers["X-RateLimit-Remaining"] = str(max(0, left))
        return response
