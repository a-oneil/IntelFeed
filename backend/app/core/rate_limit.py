import ipaddress
import re
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

_PROVIDER_TEST = re.compile(r"^/api/ai/providers/[0-9a-fA-F-]{36}/test$")


def _get_limit(path: str, method: str = "GET") -> tuple[int, int, str] | None:
    """Return (max_requests, window_seconds, bucket_name), or None to skip rate limiting."""
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
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        import jwt

        from app.config import settings
        from app.core.security import ALGORITHM

        try:
            payload = jwt.decode(auth[7:], settings.secret_key, algorithms=[ALGORITHM])
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


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        path = request.url.path

        if path in EXEMPT_PATHS or request.method == "OPTIONS":
            return await call_next(request)

        limit = _get_limit(path, request.method)
        if limit is None:
            return await call_next(request)

        max_requests, window, bucket = limit
        identity = _get_identity(request)
        key = f"ratelimit:{bucket}:{identity}:{window}"

        try:
            from app.services.redis_client import get_redis_bytes

            r = await get_redis_bytes()
            now = time.time()
            pipe = r.pipeline()
            # Sliding window: remove expired entries, add current, count
            pipe.zremrangebyscore(key, 0, now - window)
            pipe.zadd(key, {str(now): now})
            pipe.zcard(key)
            pipe.expire(key, window)
            results = await pipe.execute()
            count = results[2]
        except (TimeoutError, redis.exceptions.RedisError, ConnectionError, OSError, RuntimeError):
            # If Redis is down, allow the request but log
            logger.warning("Rate limiter Redis unavailable, allowing request", path=path)
            return await call_next(request)

        if count > max_requests:
            logger.warning("rate_limited", identity=identity, path=path, count=count)
            return JSONResponse(
                status_code=429,
                content={"error": {"code": "rate_limited", "message": "Too many requests", "details": []}},
                headers={"Retry-After": str(window)},
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(max_requests)
        response.headers["X-RateLimit-Remaining"] = str(max(0, max_requests - count))
        return response
