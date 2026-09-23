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


def _get_limit(path: str, method: str = "GET") -> tuple[int, int, str] | None:
    """Return (max_requests, window_seconds, bucket_name), or None to skip rate limiting."""
    if path in AUTH_PATHS:
        return (*AUTH_LIMIT, "auth")
    if method == "POST" and path == CHAT_POST_PATH:
        return (*CHAT_LIMIT, "chat")
    if path.startswith(AI_PATH_PREFIX) and not path.startswith(AI_EXEMPT_PREFIXES):
        return (*AI_LIMIT, "ai")
    # Authenticated read-only API traffic is not rate limited.
    # This is a self-hosted, single-user app — the default 600 req/min
    # limit was too low for normal operation with 200+ feeds triggering
    # SSE-driven query invalidations.
    return None


def _get_identity(request: Request) -> str:
    """Extract rate limit identity: JWT sub claim or client IP."""
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:]
        # Decode just the payload without verification for identity extraction
        # (auth middleware handles actual verification)
        try:
            import base64
            import json

            payload_b64 = token.split(".")[1]
            # Add padding
            payload_b64 += "=" * (4 - len(payload_b64) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            sub = payload.get("sub")
            if sub:
                return f"user:{sub}"
        except Exception:
            pass

    # Fallback to IP
    client = request.client
    return f"ip:{client.host}" if client else "ip:unknown"


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
