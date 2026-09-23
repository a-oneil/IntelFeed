import redis.asyncio as aioredis

from app.config import settings

_pool: aioredis.Redis | None = None
_pool_bytes: aioredis.Redis | None = None


async def get_redis() -> aioredis.Redis:
    """Get shared Redis client with decoded string responses."""
    global _pool
    if _pool is None:
        _pool = aioredis.from_url(settings.redis_url, decode_responses=True)
    return _pool


async def get_redis_bytes() -> aioredis.Redis:
    """Get shared Redis client with raw bytes responses (for rate limiting)."""
    global _pool_bytes
    if _pool_bytes is None:
        _pool_bytes = aioredis.from_url(settings.redis_url, decode_responses=False)
    return _pool_bytes


def reset_pools() -> None:
    """Reset Redis singletons (used in tests to avoid stale event-loop refs)."""
    global _pool, _pool_bytes
    _pool = None
    _pool_bytes = None
