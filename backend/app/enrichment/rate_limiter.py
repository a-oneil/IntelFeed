"""Sliding window rate limiter and daily budget tracker backed by Redis."""

import time
from datetime import UTC, datetime

import redis.asyncio as redis

from app.config import settings


class RedisRateLimiter:
    """Sliding window rate limiter for enrichment sources."""

    def __init__(self, source_type: str, config: dict):
        self.redis = redis.from_url(settings.redis_url)
        self.key = f"enrichment:rate:{source_type}"
        self.max_requests = config.get("requests_per_period", 100)
        self.period_seconds = config.get("period_seconds", 86400)

    async def check(self) -> bool:
        """Returns True if request is allowed, False if rate limited."""
        now = time.time()
        pipe = self.redis.pipeline()
        pipe.zremrangebyscore(self.key, 0, now - self.period_seconds)
        pipe.zcard(self.key)
        pipe.zadd(self.key, {str(now): now})
        pipe.expire(self.key, self.period_seconds)
        results = await pipe.execute()
        current_count = results[1]
        return current_count < self.max_requests

    async def get_remaining(self) -> int:
        """Return number of requests remaining in current window."""
        now = time.time()
        await self.redis.zremrangebyscore(self.key, 0, now - self.period_seconds)
        current = await self.redis.zcard(self.key)
        return max(0, self.max_requests - current)


class RedisBudgetTracker:
    """Daily budget tracker for enrichment sources.

    Uses a Redis key per source per UTC day that auto-expires after 25 hours.
    """

    def __init__(self, source_type: str):
        self.redis = redis.from_url(settings.redis_url)
        today = datetime.now(UTC).strftime("%Y-%m-%d")
        self.key = f"enrichment:budget:{source_type}:{today}"

    async def check_and_increment(self, budget: int) -> bool:
        """Atomically check budget and increment if within limit.

        Returns True if within budget (request allowed), False if exhausted.
        """
        current = await self.redis.incr(self.key)
        # Set expiry on first increment (25h to cover timezone edge cases)
        if current == 1:
            await self.redis.expire(self.key, 90000)
        if current > budget:
            await self.redis.decr(self.key)
            return False
        return True

    async def get_used(self) -> int:
        """Get number of enrichments used today."""
        val = await self.redis.get(self.key)
        return int(val) if val else 0

    @staticmethod
    async def get_used_bulk(source_types: list[str]) -> dict[str, int]:
        """Get budget usage for multiple sources at once."""
        r = redis.from_url(settings.redis_url)
        today = datetime.now(UTC).strftime("%Y-%m-%d")
        pipe = r.pipeline()
        for st in source_types:
            pipe.get(f"enrichment:budget:{st}:{today}")
        results = await pipe.execute()
        return {st: int(val) if val else 0 for st, val in zip(source_types, results)}
