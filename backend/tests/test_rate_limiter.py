"""Tests for app.services.rate_limiter.

All tests mock Redis to avoid needing a running Redis instance.
"""

import time
from unittest.mock import AsyncMock, patch

import pytest

from app.services import rate_limiter


@pytest.fixture
def mock_redis():
    """Create a mock async Redis client."""
    return AsyncMock()


def _patch_redis(mock_redis):
    """Swap in the mock for the shared bytes-mode Redis client."""
    return patch(
        "app.services.rate_limiter.get_redis_bytes",
        new_callable=AsyncMock,
        return_value=mock_redis,
    )


@pytest.mark.asyncio
class TestAcquireRateLimit:
    """``acquire_rate_limit`` claims a slot with a single atomic Lua call.

    The script returns the number of seconds the caller must wait; the caller
    only decides whether to sleep, to proceed, or to give up.
    """

    async def test_acquire_rate_limit_first_request(self, mock_redis):
        """First request to a domain: no wait, and the slot is claimed."""
        mock_redis.eval.return_value = b"0"

        with _patch_redis(mock_redis):
            result = await rate_limiter.acquire_rate_limit("https://example.com/feed.xml")

        assert result is True

        mock_redis.eval.assert_awaited_once()
        args = mock_redis.eval.call_args[0]
        assert args[0] == rate_limiter._RATE_LIMIT_LUA
        assert args[1] == 1
        assert args[2] == "ratelimit:example.com"
        assert float(args[3]) == 2.0  # default interval
        assert abs(float(args[4]) - time.time()) < 5  # "now" argument
        assert int(args[5]) > 0  # TTL

    async def test_acquire_rate_limit_within_interval(self, mock_redis):
        """A non-zero wait from the script makes the caller sleep, then proceed."""
        mock_redis.eval.return_value = b"1.0"

        with _patch_redis(mock_redis), patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            result = await rate_limiter.acquire_rate_limit("https://example.com/feed.xml")

        assert result is True
        mock_sleep.assert_awaited_once_with(1.0)

    async def test_acquire_rate_limit_elapsed_past_interval(self, mock_redis):
        """A zero wait means the caller proceeds without sleeping."""
        mock_redis.eval.return_value = b"0"

        with _patch_redis(mock_redis), patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            result = await rate_limiter.acquire_rate_limit("https://example.com/old-request")

        assert result is True
        mock_sleep.assert_not_awaited()

    async def test_acquire_rate_limit_too_long_wait(self, mock_redis):
        """A wait beyond 30s is refused rather than slept through."""
        mock_redis.eval.return_value = b"60.0"

        with _patch_redis(mock_redis), patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            result = await rate_limiter.acquire_rate_limit("https://example.com/feed.xml")

        assert result is False
        mock_sleep.assert_not_awaited()

    async def test_acquire_rate_limit_honours_min_interval(self, mock_redis):
        """An explicit ``min_interval`` wins when it exceeds the configured one."""
        mock_redis.eval.return_value = b"0"

        with _patch_redis(mock_redis):
            await rate_limiter.acquire_rate_limit("https://example.com/feed.xml", min_interval=30.0)

        assert float(mock_redis.eval.call_args[0][3]) == 30.0

    async def test_acquire_rate_limit_uses_domain_override(self, mock_redis):
        """A per-domain override replaces the default interval."""
        mock_redis.eval.return_value = b"0"

        with (
            _patch_redis(mock_redis),
            patch.object(rate_limiter.settings, "rate_limit_overrides", {"example.com": 15.0}),
        ):
            await rate_limiter.acquire_rate_limit("https://example.com/feed.xml")

        assert float(mock_redis.eval.call_args[0][3]) == 15.0


@pytest.mark.asyncio
class TestCheckRateLimit:
    async def test_check_rate_limit_no_previous_request(self, mock_redis):
        """When no previous request exists, check_rate_limit should return 0."""
        mock_redis.get.return_value = None

        with _patch_redis(mock_redis):
            wait = await rate_limiter.check_rate_limit("https://newdomain.com/feed")

        assert wait == 0

    async def test_check_rate_limit_recently_requested(self, mock_redis):
        """When a recent request was made, should return remaining wait time."""
        mock_redis.get.return_value = str(time.time() - 0.5).encode()

        with _patch_redis(mock_redis):
            wait = await rate_limiter.check_rate_limit("https://example.com/feed")

        # With default 2s interval and 0.5s elapsed, wait should be ~1.5s
        assert 1.0 < wait < 2.0

    async def test_check_rate_limit_interval_passed(self, mock_redis):
        """When the interval has fully elapsed, should return 0."""
        mock_redis.get.return_value = str(time.time() - 10.0).encode()

        with _patch_redis(mock_redis):
            wait = await rate_limiter.check_rate_limit("https://example.com/feed")

        assert wait == 0

    async def test_check_rate_limit_domain_extraction(self, mock_redis):
        """Verify that the correct Redis key is used based on domain extraction."""
        mock_redis.get.return_value = None

        with _patch_redis(mock_redis):
            await rate_limiter.check_rate_limit("https://blog.example.com/path/to/feed")

        mock_redis.get.assert_awaited_once_with("ratelimit:blog.example.com")
