"""Tests for app.services.robots.

All tests mock httpx to avoid fetching real robots.txt files.
The module-level _cache dict is cleared between tests.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services import robots

ROBOTS_TXT_ALLOW = """\
User-agent: *
Allow: /
Disallow: /admin/
"""

ROBOTS_TXT_DISALLOW_ALL = """\
User-agent: *
Disallow: /
"""

ROBOTS_TXT_WITH_CRAWL_DELAY = """\
User-agent: *
Allow: /
Crawl-delay: 5

User-agent: IntelFeed
Crawl-delay: 10
"""

ROBOTS_TXT_SPECIFIC_AGENT = """\
User-agent: IntelFeed/1.0 (+https://github.com/intelfeed; feed-aggregator)
Disallow: /private/

User-agent: *
Allow: /
"""


@pytest.fixture(autouse=True)
def clear_robots_cache():
    """Clear the robots.txt cache before and after each test."""
    robots._cache.clear()
    yield
    robots._cache.clear()


def _make_mock_client(response_text, status_code=200):
    """Helper to create a mock httpx.AsyncClient with a canned response."""
    mock_response = MagicMock()
    mock_response.status_code = status_code
    mock_response.text = response_text

    mock_client = AsyncMock()
    mock_client.get.return_value = mock_response
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    return mock_client


@pytest.mark.asyncio
class TestCanFetchAllowed:
    async def test_can_fetch_allowed(self):
        """When robots.txt allows the path, can_fetch should return True."""
        mock_client = _make_mock_client(ROBOTS_TXT_ALLOW)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await robots.can_fetch("https://example.com/articles/feed.xml")

        assert result is True

    async def test_can_fetch_allowed_specific_path(self):
        """A path that is not in the Disallow list should be allowed."""
        mock_client = _make_mock_client(ROBOTS_TXT_ALLOW)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await robots.can_fetch("https://example.com/blog/post-1")

        assert result is True

    async def test_can_fetch_uses_cache(self):
        """Second call for the same domain should use the cache, not fetch again."""
        mock_client = _make_mock_client(ROBOTS_TXT_ALLOW)

        with patch("httpx.AsyncClient", return_value=mock_client) as mock_cls:
            await robots.can_fetch("https://example.com/page1")
            await robots.can_fetch("https://example.com/page2")

        # httpx.AsyncClient should only be instantiated once (for the first fetch)
        assert mock_cls.call_count == 1


@pytest.mark.asyncio
class TestCanFetchBlocked:
    async def test_can_fetch_blocked(self):
        """When robots.txt disallows all paths, can_fetch should return False."""
        mock_client = _make_mock_client(ROBOTS_TXT_DISALLOW_ALL)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await robots.can_fetch("https://blocked.example.com/feed.xml")

        assert result is False

    async def test_can_fetch_blocked_admin_path(self):
        """A specifically disallowed path should be blocked."""
        mock_client = _make_mock_client(ROBOTS_TXT_ALLOW)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await robots.can_fetch("https://example.com/admin/settings")

        assert result is False


@pytest.mark.asyncio
class TestCanFetchNoRobots:
    async def test_can_fetch_no_robots_404(self):
        """When robots.txt returns 404, should default to allowing all URLs."""
        mock_client = _make_mock_client("Not Found", status_code=404)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await robots.can_fetch("https://no-robots.example.com/feed.xml")

        assert result is True

    async def test_can_fetch_no_robots_500(self):
        """When robots.txt returns 500, should default to allowing."""
        mock_client = _make_mock_client("Internal Server Error", status_code=500)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await robots.can_fetch("https://error.example.com/feed.xml")

        assert result is True

    async def test_can_fetch_http_error(self):
        """When fetching robots.txt raises an HTTP error, should default to allowing."""
        import httpx

        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.ConnectError("Connection refused")
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await robots.can_fetch("https://unreachable.example.com/feed.xml")

        assert result is True


@pytest.mark.asyncio
class TestGetCrawlDelay:
    async def test_get_crawl_delay(self):
        """get_crawl_delay should return the Crawl-delay value from robots.txt."""
        mock_client = _make_mock_client(ROBOTS_TXT_WITH_CRAWL_DELAY)

        with patch("httpx.AsyncClient", return_value=mock_client):
            delay = await robots.get_crawl_delay("https://delayed.example.com/feed.xml")

        # The parser should find a crawl delay (either 5 for * or 10 for IntelFeed)
        assert delay is not None
        assert isinstance(delay, float)
        assert delay > 0

    async def test_get_crawl_delay_none(self):
        """When robots.txt has no Crawl-delay, should return None."""
        mock_client = _make_mock_client(ROBOTS_TXT_ALLOW)

        with patch("httpx.AsyncClient", return_value=mock_client):
            delay = await robots.get_crawl_delay("https://example.com/feed.xml")

        assert delay is None

    async def test_get_crawl_delay_no_robots(self):
        """When robots.txt is missing (404), should return None."""
        mock_client = _make_mock_client("Not Found", status_code=404)

        with patch("httpx.AsyncClient", return_value=mock_client):
            delay = await robots.get_crawl_delay("https://no-robots.example.com/feed.xml")

        assert delay is None


class TestSelectEntry:
    """Guards the catch-all lookup across Python versions.

    Python 3.13 moved the ``*`` group out of ``RobotFileParser.default_entry``
    into ``.entries`` and made ``Entry.applies_to`` reject a real user agent for
    a ``*`` group. The previous implementation leaned on both, so on 3.13+ it
    matched no group at all and ``can_fetch`` allowed everything. These assert
    the selection itself, independent of which interpreter is running.
    """

    @staticmethod
    def _parse(text):
        from urllib.robotparser import RobotFileParser

        parser = RobotFileParser()
        parser.parse(text.splitlines())
        return parser

    def test_wildcard_group_is_found(self):
        """A `User-agent: *` group must be selected for an agent it never names."""
        parser = self._parse(ROBOTS_TXT_DISALLOW_ALL)

        entry = robots._select_entry(parser, "Mozilla/5.0 (Windows NT 10.0) Chrome/126.0")

        assert entry is not None, "catch-all group was not found — Disallow rules would be ignored"
        assert "*" in entry.useragents

    def test_named_group_wins_over_wildcard(self):
        """RFC 9309 §2.2.1: the group naming our agent beats the catch-all.

        The named group uses a bare product token, which is what agent matching
        compares against — a robots.txt that spells out a full
        ``Product/1.0 (+url)`` string as its ``User-agent`` matches nobody, in
        the stdlib and here alike.
        """
        parser = self._parse("User-agent: IntelFeed\nDisallow: /private/\n\nUser-agent: *\nAllow: /\n")

        entry = robots._select_entry(parser, "IntelFeed/1.0 (+https://github.com/intelfeed)")

        assert entry is not None
        assert "*" not in entry.useragents
        assert [str(r) for r in entry.rulelines] == ["Disallow: /private/"]

    def test_unnamed_agent_falls_back_to_wildcard(self):
        parser = self._parse(ROBOTS_TXT_SPECIFIC_AGENT)

        entry = robots._select_entry(parser, "SomeOtherBot/2.0")

        assert entry is not None
        assert "*" in entry.useragents

    def test_no_groups_at_all(self):
        parser = self._parse("# just a comment\n")

        assert robots._select_entry(parser, "AnyBot/1.0") is None


@pytest.mark.asyncio
class TestWildcardDisallowIsEnforced:
    async def test_wildcard_disallow_blocks_browser_user_agent(self):
        """Regression: `Disallow: /` under `User-agent: *` must block us.

        The fetcher sends a browser-like UA, which no robots.txt names, so this
        is the path that silently failed open on Python 3.13+.
        """
        mock_client = _make_mock_client(ROBOTS_TXT_DISALLOW_ALL)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await robots.can_fetch("https://blocked.example.com/anything")

        assert result is False
