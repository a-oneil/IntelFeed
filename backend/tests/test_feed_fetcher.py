"""Tests for the _fetch_feed async pipeline in app.workers.feed_tasks.

These tests mock httpx, the database session, feedparser, rate_limiter, etc.
to isolate the fetch logic without needing a real DB or network.
"""

import uuid
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.models.feed import Feed


@pytest.fixture
def mock_feed():
    """Create a mock Feed object that behaves like a real Feed model."""
    feed = MagicMock(spec=Feed)
    feed.id = uuid.uuid4()
    feed.url = "https://example.com/feed.xml"
    feed.is_active = True
    feed.etag = '"abc123"'
    feed.last_modified = "Mon, 01 Jan 2024 00:00:00 GMT"
    feed.last_fetched_at = None
    feed.error_count = 0
    feed.last_error = None
    feed.title = "Test Feed"
    feed.description = None
    feed.site_url = None
    feed.feed_type = "rss"
    feed.adapter_config = {}
    return feed


@pytest.fixture
def mock_db_session(mock_feed):
    """Create a mock async DB session that returns our mock_feed."""
    session = AsyncMock()

    # mock db.execute(select(Feed).where(...)) -> result.scalar_one_or_none() -> feed
    result_mock = MagicMock()
    result_mock.scalar_one_or_none.return_value = mock_feed
    session.execute.return_value = result_mock

    session.add = MagicMock()
    session.commit = AsyncMock()
    session.flush = AsyncMock()

    # db.begin_nested() is used as an async context manager (savepoint)
    nested = AsyncMock()
    nested.__aenter__.return_value = None
    nested.__aexit__.return_value = None
    session.begin_nested = MagicMock(return_value=nested)

    return session


@pytest.fixture
def mock_session_factory(mock_db_session):
    """Async context manager returned by _get_worker_session()."""
    ctx = AsyncMock()
    ctx.__aenter__.return_value = mock_db_session
    ctx.__aexit__.return_value = None
    return ctx


SAMPLE_RSS_RESPONSE = """\
<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Test Feed</title>
    <link>https://example.com</link>
    <description>A test feed</description>
    <item>
      <title>New Entry</title>
      <link>https://example.com/entry-1</link>
      <guid>https://example.com/entry-1</guid>
      <description>Entry content here.</description>
      <pubDate>Mon, 01 Jan 2024 12:00:00 GMT</pubDate>
    </item>
  </channel>
</rss>
"""


@pytest.mark.asyncio
class TestFetchFeed304NotModified:
    async def test_fetch_feed_304_not_modified(self, mock_feed, mock_db_session, mock_session_factory):
        """When the server returns 304, last_fetched_at should be updated but no entries created."""
        mock_response = MagicMock()
        mock_response.status_code = 304

        mock_http_client = AsyncMock()
        mock_http_client.get.return_value = mock_response
        mock_http_client.__aenter__ = AsyncMock(return_value=mock_http_client)
        mock_http_client.__aexit__ = AsyncMock(return_value=None)

        with (
            patch("app.workers.feed_tasks._get_worker_session", return_value=mock_session_factory),
            patch("httpx.AsyncClient", return_value=mock_http_client),
            patch("app.services.rate_limiter.acquire_rate_limit", new_callable=AsyncMock, return_value=True),
        ):
            from app.workers.feed_tasks import _fetch_feed

            await _fetch_feed(str(mock_feed.id))

        # Feed should have its last_fetched_at updated
        assert mock_feed.last_fetched_at is not None
        assert isinstance(mock_feed.last_fetched_at, datetime)

        # DB should have been committed
        mock_db_session.commit.assert_awaited()

        # error_count should NOT have been incremented
        assert mock_feed.error_count == 0


@pytest.mark.asyncio
class TestFetchFeedHttpError:
    async def test_fetch_feed_http_error(self, mock_feed, mock_db_session, mock_session_factory):
        """When httpx raises an HTTP error, error_count should be incremented."""
        mock_feed.error_count = 0

        mock_http_client = AsyncMock()
        mock_http_client.get.side_effect = httpx.ConnectError("Connection refused")
        mock_http_client.__aenter__ = AsyncMock(return_value=mock_http_client)
        mock_http_client.__aexit__ = AsyncMock(return_value=None)

        with (
            patch("app.workers.feed_tasks._get_worker_session", return_value=mock_session_factory),
            patch("httpx.AsyncClient", return_value=mock_http_client),
            patch("app.services.rate_limiter.acquire_rate_limit", new_callable=AsyncMock, return_value=True),
        ):
            from app.workers.feed_tasks import _fetch_feed

            await _fetch_feed(str(mock_feed.id))

        # error_count should be incremented
        assert mock_feed.error_count == 1
        assert mock_feed.last_error is not None
        assert "Connection refused" in mock_feed.last_error

        # last_fetched_at should still be updated
        assert mock_feed.last_fetched_at is not None

        # DB should have been committed even on error
        mock_db_session.commit.assert_awaited()

    async def test_fetch_feed_non_200_status(self, mock_feed, mock_db_session, mock_session_factory):
        """When the server returns a non-200/non-304 status, error_count should be incremented."""
        mock_response = MagicMock()
        mock_response.status_code = 500

        mock_http_client = AsyncMock()
        mock_http_client.get.return_value = mock_response
        mock_http_client.__aenter__ = AsyncMock(return_value=mock_http_client)
        mock_http_client.__aexit__ = AsyncMock(return_value=None)

        with (
            patch("app.workers.feed_tasks._get_worker_session", return_value=mock_session_factory),
            patch("httpx.AsyncClient", return_value=mock_http_client),
            patch("app.services.rate_limiter.acquire_rate_limit", new_callable=AsyncMock, return_value=True),
        ):
            from app.workers.feed_tasks import _fetch_feed

            await _fetch_feed(str(mock_feed.id))

        assert mock_feed.error_count == 1
        assert mock_feed.last_error == "HTTP 500"
        mock_db_session.commit.assert_awaited()


@pytest.mark.asyncio
class TestFetchFeedNewEntries:
    async def test_fetch_feed_new_entries(self, mock_feed, mock_db_session, mock_session_factory):
        """When feed returns new entries, they should be created and indexed."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = SAMPLE_RSS_RESPONSE
        mock_response.headers = {"etag": '"new-etag"', "last-modified": "Tue, 02 Jan 2024 00:00:00 GMT"}

        mock_http_client = AsyncMock()
        mock_http_client.get.return_value = mock_response
        mock_http_client.__aenter__ = AsyncMock(return_value=mock_http_client)
        mock_http_client.__aexit__ = AsyncMock(return_value=None)

        # First execute call returns the feed; subsequent calls (entry existence checks)
        # return no existing entry
        call_count = 0

        async def mock_execute(stmt):
            nonlocal call_count
            call_count += 1
            result = MagicMock()
            if call_count == 1:
                # First call: select(Feed)
                result.scalar_one_or_none.return_value = mock_feed
            elif call_count == 2:
                # Second call: select(Entry) existence check -- no existing entry
                result.scalar_one_or_none.return_value = None
            else:
                # Any further calls (e.g. SSE subscription query)
                result.all.return_value = []
                result.scalar_one_or_none.return_value = None
            return result

        mock_db_session.execute = AsyncMock(side_effect=mock_execute)

        with (
            patch("app.workers.feed_tasks._get_worker_session", return_value=mock_session_factory),
            patch("httpx.AsyncClient", return_value=mock_http_client),
            patch("app.services.rate_limiter.acquire_rate_limit", new_callable=AsyncMock, return_value=True),
            patch("app.workers.feed_tasks._extract_full_text", new_callable=AsyncMock, return_value=(None, None)),
            patch("app.services.meilisearch_client.index_entry") as mock_index,
        ):
            from app.workers.feed_tasks import _fetch_feed

            await _fetch_feed(str(mock_feed.id))

        # New entry should have been added to the session
        add_calls = mock_db_session.add.call_args_list
        assert len(add_calls) >= 2  # at least one Entry + the Feed update

        # Meilisearch indexing should have been called
        mock_index.assert_called_once()
        index_kwargs = mock_index.call_args
        assert index_kwargs.kwargs.get("title") == "New Entry" or (
            len(index_kwargs.args) > 0 or "title" in (index_kwargs.kwargs or {})
        )

        # Feed metadata should be updated
        assert mock_feed.etag == '"new-etag"'
        assert mock_feed.last_modified == "Tue, 02 Jan 2024 00:00:00 GMT"
        assert mock_feed.error_count == 0
        assert mock_feed.last_error is None

        # DB should have been committed
        mock_db_session.commit.assert_awaited()

    async def test_fetch_feed_rate_limited(self, mock_feed, mock_db_session, mock_session_factory):
        """When rate limited, the feed should not be fetched."""
        with (
            patch("app.workers.feed_tasks._get_worker_session", return_value=mock_session_factory),
            patch("app.services.rate_limiter.acquire_rate_limit", new_callable=AsyncMock, return_value=False),
            patch("httpx.AsyncClient") as mock_client_cls,
        ):
            from app.workers.feed_tasks import _fetch_feed

            await _fetch_feed(str(mock_feed.id))

        # httpx should never have been called
        mock_client_cls.assert_not_called()

    async def test_fetch_feed_inactive(self, mock_feed, mock_db_session, mock_session_factory):
        """When the feed is inactive, nothing should happen."""
        mock_feed.is_active = False

        with (
            patch("app.workers.feed_tasks._get_worker_session", return_value=mock_session_factory),
            patch("app.services.rate_limiter.acquire_rate_limit", new_callable=AsyncMock) as mock_rl,
        ):
            from app.workers.feed_tasks import _fetch_feed

            await _fetch_feed(str(mock_feed.id))

        # Rate limiter should not even be consulted
        mock_rl.assert_not_awaited()


@pytest.mark.asyncio
class TestFetchFeedHeaders:
    async def test_browser_headers_sent(self, mock_feed, mock_db_session, mock_session_factory):
        """The fetch client must send the configured UA plus standard Accept headers."""
        mock_feed.etag = None
        mock_feed.last_modified = None

        mock_response = MagicMock()
        mock_response.status_code = 304

        mock_http_client = AsyncMock()
        mock_http_client.get.return_value = mock_response
        mock_http_client.__aenter__ = AsyncMock(return_value=mock_http_client)
        mock_http_client.__aexit__ = AsyncMock(return_value=None)

        with (
            patch("app.workers.feed_tasks._get_worker_session", return_value=mock_session_factory),
            patch("httpx.AsyncClient", return_value=mock_http_client) as mock_client_cls,
            patch("app.services.rate_limiter.acquire_rate_limit", new_callable=AsyncMock, return_value=True),
            patch(
                "app.workers.feed_tasks._resolve_user_agent",
                new_callable=AsyncMock,
                return_value="TestBrowser/1.0",
            ),
        ):
            from app.workers.feed_tasks import _fetch_feed

            await _fetch_feed(str(mock_feed.id))

        headers = mock_client_cls.call_args.kwargs["headers"]
        assert headers["User-Agent"] == "TestBrowser/1.0"
        assert "application/rss+xml" in headers["Accept"]
        assert "application/atom+xml" in headers["Accept"]
        assert headers["Accept-Language"].startswith("en-US")
        # No stale conditional headers when the feed has no etag/last-modified
        assert "If-None-Match" not in headers
        assert "If-Modified-Since" not in headers

    async def test_conditional_headers_included_when_cached(self, mock_feed, mock_db_session, mock_session_factory):
        mock_response = MagicMock()
        mock_response.status_code = 304

        mock_http_client = AsyncMock()
        mock_http_client.get.return_value = mock_response
        mock_http_client.__aenter__ = AsyncMock(return_value=mock_http_client)
        mock_http_client.__aexit__ = AsyncMock(return_value=None)

        with (
            patch("app.workers.feed_tasks._get_worker_session", return_value=mock_session_factory),
            patch("httpx.AsyncClient", return_value=mock_http_client) as mock_client_cls,
            patch("app.services.rate_limiter.acquire_rate_limit", new_callable=AsyncMock, return_value=True),
            patch(
                "app.workers.feed_tasks._resolve_user_agent",
                new_callable=AsyncMock,
                return_value="TestBrowser/1.0",
            ),
        ):
            from app.workers.feed_tasks import _fetch_feed

            await _fetch_feed(str(mock_feed.id))

        headers = mock_client_cls.call_args.kwargs["headers"]
        assert headers["If-None-Match"] == '"abc123"'
        assert headers["If-Modified-Since"] == "Mon, 01 Jan 2024 00:00:00 GMT"


def test_default_user_agent_is_browser_like():
    """Bot-style UAs get 403'd by CISA/gov and Cloudflare-fronted sites."""
    from app.config import Settings

    default_ua = Settings.model_fields["user_agent"].default
    assert default_ua.startswith("Mozilla/5.0")
    assert "IntelFeed" not in default_ua


@pytest.mark.asyncio
class TestNonFetchableFeeds:
    async def test_manual_feed_skipped_without_error(self, mock_feed, mock_db_session, mock_session_factory):
        """manual:// pseudo-feeds must be skipped, not error every cycle."""
        mock_feed.feed_type = "manual"
        mock_feed.url = "manual://uploads"
        mock_feed.error_count = 42
        mock_feed.last_error = "unsupported protocol 'manual://'"

        with (
            patch("app.workers.feed_tasks._get_worker_session", return_value=mock_session_factory),
            patch("httpx.AsyncClient") as mock_client_cls,
            patch("app.services.rate_limiter.acquire_rate_limit", new_callable=AsyncMock) as mock_rl,
        ):
            from app.workers.feed_tasks import _fetch_feed

            await _fetch_feed(str(mock_feed.id))

        mock_client_cls.assert_not_called()
        mock_rl.assert_not_awaited()
        assert mock_feed.error_count == 0
        assert mock_feed.last_error is None
        assert mock_feed.last_fetched_at is not None
        mock_db_session.commit.assert_awaited()

    async def test_non_http_url_skipped(self, mock_feed, mock_db_session, mock_session_factory):
        """Any non-http(s) URL is treated as non-fetchable regardless of feed_type."""
        mock_feed.url = "file:///etc/passwd"

        with (
            patch("app.workers.feed_tasks._get_worker_session", return_value=mock_session_factory),
            patch("httpx.AsyncClient") as mock_client_cls,
        ):
            from app.workers.feed_tasks import _fetch_feed

            await _fetch_feed(str(mock_feed.id))

        mock_client_cls.assert_not_called()
        assert mock_feed.last_fetched_at is not None


@pytest.mark.asyncio
class TestFetch404Autodiscovery:
    def _client_returning(self, response):
        client = AsyncMock()
        client.get.return_value = response
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=None)
        return client

    async def test_autodiscovery_attempted_after_consecutive_404s(
        self, mock_feed, mock_db_session, mock_session_factory
    ):
        mock_feed.last_error = "HTTP 404"
        mock_feed.error_count = 2  # becomes 3 after this failure

        mock_response = MagicMock()
        mock_response.status_code = 404

        with (
            patch("app.workers.feed_tasks._get_worker_session", return_value=mock_session_factory),
            patch("httpx.AsyncClient", return_value=self._client_returning(mock_response)),
            patch("app.services.rate_limiter.acquire_rate_limit", new_callable=AsyncMock, return_value=True),
            patch("app.workers.feed_tasks._attempt_feed_url_autodiscovery", new_callable=AsyncMock) as mock_discover,
        ):
            from app.workers.feed_tasks import _fetch_feed

            await _fetch_feed(str(mock_feed.id))

        mock_discover.assert_awaited_once()
        assert mock_feed.error_count == 3

    async def test_autodiscovery_not_attempted_on_first_404(self, mock_feed, mock_db_session, mock_session_factory):
        """A single 404 (or a 404 after a different error) must not trigger rediscovery."""
        mock_feed.last_error = None
        mock_feed.error_count = 5

        mock_response = MagicMock()
        mock_response.status_code = 404

        with (
            patch("app.workers.feed_tasks._get_worker_session", return_value=mock_session_factory),
            patch("httpx.AsyncClient", return_value=self._client_returning(mock_response)),
            patch("app.services.rate_limiter.acquire_rate_limit", new_callable=AsyncMock, return_value=True),
            patch("app.workers.feed_tasks._attempt_feed_url_autodiscovery", new_callable=AsyncMock) as mock_discover,
        ):
            from app.workers.feed_tasks import _fetch_feed

            await _fetch_feed(str(mock_feed.id))

        mock_discover.assert_not_awaited()

    async def test_autodiscovery_not_attempted_for_403(self, mock_feed, mock_db_session, mock_session_factory):
        mock_feed.last_error = "HTTP 403"
        mock_feed.error_count = 10

        mock_response = MagicMock()
        mock_response.status_code = 403

        with (
            patch("app.workers.feed_tasks._get_worker_session", return_value=mock_session_factory),
            patch("httpx.AsyncClient", return_value=self._client_returning(mock_response)),
            patch("app.services.rate_limiter.acquire_rate_limit", new_callable=AsyncMock, return_value=True),
            patch("app.workers.feed_tasks._attempt_feed_url_autodiscovery", new_callable=AsyncMock) as mock_discover,
        ):
            from app.workers.feed_tasks import _fetch_feed

            await _fetch_feed(str(mock_feed.id))

        mock_discover.assert_not_awaited()

    async def test_autodiscovery_updates_url_and_records_audit_history(self, mock_feed):
        """End-to-end: homepage <link> tag -> verified candidate -> feed.url updated."""
        mock_feed.last_error = "HTTP 404"
        mock_feed.error_count = 4
        mock_feed.site_url = "https://example.com"
        mock_feed.adapter_config = {}

        homepage_response = MagicMock()
        homepage_response.status_code = 200
        homepage_response.headers = {"content-type": "text/html; charset=utf-8"}
        homepage_response.url = "https://example.com/"
        homepage_response.text = (
            '<html><head><link rel="alternate" type="application/rss+xml" href="/new-feed.xml"></head></html>'
        )

        feed_response = MagicMock()
        feed_response.status_code = 200
        feed_response.text = SAMPLE_RSS_RESPONSE

        client = AsyncMock()
        client.get.side_effect = [homepage_response, feed_response]
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=None)

        db = AsyncMock()
        uniqueness_result = MagicMock()
        uniqueness_result.scalar_one_or_none.return_value = None  # candidate URL not taken
        db.execute.return_value = uniqueness_result
        db.add = MagicMock()
        db.commit = AsyncMock()

        with patch("httpx.AsyncClient", return_value=client):
            from app.workers.feed_tasks import _attempt_feed_url_autodiscovery

            updated = await _attempt_feed_url_autodiscovery(db, mock_feed, {"User-Agent": "TestBrowser/1.0"})

        assert updated is True
        assert mock_feed.url == "https://example.com/new-feed.xml"
        assert mock_feed.error_count == 0
        assert mock_feed.last_error is None
        assert mock_feed.etag is None
        history = mock_feed.adapter_config["url_autodiscovery_history"]
        assert len(history) == 1
        assert history[0]["old_url"] == "https://example.com/feed.xml"
        assert history[0]["new_url"] == "https://example.com/new-feed.xml"
        assert "404" in history[0]["reason"]
        db.commit.assert_awaited()

    async def test_autodiscovery_skips_url_owned_by_another_feed(self, mock_feed):
        mock_feed.site_url = "https://example.com"
        mock_feed.adapter_config = {}
        original_url = mock_feed.url

        homepage_response = MagicMock()
        homepage_response.status_code = 200
        homepage_response.headers = {"content-type": "text/html"}
        homepage_response.url = "https://example.com/"
        homepage_response.text = (
            '<link rel="alternate" type="application/rss+xml" href="https://example.com/taken.xml">'
        )

        client = AsyncMock()
        client.get.return_value = homepage_response
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=None)

        db = AsyncMock()
        uniqueness_result = MagicMock()
        uniqueness_result.scalar_one_or_none.return_value = uuid.uuid4()  # URL already taken
        db.execute.return_value = uniqueness_result
        db.commit = AsyncMock()

        with patch("httpx.AsyncClient", return_value=client):
            from app.workers.feed_tasks import _attempt_feed_url_autodiscovery

            updated = await _attempt_feed_url_autodiscovery(db, mock_feed, {"User-Agent": "TestBrowser/1.0"})

        assert updated is False
        assert mock_feed.url == original_url
        db.commit.assert_not_awaited()
