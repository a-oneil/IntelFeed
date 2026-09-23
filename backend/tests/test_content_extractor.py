"""Tests for the _extract_full_text function in app.workers.feed_tasks.

These tests mock httpx, readability, robots, and rate_limiter to isolate
the full-text extraction logic.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

SAMPLE_HTML = """\
<!DOCTYPE html>
<html>
<head><title>Threat Report</title></head>
<body>
<article>
  <h1>Critical Vulnerability Analysis</h1>
  <p>This is the main article content that should be extracted by readability.
  It contains enough text to pass the 100 character minimum threshold that
  _extract_full_text checks before returning content.</p>
  <p>Additional paragraph with more analysis details about the vulnerability,
  including IOCs, TTPs, and recommended mitigations for security teams.</p>
</article>
</body>
</html>
"""

EXTRACTED_CONTENT = (
    "<div><h1>Critical Vulnerability Analysis</h1>"
    "<p>This is the main article content that should be extracted by readability. "
    "It contains enough text to pass the 100 character minimum threshold.</p>"
    "<p>Additional paragraph with more analysis details.</p></div>"
)


@pytest.mark.asyncio
class TestExtractFullTextSuccess:
    async def test_extract_full_text_success(self):
        """Successful extraction: robots allows, rate limit OK, HTML returned, readability extracts."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = SAMPLE_HTML
        mock_response.headers = {"content-type": "text/html; charset=utf-8"}

        mock_http_client = AsyncMock()
        mock_http_client.get.return_value = mock_response
        mock_http_client.__aenter__ = AsyncMock(return_value=mock_http_client)
        mock_http_client.__aexit__ = AsyncMock(return_value=None)

        mock_doc = MagicMock()
        mock_doc.summary.return_value = EXTRACTED_CONTENT

        with (
            patch(
                "app.services.robots.can_fetch",
                new_callable=AsyncMock,
                return_value=True,
            ),
            patch(
                "app.services.rate_limiter.acquire_rate_limit",
                new_callable=AsyncMock,
                return_value=True,
            ),
            patch("httpx.AsyncClient", return_value=mock_http_client),
            patch("readability.Document", return_value=mock_doc) as mock_doc_cls,
        ):
            from app.workers.feed_tasks import _extract_full_text

            content, og_image = await _extract_full_text("https://example.com/article")

        assert content == EXTRACTED_CONTENT
        assert og_image is None

        # Verify readability was called with the response text
        mock_doc_cls.assert_called_once_with(SAMPLE_HTML)
        mock_doc.summary.assert_called_once()

    async def test_extract_full_text_short_content_returns_none(self):
        """When readability returns content shorter than 100 chars, return None."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html><body><p>Short</p></body></html>"
        mock_response.headers = {"content-type": "text/html"}

        mock_http_client = AsyncMock()
        mock_http_client.get.return_value = mock_response
        mock_http_client.__aenter__ = AsyncMock(return_value=mock_http_client)
        mock_http_client.__aexit__ = AsyncMock(return_value=None)

        mock_doc = MagicMock()
        mock_doc.summary.return_value = "<p>Short</p>"  # < 100 chars

        with (
            patch("app.services.robots.can_fetch", new_callable=AsyncMock, return_value=True),
            patch("app.services.rate_limiter.acquire_rate_limit", new_callable=AsyncMock, return_value=True),
            patch("httpx.AsyncClient", return_value=mock_http_client),
            patch("readability.Document", return_value=mock_doc),
        ):
            from app.workers.feed_tasks import _extract_full_text

            content, og_image = await _extract_full_text("https://example.com/short")

        assert content is None
        assert og_image is None


@pytest.mark.asyncio
class TestExtractFullTextRobotsBlocked:
    async def test_extract_full_text_robots_blocked(self):
        """When robots.txt disallows the URL, should return None without fetching."""
        with (
            patch(
                "app.services.robots.can_fetch",
                new_callable=AsyncMock,
                return_value=False,
            ),
            patch("httpx.AsyncClient") as mock_client_cls,
        ):
            from app.workers.feed_tasks import _extract_full_text

            content, og_image = await _extract_full_text("https://example.com/blocked-by-robots")

        assert content is None
        assert og_image is None

        # httpx should never be instantiated when robots blocks the request
        mock_client_cls.assert_not_called()

    async def test_extract_full_text_rate_limited(self):
        """When rate limiter blocks the request, should return None."""
        with (
            patch("app.services.robots.can_fetch", new_callable=AsyncMock, return_value=True),
            patch(
                "app.services.rate_limiter.acquire_rate_limit",
                new_callable=AsyncMock,
                return_value=False,
            ),
            patch("httpx.AsyncClient") as mock_client_cls,
        ):
            from app.workers.feed_tasks import _extract_full_text

            content, og_image = await _extract_full_text("https://example.com/rate-limited")

        assert content is None
        assert og_image is None
        mock_client_cls.assert_not_called()


@pytest.mark.asyncio
class TestExtractFullTextNonHtml:
    async def test_extract_full_text_non_html(self):
        """When the response content-type is not HTML, should return None."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '{"data": "json content"}'
        mock_response.headers = {"content-type": "application/json"}

        mock_http_client = AsyncMock()
        mock_http_client.get.return_value = mock_response
        mock_http_client.__aenter__ = AsyncMock(return_value=mock_http_client)
        mock_http_client.__aexit__ = AsyncMock(return_value=None)

        with (
            patch("app.services.robots.can_fetch", new_callable=AsyncMock, return_value=True),
            patch("app.services.rate_limiter.acquire_rate_limit", new_callable=AsyncMock, return_value=True),
            patch("httpx.AsyncClient", return_value=mock_http_client),
        ):
            from app.workers.feed_tasks import _extract_full_text

            content, og_image = await _extract_full_text("https://example.com/api/data.json")

        assert content is None
        assert og_image is None

    async def test_extract_full_text_pdf_content_type(self):
        """When the response is a PDF, should return None."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "%PDF-1.4 binary data"
        mock_response.headers = {"content-type": "application/pdf"}

        mock_http_client = AsyncMock()
        mock_http_client.get.return_value = mock_response
        mock_http_client.__aenter__ = AsyncMock(return_value=mock_http_client)
        mock_http_client.__aexit__ = AsyncMock(return_value=None)

        with (
            patch("app.services.robots.can_fetch", new_callable=AsyncMock, return_value=True),
            patch("app.services.rate_limiter.acquire_rate_limit", new_callable=AsyncMock, return_value=True),
            patch("httpx.AsyncClient", return_value=mock_http_client),
        ):
            from app.workers.feed_tasks import _extract_full_text

            content, og_image = await _extract_full_text("https://example.com/report.pdf")

        assert content is None
        assert og_image is None

    async def test_extract_full_text_http_error(self):
        """When the page returns a non-200 status, should return None."""
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.headers = {"content-type": "text/html"}

        mock_http_client = AsyncMock()
        mock_http_client.get.return_value = mock_response
        mock_http_client.__aenter__ = AsyncMock(return_value=mock_http_client)
        mock_http_client.__aexit__ = AsyncMock(return_value=None)

        with (
            patch("app.services.robots.can_fetch", new_callable=AsyncMock, return_value=True),
            patch("app.services.rate_limiter.acquire_rate_limit", new_callable=AsyncMock, return_value=True),
            patch("httpx.AsyncClient", return_value=mock_http_client),
        ):
            from app.workers.feed_tasks import _extract_full_text

            content, og_image = await _extract_full_text("https://example.com/not-found")

        assert content is None
        assert og_image is None
