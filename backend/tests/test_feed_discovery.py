"""Tests for app.services.feed_discovery.

All tests mock httpx.AsyncClient to avoid real network calls.
Covers direct RSS/Atom feed URLs, HTML page discovery, YouTube channel/video URLs,
invalid/unreachable URLs, and pages with no feed links.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.services.feed_discovery import discover_feed, extract_feed_links

# ---------------------------------------------------------------------------
# Sample responses
# ---------------------------------------------------------------------------

SAMPLE_RSS = """\
<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Security Blog</title>
    <link>https://example.com</link>
    <description>Latest security news</description>
    <item>
      <title>CVE-2024-0001 Analysis</title>
      <link>https://example.com/cve-2024-0001</link>
      <guid>https://example.com/cve-2024-0001</guid>
      <description>Analysis of CVE-2024-0001.</description>
      <pubDate>Mon, 15 Jan 2024 12:00:00 GMT</pubDate>
    </item>
  </channel>
</rss>
"""

SAMPLE_ATOM = """\
<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Threat Intel Feed</title>
  <subtitle>Threat intelligence updates</subtitle>
  <link href="https://example.com"/>
  <entry>
    <title>New Threat Actor</title>
    <link href="https://example.com/threat-actor-1"/>
    <id>https://example.com/threat-actor-1</id>
    <summary>Details on a new threat actor.</summary>
    <updated>2024-01-15T12:00:00Z</updated>
  </entry>
</feed>
"""

HTML_WITH_RSS_LINK = """\
<!DOCTYPE html>
<html>
<head>
  <title>Security Blog</title>
  <link rel="alternate" type="application/rss+xml" href="https://example.com/feed.xml" title="RSS Feed"/>
</head>
<body><h1>Security Blog</h1></body>
</html>
"""

HTML_WITH_ATOM_LINK = """\
<!DOCTYPE html>
<html>
<head>
  <title>Threat Intel Site</title>
  <link rel="alternate" type="application/atom+xml" href="/atom.xml" title="Atom Feed"/>
</head>
<body><h1>Threat Intel</h1></body>
</html>
"""

HTML_WITH_MULTIPLE_FEED_LINKS = """\
<!DOCTYPE html>
<html>
<head>
  <title>Multi-Feed Site</title>
  <link rel="alternate" type="application/rss+xml" href="https://example.com/rss.xml" title="RSS"/>
  <link rel="alternate" type="application/atom+xml" href="https://example.com/atom.xml" title="Atom"/>
</head>
<body><h1>Multi</h1></body>
</html>
"""

HTML_NO_FEEDS = """\
<!DOCTYPE html>
<html>
<head><title>No Feeds Here</title></head>
<body><p>Just a plain page.</p></body>
</html>
"""

YOUTUBE_CHANNEL_PAGE = """\
<!DOCTYPE html>
<html>
<head>
  <meta property="og:title" content="Security Weekly"/>
</head>
<body>
  <script>var ytInitialData = {"externalId":"UC1234567890abcdef"};</script>
</body>
</html>
"""

# No externalId — discovery falls back to browseId.
YOUTUBE_CHANNEL_PAGE_BROWSE_ID = """\
<!DOCTYPE html>
<html>
<head>
  <meta property="og:title" content="Hacker News TV"/>
</head>
<body>
  <script>var ytInitialData = {"browseId":"UCabcdefghij1234567890"};</script>
</body>
</html>
"""

# The RSS <link> tag is preferred over any ID scraped out of the page body.
YOUTUBE_CHANNEL_PAGE_RSS_LINK = """\
<!DOCTYPE html>
<html>
<head>
  <meta property="og:title" content="Linked Channel"/>
  <link rel="alternate" type="application/rss+xml" title="RSS"
        href="https://www.youtube.com/feeds/videos.xml?channel_id=UCfromlinktag00000"/>
</head>
<body>
  <script>var ytInitialData = {"externalId":"UCshouldbeignored0"};</script>
</body>
</html>
"""

YOUTUBE_CHANNEL_PAGE_NO_ID = """\
<!DOCTYPE html>
<html>
<head>
  <meta property="og:title" content="Mystery Channel"/>
</head>
<body><p>No channel ID anywhere.</p></body>
</html>
"""

YOUTUBE_VIDEO_PAGE = """\
<!DOCTYPE html>
<html>
<head>
  <meta property="og:title" content="How to Write SIGMA Rules"/>
</head>
<body>
  <script>var ytInitialPlayerResponse = {"videoDetails":{"channelId":"UCvideo_channel_id_123"}};</script>
</body>
</html>
"""

MALFORMED_XML = """\
<?xml version="1.0"?>
<rss version="2.0">
  <channel>
    <title>Broken Feed</title>
    <!-- missing closing tags
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_response(text: str, content_type: str = "text/html", status_code: int = 200):
    """Create a mock httpx.Response with the given body and content-type."""
    resp = MagicMock()
    resp.text = text
    resp.status_code = status_code
    resp.headers = {"content-type": content_type}
    resp.raise_for_status = MagicMock()
    if status_code >= 400:
        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            message=f"HTTP {status_code}",
            request=MagicMock(),
            response=resp,
        )
    return resp


def _mock_async_client(responses: dict[str, MagicMock] | MagicMock | None = None):
    """Create a mock httpx.AsyncClient that returns canned responses.

    Args:
        responses: Either a single MagicMock response (used for all GETs),
                   or a dict mapping URL substrings to responses.
    """
    mock_client = AsyncMock()

    if isinstance(responses, dict):

        async def side_effect(url, **kwargs):
            for pattern, resp in responses.items():
                if pattern in str(url):
                    return resp
            # Fallback: 404
            return _mock_response("Not Found", status_code=404)

        mock_client.get = AsyncMock(side_effect=side_effect)
    elif responses is not None:
        mock_client.get = AsyncMock(return_value=responses)
    else:
        mock_client.get = AsyncMock(return_value=_mock_response("", status_code=404))

    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    return mock_client


# ---------------------------------------------------------------------------
# Tests: Direct RSS/Atom URL discovery
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestDiscoverDirectFeed:
    """Tests for discovering feeds when the URL points directly to a feed."""

    async def test_discover_rss_feed_by_content_type(self):
        """An RSS URL with application/rss+xml content-type should be discovered."""
        mock_client = _mock_async_client(_mock_response(SAMPLE_RSS, content_type="application/rss+xml"))

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await discover_feed("https://example.com/feed.xml")

        assert result is not None
        assert result.url == "https://example.com/feed.xml"
        assert result.title == "Security Blog"
        assert result.feed_type == "rss"
        assert result.description == "Latest security news"

    async def test_discover_atom_feed_by_content_type(self):
        """An Atom URL with application/atom+xml content-type should be discovered."""
        mock_client = _mock_async_client(_mock_response(SAMPLE_ATOM, content_type="application/atom+xml"))

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await discover_feed("https://example.com/atom.xml")

        assert result is not None
        assert result.url == "https://example.com/atom.xml"
        assert result.title == "Threat Intel Feed"
        assert result.feed_type == "atom"
        assert result.description == "Threat intelligence updates"

    async def test_discover_rss_feed_by_xml_content_type(self):
        """An RSS URL with generic text/xml content-type should still be detected."""
        mock_client = _mock_async_client(_mock_response(SAMPLE_RSS, content_type="text/xml; charset=utf-8"))

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await discover_feed("https://example.com/rss")

        assert result is not None
        assert result.url == "https://example.com/rss"
        assert result.title == "Security Blog"

    async def test_discover_feed_by_xml_declaration(self):
        """A feed served as text/html but starting with <?xml should be detected."""
        mock_client = _mock_async_client(_mock_response(SAMPLE_RSS, content_type="text/html"))

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await discover_feed("https://example.com/feed")

        assert result is not None
        assert result.url == "https://example.com/feed"
        assert result.title == "Security Blog"

    async def test_discover_feed_by_rss_tag(self):
        """A feed starting with <rss but without <?xml declaration should be detected."""
        rss_no_decl = SAMPLE_RSS.replace('<?xml version="1.0" encoding="UTF-8"?>\n', "")
        mock_client = _mock_async_client(_mock_response(rss_no_decl, content_type="text/plain"))

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await discover_feed("https://example.com/raw-rss")

        assert result is not None
        assert result.title == "Security Blog"

    async def test_discover_feed_by_feed_tag(self):
        """A feed starting with <feed (Atom) should be detected even with wrong content-type."""
        atom_no_decl = SAMPLE_ATOM.replace('<?xml version="1.0" encoding="UTF-8"?>\n', "")
        mock_client = _mock_async_client(_mock_response(atom_no_decl, content_type="text/plain"))

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await discover_feed("https://example.com/raw-atom")

        assert result is not None
        assert result.title == "Threat Intel Feed"

    async def test_discover_malformed_feed_returns_none(self):
        """A malformed XML feed with no parseable entries should return None."""
        mock_client = _mock_async_client(_mock_response(MALFORMED_XML, content_type="application/rss+xml"))

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await discover_feed("https://example.com/broken.xml")

        assert result is None


# ---------------------------------------------------------------------------
# Tests: HTML page with feed <link> tags
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestDiscoverFromHTMLPage:
    """Tests for discovering feeds from HTML pages containing <link> tags."""

    async def test_discover_rss_from_html_link_tag(self):
        """An HTML page with an RSS <link> tag should discover the referenced feed."""
        mock_client = _mock_async_client(
            {
                "example.com/blog": _mock_response(HTML_WITH_RSS_LINK, content_type="text/html"),
                "feed.xml": _mock_response(SAMPLE_RSS, content_type="application/rss+xml"),
            }
        )

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await discover_feed("https://example.com/blog")

        assert result is not None
        assert result.url == "https://example.com/feed.xml"
        assert result.title == "Security Blog"
        assert result.feed_type == "rss"

    async def test_discover_atom_from_html_with_relative_url(self):
        """An HTML page with an Atom <link> using a relative href should resolve correctly."""
        mock_client = _mock_async_client(
            {
                "example.com/site": _mock_response(HTML_WITH_ATOM_LINK, content_type="text/html"),
                "atom.xml": _mock_response(SAMPLE_ATOM, content_type="application/atom+xml"),
            }
        )

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await discover_feed("https://example.com/site")

        assert result is not None
        assert result.url == "https://example.com/atom.xml"
        assert result.title == "Threat Intel Feed"
        assert result.feed_type == "atom"

    async def test_discover_picks_first_feed_link(self):
        """When multiple feed links are present, the first one should be used."""
        mock_client = _mock_async_client(
            {
                "example.com/multi": _mock_response(HTML_WITH_MULTIPLE_FEED_LINKS, content_type="text/html"),
                "rss.xml": _mock_response(SAMPLE_RSS, content_type="application/rss+xml"),
            }
        )

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await discover_feed("https://example.com/multi")

        assert result is not None
        assert result.url == "https://example.com/rss.xml"
        assert result.title == "Security Blog"

    async def test_discover_html_feed_link_unreachable(self):
        """When an HTML page has a feed link but the feed URL is unreachable, return None."""
        feed_response = MagicMock()
        feed_response.status_code = 500
        feed_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            message="HTTP 500",
            request=MagicMock(),
            response=feed_response,
        )

        mock_client = _mock_async_client(
            {
                "example.com/blog": _mock_response(HTML_WITH_RSS_LINK, content_type="text/html"),
                "feed.xml": feed_response,
            }
        )

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await discover_feed("https://example.com/blog")

        assert result is None


# ---------------------------------------------------------------------------
# Tests: YouTube channel URL
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestDiscoverYouTubeChannel:
    """Tests for discovering YouTube channel feeds from channel URLs."""

    async def test_discover_youtube_channel_url(self):
        """A youtube.com/channel/... URL should discover the channel's feed."""
        mock_client = _mock_async_client(_mock_response(YOUTUBE_CHANNEL_PAGE, content_type="text/html"))

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await discover_feed("https://www.youtube.com/channel/UC1234567890abcdef")

        assert result is not None
        assert result.url == "https://www.youtube.com/feeds/videos.xml?channel_id=UC1234567890abcdef"
        assert result.title == "Security Weekly"
        assert result.feed_type == "youtube"

    async def test_discover_youtube_at_handle_url_not_matched(self):
        """A youtube.com/@handle URL does NOT match the channel regex.

        The current YOUTUBE_CHANNEL_RE expects a '/' between '@' and the handle
        (i.e. youtube.com/@/handle), but real YouTube @handle URLs are
        youtube.com/@handle (no slash). This means @handle URLs fall through
        to normal HTML page discovery, which won't find RSS/Atom <link> tags
        on a YouTube page and returns None.
        """
        mock_client = _mock_async_client(_mock_response(YOUTUBE_CHANNEL_PAGE, content_type="text/html"))

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await discover_feed("https://www.youtube.com/@SecurityWeekly")

        # @handle URLs don't match the YouTube regex, so they fall through
        # to the HTML path. The YouTube HTML has no RSS/Atom <link> tags,
        # so discovery returns None.
        assert result is None

    async def test_discover_youtube_c_url(self):
        """A youtube.com/c/... URL should discover the channel's feed."""
        mock_client = _mock_async_client(_mock_response(YOUTUBE_CHANNEL_PAGE, content_type="text/html"))

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await discover_feed("https://www.youtube.com/c/SecurityWeekly")

        assert result is not None
        assert result.feed_type == "youtube"

    async def test_discover_youtube_user_url(self):
        """A youtube.com/user/... URL should discover the channel's feed."""
        mock_client = _mock_async_client(_mock_response(YOUTUBE_CHANNEL_PAGE, content_type="text/html"))

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await discover_feed("https://www.youtube.com/user/SecurityWeekly")

        assert result is not None
        assert result.feed_type == "youtube"

    async def test_discover_youtube_browse_id_fallback(self):
        """With no externalId in the page, discovery falls back to browseId."""
        mock_client = _mock_async_client(_mock_response(YOUTUBE_CHANNEL_PAGE_BROWSE_ID, content_type="text/html"))

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await discover_feed("https://www.youtube.com/channel/UCabcdefghij1234567890")

        assert result is not None
        assert result.url == "https://www.youtube.com/feeds/videos.xml?channel_id=UCabcdefghij1234567890"
        assert result.title == "Hacker News TV"
        assert result.feed_type == "youtube"

    async def test_discover_youtube_prefers_rss_link_tag(self):
        """The RSS <link> tag wins over any channel ID scraped from the body.

        Ids embedded in the page can belong to recommended or embedded content,
        so the declared feed URL is the more trustworthy source.
        """
        mock_client = _mock_async_client(_mock_response(YOUTUBE_CHANNEL_PAGE_RSS_LINK, content_type="text/html"))

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await discover_feed("https://www.youtube.com/channel/UCfromlinktag00000")

        assert result is not None
        assert result.url == "https://www.youtube.com/feeds/videos.xml?channel_id=UCfromlinktag00000"
        assert result.title == "Linked Channel"

    async def test_discover_youtube_ignores_channel_id_key(self):
        """A bare "channelId" is no longer trusted — it can match embedded content."""
        page = '<html><body><script>{"channelId":"UCembeddedvideo00"}</script></body></html>'
        mock_client = _mock_async_client(_mock_response(page, content_type="text/html"))

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await discover_feed("https://www.youtube.com/channel/UCembeddedvideo00")

        assert result is None

    async def test_discover_youtube_no_channel_id_found(self):
        """When the YouTube page does not contain a channel ID, return None."""
        mock_client = _mock_async_client(_mock_response(YOUTUBE_CHANNEL_PAGE_NO_ID, content_type="text/html"))

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await discover_feed("https://www.youtube.com/@MysteryChannel")

        assert result is None

    async def test_discover_youtube_fallback_title(self):
        """When og:title is missing, the feed URL stands in as the title."""
        page_no_og = '<html><body><script>"externalId":"UCtest123"</script></body></html>'
        mock_client = _mock_async_client(_mock_response(page_no_og, content_type="text/html"))

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await discover_feed("https://www.youtube.com/channel/UCtest123")

        assert result is not None
        assert result.title == "https://www.youtube.com/feeds/videos.xml?channel_id=UCtest123"

    async def test_discover_youtube_http_error(self):
        """When the YouTube page is unreachable, return None."""
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("Connection refused"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await discover_feed("https://www.youtube.com/@UnreachableChannel")

        assert result is None


# ---------------------------------------------------------------------------
# Tests: YouTube video URL
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestDiscoverYouTubeVideoURL:
    """Tests for YouTube video URLs (youtube.com/watch?v=...).

    Video URLs do NOT match the YOUTUBE_CHANNEL_RE regex, so they fall through
    to the normal HTML discovery path. The video page HTML typically does not
    contain RSS/Atom <link> tags, so discovery returns None.
    """

    async def test_youtube_video_url_no_feed_link_returns_none(self):
        """A YouTube /watch?v= URL with no feed <link> tags returns None."""
        mock_client = _mock_async_client(_mock_response(YOUTUBE_VIDEO_PAGE, content_type="text/html"))

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await discover_feed("https://www.youtube.com/watch?v=abc123")

        # Video URLs do not match the YouTube channel regex, so the function
        # falls through to HTML discovery. No <link type="application/rss+xml">
        # is present in the video page, so result is None.
        assert result is None

    async def test_youtube_video_url_with_feed_link(self):
        """If a YouTube video page somehow contains a feed <link>, it would be followed."""
        video_page_with_link = (
            "<!DOCTYPE html>\n<html>\n<head>\n"
            '  <link rel="alternate" type="application/rss+xml" '
            'href="https://www.youtube.com/feeds/videos.xml?channel_id=UCvideo123" title="Channel Feed"/>\n'
            "</head>\n<body></body>\n</html>\n"
        )
        mock_client = _mock_async_client(
            {
                "watch": _mock_response(video_page_with_link, content_type="text/html"),
                "feeds/videos.xml": _mock_response(
                    '<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom">'
                    "<title>Channel</title>"
                    "<entry><title>Video</title><id>1</id><updated>2024-01-01T00:00:00Z</updated></entry>"
                    "</feed>",
                    content_type="application/atom+xml",
                ),
            }
        )

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await discover_feed("https://www.youtube.com/watch?v=xyz789")

        assert result is not None
        assert "feeds/videos.xml" in result.url


# ---------------------------------------------------------------------------
# Tests: Invalid / unreachable URLs
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestDiscoverInvalidURLs:
    """Tests for error handling with invalid or unreachable URLs."""

    async def test_unreachable_url_connection_error(self):
        """A URL that causes a connection error should return None."""
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("Connection refused"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await discover_feed("https://unreachable.example.com/feed")

        assert result is None

    async def test_unreachable_url_timeout(self):
        """A URL that times out should return None."""
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.ReadTimeout("Request timed out"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await discover_feed("https://slow.example.com/feed")

        assert result is None

    async def test_url_returns_404(self):
        """A URL that returns HTTP 404 should return None."""
        mock_client = _mock_async_client(_mock_response("Not Found", content_type="text/html", status_code=404))

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await discover_feed("https://example.com/nonexistent")

        assert result is None

    async def test_url_returns_500(self):
        """A URL that returns HTTP 500 should return None."""
        mock_client = _mock_async_client(
            _mock_response("Internal Server Error", content_type="text/html", status_code=500)
        )

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await discover_feed("https://example.com/error")

        assert result is None

    async def test_url_returns_403(self):
        """A URL that returns HTTP 403 Forbidden should return None."""
        mock_client = _mock_async_client(_mock_response("Forbidden", content_type="text/html", status_code=403))

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await discover_feed("https://example.com/private")

        assert result is None

    async def test_dns_resolution_error(self):
        """A URL with DNS resolution failure should return None."""
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("Name or service not known"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await discover_feed("https://this-domain-does-not-exist.invalid/feed")

        assert result is None


# ---------------------------------------------------------------------------
# Tests: Pages with no feed links
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestDiscoverNoFeeds:
    """Tests for pages that do not contain any discoverable feed links."""

    async def test_html_page_no_feed_links(self):
        """An HTML page with no feed <link> tags should return None."""
        mock_client = _mock_async_client(_mock_response(HTML_NO_FEEDS, content_type="text/html"))

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await discover_feed("https://example.com/no-feeds")

        assert result is None

    async def test_empty_response_body(self):
        """An empty response body should return None."""
        mock_client = _mock_async_client(_mock_response("", content_type="text/html"))

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await discover_feed("https://example.com/empty")

        assert result is None

    async def test_json_api_response(self):
        """A JSON API response should not be mistaken for a feed."""
        mock_client = _mock_async_client(
            _mock_response('{"status": "ok", "data": []}', content_type="application/json")
        )

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await discover_feed("https://api.example.com/v1/status")

        assert result is None

    async def test_plain_text_response(self):
        """A plain text response with no XML should return None."""
        mock_client = _mock_async_client(_mock_response("Hello, this is just plain text.", content_type="text/plain"))

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await discover_feed("https://example.com/readme.txt")

        assert result is None

    async def test_html_with_non_feed_link_tags(self):
        """HTML with <link> tags for stylesheets (not feeds) should return None."""
        html = """\
<!DOCTYPE html>
<html>
<head>
  <link rel="stylesheet" type="text/css" href="/styles.css"/>
  <link rel="icon" type="image/x-icon" href="/favicon.ico"/>
</head>
<body><p>No feeds.</p></body>
</html>
"""
        mock_client = _mock_async_client(_mock_response(html, content_type="text/html"))

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await discover_feed("https://example.com/styled-page")

        assert result is None


# ---------------------------------------------------------------------------
# Tests: Edge cases
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestDiscoverEdgeCases:
    """Edge case tests for feed discovery."""

    async def test_feed_with_whitespace_before_xml_declaration(self):
        """A feed with leading whitespace before <?xml should still be detected."""
        rss_with_whitespace = "\n  \n" + SAMPLE_RSS
        mock_client = _mock_async_client(_mock_response(rss_with_whitespace, content_type="text/plain"))

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await discover_feed("https://example.com/whitespace-feed")

        # .strip() is called on the text, so the <?xml should be found
        assert result is not None
        assert result.title == "Security Blog"

    async def test_result_has_correct_schema_fields(self):
        """Verify that the returned FeedDiscoverResult has all expected fields."""
        mock_client = _mock_async_client(_mock_response(SAMPLE_RSS, content_type="application/rss+xml"))

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await discover_feed("https://example.com/feed.xml")

        assert result is not None
        # All four fields from FeedDiscoverResult should be present
        assert hasattr(result, "url")
        assert hasattr(result, "title")
        assert hasattr(result, "feed_type")
        assert hasattr(result, "description")
        assert isinstance(result.url, str)
        assert isinstance(result.title, str)
        assert isinstance(result.feed_type, str)

    async def test_youtube_channel_url_with_trailing_slash(self):
        """A YouTube /channel/ URL with a trailing slash should still match."""
        mock_client = _mock_async_client(_mock_response(YOUTUBE_CHANNEL_PAGE, content_type="text/html"))

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await discover_feed("https://www.youtube.com/channel/UC1234567890abcdef/")

        assert result is not None
        assert result.feed_type == "youtube"

    async def test_discover_feed_description_none_when_absent(self):
        """When a feed has no description, the result's description should be None."""
        rss_no_desc = """\
<?xml version="1.0"?>
<rss version="2.0">
  <channel>
    <title>No Description Feed</title>
    <link>https://example.com</link>
    <item>
      <title>Entry</title>
      <link>https://example.com/1</link>
      <guid>1</guid>
    </item>
  </channel>
</rss>
"""
        mock_client = _mock_async_client(_mock_response(rss_no_desc, content_type="application/rss+xml"))

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await discover_feed("https://example.com/nodesc.xml")

        assert result is not None
        assert result.title == "No Description Feed"
        assert result.description is None

    async def test_discover_youtube_description_is_none(self):
        """YouTube discovery results always have description=None."""
        mock_client = _mock_async_client(_mock_response(YOUTUBE_CHANNEL_PAGE, content_type="text/html"))

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await discover_feed("https://www.youtube.com/channel/UC1234567890abcdef")

        assert result is not None
        assert result.description is None


# ---------------------------------------------------------------------------
# extract_feed_links (RSS/Atom autodiscovery parser)
# ---------------------------------------------------------------------------


class TestExtractFeedLinks:
    def test_extracts_absolute_rss_link(self):
        html = (
            "<html><head>"
            '<link rel="alternate" type="application/rss+xml" href="https://example.com/feed.xml"/>'
            "</head><body></body></html>"
        )
        assert extract_feed_links(html, "https://example.com/") == ["https://example.com/feed.xml"]

    def test_resolves_relative_href_against_base(self):
        html = '<link rel="alternate" type="application/atom+xml" href="/atom.xml">'
        assert extract_feed_links(html, "https://blog.example.com/posts/") == ["https://blog.example.com/atom.xml"]

    def test_attribute_order_independent(self):
        html = '<link href="/rss/" type="application/rss+xml" rel="alternate" title="RSS">'
        assert extract_feed_links(html, "https://blog.google/threat-analysis-group/") == ["https://blog.google/rss/"]

    def test_single_quoted_and_unquoted_attributes(self):
        html = (
            "<link rel='alternate' type='application/rss+xml' href='/feed1'>"
            "<link rel=alternate type=application/rss+xml href=/feed2>"
        )
        assert extract_feed_links(html, "https://example.com") == [
            "https://example.com/feed1",
            "https://example.com/feed2",
        ]

    def test_ignores_non_feed_links(self):
        html = (
            '<link rel="stylesheet" type="text/css" href="/style.css">'
            '<link rel="alternate" type="application/json" href="/feed.json">'
            '<link rel="icon" href="/favicon.ico">'
        )
        assert extract_feed_links(html, "https://example.com") == []

    def test_deduplicates_and_preserves_document_order(self):
        html = (
            '<link rel="alternate" type="application/rss+xml" href="/a.xml">'
            '<link rel="alternate" type="application/atom+xml" href="/b.xml">'
            '<link rel="alternate" type="application/rss+xml" href="/a.xml">'
        )
        assert extract_feed_links(html, "https://example.com") == [
            "https://example.com/a.xml",
            "https://example.com/b.xml",
        ]

    def test_skips_empty_and_non_http_hrefs(self):
        html = (
            '<link rel="alternate" type="application/rss+xml" href="">'
            '<link rel="alternate" type="application/rss+xml" href="ftp://example.com/feed">'
        )
        assert extract_feed_links(html, "https://example.com") == []
