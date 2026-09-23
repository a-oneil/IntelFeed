import re
from urllib.parse import urljoin

import feedparser
import httpx

from app.config import settings
from app.schemas.feed import FeedDiscoverResult

FEED_LINK_RE = re.compile(
    r'<link[^>]+type="application/(rss|atom)\+xml"[^>]+href="([^"]+)"',
    re.IGNORECASE,
)

# Attribute-order-independent <link> tag parsing for RSS/Atom autodiscovery
_LINK_TAG_RE = re.compile(r"<link\b[^>]*>", re.IGNORECASE)
_ATTR_RE = re.compile(r"""([a-zA-Z-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""")
_FEED_MIME_TYPES = frozenset({"application/rss+xml", "application/atom+xml"})


def extract_feed_links(html: str, base_url: str) -> list[str]:
    """Extract RSS/Atom autodiscovery URLs from an HTML page.

    Parses ``<link rel="alternate" type="application/rss+xml|atom+xml" href=...>``
    tags regardless of attribute order, resolves relative hrefs against
    ``base_url``, and returns absolute URLs in document order (deduplicated).
    """
    candidates: list[str] = []
    seen: set[str] = set()
    for tag in _LINK_TAG_RE.findall(html):
        attrs = {m.group(1).lower(): (m.group(2) or m.group(3) or m.group(4) or "") for m in _ATTR_RE.finditer(tag)}
        if "alternate" not in attrs.get("rel", "").lower():
            continue
        if attrs.get("type", "").lower().strip() not in _FEED_MIME_TYPES:
            continue
        href = attrs.get("href", "").strip()
        if not href:
            continue
        absolute = urljoin(base_url, href)
        if not absolute.lower().startswith(("http://", "https://")):
            continue
        if absolute not in seen:
            seen.add(absolute)
            candidates.append(absolute)
    return candidates


YOUTUBE_CHANNEL_RE = re.compile(r"youtube\.com/(?:channel|c|@|user)/([^/?\s]+)")
YOUTUBE_FEED_RE = re.compile(r"youtube\.com/feeds/videos\.xml\?channel_id=([^&\s]+)")
YOUTUBE_FEED_TEMPLATE = "https://www.youtube.com/feeds/videos.xml?channel_id={}"


async def discover_feed(url: str) -> FeedDiscoverResult | None:
    """Discover a feed from a URL. Returns the best candidate or None."""
    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=15.0,
        headers={"User-Agent": settings.user_agent},
    ) as client:
        # Check if it's a YouTube feed XML URL (already resolved)
        yt_feed_match = YOUTUBE_FEED_RE.search(url)
        if yt_feed_match:
            return await _discover_youtube_feed(client, url, yt_feed_match.group(1))

        # Check if it's a YouTube channel URL
        yt_match = YOUTUBE_CHANNEL_RE.search(url)
        if yt_match:
            return await _discover_youtube(client, url)

        try:
            response = await client.get(url)
            response.raise_for_status()
        except httpx.HTTPError:
            return None

        content_type = response.headers.get("content-type", "")

        # Check if it's directly a feed
        if any(ct in content_type for ct in ["xml", "rss", "atom"]):
            return _parse_feed(url, response.text)

        # Check if the content looks like XML
        text = response.text.strip()
        if text.startswith("<?xml") or text.startswith("<rss") or text.startswith("<feed"):
            return _parse_feed(url, text)

        # HTML page — look for feed links
        links = FEED_LINK_RE.findall(response.text)
        if links:
            feed_type, feed_url = links[0]
            # Handle relative URLs
            if feed_url.startswith("/"):
                from urllib.parse import urlparse

                parsed = urlparse(url)
                feed_url = f"{parsed.scheme}://{parsed.netloc}{feed_url}"

            try:
                feed_response = await client.get(feed_url)
                feed_response.raise_for_status()
                return _parse_feed(feed_url, feed_response.text)
            except httpx.HTTPError:
                return None

    return None


async def _discover_youtube_feed(client: httpx.AsyncClient, url: str, channel_id: str) -> FeedDiscoverResult | None:
    """Discover a YouTube feed from a direct XML feed URL.

    YouTube returns 404 status for valid feed XML, so we check content instead.
    """
    try:
        response = await client.get(url)
    except httpx.HTTPError:
        return None

    text = response.text.strip()
    if text.startswith("<?xml") or text.startswith("<feed"):
        parsed = feedparser.parse(text)
        title = parsed.feed.get("title") or f"YouTube: {channel_id}"
        return FeedDiscoverResult(
            url=url,
            title=title,
            feed_type="youtube",
            description=None,
        )
    return None


async def _discover_youtube(client: httpx.AsyncClient, url: str) -> FeedDiscoverResult | None:
    """Discover YouTube channel feed."""
    try:
        response = await client.get(url)
        response.raise_for_status()

        # Prefer the RSS <link> tag — gives us the feed URL directly
        rss_match = re.search(
            r'<link[^>]+type="application/rss\+xml"[^>]+href="([^"]+)"',
            response.text,
        )
        if rss_match:
            feed_url = rss_match.group(1)
        else:
            # Fallback: externalId is the channel's own ID (channelId can match
            # embedded/recommended content)
            channel_id_match = re.search(r'"externalId":"([^"]+)"', response.text)
            if not channel_id_match:
                channel_id_match = re.search(r'"browseId":"(UC[^"]+)"', response.text)
            if not channel_id_match:
                return None
            feed_url = YOUTUBE_FEED_TEMPLATE.format(channel_id_match.group(1))

        # Get channel title
        title_match = re.search(r'<meta property="og:title" content="([^"]+)"', response.text)
        title = title_match.group(1) if title_match else feed_url

        return FeedDiscoverResult(
            url=feed_url,
            title=title,
            feed_type="youtube",
            description=None,
        )
    except httpx.HTTPError:
        return None


def _parse_feed(url: str, content: str) -> FeedDiscoverResult | None:
    """Parse feed content and return discovery result."""
    parsed = feedparser.parse(content)
    if parsed.bozo and not parsed.entries:
        return None

    from app.adapters.base import BaseAdapter

    feed_type = BaseAdapter.detect_feed_type(url, content)

    return FeedDiscoverResult(
        url=url,
        title=parsed.feed.get("title"),
        feed_type=feed_type,
        description=parsed.feed.get("description") or parsed.feed.get("subtitle"),
    )
