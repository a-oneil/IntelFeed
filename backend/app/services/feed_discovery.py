import asyncio
import re
from urllib.parse import urljoin, urlsplit

import feedparser
import httpx

from app.config import settings
from app.core.safe_http import safe_async_client
from app.schemas.feed import FeedDiscoverResult

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


# Where a site that doesn't advertise its feed usually keeps it: WordPress,
# Ghost, Substack (/feed), Hugo (/index.xml), Jekyll (/feed.xml), Blogger.
COMMON_FEED_PATHS = (
    "/feed",
    "/rss",
    "/feed.xml",
    "/rss.xml",
    "/atom.xml",
    "/index.xml",
    "/feed/atom",
    "/feeds/posts/default",
)


# Content types a feed is served with. Not a bare "xml": application/xhtml+xml
# is an HTML page.
_FEED_CONTENT_TYPES = ("rss", "atom", "application/xml", "text/xml")


def _looks_like_feed(content_type: str, text: str) -> bool:
    """True when the response's content type or its first characters say it is RSS/Atom."""
    content_type = content_type.lower()
    head = text.lstrip()[:200].lower()
    return any(ct in content_type for ct in _FEED_CONTENT_TYPES) or head.startswith(("<?xml", "<rss", "<feed"))


async def _probe_common_paths(client: httpx.AsyncClient, url: str) -> FeedDiscoverResult | None:
    """The first of COMMON_FEED_PATHS on the page's site that answers with a feed."""
    parts = urlsplit(url)
    origin = f"{parts.scheme}://{parts.netloc}"

    async def probe(path: str) -> FeedDiscoverResult | None:
        candidate = origin + path
        try:
            response = await client.get(candidate, timeout=8.0)
        except httpx.HTTPError:
            return None
        if response.status_code != 200:
            return None
        if not _looks_like_feed(response.headers.get("content-type", ""), response.text):
            return None
        return _parse_feed(candidate, response.text)

    results = await asyncio.gather(*(probe(path) for path in COMMON_FEED_PATHS))
    return next((r for r in results if r), None)


# /channel/ID, /c/name, /user/name, and the handle form /@name (no slash after @)
YOUTUBE_CHANNEL_RE = re.compile(r"youtube\.com/(?:(?:channel|c|user)/|@)([^/?\s]+)")
YOUTUBE_FEED_RE = re.compile(r"youtube\.com/feeds/videos\.xml\?channel_id=([^&\s]+)")
YOUTUBE_FEED_TEMPLATE = "https://www.youtube.com/feeds/videos.xml?channel_id={}"

# From an EU address (prod's IP geolocates to France) YouTube redirects every
# page to consent.youtube.com, which has no feed link and no channel ID.
# SOCS=CAI is the cookie YouTube sets when consent is declined, so the real
# page comes back. Scoped to youtube.com: no other site receives it.
YOUTUBE_CONSENT_COOKIE = ("SOCS", "CAI")


def _discovery_cookies() -> httpx.Cookies:
    cookies = httpx.Cookies()
    name, value = YOUTUBE_CONSENT_COOKIE
    cookies.set(name, value, domain=".youtube.com")
    return cookies


# How many of a page's advertised feeds discovery fetches. A blog advertises
# posts and comments; a news site may list one per section.
MAX_FEED_OPTIONS = 6


async def discover_feed(url: str) -> FeedDiscoverResult | None:
    """Discover a feed from a URL. Returns the best candidate or None."""
    feeds, _ = await discover_feeds(url)
    return feeds[0] if feeds else None


async def discover_feeds(url: str) -> tuple[list[FeedDiscoverResult], str | None]:
    """Every feed a URL leads to, best first, plus the page HTML when it is a page.

    The HTML comes back so a caller that finds no feed can look at the page
    itself (the web scraper's link count) without fetching it twice.
    """
    async with safe_async_client(
        follow_redirects=True,
        timeout=15.0,
        headers={"User-Agent": str(settings.get("user_agent") or settings.user_agent)},
        cookies=_discovery_cookies(),
    ) as client:
        # Check if it's a YouTube feed XML URL (already resolved)
        yt_feed_match = YOUTUBE_FEED_RE.search(url)
        if yt_feed_match:
            found = await _discover_youtube_feed(client, url, yt_feed_match.group(1))
            return ([found] if found else []), None

        # Check if it's a YouTube channel URL
        yt_match = YOUTUBE_CHANNEL_RE.search(url)
        if yt_match:
            found = await _discover_youtube(client, url)
            return ([found] if found else []), None

        try:
            response = await client.get(url)
            response.raise_for_status()
        except httpx.HTTPError:
            return [], None

        # The URL is a feed itself
        if _looks_like_feed(response.headers.get("content-type", ""), response.text):
            found = _parse_feed(url, response.text.strip())
            return ([found] if found else []), None

        # HTML page — look for feed links
        page_html = response.text
        links = extract_feed_links(page_html, url)[:MAX_FEED_OPTIONS]
        if links:

            async def fetch(feed_url: str) -> FeedDiscoverResult | None:
                try:
                    feed_response = await client.get(feed_url)
                    feed_response.raise_for_status()
                except httpx.HTTPError:
                    return None
                return _parse_feed(feed_url, feed_response.text)

            results = await asyncio.gather(*(fetch(link) for link in links))
            return [r for r in results if r], page_html

        # No advertised feed: try the addresses sites usually keep one at
        found = await _probe_common_paths(client, url)
        return ([found] if found else []), page_html


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
