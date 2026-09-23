"""Web scraper adapter — discovers and extracts articles from blog pages without RSS feeds."""

import asyncio
import hashlib
import logging
import re
from datetime import UTC, datetime
from urllib.parse import urljoin, urlparse

import httpx
from lxml import html as lxml_html

from app.adapters.base import ExtendedAdapter, ParsedEntry, ParsedFeedMeta
from app.config import settings

logger = logging.getLogger(__name__)

# Paths that are almost never articles
_SKIP_PATH_PATTERNS = re.compile(
    r"/(login|signup|register|signin|auth|account|cart|checkout|privacy|terms|"
    r"contact|about|faq|help|search|tags?|categor|authors?|page/\d+|feed|rss|atom|sitemap)",
    re.IGNORECASE,
)

_SKIP_EXTENSIONS = re.compile(r"\.(png|jpe?g|gif|svg|webp|ico|pdf|zip|tar|gz|mp[34]|wav|css|js)$", re.IGNORECASE)

# Index paths that are archives/taxonomies/pagination rather than a blog root —
# their path is NOT a useful prefix for filtering article URLs, because articles
# linked from them typically live elsewhere (e.g. root permalinks on WordPress).
_ARCHIVE_INDEX_RE = re.compile(
    r"(^|/)(category|categories|tag|tags|author|authors|archive|archives|topic|topics|section|sections|page/\d+)(/|$)",
    re.IGNORECASE,
)

# Meta tag patterns
_OG_TITLE_RE = re.compile(r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\']([^"\']+)["\']', re.I)
_OG_TITLE_RE_ALT = re.compile(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+property=["\']og:title["\']', re.I)
_OG_DESC_RE = re.compile(r'<meta[^>]+property=["\']og:description["\'][^>]+content=["\']([^"\']+)["\']', re.I)
_OG_DESC_RE_ALT = re.compile(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+property=["\']og:description["\']', re.I)
_OG_IMAGE_RE = re.compile(r'<meta[^>]+property=["\']og:image["\'][^>]+content=["\']([^"\']+)["\']', re.I)
_OG_IMAGE_RE_ALT = re.compile(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+property=["\']og:image["\']', re.I)
_META_AUTHOR_RE = re.compile(r'<meta[^>]+name=["\']author["\'][^>]+content=["\']([^"\']+)["\']', re.I)
_META_DESC_RE = re.compile(r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)["\']', re.I)
_ARTICLE_TIME_RE = re.compile(
    r'<meta[^>]+property=["\']article:published_time["\'][^>]+content=["\']([^"\']+)["\']',
    re.I,
)
_ARTICLE_TIME_RE_ALT = re.compile(
    r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+property=["\']article:published_time["\']',
    re.I,
)
_TIME_DATETIME_RE = re.compile(r'<time[^>]+datetime=["\']([^"\']+)["\']', re.I)
_JSON_LD_RE = re.compile(r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>', re.I | re.DOTALL)

# CSS selectors for article containers (ordered by specificity)
_ARTICLE_CONTENT_SELECTORS = [
    "div.article-body",
    "div.entry-content",
    "div.post-content",
    "div.story-body",
    "article .content",
]

# Selectors for finding article links on index pages
_INDEX_LINK_SELECTORS = [
    "article a[href]",
    "main a[href]",
    ".post a[href]",
    ".posts a[href]",
    ".blog-posts a[href]",
    ".blog-list a[href]",
    ".post-list a[href]",
    ".article-list a[href]",
    ".entries a[href]",
    ".card a[href]",
]

# Pagination selectors
_DEFAULT_PAGINATION_SELECTORS = "a[rel='next'], a.next, a.pagination-next, a.page-next, li.next a"


class WebScraperAdapter(ExtendedAdapter):
    """Scrapes blog index pages to discover and ingest articles."""

    async def fetch_entries(
        self, config: dict, since: datetime | None = None
    ) -> tuple[ParsedFeedMeta, list[ParsedEntry]]:
        blog_url = config.get("blog_url", "")
        if not blog_url:
            return ParsedFeedMeta(), []

        link_selector = config.get("link_selector")
        url_pattern = config.get("url_pattern")
        max_articles = min(config.get("max_articles", 20), 100)
        follow_pagination = config.get("follow_pagination", False)
        pagination_selector = config.get("pagination_selector", _DEFAULT_PAGINATION_SELECTORS)
        max_pages = min(config.get("max_pages", 3), 10)

        parsed_base = urlparse(blog_url)
        base_domain = parsed_base.netloc

        # Discover article links from index page(s)
        all_links: list[str] = []
        visited_pages: set[str] = set()
        pages_to_visit = [blog_url]

        for page_num in range(max_pages if follow_pagination else 1):
            if not pages_to_visit:
                break

            page_url = pages_to_visit.pop(0)
            if page_url in visited_pages:
                break
            visited_pages.add(page_url)

            page_html = await self._fetch_page(page_url)
            if not page_html:
                if page_num == 0:
                    raise RuntimeError(f"Failed to fetch index page: {blog_url}")
                break

            links = self._discover_links(page_html, page_url, base_domain, link_selector, url_pattern)
            all_links.extend(link for link in links if link not in set(all_links))

            # Find next page link if paginating
            if follow_pagination and page_num < max_pages - 1:
                next_url = self._find_next_page(page_html, page_url, pagination_selector)
                if next_url and next_url not in visited_pages:
                    pages_to_visit.append(next_url)

        # Cap articles
        all_links = all_links[:max_articles]

        if not all_links:
            logger.debug(f"No article links discovered on {blog_url}")
            meta = self._build_meta(config)
            return meta, []

        # Fetch and extract articles concurrently with rate limiting
        semaphore = asyncio.Semaphore(3)
        entries: list[ParsedEntry] = []

        async def process_article(url: str) -> ParsedEntry | None:
            async with semaphore:
                return await self._extract_article(url, config)

        tasks = [process_article(url) for url in all_links]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, ParsedEntry):
                entries.append(result)
            elif isinstance(result, Exception):
                logger.debug(f"Article extraction failed: {result}")

        meta = self._build_meta(config)
        return meta, entries

    def get_feed_meta(self, config: dict) -> ParsedFeedMeta:
        return self._build_meta(config)

    def _build_meta(self, config: dict) -> ParsedFeedMeta:
        blog_url = config.get("blog_url", "")
        try:
            domain = urlparse(blog_url).netloc
        except Exception:
            domain = blog_url
        return ParsedFeedMeta(
            title=f"{domain} (scraped)",
            description=f"Articles scraped from {blog_url}",
            site_url=blog_url,
        )

    async def _fetch_page(self, url: str) -> str | None:
        """Fetch a page's HTML, with curl_cffi fallback for bot protection."""
        from app.services.rate_limiter import acquire_rate_limit
        from app.services.robots import can_fetch, get_crawl_delay

        if not await can_fetch(url):
            logger.debug(f"robots.txt disallows {url}")
            return None

        crawl_delay = await get_crawl_delay(url)
        if not await acquire_rate_limit(url, min_interval=crawl_delay):
            logger.debug(f"Rate limit not acquired for {url}")
            return None

        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=20.0,
                headers={"User-Agent": settings.user_agent},
            ) as client:
                response = await client.get(url)
                content_type = response.headers.get("content-type", "")

                if response.status_code == 200 and "html" in content_type:
                    return response.text

                if response.status_code in (403, 429, 503):
                    pass  # Fall through to curl_cffi

            # Fallback to curl_cffi for bot protection
            try:
                from curl_cffi import requests as cffi_requests

                resp = cffi_requests.get(url, impersonate="chrome", timeout=20)
                if resp.status_code == 200 and "html" in resp.headers.get("content-type", ""):
                    return resp.text
            except Exception as e:
                logger.debug(f"curl_cffi fallback failed for {url}: {e}")

        except Exception as e:
            logger.warning(f"Failed to fetch {url}: {e}")

        return None

    def _discover_links(
        self,
        html: str,
        page_url: str,
        base_domain: str,
        link_selector: str | None,
        url_pattern: str | None,
    ) -> list[str]:
        """Discover article links from an index page."""
        try:
            tree = lxml_html.fromstring(html)
        except Exception:
            return []

        hrefs: list[str] = []

        if link_selector:
            # User-provided CSS selector
            for sel in link_selector.split(","):
                sel = sel.strip()
                if not sel:
                    continue
                try:
                    elements = tree.cssselect(sel)
                    for el in elements:
                        href = el.get("href")
                        if href:
                            hrefs.append(href)
                except Exception:
                    logger.debug(f"Invalid CSS selector: {sel}")
        else:
            # Auto-detect article links
            hrefs = self._auto_detect_links(tree)

        # Normalize, filter, and deduplicate
        seen: set[str] = set()
        result: list[str] = []

        # If no explicit url_pattern, derive one from the blog_url path.
        # e.g. https://panther.com/blog → only keep links under /blog/
        compiled_pattern = None
        if url_pattern:
            try:
                compiled_pattern = re.compile(url_pattern)
            except re.error:
                logger.warning(f"Invalid URL pattern regex: {url_pattern}")
        else:
            index_path = urlparse(page_url).path.rstrip("/")
            if index_path and index_path != "/" and not _ARCHIVE_INDEX_RE.search(index_path):
                try:
                    compiled_pattern = re.compile(f"^{re.escape(index_path)}/.")
                except re.error:
                    pass

        for href in hrefs:
            # Skip empty, fragment-only, javascript, and mailto links
            if not href or href.startswith(("#", "javascript:", "mailto:")):
                continue

            # Resolve relative URL
            absolute = urljoin(page_url, href)
            parsed = urlparse(absolute)

            # Strip fragment
            clean_url = parsed._replace(fragment="").geturl()

            # Skip if already seen
            if clean_url in seen:
                continue

            # Skip external domains
            if parsed.netloc and parsed.netloc != base_domain:
                continue

            # Skip non-article paths
            if _SKIP_PATH_PATTERNS.search(parsed.path):
                continue

            # Skip file extensions
            if _SKIP_EXTENSIONS.search(parsed.path):
                continue

            # Skip the index page itself
            if clean_url.rstrip("/") == page_url.rstrip("/"):
                continue

            # Apply URL pattern filter
            if compiled_pattern and not compiled_pattern.search(parsed.path):
                continue

            seen.add(clean_url)
            result.append(clean_url)

        return result

    def _auto_detect_links(self, tree) -> list[str]:
        """Heuristic link discovery when no CSS selector is provided."""
        hrefs: list[str] = []

        # Try structured selectors in order of specificity
        for selector in _INDEX_LINK_SELECTORS:
            try:
                elements = tree.cssselect(selector)
                if elements:
                    for el in elements:
                        href = el.get("href")
                        if href:
                            hrefs.append(href)
            except Exception:
                continue

        # If we found links in structured containers, return them
        if hrefs:
            return hrefs

        # Fallback: links inside headings (h1-h3) — strong article signal
        for tag in ("h1", "h2", "h3"):
            try:
                headings = tree.cssselect(tag)
                for h in headings:
                    for a in h.cssselect("a[href]"):
                        href = a.get("href")
                        if href:
                            hrefs.append(href)
            except Exception:
                continue

        if hrefs:
            return hrefs

        # Last resort: collect all <a> links on the page.
        # The URL filtering in _discover_links will remove non-article links.
        try:
            for a in tree.cssselect("a[href]"):
                href = a.get("href")
                if href:
                    hrefs.append(href)
        except Exception:
            pass

        return hrefs

    def _find_next_page(self, html: str, page_url: str, pagination_selector: str) -> str | None:
        """Find the next page link for pagination."""
        try:
            tree = lxml_html.fromstring(html)
        except Exception:
            return None

        for sel in pagination_selector.split(","):
            sel = sel.strip()
            if not sel:
                continue
            try:
                elements = tree.cssselect(sel)
                for el in elements:
                    href = el.get("href")
                    if href:
                        absolute = urljoin(page_url, href)
                        if absolute.rstrip("/") != page_url.rstrip("/"):
                            return absolute
            except Exception:
                continue

        return None

    async def _extract_article(self, url: str, config: dict) -> ParsedEntry | None:
        """Fetch and extract content from a single article page."""
        raw_html = await self._fetch_page(url)
        if not raw_html:
            return None

        # Extract metadata from HTML
        title = self._extract_title(raw_html)
        author = self._extract_author(raw_html)
        published_at = self._extract_date(raw_html)
        image_url = self._extract_og_image(raw_html)
        summary = self._extract_description(raw_html)

        # Extract article content
        content_html = self._extract_content(raw_html)

        if not title:
            title = url.split("/")[-1].replace("-", " ").replace("_", " ").title() or "Untitled"

        guid = hashlib.sha256(url.encode()).hexdigest()[:32]

        return ParsedEntry(
            guid=guid,
            url=url,
            title=title,
            author=author,
            content_html=content_html,
            summary=summary,
            published_at=published_at,
            metadata={
                "source": "web_scraper",
                "blog_url": config.get("blog_url", ""),
                "image_url": image_url,
            },
        )

    def _extract_content(self, raw_html: str) -> str | None:
        """Extract article content using readability with CSS selector fallback."""
        try:
            from readability import Document

            doc = Document(raw_html)
            content = doc.summary()
            if content:
                # Check if we got meaningful content
                from app.services.sanitizer import html_to_text

                plain = html_to_text(content)
                if len(plain) > 100:
                    return content
        except Exception as e:
            logger.debug(f"Readability extraction failed: {e}")

        # CSS selector fallback
        try:
            import lxml.etree as etree

            tree = lxml_html.fromstring(raw_html)
            for selector in _ARTICLE_CONTENT_SELECTORS:
                elements = tree.cssselect(selector)
                if elements:
                    content = etree.tostring(elements[0], encoding="unicode", method="html")
                    if content and len(content) > 200:
                        return content
        except Exception:
            pass

        # Return readability output even if short
        try:
            from readability import Document

            doc = Document(raw_html)
            return doc.summary()
        except Exception:
            return None

    def _strip_site_suffix(self, title: str) -> str:
        """Strip common site name suffixes like ' | SiteName' or ' - SiteName'."""
        for sep in (" | ", " - ", " – ", " — "):
            if sep in title:
                title = title.split(sep)[0].strip()
        return title

    def _extract_title(self, html: str) -> str | None:
        """Extract article title from meta tags or HTML."""
        # og:title (often includes site suffix, so strip it)
        m = _OG_TITLE_RE.search(html) or _OG_TITLE_RE_ALT.search(html)
        if m:
            return self._strip_site_suffix(m.group(1).strip())

        try:
            tree = lxml_html.fromstring(html)
        except Exception:
            tree = None

        # Article-scoped title selectors. Checked before the bare <h1> below
        # because many themes (WordPress especially) put the site name in an
        # <h1 class="site-title">, which would otherwise hijack the title.
        if tree is not None:
            for selector in (
                "h1.entry-title",
                ".entry-title",
                "h1.post-title",
                ".post-title",
                "article h1",
                "main h1",
            ):
                try:
                    for el in tree.cssselect(selector):
                        text = el.text_content().strip()
                        if text and len(text) < 300:
                            return text
                except Exception:
                    continue

        # <title> tag (strip site suffix)
        title_match = re.search(r"<title[^>]*>([^<]+)</title>", html, re.I)
        if title_match:
            return self._strip_site_suffix(title_match.group(1).strip())

        # Bare <h1> as last resort (may be the site logo on some themes)
        if tree is not None:
            try:
                h1s = tree.cssselect("h1")
                if h1s:
                    text = h1s[0].text_content().strip()
                    if text and len(text) < 300:
                        return text
            except Exception:
                pass

        return None

    def _extract_author(self, html: str) -> str | None:
        """Extract author from meta tags or JSON-LD."""
        m = _META_AUTHOR_RE.search(html)
        if m:
            return m.group(1).strip()

        # JSON-LD author
        for ld_match in _JSON_LD_RE.finditer(html):
            try:
                import json

                data = json.loads(ld_match.group(1))
                if isinstance(data, list):
                    data = data[0] if data else {}
                author = data.get("author")
                if isinstance(author, dict):
                    return author.get("name")
                elif isinstance(author, list) and author:
                    a = author[0]
                    return a.get("name") if isinstance(a, dict) else str(a)
                elif isinstance(author, str):
                    return author
            except Exception:
                continue

        return None

    def _extract_date(self, html: str) -> datetime | None:
        """Extract publish date from meta tags, time elements, or JSON-LD."""
        # article:published_time meta tag
        m = _ARTICLE_TIME_RE.search(html) or _ARTICLE_TIME_RE_ALT.search(html)
        if m:
            return self._parse_datetime(m.group(1))

        # <time datetime="..."> element
        m = _TIME_DATETIME_RE.search(html)
        if m:
            return self._parse_datetime(m.group(1))

        # JSON-LD datePublished
        for ld_match in _JSON_LD_RE.finditer(html):
            try:
                import json

                data = json.loads(ld_match.group(1))
                if isinstance(data, list):
                    data = data[0] if data else {}
                date_str = data.get("datePublished")
                if date_str:
                    return self._parse_datetime(date_str)
            except Exception:
                continue

        return None

    def _parse_datetime(self, date_str: str) -> datetime | None:
        """Parse an ISO 8601 date string."""
        try:
            dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            return dt
        except ValueError:
            return None

    def _extract_og_image(self, html: str) -> str | None:
        m = _OG_IMAGE_RE.search(html) or _OG_IMAGE_RE_ALT.search(html)
        return m.group(1).strip() if m else None

    def _extract_description(self, html: str) -> str | None:
        m = _OG_DESC_RE.search(html) or _OG_DESC_RE_ALT.search(html)
        if m:
            return m.group(1).strip()
        m = _META_DESC_RE.search(html)
        return m.group(1).strip() if m else None
