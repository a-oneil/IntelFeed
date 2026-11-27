"""The Manual Uploads feed and the single-item ingest paths.

Bulk ingest (services/ingest_batches.py) builds on the same three pieces this
module owns: the singleton ``manual://uploads`` feed, ``fetch_url_document``
(fetch + readability + sanitize, no database), and ``create_manual_entry``
(dedup by GUID, then one ordinary Entry row). ``ingest_url`` (used by
``POST /ingest/url``, the Android client and the ``ingest_url`` registry tool)
and ``ingest_page`` (the browser extension) each create one entry right away.
"""

import asyncio
import hashlib
import logging
import re
from datetime import UTC, datetime
from urllib.parse import urljoin, urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppError
from app.models.entry import Entry
from app.models.feed import Feed
from app.services.dedup import compute_content_hash
from app.services.ingest_parsers import ParsedDocument
from app.services.sanitizer import (
    extract_first_image,
    extract_og_image,
    html_to_text,
    sanitize_html,
)

logger = logging.getLogger(__name__)

MANUAL_FEED_URL = "manual://uploads"

_REL_SRC_RE = re.compile(r'(<(?:img|source|video|audio)\s[^>]*?)src="([^"]+)"', re.IGNORECASE)
_REL_HREF_RE = re.compile(r'(<a\s[^>]*?)href="([^"]+)"', re.IGNORECASE)


class DuplicateEntry(Exception):
    """The manual feed already holds this GUID. ``entry_id`` is the existing row."""

    def __init__(self, entry_id):
        super().__init__("already ingested")
        self.entry_id = entry_id


def _resolve_relative_urls(html: str, base_url: str) -> str:
    """Resolve relative src= and href= attributes to absolute URLs."""

    def resolve_src(match: re.Match) -> str:
        prefix = match.group(1)
        src = match.group(2)
        if src.startswith(("http://", "https://", "data:", "//")):
            return match.group(0)
        return f'{prefix}src="{urljoin(base_url, src)}"'

    def resolve_href(match: re.Match) -> str:
        prefix = match.group(1)
        href = match.group(2)
        if href.startswith(("http://", "https://", "mailto:", "data:", "//", "#")):
            return match.group(0)
        return f'{prefix}href="{urljoin(base_url, href)}"'

    html = _REL_SRC_RE.sub(resolve_src, html)
    html = _REL_HREF_RE.sub(resolve_href, html)
    return html


async def get_or_create_manual_feed(db: AsyncSession) -> Feed:
    """Get or create the singleton 'Manual Uploads' feed."""
    result = await db.execute(select(Feed).where(Feed.url == MANUAL_FEED_URL))
    feed = result.scalar_one_or_none()
    if feed:
        return feed

    feed = Feed(
        title="Manual Uploads",
        url=MANUAL_FEED_URL,
        feed_type="manual",
        is_active=False,  # poller should skip this feed
        intel_extraction_mode="full",
        auto_extract_on_ingest=True,
        extract_detection_rules=True,
        description="Manually ingested articles, files and pasted text",
    )
    db.add(feed)
    await db.flush()

    # System feed — visible to everyone
    from app.services.feed_visibility import subscribe_all_users

    await subscribe_all_users(db, feed.id)
    await db.flush()
    return feed


def url_guid(url: str) -> str:
    return f"manual:url:{hashlib.sha256(url.encode()).hexdigest()}"


def bytes_guid(data: bytes, *, kind: str = "file") -> str:
    """``manual:pdf:<sha256>`` for PDFs (the historical form, so re-uploading a
    PDF ingested before batches existed still reads as a duplicate),
    ``manual:file:<sha256>`` for everything else."""
    return f"manual:{kind}:{hashlib.sha256(data).hexdigest()}"


def validate_http_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise AppError(code="invalid_url", message="URL must use http or https", status_code=400)


async def fetch_url_document(url: str) -> ParsedDocument:
    """Fetch a page and reduce it to sanitized HTML + text. No database.

    Reuses the poller's readability extraction (bot-protection impersonation,
    robots.txt, Google News unwrapping); when that returns nothing, falls back
    to a plain fetch of the raw HTML, its title and og:image. Both paths go
    through the SSRF-vetted client.
    """
    validate_http_url(url)
    parsed = urlparse(url)

    from app.workers.feed_tasks import _extract_full_text

    content_html, og_image = await _extract_full_text(url)

    title = None
    if not content_html:
        from app.core.safe_http import safe_async_client

        try:
            async with safe_async_client(follow_redirects=True, timeout=15.0) as client:
                resp = await client.get(url)
                if resp.status_code == 200 and "html" in resp.headers.get("content-type", ""):
                    raw_html = resp.text
                    content_html = raw_html
                    if not og_image:
                        og_image = extract_og_image(raw_html)
                    title_match = re.search(r"<title[^>]*>([^<]+)</title>", raw_html, re.IGNORECASE)
                    if title_match:
                        title = title_match.group(1).strip()
        except Exception as e:
            logger.warning("Basic fetch failed for %s: %s", url, e)

    if not content_html:
        raise AppError(
            code="extraction_failed",
            message="Could not extract content from this URL",
            status_code=422,
        )

    content_html = _resolve_relative_urls(content_html, url)
    sanitized_html = sanitize_html(content_html)
    content_text = html_to_text(sanitized_html)

    if not title:
        h1_match = re.search(r"<h1[^>]*>([^<]+)</h1>", content_html, re.IGNORECASE)
        title = h1_match.group(1).strip() if h1_match else f"{parsed.netloc}{parsed.path}"

    image_url = extract_first_image(sanitized_html) if sanitized_html else None
    if not image_url:
        image_url = og_image

    return ParsedDocument(text=content_text, html=sanitized_html, title=title, meta={"image_url": image_url})


async def create_manual_entry(
    db: AsyncSession,
    *,
    guid: str,
    title: str,
    html: str | None,
    text: str | None,
    url: str | None = None,
    image_url: str | None = None,
    metadata: dict | None = None,
    author: str | None = None,
    published_at: datetime | None = None,
) -> Entry:
    """One ordinary entry on the manual feed. Raises DuplicateEntry on a known GUID."""
    feed = await get_or_create_manual_feed(db)
    existing = await db.execute(select(Entry.id).where(Entry.feed_id == feed.id, Entry.guid == guid))
    existing_id = existing.scalar_one_or_none()
    if existing_id:
        raise DuplicateEntry(existing_id)

    now = datetime.now(UTC)
    word_count = len(text.split()) if text else 0
    entry = Entry(
        feed_id=feed.id,
        guid=guid,
        url=url,
        title=(title or "Untitled")[:2000],
        author=author,
        content_html=html,
        content_text=text,
        published_at=published_at or now,
        fetched_at=now,
        word_count=word_count,
        content_hash=compute_content_hash(title, text),
        image_url=image_url,
        metadata_=metadata or {},
    )
    db.add(entry)
    await db.flush()
    return entry


def document_from_html(raw_html: str, url: str, title: str | None = None) -> ParsedDocument:
    """Extract the article from HTML the client sent and sanitize it, the same
    way as a fetched page. Client HTML is untrusted.

    CPU-bound on large pages: async callers run it with ``asyncio.to_thread``.
    """
    from app.workers.feed_tasks import _pick_article_content

    parsed = urlparse(url)
    og_image = extract_og_image(raw_html, base_url=url)
    content_html = _pick_article_content(raw_html, "medium.com" in parsed.netloc) or raw_html
    content_html = _resolve_relative_urls(content_html, url)
    sanitized_html = sanitize_html(content_html)
    content_text = html_to_text(sanitized_html)
    if not content_text or not content_text.strip():
        raise AppError(code="extraction_failed", message="The page has no readable text", status_code=422)

    if not title:
        title_match = re.search(r"<title[^>]*>([^<]+)</title>", raw_html, re.IGNORECASE)
        title = title_match.group(1).strip() if title_match else f"{parsed.netloc}{parsed.path}"
    image_url = extract_first_image(sanitized_html) or og_image
    return ParsedDocument(text=content_text, html=sanitized_html, title=title, meta={"image_url": image_url})


def strip_fragment(url: str) -> str:
    """The URL without its #fragment, so two links to one page match."""
    return url.split("#", 1)[0]


def normalize_page_url(url: str) -> str:
    """Check the URL is http(s) and drop its #fragment, so two sends of one page make one entry."""
    validate_http_url(url)
    return strip_fragment(url)


# Dates before 1995 or in the future are treated as wrong and dropped. This is
# stricter than real_date_or_none (app/adapters/base.py), which drops only the
# placeholder dates feeds write for "no date": the date tags on a web page are
# often template defaults, so anything before the web was in common use is
# not trusted.
_EARLIEST_PUBLISHED = datetime(1995, 1, 1, tzinfo=UTC)


def plausible_published_at(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    if not (_EARLIEST_PUBLISHED <= value <= datetime.now(UTC)):
        return None
    return value


async def find_entry_by_url(db: AsyncSession, url: str, user_id=None) -> Entry | None:
    """The newest entry the user can see whose URL is ``url`` (fragment ignored), on any feed."""
    from app.services.feed_visibility import subscriptions_enabled, visible_feed_ids_query

    url = strip_fragment(url)
    visible = visible_feed_ids_query(user_id, enabled=await subscriptions_enabled(db), include_muted=True)
    manual = select(Feed.id).where(Feed.url == MANUAL_FEED_URL)
    result = await db.execute(
        select(Entry)
        .where(Entry.url == url, Entry.feed_id.in_(visible.union(manual)))
        .order_by(Entry.fetched_at.desc().nulls_last())
        .limit(1)
    )
    return result.scalar_one_or_none()


async def ingest_page(
    db: AsyncSession,
    *,
    url: str,
    user_id,
    html: str | None = None,
    title: str | None = None,
    selection: str | None = None,
    published_at: datetime | None = None,
    author: str | None = None,
    client: str | None = None,
) -> tuple[Entry, bool]:
    """Create an entry for the page the sender is reading. Returns (entry, created).

    If the user can already see an entry for this URL (sent before, or
    fetched from one of their feeds), that entry is returned with ``created``
    False. With ``html`` the URL is not fetched, so pages behind a login, a
    paywall or robots.txt can still be sent. The entry's metadata records
    ``source: extension_page`` (``url_ingest`` when the URL was fetched) and
    the sender's user id.
    """
    url = normalize_page_url(url)
    existing = await find_entry_by_url(db, url, user_id)
    if existing is not None:
        return existing, False

    doc = await asyncio.to_thread(document_from_html, html, url, title) if html else await fetch_url_document(url)
    metadata = {
        "source": "extension_page" if html else "url_ingest",
        "uploaded_by": str(user_id),
    }
    if client:
        metadata["client"] = client
    if selection and selection.strip():
        metadata["excerpt"] = selection.strip()
    try:
        entry = await create_manual_entry(
            db,
            guid=url_guid(url),
            title=title or doc.title or url,
            html=doc.html,
            text=doc.text,
            url=url,
            image_url=doc.meta.get("image_url"),
            metadata=metadata,
            author=author,
            published_at=plausible_published_at(published_at),
        )
    except DuplicateEntry as dup:
        return await db.get(Entry, dup.entry_id), False
    return entry, True


async def ingest_url(db: AsyncSession, url: str, user_id=None) -> Entry:
    """Fetch a URL and create one entry from its content. 409 if this URL was already ingested."""
    guid = url_guid(url)
    feed = await get_or_create_manual_feed(db)
    existing = await db.execute(select(Entry).where(Entry.feed_id == feed.id, Entry.guid == guid))
    if existing.scalar_one_or_none():
        raise AppError(code="duplicate", message="This URL has already been ingested", status_code=409)

    doc = await fetch_url_document(url)
    try:
        return await create_manual_entry(
            db,
            guid=guid,
            title=doc.title or url,
            html=doc.html,
            text=doc.text,
            url=url,
            image_url=doc.meta.get("image_url"),
            metadata={"source": "url_ingest", **({"uploaded_by": str(user_id)} if user_id else {})},
        )
    except DuplicateEntry:
        raise AppError(code="duplicate", message="This URL has already been ingested", status_code=409) from None
