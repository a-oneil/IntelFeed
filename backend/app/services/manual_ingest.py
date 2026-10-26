"""The Manual Uploads feed and the single-item ingest paths.

Bulk ingest (services/ingest_batches.py) builds on the same three pieces this
module owns: the singleton ``manual://uploads`` feed, ``fetch_url_document``
(fetch + readability + sanitize, no database), and ``create_manual_entry``
(dedup by GUID, then one ordinary Entry row). ``ingest_url`` / ``ingest_pdf``
remain as the synchronous one-item doors the Android client and the
``ingest_url`` registry tool call.
"""

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
from app.services.ingest_parsers import (
    ParsedDocument,
    extract_pdf_content,  # noqa: F401 — re-exported; the PDF extractor lives in ingest_parsers now
    sanitize_pdf_html,
)
from app.services.sanitizer import (
    extract_first_image,
    extract_og_image,
    html_to_text,
    sanitize_html,
)

logger = logging.getLogger(__name__)

MANUAL_FEED_URL = "manual://uploads"
MAX_PDF_SIZE = 50 * 1024 * 1024  # 50 MB — the legacy single-PDF cap; batches read ingest_max_file_mb

_REL_SRC_RE = re.compile(r'(<(?:img|source|video|audio)\s[^>]*?)src="([^"]+)"', re.IGNORECASE)
_REL_HREF_RE = re.compile(r'(<a\s[^>]*?)href="([^"]+)"', re.IGNORECASE)

# Kept under the old private name: callers outside this module imported it.
_sanitize_pdf_html = sanitize_pdf_html


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
    robots.txt, Google News unwrapping), then falls back to a plain fetch for a
    title and og:image. Both paths go through the SSRF-vetted client.
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


async def ingest_url(db: AsyncSession, url: str) -> Entry:
    """Fetch a URL and create an entry from its content (the one-item door)."""
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
            metadata={"source": "url_ingest"},
        )
    except DuplicateEntry:
        raise AppError(code="duplicate", message="This URL has already been ingested", status_code=409) from None


async def ingest_pdf(
    db: AsyncSession,
    file_content: bytes,
    filename: str,
    title: str | None = None,
) -> Entry:
    """Extract text from a PDF and create an entry (the one-item door; no file retained)."""
    if len(file_content) > MAX_PDF_SIZE:
        raise AppError(
            code="file_too_large",
            message=f"PDF exceeds maximum size of {MAX_PDF_SIZE // (1024 * 1024)} MB",
            status_code=413,
        )

    guid = bytes_guid(file_content, kind="pdf")
    content_text, raw_html = extract_pdf_content(file_content)
    if not content_text or not content_text.strip():
        raise AppError(
            code="extraction_failed",
            message="Could not extract text from this PDF (it may be a scanned image)",
            status_code=422,
        )

    if not title:
        title = re.sub(r"\.pdf$", "", filename, flags=re.IGNORECASE).strip() or "Untitled PDF"

    try:
        return await create_manual_entry(
            db,
            guid=guid,
            title=title,
            html=sanitize_pdf_html(raw_html),
            text=content_text,
            metadata={"source": "pdf_upload", "filename": filename},
        )
    except DuplicateEntry:
        raise AppError(code="duplicate", message="This PDF has already been ingested", status_code=409) from None
