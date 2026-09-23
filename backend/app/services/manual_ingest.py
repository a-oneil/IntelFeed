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
from app.services.sanitizer import (
    ALLOWED_ATTRIBUTES,
    ALLOWED_TAGS,
    extract_first_image,
    extract_og_image,
    html_to_text,
    sanitize_html,
)

logger = logging.getLogger(__name__)

MANUAL_FEED_URL = "manual://uploads"
MAX_PDF_SIZE = 50 * 1024 * 1024  # 50 MB

_REL_SRC_RE = re.compile(r'(<(?:img|source|video|audio)\s[^>]*?)src="([^"]+)"', re.IGNORECASE)
_REL_HREF_RE = re.compile(r'(<a\s[^>]*?)href="([^"]+)"', re.IGNORECASE)


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
        description="Manually ingested articles and PDFs",
    )
    db.add(feed)
    await db.flush()

    # System feed — visible to everyone
    from app.services.feed_visibility import subscribe_all_users

    await subscribe_all_users(db, feed.id)
    await db.flush()
    return feed


async def ingest_url(db: AsyncSession, url: str) -> Entry:
    """Fetch a URL and create an entry from its content."""
    # Validate URL
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise AppError(code="invalid_url", message="URL must use http or https", status_code=400)

    feed = await get_or_create_manual_feed(db)

    # Check for duplicate
    guid = f"manual:url:{hashlib.sha256(url.encode()).hexdigest()}"
    existing = await db.execute(select(Entry).where(Entry.feed_id == feed.id, Entry.guid == guid))
    if existing.scalar_one_or_none():
        raise AppError(code="duplicate", message="This URL has already been ingested", status_code=409)

    # Extract full text using the existing extraction pipeline
    from app.workers.feed_tasks import _extract_full_text

    content_html, og_image = await _extract_full_text(url)

    # If full extraction failed, try a basic fetch for the title at minimum
    title = None
    if not content_html:
        import httpx

        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=15.0) as client:
                resp = await client.get(url)
                if resp.status_code == 200 and "html" in resp.headers.get("content-type", ""):
                    raw_html = resp.text
                    content_html = raw_html
                    if not og_image:
                        og_image = extract_og_image(raw_html)
                    # Try to extract title from <title> tag
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

    # Resolve relative URLs to absolute before sanitizing/proxying
    content_html = _resolve_relative_urls(content_html, url)

    # Sanitize and process
    sanitized_html = sanitize_html(content_html)
    content_text = html_to_text(sanitized_html)
    word_count = len(content_text.split()) if content_text else 0

    # Extract title from content if we don't have one yet
    if not title:
        # Try <h1> in the extracted content
        h1_match = re.search(r"<h1[^>]*>([^<]+)</h1>", content_html, re.IGNORECASE)
        if h1_match:
            title = h1_match.group(1).strip()
        else:
            # Fallback: use domain + path
            title = f"{parsed.netloc}{parsed.path}"

    # Extract lead image
    image_url = extract_first_image(sanitized_html) if sanitized_html else None
    if not image_url:
        image_url = og_image

    content_hash = compute_content_hash(title, content_text)
    now = datetime.now(UTC)

    entry = Entry(
        feed_id=feed.id,
        guid=guid,
        url=url,
        title=title[:2000],
        content_html=sanitized_html,
        content_text=content_text,
        published_at=now,
        fetched_at=now,
        word_count=word_count,
        content_hash=content_hash,
        image_url=image_url,
        metadata_={"source": "url_ingest"},
    )
    db.add(entry)
    await db.flush()
    return entry


async def ingest_pdf(
    db: AsyncSession,
    file_content: bytes,
    filename: str,
    title: str | None = None,
) -> Entry:
    """Extract text from a PDF and create an entry."""
    if len(file_content) > MAX_PDF_SIZE:
        raise AppError(
            code="file_too_large",
            message=f"PDF exceeds maximum size of {MAX_PDF_SIZE // (1024 * 1024)} MB",
            status_code=413,
        )

    feed = await get_or_create_manual_feed(db)

    # Check for duplicate
    guid = f"manual:pdf:{hashlib.sha256(file_content).hexdigest()}"
    existing = await db.execute(select(Entry).where(Entry.feed_id == feed.id, Entry.guid == guid))
    if existing.scalar_one_or_none():
        raise AppError(code="duplicate", message="This PDF has already been ingested", status_code=409)

    # Extract text and HTML (with images as base64 data URIs)
    content_text, raw_html = extract_pdf_content(file_content)
    if not content_text or not content_text.strip():
        raise AppError(
            code="extraction_failed",
            message="Could not extract text from this PDF (it may be a scanned image)",
            status_code=422,
        )

    # Use filename as title if not provided
    if not title:
        title = re.sub(r"\.pdf$", "", filename, flags=re.IGNORECASE).strip() or "Untitled PDF"

    # Sanitize HTML, allowing data: URIs for embedded PDF images
    content_html = _sanitize_pdf_html(raw_html)

    word_count = len(content_text.split())
    content_hash = compute_content_hash(title, content_text)
    now = datetime.now(UTC)

    entry = Entry(
        feed_id=feed.id,
        guid=guid,
        title=title[:2000],
        content_html=content_html,
        content_text=content_text,
        published_at=now,
        fetched_at=now,
        word_count=word_count,
        content_hash=content_hash,
        metadata_={"source": "pdf_upload", "filename": filename},
    )
    db.add(entry)
    await db.flush()
    return entry


def extract_pdf_content(content: bytes) -> tuple[str, str]:
    """Extract text and HTML (with embedded images) from PDF bytes.

    Returns (plain_text, html_with_images) tuple.
    """
    import fitz  # pymupdf

    text_pages = []
    html_pages = []
    with fitz.open(stream=content, filetype="pdf") as doc:
        for page in doc:
            text = page.get_text()
            if text.strip():
                text_pages.append(text.strip())
            # get_text("html") returns HTML with images as base64 data URIs
            page_html = page.get_text("html")
            if page_html.strip():
                html_pages.append(page_html)

    plain_text = "\n\n".join(text_pages)
    # If HTML extraction produced content with images, use it; otherwise fall back to
    # wrapping plain text in paragraphs
    if html_pages:
        combined_html = "\n".join(html_pages)
    else:
        paragraphs = plain_text.split("\n\n")
        combined_html = "".join(f"<p>{p.strip()}</p>" for p in paragraphs if p.strip())

    return plain_text, combined_html


def _sanitize_pdf_html(raw_html: str) -> str:
    """Sanitize PDF-extracted HTML, allowing data: URIs for embedded images."""
    import nh3

    return nh3.clean(
        raw_html,
        tags=ALLOWED_TAGS | {"span", "div", "img"},
        attributes={
            **ALLOWED_ATTRIBUTES,
            "img": {"src", "alt", "width", "height", "loading", "style"},
            "span": {"style"},
            "div": {"style"},
            "p": {"style"},
        },
        link_rel="noopener noreferrer nofollow",
        url_schemes={"http", "https", "data"},
    )
