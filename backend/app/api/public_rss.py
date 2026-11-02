"""Public, token-gated RSS endpoints that re-publish aggregated entries.

The token lives in system_settings (`_public_rss_token`); the admin manages it
via /api/system-settings/public-rss/*. URLs look like:

    /api/public/rss/{token}.xml
    /api/public/rss/{token}/category/{slug}.xml

Both routes are intentionally unauthenticated — the unguessable token is the
only access control.
"""

from __future__ import annotations

import hmac
import html
import re
import uuid
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from email.utils import format_datetime
from urllib.parse import parse_qs, urlparse

from fastapi import APIRouter, Depends, Path, Request
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.exceptions import AppError
from app.database import get_db
from app.models.category import Category
from app.models.entry import Entry
from app.models.feed import Feed
from app.services.system_settings import get_public_rss_token, get_setting

router = APIRouter()


_SLUG_RE = re.compile(r"[^a-z0-9]+")

# XML 1.0 allows: #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF]
# This pattern matches any character NOT in those ranges so we can strip them.
_INVALID_XML_RE = re.compile("[^\t\n\r\u0020-\ud7ff\ue000-\ufffd\U00010000-\U0010ffff]")

_PROXY_IMG_ATTR_RE = re.compile(
    r'(<img\b[^>]*?\b(?:src|srcset|data-src)\s*=\s*["\'])([^"\']*?/api/proxy/image[^"\']*)(["\'])',
    re.IGNORECASE,
)


def _slugify(name: str) -> str:
    slug = _SLUG_RE.sub("-", name.lower()).strip("-")
    return slug or "category"


def _clean_xml_text(text: str | None) -> str:
    """Strip characters that are not valid in XML 1.0 text content."""
    if not text:
        return ""
    return _INVALID_XML_RE.sub("", text)


def _deproxy_image_urls(html_text: str) -> str:
    """Replace `/api/proxy/image?url=...` image sources with their original upstream URL.

    The proxy endpoint requires an authenticated user, so external RSS readers can't
    fetch through it. For public feeds we point images at the upstream origin directly.
    """
    if not html_text or "/api/proxy/image" not in html_text:
        return html_text

    def _swap(match: re.Match) -> str:
        prefix, proxy_url, suffix = match.group(1), match.group(2), match.group(3)
        # nh3/sanitizer may have HTML-escaped the &; unescape before parsing the query.
        parsed = urlparse(html.unescape(proxy_url))
        params = parse_qs(parsed.query)
        original = params.get("url", [None])[0]
        if not original:
            return match.group(0)
        return f"{prefix}{html.escape(original, quote=True)}{suffix}"

    return _PROXY_IMG_ATTR_RE.sub(_swap, html_text)


async def _resolve_token(db: AsyncSession, token: str) -> None:
    enabled = bool(await get_setting("public_rss_enabled", db))
    if not enabled:
        raise AppError(code="not_found", message="Not found", status_code=404)

    expected = await get_public_rss_token(db, create_if_missing=False)
    if not expected or not hmac.compare_digest(token.encode(), expected.encode()):
        raise AppError(code="not_found", message="Not found", status_code=404)


def _base_url(request: Request) -> str:
    # Honor reverse-proxy headers (Caddy in prod) so URLs use the public https origin
    # rather than the internal http://api:8000 the app sees directly.
    scheme = request.headers.get("x-forwarded-proto", "").split(",")[0].strip() or request.url.scheme
    host = request.headers.get("x-forwarded-host", "").split(",")[0].strip() or request.url.netloc
    return f"{scheme}://{host}".rstrip("/")


def _format_rfc822(dt: datetime | None) -> str:
    if dt is None:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return format_datetime(dt, usegmt=True)


def _build_rss(
    *,
    title: str,
    description: str,
    self_url: str,
    site_url: str,
    entries: list[tuple[Entry, Feed]],
    full_content: bool,
) -> bytes:
    rss = ET.Element(
        "rss",
        {
            "version": "2.0",
            "xmlns:atom": "http://www.w3.org/2005/Atom",
            "xmlns:content": "http://purl.org/rss/1.0/modules/content/",
            "xmlns:dc": "http://purl.org/dc/elements/1.1/",
        },
    )
    channel = ET.SubElement(rss, "channel")
    ET.SubElement(channel, "title").text = _clean_xml_text(title)
    ET.SubElement(channel, "link").text = site_url
    ET.SubElement(channel, "description").text = _clean_xml_text(description)
    ET.SubElement(channel, "generator").text = "IntelFeed"
    ET.SubElement(
        channel,
        "atom:link",
        {
            "href": self_url,
            "rel": "self",
            "type": "application/rss+xml",
        },
    )

    latest = max((e.published_at or e.fetched_at for e, _ in entries), default=None)
    if latest:
        ET.SubElement(channel, "lastBuildDate").text = _format_rfc822(latest)

    for entry, feed in entries:
        item = ET.SubElement(channel, "item")
        # Titles from upstream feeds occasionally arrive HTML-encoded (e.g. `&#x5b;`);
        # decode so RSS readers don't display raw entity references.
        item_title = _clean_xml_text(html.unescape(entry.title or "")) or "(untitled)"
        ET.SubElement(item, "title").text = item_title
        if entry.url:
            ET.SubElement(item, "link").text = entry.url
        guid_text = entry.guid or entry.url or str(entry.id)
        guid_el = ET.SubElement(item, "guid")
        guid_el.set("isPermaLink", "true" if entry.url and guid_text == entry.url else "false")
        guid_el.text = _clean_xml_text(guid_text)
        pub = entry.published_at or entry.fetched_at
        if pub:
            ET.SubElement(item, "pubDate").text = _format_rfc822(pub)
        if entry.author:
            ET.SubElement(item, "dc:creator").text = _clean_xml_text(entry.author)

        feed_title = feed.custom_title or feed.title
        if feed_title:
            ET.SubElement(item, "source", {"url": feed.url}).text = _clean_xml_text(feed_title)

        summary = _clean_xml_text(_deproxy_image_urls(entry.summary or ""))
        if full_content and entry.content_html:
            content = _clean_xml_text(_deproxy_image_urls(entry.content_html))
            ET.SubElement(item, "description").text = summary or item_title
            ET.SubElement(item, "content:encoded").text = content
        else:
            ET.SubElement(item, "description").text = summary or item_title

    return b'<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(rss, encoding="utf-8")


async def _fetch_entries(
    db: AsyncSession,
    *,
    category_id: uuid.UUID | None,
    limit: int,
) -> list[tuple[Entry, Feed]]:
    stmt = (
        select(Entry, Feed)
        .join(Feed, Feed.id == Entry.feed_id)
        # The global mute column, deliberately (see services/feed_visibility.py):
        # the proxy has no reader, so a feed an admin muted for the instance
        # stays out of what it re-publishes.
        .where(Feed.is_active.is_(True), Feed.is_muted.is_(False))
        .order_by(Entry.published_at.desc().nulls_last(), Entry.fetched_at.desc())
        .limit(limit)
    )
    if category_id is not None:
        stmt = stmt.where(Feed.category_id == category_id)
    result = await db.execute(stmt)
    return list(result.all())


@router.get("/{token}.xml")
async def public_rss_all(
    request: Request,
    token: str = Path(..., description="Unguessable public RSS access token managed under system settings"),
    db: AsyncSession = Depends(get_db),
):
    """Public (unauthenticated) RSS 2.0 feed of the newest entries across all active, unmuted sources.

    Access is gated only by the secret token; an invalid or disabled token yields 404.
    Item count and full-content inclusion follow the public_rss_* system settings.
    """
    await _resolve_token(db, token)
    limit = int(await get_setting("public_rss_per_feed_limit", db) or 100)
    full_content = bool(await get_setting("public_rss_full_content", db))
    entries = await _fetch_entries(db, category_id=None, limit=limit)

    base = _base_url(request)
    xml = _build_rss(
        title="IntelFeed — All Sources",
        description="Aggregated entries from all IntelFeed sources.",
        self_url=f"{base}/api/public/rss/{token}.xml",
        site_url=base,
        entries=entries,
        full_content=full_content,
    )
    return Response(content=xml, media_type="application/rss+xml; charset=utf-8")


@router.get("/{token}/category/{slug}.xml")
async def public_rss_category(
    request: Request,
    token: str = Path(..., description="Unguessable public RSS access token managed under system settings"),
    slug: str = Path(..., description="Slugified category name (see the /categories endpoint for valid slugs)"),
    db: AsyncSession = Depends(get_db),
):
    """Public (unauthenticated) RSS 2.0 feed of the newest entries in one category.

    404 if the token is invalid/disabled or no category matches the slug.
    """
    await _resolve_token(db, token)

    cats = (await db.execute(select(Category))).scalars().all()
    match = next((c for c in cats if _slugify(c.name) == slug), None)
    if match is None:
        raise AppError(code="not_found", message="Category not found", status_code=404)

    limit = int(await get_setting("public_rss_per_feed_limit", db) or 100)
    full_content = bool(await get_setting("public_rss_full_content", db))
    entries = await _fetch_entries(db, category_id=match.id, limit=limit)

    base = _base_url(request)
    xml = _build_rss(
        title=f"IntelFeed — {match.name}",
        description=f"Aggregated entries from the {match.name} category.",
        self_url=f"{base}/api/public/rss/{token}/category/{slug}.xml",
        site_url=base,
        entries=entries,
        full_content=full_content,
    )
    return Response(content=xml, media_type="application/rss+xml; charset=utf-8")


@router.get("/{token}/categories")
async def public_rss_categories(
    request: Request,
    token: str = Path(..., description="Unguessable public RSS access token managed under system settings"),
    db: AsyncSession = Depends(get_db),
):
    """Return the list of category slugs available as per-category feeds.

    Useful for the admin UI to render copyable per-category URLs.
    """
    await _resolve_token(db, token)
    result = await db.execute(select(Category).options(selectinload(Category.feeds)).order_by(Category.name))
    categories = result.scalars().all()
    base = _base_url(request)
    return {
        "categories": [
            {
                "id": str(c.id),
                "name": c.name,
                "slug": _slugify(c.name),
                "feed_count": len(c.feeds),
                "url": f"{base}/api/public/rss/{token}/category/{_slugify(c.name)}.xml",
            }
            for c in categories
        ]
    }
