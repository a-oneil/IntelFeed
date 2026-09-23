import uuid
import xml.etree.ElementTree as ET

import defusedxml.ElementTree as DefusedET
from fastapi import APIRouter, Depends, File, UploadFile
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppError
from app.core.security import get_current_user
from app.database import get_db
from app.models.category import Category
from app.models.feed import Feed
from app.models.user import User
from app.services.feed_visibility import (
    ensure_subscription,
    subscribe_all_users,
    subscriptions_enabled,
    visible_feed_ids_query,
)

router = APIRouter()


@router.post("/import")
async def import_opml(
    file: UploadFile = File(..., description="OPML subscription file (XML, max 10 MB) uploaded as multipart form data"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Import feed subscriptions from an uploaded OPML file.

    Creates categories from OPML outline groups, skips feeds whose URL already
    exists, and queues an initial fetch for every newly added feed. Returns
    import statistics (feeds_added, feeds_skipped, categories_created, errors).

    With per-user subscriptions off, imports mutate the shared feed list, so
    they are admin-only; with them on, any user may import — new feeds join the
    shared pool subscribed to the importer, existing ones are subscribed to.
    """
    enabled = await subscriptions_enabled(db)
    if not enabled and user.role != "admin":
        raise AppError(code="forbidden", message="Admin access required", status_code=403)

    content = await file.read()
    if len(content) > 10 * 1024 * 1024:  # 10 MB
        return {"error": "OPML file too large (max 10 MB)"}
    try:
        root = DefusedET.fromstring(content)
    except (ET.ParseError, DefusedET.DTDForbidden, DefusedET.EntitiesForbidden):
        return {"error": "Invalid OPML file"}

    body = root.find("body")
    if body is None:
        return {"error": "Invalid OPML file: no body element"}

    stats = {"feeds_added": 0, "feeds_skipped": 0, "categories_created": 0, "errors": []}

    for outline in body:
        children = list(outline)
        if children:
            # This is a category
            category_name = outline.get("text") or outline.get("title") or "Unnamed"

            # Check if category already exists
            cat_result = await db.execute(
                select(Category).where(
                    Category.name == category_name,
                )
            )
            category = cat_result.scalar_one_or_none()
            if not category:
                category = Category(created_by=user.id, name=category_name)
                db.add(category)
                await db.flush()
                stats["categories_created"] += 1

            # Import feeds in this category
            for feed_outline in children:
                await _import_feed_outline(feed_outline, user, category.id, db, stats)
        else:
            # Top-level feed (no category)
            await _import_feed_outline(outline, user, None, db, stats)

    await db.flush()

    # Queue initial fetch for the feeds THIS import added (not every
    # never-fetched feed on the instance)
    new_feed_ids = stats.pop("_new_feed_ids", [])
    if new_feed_ids:
        from app.workers.feed_tasks import fetch_feed

        for feed_id in new_feed_ids:
            fetch_feed.delay(feed_id)

    return stats


async def _import_feed_outline(
    outline: ET.Element,
    user: User,
    category_id: uuid.UUID | None,
    db: AsyncSession,
    stats: dict,
):
    xml_url = outline.get("xmlUrl")
    if not xml_url:
        return

    # Skip non-URL feeds (e.g. Inoreader keyword monitoring)
    if not xml_url.startswith(("http://", "https://")):
        stats.setdefault("feeds_skipped_invalid", 0)
        stats["feeds_skipped_invalid"] += 1
        return

    title = outline.get("text") or outline.get("title") or xml_url
    html_url = outline.get("htmlUrl")
    feed_type = outline.get("type", "rss").lower()
    if feed_type not in ("rss", "atom", "youtube", "podcast"):
        feed_type = "rss"

    # Check if feed already exists
    result = await db.execute(select(Feed).where(Feed.url == xml_url))
    feed = result.scalar_one_or_none()

    if feed:
        # Already in the pool — with per-user subscriptions on, importing means
        # subscribing to it.
        if await subscriptions_enabled(db):
            await ensure_subscription(db, user.id, feed.id)
            await db.flush()
        stats["feeds_skipped"] += 1
        return

    feed = Feed(
        title=title,
        url=xml_url,
        feed_type=feed_type,
        site_url=html_url,
        category_id=category_id,
        custom_title=title if title != xml_url else None,
    )
    db.add(feed)
    await db.flush()
    if await subscriptions_enabled(db):
        await ensure_subscription(db, user.id, feed.id)
    else:
        await subscribe_all_users(db, feed.id)
    await db.flush()
    stats["feeds_added"] += 1
    stats.setdefault("_new_feed_ids", []).append(str(feed.id))


@router.get("/export")
async def export_opml(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Export all feed subscriptions as an OPML XML document, grouped by category.

    Returned as a text/xml attachment named intelfeed-subscriptions.opml.
    """
    # Get the caller's feeds with categories (all feeds when per-user
    # subscriptions are off)
    enabled = await subscriptions_enabled(db)
    feeds_query = (
        select(Feed, Category).outerjoin(Category, Category.id == Feed.category_id).order_by(Category.name, Feed.title)
    )
    if enabled:
        feeds_query = feeds_query.where(Feed.id.in_(visible_feed_ids_query(user.id, enabled=True, include_muted=True)))
    feeds_result = await db.execute(feeds_query)
    rows = feeds_result.all()

    # Build OPML
    opml = ET.Element("opml", version="1.0")
    head = ET.SubElement(opml, "head")
    title_elem = ET.SubElement(head, "title")
    title_elem.text = "IntelFeed Subscriptions"
    body = ET.SubElement(opml, "body")

    # Group by category
    categories: dict[str | None, list] = {}
    for feed, category in rows:
        cat_name = category.name if category else None
        if cat_name not in categories:
            categories[cat_name] = []
        categories[cat_name].append(feed)

    for cat_name, feeds in categories.items():
        if cat_name:
            cat_outline = ET.SubElement(body, "outline", text=cat_name, title=cat_name)
            parent = cat_outline
        else:
            parent = body

        for feed in feeds:
            attrs = {
                "text": feed.custom_title or feed.title,
                "title": feed.custom_title or feed.title,
                "type": "rss",
                "xmlUrl": feed.url,
            }
            if feed.site_url:
                attrs["htmlUrl"] = feed.site_url
            ET.SubElement(parent, "outline", **attrs)

    xml_str = ET.tostring(opml, encoding="unicode", xml_declaration=True)
    return Response(
        content=xml_str,
        media_type="text/xml",
        headers={"Content-Disposition": "attachment; filename=intelfeed-subscriptions.opml"},
    )
