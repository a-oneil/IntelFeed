import json
import uuid
import xml.etree.ElementTree as ET

import defusedxml.ElementTree as DefusedET
from fastapi import APIRouter, Depends, File, UploadFile
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters import is_extended_feed_type, known_feed_types
from app.core.exceptions import AppError
from app.core.security import get_current_user
from app.database import get_db
from app.feed_packs import INTELFEED_NS, get_pack, load_packs
from app.models.category import Category
from app.models.feed import Feed
from app.models.user import User
from app.services.feed_defaults import FEED_DEFAULT_FIELDS, category_for_feed_type, new_feed_settings
from app.services.feed_fetch_health import strip_client_keys
from app.services.feed_visibility import (
    ensure_subscription,
    subscribe_all_users,
    subscriptions_enabled,
    visible_feed_ids_query,
)
from app.services.title_filter import normalize_patterns

router = APIRouter()

# Every feed type a plain OPML `type` attribute is allowed to name. Deliberately
# narrow: these are the four an arbitrary reader's export could plausibly mean,
# and all four work from a URL alone. The extended types (github_repo, reddit,
# nvd, web_scraper, telegram, bluesky) are inert without an adapter_config, so a
# third-party export claiming `type="reddit"` would create a feed that can never
# fetch. Those types are reachable only through the extension namespace below,
# which carries the config in the same breath.
PORTABLE_FEED_TYPES = ("rss", "atom", "youtube", "podcast")


def parse_extension_attrs(outline: ET.Element) -> dict:
    """Read this outline's ``intelfeed:*`` attributes into feed column values.

    Anything malformed is dropped rather than raising: one bad attribute in a
    400-feed file should cost that one setting, not the whole import.
    """
    raw = {
        key.removeprefix(f"{{{INTELFEED_NS}}}"): value
        for key, value in outline.attrib.items()
        if key.startswith(f"{{{INTELFEED_NS}}}")
    }
    if not raw:
        return {}

    out: dict = {}

    feed_type = (raw.get("feedType") or "").strip().lower()
    if feed_type in known_feed_types():
        out["feed_type"] = feed_type

    if "config" in raw:
        try:
            config = json.loads(raw["config"])
        except (ValueError, TypeError):
            config = None
        if isinstance(config, dict):
            out["adapter_config"] = strip_client_keys(config)

    if (interval := _as_int(raw.get("interval"))) and interval > 0:
        out["fetch_interval_minutes"] = interval

    mode = (raw.get("extractionMode") or "").strip().lower()
    if mode in ("full", "selective", "manual", "none"):
        out["intel_extraction_mode"] = mode

    for attr, column in (
        ("aiAnalysis", "ai_analysis_enabled"),
        ("extractTools", "extract_tools"),
        ("extractRules", "extract_detection_rules"),
        ("autoExtract", "auto_extract_on_ingest"),
    ):
        if (flag := _as_bool(raw.get(attr))) is not None:
            out[column] = flag

    # A JSON list of phrases rather than newline-separated text: a newline in
    # an attribute survives only as a character reference, which hand edits
    # and other tools tend to lose.
    if "excludeTitles" in raw:
        try:
            phrases = json.loads(raw["excludeTitles"])
        except (ValueError, TypeError):
            phrases = None
        if isinstance(phrases, list) and all(isinstance(p, str) for p in phrases):
            try:
                if normalized := normalize_patterns("\n".join(phrases)):
                    out["exclude_title_patterns"] = normalized
            except AppError:
                pass

    return out


def _as_int(value: str | None) -> int | None:
    try:
        return int(str(value).strip())
    except (ValueError, TypeError):
        return None


def _as_bool(value: str | None) -> bool | None:
    match (value or "").strip().lower():
        case "true" | "1" | "yes":
            return True
        case "false" | "0" | "no":
            return False
        case _:
            return None


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

    if root.find("body") is None:
        return {"error": "Invalid OPML file: no body element"}

    return await _import_opml_tree(root, user, db)


async def _import_opml_tree(root: ET.Element, user: User, db: AsyncSession, queue_fetches: bool = True) -> dict:
    """Walk a parsed OPML document, creating its categories and feeds.

    Shared by the upload endpoint and the starter-pack import so both produce
    the same categories, the same dedup behaviour and the same initial fetches.

    ``queue_fetches=False`` returns the new feed ids under ``new_feed_ids``
    instead of dispatching, for callers that own their own transaction and want
    to commit before a worker can go looking for the rows — or that are only
    previewing and must not queue anything at all.
    """
    body = root.find("body")
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
    if not queue_fetches:
        stats["new_feed_ids"] = new_feed_ids
    elif new_feed_ids:
        from app.workers.feed_tasks import fetch_feed

        for feed_id in new_feed_ids:
            fetch_feed.delay(feed_id)

    return stats


def feed_outline_attrs(feed: Feed) -> dict[str, str]:
    """Render one feed as OPML outline attributes, losslessly.

    ``type`` stays within :data:`PORTABLE_FEED_TYPES` so another reader can still
    use the file; anything that would not survive that — the real feed type, the
    adapter config, the extraction tuning — rides in the extension namespace,
    and only when it differs from the column default, to keep the file diffable.
    """
    title = feed.custom_title or feed.title
    attrs = {
        "text": title,
        "title": title,
        "type": feed.feed_type if feed.feed_type in PORTABLE_FEED_TYPES else "rss",
        "xmlUrl": feed.url,
    }
    if feed.site_url:
        attrs["htmlUrl"] = feed.site_url

    ns = "intelfeed:"
    if feed.feed_type not in PORTABLE_FEED_TYPES:
        attrs[f"{ns}feedType"] = feed.feed_type
    # fetch_health is what this server learned fetching the feed, not config.
    config = strip_client_keys(feed.adapter_config)
    if config:
        attrs[f"{ns}config"] = json.dumps(config, sort_keys=True, separators=(",", ":"))
    if feed.fetch_interval_minutes != 30:
        attrs[f"{ns}interval"] = str(feed.fetch_interval_minutes)
    if feed.intel_extraction_mode != "selective":
        attrs[f"{ns}extractionMode"] = feed.intel_extraction_mode
    for attr, value, default in (
        ("aiAnalysis", feed.ai_analysis_enabled, True),
        ("extractTools", feed.extract_tools, True),
        ("extractRules", feed.extract_detection_rules, False),
        ("autoExtract", feed.auto_extract_on_ingest, False),
    ):
        if bool(value) is not default:
            attrs[f"{ns}{attr}"] = "true" if value else "false"
    if phrases := [line for line in (feed.exclude_title_patterns or "").splitlines() if line.strip()]:
        attrs[f"{ns}excludeTitles"] = json.dumps(phrases, separators=(",", ":"))
    return attrs


@router.get("/starter-packs")
async def list_starter_packs(user: User = Depends(get_current_user)):
    """List the curated starter feed packs this build ships.

    A fresh install has no feeds, so the onboarding wizard offers these instead
    of asking the user to go and find sources. ``recommended`` marks the core
    pack the wizard pre-selects; ``requires`` names a prerequisite (an API
    token, say) that the pack needs before its feeds can fetch.
    """
    return {
        "packs": [
            {
                "id": pack.id,
                "title": pack.title,
                "description": pack.description,
                "feed_count": pack.feed_count,
                "recommended": pack.recommended,
                "requires": pack.requires,
            }
            for pack in load_packs()
        ]
    }


@router.post("/starter-packs/import")
async def import_starter_packs(
    pack_ids: list[str],
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Import one or more curated starter packs by id.

    Same permission rule, categories, dedup and initial fetches as a user's own
    OPML upload — these are the same importer reading files that ship in the
    image rather than a file the user had to find. Importing a pack twice adds
    nothing: every feed is matched on URL.
    """
    enabled = await subscriptions_enabled(db)
    if not enabled and user.role != "admin":
        raise AppError(code="forbidden", message="Admin access required", status_code=403)

    unknown = [pid for pid in pack_ids if get_pack(pid) is None]
    if unknown:
        raise AppError(
            code="unknown_feed_pack",
            message=f"Unknown starter pack(s): {', '.join(unknown)}",
            status_code=404,
        )

    totals = {"feeds_added": 0, "feeds_skipped": 0, "categories_created": 0, "errors": [], "packs": []}
    for pack_id in dict.fromkeys(pack_ids):  # de-dup, keep order
        pack = get_pack(pack_id)
        try:
            root = DefusedET.fromstring(pack.path().read_text())
        except (OSError, ET.ParseError, DefusedET.DTDForbidden, DefusedET.EntitiesForbidden):
            totals["errors"].append(f"Could not read starter pack '{pack_id}'")
            continue

        stats = await _import_opml_tree(root, user, db)
        for key in ("feeds_added", "feeds_skipped", "categories_created"):
            totals[key] += stats[key]
        totals["errors"].extend(stats["errors"])
        totals["packs"].append({"id": pack_id, "title": pack.title, "feeds_added": stats["feeds_added"]})

    return totals


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

    title = outline.get("text") or outline.get("title") or xml_url
    html_url = outline.get("htmlUrl")
    feed_type = outline.get("type", "rss").lower()
    if feed_type not in PORTABLE_FEED_TYPES:
        feed_type = "rss"

    # IntelFeed's own extension attributes win over the portable ones: they are
    # the only place an extended feed type and its adapter_config can come from.
    extras = parse_extension_attrs(outline)
    feed_type = extras.pop("feed_type", feed_type)

    # Skip non-URL feeds (e.g. Inoreader keyword monitoring). Extended types are
    # exempt: their adapter is driven by adapter_config and never fetches this
    # value, so the NVD source legitimately identifies itself as `nvd://cves`.
    if not xml_url.startswith(("http://", "https://")) and not is_extended_feed_type(feed_type):
        stats.setdefault("feeds_skipped_invalid", 0)
        stats["feeds_skipped_invalid"] += 1
        return

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

    # A top-level outline has no folder: file it where feeds of its type live.
    if category_id is None:
        category_id = await category_for_feed_type(db, feed_type)
    # The outline's own tuning wins; the category's defaults fill the rest.
    pipeline = await new_feed_settings(db, category_id, {f: extras.pop(f, None) for f in FEED_DEFAULT_FIELDS})
    feed = Feed(
        title=title,
        url=xml_url,
        feed_type=feed_type,
        site_url=html_url,
        category_id=category_id,
        custom_title=title if title != xml_url else None,
        **extras,
        **pipeline,
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
    opml = ET.Element("opml", {"version": "1.0", "xmlns:intelfeed": INTELFEED_NS})
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
            ET.SubElement(parent, "outline", **feed_outline_attrs(feed))

    xml_str = ET.tostring(opml, encoding="unicode", xml_declaration=True)
    return Response(
        content=xml_str,
        media_type="text/xml",
        headers={"Content-Disposition": "attachment; filename=intelfeed-subscriptions.opml"},
    )
