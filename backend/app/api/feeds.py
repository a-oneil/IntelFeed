import json
import uuid
from datetime import UTC, datetime

import structlog
from fastapi import APIRouter, Body, Depends, Path, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters import _EXTENDED_ADAPTERS
from app.core.exceptions import AppError
from app.core.pagination import CursorPaginatedResponse, PaginatedResponse
from app.core.security import get_admin_user, get_current_user
from app.database import get_db
from app.models.entry import Entry
from app.models.entry_state import UserEntryState
from app.models.feed import Feed
from app.models.user import User
from app.schemas.entry import EntryResponse
from app.schemas.feed import (
    BulkCategoryUpdateRequest,
    BulkExcludeShortsRequest,
    BulkIntelModeRequest,
    FeedCreateRequest,
    FeedDiscoverRequest,
    FeedPushRequest,
    FeedResponse,
    FeedUpdateRequest,
)
from app.services.feed_discovery import discover_feed
from app.services.feed_fetch_health import clear_pause, health_warning, pause_reason, strip_client_keys
from app.services.feed_visibility import (
    ensure_subscription,
    get_subscription,
    subscribe_all_users,
    subscription_mute_map,
    subscription_pause_map,
    subscriptions_enabled,
    visible_feed_ids_query,
)

# Extended adapter feed types that skip URL discovery. Derived from the adapter
# registry rather than hand-listed: the update endpoint's own copy of a feed-type
# set had silently drifted from it, and this one would have gone the same way.
_EXTENDED_FEED_TYPES = frozenset(_EXTENDED_ADAPTERS)
_EXTENDED_FEED_DEFAULTS: dict[str, dict] = {
    "github_repo": {"interval": 1440},
    "nvd": {"interval": 60},
    "web_scraper": {"interval": 360},
    "telegram": {"interval": 30},
    "bluesky": {"interval": 15, "relevance_rating": "medium"},
}


def _normalize_telegram_config(adapter_config: dict) -> dict:
    """Strip ``/s/`` from any Telegram channel URL pasted into adapter_config."""
    from app.adapters.telegram import normalize_channel_handle

    out = dict(adapter_config)
    for key in ("channel", "channel_username"):
        if key in out:
            out[key] = normalize_channel_handle(out[key])
    return out


logger = structlog.get_logger("app.feeds")

UNREAD_CACHE_TTL = 120  # seconds

router = APIRouter()


def _encrypt_bluesky_app_password(adapter_config: dict) -> dict:
    """Encrypt the plaintext app_password from a Bluesky adapter_config dict."""
    pw = adapter_config.get("app_password")
    if not pw:
        return adapter_config
    # Heuristic: Fernet ciphertext is URL-safe base64 starting with "gAAAAA".
    if isinstance(pw, str) and pw.startswith("gAAAAA"):
        return adapter_config
    # Reject the masked sentinel — it means "no change", not a real password.
    if isinstance(pw, str) and set(pw) == {"•"}:
        out = dict(adapter_config)
        out.pop("app_password", None)
        return out
    from app.core.encryption import encrypt_value

    out = dict(adapter_config)
    out["app_password"] = encrypt_value(pw)
    return out


async def _validate_bluesky_author_entity(adapter_config: dict, db: AsyncSession) -> None:
    """If `author_entity` is set, validate the referenced entity exists."""
    author = adapter_config.get("author_entity")
    if not isinstance(author, dict):
        return
    etype = author.get("type")
    eid = author.get("id")
    if not etype and not eid:
        return
    if not etype or not eid:
        raise AppError(
            code="invalid_author_entity",
            message="author_entity requires both type and id",
            status_code=400,
        )
    if etype not in {"threat_actor", "vendor", "product"}:
        raise AppError(
            code="invalid_author_entity",
            message="author_entity.type must be one of: threat_actor, vendor, product",
            status_code=400,
        )
    try:
        ent_uuid = uuid.UUID(str(eid))
    except (ValueError, TypeError) as e:
        raise AppError(
            code="invalid_author_entity",
            message="author_entity.id must be a UUID",
            status_code=400,
        ) from e
    if etype == "threat_actor":
        from app.models.threat_actor import ThreatActor as _Model
    elif etype == "vendor":
        from app.models.vendor import Vendor as _Model
    else:
        from app.models.product import Product as _Model
    found = await db.get(_Model, ent_uuid)
    if not found:
        raise AppError(
            code="invalid_author_entity",
            message=f"{etype} with id {eid} not found",
            status_code=404,
        )


@router.get("", response_model=PaginatedResponse[FeedResponse])
async def list_feeds(
    category_id: uuid.UUID | None = Query(None, description="Only return feeds in this category"),
    limit: int = Query(50, ge=1, le=1000, description="Maximum number of feeds to return"),
    offset: int = Query(0, ge=0, description="Number of feeds to skip for pagination"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List subscribed feeds with per-feed unread counts for the current user.

    Unread counts are batch-computed and cached in Redis for 120 seconds.
    """
    enabled = await subscriptions_enabled(db)
    # Muted feeds stay listed (the sidebar folds them); visibility is what the
    # subscription filter decides.
    vis = visible_feed_ids_query(user.id, enabled=enabled, include_muted=True, category_id=category_id)
    query = select(Feed).where(Feed.id.in_(vis))

    count_query = select(func.count()).select_from(vis.subquery())
    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    result = await db.execute(query.offset(offset).limit(limit))
    feeds = result.scalars().all()

    # Batch unread counts — try Redis cache first, fall back to DB. The cache
    # holds counts for the caller's FULL feed list, so a category-filtered or
    # paginated request must neither trust nor overwrite it.
    feed_ids = [feed.id for feed in feeds]
    full_list = category_id is None and offset == 0 and len(feeds) >= total
    unread_map: dict[uuid.UUID, int] = {}
    if feed_ids:
        cache_key = f"feed_unreads:{user.id}"
        try:
            from app.services.redis_client import get_redis

            r = await get_redis()
            cached = await r.get(cache_key) if full_list else None
            if cached:
                raw = json.loads(cached)
                unread_map = {uuid.UUID(k): v for k, v in raw.items()}
        except Exception:
            cached = None

        if not unread_map:
            unread_query = (
                select(Entry.feed_id, func.count().label("cnt"))
                .outerjoin(
                    UserEntryState,
                    (UserEntryState.entry_id == Entry.id) & (UserEntryState.user_id == user.id),
                )
                .where(
                    Entry.feed_id.in_(feed_ids),
                    (UserEntryState.is_read == False) | (UserEntryState.id == None),  # noqa: E711, E712
                )
                .group_by(Entry.feed_id)
            )
            unread_result = await db.execute(unread_query)
            unread_map = {row.feed_id: row.cnt for row in unread_result.all()}

            # Cache the result (full unfiltered list only)
            if full_list:
                try:
                    from app.services.redis_client import get_redis

                    r = await get_redis()
                    await r.set(cache_key, json.dumps({str(k): v for k, v in unread_map.items()}), ex=UNREAD_CACHE_TTL)
                except Exception:
                    pass

    mute_map = await subscription_mute_map(db, user.id, feed_ids) if enabled else {}
    pause_map = await subscription_pause_map(db, user.id, feed_ids) if enabled else {}

    items = []
    for feed in feeds:
        resp = FeedResponse.model_validate(feed)
        resp.unread_count = unread_map.get(feed.id, 0)
        if enabled:
            resp.is_muted = mute_map.get(feed.id, feed.is_muted)
            # Reads as paused if the instance switched it off OR this reader did.
            resp.is_active = feed.is_active and not pause_map.get(feed.id, False)
            resp.per_user = True
        items.append(resp)

    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset, has_more=offset + limit < total)


@router.post("", response_model=FeedResponse, status_code=201)
async def create_feed(
    request: FeedCreateRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Subscribe to a new feed.

    For standard feed types the URL is run through feed discovery to find the actual
    feed; extended adapter types (github_repo, reddit, nvd, telegram, bluesky, etc.)
    skip discovery and use adapter_config directly. Returns 409 if a feed with the
    same URL already exists, then queues an initial fetch via Celery.
    """
    enabled = await subscriptions_enabled(db)

    # Check if feed URL already exists
    result = await db.execute(select(Feed).where(Feed.url == request.url))
    feed = result.scalar_one_or_none()

    if feed:
        if enabled:
            # Adding a feed that's already in the shared pool just subscribes you
            if await get_subscription(db, user.id, feed.id):
                raise AppError(code="conflict", message="You are already subscribed to this feed", status_code=409)
            # Whether this feed is inactive because its last subscriber left, or
            # because an admin paused it, has to be settled BEFORE we subscribe.
            had_subscribers = await _subscriber_count(db, feed.id) > 0
            await ensure_subscription(db, user.id, feed.id)
            if not feed.is_active and not had_subscribers:
                # Deactivated when its last subscriber left — it has a reader
                # again. A feed an admin paused while others still read it keeps
                # its paused state; is_active is admin-only on PUT /feeds/{id}
                # and resubscribing must not be a side door around that.
                feed.is_active = True
                db.add(feed)
            await db.flush()
            # The newly subscribed feed is missing from the cached unread map
            await _invalidate_unread_cache(user.id)
            resp = FeedResponse.model_validate(feed)
            resp.per_user = True
            return resp
        raise AppError(code="conflict", message="A feed with this URL already exists", status_code=409)

    # Extended adapters (github_repo, etc.) skip URL discovery
    if request.feed_type and request.feed_type in _EXTENDED_FEED_TYPES:
        adapter_config = strip_client_keys(request.adapter_config) or {}
        if request.feed_type == "telegram":
            adapter_config = _normalize_telegram_config(adapter_config)
        if request.feed_type == "bluesky":
            adapter_config = _encrypt_bluesky_app_password(adapter_config)
            await _validate_bluesky_author_entity(adapter_config, db)
        defaults = _EXTENDED_FEED_DEFAULTS.get(request.feed_type, {})
        default_interval = defaults.get("interval", 30)
        default_relevance = defaults.get("relevance_rating")
        feed = Feed(
            title=request.custom_title or request.url,
            url=request.url,
            feed_type=request.feed_type,
            fetch_interval_minutes=request.fetch_interval_minutes or default_interval,
            adapter_config=adapter_config,
            intel_extraction_mode=request.intel_extraction_mode or "selective",
            auto_extract_on_ingest=request.auto_extract_on_ingest or False,
            extract_detection_rules=request.extract_detection_rules or False,
            extract_tools=True if request.extract_tools is None else request.extract_tools,
            category_id=request.category_id,
            custom_title=request.custom_title,
            relevance_rating=default_relevance,
        )
        db.add(feed)
        await db.flush()
    else:
        # Standard feeds: discover via URL
        discovered = await discover_feed(request.url)
        if not discovered:
            raise AppError(
                code="unprocessable",
                message="Could not find a valid feed at this URL",
                status_code=422,
            )

        adapter_config = {}
        # Shorts are noise for an intel feed, so the per-user default is on
        # unless the user switched it off (Settings → Feeds).
        if discovered.feed_type == "youtube" and (user.settings or {}).get("youtube_exclude_shorts_default", True):
            adapter_config["exclude_shorts"] = True

        feed = Feed(
            title=discovered.title or request.url,
            url=discovered.url,
            feed_type=discovered.feed_type,
            description=discovered.description,
            fetch_interval_minutes=request.fetch_interval_minutes or 30,
            adapter_config=adapter_config,
            intel_extraction_mode=request.intel_extraction_mode or "selective",
            auto_extract_on_ingest=request.auto_extract_on_ingest or False,
            extract_detection_rules=request.extract_detection_rules or False,
            extract_tools=True if request.extract_tools is None else request.extract_tools,
            category_id=request.category_id,
            custom_title=request.custom_title,
        )
        db.add(feed)
        await db.flush()

    # Keep the subscriptions table consistent regardless of the flag: with it
    # on, only the creator sees the new feed; with it off everyone does (so a
    # later flag flip doesn't orphan feeds added in the meantime).
    if enabled:
        await ensure_subscription(db, user.id, feed.id)
    else:
        await subscribe_all_users(db, feed.id)
    await db.flush()

    # Trigger initial fetch via Celery
    from app.workers.feed_tasks import fetch_feed

    fetch_feed.delay(str(feed.id))

    resp = FeedResponse.model_validate(feed)
    resp.per_user = enabled
    return resp


@router.post("/github-repo/bulk-setup")
async def bulk_setup_github_repos(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create feeds for all pre-configured detection rule repositories.

    Skips repos that already exist.  Automatically creates a
    "GitHub Repos" category and assigns all new feeds to it.
    Returns a summary of created and skipped feeds.
    """
    from app.models.category import Category
    from app.services.github_repo_templates import get_template_feed_configs

    configs = get_template_feed_configs()
    created = []
    skipped = []

    # Find or create the "GitHub Repos" category
    cat_result = await db.execute(
        select(Category).where(
            Category.name == "GitHub Repos",
        )
    )
    category = cat_result.scalar_one_or_none()
    if not category:
        category = Category(created_by=user.id, name="GitHub Repos")
        db.add(category)
        await db.flush()

    for cfg in configs:
        # Check if feed already exists by URL
        result = await db.execute(select(Feed).where(Feed.url == cfg["url"]))
        feed = result.scalar_one_or_none()

        if feed:
            # Move to GitHub Repos category if uncategorized
            if feed.category_id is None:
                feed.category_id = category.id
                db.add(feed)
            skipped.append({"url": cfg["url"], "title": cfg["custom_title"], "reason": "already_exists"})
            continue
        else:
            # Create the feed
            feed = Feed(
                title=cfg["custom_title"],
                url=cfg["url"],
                feed_type=cfg["feed_type"],
                fetch_interval_minutes=cfg["fetch_interval_minutes"],
                adapter_config=cfg["adapter_config"],
                intel_extraction_mode=cfg["intel_extraction_mode"],
                category_id=category.id,
            )
            db.add(feed)
            await db.flush()
            if await subscriptions_enabled(db):
                await ensure_subscription(db, user.id, feed.id)
            else:
                await subscribe_all_users(db, feed.id)
            await db.flush()

        # Trigger initial fetch
        from app.workers.feed_tasks import fetch_feed

        fetch_feed.delay(str(feed.id))

        created.append({"url": cfg["url"], "title": cfg["custom_title"], "feed_id": str(feed.id)})

    # Also move any other uncategorized github_repo feeds into this category
    orphan_result = await db.execute(
        select(Feed).where(
            Feed.category_id.is_(None),
            Feed.feed_type == "github_repo",
        )
    )
    for feed in orphan_result.scalars().all():
        feed.category_id = category.id
        db.add(feed)

    return {
        "created": created,
        "skipped": skipped,
        "total_created": len(created),
        "total_skipped": len(skipped),
        "category_id": str(category.id),
        "category_name": category.name,
    }


@router.get("/github-repo/templates")
async def list_github_repo_templates(
    user: User = Depends(get_current_user),
):
    """List available pre-configured detection repository templates."""
    from app.services.github_repo_templates import DETECTION_REPO_TEMPLATES

    return {
        "templates": [
            {
                "owner": t["owner"],
                "repo": t["repo"],
                "label": t["label"],
                "description": t["description"],
                "paths": t["paths"],
                "content_types": t["content_types"],
                "url": f"https://github.com/{t['owner']}/{t['repo']}",
            }
            for t in DETECTION_REPO_TEMPLATES
        ]
    }


@router.post("/bluesky/resolve-feed-url")
async def resolve_bluesky_feed_url(
    request: dict = Body(
        ..., json_schema_extra={"example": {"url": "https://bsky.app/profile/infosec.exchange/feed/aaabbbcccddde"}}
    ),
    user: User = Depends(get_current_user),
):
    """Resolve a bsky.app custom feed URL to its at:// URI.

    Expects {"url": "https://bsky.app/profile/<handle>/feed/<rkey>"} and returns
    {"feed_uri": "at://<did>/app.bsky.feed.generator/<rkey>", "did": ..., "handle": ...}.
    """
    import re as _re

    url = (request or {}).get("url", "").strip()
    match = _re.match(r"https://bsky\.app/profile/([^/]+)/feed/([^/?#]+)", url)
    if not match:
        raise AppError(
            code="invalid_url",
            message="Expected https://bsky.app/profile/<handle>/feed/<rkey>",
            status_code=400,
        )
    handle, rkey = match.group(1), match.group(2)
    import httpx as _httpx

    resolve_url = "https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle"
    try:
        async with _httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(resolve_url, params={"handle": handle})
        if resp.status_code != 200:
            raise AppError(
                code="resolve_failed",
                message=f"Could not resolve Bluesky handle {handle}",
                status_code=400,
            )
        did = resp.json().get("did")
    except _httpx.HTTPError as e:
        raise AppError(code="resolve_failed", message=f"Network error: {e}", status_code=502) from e
    if not did:
        raise AppError(
            code="resolve_failed",
            message=f"Bluesky did not return a DID for {handle}",
            status_code=400,
        )
    return {"feed_uri": f"at://{did}/app.bsky.feed.generator/{rkey}", "did": did, "handle": handle}


@router.put("/youtube/exclude-shorts")
async def bulk_exclude_shorts(
    request: BulkExcludeShortsRequest,
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Set exclude_shorts on all YouTube feeds."""
    result = await db.execute(select(Feed).where(Feed.feed_type == "youtube"))
    feeds = result.scalars().all()

    updated = 0
    for feed in feeds:
        config = dict(feed.adapter_config or {})
        if config.get("exclude_shorts") == request.exclude_shorts:
            continue
        config["exclude_shorts"] = request.exclude_shorts
        feed.adapter_config = config
        db.add(feed)
        updated += 1

    await db.flush()
    return {"updated": updated}


@router.put("/category/{category_id}/intel-mode")
async def bulk_set_intel_mode(
    category_id: uuid.UUID = Path(..., description="UUID of the category whose feeds to update"),
    request: BulkIntelModeRequest = Body(...),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Set intel_extraction_mode on all feeds in a category."""
    result = await db.execute(select(Feed).where(Feed.category_id == category_id))
    feeds = result.scalars().all()

    updated = 0
    for feed in feeds:
        if feed.intel_extraction_mode == request.intel_extraction_mode:
            continue
        feed.intel_extraction_mode = request.intel_extraction_mode
        db.add(feed)
        updated += 1

    await db.flush()
    return {"updated": updated}


@router.put("/category/{category_id}/bulk-update")
async def bulk_update_category_feeds(
    category_id: uuid.UUID = Path(..., description="UUID of the category whose feeds to update"),
    request: BulkCategoryUpdateRequest = Body(...),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Bulk update settings on all feeds in a category."""
    result = await db.execute(select(Feed).where(Feed.category_id == category_id))
    feeds = result.scalars().all()

    updated = 0
    for feed in feeds:
        changed = False

        if request.fetch_interval_minutes is not None and feed.fetch_interval_minutes != request.fetch_interval_minutes:
            feed.fetch_interval_minutes = request.fetch_interval_minutes
            changed = True
        if request.intel_extraction_mode is not None and feed.intel_extraction_mode != request.intel_extraction_mode:
            feed.intel_extraction_mode = request.intel_extraction_mode
            changed = True
        if request.ai_analysis_enabled is not None and feed.ai_analysis_enabled != request.ai_analysis_enabled:
            feed.ai_analysis_enabled = request.ai_analysis_enabled
            changed = True
        if request.auto_extract_on_ingest is not None and feed.auto_extract_on_ingest != request.auto_extract_on_ingest:
            feed.auto_extract_on_ingest = request.auto_extract_on_ingest
            changed = True
        if (
            request.extract_detection_rules is not None
            and feed.extract_detection_rules != request.extract_detection_rules
        ):
            feed.extract_detection_rules = request.extract_detection_rules
        if request.extract_tools is not None and feed.extract_tools != request.extract_tools:
            feed.extract_tools = request.extract_tools
            changed = True
        # Assessment fields stamp the review date, exactly as the single-feed
        # PUT does. Without this, rating a whole category left every feed
        # reading "never assessed" on its own Overview.
        assessed = False
        for field in ("reliability_rating", "timeliness_rating", "relevance_rating"):
            value = getattr(request, field)
            if value is not None and getattr(feed, field) != value:
                setattr(feed, field, value)
                assessed = True
                changed = True
        if assessed:
            feed.last_reviewed_at = datetime.now(UTC)

        # Retention is now on Feed directly
        if request.clear_retention:
            if feed.retention_days is not None:
                feed.retention_days = None
                changed = True
        elif request.retention_days is not None and feed.retention_days != request.retention_days:
            feed.retention_days = request.retention_days
            changed = True

        if changed:
            db.add(feed)
            updated += 1

    await db.flush()
    return {"updated": updated}


@router.get("/health")
async def get_feed_health(
    stale_days: int = Query(
        7, ge=1, le=90, description="Days without a successful fetch before a feed counts as stale"
    ),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Feed health overview — healthy, stale, erroring, and disabled feed counts.

    For admins each listed feed also carries a `reach` block (who subscribes to
    it and how many of them muted it), so a broken feed can be triaged by how
    many analysts it actually costs. Non-admins get the counts without the
    roster — other people's subscriptions aren't theirs to see.
    """
    from datetime import timedelta

    now = datetime.now(UTC)
    stale_cutoff = now - timedelta(days=stale_days)

    # Get all feeds
    result = await db.execute(select(Feed))
    feeds = result.scalars().all()

    healthy = []
    stale = []
    erroring = []
    disabled = []
    dead = []
    empty = []

    for feed in feeds:
        feed_info = {
            "id": str(feed.id),
            "title": feed.title,
            "feed_type": feed.feed_type,
            "last_fetched_at": feed.last_fetched_at.isoformat() if feed.last_fetched_at else None,
            "error_count": feed.error_count,
            "last_error": feed.last_error,
            "is_active": feed.is_active,
            "reliability_rating": feed.reliability_rating,
            "error_since": feed.error_since.isoformat() if feed.error_since else None,
            "failing_for_days": (now - feed.error_since).days if feed.error_since else None,
            "auto_paused_at": feed.auto_paused_at.isoformat() if feed.auto_paused_at else None,
            "pause_reason": pause_reason(feed),
            "health_warning": health_warning(feed),
        }

        if not feed.is_active:
            # Dead = paused by the health check (a 4xx streak past the window),
            # distinct from a feed someone switched off on purpose.
            (dead if feed.auto_paused_at else disabled).append(feed_info)
        elif feed.error_count and feed.error_count >= 3:
            erroring.append(feed_info)
        elif feed_info["health_warning"]:
            # Answers 200 but has stopped delivering items (a feed URL that
            # redirects to a landing page, or an empty channel).
            empty.append(feed_info)
        elif not feed.last_fetched_at or feed.last_fetched_at < stale_cutoff:
            feed_info["days_since_fetch"] = (now - feed.last_fetched_at).days if feed.last_fetched_at else None
            stale.append(feed_info)
        else:
            healthy.append(feed_info)

    listed = stale + erroring + disabled + dead + empty
    await _attach_reach(db, listed, user)

    return {
        "summary": {
            "healthy": len(healthy),
            "stale": len(stale),
            "erroring": len(erroring),
            "disabled": len(disabled),
            "dead": len(dead),
            "empty": len(empty),
            "total": len(feeds),
        },
        "stale_feeds": stale,
        "erroring_feeds": erroring,
        "disabled_feeds": disabled,
        "dead_feeds": dead,
        "empty_feeds": empty,
    }


async def _attach_reach(db: AsyncSession, feed_infos: list[dict], user: User) -> None:
    """Add a `reach` block to each feed dict, in place. Admins only."""
    if user.role != "admin" or not feed_infos:
        return
    from app.services.feed_visibility import reach_payload, subscriber_map

    subs = await subscriber_map(db, [uuid.UUID(f["id"]) for f in feed_infos])
    for info in feed_infos:
        info["reach"] = reach_payload(subs.get(uuid.UUID(info["id"]), []))


@router.get("/health/failing")
async def get_failing_feeds(
    threshold: int = Query(5, ge=1, le=100, description="Minimum consecutive fetch errors for a feed to be included"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Active feeds currently failing with >= threshold consecutive fetch errors.

    error_count is reset to 0 on every successful fetch, so it counts
    consecutive failures. High-value feeds (reliability A/B) are flagged and
    sorted first so alerting UIs can highlight them.
    """
    result = await db.execute(
        select(Feed).where(Feed.is_active.is_(True), Feed.error_count >= threshold).order_by(Feed.error_count.desc())
    )
    feeds = result.scalars().all()

    items = [
        {
            "id": str(feed.id),
            "title": feed.custom_title or feed.title,
            "feed_type": feed.feed_type,
            "error_count": feed.error_count,
            "last_error": feed.last_error,
            "last_fetched_at": feed.last_fetched_at.isoformat() if feed.last_fetched_at else None,
            "is_high_value": feed.reliability_rating in ("A", "B"),
        }
        for feed in feeds
    ]
    items.sort(key=lambda f: (not f["is_high_value"], -f["error_count"]))
    await _attach_reach(db, items, user)

    return {
        "threshold": threshold,
        "total": len(items),
        "high_value_count": sum(1 for f in items if f["is_high_value"]),
        "feeds": items,
    }


@router.post("/{feed_id}/resume")
async def resume_feed(
    feed_id: uuid.UUID = Path(..., description="UUID of the feed to resume"),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Re-activate a feed the health check auto-paused (or an admin paused)
    and clear its failure streak, so the next poll starts from a clean slate.

    Pool-level and admin-only: with per-user subscriptions on, `is_active`
    on PUT /feeds/{id} writes only the caller's own pause, which is what
    made a dead feed impossible to bring back from the Feeds view.
    """
    feed = await db.get(Feed, feed_id)
    if not feed:
        raise AppError(code="not_found", message="Feed not found", status_code=404)
    feed.is_active = True
    feed.auto_paused_at = None
    clear_pause(feed)
    feed.error_count = 0
    feed.last_error = None
    feed.error_since = None
    db.add(feed)
    await db.commit()
    return {"id": str(feed.id), "is_active": True}


@router.get("/{feed_id}/analytics")
async def get_feed_analytics(
    feed_id: uuid.UUID = Path(..., description="UUID of the feed to analyze"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Compute source reliability analytics for a feed."""
    # Verify feed exists
    feed = await db.get(Feed, feed_id)
    if not feed:
        raise AppError(code="not_found", message="Feed not found", status_code=404)

    from app.intelligence.source_analytics import compute_feed_analytics

    analytics = await compute_feed_analytics(feed_id, db)
    if not analytics:
        raise AppError(code="not_found", message="Feed not found", status_code=404)
    return analytics


@router.get("/{feed_id}", response_model=FeedResponse)
async def get_feed(
    feed_id: uuid.UUID = Path(..., description="UUID of the feed"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get a single feed by id. Returns 404 if the feed does not exist."""
    feed = await db.get(Feed, feed_id)
    if not feed:
        raise AppError(code="not_found", message="Feed not found", status_code=404)
    resp = FeedResponse.model_validate(feed)
    if await subscriptions_enabled(db):
        sub = await get_subscription(db, user.id, feed.id)
        if sub:
            resp.is_muted = sub.is_muted
        resp.per_user = True
    return resp


@router.put("/{feed_id}", response_model=FeedResponse)
async def update_feed(
    feed_id: uuid.UUID = Path(..., description="UUID of the feed to update"),
    request: FeedUpdateRequest = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Partially update a feed; only the fields present in the request are changed.

    Changing the URL resets fetch state (etag, errors) and returns 409 on duplicates.
    Bluesky app passwords are encrypted at rest; setting any reliability/timeliness/
    relevance rating or analyst notes stamps last_reviewed_at.
    """
    feed = await db.get(Feed, feed_id)
    if not feed:
        raise AppError(code="not_found", message="Feed not found", status_code=404)

    # The feed row is shared infrastructure: its URL, adapter config (incl.
    # credentials), fetch cadence, retention and extraction wiring affect every
    # user and the workers. Only curation fields (title, category, mute,
    # source ratings, analyst notes) are open to any analyst.
    _ADMIN_FEED_FIELDS = (
        "url",
        "feed_type",
        "fetch_interval_minutes",
        "retention_days",
        "adapter_config",
        "exclude_shorts",
        "intel_extraction_mode",
        "ai_analysis_enabled",
        "auto_extract_on_ingest",
        "extract_detection_rules",
        "extract_tools",
    )
    # `model_fields_set` rather than a None check: for the nullable fields below,
    # None is a real value ("uncategorized", "keep forever") and must not be
    # mistaken for "absent" — in either direction.
    sent = request.model_fields_set
    enabled = await subscriptions_enabled(db)
    if user.role != "admin":
        touched = [f for f in _ADMIN_FEED_FIELDS if f in sent]
        # Pause is personal once subscriptions are on, so anyone may set it.
        # With the flag off it writes the one shared column and stays admin-only.
        if "is_active" in sent and not enabled:
            touched.append("is_active")
        if touched:
            raise AppError(
                code="forbidden",
                message=f"Only an admin can change feed infrastructure settings ({', '.join(touched)})",
                status_code=403,
            )

    if request.url is not None:
        clean_url = request.url.strip()
        if clean_url != feed.url:
            existing = await db.execute(select(Feed).where(Feed.url == clean_url))
            if existing.scalar_one_or_none():
                raise AppError(code="duplicate_url", message="A feed with this URL already exists", status_code=409)
            feed.url = clean_url
            feed.etag = None
            feed.last_modified = None
            feed.error_count = 0
            feed.last_error = None
            feed.error_since = None
    if request.custom_title is not None:
        feed.custom_title = request.custom_title
    if "category_id" in sent:
        # None = move to Uncategorized. The old `is not None` guard dropped it,
        # so a feed could be filed but never unfiled from this endpoint.
        feed.category_id = request.category_id
    per_user_mute: bool | None = None
    per_user_paused: bool | None = None
    if request.is_muted is not None:
        if enabled:
            # Mute is personal: write the caller's subscription row, not the pool
            sub = await get_subscription(db, user.id, feed.id)
            if sub:
                sub.is_muted = request.is_muted
                db.add(sub)
            else:
                await ensure_subscription(db, user.id, feed.id, is_muted=request.is_muted)
            per_user_mute = request.is_muted
        else:
            feed.is_muted = request.is_muted
    if request.is_active is not None:
        if enabled:
            # Pause is personal: write the caller's subscription row, not the pool
            sub = await get_subscription(db, user.id, feed.id)
            if sub:
                sub.is_paused = not request.is_active
                db.add(sub)
            else:
                await ensure_subscription(db, user.id, feed.id, is_paused=not request.is_active)
            per_user_paused = not request.is_active
        else:
            feed.is_active = request.is_active
            if request.is_active:
                # Turned back on by a person: the health check's pause is over.
                feed.auto_paused_at = None
                clear_pause(feed)
    if request.fetch_interval_minutes is not None:
        feed.fetch_interval_minutes = request.fetch_interval_minutes
    if request.exclude_shorts is not None and feed.feed_type == "youtube":
        config = dict(feed.adapter_config or {})
        config["exclude_shorts"] = request.exclude_shorts
        feed.adapter_config = config
    if request.adapter_config is not None:
        old_config = dict(feed.adapter_config or {})
        config = dict(old_config)
        # fetch_health is server-owned; a modal echoing back a stale copy
        # must not overwrite what the fetcher learned since.
        config.update(strip_client_keys(request.adapter_config))
        if feed.feed_type == "telegram":
            config = _normalize_telegram_config(config)
        # Bluesky: encrypt new plaintext app_password; preserve existing if blank/masked.
        if feed.feed_type == "bluesky":
            new_pw = request.adapter_config.get("app_password")
            if new_pw is None or new_pw == "" or (isinstance(new_pw, str) and set(new_pw) == {"•"}):
                if old_config.get("app_password"):
                    config["app_password"] = old_config["app_password"]
                else:
                    config.pop("app_password", None)
            elif not (isinstance(new_pw, str) and new_pw.startswith("gAAAAA")):
                from app.core.encryption import encrypt_value

                config["app_password"] = encrypt_value(new_pw)
            await _validate_bluesky_author_entity(config, db)
        feed.adapter_config = config
        # If backfill_days changed on a github_repo feed, reset fetch state
        # so the next refresh does a fresh backfill with the new window
        if feed.feed_type == "github_repo" and config.get("backfill_days") != old_config.get("backfill_days"):
            feed.last_fetched_at = None
            config.pop("last_commit_sha", None)
            feed.adapter_config = config
    if request.feed_type is not None:
        from app.adapters import known_feed_types

        allowed = known_feed_types()
        if request.feed_type not in allowed:
            raise AppError(
                code="invalid_feed_type",
                message=f"Feed type must be one of: {', '.join(sorted(allowed))}",
                status_code=400,
            )
        feed.feed_type = request.feed_type
    if "retention_days" in sent:
        # None or <= 0 = keep forever. Same bug as category_id: the previous
        # guard meant a feed on a 90-day window could never be set back to
        # unlimited, which is why the bulk-category path needed `clear_retention`.
        feed.retention_days = request.retention_days if (request.retention_days or 0) > 0 else None

    # Source reliability fields
    reliability_changed = False
    if request.reliability_rating is not None:
        feed.reliability_rating = request.reliability_rating
        reliability_changed = True
    if request.timeliness_rating is not None:
        feed.timeliness_rating = request.timeliness_rating
        reliability_changed = True
    if request.relevance_rating is not None:
        feed.relevance_rating = request.relevance_rating
        reliability_changed = True
    if request.analyst_notes is not None:
        feed.analyst_notes = request.analyst_notes
        reliability_changed = True
    if reliability_changed:
        feed.last_reviewed_at = datetime.now(UTC)

    if request.intel_extraction_mode is not None:
        feed.intel_extraction_mode = request.intel_extraction_mode
    if request.ai_analysis_enabled is not None:
        feed.ai_analysis_enabled = request.ai_analysis_enabled
    if request.auto_extract_on_ingest is not None:
        feed.auto_extract_on_ingest = request.auto_extract_on_ingest
    if request.extract_detection_rules is not None:
        feed.extract_detection_rules = request.extract_detection_rules
    if request.extract_tools is not None:
        feed.extract_tools = request.extract_tools

    db.add(feed)
    await db.flush()

    resp = FeedResponse.model_validate(feed)
    if enabled:
        sub = await get_subscription(db, user.id, feed.id)
        resp.is_muted = per_user_mute if per_user_mute is not None else (sub.is_muted if sub else resp.is_muted)
        if per_user_paused is not None:
            resp.is_active = not per_user_paused
        elif sub:
            resp.is_active = feed.is_active and not sub.is_paused
        resp.per_user = True
    return resp


@router.get("/{feed_id}/entries", response_model=CursorPaginatedResponse[EntryResponse])
async def list_feed_entries(
    feed_id: uuid.UUID = Path(..., description="UUID of the feed whose entries to list"),
    is_read: bool | None = Query(None, description="Filter by read state for the current user"),
    is_starred: bool | None = Query(None, description="Filter by starred state for the current user"),
    is_bookmarked: bool | None = Query(None, description="Filter by bookmarked state for the current user"),
    sort: str = Query("newest", description="Sort order: 'newest' or 'oldest' by published date"),
    limit: int = Query(50, ge=1, le=500, description="Maximum number of entries per page"),
    cursor: str | None = Query(None, description="Opaque cursor from a previous page for pagination"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List entries for a specific feed."""
    # Verify feed exists
    feed = await db.get(Feed, feed_id)
    if not feed:
        raise AppError(code="not_found", message="Feed not found", status_code=404)

    from app.api.entries import _entry_page

    # _entry_page, not the route function: unpassed arguments on a route would
    # arrive as FastAPI Query objects rather than their defaults.
    return await _entry_page(
        db,
        user,
        feed_id=feed_id,
        is_read=is_read,
        is_starred=is_starred,
        is_bookmarked=is_bookmarked,
        sort=sort,
        limit=limit,
        cursor=cursor,
    )


@router.delete("/{feed_id}", status_code=204)
async def delete_feed(
    feed_id: uuid.UUID = Path(..., description="UUID of the feed to delete"),
    purge: bool = Query(False, description="Physically delete the feed and its entries (admin only)"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Remove a feed.

    With per-user subscriptions on, this unsubscribes the caller; the feed and
    its entries stay for other subscribers, and a feed nobody subscribes to
    anymore stops fetching. Admins can pass purge=true to physically delete the
    feed and its entries. With subscriptions off, deletion is the physical one
    and admin-only.
    """
    feed = await db.get(Feed, feed_id)
    if not feed:
        raise AppError(code="not_found", message="Feed not found", status_code=404)

    enabled = await subscriptions_enabled(db)
    if not enabled or purge:
        if user.role != "admin":
            raise AppError(code="forbidden", message="Admin access required", status_code=403)
        # Remove entries from search index before cascade delete
        from app.services.meilisearch_client import delete_entries_by_feed

        delete_entries_by_feed(feed_id)
        await db.delete(feed)
        await db.flush()
        return

    sub = await get_subscription(db, user.id, feed.id)
    if sub:
        await db.delete(sub)
        await db.flush()
        # The cached unread map still lists this feed; a 120s-stale sidebar
        # count after an explicit unsubscribe reads as the action not working.
        await _invalidate_unread_cache(user.id)

    if await _subscriber_count(db, feed.id) == 0 and feed.is_active:
        # Nobody reads it anymore — stop fetching but keep the entries
        feed.is_active = False
        db.add(feed)
        await db.flush()


async def _subscriber_count(db: AsyncSession, feed_id: uuid.UUID) -> int:
    """How many users currently subscribe to a feed."""
    from app.models.user_feed_subscription import UserFeedSubscription

    result = await db.execute(
        select(func.count()).select_from(UserFeedSubscription).where(UserFeedSubscription.feed_id == feed_id)
    )
    return result.scalar() or 0


async def _invalidate_unread_cache(user_id: uuid.UUID) -> None:
    """Drop a user's cached per-feed unread counts (see list_feeds)."""
    try:
        from app.services.redis_client import get_redis

        r = await get_redis()
        await r.delete(f"feed_unreads:{user_id}")
    except Exception:
        pass


# --------------------------------------------------------------------------- subscribers
# Admin-side control over who reads what. Only meaningful with per-user
# subscriptions on — with the flag off everyone sees every feed regardless — but
# the rows are maintained either way, so pushing a feed now survives a later flip.


@router.get("/{feed_id}/subscribers")
async def list_feed_subscribers(
    feed_id: uuid.UUID = Path(..., description="UUID of the feed"),
    _admin: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Who reads this feed, and who doesn't. Admin only.

    `subscribers` carries each reader's personal mute state; `non_subscribers`
    is everyone the feed could still be pushed to.
    """
    feed = await db.get(Feed, feed_id)
    if not feed:
        raise AppError(code="not_found", message="Feed not found", status_code=404)

    from app.services.feed_visibility import subscriber_map

    subs = (await subscriber_map(db, [feed_id])).get(feed_id, [])
    subscribed_ids = {s["user_id"] for s in subs}

    everyone = (
        await db.execute(select(User.id, User.username).where(User.role != "system").order_by(User.username))
    ).all()
    return {
        "feed_id": str(feed_id),
        "per_user_active": await subscriptions_enabled(db),
        "subscriber_count": len(subs),
        "muted_count": sum(1 for s in subs if s["is_muted"]),
        "subscribers": subs,
        "non_subscribers": [
            {"user_id": str(uid), "username": uname} for uid, uname in everyone if str(uid) not in subscribed_ids
        ],
    }


@router.post("/{feed_id}/subscribers")
async def push_feed_to_users(
    feed_id: uuid.UUID = Path(..., description="UUID of the feed to push"),
    request: FeedPushRequest | None = None,
    _admin: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Subscribe users to a feed on their behalf. Admin only.

    Omit `user_ids` to push to every human account — the "this feed should be
    on everyone's list" case. Already-subscribed users are left alone (their
    mute state is preserved), so this is safe to re-run.
    """
    feed = await db.get(Feed, feed_id)
    if not feed:
        raise AppError(code="not_found", message="Feed not found", status_code=404)

    from app.services.feed_visibility import ensure_subscription, subscribe_all_users

    before = await _subscriber_count(db, feed_id)
    requested = request.user_ids if request else None
    if requested is None:
        # Push to everyone: the cache bust has to cover every human account, so
        # resolve them rather than relying on the set-based INSERT's return.
        targets = list((await db.execute(select(User.id).where(User.role != "system"))).scalars().all())
        await subscribe_all_users(db, feed_id)
    else:
        targets = list(dict.fromkeys(requested))
        if not targets:
            raise AppError(code="invalid_request", message="user_ids was empty", status_code=400)
        valid = set(
            (await db.execute(select(User.id).where(User.id.in_(targets), User.role != "system"))).scalars().all()
        )
        missing = [str(u) for u in targets if u not in valid]
        if missing:
            raise AppError(
                code="not_found",
                message=f"Unknown or non-assignable user(s): {', '.join(missing)}",
                status_code=404,
            )
        for uid in targets:
            await ensure_subscription(db, uid, feed_id)
    await db.flush()

    # A feed the last-unsubscribe rule paused has readers again
    if not feed.is_active and before == 0:
        feed.is_active = True
        db.add(feed)
        await db.flush()

    for uid in targets:
        await _invalidate_unread_cache(uid)

    after = await _subscriber_count(db, feed_id)
    return {
        "feed_id": str(feed_id),
        "added": max(after - before, 0),
        "subscriber_count": after,
        "is_active": feed.is_active,
        "per_user_active": await subscriptions_enabled(db),
    }


@router.delete("/{feed_id}/subscribers/{user_id}", status_code=204)
async def remove_feed_subscriber(
    feed_id: uuid.UUID = Path(..., description="UUID of the feed"),
    user_id: uuid.UUID = Path(..., description="UUID of the user to unsubscribe"),
    _admin: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Unsubscribe a user from a feed on their behalf. Admin only.

    Mirrors what that user's own unsubscribe would do, including pausing a feed
    whose last reader just left.
    """
    from app.models.user_feed_subscription import UserFeedSubscription

    feed = await db.get(Feed, feed_id)
    if not feed:
        raise AppError(code="not_found", message="Feed not found", status_code=404)

    sub = (
        await db.execute(
            select(UserFeedSubscription).where(
                UserFeedSubscription.feed_id == feed_id,
                UserFeedSubscription.user_id == user_id,
            )
        )
    ).scalar_one_or_none()
    if not sub:
        raise AppError(code="not_found", message="That user is not subscribed to this feed", status_code=404)

    await db.delete(sub)
    await db.flush()
    await _invalidate_unread_cache(user_id)

    if await _subscriber_count(db, feed_id) == 0 and feed.is_active:
        feed.is_active = False
        db.add(feed)
        await db.flush()


@router.post("/discover")
async def discover_feed_endpoint(
    request: FeedDiscoverRequest,
    user: User = Depends(get_current_user),
):
    """Discover a feed from a URL without subscribing."""
    result = await discover_feed(request.url)
    if not result:
        raise AppError(code="unprocessable", message="Could not find a valid feed at this URL", status_code=422)
    return result


@router.post("/{feed_id}/refresh")
async def refresh_feed(
    feed_id: uuid.UUID = Path(..., description="UUID of the feed to refresh"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Queue an immediate background fetch of the feed via Celery. Returns 404 if the feed does not exist."""
    # Verify feed exists
    feed = await db.get(Feed, feed_id)
    if not feed:
        raise AppError(code="not_found", message="Feed not found", status_code=404)

    # Queue fetch task
    from app.workers.feed_tasks import fetch_feed

    fetch_feed.delay(str(feed_id))
    return {"message": "Feed refresh queued"}


@router.get("/{feed_id}/pipeline")
async def get_feed_pipeline(
    feed_id: uuid.UUID = Path(..., description="UUID of the feed"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Which stages run for this feed, and what decided each one.

    The edit modal's Pipeline pane reads this so it can say where a value comes
    from. While `pipeline_engine_enabled` is off every stage reads "legacy" and
    the Feed booleans are authoritative; once it is on, a plan at global,
    category or feed scope can override a stage, and the pane has to stop
    presenting its own checkbox as the thing in charge.
    """
    feed = await db.get(Feed, feed_id)
    if not feed:
        raise AppError(code="not_found", message="Feed not found", status_code=404)

    from app.pipeline.plans import explain_feed_plan

    return await explain_feed_plan(db, feed)


@router.get("/{feed_id}/value")
async def get_one_feed_value(
    feed_id: uuid.UUID = Path(..., description="UUID of the feed to score"),
    days: int = Query(90, ge=7, le=365, description="Scoring window in days."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """One feed's intelligence value score, plus its rank among the scored set.

    Scoring runs over every active feed rather than this one alone, because
    "entity introductions" means *first seen anywhere* — scoped to a single
    feed the subquery would count every entity it ever mentioned as an
    introduction and the number would be meaningless. The response is one row
    either way, so the modal fetches kilobytes, not the whole table.
    """
    feed = await db.get(Feed, feed_id)
    if not feed:
        raise AppError(code="not_found", message="Feed not found", status_code=404)

    from app.intelligence.source_analytics import compute_feed_value_scores

    active_ids = [row[0] for row in (await db.execute(select(Feed.id).where(Feed.is_active.is_(True)))).all()]
    # A paused feed is not in the active set but still has a history worth showing.
    if feed_id not in active_ids:
        active_ids.append(feed_id)

    rows = await compute_feed_value_scores(db, feed_ids=active_ids, days=days)
    mine = next((r for r in rows if r["feed_id"] == str(feed_id)), None)
    if mine is None:
        return {"feed_id": str(feed_id), "scored": False}

    ranked = sorted(rows, key=lambda r: r["score"], reverse=True)
    rank = next((i + 1 for i, r in enumerate(ranked) if r["feed_id"] == str(feed_id)), None)
    return {**mine, "scored": True, "rank": rank, "of": len(rows), "days": days}


@router.post("/{feed_id}/full-sync")
async def full_sync_feed(
    feed_id: uuid.UUID = Path(..., description="UUID of the GitHub repo feed to fully sync"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Trigger a full tree sync for a GitHub repo feed.

    Imports ALL matching files from the repo, not just recent changes.
    Use this to backfill the complete rule set from detection rule repos.
    """
    # Verify feed exists and is a github_repo feed
    feed = await db.get(Feed, feed_id)
    if not feed:
        raise AppError(code="not_found", message="Feed not found", status_code=404)

    if feed.feed_type != "github_repo":
        raise AppError(
            code="invalid_request",
            message="Full sync is only available for GitHub repo feeds",
            status_code=400,
        )

    from app.workers.feed_tasks import full_sync_github_feed

    full_sync_github_feed.delay(str(feed_id), str(user.id))
    return {
        "message": f"Full sync queued for {feed.title}",
        "feed_id": str(feed_id),
    }


@router.get("/{feed_id}/full-sync/progress")
async def full_sync_progress(
    feed_id: uuid.UUID = Path(..., description="UUID of the GitHub repo feed being synced"),
    user: User = Depends(get_current_user),
):
    """Check progress of a running full sync for a GitHub repo feed."""
    import redis

    from app.config import settings

    r = redis.from_url(settings.redis_url)
    try:
        data = r.get(f"full_sync:{feed_id}")
        if not data:
            return {"status": "not_running"}
        return json.loads(data)
    finally:
        r.close()
