"""Telegram-specific API endpoints: discovery, health, listener control, link mentions."""

import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, Path, Query
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.exceptions import AppError
from app.core.security import get_current_user
from app.database import get_db
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.telegram_mention import TelegramChannelMention, TelegramLinkMention
from app.models.user import User

logger = logging.getLogger(__name__)
router = APIRouter()


def _telegram_disabled() -> bool:
    return not settings.telegram_api_id or not settings.telegram_api_hash


@router.get("/discover")
async def discover_my_channels(
    session_name: str = Query("", description="Named Telethon session to use; empty for the default session"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """List every broadcast channel the bootstrap account is joined to.

    Annotates each result with `is_subscribed`: true if IntelFeed already has a feed for
    that channel. The frontend uses this to show "Add" buttons only for channels you're
    not already ingesting.
    """
    if _telegram_disabled():
        raise AppError(
            code="telegram_disabled",
            message="Telegram is not configured on this server.",
            status_code=503,
        )

    from app.adapters.telegram import TelegramAdapter

    try:
        adapter = TelegramAdapter()
        dialogs = await adapter.list_my_dialogs(session_name=session_name)
    except RuntimeError as e:
        raise AppError(
            code="telegram_discovery_failed",
            message=str(e),
            status_code=502,
        ) from e

    # Build a set of (channel_id) and (username) already subscribed
    feed_rows = await db.execute(select(Feed).where(Feed.feed_type == "telegram"))
    subscribed_channel_ids: set[int] = set()
    subscribed_usernames: set[str] = set()
    feed_id_by_channel: dict[int, str] = {}
    for f in feed_rows.scalars().all():
        cfg = f.adapter_config or {}
        cid = cfg.get("channel_id")
        if cid is not None:
            try:
                cid_int = int(cid)
                subscribed_channel_ids.add(cid_int)
                feed_id_by_channel[cid_int] = str(f.id)
            except (TypeError, ValueError):
                pass
        uname = (cfg.get("channel_username") or cfg.get("channel") or "").lstrip("@").lower()
        if uname:
            subscribed_usernames.add(uname)

    items = []
    for d in dialogs:
        cid = d["channel_id"]
        uname = (d.get("username") or "").lower()
        is_sub = cid in subscribed_channel_ids or (uname and uname in subscribed_usernames)
        items.append(
            {
                **d,
                "is_subscribed": is_sub,
                "feed_id": feed_id_by_channel.get(cid),
            }
        )

    # Sort: unsubscribed first (so the operator's eye lands on the "to add" candidates),
    # then by subscriber count desc.
    items.sort(key=lambda x: (x["is_subscribed"], -1 * (x.get("subscribers") or 0)))

    return {
        "items": items,
        "total": len(items),
        "subscribed_count": sum(1 for it in items if it["is_subscribed"]),
        "unsubscribed_count": sum(1 for it in items if not it["is_subscribed"]),
    }


@router.get("/feeds/{feed_id}/health")
async def telegram_feed_health(
    feed_id: uuid.UUID = Path(..., description="UUID of the Telegram feed"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Telegram-specific health snapshot for a single feed.

    Includes: resolved channel id/username, last_seen_id, last_error, recent flood-wait
    state, edited / soft-deleted entry counts over the last 7 days, session name + auth
    status, and (best-effort) live subscriber count from Telethon.
    """
    feed = await db.get(Feed, feed_id)
    if not feed or feed.feed_type != "telegram":
        raise AppError(
            code="not_found",
            message="Feed not found or not a telegram feed",
            status_code=404,
        )

    cfg = feed.adapter_config or {}
    cutoff = datetime.now(UTC) - timedelta(days=7)

    # Edited entries — those whose metadata_.edited_at is set
    edited_q = await db.execute(
        select(func.count())
        .select_from(Entry)
        .where(Entry.feed_id == feed.id)
        .where(Entry.published_at >= cutoff)
        .where(Entry.metadata_["edited_at"].isnot(None))
    )
    edited_count = int(edited_q.scalar_one() or 0)

    # Soft-deleted entries — telegram_deleted_at set
    deleted_q = await db.execute(
        select(func.count())
        .select_from(Entry)
        .where(Entry.feed_id == feed.id)
        .where(Entry.published_at >= cutoff)
        .where(Entry.metadata_["telegram_deleted_at"].isnot(None))
    )
    deleted_count = int(deleted_q.scalar_one() or 0)

    # Total entries on this feed (last 7 days) for context
    total_q = await db.execute(
        select(func.count()).select_from(Entry).where(Entry.feed_id == feed.id).where(Entry.published_at >= cutoff)
    )
    total_recent = int(total_q.scalar_one() or 0)

    # Best-effort live channel info — wrap in try/except so a flood wait doesn't break the panel
    live: dict[str, Any] = {"available": False}
    if not _telegram_disabled():
        try:
            from app.adapters.telegram import TelegramAdapter

            adapter = TelegramAdapter()
            client = await adapter._get_client(session_name=cfg.get("session_name") or "")
            entity_ref: Any = cfg.get("channel_id") or cfg.get("channel")
            if entity_ref:
                entity = await client.get_entity(entity_ref)
                live = {
                    "available": True,
                    "title": getattr(entity, "title", None),
                    "subscribers": getattr(entity, "participants_count", None),
                    "verified": bool(getattr(entity, "verified", False)),
                    "scam": bool(getattr(entity, "scam", False)),
                    "fake": bool(getattr(entity, "fake", False)),
                }
        except Exception as exc:
            logger.debug("Telegram health probe failed for feed %s: %s", feed.id, exc)
            live = {"available": False, "error": str(exc)[:200]}

    # Detect flood-wait signal from the most recent fetch
    last_error = feed.last_error or ""
    flood_wait_seconds: int | None = None
    if "flood wait" in last_error.lower():
        # Parse "Telegram flood wait NNNs" if present
        import re

        m = re.search(r"flood wait (\d+)", last_error, re.IGNORECASE)
        if m:
            flood_wait_seconds = int(m.group(1))

    return {
        "feed_id": str(feed.id),
        "title": feed.title,
        "is_active": feed.is_active,
        "last_fetched_at": feed.last_fetched_at.isoformat() if feed.last_fetched_at else None,
        "fetch_interval_minutes": feed.fetch_interval_minutes,
        "error_count": feed.error_count,
        "last_error": feed.last_error,
        "channel": {
            "channel_id": cfg.get("channel_id"),
            "channel_username": cfg.get("channel_username"),
            "configured_handle": cfg.get("channel"),
        },
        "session": {
            "name": cfg.get("session_name") or "(default)",
        },
        "watermark": {
            "last_seen_id": cfg.get("last_seen_id"),
        },
        "attribution": {
            "threat_actor_id": cfg.get("threat_actor_id"),
            "campaign_id": cfg.get("campaign_id"),
        },
        "media": {
            "include_media": bool(cfg.get("include_media", True)),
            "extract_forwards": bool(cfg.get("extract_forwards", True)),
        },
        "realtime_enabled": bool(cfg.get("realtime", False)),
        "recent_7d": {
            "total": total_recent,
            "edited": edited_count,
            "deleted": deleted_count,
        },
        "flood_wait_seconds": flood_wait_seconds,
        "live": live,
    }


@router.get("/listener/status")
async def listener_status(
    _user: User = Depends(get_current_user),
) -> dict:
    """Report whether the realtime listener process has checked in recently.

    The listener writes its heartbeat to Redis under `intelfeed:telegram_listener:heartbeat`
    every 30 seconds. Absence of that key means the process is down — fall back to polling.
    """
    try:
        from app.services.redis_client import get_redis

        r = await get_redis()
        hb = await r.get("intelfeed:telegram_listener:heartbeat")
        subs = await r.get("intelfeed:telegram_listener:subscriptions")
    except Exception as exc:
        return {"running": False, "error": str(exc)[:200]}

    if not hb:
        return {"running": False, "last_heartbeat": None, "subscribed_channels": 0}

    try:
        last = float(hb)
    except (ValueError, TypeError):
        return {"running": False, "last_heartbeat": None}

    now = datetime.now(UTC).timestamp()
    age = now - last
    return {
        "running": age < 120,  # heartbeat older than 2 min = considered down
        "last_heartbeat_age_seconds": int(age),
        "subscribed_channels": int(subs or 0),
    }


# ---------------------------------------------------------------------------
# Telegram link mentions — channels referenced by ingested entry content
# ---------------------------------------------------------------------------


@router.get("/mentions")
async def list_telegram_mentions(
    only_unsubscribed: bool = Query(False, description="Hide channels we already ingest"),
    only_active: bool = Query(True, description="Hide dismissed channels"),
    link_type: str | None = Query(None, description="Filter by primary_link_type"),
    sort: str = Query("last_seen", description="last_seen | first_seen | mentions | feeds"),
    limit: int = Query(50, ge=1, le=200, description="Maximum number of channel mentions to return"),
    offset: int = Query(0, ge=0, description="Number of channel mentions to skip for pagination"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """List Telegram channel mentions discovered in ingested content.

    The Workbench panel calls this to show "Telegram channels mentioned across my feeds
    that I haven't yet wired up as sources." Joins against existing telegram feeds so
    is_subscribed reflects current state even if the cached feed_id is stale.
    """
    # Which mentioned channels are already ingested, keyed by handle
    feed_rows = await db.execute(select(Feed).where(Feed.feed_type == "telegram"))
    handle_to_feed: dict[str, str] = {}
    for f in feed_rows.scalars().all():
        cfg = f.adapter_config or {}
        h = (cfg.get("channel_username") or (cfg.get("channel") or "")).lstrip("@").lower()
        if h:
            handle_to_feed[h] = str(f.id)

    q = select(TelegramChannelMention)
    if only_active:
        q = q.where(TelegramChannelMention.dismissed_at.is_(None))
    if only_unsubscribed and handle_to_feed:
        q = q.where(TelegramChannelMention.handle.not_in(handle_to_feed))
    if link_type:
        q = q.where(TelegramChannelMention.primary_link_type == link_type)

    sort_map = {
        "last_seen": TelegramChannelMention.last_seen_at,
        "first_seen": TelegramChannelMention.first_seen_at,
        "mentions": TelegramChannelMention.mention_count,
        "feeds": TelegramChannelMention.distinct_feed_count,
    }
    sort_col = sort_map.get(sort, TelegramChannelMention.last_seen_at)
    q = q.order_by(desc(sort_col), desc(TelegramChannelMention.last_seen_at))

    count_q = q.with_only_columns(func.count(TelegramChannelMention.id)).order_by(None)
    total = (await db.execute(count_q)).scalar_one()

    rows = (await db.execute(q.offset(offset).limit(limit))).scalars().all()

    items = []
    for ch in rows:
        # Subscription comes from the live feed list, not the cached feed_id:
        # this is a read, so it must not write the reconciled value back.
        live_feed_id = handle_to_feed.get(ch.handle)
        items.append(
            {
                "id": str(ch.id),
                "handle": ch.handle,
                "display_handle": ch.display_handle,
                "canonical_url": ch.canonical_url,
                "primary_link_type": ch.primary_link_type,
                "first_seen_at": ch.first_seen_at.isoformat() if ch.first_seen_at else None,
                "last_seen_at": ch.last_seen_at.isoformat() if ch.last_seen_at else None,
                "mention_count": ch.mention_count,
                "distinct_feed_count": ch.distinct_feed_count,
                "is_subscribed": live_feed_id is not None,
                "feed_id": live_feed_id,
                "is_dismissed": ch.dismissed_at is not None,
                "dismissed_at": ch.dismissed_at.isoformat() if ch.dismissed_at else None,
                "notes": ch.notes,
            }
        )

    return {"items": items, "total": int(total), "limit": limit, "offset": offset}


@router.get("/mentions/{mention_id}")
async def get_telegram_mention(
    mention_id: uuid.UUID = Path(..., description="UUID of the channel mention"),
    limit: int = Query(20, ge=1, le=100, description="Maximum number of sample source entries to include"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Detail for one channel mention with sample source entries."""
    ch = await db.get(TelegramChannelMention, mention_id)
    if ch is None:
        raise AppError(code="not_found", message="Mention not found", status_code=404)

    sample_q = await db.execute(
        select(TelegramLinkMention, Entry, Feed)
        .join(Entry, Entry.id == TelegramLinkMention.entry_id)
        .join(Feed, Feed.id == Entry.feed_id, isouter=True)
        .where(TelegramLinkMention.channel_id == ch.id)
        .order_by(TelegramLinkMention.discovered_at.desc())
        .limit(limit)
    )
    samples = []
    for link, entry, feed in sample_q.all():
        samples.append(
            {
                "link_id": str(link.id),
                "url": link.url,
                "link_type": link.link_type,
                "message_id": link.message_id,
                "discovered_at": link.discovered_at.isoformat() if link.discovered_at else None,
                "entry": {
                    "id": str(entry.id),
                    "title": entry.title,
                    "url": entry.url,
                    "published_at": entry.published_at.isoformat() if entry.published_at else None,
                },
                "feed": (
                    {
                        "id": str(feed.id),
                        "title": feed.title,
                        "feed_type": feed.feed_type,
                    }
                    if feed
                    else None
                ),
            }
        )

    return {
        "id": str(ch.id),
        "handle": ch.handle,
        "display_handle": ch.display_handle,
        "canonical_url": ch.canonical_url,
        "primary_link_type": ch.primary_link_type,
        "first_seen_at": ch.first_seen_at.isoformat() if ch.first_seen_at else None,
        "last_seen_at": ch.last_seen_at.isoformat() if ch.last_seen_at else None,
        "mention_count": ch.mention_count,
        "distinct_feed_count": ch.distinct_feed_count,
        "is_subscribed": ch.feed_id is not None,
        "feed_id": str(ch.feed_id) if ch.feed_id else None,
        "is_dismissed": ch.dismissed_at is not None,
        "notes": ch.notes,
        "samples": samples,
    }


@router.post("/mentions/{mention_id}/dismiss")
async def dismiss_telegram_mention(
    mention_id: uuid.UUID = Path(..., description="UUID of the channel mention to dismiss"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Mark a channel mention as not interesting so it stops appearing in the default list."""
    ch = await db.get(TelegramChannelMention, mention_id)
    if ch is None:
        raise AppError(code="not_found", message="Mention not found", status_code=404)
    ch.dismissed_at = datetime.now(UTC)
    ch.dismissed_by = user.id
    db.add(ch)
    await db.commit()
    return {"id": str(ch.id), "dismissed": True}


@router.post("/mentions/{mention_id}/undismiss")
async def undismiss_telegram_mention(
    mention_id: uuid.UUID = Path(..., description="UUID of the channel mention to restore"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Clear a mention's dismissed state so it reappears in the default mentions list."""
    ch = await db.get(TelegramChannelMention, mention_id)
    if ch is None:
        raise AppError(code="not_found", message="Mention not found", status_code=404)
    ch.dismissed_at = None
    ch.dismissed_by = None
    db.add(ch)
    await db.commit()
    return {"id": str(ch.id), "dismissed": False}


@router.post("/mentions/{mention_id}/subscribe")
async def subscribe_to_telegram_mention(
    mention_id: uuid.UUID = Path(..., description="UUID of the channel mention to subscribe to"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """One-click: create a Telegram feed for this mentioned channel.

    Refuses if the mention is invite-only (operator must join via telegram_join.py first)
    or if a feed already exists. On success, links the mention back to the new feed via
    feed_id so the panel reflects the change.
    """
    ch = await db.get(TelegramChannelMention, mention_id)
    if ch is None:
        raise AppError(code="not_found", message="Mention not found", status_code=404)
    if ch.feed_id is not None:
        return {"id": str(ch.id), "already_subscribed": True, "feed_id": str(ch.feed_id)}
    if ch.handle.startswith("invite:"):
        raise AppError(
            code="invite_only",
            message=(
                "This is an invite-only channel. Join it from the Telegram client app or via "
                "scripts/telegram/telegram_join.py, then add the feed manually with the resolved channel id."
            ),
            status_code=400,
        )
    if not ch.display_handle:
        raise AppError(
            code="invalid_handle",
            message="No usable handle on this mention.",
            status_code=400,
        )

    handle = ch.display_handle
    url = f"https://t.me/{handle}"

    # Refuse to clobber an existing telegram feed at the same URL
    existing = await db.execute(select(Feed).where(Feed.url == url))
    if existing.scalar_one_or_none():
        raise AppError(
            code="conflict",
            message="A Telegram feed for this channel already exists.",
            status_code=409,
        )

    feed = Feed(
        url=url,
        title=f"Telegram: @{handle}",
        custom_title=f"Telegram: @{handle}",
        feed_type="telegram",
        adapter_config={
            "channel": f"@{handle}",
            "include_media": True,
            "extract_forwards": True,
            "max_message_age_days": 30,
            "max_messages_per_fetch": 200,
        },
        is_active=True,
        error_count=0,
        fetch_interval_minutes=30,
    )
    db.add(feed)
    await db.flush()

    from app.services.feed_visibility import ensure_subscription, subscribe_all_users, subscriptions_enabled

    if await subscriptions_enabled(db):
        await ensure_subscription(db, user.id, feed.id)
    else:
        await subscribe_all_users(db, feed.id)
    await db.flush()

    ch.feed_id = feed.id
    db.add(ch)
    await db.commit()
    return {
        "id": str(ch.id),
        "subscribed": True,
        "feed_id": str(feed.id),
        "url": url,
    }
