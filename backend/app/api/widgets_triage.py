"""Widget data API — triage queue, saved-search hits, top tags, telegram mentions."""

import json
import logging

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.widgets import _parse_date_range
from app.core.exceptions import AppError
from app.core.security import get_current_user
from app.database import get_db
from app.models.entry import Entry
from app.models.entry_state import UserEntryState
from app.models.saved_search import SavedSearch
from app.models.tag import EntryTag, Tag
from app.models.telegram_mention import TelegramChannelMention
from app.models.user import User
from app.services.entry_tags import visible_to
from app.services.read_state import unread_by_user

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/triage-queue-stats")
async def triage_queue_stats(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Unread, starred, and total entry counts for the current user across active, unmuted feeds."""
    try:
        from app.services.feed_visibility import subscriptions_enabled, visible_feed_ids_query

        feed_q = visible_feed_ids_query(user.id, enabled=await subscriptions_enabled(db), active_only=True)

        total = (await db.execute(select(func.count(Entry.id)).where(Entry.feed_id.in_(feed_q)))).scalar() or 0

        unread = (
            await db.execute(
                select(func.count(Entry.id)).where(
                    Entry.feed_id.in_(feed_q),
                    unread_by_user(user.id),
                )
            )
        ).scalar() or 0

        starred = (
            await db.execute(
                select(func.count(UserEntryState.entry_id)).where(
                    UserEntryState.user_id == user.id,
                    UserEntryState.is_starred == True,  # noqa: E712
                )
            )
        ).scalar() or 0

        return {
            "unread": int(unread),
            "starred": int(starred),
            "total": int(total),
        }
    except Exception as exc:
        logger.exception("Error in triage_queue_stats widget")
        raise AppError(
            code="widget_error",
            message="Failed to load triage queue stats widget",
            status_code=500,
        ) from exc


@router.get("/saved-search-hits")
async def saved_search_hits(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Unread/total hit counts per saved search (Redis-cached when available), sorted by unread, top 20."""
    try:
        result = await db.execute(
            select(SavedSearch).where(SavedSearch.created_by == user.id).order_by(SavedSearch.created_at.desc())
        )
        searches = result.scalars().all()
        if not searches:
            return []

        counts: dict[str, dict] = {}
        try:
            from app.services.redis_client import get_redis

            r = await get_redis()
            cached = await r.get(f"saved_search_counts:{user.id}")
            if cached:
                counts = json.loads(cached)
        except Exception:
            logger.debug("saved_search_hits cache lookup failed", exc_info=True)

        if not counts:
            from app.api.saved_searches import _compute_counts_inline

            counts = await _compute_counts_inline(searches, user.id, db)

        rows = []
        for s in searches:
            c = counts.get(str(s.id), {})
            rows.append(
                {
                    "id": str(s.id),
                    "name": s.display_name or s.name,
                    "query": s.query,
                    "unread": int(c.get("unread", 0)),
                    "total": int(c.get("total", 0)),
                }
            )
        rows.sort(key=lambda r: r["unread"], reverse=True)
        return rows[:20]
    except Exception as exc:
        logger.exception("Error in saved_search_hits widget")
        raise AppError(
            code="widget_error",
            message="Failed to load saved search hits widget",
            status_code=500,
        ) from exc


@router.get("/top-tags")
async def top_tags(
    date_from: str | None = Query(None, description="Start of window (ISO 8601); default 30 days before date_to."),
    date_to: str | None = Query(None, description="End of window (ISO 8601); default now (UTC)."),
    limit: int = Query(15, ge=1, le=100, description="Maximum number of tags to return."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Tags ranked by distinct tagged entries published in the window."""
    try:
        start, end = _parse_date_range(date_from, date_to, default_days=30)
        result = await db.execute(
            select(
                Tag.id,
                Tag.name,
                Tag.color,
                func.count(func.distinct(EntryTag.entry_id)).label("entry_count"),
            )
            .join(EntryTag, EntryTag.tag_id == Tag.id)
            .join(Entry, Entry.id == EntryTag.entry_id)
            .where(Entry.published_at >= start, Entry.published_at <= end, visible_to(user.id))
            .group_by(Tag.id, Tag.name, Tag.color)
            .order_by(func.count(func.distinct(EntryTag.entry_id)).desc())
            .limit(limit)
        )
        return [
            {
                "id": str(row.id),
                "name": row.name,
                "color": row.color,
                "entry_count": int(row.entry_count),
            }
            for row in result.all()
        ]
    except Exception as exc:
        logger.exception("Error in top_tags widget")
        raise AppError(
            code="widget_error",
            message="Failed to load top tags widget",
            status_code=500,
        ) from exc


@router.get("/telegram-mentions")
async def telegram_mentions(
    date_from: str | None = Query(None, description="Start of window (ISO 8601); default 30 days before date_to."),
    date_to: str | None = Query(None, description="End of window (ISO 8601); default now (UTC)."),
    limit: int = Query(15, ge=1, le=100, description="Maximum number of channels to return."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Telegram channels mentioned in entries during the window, ranked by total mention count."""
    try:
        start, end = _parse_date_range(date_from, date_to, default_days=30)
        result = await db.execute(
            select(TelegramChannelMention)
            .where(
                TelegramChannelMention.last_seen_at >= start,
                TelegramChannelMention.last_seen_at <= end,
            )
            .order_by(TelegramChannelMention.mention_count.desc())
            .limit(limit)
        )
        rows = result.scalars().all()
        return [
            {
                "handle": m.handle,
                "display_handle": m.display_handle,
                "canonical_url": m.canonical_url,
                "mention_count": int(m.mention_count or 0),
                "last_seen_at": m.last_seen_at.isoformat() if m.last_seen_at else None,
                "primary_link_type": m.primary_link_type,
            }
            for m in rows
        ]
    except Exception as exc:
        logger.exception("Error in telegram_mentions widget")
        raise AppError(
            code="widget_error",
            message="Failed to load telegram mentions widget",
            status_code=500,
        ) from exc
