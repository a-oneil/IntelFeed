"""Operational widget data API — feed health, worker queues, AI usage."""

import logging
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.widgets import _parse_date_range
from app.core.exceptions import AppError
from app.core.security import get_current_user
from app.database import get_db
from app.models.ai_provider import AIProvider
from app.models.ai_result import AIResult
from app.models.feed import Feed
from app.models.user import User
from app.services.redis_client import get_redis

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/feed-health")
async def feed_health(
    limit: int = Query(20, ge=1, le=200, description="Maximum number of feeds to return."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Feeds in trouble: high error counts or stale fetches."""
    try:
        result = await db.execute(
            select(Feed)
            .where(Feed.is_active == True)  # noqa: E712
            .order_by(desc(Feed.error_count), Feed.last_fetched_at.asc().nullsfirst())
            .limit(limit)
        )
        feeds = result.scalars().all()
        now = datetime.now(UTC)
        items = []
        for f in feeds:
            hours = None
            if f.last_fetched_at is not None:
                delta = now - f.last_fetched_at
                hours = round(delta.total_seconds() / 3600, 1)
            items.append(
                {
                    "id": str(f.id),
                    "name": f.custom_title or f.title,
                    "last_fetched_at": f.last_fetched_at.isoformat() if f.last_fetched_at else None,
                    "error_count": f.error_count or 0,
                    "last_error": f.last_error,
                    "is_muted": f.is_muted,
                    "hours_since_fetch": hours,
                }
            )
        return items
    except Exception as exc:
        logger.exception("Error in feed_health widget")
        raise AppError(
            code="widget_error",
            message="Failed to load feed health widget",
            status_code=500,
        ) from exc


@router.get("/worker-queue")
async def worker_queue(
    user: User = Depends(get_current_user),
):
    """Current Celery queue depth from Redis."""
    try:
        r = await get_redis()
        queue_names = ["celery"]
        queues = []
        total = 0
        for name in queue_names:
            try:
                pending = await r.llen(name)
            except Exception:
                pending = 0
            queues.append({"name": name, "pending": int(pending or 0)})
            total += int(pending or 0)
        return {"queues": queues, "total_pending": total, "redis_ok": True}
    except Exception as exc:
        logger.exception("Error in worker_queue widget")
        raise AppError(
            code="widget_error",
            message="Failed to load worker queue widget",
            status_code=500,
        ) from exc


@router.get("/ai-usage")
async def ai_usage(
    date_from: str | None = Query(None, description="Start of window (ISO 8601); default 7 days before date_to."),
    date_to: str | None = Query(None, description="End of window (ISO 8601); default now (UTC)."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Sum of token usage and cost per AI provider over the window."""
    try:
        start, end = _parse_date_range(date_from, date_to, default_days=7)

        latest_model_subq = (
            select(
                AIResult.provider_id,
                AIResult.model_name,
                func.row_number()
                .over(partition_by=AIResult.provider_id, order_by=AIResult.created_at.desc())
                .label("rn"),
            )
            .where(
                AIResult.created_at >= start,
                AIResult.created_at <= end,
                AIResult.provider_id.is_not(None),
            )
            .subquery()
        )

        agg_q = (
            select(
                AIResult.provider_id,
                AIProvider.name.label("provider_name"),
                func.count(AIResult.id).label("calls"),
                func.coalesce(func.sum(AIResult.tokens_input), 0).label("tokens_input"),
                func.coalesce(func.sum(AIResult.tokens_output), 0).label("tokens_output"),
                func.coalesce(func.sum(AIResult.cost_estimate), 0).label("cost_estimate"),
            )
            .join(AIProvider, AIProvider.id == AIResult.provider_id, isouter=True)
            .where(
                AIResult.created_at >= start,
                AIResult.created_at <= end,
                AIResult.provider_id.is_not(None),
            )
            .group_by(AIResult.provider_id, AIProvider.name)
            .order_by(desc("calls"))
        )
        rows = (await db.execute(agg_q)).all()

        latest_q = select(latest_model_subq.c.provider_id, latest_model_subq.c.model_name).where(
            latest_model_subq.c.rn == 1
        )
        latest_models = {pid: model for pid, model in (await db.execute(latest_q)).all()}

        providers = []
        totals = {"calls": 0, "tokens_input": 0, "tokens_output": 0, "cost_estimate": 0.0}
        for row in rows:
            calls = int(row.calls or 0)
            t_in = int(row.tokens_input or 0)
            t_out = int(row.tokens_output or 0)
            cost = float(row.cost_estimate or 0)
            providers.append(
                {
                    "provider_id": str(row.provider_id) if row.provider_id else None,
                    "provider_name": row.provider_name or "(unknown)",
                    "model_name": latest_models.get(row.provider_id),
                    "calls": calls,
                    "tokens_input": t_in,
                    "tokens_output": t_out,
                    "cost_estimate": cost,
                }
            )
            totals["calls"] += calls
            totals["tokens_input"] += t_in
            totals["tokens_output"] += t_out
            totals["cost_estimate"] += cost

        totals["cost_estimate"] = round(totals["cost_estimate"], 6)
        return {"providers": providers, "totals": totals}
    except Exception as exc:
        logger.exception("Error in ai_usage widget")
        raise AppError(
            code="widget_error",
            message="Failed to load AI usage widget",
            status_code=500,
        ) from exc
