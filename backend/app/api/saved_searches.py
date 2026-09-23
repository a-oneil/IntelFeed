import asyncio
import json
import logging
import uuid

from fastapi import APIRouter, Body, Depends, Path
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppError
from app.core.security import get_current_user
from app.database import get_db
from app.models.entry_state import UserEntryState
from app.models.saved_search import SavedSearch
from app.models.user import User
from app.schemas.search import (
    SavedSearchCreate,
    SavedSearchResponse,
    SavedSearchUpdate,
)

logger = logging.getLogger(__name__)

router = APIRouter()

COUNTS_TTL = 600  # 10 minutes


async def _compute_counts_inline(
    searches: list[SavedSearch],
    user_id: uuid.UUID,
    db: AsyncSession,
) -> dict[str, dict[str, int]]:
    """Compute saved search counts inline when Redis cache is empty."""
    from app.search.meili_builder import execute_entry_search
    from app.search.query_parser import ParseError, parse_query
    from app.search.query_planner import build_execution_plan

    counts: dict[str, dict[str, int]] = {}
    for s in searches:
        query_str = s.query or s.name or ""
        if not query_str.strip():
            counts[str(s.id)] = {"unread": 0, "total": 0}
            continue

        try:
            ast = parse_query(query_str)
        except ParseError:
            counts[str(s.id)] = {"unread": 0, "total": 0}
            continue

        plan = build_execution_plan(ast)

        # Every Postgres-backed filter, not just `feed:` — resolving one and not
        # the other leaves the rest of them unapplied.
        from app.search.query_planner import resolve_deferred_filters

        await resolve_deferred_filters(db, plan)

        if not (plan.has_entry_queries or plan.meili_query.strip()):
            counts[str(s.id)] = {"unread": 0, "total": 0}
            continue

        try:
            # Fetch entry IDs (cap at 5000) for unread calculation
            constraint = list(plan.db_entry_ids) if plan.db_entry_ids is not None else None
            ids_result = await asyncio.to_thread(execute_entry_search, plan, constraint, 5000, 0)
            entry_ids = [hit["id"] for hit in ids_result.get("hits", []) if "id" in hit]
            # Use actual hit count rather than estimatedTotalHits which can overcount
            total = len(entry_ids)

            if total == 0:
                counts[str(s.id)] = {"unread": 0, "total": 0}
                continue

            # Count read entries
            read_count = 0
            if entry_ids:
                entry_uuids = [uuid.UUID(eid) for eid in entry_ids]
                result = await db.execute(
                    select(func.count())
                    .select_from(UserEntryState)
                    .where(
                        UserEntryState.user_id == user_id,
                        UserEntryState.entry_id.in_(entry_uuids),
                        UserEntryState.is_read.is_(True),
                    )
                )
                read_count = result.scalar_one()

            unread = max(total - read_count, 0)
            counts[str(s.id)] = {"unread": unread, "total": total}
        except Exception:
            logger.warning("Failed to compute count for saved search %s", s.id, exc_info=True)
            counts[str(s.id)] = {"unread": 0, "total": 0}

    # Cache the computed counts in Redis
    try:
        from app.services.redis_client import get_redis

        r = await get_redis()
        await r.set(
            f"saved_search_counts:{user_id}",
            json.dumps(counts),
            ex=COUNTS_TTL,
        )
    except Exception:
        pass

    return counts


@router.get("", response_model=list[SavedSearchResponse])
async def list_saved_searches(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List the current user's saved searches with their unread/total entry counts.
    Counts come from a 10-minute Redis cache and are computed inline on a cache miss."""
    result = await db.execute(
        select(SavedSearch).where(SavedSearch.created_by == user.id).order_by(SavedSearch.created_at.desc())
    )
    searches = result.scalars().all()

    # Try cached counts from Redis first
    counts: dict[str, dict] = {}
    try:
        from app.services.redis_client import get_redis

        r = await get_redis()
        cached = await r.get(f"saved_search_counts:{user.id}")
        if cached:
            counts = json.loads(cached)
    except Exception:
        pass

    # If cache is empty and there are searches, compute inline
    if not counts and searches:
        counts = await _compute_counts_inline(searches, user.id, db)

    responses = []
    for s in searches:
        sid = str(s.id)
        c = counts.get(sid, {})
        responses.append(
            SavedSearchResponse(
                id=s.id,
                name=s.name,
                display_name=s.display_name,
                query=s.query,
                filters=s.filters,
                unread_count=c.get("unread", 0),
                total_count=c.get("total", 0),
                created_at=s.created_at,
            )
        )
    return responses


@router.post("", response_model=SavedSearchResponse, status_code=201)
async def create_saved_search(
    body: SavedSearchCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a saved search from a query-language string and/or structured filters."""
    saved = SavedSearch(
        created_by=user.id,
        name=body.name,
        display_name=body.display_name,
        query=body.query,
        filters=body.filters,
    )
    db.add(saved)
    await db.flush()
    await db.refresh(saved)
    return saved


@router.put("/{search_id}", response_model=SavedSearchResponse)
async def update_saved_search(
    search_id: uuid.UUID = Path(..., description="Saved search UUID"),
    body: SavedSearchUpdate = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Partially update one of the current user's saved searches; only the provided fields change."""
    result = await db.execute(select(SavedSearch).where(SavedSearch.id == search_id))
    saved = result.scalar_one_or_none()
    if not saved:
        raise AppError(
            code="not_found",
            message="Saved search not found",
            status_code=404,
        )
    if user.role != "admin" and saved.created_by != user.id:
        raise AppError(
            code="forbidden", message="Only the saved search's owner or an admin can modify it", status_code=403
        )

    if body.name is not None:
        saved.name = body.name
    if body.display_name is not None:
        saved.display_name = body.display_name
    if body.query is not None:
        saved.query = body.query
    if body.filters is not None:
        saved.filters = body.filters

    db.add(saved)
    await db.flush()
    await db.refresh(saved)
    return saved


@router.delete("/{search_id}", status_code=204)
async def delete_saved_search(
    search_id: uuid.UUID = Path(..., description="Saved search UUID"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete one of the current user's saved searches."""
    result = await db.execute(select(SavedSearch).where(SavedSearch.id == search_id))
    saved = result.scalar_one_or_none()
    if not saved:
        raise AppError(
            code="not_found",
            message="Saved search not found",
            status_code=404,
        )
    if user.role != "admin" and saved.created_by != user.id:
        raise AppError(
            code="forbidden", message="Only the saved search's owner or an admin can delete it", status_code=403
        )
    await db.delete(saved)
    await db.flush()
