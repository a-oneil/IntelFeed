"""Story threads — one unfolding story instead of twenty-three articles.

Read-only over what the sweeper (app.intelligence.story_threads) and the
narrator (app.services.thread_narrative) have already written, plus the one
per-analyst write a thread supports: opening it.
"""

import uuid

from fastapi import APIRouter, Depends, Path, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppError
from app.core.security import get_current_user
from app.database import get_db
from app.intelligence import story_threads
from app.models.story_thread import StoryThread
from app.models.user import User
from app.schemas.thread import (
    NearestThread,
    ThreadBeat,
    ThreadDetail,
    ThreadListResponse,
    ThreadMember,
    ThreadSummary,
    ThreadYield,
)

router = APIRouter()


@router.get(
    "",
    response_model=ThreadListResponse,
    summary="List story threads",
    description=(
        "Open story threads, most recently active first. Each row carries the counts a reading "
        "surface needs to fold the pile: unread members, members added since this analyst last "
        "opened it, the score of the best unread beat, and every member id so a list view can "
        "absorb them into the thread row. Pass `q` to search titles instead, for a picker that "
        "needs one named story rather than the recent ones."
    ),
)
async def list_threads(
    status: str = Query("open", description="open, dormant, closed, or 'any'"),
    limit: int = Query(40, ge=1, le=200, description="Maximum threads returned"),
    q: str | None = Query(None, max_length=200, description="Substring match on the thread title"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    rows = await story_threads.list_threads(db, user.id, status=status, limit=limit, q=q)
    return ThreadListResponse(threads=[ThreadSummary.from_row(r) for r in rows], total=len(rows))


@router.get(
    "/{slug}",
    response_model=ThreadDetail,
    summary="Read one story thread",
    description=(
        "The thread's spine (one beat per wave of coverage), every member article with its role "
        "(origin, beat, or folded echo), what the story has yielded, and the threads it most "
        "resembles."
    ),
)
async def get_thread(
    slug: str = Path(..., description="Thread slug", examples=["shai-hulud-npm-supply-chain-worm"]),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    row = await story_threads.get_thread(db, slug, user.id)
    if row is None:
        raise AppError("not_found", f"No story thread with slug '{slug}'", status_code=404)

    thread_id = row["id"]
    members = await story_threads.thread_members(db, thread_id, user.id)
    beats = await story_threads.thread_beats(db, thread_id)
    yields = await story_threads.thread_yield(db, thread_id)
    nearest = await story_threads.nearest_threads(db, thread_id)

    unread = [m for m in members if not m["is_read"]]
    # Members arrive in publication order; the thread's rank is its best unread
    # beat, so the entry reported alongside that score has to be the same one.
    best_unread = max(
        (m for m in unread if m["role"] != "echo"),
        key=lambda m: m["priority_raw"] or 0,
        default=None,
    )
    last_opened = row.get("last_opened_at")
    summary = ThreadSummary.from_row(
        {
            **row,
            "unread_count": len(unread),
            "new_since_opened": sum(
                1 for m in members if last_opened is None or (m["added_at"] and m["added_at"] > last_opened)
            ),
            "top_score": (best_unread["priority_score"] or 0) if best_unread else None,
            "top_entry_id": best_unread["entry_id"] if best_unread else None,
            "entry_ids": [m["entry_id"] for m in members],
        }
    )

    return ThreadDetail(
        **summary.model_dump(),
        beats=[
            ThreadBeat(
                id=b["id"],
                position=b["position"],
                occurred_at=b["occurred_at"],
                kind=b["kind"],
                headline=b["headline"],
                body=b["body"],
                lead_entry_id=b["lead_entry_id"],
                entry_ids=[str(e) for e in (b["entry_ids"] or [])],
                collapsed_count=b["collapsed_count"] or 0,
                is_ai=bool(b["is_ai"]),
            )
            for b in beats
        ],
        members=[
            ThreadMember(
                entry_id=m["entry_id"],
                title=m["title"],
                url=m["url"],
                published_at=m["published_at"],
                priority_score=m["priority_score"],
                feed_title=m["feed_title"],
                source=m["source_key"],
                role=m["role"],
                similarity=float(m["similarity"] or 0),
                duplicate_of_entry_id=m["duplicate_of_entry_id"],
                is_read=bool(m["is_read"]),
            )
            for m in members
        ],
        thread_yield=ThreadYield(**{k: int(v or 0) for k, v in yields.items()}),
        nearest=[
            NearestThread(
                slug=n["slug"],
                title=n["title"],
                status=n["status"],
                entry_count=n["entry_count"] or 0,
                similarity=round(float(n["similarity"] or 0), 3),
            )
            for n in nearest
        ],
    )


async def _require_thread(db: AsyncSession, thread_id: uuid.UUID) -> None:
    """404 rather than a foreign-key violation for a thread that is gone.

    Threads are deleted — merged into one another, or pruned when their articles
    age out — so a stale bookmark or an open tab addressing one by id is routine.
    """
    exists = await db.execute(select(StoryThread.id).where(StoryThread.id == thread_id))
    if exists.scalar_one_or_none() is None:
        raise AppError("not_found", f"No story thread with id '{thread_id}'", status_code=404)


@router.post(
    "/{thread_id}/open",
    summary="Stamp a thread as opened",
    description=(
        "Records that this analyst has seen the thread as it currently stands. The 'N new' count "
        "on the thread row is measured from this timestamp."
    ),
)
async def open_thread(
    thread_id: uuid.UUID = Path(..., description="Thread UUID"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _require_thread(db, thread_id)
    await story_threads.mark_opened(db, thread_id, user.id)
    return {"status": "ok"}
