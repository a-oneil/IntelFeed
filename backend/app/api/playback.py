import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Body, Depends, Path
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppError
from app.core.security import get_current_user
from app.database import get_db
from app.models.entry import Entry
from app.models.entry_media import EntryMedia
from app.models.feed import Feed
from app.models.playback_progress import PlaybackProgress
from app.models.user import User
from app.schemas.media import PlaybackInProgressItem, PlaybackProgressResponse, PlaybackProgressUpdate

router = APIRouter()


@router.get("/{media_id}/progress", response_model=PlaybackProgressResponse | None)
async def get_progress(
    media_id: uuid.UUID = Path(..., description="UUID of the entry media item"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get playback progress for a media item."""
    result = await db.execute(
        select(PlaybackProgress).where(
            PlaybackProgress.user_id == user.id,
            PlaybackProgress.entry_media_id == media_id,
        )
    )
    progress = result.scalar_one_or_none()
    if not progress:
        return None
    return PlaybackProgressResponse.model_validate(progress)


@router.put("/{media_id}/progress", response_model=PlaybackProgressResponse)
async def update_progress(
    media_id: uuid.UUID = Path(..., description="UUID of the entry media item"),
    data: PlaybackProgressUpdate = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update playback position for a media item."""
    # Verify media exists
    media_result = await db.execute(select(EntryMedia).where(EntryMedia.id == media_id))
    if not media_result.scalar_one_or_none():
        raise AppError(code="not_found", message="Media not found", status_code=404)

    result = await db.execute(
        select(PlaybackProgress).where(
            PlaybackProgress.user_id == user.id,
            PlaybackProgress.entry_media_id == media_id,
        )
    )
    progress = result.scalar_one_or_none()

    if progress:
        progress.position_seconds = data.position_seconds
        progress.updated_at = datetime.now(UTC)
    else:
        progress = PlaybackProgress(
            user_id=user.id,
            entry_media_id=media_id,
            position_seconds=data.position_seconds,
        )

    db.add(progress)
    await db.flush()
    return PlaybackProgressResponse.model_validate(progress)


@router.put("/{media_id}/complete", response_model=PlaybackProgressResponse)
async def mark_complete(
    media_id: uuid.UUID = Path(..., description="UUID of the entry media item"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Mark a media item as completed."""
    result = await db.execute(
        select(PlaybackProgress).where(
            PlaybackProgress.user_id == user.id,
            PlaybackProgress.entry_media_id == media_id,
        )
    )
    progress = result.scalar_one_or_none()

    if progress:
        progress.is_completed = True
        progress.updated_at = datetime.now(UTC)
    else:
        progress = PlaybackProgress(
            user_id=user.id,
            entry_media_id=media_id,
            position_seconds=0,
            is_completed=True,
        )

    db.add(progress)
    await db.flush()
    return PlaybackProgressResponse.model_validate(progress)


@router.get("/in-progress", response_model=list[PlaybackInProgressItem])
async def list_in_progress(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List in-progress media items (resume queue)."""
    result = await db.execute(
        select(
            PlaybackProgress, EntryMedia, Entry.title, func.coalesce(Feed.custom_title, Feed.title).label("feed_title")
        )
        .join(EntryMedia, EntryMedia.id == PlaybackProgress.entry_media_id)
        .join(Entry, Entry.id == EntryMedia.entry_id)
        .join(Feed, Feed.id == Entry.feed_id)
        .where(
            PlaybackProgress.user_id == user.id,
            PlaybackProgress.is_completed == False,  # noqa: E712
            PlaybackProgress.position_seconds > 0,
        )
        .order_by(PlaybackProgress.updated_at.desc())
        .limit(20)
    )

    items = []
    for progress, media, entry_title, feed_title in result.all():
        items.append(
            PlaybackInProgressItem(
                entry_media_id=media.id,
                entry_id=media.entry_id,
                entry_title=entry_title,
                feed_title=feed_title,
                media_type=media.media_type,
                media_url=media.url,
                thumbnail_url=media.thumbnail_url,
                duration_seconds=media.duration_seconds,
                position_seconds=progress.position_seconds,
                updated_at=progress.updated_at,
            )
        )

    return items
