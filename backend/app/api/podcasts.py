import uuid

from fastapi import APIRouter, Depends, Path, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppError
from app.core.security import get_current_user
from app.database import get_db
from app.models.entry import Entry
from app.models.entry_media import EntryMedia
from app.models.feed import Feed
from app.models.playback_progress import PlaybackProgress
from app.models.podcast import Podcast
from app.models.user import User
from app.schemas.media import PodcastDetailResponse, PodcastEpisodeResponse

router = APIRouter()


@router.get("", response_model=list[PodcastDetailResponse])
async def list_podcasts(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all podcasts with show metadata."""
    result = await db.execute(
        select(Podcast, Feed.title, Feed.url, Feed.description)
        .join(Feed, Feed.id == Podcast.feed_id)
        .where(Feed.feed_type == "podcast")
    )

    podcasts = []
    for podcast, feed_title, feed_url, feed_description in result.all():
        # Count episodes
        count_result = await db.execute(select(func.count(Entry.id)).where(Entry.feed_id == podcast.feed_id))
        episode_count = count_result.scalar() or 0

        podcasts.append(
            PodcastDetailResponse(
                id=podcast.id,
                feed_id=podcast.feed_id,
                author=podcast.author,
                categories=podcast.categories or [],
                is_explicit=podcast.is_explicit,
                podcast_type=podcast.podcast_type,
                artwork_url=podcast.artwork_url,
                created_at=podcast.created_at,
                feed_title=feed_title,
                feed_url=feed_url,
                description=feed_description,
                episode_count=episode_count,
            )
        )

    return podcasts


@router.get("/{feed_id}", response_model=PodcastDetailResponse)
async def get_podcast(
    feed_id: uuid.UUID = Path(..., description="UUID of the podcast feed"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get podcast show details."""
    # Verify feed exists
    feed = await db.get(Feed, feed_id)
    if not feed:
        raise AppError(code="not_found", message="Podcast not found", status_code=404)

    result = await db.execute(
        select(Podcast, Feed.title, Feed.url, Feed.description)
        .join(Feed, Feed.id == Podcast.feed_id)
        .where(Podcast.feed_id == feed_id)
    )
    row = result.one_or_none()
    if not row:
        raise AppError(code="not_found", message="Podcast metadata not found", status_code=404)

    podcast, feed_title, feed_url, feed_description = row

    count_result = await db.execute(select(func.count(Entry.id)).where(Entry.feed_id == feed_id))
    episode_count = count_result.scalar() or 0

    return PodcastDetailResponse(
        id=podcast.id,
        feed_id=podcast.feed_id,
        author=podcast.author,
        categories=podcast.categories or [],
        is_explicit=podcast.is_explicit,
        podcast_type=podcast.podcast_type,
        artwork_url=podcast.artwork_url,
        created_at=podcast.created_at,
        feed_title=feed_title,
        feed_url=feed_url,
        description=feed_description,
        episode_count=episode_count,
    )


@router.get("/{feed_id}/episodes", response_model=list[PodcastEpisodeResponse])
async def list_podcast_episodes(
    feed_id: uuid.UUID = Path(..., description="UUID of the podcast feed"),
    limit: int = Query(50, ge=1, le=500, description="Maximum number of episodes to return"),
    offset: int = Query(0, ge=0, description="Number of episodes to skip for pagination"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List episodes for a podcast feed with playback progress."""
    # Verify feed exists
    feed = await db.get(Feed, feed_id)
    if not feed:
        raise AppError(code="not_found", message="Podcast not found", status_code=404)

    # Get entries for this feed, sorted by published_at desc
    entries_result = await db.execute(
        select(Entry)
        .where(Entry.feed_id == feed_id)
        .order_by(Entry.published_at.desc().nullslast())
        .offset(offset)
        .limit(limit)
    )
    entries = entries_result.scalars().all()

    if not entries:
        return []

    entry_ids = [e.id for e in entries]

    # Batch-load media for these entries
    media_result = await db.execute(select(EntryMedia).where(EntryMedia.entry_id.in_(entry_ids)))
    media_map: dict[uuid.UUID, EntryMedia] = {}
    media_ids: list[uuid.UUID] = []
    for m in media_result.scalars().all():
        if m.entry_id not in media_map:
            media_map[m.entry_id] = m
            media_ids.append(m.id)

    # Batch-load playback progress
    progress_map: dict[uuid.UUID, PlaybackProgress] = {}
    if media_ids:
        progress_result = await db.execute(
            select(PlaybackProgress).where(
                PlaybackProgress.user_id == user.id,
                PlaybackProgress.entry_media_id.in_(media_ids),
            )
        )
        for p in progress_result.scalars().all():
            progress_map[p.entry_media_id] = p

    episodes = []
    for entry in entries:
        media = media_map.get(entry.id)
        progress = progress_map.get(media.id) if media else None
        episodes.append(
            PodcastEpisodeResponse(
                id=entry.id,
                feed_id=entry.feed_id,
                title=entry.title,
                url=entry.url,
                author=entry.author,
                summary=entry.summary,
                published_at=entry.published_at,
                media_url=media.url if media else None,
                media_id=media.id if media else None,
                duration_seconds=media.duration_seconds if media else None,
                thumbnail_url=media.thumbnail_url if media else None,
                position_seconds=progress.position_seconds if progress else 0,
                is_completed=progress.is_completed if progress else False,
            )
        )

    return episodes
