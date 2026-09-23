import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class EntryMediaResponse(BaseModel):
    id: uuid.UUID
    entry_id: uuid.UUID
    media_type: str
    url: str
    mime_type: str | None
    file_size: int | None
    duration_seconds: int | None
    thumbnail_url: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class PodcastResponse(BaseModel):
    id: uuid.UUID
    feed_id: uuid.UUID
    author: str | None
    categories: list[str]
    is_explicit: bool
    podcast_type: str
    artwork_url: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class PodcastDetailResponse(PodcastResponse):
    """Podcast show with feed info."""

    feed_title: str
    feed_url: str
    description: str | None
    episode_count: int = 0


class PodcastEpisodeResponse(BaseModel):
    """Podcast episode with playback progress."""

    id: uuid.UUID
    feed_id: uuid.UUID
    title: str | None
    url: str | None
    author: str | None
    summary: str | None
    published_at: datetime | None
    media_url: str | None
    media_id: uuid.UUID | None
    duration_seconds: int | None
    thumbnail_url: str | None
    position_seconds: int = 0
    is_completed: bool = False


class PlaybackProgressResponse(BaseModel):
    id: uuid.UUID
    entry_media_id: uuid.UUID
    position_seconds: int
    is_completed: bool
    updated_at: datetime

    model_config = {"from_attributes": True}


class PlaybackProgressUpdate(BaseModel):
    position_seconds: int

    model_config = ConfigDict(json_schema_extra={"example": {"position_seconds": 754}})


class PlaybackInProgressItem(BaseModel):
    """An in-progress media item for the resume queue."""

    entry_media_id: uuid.UUID
    entry_id: uuid.UUID
    entry_title: str
    feed_title: str
    media_type: str
    media_url: str
    thumbnail_url: str | None
    duration_seconds: int | None
    position_seconds: int
    updated_at: datetime
