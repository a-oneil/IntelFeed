import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class EntryMediaBrief(BaseModel):
    """Compact media info included in entry list responses."""

    id: uuid.UUID
    media_type: str
    url: str
    thumbnail_url: str | None
    duration_seconds: int | None

    model_config = {"from_attributes": True}


class EntryResponse(BaseModel):
    id: uuid.UUID
    feed_id: uuid.UUID
    guid: str | None
    url: str | None
    title: str
    translated_title: str | None = None
    author: str | None
    summary: str | None
    published_at: datetime | None
    fetched_at: datetime
    word_count: int | None
    content_hash: str | None
    image_url: str | None = None
    feed_title: str | None = None
    feed_type: str | None = None
    metadata: dict | None = None
    # Media attachments (compact)
    media: list[EntryMediaBrief] = []
    # User state
    is_read: bool = False
    is_starred: bool = False
    is_bookmarked: bool = False
    tags: list[dict] = []  # [{id, name, color, display_as_chip, description, is_global, personal}]
    # Signal engine (populated only when signal_engine_surface is enabled and
    # the entry's score clears the radar threshold; is_echo always set).
    # priority_score is 0–10: 0 = no signals, 9+ ≈ top 5%, 10 = top 1%.
    priority_score: float | None = None
    top_signals: list[dict] = []  # [{type, explanation}]
    is_echo: bool = False
    # My Stack exposure (read-time, per-user; only set for radar-sorted entries
    # that affect the user's declared stack). See app/services/exposure.py.
    # {lift, posture, asset_name, asset_type, cve_ids, missing_data_sources}
    exposure: dict | None = None
    # Learned Radar weights (read-time, per-user; only set for radar-sorted
    # entries this analyst's own fitted weights actually moved). See
    # app/services/radar_personalization.py. {lift, families: [{family, weight, delta}]}
    personal: dict | None = None

    model_config = {"from_attributes": True}


class EntryDetailResponse(EntryResponse):
    content_html: str | None
    content_text: str | None
    extracted_urls: list[dict] = []
    duplicates: list["EntryDuplicate"] = []
    translated_html: str | None = None
    translation_source_language: str | None = None
    translation_target_language: str | None = None
    translated_at: datetime | None = None
    # Full signal breakdown for the reader's "Why it's ranked" card. Populated
    # under the same gating as priority_score (surface enabled + score clears
    # the radar threshold). ``weighted`` is the signal's actual contribution to
    # the score (raw × rarity weight × family multiplier) and is what the card
    # plots; ``score`` is the raw strength before weighting. feed_echo is
    # included with a negative ``weighted`` — it is the one signal that
    # subtracts. [{type, family, score, weighted, explanation}]
    priority_signals: list[dict] = []
    # The raw signal sum priority_score was scaled from — what the ``weighted``
    # rows add up to. Same gating as priority_signals.
    priority_raw: float | None = None
    # When is_echo is true, the earlier entry this one echoes (resolved from the
    # feed_echo signal's ``duplicate_of`` payload). Null if the original is gone.
    echo_of: "EchoOf | None" = None


class TranslateEntryResponse(BaseModel):
    entry_id: uuid.UUID
    translated_html: str
    translated_title: str | None = None
    source_language: str
    target_language: str
    translated_at: datetime
    cached: bool


class EntryDuplicate(BaseModel):
    entry_id: uuid.UUID
    feed_title: str
    feed_id: uuid.UUID


class EchoOf(BaseModel):
    entry_id: uuid.UUID
    title: str
    feed_title: str
    published_at: datetime | None = None
    shared: int | None = None
    total: int | None = None


class MarkAllReadRequest(BaseModel):
    feed_id: uuid.UUID | None = None
    category_id: uuid.UUID | None = None
    since: datetime | None = None
    before: datetime | None = None
    # Priority Queue: restrict to entries clearing the radar threshold so
    # "Mark All Read" clears only the queue, not every unread entry.
    radar_only: bool = False

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "feed_id": "d5b2f1a4-3c6e-4b8a-9f21-7e5a2c9d1b34",
                "before": "2026-08-27T00:00:00Z",
                "radar_only": False,
            }
        }
    )


class BulkActionRequest(BaseModel):
    entry_ids: list[uuid.UUID]
    action: str  # "read" | "unread" | "star" | "unstar" | "bookmark" | "unbookmark" | "hide"

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "entry_ids": [
                    "d5b2f1a4-3c6e-4b8a-9f21-7e5a2c9d1b34",
                    "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
                ],
                "action": "read",
            }
        }
    )
