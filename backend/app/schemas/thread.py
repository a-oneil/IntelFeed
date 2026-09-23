"""Story thread response shapes."""

import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class ThreadEntity(BaseModel):
    entity_type: str
    entity_id: str
    label: str
    count: int = Field(description="Member articles this entity was extracted from")


class ThreadBeat(BaseModel):
    id: uuid.UUID
    position: int
    occurred_at: datetime | None
    kind: str = Field(description="first_disclosure | new_tradecraft | peak | update")
    headline: str
    body: str | None
    lead_entry_id: uuid.UUID | None
    entry_ids: list[str] = Field(default_factory=list, description="Member articles carrying this wave")
    collapsed_count: int = Field(0, description="Near-duplicate re-reports folded into this wave")
    is_ai: bool = Field(description="False when the beat came from the day-grouping fallback")


class ThreadMember(BaseModel):
    entry_id: uuid.UUID
    title: str
    url: str | None
    published_at: datetime | None
    priority_score: float | None
    feed_title: str
    source: str | None = Field(description="Source domain — the outlet, not the feed row")
    role: str = Field(description="origin | beat | echo")
    similarity: float
    duplicate_of_entry_id: uuid.UUID | None = Field(description="For echoes: the article this one re-reports")
    is_read: bool


class ThreadYield(BaseModel):
    techniques: int
    cves: int
    products: int
    rules: int
    echoes_folded: int


class NearestThread(BaseModel):
    slug: str
    title: str
    status: str
    entry_count: int
    similarity: float


class ThreadSummary(BaseModel):
    id: uuid.UUID
    slug: str
    title: str
    summary: str | None
    status: str
    entry_count: int
    source_count: int = Field(description="Distinct outlets, not feed rows")
    echo_count: int
    first_seen: datetime | None
    last_seen: datetime | None
    peak_at: datetime | None
    key_entities: list[ThreadEntity] = Field(default_factory=list)
    unread_count: int
    new_since_opened: int = Field(description="Members added since this analyst last opened the thread")
    top_score: float | None = Field(
        description="Priority score of the best unread non-echo member — the rank the thread row takes"
    )
    top_entry_id: uuid.UUID | None
    entry_ids: list[uuid.UUID] = Field(
        default_factory=list, description="Every member, so a list view can absorb them into the thread row"
    )
    narrated_at: datetime | None = Field(description="Null means the spine is the heuristic one")

    @classmethod
    def from_row(cls, row: dict) -> "ThreadSummary":
        """Build from a story_threads query row (its counts come back as a dict)."""
        return cls(
            id=row["id"],
            slug=row["slug"],
            title=row["title"],
            summary=row.get("summary"),
            status=row["status"],
            entry_count=row.get("entry_count") or 0,
            source_count=row.get("source_count") or 0,
            echo_count=row.get("echo_count") or 0,
            first_seen=row.get("first_seen"),
            last_seen=row.get("last_seen"),
            peak_at=row.get("peak_at"),
            key_entities=row.get("key_entities") or [],
            unread_count=row.get("unread_count") or 0,
            new_since_opened=row.get("new_since_opened") or 0,
            top_score=float(row["top_score"]) if row.get("top_score") is not None else None,
            top_entry_id=row.get("top_entry_id"),
            entry_ids=row.get("entry_ids") or [],
            narrated_at=row.get("narrated_at"),
        )


class ThreadDetail(ThreadSummary):
    beats: list[ThreadBeat] = Field(default_factory=list)
    members: list[ThreadMember] = Field(default_factory=list)
    thread_yield: ThreadYield
    nearest: list[NearestThread] = Field(default_factory=list)


class ThreadListResponse(BaseModel):
    threads: list[ThreadSummary]
    total: int


class SimilarEntry(BaseModel):
    entry_id: uuid.UUID
    title: str
    url: str | None
    published_at: datetime | None
    priority_score: float | None
    feed_title: str
    similarity: float = Field(description="Cosine similarity, 0-1")
    thread_id: uuid.UUID | None = Field(description="Set when the neighbour already belongs to a story thread")


class SimilarEntriesResponse(BaseModel):
    entries: list[SimilarEntry]
