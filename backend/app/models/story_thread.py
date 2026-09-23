import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.entry_embedding import EMBEDDING_DIM
from app.models.vector_types import HalfVec


class StoryThread(Base):
    """One unfolding story: its articles, its spine, and its echoes.

    Written only by the thread sweeper (app.intelligence.story_threads). The
    ``centroid`` is the mean of its members' embeddings and is what a new
    article is compared against.
    """

    __tablename__ = "story_threads"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    slug: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(12), nullable=False, default="open", server_default="open")
    centroid: Mapped[list[float] | None] = mapped_column(HalfVec(EMBEDDING_DIM), nullable=True)
    entry_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    source_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    echo_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    peak_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # server_default as well as default: the sweeper inserts through raw SQL,
    # so a Python-side default alone leaves the column null.
    key_entities: Mapped[list] = mapped_column(JSONB, nullable=False, default=list, server_default="[]")
    narrative_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    narrated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    members: Mapped[list["StoryThreadEntry"]] = relationship(
        back_populates="thread", cascade="all, delete-orphan", passive_deletes=True
    )
    beats: Mapped[list["StoryThreadBeat"]] = relationship(
        back_populates="thread",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="StoryThreadBeat.position",
    )

    __table_args__ = (Index("ix_story_threads_status_last_seen", "status", "last_seen"),)


class StoryThreadEntry(Base):
    """Membership of one article in one thread. An article joins at most one."""

    __tablename__ = "story_thread_entries"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    thread_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("story_threads.id", ondelete="CASCADE"), nullable=False
    )
    entry_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entries.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    role: Mapped[str] = mapped_column(String(10), nullable=False, default="beat", server_default="beat")
    similarity: Mapped[float] = mapped_column(Float, nullable=False, default=0.0, server_default="0")
    duplicate_of_entry_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entries.id", ondelete="SET NULL"), nullable=True
    )
    source_key: Mapped[str | None] = mapped_column(String(255), nullable=True)
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    thread: Mapped[StoryThread] = relationship(back_populates="members")

    __table_args__ = (Index("ix_story_thread_entries_thread", "thread_id"),)


class StoryThreadBeat(Base):
    """One wave of a story — what was new, and which articles carried it."""

    __tablename__ = "story_thread_beats"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    thread_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("story_threads.id", ondelete="CASCADE"), nullable=False
    )
    position: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    occurred_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    kind: Mapped[str] = mapped_column(String(20), nullable=False, default="update", server_default="update")
    headline: Mapped[str] = mapped_column(Text, nullable=False)
    body: Mapped[str | None] = mapped_column(Text, nullable=True)
    lead_entry_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entries.id", ondelete="SET NULL"), nullable=True
    )
    entry_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list, server_default="[]")
    collapsed_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    is_ai: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=text("false"))

    thread: Mapped[StoryThread] = relationship(back_populates="beats")

    __table_args__ = (Index("ix_story_thread_beats_thread", "thread_id", "position"),)


class UserThreadState(Base):
    """Per-analyst thread state: when they last opened it."""

    __tablename__ = "user_thread_states"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    thread_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("story_threads.id", ondelete="CASCADE"), nullable=False
    )
    last_opened_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint("user_id", "thread_id", name="uq_user_thread_states_user_thread"),
        Index("ix_user_thread_states_user", "user_id"),
    )
