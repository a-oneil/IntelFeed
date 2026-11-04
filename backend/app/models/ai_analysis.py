import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, Integer, Numeric, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class AIAnalysisRequest(Base):
    """Queue row driving the one-pass entry_analysis extraction for an entry.

    Lifecycle: pending → submitted (in a provider batch) → completed | failed.
    Terminal shortcut statuses: skipped_junk (relevance gate), reused_echo
    (analysis copied from a near-duplicate entry at zero cost). Feed-policy
    skips — skipped_feed_ai (the feed's AI analysis toggle is off) and
    skipped_feed_none (extraction mode "none") — are recorded but re-decided:
    the missed-entry sweep re-enqueues them once the feed allows AI again.
    No row at all means the global switch or the task assignment is off, or
    scoring hasn't reached the entry yet.

    ``adjudication_status`` tracks the post-analysis adjudicate stage for the
    same entry: pending | completed | failed | recheck | skipped_<reason>
    (off, plan, echo, nothing_new, score, budget, paused). NULL = not yet
    decided. The resweep re-enqueues completed analyses left NULL,
    budget/paused/recheck rows every hour, and pending rows whose
    ``adjudication_queued_at`` is older than its stale window (a lost task).
    ``adjudication_recheck_since`` is set while a review is owed only for
    held matches settled after that moment: the review then judges just
    those, not the whole article again.
    Pruned after 30 days by prune_engine_tables.
    """

    __tablename__ = "ai_analysis_requests"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entry_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entries.id", ondelete="CASCADE"), nullable=False, unique=True, index=True
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    # pending | submitted | completed | failed | skipped_junk | reused_echo | skipped_feed_ai | skipped_feed_none
    batch_id: Mapped[str | None] = mapped_column(String(80), index=True)
    custom_id: Mapped[str | None] = mapped_column(String(64))  # "ea-{entry_id}"
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    reused_from_entry_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    submitted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    adjudication_status: Mapped[str | None] = mapped_column(String(24), index=True)
    adjudicated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    adjudication_queued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    adjudication_recheck_since: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (Index("ix_ai_analysis_status_created", "status", "created_at"),)


class AIBatchJob(Base):
    """One submitted Anthropic Message Batch (engine phase 4)."""

    __tablename__ = "ai_batch_jobs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    provider_batch_id: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    provider_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ai_providers.id", ondelete="SET NULL"), nullable=True
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="in_progress")
    # in_progress | ingesting | ended | canceled | failed
    request_count: Mapped[int] = mapped_column(Integer, default=0)
    succeeded: Mapped[int] = mapped_column(Integer, default=0)
    errored: Mapped[int] = mapped_column(Integer, default=0)
    expired: Mapped[int] = mapped_column(Integer, default=0)
    cost_estimate: Mapped[float | None] = mapped_column(Numeric(12, 6))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
