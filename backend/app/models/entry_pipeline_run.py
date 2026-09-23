import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class EntryPipelineRun(Base):
    """Terminal record of one pipeline stage execution for one entry.

    Written by the @pipeline_stage decorator (workers/pipeline_logging.py) on
    stage completion — one INSERT per stage per entry, no "running" rows.
    Powers the entry processing popover and per-stage retry. Pruned after
    30 days by prune_engine_tables; cascade-deletes with the entry.
    """

    __tablename__ = "entry_pipeline_runs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entry_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entries.id", ondelete="CASCADE"), nullable=False, index=True
    )
    stage: Mapped[str] = mapped_column(String(30), nullable=False)
    # autolink, telegram_links, extract, cooccurrence, correlation,
    # requirements, score, automate, translate
    status: Mapped[str] = mapped_column(String(12), nullable=False)  # success, error, retry
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    error: Mapped[str | None] = mapped_column(Text)
    detail: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (Index("ix_pipeline_runs_entry_created", "entry_id", "created_at"),)
