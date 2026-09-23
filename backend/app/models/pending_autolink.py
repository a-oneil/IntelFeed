"""Pending autolink matches — dictionary-word entity matches held for AI confirmation.

The autolinker diverts actor/malware/tool/country matches whose only surface
forms are common English words ("Royal", "Hive", "Turkey") here instead of
creating junction rows. The one-pass AI analysis reconciler promotes rows whose
entity it confirms is discussed (creating the real junction row) and rejects
the rest. Unresolved rows expire via the engine-tables prune job.
"""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, SmallInteger, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class PendingAutolinkMatch(Base):
    __tablename__ = "pending_autolink_matches"
    __table_args__ = (
        UniqueConstraint("entry_id", "entity_type", "entity_id", name="uq_pending_autolink_entry_entity"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entry_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entries.id", ondelete="CASCADE"), nullable=False, index=True
    )
    entity_type: Mapped[str] = mapped_column(String(20), nullable=False)
    # No FK — spans multiple entity tables; stale rows resolve harmlessly.
    entity_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    canonical_name: Mapped[str] = mapped_column(String(500), nullable=False)
    matched_names: Mapped[list[str] | None] = mapped_column(ARRAY(Text), nullable=True)
    paragraph_indices: Mapped[list[int] | None] = mapped_column(ARRAY(SmallInteger), nullable=True)
    confidence: Mapped[str | None] = mapped_column(String(10))
    source_weight: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolution: Mapped[str | None] = mapped_column(String(20), nullable=True)  # promoted | rejected
