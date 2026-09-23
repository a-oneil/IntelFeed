import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Index, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class EntrySignal(Base):
    """One scored, explainable signal on an entry (signal engine).

    Signals are computed by score_entry_task after post-processing completes and
    upserted on (entry_id, signal_type) — re-scoring overwrites, never appends.
    Rows cascade-delete with their entry, so retention cleanup covers pruning.
    """

    __tablename__ = "entry_signals"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entry_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entries.id", ondelete="CASCADE"), nullable=False, index=True
    )
    signal_type: Mapped[str] = mapped_column(String(40), nullable=False)
    # novelty: novel_entity, entity_resurgence, new_pairing, scoop
    # coverage: source_convergence, under_reported, feed_echo (negative)
    # severity: kev_added, epss_jump, weaponized_poc, critical_cvss
    # interest: pir_match, correlation_event, watchlist (read-time only, not stored)
    # content: detection_content, research_depth
    score: Mapped[float] = mapped_column(Float, nullable=False)  # raw strength 0..1
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    payload: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        UniqueConstraint("entry_id", "signal_type", name="uq_entry_signals_entry_type"),
        Index("ix_entry_signals_type_created", "signal_type", "created_at"),
    )

    entry = relationship("Entry", back_populates="signals")
