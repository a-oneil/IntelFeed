import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, SmallInteger, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class EntrySignalFeedback(Base):
    """Per-user thumbs on Radar items — nudges signal family multipliers (bounded)."""

    __tablename__ = "entry_signal_feedback"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entry_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entries.id", ondelete="CASCADE"), nullable=False, index=True
    )
    created_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    verdict: Mapped[int] = mapped_column(SmallInteger, nullable=False)  # 1 = useful, -1 = noise
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (UniqueConstraint("entry_id", "created_by", name="uq_signal_feedback_entry_user"),)
