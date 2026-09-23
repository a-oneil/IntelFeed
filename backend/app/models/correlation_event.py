"""Correlation event records — persisted correlation events for user notification."""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class CorrelationEventRecord(Base):
    __tablename__ = "correlation_event_records"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    entry_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entries.id", ondelete="CASCADE"), nullable=True, index=True
    )
    source_entity_type: Mapped[str] = mapped_column(String(30), nullable=False)
    source_entity_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    source_entity_label: Mapped[str] = mapped_column(String(500), nullable=False)
    related_entity_type: Mapped[str] = mapped_column(String(30), nullable=False)
    related_entity_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    related_entity_label: Mapped[str] = mapped_column(String(500), nullable=False)
    context: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(10), nullable=False, default="medium", server_default="medium")
    occurrence_count: Mapped[int] = mapped_column(default=1, server_default="1")
    is_read: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)

    __table_args__ = (
        Index("ix_corr_events_unread_created", "is_read", "created_at"),
        Index("ix_corr_events_severity", "severity"),
    )
