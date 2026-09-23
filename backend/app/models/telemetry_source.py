import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class TelemetrySource(Base):
    __tablename__ = "telemetry_sources"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(30), nullable=False)
    # endpoint, network, email, identity, cloud, saas, virtualization, container, database, application
    vendor: Mapped[str | None] = mapped_column(String(100))
    product: Mapped[str | None] = mapped_column(String(100))
    log_types: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    # Normalised behaviour ids for the raw strings above (see LogTypeAlias).
    # Written by the alias resolver; log_types itself is never rewritten.
    log_types_canonical: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    ingested_into: Mapped[str | None] = mapped_column(String(50))
    # splunk, elastic, sentinel, crowdstrike, etc.
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    creator = relationship("User", back_populates="telemetry_sources")
