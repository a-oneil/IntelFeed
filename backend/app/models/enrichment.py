import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class EnrichmentSource(Base):
    __tablename__ = "enrichment_sources"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_type: Mapped[str] = mapped_column(String(30), unique=True, nullable=False)
    # vulncheck, osv, nvd, epss, malpedia, github_poc,
    # cisa_kev, mitre_attack, cvedetails, wikipedia
    display_name: Mapped[str] = mapped_column(String(100), nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    trigger_mode: Mapped[str] = mapped_column(String(20), default="manual")
    # auto, scheduled, manual
    api_key_encrypted: Mapped[str | None] = mapped_column(Text)
    rate_limit_config: Mapped[dict] = mapped_column(JSONB, default=dict)
    # {"requests_per_period": 50, "period_seconds": 604800}
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    health_status: Mapped[str] = mapped_column(String(20), default="unknown")
    # healthy, degraded, down, unknown
    config: Mapped[dict] = mapped_column(JSONB, default=dict)
    min_confidence_threshold: Mapped[str] = mapped_column(String(10), default="low")
    # high, medium, low — minimum IOC confidence required for auto-enrichment
    daily_budget: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Maximum enrichment requests per day; None = unlimited
    daily_budget_used: Mapped[int] = mapped_column(Integer, default=0)
    # Fallback counter synced from Redis for API reads
    schedule_interval_hours: Mapped[int] = mapped_column(Integer, default=24)
    # How often to run when trigger_mode is "scheduled" (in hours)
    next_scheduled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # When this source should next be enriched (set after each scheduled run)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    # Relationships
    overrides = relationship("UserEnrichmentOverride", back_populates="source", cascade="all, delete-orphan")


class UserEnrichmentOverride(Base):
    __tablename__ = "user_enrichment_overrides"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    source_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("enrichment_sources.id", ondelete="CASCADE"), nullable=False, index=True
    )
    api_key_encrypted: Mapped[str | None] = mapped_column(Text)
    trigger_mode_override: Mapped[str | None] = mapped_column(String(20))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (UniqueConstraint("source_id", name="uq_enrichment_overrides_source_id"),)

    # Relationships
    creator = relationship("User", back_populates="enrichment_overrides")
    source = relationship("EnrichmentSource", back_populates="overrides")


class EnrichmentResult(Base):
    __tablename__ = "enrichment_results"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_type: Mapped[str] = mapped_column(String(20), nullable=False)
    # ioc, cve, threat_actor, malware, ttp
    entity_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    source_type: Mapped[str] = mapped_column(String(30), nullable=False)
    raw_response: Mapped[dict] = mapped_column(JSONB, nullable=False)
    parsed_data: Mapped[dict] = mapped_column(JSONB, nullable=False)
    enriched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="success")
    # success, error, rate_limited, not_found, budget_exhausted, skipped_low_confidence

    __table_args__ = (
        Index("ix_enrichment_entity", "entity_type", "entity_id"),
        Index("ix_enrichment_source_entity", "source_type", "entity_type", "entity_id"),
    )
