import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class EnrichmentSource(Base):
    __tablename__ = "enrichment_sources"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_type: Mapped[str] = mapped_column(String(30), unique=True, nullable=False)
    # a key of app.enrichment.registry.SOURCE_REGISTRY
    display_name: Mapped[str] = mapped_column(String(100), nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    trigger_mode: Mapped[str] = mapped_column(String(20), default="manual")
    # auto (looked up when a new entity appears), manual
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
    # Maximum requests per UTC day; None = unlimited. The gateway counts usage.
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
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # One override per user per source.
    __table_args__ = (UniqueConstraint("created_by", "source_id", name="uq_enrichment_overrides_user_source"),)

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


class EnrichmentJob(Base):
    """One entity's pending lookup at one source. Waiting work lives here until
    the dispatcher runs it, so a lookup a source refuses is deferred, never
    dropped. See app/enrichment/queue.py."""

    __tablename__ = "enrichment_jobs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_type: Mapped[str] = mapped_column(String(20), nullable=False)
    entity_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    entity_value: Mapped[str] = mapped_column(Text, nullable=False)
    source_type: Mapped[str] = mapped_column(String(30), nullable=False)
    lane: Mapped[str] = mapped_column(String(10), nullable=False)
    # manual, new, refresh, backfill
    priority: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    # The lane's rank: lower runs first
    status: Mapped[str] = mapped_column(String(10), nullable=False, default="queued", server_default="queued")
    # queued, running, failed
    due_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    last_status: Mapped[str | None] = mapped_column(String(30))
    # The pipeline status of the last run (rate_limited, error, ...)
    last_error: Mapped[str | None] = mapped_column(Text)
    requested_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    # Whose override key a manual job runs with
    entity_confidence: Mapped[str | None] = mapped_column(String(10))
    entity_base_confidence: Mapped[float | None] = mapped_column(Float)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        UniqueConstraint("entity_type", "entity_id", "source_type", name="uq_enrichment_jobs_entity_source"),
        # The dispatcher's claim: due work by lane, then age.
        Index("ix_enrichment_jobs_claim", "status", "priority", "due_at"),
    )
