import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class IntelligenceRequirement(Base):
    __tablename__ = "intelligence_requirements"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    priority: Mapped[str] = mapped_column(String(20), nullable=False)
    # critical, high, medium, low
    status: Mapped[str] = mapped_column(String(20), default="active", index=True)
    # active, fulfilled, expired, draft
    category: Mapped[str] = mapped_column(String(20), default="operational")
    # strategic, operational, tactical, technical
    keywords: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    linked_feed_ids: Mapped[list[uuid.UUID]] = mapped_column(ARRAY(UUID(as_uuid=True)), default=list)
    linked_entities: Mapped[dict] = mapped_column(JSONB, default=dict)
    # {"threat_actors": [{"id", "name"}], "malware": [...], "cves": [...], "ttps": [...]}
    min_relevance: Mapped[str | None] = mapped_column(String(10))
    # high, medium, low — minimum relevance for auto-matches; None keeps all
    auto_match: Mapped[bool] = mapped_column(Boolean, default=True)
    match_count: Mapped[int] = mapped_column(Integer, default=0)
    last_matched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    fulfilled_by_report_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("intel_reports.id", ondelete="SET NULL"), nullable=True
    )

    # Relationships
    creator = relationship("User", back_populates="intelligence_requirements")
    matches = relationship("RequirementMatch", back_populates="requirement", cascade="all, delete-orphan")


class RequirementMatch(Base):
    __tablename__ = "requirement_matches"

    requirement_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("intelligence_requirements.id", ondelete="CASCADE"), primary_key=True
    )
    entry_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entries.id", ondelete="CASCADE"), primary_key=True, index=True
    )
    match_type: Mapped[str] = mapped_column(String(20), nullable=False)
    # keyword, entity, manual
    matched_on: Mapped[str] = mapped_column(String(500), nullable=False)
    matched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    relevance: Mapped[str | None] = mapped_column(String(10))
    # high, medium, low

    # Relationships
    requirement = relationship("IntelligenceRequirement", back_populates="matches")
    entry = relationship("Entry", back_populates="requirement_matches")
