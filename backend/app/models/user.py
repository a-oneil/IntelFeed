import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(String(30), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(20), nullable=False, default="user")
    settings: Mapped[dict] = mapped_column(JSONB, default=dict)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    # FK constraint exists in migration; omitted from model to avoid circular dependency with themes.created_by
    theme_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    custom_css: Mapped[str | None] = mapped_column(Text)
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    # Per-user data (cascade delete)
    entry_states = relationship("UserEntryState", back_populates="user", cascade="all, delete-orphan")
    playback_progress = relationship("PlaybackProgress", back_populates="user", cascade="all, delete-orphan")
    # Author attribution (keep user_id, no cascade delete)
    comments = relationship("Comment", back_populates="user")
    entity_notes = relationship("EntityNote", back_populates="user")
    # Shared data (created_by audit, no cascade delete)
    categories = relationship("Category", back_populates="creator")
    notes = relationship("Note", back_populates="creator")
    saved_searches = relationship("SavedSearch", back_populates="creator")
    tags = relationship("Tag", back_populates="creator")
    ai_task_assignments = relationship("AITaskAssignment", back_populates="creator")
    detection_rules = relationship("DetectionRule", back_populates="creator")
    enrichment_overrides = relationship("UserEnrichmentOverride", back_populates="creator")
    intelligence_requirements = relationship("IntelligenceRequirement", back_populates="creator")
    report_templates = relationship(
        "ReportTemplate", back_populates="creator", foreign_keys="[ReportTemplate.created_by]"
    )
    custom_themes = relationship("Theme", back_populates="creator", foreign_keys="[Theme.created_by]")
    automation_rules = relationship("AutomationRule", back_populates="creator")
    telemetry_sources = relationship("TelemetrySource", back_populates="creator")
    glossary_terms = relationship("GlossaryTerm", back_populates="creator", foreign_keys="[GlossaryTerm.created_by]")
    intel_reports = relationship("IntelReport", back_populates="creator")
    campaigns = relationship("Campaign", back_populates="creator")
    dashboards = relationship("Dashboard", back_populates="creator")
    detection_summaries = relationship("DetectionSummary", back_populates="creator")
    webhook_presets = relationship("WebhookPreset", back_populates="creator")
