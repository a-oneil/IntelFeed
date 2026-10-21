import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Feed(Base):
    __tablename__ = "feeds"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    url: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    feed_type: Mapped[str] = mapped_column(String(30), nullable=False, default="rss", index=True)
    site_url: Mapped[str | None] = mapped_column(Text)
    icon_url: Mapped[str | None] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)
    language: Mapped[str | None] = mapped_column(String(10))
    last_fetched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    fetch_interval_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    etag: Mapped[str | None] = mapped_column(String(255))
    last_modified: Mapped[str | None] = mapped_column(String(255))
    error_count: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(Text)
    # Start of the current failure streak (cleared on success). The health
    # check pauses a feed whose 4xx streak has outlasted feed_auto_pause_days.
    error_since: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Set when the health check paused the feed, so the Feeds view can show a
    # dead feed as dead rather than merely disabled; cleared on resume.
    auto_paused_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    adapter_config: Mapped[dict] = mapped_column(JSONB, default=dict)
    # Source reliability
    reliability_rating: Mapped[str | None] = mapped_column(String(1))  # A-F
    timeliness_rating: Mapped[str | None] = mapped_column(String(10))
    relevance_rating: Mapped[str | None] = mapped_column(String(10))
    analyst_notes: Mapped[str | None] = mapped_column(Text)
    last_reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Intelligence extraction scoping
    intel_extraction_mode: Mapped[str] = mapped_column(
        String(20), nullable=False, default="selective"
    )  # full, selective, manual, none
    auto_extract_on_ingest: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )  # Run regex TTP/CVE extraction on new entries automatically
    extract_detection_rules: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )  # Auto-extract SIGMA, YARA, Elastic, Snort/Suricata, Splunk rules from content
    ai_analysis_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )  # Run the one-pass AI analysis on this feed's entries at ingest.
    # Until this existed, the only way to stop the AI reading a feed was to set
    # intel_extraction_mode="none", which also killed autolinking and scoring —
    # so a noisy source you still wanted matched against your catalog had no
    # setting that expressed it. Gated globally by `ai_one_pass_enabled` too:
    # both must be on.
    extract_tools: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )  # Allow AI extraction to create tool entities from this feed's entries.
    # Off for advisory and detection-content feeds (NVD, distro bulletins, rule
    # repos): they name affected or referenced software, not wielded tooling.
    # Subscription-level settings (shared across all users)
    category_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("categories.id", ondelete="SET NULL"), index=True
    )
    custom_title: Mapped[str | None] = mapped_column(String(500))
    is_muted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    retention_days: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    # Relationships
    entries = relationship("Entry", back_populates="feed", cascade="all, delete-orphan")
    category = relationship("Category", back_populates="feeds")
    podcast = relationship("Podcast", back_populates="feed", uselist=False, cascade="all, delete-orphan")
