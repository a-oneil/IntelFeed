import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Entry(Base):
    __tablename__ = "entries"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    feed_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("feeds.id", ondelete="CASCADE"), nullable=False, index=True
    )
    guid: Mapped[str | None] = mapped_column(String(2000))
    url: Mapped[str | None] = mapped_column(Text)
    title: Mapped[str] = mapped_column(String(2000), nullable=False)
    author: Mapped[str | None] = mapped_column(String(500))
    content_html: Mapped[str | None] = mapped_column(Text)
    content_text: Mapped[str | None] = mapped_column(Text)
    summary: Mapped[str | None] = mapped_column(Text)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    word_count: Mapped[int | None] = mapped_column(Integer)
    language: Mapped[str | None] = mapped_column(String(10))
    metadata_: Mapped[dict] = mapped_column("metadata", JSONB, default=dict)
    content_hash: Mapped[str | None] = mapped_column(String(64))
    image_url: Mapped[str | None] = mapped_column(Text)
    extracted_urls: Mapped[list] = mapped_column(JSONB, default=list, server_default="[]")
    #: Tier-0 observable candidates: [{kind, value, surface_form, was_defanged,
    #: paragraph_index}]. Written by the observables stage's refang+regex scan.
    #: Candidates are entry-local — never entities, never searchable, never
    #: graphed. They exist so the reader can offer one-click promotion and so
    #: the one-pass analysis gets hints. See models/observable.py for the rule.
    observable_candidates: Mapped[list] = mapped_column(JSONB, default=list, server_default="[]")
    translated_html: Mapped[str | None] = mapped_column(Text)
    translated_title: Mapped[str | None] = mapped_column(String(2000))
    translation_source_language: Mapped[str | None] = mapped_column(String(10))
    translation_target_language: Mapped[str | None] = mapped_column(String(10))
    translated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Signal engine: the 0–10 score everything reads, and the unbounded weighted
    # sum it is scaled from (the ordering key — see app/intelligence/signals.py).
    priority_score: Mapped[float | None] = mapped_column(Float, index=True)
    priority_raw: Mapped[float | None] = mapped_column(Float, index=True)
    scored_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        UniqueConstraint("feed_id", "guid"),
        # Composite, not a bare content_hash index: the dedup subquery behind
        # the entry list and count is DISTINCT ON (content_hash) ORDER BY
        # content_hash, created_at, and only this ordering lets it skip the sort.
        Index("ix_entries_content_hash_created_at", "content_hash", "created_at"),
    )

    # Relationships
    feed = relationship("Feed", back_populates="entries")
    user_states = relationship("UserEntryState", back_populates="entry", cascade="all, delete-orphan")
    media = relationship("EntryMedia", back_populates="entry", cascade="all, delete-orphan")
    notes = relationship("Note", back_populates="entry")
    entry_tags = relationship("EntryTag", back_populates="entry", cascade="all, delete-orphan")
    entry_ttps = relationship("EntryTTP", back_populates="entry", cascade="all, delete-orphan")
    entry_cves = relationship("EntryCVE", back_populates="entry", cascade="all, delete-orphan")
    entry_cwes = relationship("EntryCWE", back_populates="entry", cascade="all, delete-orphan")
    entry_observables = relationship("EntryObservable", back_populates="entry", cascade="all, delete-orphan")
    entry_threat_actors = relationship("EntryThreatActor", back_populates="entry", cascade="all, delete-orphan")
    entry_malware = relationship("EntryMalware", back_populates="entry", cascade="all, delete-orphan")
    entry_countries = relationship("EntryCountry", back_populates="entry", cascade="all, delete-orphan")
    entry_sectors = relationship("EntrySector", back_populates="entry", cascade="all, delete-orphan")
    detection_rules = relationship("DetectionRule", back_populates="entry")
    ai_results = relationship("AIResult", back_populates="entry")
    requirement_matches = relationship("RequirementMatch", back_populates="entry", cascade="all, delete-orphan")
    campaign_entries = relationship("CampaignEntry", back_populates="entry", cascade="all, delete-orphan")
    automation_logs = relationship("AutomationLog", back_populates="entry")
    entry_mitigations = relationship("EntryMitigation", back_populates="entry", cascade="all, delete-orphan")
    entry_vendors = relationship("EntryVendor", back_populates="entry", cascade="all, delete-orphan")
    entry_products = relationship("EntryProduct", back_populates="entry", cascade="all, delete-orphan")
    link_validation_log = relationship("EntityLinkValidationLog", back_populates="entry", cascade="all, delete-orphan")
    signals = relationship("EntrySignal", back_populates="entry", cascade="all, delete-orphan")
