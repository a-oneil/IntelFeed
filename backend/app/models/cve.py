import uuid
from datetime import date, datetime
from decimal import Decimal

from sqlalchemy import Boolean, Date, DateTime, Float, ForeignKey, Integer, Numeric, SmallInteger, String, Text, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class CVE(Base):
    __tablename__ = "cves"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cve_id: Mapped[str] = mapped_column(String(20), unique=True, nullable=False)
    cvss_score: Mapped[Decimal | None] = mapped_column(Numeric(3, 1))
    severity: Mapped[str | None] = mapped_column(String(20), index=True)
    description: Mapped[str | None] = mapped_column(Text)
    affected_products: Mapped[list] = mapped_column(JSONB, default=list)
    exploit_status: Mapped[str | None] = mapped_column(String(30))
    exploit_sources: Mapped[list] = mapped_column(JSONB, default=list)
    references_: Mapped[list] = mapped_column("references_", JSONB, default=list)
    nvd_data: Mapped[dict] = mapped_column(JSONB, default=dict)
    timeline: Mapped[list] = mapped_column(JSONB, default=list)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    # EPSS and exploit tracking
    epss_score: Mapped[float | None] = mapped_column(Float, index=True)
    epss_percentile: Mapped[float | None] = mapped_column(Float)
    epss_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Set only on significant EPSS changes (delta >= 0.1 or crossing 0.5) —
    # the epss_jump signal reads these; epss_updated_at just tracks sync time.
    epss_previous_score: Mapped[float | None] = mapped_column(Float)
    epss_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    exploit_availability: Mapped[str | None] = mapped_column(String(25))
    # none, poc, weaponized, active_exploitation
    # Provenance: 'manual' when an analyst set exploit status via the UI;
    # NULL/'auto' when derived by enrichment. Enrichment never overwrites 'manual'.
    exploit_status_source: Mapped[str | None] = mapped_column(String(20))
    # CISA KEV membership
    is_kev: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false", index=True)
    kev_date_added: Mapped[date | None] = mapped_column(Date)
    kev_due_date: Mapped[date | None] = mapped_column(Date)
    # CISA's SSVC decision points, from its ADP container in the CVE record
    # (cvelist enrichment source): none | poc | active, yes | no, partial | total.
    ssvc_exploitation: Mapped[str | None] = mapped_column(String(10))
    ssvc_automatable: Mapped[str | None] = mapped_column(String(10))
    ssvc_technical_impact: Mapped[str | None] = mapped_column(String(10))
    github_poc_count: Mapped[int | None] = mapped_column(Integer)
    github_poc_urls: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    metasploit_module: Mapped[str | None] = mapped_column(String(255))
    wikipedia_url: Mapped[str | None] = mapped_column(Text)
    wikipedia_content: Mapped[str | None] = mapped_column(Text)
    wikipedia_image_url: Mapped[str | None] = mapped_column(Text)
    # --- AI-extraction provenance (Engine → Extraction management tab) ---
    # CVEs are catalog-keyed (never gated), so needs_review stays false.
    created_via: Mapped[str | None] = mapped_column(String(20), nullable=True, index=True)
    created_from_entry_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entries.id", ondelete="SET NULL"), nullable=True
    )
    created_confidence: Mapped[str | None] = mapped_column(String(10), nullable=True)
    needs_review: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")

    # Relationships
    entry_cves = relationship("EntryCVE", back_populates="cve", cascade="all, delete-orphan")
    affected_links = relationship("CVEAffected", back_populates="cve", cascade="all, delete-orphan")
    weakness_links = relationship("CVEWeakness", back_populates="cve", cascade="all, delete-orphan")


class EntryCVE(Base):
    __tablename__ = "entry_cves"

    entry_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entries.id", ondelete="CASCADE"), primary_key=True
    )
    cve_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cves.id", ondelete="CASCADE"), primary_key=True, index=True
    )
    extracted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    paragraph_indices: Mapped[list[int] | None] = mapped_column(ARRAY(SmallInteger), nullable=True)

    # Relationships
    entry = relationship("Entry", back_populates="entry_cves")
    cve = relationship("CVE", back_populates="entry_cves")
