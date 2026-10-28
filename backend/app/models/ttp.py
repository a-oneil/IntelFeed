import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, SmallInteger, String, Text, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class TTP(Base):
    __tablename__ = "ttps"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    technique_id: Mapped[str] = mapped_column(String(20), unique=True, nullable=False, index=True)
    technique_name: Mapped[str] = mapped_column(String(255), nullable=False)
    tactic: Mapped[str | None] = mapped_column(String(100), index=True)
    tactics: Mapped[list] = mapped_column(JSONB, default=list)  # all ATT&CK tactics (tactic = primary)
    description: Mapped[str | None] = mapped_column(Text)
    platforms: Mapped[list] = mapped_column(JSONB, default=list)
    data_sources: Mapped[list] = mapped_column(JSONB, default=list)
    mitre_url: Mapped[str | None] = mapped_column(Text)
    detection: Mapped[str | None] = mapped_column(Text)
    is_subtechnique: Mapped[bool] = mapped_column(Boolean, default=False)
    # ATT&CK catalog metadata (hydrated from the official STIX bundles)
    parent_technique_id: Mapped[str | None] = mapped_column(String(20), index=True)
    is_deprecated: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    superseded_by: Mapped[str | None] = mapped_column(String(20))  # replacement technique for revoked entries
    matrix_domain: Mapped[str | None] = mapped_column(String(20), index=True)  # enterprise | mobile | ics
    # Security controls that mitigate the technique, from CTID's mappings
    # (the ``ctid`` enrichment source): "AC-06", "CIS-13.7".
    nist_controls: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    cis_controls: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    article_count: Mapped[int] = mapped_column(Integer, default=1)
    wikipedia_url: Mapped[str | None] = mapped_column(Text)
    wikipedia_content: Mapped[str | None] = mapped_column(Text)
    wikipedia_image_url: Mapped[str | None] = mapped_column(Text)
    # --- AI-extraction provenance (Engine → Extraction management tab) ---
    # TTPs are ATT&CK-catalog-validated (never gated), so needs_review stays false.
    created_via: Mapped[str | None] = mapped_column(String(20), nullable=True, index=True)
    created_from_entry_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entries.id", ondelete="SET NULL"), nullable=True
    )
    created_confidence: Mapped[str | None] = mapped_column(String(10), nullable=True)
    needs_review: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")

    # Relationships
    entry_ttps = relationship("EntryTTP", back_populates="ttp", cascade="all, delete-orphan")
    ttp_mitigations = relationship("TTPMitigation", back_populates="ttp", cascade="all, delete-orphan")


class EntryTTP(Base):
    __tablename__ = "entry_ttps"

    entry_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entries.id", ondelete="CASCADE"), primary_key=True
    )
    ttp_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ttps.id", ondelete="CASCADE"), primary_key=True, index=True
    )
    confidence: Mapped[str | None] = mapped_column(String(10))
    source_text: Mapped[str | None] = mapped_column(Text)
    extracted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    paragraph_indices: Mapped[list[int] | None] = mapped_column(ARRAY(SmallInteger), nullable=True)
    # The concrete artefact the source sentence documents, typed so a rule
    # draft can compile it into a selection clause instead of re-deriving it
    # from prose: domain_pattern | path | cmdline | registry | client_id |
    # header | hash | other.
    observable_type: Mapped[str | None] = mapped_column(String(20))
    observable_value: Mapped[str | None] = mapped_column(Text)
    #: Where a defender would see this activity — the non-endpoint bridge:
    #: endpoint | dns | netflow | proxy | firewall | vpn | identity |
    #: cloudtrail | email_gw | ot. Lets the coverage workspace and Threats
    #: board answer "what's detectable in telemetry I actually have."
    telemetry: Mapped[str | None] = mapped_column(String(20))

    # Relationships
    entry = relationship("Entry", back_populates="entry_ttps")
    ttp = relationship("TTP", back_populates="entry_ttps")
