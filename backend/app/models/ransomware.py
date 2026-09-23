"""Ransomware leak-site / victim tracker models.

Two nouns, one join:

  RansomwareVictim   — the *organization* that got listed. Dedup target,
                       watchable, alias-indexed (follows the standard entity
                       shape, compare vendor.py/product.py: name + aliases +
                       DB-computed normalized_name via entity_norm()).
  VictimDisclosure   — one *posting event* (org × group × timestamp × leak
                       site). An org has many disclosures (re-extortion, a
                       second group re-listing the same victim), which is what
                       keeps "posted by Qilin and later LockBit" one org / two
                       disclosures instead of two duplicate orgs.

See planning/ransomware-victim-tracker.md §3. The victim is registered into the
alias-index machinery (models/entity_index.py ALIAS_INDEXED_TABLES), so it needs
`name` + `aliases` columns and the entity_norm() trigger fires on write.
"""

import uuid
from datetime import datetime

from sqlalchemy import Computed, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class RansomwareVictim(Base):
    __tablename__ = "ransomware_victims"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # Org name as posted on the leak site. Not unique — dedup goes through
    # normalized_name / domain, not the raw surface form.
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    aliases: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    # Hardened normal form of ``name`` (see entity_norm() in models/entity_index.py
    # and normalize_entity_name() in intelligence/entity_resolution.py). Primary
    # dedup key when ``domain`` is absent.
    normalized_name: Mapped[str | None] = mapped_column(
        String(255), Computed("entity_norm(name)", persisted=True), nullable=True, index=True
    )
    # Strongest dedup signal when present (leak sites often post the victim's site).
    domain: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    country_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("countries.id", ondelete="SET NULL"), nullable=True, index=True
    )
    # Canonical sector slug via intelligence.sectors.normalize_sector.
    sector: Mapped[str | None] = mapped_column(String(50), nullable=True, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    # Denormalized count of disclosures, maintained by the resolver (like article_count).
    disclosure_count: Mapped[int] = mapped_column(Integer, default=0)
    metadata_: Mapped[dict] = mapped_column("metadata_", JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    # Relationships
    country = relationship("Country", foreign_keys=[country_id])
    disclosures = relationship(
        "VictimDisclosure",
        back_populates="victim",
        cascade="all, delete-orphan",
        order_by="VictimDisclosure.posted_at.desc()",
    )


class VictimDisclosure(Base):
    __tablename__ = "victim_disclosures"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    victim_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ransomware_victims.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Ransomware group as a ThreatActor (actor_type='ransomware'). Nullable so a
    # posting from an unresolvable/new group still records rather than dropping.
    group_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("threat_actors.id", ondelete="SET NULL"), nullable=True, index=True
    )
    # Group name exactly as posted, before resolution to a ThreatActor.
    group_name_raw: Mapped[str | None] = mapped_column(String(255), nullable=True)
    leak_site_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    # "discovered" timestamp on the source feed.
    posted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    # Countdown / publish deadline if the group gave one.
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    country_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("countries.id", ondelete="SET NULL"), nullable=True, index=True
    )
    sector: Mapped[str | None] = mapped_column(String(50), nullable=True, index=True)
    # Free-text claim, e.g. "180K records / 420GB".
    claimed_data: Mapped[str | None] = mapped_column(Text, nullable=True)
    # "ransomware.live" | "ecrime.ch" | ... — the source column earns its keep once
    # dedup spans multiple sources.
    source: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    # Stable cross-run dedup id: sha256(source + group + victim + posted)[:32].
    guid: Mapped[str] = mapped_column(String(64), nullable=False)
    metadata_: Mapped[dict] = mapped_column("metadata_", JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (UniqueConstraint("source", "guid", name="uq_victim_disclosure_source_guid"),)

    # Relationships
    victim = relationship("RansomwareVictim", back_populates="disclosures")
    group = relationship("ThreatActor", foreign_keys=[group_id])
    country = relationship("Country", foreign_keys=[country_id])
