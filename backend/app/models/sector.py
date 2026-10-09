"""The sector entity and the junctions that say who targets it.

A sector is a closed-vocabulary noun (see ``app.intelligence.sectors``): one
row per canonical slug, seeded rather than extracted, never merged, never
reclassified, never autolinked. It exists as a table so a sector can be landed
on — profile, pivot, timeline, watch, workbench list — the way a country can.

Ids are deterministic (``sector_uuid(slug)``) so every install agrees on them;
the ORM default below derives the id from the slug when a caller omits it.
"""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.intelligence.sectors import sector_uuid


def _id_from_slug(context) -> uuid.UUID:
    return sector_uuid(context.get_current_parameters()["slug"])


class Sector(Base):
    __tablename__ = "sectors"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_id_from_slug)
    slug: Mapped[str] = mapped_column(String(50), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    aliases: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    description: Mapped[str | None] = mapped_column(Text)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    article_count: Mapped[int] = mapped_column(Integer, default=0)
    metadata_: Mapped[dict] = mapped_column("metadata_", JSONB, default=dict)

    # Relationships
    entry_sectors = relationship("EntrySector", back_populates="sector_ref", cascade="all, delete-orphan")
    targeted_by_actor_links = relationship(
        "ThreatActorTargetSector", back_populates="sector", cascade="all, delete-orphan"
    )
    targeted_by_malware_links = relationship(
        "MalwareTargetSector", back_populates="sector", cascade="all, delete-orphan"
    )
    campaign_links = relationship("CampaignSector", back_populates="sector", cascade="all, delete-orphan")


class ThreatActorTargetSector(Base):
    """An actor targets a sector — the claims layer behind the profile chips.

    ``source`` records which door wrote the row: ``rollup`` (the nightly
    aggregation of entry_sectors through the actor's articles, with
    ``article_count`` as its evidence), ``enrichment`` (MISP Galaxy / CFR),
    ``seed`` (the one-time backfill of the legacy free-text column) or
    ``analyst``. The rollup only ever rewrites its own rows.
    """

    __tablename__ = "threat_actor_target_sectors"

    threat_actor_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("threat_actors.id", ondelete="CASCADE"), primary_key=True
    )
    sector_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("sectors.id", ondelete="CASCADE"), primary_key=True, index=True
    )
    source: Mapped[str] = mapped_column(String(20), nullable=False, default="analyst")
    article_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    threat_actor = relationship("ThreatActor", back_populates="target_sector_links")
    sector = relationship("Sector", back_populates="targeted_by_actor_links")


class MalwareTargetSector(Base):
    """A malware family targets a sector. Same semantics as the actor junction."""

    __tablename__ = "malware_target_sectors"

    malware_family_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("malware_families.id", ondelete="CASCADE"), primary_key=True
    )
    sector_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("sectors.id", ondelete="CASCADE"), primary_key=True, index=True
    )
    source: Mapped[str] = mapped_column(String(20), nullable=False, default="analyst")
    article_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    malware_family = relationship("MalwareFamily", back_populates="target_sector_links")
    sector = relationship("Sector", back_populates="targeted_by_malware_links")


class CampaignSector(Base):
    """A campaign's victim verticals, curated by the analyst who owns it."""

    __tablename__ = "campaign_sectors"

    campaign_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("campaigns.id", ondelete="CASCADE"), primary_key=True
    )
    sector_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("sectors.id", ondelete="CASCADE"), primary_key=True, index=True
    )
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    campaign = relationship("Campaign", back_populates="sector_links")
    sector = relationship("Sector", back_populates="campaign_links")
