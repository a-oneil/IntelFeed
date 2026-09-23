import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, Computed, DateTime, ForeignKey, Integer, SmallInteger, String, Text, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

if TYPE_CHECKING:
    from app.models.country import Country

from app.database import Base
from app.intelligence.actor_attributes import normalize_country, normalize_motivation


class ThreatActor(Base):
    __tablename__ = "threat_actors"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    aliases: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    # Hardened normal form of ``name`` (see entity_norm() in models/entity_index.py
    # and normalize_entity_name() in intelligence/entity_resolution.py).
    normalized_name: Mapped[str | None] = mapped_column(
        String(255), Computed("entity_norm(name)", persisted=True), nullable=True, index=True
    )
    description: Mapped[str | None] = mapped_column(Text)
    # Lightweight discriminator so the ransomware dashboard can scope to groups
    # without heuristics: 'ransomware' | 'nation-state' | 'hacktivist' | 'ecrime' | ...
    actor_type: Mapped[str | None] = mapped_column(String(30), nullable=True, index=True)
    mitre_id: Mapped[str | None] = mapped_column(String(20))
    country: Mapped[str | None] = mapped_column(String(100))
    origin_country_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("countries.id", ondelete="SET NULL"), nullable=True, index=True
    )
    motivation: Mapped[str | None] = mapped_column(String(100))
    associated_ttps: Mapped[list] = mapped_column(JSONB, default=list)
    targeted_sectors: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    # e.g. ["financial", "healthcare", "government", "energy", "technology"]
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    article_count: Mapped[int] = mapped_column(Integer, default=1)
    wikipedia_url: Mapped[str | None] = mapped_column(Text)
    wikipedia_content: Mapped[str | None] = mapped_column(Text)
    wikipedia_image_url: Mapped[str | None] = mapped_column(Text)
    metadata_: Mapped[dict] = mapped_column("metadata_", JSONB, default=dict)
    # --- AI-extraction provenance (Engine → Extraction management tab) ---
    # created_via: 'ai_extraction' | 'manual' | 'seed' | NULL(unknown/legacy)
    created_via: Mapped[str | None] = mapped_column(String(20), nullable=True, index=True)
    created_from_entry_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entries.id", ondelete="SET NULL"), nullable=True
    )
    created_confidence: Mapped[str | None] = mapped_column(String(10), nullable=True)
    # True when the resolver's creation gates flagged this in shadow mode (still minted).
    needs_review: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")

    @validates("motivation")
    def _normalize_motivation(self, _key: str, value):
        """Fold the motivation vocabulary on the way in, whoever is writing.

        `coerce_motivation` has existed since the reference-feed importer
        landed, but only that one caller used it — AI extraction, the tool
        registry, the profile editor and the AI field-fill each wrote raw, so a
        third of actors carried a motivation the facet couldn't group. The
        check belongs on the column, not on whichever caller remembers it.
        """
        return normalize_motivation(value)

    @validates("country")
    def _drop_placeholder_country(self, _key: str, value):
        """ "Unknown" is not a country. Real names pass through untouched — the
        countries table, not this hook, is what resolves them."""
        return normalize_country(value)

    # Relationships
    origin_country: Mapped["Country | None"] = relationship(
        "Country", foreign_keys=[origin_country_id], back_populates="threat_actor_origins"
    )
    target_country_links = relationship(
        "ThreatActorTargetCountry", back_populates="threat_actor", cascade="all, delete-orphan"
    )
    entry_threat_actors = relationship("EntryThreatActor", back_populates="threat_actor", cascade="all, delete-orphan")


class EntryThreatActor(Base):
    __tablename__ = "entry_threat_actors"

    entry_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entries.id", ondelete="CASCADE"), primary_key=True
    )
    threat_actor_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("threat_actors.id", ondelete="CASCADE"), primary_key=True, index=True
    )
    confidence: Mapped[str | None] = mapped_column(String(10))
    source: Mapped[str | None] = mapped_column(String(20))
    matched_names: Mapped[list[str] | None] = mapped_column(ARRAY(Text), nullable=True)
    extracted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    paragraph_indices: Mapped[list[int] | None] = mapped_column(ARRAY(SmallInteger), nullable=True)

    # Relationships
    entry = relationship("Entry", back_populates="entry_threat_actors")
    threat_actor = relationship("ThreatActor", back_populates="entry_threat_actors")
