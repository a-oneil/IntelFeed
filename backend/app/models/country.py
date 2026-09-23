import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, SmallInteger, String, Text, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Country(Base):
    __tablename__ = "countries"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    iso_code: Mapped[str | None] = mapped_column(String(3))
    aliases: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    region: Mapped[str | None] = mapped_column(String(100))
    description: Mapped[str | None] = mapped_column(Text)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    article_count: Mapped[int] = mapped_column(Integer, default=1)
    wikipedia_url: Mapped[str | None] = mapped_column(Text)
    wikipedia_content: Mapped[str | None] = mapped_column(Text)
    wikipedia_image_url: Mapped[str | None] = mapped_column(Text)
    metadata_: Mapped[dict] = mapped_column("metadata_", JSONB, default=dict)

    # Relationships
    entry_countries = relationship("EntryCountry", back_populates="country", cascade="all, delete-orphan")
    targeted_by_actor_links = relationship(
        "ThreatActorTargetCountry", back_populates="country", cascade="all, delete-orphan"
    )
    campaign_links = relationship("CampaignCountry", back_populates="country", cascade="all, delete-orphan")
    threat_actor_origins = relationship(
        "ThreatActor", back_populates="origin_country", foreign_keys="[ThreatActor.origin_country_id]"
    )


class EntryCountry(Base):
    __tablename__ = "entry_countries"

    entry_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entries.id", ondelete="CASCADE"), primary_key=True
    )
    country_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("countries.id", ondelete="CASCADE"), primary_key=True, index=True
    )
    confidence: Mapped[str | None] = mapped_column(String(10))
    source: Mapped[str | None] = mapped_column(String(20))
    role: Mapped[str | None] = mapped_column(String(20))
    # origin, target, infrastructure, mentioned
    matched_names: Mapped[list[str] | None] = mapped_column(ARRAY(Text), nullable=True)
    extracted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    paragraph_indices: Mapped[list[int] | None] = mapped_column(ARRAY(SmallInteger), nullable=True)

    # Relationships
    entry = relationship("Entry", back_populates="entry_countries")
    country = relationship("Country", back_populates="entry_countries")
