import uuid
from datetime import datetime

from sqlalchemy import Computed, DateTime, ForeignKey, Integer, SmallInteger, String, Text, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

VENDOR_TYPES = [
    "software",
    "hardware",
    "cloud",
    "security",
    "networking",
    "semiconductor",
    "telecommunications",
    "other",
]


class Vendor(Base):
    __tablename__ = "vendors"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    aliases: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    # Hardened normal form of ``name`` (see entity_norm() in models/entity_index.py
    # and normalize_entity_name() in intelligence/entity_resolution.py).
    normalized_name: Mapped[str | None] = mapped_column(
        String(255), Computed("entity_norm(name)", persisted=True), nullable=True, index=True
    )
    description: Mapped[str | None] = mapped_column(Text)
    website: Mapped[str | None] = mapped_column(Text)
    vendor_type: Mapped[str | None] = mapped_column(String(50), index=True)
    #: The country the company is from (Wikidata P17), when IntelFeed tracks it.
    #: A link to a country row, as a victim's country and an actor's origin are.
    country_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("countries.id", ondelete="SET NULL"), nullable=True, index=True
    )
    article_count: Mapped[int] = mapped_column(Integer, default=1)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    wikipedia_url: Mapped[str | None] = mapped_column(Text)
    wikipedia_content: Mapped[str | None] = mapped_column(Text)
    wikipedia_image_url: Mapped[str | None] = mapped_column(Text)
    metadata_: Mapped[dict] = mapped_column("metadata_", JSONB, default=dict)

    # Relationships
    entry_vendors = relationship("EntryVendor", back_populates="vendor", cascade="all, delete-orphan")
    products = relationship("Product", back_populates="vendor")
    country = relationship("Country", foreign_keys=[country_id])


class EntryVendor(Base):
    __tablename__ = "entry_vendors"

    entry_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("entries.id", ondelete="CASCADE"),
        primary_key=True,
    )
    vendor_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("vendors.id", ondelete="CASCADE"),
        primary_key=True,
        index=True,
    )
    confidence: Mapped[str | None] = mapped_column(String(10))
    source: Mapped[str | None] = mapped_column(String(20))
    matched_names: Mapped[list[str] | None] = mapped_column(ARRAY(Text), nullable=True)
    extracted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    paragraph_indices: Mapped[list[int] | None] = mapped_column(ARRAY(SmallInteger), nullable=True)

    # Relationships
    entry = relationship("Entry", back_populates="entry_vendors")
    vendor = relationship("Vendor", back_populates="entry_vendors")
