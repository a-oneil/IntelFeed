import uuid
from datetime import date, datetime

from sqlalchemy import Computed, Date, DateTime, ForeignKey, Integer, SmallInteger, String, Text, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

PRODUCT_TYPES = [
    "os",
    "application",
    "security_tool",
    "network_device",
    "cloud_service",
    "database",
    "firmware",
    "library",
    "other",
]


class Product(Base):
    __tablename__ = "products"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    vendor_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("vendors.id", ondelete="SET NULL"), nullable=True, index=True
    )
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    aliases: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    # Hardened normal form of ``name`` (see entity_norm() in models/entity_index.py
    # and normalize_entity_name() in intelligence/entity_resolution.py).
    normalized_name: Mapped[str | None] = mapped_column(
        String(255), Computed("entity_norm(name)", persisted=True), nullable=True, index=True
    )
    description: Mapped[str | None] = mapped_column(Text)
    product_type: Mapped[str | None] = mapped_column(String(50), index=True)
    website: Mapped[str | None] = mapped_column(Text)
    # From endoflife.date (app/enrichment/endoflife.py): maintained,
    # security_only, eol or unknown; and the soonest end of security support.
    support_status: Mapped[str | None] = mapped_column(String(20))
    next_eol: Mapped[date | None] = mapped_column(Date)
    article_count: Mapped[int] = mapped_column(Integer, default=1)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    wikipedia_url: Mapped[str | None] = mapped_column(Text)
    wikipedia_content: Mapped[str | None] = mapped_column(Text)
    wikipedia_image_url: Mapped[str | None] = mapped_column(Text)
    metadata_: Mapped[dict] = mapped_column("metadata_", JSONB, default=dict)

    # Relationships
    vendor = relationship("Vendor", back_populates="products")
    entry_products = relationship("EntryProduct", back_populates="product", cascade="all, delete-orphan")


class EntryProduct(Base):
    __tablename__ = "entry_products"

    entry_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("entries.id", ondelete="CASCADE"),
        primary_key=True,
    )
    product_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("products.id", ondelete="CASCADE"),
        primary_key=True,
        index=True,
    )
    confidence: Mapped[str | None] = mapped_column(String(10))
    source: Mapped[str | None] = mapped_column(String(20))
    matched_names: Mapped[list[str] | None] = mapped_column(ARRAY(Text), nullable=True)
    extracted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    paragraph_indices: Mapped[list[int] | None] = mapped_column(ARRAY(SmallInteger), nullable=True)

    # Relationships
    entry = relationship("Entry", back_populates="entry_products")
    product = relationship("Product", back_populates="entry_products")
