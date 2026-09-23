import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, SmallInteger, String, Text, func
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Mitigation(Base):
    __tablename__ = "mitigations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    mitre_id: Mapped[str | None] = mapped_column(String(20), unique=True, index=True)
    # M-IDs are unique; non-MITRE mitigations (CIS/NIST-only) won't have one
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text)
    mitre_url: Mapped[str | None] = mapped_column(Text)
    cis_controls: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    nist_controls: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    article_count: Mapped[int] = mapped_column(Integer, default=1)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    wikipedia_url: Mapped[str | None] = mapped_column(Text)
    wikipedia_content: Mapped[str | None] = mapped_column(Text)
    wikipedia_image_url: Mapped[str | None] = mapped_column(Text)

    # Relationships
    entry_mitigations = relationship("EntryMitigation", back_populates="mitigation", cascade="all, delete-orphan")
    ttp_mitigations = relationship("TTPMitigation", back_populates="mitigation", cascade="all, delete-orphan")


class EntryMitigation(Base):
    __tablename__ = "entry_mitigations"

    entry_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entries.id", ondelete="CASCADE"), primary_key=True
    )
    mitigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("mitigations.id", ondelete="CASCADE"), primary_key=True, index=True
    )
    confidence: Mapped[str | None] = mapped_column(String(10))
    source: Mapped[str | None] = mapped_column(String(20))  # regex | ai
    extracted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    paragraph_indices: Mapped[list[int] | None] = mapped_column(ARRAY(SmallInteger), nullable=True)

    # Relationships
    entry = relationship("Entry", back_populates="entry_mitigations")
    mitigation = relationship("Mitigation", back_populates="entry_mitigations")


class TTPMitigation(Base):
    """Links a TTP to its recommended mitigations (M-ID mappings)."""

    __tablename__ = "ttp_mitigations"

    ttp_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ttps.id", ondelete="CASCADE"), primary_key=True
    )
    mitigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("mitigations.id", ondelete="CASCADE"), primary_key=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    ttp = relationship("TTP", back_populates="ttp_mitigations")
    mitigation = relationship("Mitigation", back_populates="ttp_mitigations")
