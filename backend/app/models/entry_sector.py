"""Entry ↔ sector links — which victim sectors an article describes as TARGETED.

Rows are written by one door only: the one-pass ``entry_analysis`` AI task via
``store_sectors`` (plus an analyst marking a sector by hand). Sectors are never
autolinked — their names are everyday words — so a row here means "this article
is about this industry being hit", not "this word appeared".

``sector`` keeps the canonical slug as a natural key (the vocabulary is closed,
so it never changes) and ``sector_id`` is the FK the correlation engine pivots
on. Every slug-keyed reader — the ``sector:`` search filter, the threat-surface
scope match, the ransomware landscape — keeps working untouched.
"""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, SmallInteger, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.intelligence.sectors import sector_uuid


def _sector_id_from_slug(context) -> uuid.UUID:
    return sector_uuid(context.get_current_parameters()["sector"])


class EntrySector(Base):
    __tablename__ = "entry_sectors"
    __table_args__ = (UniqueConstraint("entry_id", "sector_id", name="uq_entry_sectors_entry_sector_id"),)

    entry_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entries.id", ondelete="CASCADE"), primary_key=True
    )
    sector: Mapped[str] = mapped_column(String(50), primary_key=True, index=True)
    sector_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sectors.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        default=_sector_id_from_slug,
    )
    confidence: Mapped[str | None] = mapped_column(String(10))
    source: Mapped[str | None] = mapped_column(String(20))
    # Always "target" today; the column exists so the junction has the same
    # shape as entry_countries if a non-target reading is ever extracted.
    role: Mapped[str | None] = mapped_column(String(20))
    # Nothing populates this (sectors are not autolinked), but the correlation
    # engine reads paragraph_indices off every junction for proximity scoring.
    paragraph_indices: Mapped[list[int] | None] = mapped_column(ARRAY(SmallInteger), nullable=True)
    extracted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    entry = relationship("Entry", back_populates="entry_sectors")
    sector_ref = relationship("Sector", back_populates="entry_sectors")
