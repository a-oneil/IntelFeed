"""Entry ↔ sector links — controlled-vocabulary victim sector targeting.

Sectors are not an entity table: `sector` holds a canonical slug from
app.intelligence.sectors (e.g. "financial-services"). Rows record which
sectors an article describes as TARGETED, powering the Priority Queue
"my sectors" boost and actor/malware targeted-sector aggregation.
"""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class EntrySector(Base):
    __tablename__ = "entry_sectors"

    entry_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entries.id", ondelete="CASCADE"), primary_key=True
    )
    sector: Mapped[str] = mapped_column(String(50), primary_key=True, index=True)
    confidence: Mapped[str | None] = mapped_column(String(10))
    source: Mapped[str | None] = mapped_column(String(20))
    extracted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    entry = relationship("Entry", back_populates="entry_sectors")
