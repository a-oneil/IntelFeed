"""Intel profiles — named, reusable report scopes.

A profile is a saved regions × verticals combination (a customer, a client
portfolio, a watch area). The platform is enterprise-agnostic: nothing is
"the org" — analysts keep one profile per scope they report against, and
exposure reports, standing briefs, and threat-surface previews all take a
profile as input.
"""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class IntelProfile(Base):
    __tablename__ = "intel_profiles"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    # Regions the profile operates in, as country entity ids.
    country_ids: Mapped[list[uuid.UUID]] = mapped_column(ARRAY(UUID(as_uuid=True)), default=list)
    # Canonical sector slugs (intelligence.sectors vocabulary).
    sectors: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    window_days: Mapped[int] = mapped_column(Integer, default=90)
    # Keep/Drop decisions from the last exposure build, remembered per profile:
    # {"kept": {"actors": [...], "malware": [...]}, "dropped": {...}}
    curation: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
