"""Narrative themes: the day-briefing's own grouping of the day's articles.

The daily briefing already does something the engine pays an AI nowhere else to
do — it reads a whole day of reporting and sorts it into `### Theme` sections,
linking every article it cites back by entry id. That structure was rendered,
shown to a reader, and thrown away.

These two tables keep it. `narrative_briefings` records that a day's briefing
was parsed (so "no rows for this entry" can be told apart from "this day was
never parsed"); `narrative_theme_members` records which articles the briefing
placed under which heading.

Parsing costs nothing — it reads markdown that was already generated and
cached. See app/intelligence/narrative_themes.py.
"""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base

#: Section of the briefing an article was cited in. Only `theme` rows carry a
#: heading; the others are the briefing's own leftover buckets, which is itself
#: worth knowing — an article the briefing could not place under any theme is
#: not corroborating anything.
SECTION_THEME = "theme"
SECTION_NOTABLE = "notable"
SECTION_CLOSER = "closer"
SECTION_TLDR = "tldr"


class NarrativeBriefing(Base):
    """One parsed daily briefing."""

    __tablename__ = "narrative_briefings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    day_key: Mapped[str] = mapped_column(String(10), nullable=False, unique=True, index=True)
    theme_count: Mapped[int] = mapped_column(Integer, default=0)
    cited_entry_count: Mapped[int] = mapped_column(Integer, default=0)
    parsed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class NarrativeThemeMember(Base):
    """One article the briefing cited, and where it placed it."""

    __tablename__ = "narrative_theme_members"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    day_key: Mapped[str] = mapped_column(String(10), nullable=False, index=True)
    entry_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entries.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Empty string, never NULL, for the non-theme sections: it keeps the
    # uniqueness constraint meaningful (Postgres treats NULLs as distinct, so a
    # nullable column here would let the same citation be stored twice).
    theme: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    section: Mapped[str] = mapped_column(String(20), nullable=False, default=SECTION_THEME)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        UniqueConstraint("day_key", "entry_id", "theme", name="uq_narrative_theme_member"),
        Index("ix_narrative_theme_members_day_theme", "day_key", "theme"),
    )
