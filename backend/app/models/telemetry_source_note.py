import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class TelemetrySourceNote(Base):
    """A note or a saved link about one telemetry source, shared with every user.

    Keyed by the source's name, not a telemetry_sources row: a catalog source
    has no row until someone enables it, and analysts can write notes about a
    source before they collect its logs. Renaming a custom inventory source
    moves its notes to the new name, unless the old name is a catalog name or
    another inventory row still has it (see _move_notes_on_rename).
    """

    __tablename__ = "telemetry_source_notes"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # A link has a url (and optionally the page's title and a quoted passage);
    # a note has content. A link can carry a note too.
    url: Mapped[str | None] = mapped_column(Text)
    page_title: Mapped[str | None] = mapped_column(String(500))
    quote: Mapped[str | None] = mapped_column(Text)
    content: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    user = relationship("User")

    __table_args__ = (
        CheckConstraint("url IS NOT NULL OR content IS NOT NULL", name="ck_telemetry_source_notes_url_or_content"),
    )
