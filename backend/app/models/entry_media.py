import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class EntryMedia(Base):
    __tablename__ = "entry_media"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entry_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entries.id", ondelete="CASCADE"), nullable=False, index=True
    )
    media_type: Mapped[str] = mapped_column(String(20), nullable=False)  # audio, video, image, document
    url: Mapped[str] = mapped_column(Text, nullable=False)
    mime_type: Mapped[str | None] = mapped_column(String(100))
    file_size: Mapped[int | None] = mapped_column(BigInteger)
    duration_seconds: Mapped[int | None] = mapped_column(Integer)
    thumbnail_url: Mapped[str | None] = mapped_column(Text)
    transcript_text: Mapped[str | None] = mapped_column(Text)
    metadata_: Mapped[dict] = mapped_column("metadata", JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    entry = relationship("Entry", back_populates="media")
    playback_progress = relationship("PlaybackProgress", back_populates="entry_media", cascade="all, delete-orphan")
