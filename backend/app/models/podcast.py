import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Podcast(Base):
    __tablename__ = "podcasts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    feed_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("feeds.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    author: Mapped[str | None] = mapped_column(String(255))
    categories: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    is_explicit: Mapped[bool] = mapped_column(Boolean, default=False)
    podcast_type: Mapped[str] = mapped_column(String(20), default="episodic")  # episodic, serial
    artwork_url: Mapped[str | None] = mapped_column(Text)
    metadata_: Mapped[dict] = mapped_column("metadata", JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    # Relationships
    feed = relationship("Feed", back_populates="podcast")
