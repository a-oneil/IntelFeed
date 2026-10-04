import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, UniqueConstraint, func, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Tag(Base):
    __tablename__ = "tags"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    color: Mapped[str] = mapped_column(String(7), default="#6B7280", nullable=False)
    # Promoted tags render as chips in the entry's badge row; the rest stay a
    # quiet label in the meta line.
    display_as_chip: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false", nullable=False)
    description: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (UniqueConstraint("name", name="uq_tags_name"),)

    # Relationships
    creator = relationship("User", back_populates="tags")
    entry_tags = relationship("EntryTag", back_populates="tag", cascade="all, delete-orphan")


class EntryTag(Base):
    """One tag on one entry.

    `user_id` NULL is a shared assignment, visible to everyone. Set, it is a
    personal stamp — a chip an automation rule applied for its owner — visible
    only to that user. Read through `app.services.entry_tags.visible_to`.
    """

    __tablename__ = "entry_tags"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, server_default=text("gen_random_uuid()")
    )
    entry_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entries.id", ondelete="CASCADE"), nullable=False
    )
    tag_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tags.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True
    )

    __table_args__ = (
        UniqueConstraint(
            "entry_id", "tag_id", "user_id", name="uq_entry_tags_entry_tag_user", postgresql_nulls_not_distinct=True
        ),
    )

    # Relationships
    tag = relationship("Tag", back_populates="entry_tags")
    entry = relationship("Entry", back_populates="entry_tags")
