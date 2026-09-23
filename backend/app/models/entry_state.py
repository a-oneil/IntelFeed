import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class UserEntryState(Base):
    __tablename__ = "user_entry_states"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    entry_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entries.id", ondelete="CASCADE"), nullable=False, index=True
    )
    is_read: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    is_starred: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    is_bookmarked: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    is_hidden: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("user_id", "entry_id"),
        Index("ix_user_entry_states_user_unread", "user_id", "is_read"),
        Index("ix_user_entry_states_user_starred", "user_id", "is_starred"),
        Index("ix_user_entry_states_user_bookmarked", "user_id", "is_bookmarked"),
    )

    # Relationships
    user = relationship("User", back_populates="entry_states")
    entry = relationship("Entry", back_populates="user_states")
