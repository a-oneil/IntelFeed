import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class AIConversation(Base):
    """Server-side persistence for AI copilot chat threads.

    scope_type is one of: "entry" | "multi_entry" | "entity" | "global".
    scope_id holds an entry id (str), or "{entity_type}:{entity_id}", or null
    for global scope. entry_ids holds the list of entry ids for multi_entry
    scope. messages is a list of {role, content, created_at, meta?}.
    """

    __tablename__ = "ai_conversations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    title: Mapped[str | None] = mapped_column(String(200))
    scope_type: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    scope_id: Mapped[str | None] = mapped_column(String(200))
    entry_ids: Mapped[list | None] = mapped_column(JSONB)
    messages: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    # Non-null when the owner has published a read-only public share link.
    share_token: Mapped[str | None] = mapped_column(String(64), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
