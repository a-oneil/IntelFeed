"""Telegram link mentions discovered in ingested entry content.

Two tables:
- telegram_channel_mentions: deduped per-channel-handle aggregate. One row per
  channel mentioned across all ingested feeds; tracks first/last seen, mention
  count, and operator state (dismissed, manually subscribed). The Workbench
  panel queries this.
- telegram_link_mentions: raw per-occurrence link mentions with back-pointer to
  the source entry/feed and the original URL. Used for "show me where this
  channel was mentioned" drill-down.
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class TelegramChannelMention(Base):
    __tablename__ = "telegram_channel_mentions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # Lowercase handle (for channels) or "invite:<hash>" (for invite-only channels we haven't joined)
    handle: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    display_handle: Mapped[str | None] = mapped_column(String(255))
    canonical_url: Mapped[str] = mapped_column(Text, nullable=False)
    # channel | invite | message (last-seen kind; message implies channel exists)
    primary_link_type: Mapped[str] = mapped_column(String(20), default="channel")
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    mention_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    distinct_feed_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    # Cached: do we have a Telegram feed wired up for this channel? Refreshed on lookup.
    feed_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("feeds.id", ondelete="SET NULL"), nullable=True
    )
    # Operator state
    dismissed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    dismissed_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    notes: Mapped[str | None] = mapped_column(Text)

    links = relationship("TelegramLinkMention", back_populates="channel", cascade="all, delete-orphan")
    feed = relationship("Feed", foreign_keys=[feed_id])


class TelegramLinkMention(Base):
    __tablename__ = "telegram_link_mentions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    channel_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("telegram_channel_mentions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    entry_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entries.id", ondelete="CASCADE"), nullable=False, index=True
    )
    feed_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("feeds.id", ondelete="SET NULL"), nullable=True, index=True
    )
    url: Mapped[str] = mapped_column(Text, nullable=False)
    # channel | invite | message | deep_link
    link_type: Mapped[str] = mapped_column(String(20), default="channel")
    message_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    invite_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    channel = relationship("TelegramChannelMention", back_populates="links")

    __table_args__ = (
        # Don't create duplicate link rows for the same (entry, url) pair if the scanner runs twice
        UniqueConstraint("entry_id", "url", name="uq_telegram_link_entry_url"),
    )
