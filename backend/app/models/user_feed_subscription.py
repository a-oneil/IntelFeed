import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class UserFeedSubscription(Base):
    """Which feeds a user sees, and their personal mute state.

    The feed pool (rows in `feeds`, fetching, entries) stays shared; this table
    is each analyst's view over it. Only read when the
    `per_user_subscriptions_enabled` system setting is on — with it off the app
    keeps the legacy single shared list driven by `Feed.is_muted`.
    """

    __tablename__ = "user_feed_subscriptions"
    __table_args__ = (UniqueConstraint("user_id", "feed_id", name="uq_user_feed_subscription"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    feed_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("feeds.id", ondelete="CASCADE"), nullable=False, index=True
    )
    is_muted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Paused is the per-user half of Feed.is_active. Muting keeps the articles
    # coming and only drops them out of unread counts; pausing stops this
    # reader receiving new ones at all, while the feed keeps fetching for
    # everyone else. Only consulted when per_user_subscriptions_enabled is on —
    # with it off, Feed.is_active is the single shared switch.
    is_paused: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    feed = relationship("Feed")
    user = relationship("User")
