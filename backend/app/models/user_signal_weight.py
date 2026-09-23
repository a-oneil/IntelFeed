"""Per-user learned signal-family weights, fitted from Radar thumbs.

The global engine already turns Radar feedback into a bounded ±10% family
nudge (``recompute_signal_rates`` → ``FEEDBACK_NUDGE_REDIS_KEY``), but that
pools every analyst's votes into one set of multipliers baked into the stored
``Entry.priority_score``. This table is the per-analyst counterpart: one row
per (user, family), fitted nightly from that user's own verdicts and applied
at *read* time as a lift on the Radar ordering — exactly the way My Stack
exposure works. The stored score stays global, so personalisation is always
one toggle away from off.
"""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class UserSignalWeight(Base):
    __tablename__ = "user_signal_weights"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # One of app.intelligence.signals.DEFAULT_FAMILY_MULTIPLIERS.
    family: Mapped[str] = mapped_column(String(20), nullable=False)
    # Fitted multiplier, clamped to [PERSONAL_WEIGHT_MIN, PERSONAL_WEIGHT_MAX].
    weight: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    # Vote tallies behind the fit — shown in the UI so the number is auditable.
    up_votes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    down_votes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    sample_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (UniqueConstraint("user_id", "family", name="uq_user_signal_weights_user_family"),)
