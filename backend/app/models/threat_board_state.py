import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class ThreatBoardState(Base):
    """Per-threat triage decision on the Intel → Rules board.

    Deliberately not a lifecycle. IntelFeed does not deploy rules and cannot see
    whether one is running, so there is no stage, owner or review date here —
    only whether you have dealt with this threat.

    ``new_count_at_decision`` is what makes a snooze date unnecessary: a handled
    threat comes back on its own once its live count of first-seen techniques
    exceeds the count at the time you dismissed it. New tradecraft reopens the
    row; a quiet fortnight does not.
    """

    __tablename__ = "threat_board_state"

    # One of app.entity_types.* — import the constants, never type the strings.
    entity_type: Mapped[str] = mapped_column(String(30), primary_key=True)
    entity_key: Mapped[str] = mapped_column(String(255), primary_key=True)
    state: Mapped[str] = mapped_column(String(10), nullable=False, default="open")  # open | handled | muted
    new_count_at_decision: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    decided_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    decided_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    note: Mapped[str | None] = mapped_column(Text)
