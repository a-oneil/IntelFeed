import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class UserEntityWatch(Base):
    """Per-user entity watch/mute/stack — curation at the entity level.

    watch → read-time priority boost (+ optional automation recipe for alerts)
    mute  → entries linked to the entity are suppressed from Radar/chips
    stack → "I run this" (vendor/product only). Feeds My Stack exposure scoring:
            CVEs affecting a stack entity get a read-time boost in the Radar and
            a detection-posture flag. See planning/my-stack-exposure-scoring.md.
    """

    __tablename__ = "user_entity_watches"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    created_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    entity_type: Mapped[str] = mapped_column(String(20), nullable=False)
    # threat_actor, malware, cve, tool, vendor, product, country
    entity_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    mode: Mapped[str] = mapped_column(String(10), nullable=False)  # watch | mute
    boost: Mapped[float] = mapped_column(Float, default=1.0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (UniqueConstraint("created_by", "entity_type", "entity_id", name="uq_user_entity_watch"),)
