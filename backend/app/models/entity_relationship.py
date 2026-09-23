import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class EntityRelationship(Base):
    __tablename__ = "entity_relationships"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_type: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    source_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    target_type: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    target_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    relationship_type: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    # uses, exploits, targets, attributed_to, variant_of, communicates_with,
    # delivers, drops, hosts, related_to
    confidence: Mapped[str] = mapped_column(String(20), default="possible")
    # confirmed, probable, possible
    source: Mapped[str] = mapped_column(String(20), default="analyst_created")
    # co_occurrence, auto_extracted, analyst_confirmed, analyst_created,
    # analyst_rejected (hidden + never resurrected by co-occurrence), external_feed
    description: Mapped[str | None] = mapped_column(Text)
    # AI adjudicator verdict: corroborated (promoted to confirmed) or
    # coincidental (demoted to possible, never re-promoted by co-occurrence).
    adjudication_verdict: Mapped[str | None] = mapped_column(String(20))
    adjudicated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    evidence_entry_ids: Mapped[list[uuid.UUID]] = mapped_column(ARRAY(UUID(as_uuid=True)), default=list)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (UniqueConstraint("source_type", "source_id", "target_type", "target_id", "relationship_type"),)

    # Relationships
    creator = relationship("User")
