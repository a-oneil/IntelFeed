"""Analyst decisions that a cleanup proposal should stay gone.

Dismissing a proposal deletes its log rows, but the next article that mentions
the entity would file the same proposal again. A row here makes the dismissal
stick:

  - kind='reclassify'    — stop proposing a type change for (entity_type,
    entity_id). ``other_key`` is '' (any target type).
  - kind='not_duplicate' — the pair (entity_id, other_key) is two different
    things. Stored once per pair with the smaller id in ``entity_id``.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base

KIND_RECLASSIFY = "reclassify"
KIND_NOT_DUPLICATE = "not_duplicate"


class ProposalDismissal(Base):
    __tablename__ = "proposal_dismissals"
    __table_args__ = (UniqueConstraint("kind", "entity_type", "entity_id", "other_key", name="uq_proposal_dismissal"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    kind: Mapped[str] = mapped_column(String(30), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(30), nullable=False)
    entity_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    other_key: Mapped[str] = mapped_column(String(100), nullable=False, default="", server_default="")
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
