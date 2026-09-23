"""Audit log for AI-driven validation of entity↔entry links.

One row per decision made by the `entity_link_validation` AI task. Snapshots
the junction row's original column values so we can restore links the AI
removed in error (via `POST /api/admin/link-validation/log/{id}/restore`).

`action` values:
  - 'shadow_remove'         — link_validation_mode == 'shadow'; would have
    removed but did not touch the junction row or article_count.
  - 'removed'               — link_validation_mode == 'apply'; junction row
    deleted.
  - 'restored'              — operator restored a previously-removed link
    from this log row's snapshot columns.
  - 'needs_reclassification' — Claude judged that the article correctly
    references the entity but the entity is filed under the wrong
    entity_type (e.g. a threat actor stored as a malware family). The
    junction stays intact; `suggested_entity_type` names the correct type.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, SmallInteger, String, Text, func
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class EntityLinkValidationLog(Base):
    __tablename__ = "entity_link_validation_log"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entry_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entries.id", ondelete="CASCADE"), nullable=False, index=True
    )
    entity_type: Mapped[str] = mapped_column(String(20), nullable=False)
    # No FK so we can keep audit history after an entity is deleted.
    entity_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    entity_name_snapshot: Mapped[str | None] = mapped_column(String(255))
    action: Mapped[str] = mapped_column(String(40), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text)
    # Snapshot of the junction row at decision time — needed for restore.
    original_source: Mapped[str | None] = mapped_column(String(20))
    original_confidence: Mapped[str | None] = mapped_column(String(10))
    original_matched_names: Mapped[list[str] | None] = mapped_column(ARRAY(Text), nullable=True)
    original_paragraph_indices: Mapped[list[int] | None] = mapped_column(ARRAY(SmallInteger), nullable=True)
    original_extracted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # When action='needs_reclassification', the entity_type Claude recommends.
    suggested_entity_type: Mapped[str | None] = mapped_column(String(20))
    # Pointer to the full AI prompt/response that produced this decision.
    ai_result_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ai_results.id", ondelete="SET NULL"), nullable=True
    )
    # Hygiene-reviewer verdict on pending advisories: 'approve' | 'reject' |
    # 'unsure'. NULL = not yet reviewed. See workers/hygiene_review_tasks.py.
    review_decision: Mapped[str | None] = mapped_column(String(10), nullable=True)
    review_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        Index("ix_link_validation_log_entity", "entity_type", "entity_id"),
        Index("ix_link_validation_log_created_at_desc", "created_at"),
        Index("ix_link_validation_log_action_created_at", "action", "created_at"),
    )

    entry = relationship("Entry", back_populates="link_validation_log")
