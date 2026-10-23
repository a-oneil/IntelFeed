import uuid
from datetime import datetime
from decimal import Decimal

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, Numeric, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class AIResult(Base):
    __tablename__ = "ai_results"
    __table_args__ = (
        Index("ix_ai_results_target_task_current", "target_type", "target_id", "task_id", "is_current"),
        Index("ix_ai_results_user_created", "user_id", "created_at"),
        Index("ix_ai_results_key_owner_created", "key_owner_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entry_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entries.id", ondelete="CASCADE"), index=True
    )
    target_type: Mapped[str | None] = mapped_column(String(20), index=True)
    target_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), index=True)
    is_current: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default="true", index=True)
    task_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ai_tasks.id"), nullable=False, index=True
    )
    provider_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("ai_providers.id"), index=True)
    model_name: Mapped[str | None] = mapped_column(String(100))
    prompt_used: Mapped[str | None] = mapped_column(Text)
    raw_response: Mapped[str | None] = mapped_column(Text)
    parsed_result: Mapped[dict | None] = mapped_column(JSONB)
    tokens_input: Mapped[int | None] = mapped_column(Integer)
    tokens_output: Mapped[int | None] = mapped_column(Integer)
    cost_estimate: Mapped[Decimal | None] = mapped_column(Numeric(10, 6))
    processing_time_ms: Mapped[int | None] = mapped_column(Integer)
    # Who asked and who answered. user_id is the person the call is attributed
    # to (the clicker, the rule author, the sharer); caller_kind says whether
    # that person actually initiated it — automation and share traffic are
    # billed as pipeline. key_owner_id is whose personal provider answered
    # (NULL = the instance's own). provider_name survives provider renames.
    # All four are NULL on rows written before attribution existed.
    user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    key_owner_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    caller_kind: Mapped[str | None] = mapped_column(String(12))
    provider_name: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    entry = relationship("Entry", back_populates="ai_results")
    task = relationship("AITask", back_populates="results")
    provider = relationship("AIProvider", back_populates="results")
