import uuid

from sqlalchemy import Boolean, ForeignKey, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class AITaskAssignment(Base):
    __tablename__ = "ai_task_assignments"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    task_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ai_tasks.id", ondelete="CASCADE"), nullable=False, index=True
    )
    provider_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ai_providers.id", ondelete="CASCADE"), nullable=False, index=True
    )
    model_name: Mapped[str] = mapped_column(String(100), nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    execution_mode: Mapped[str] = mapped_column(String(10), default="api")  # "api" or "agent"
    config: Mapped[dict] = mapped_column(JSONB, default=dict)

    __table_args__ = (UniqueConstraint("task_id", name="uq_ai_task_assignments_task_id"),)

    # Relationships
    creator = relationship("User", back_populates="ai_task_assignments")
    task = relationship("AITask", back_populates="assignments")
    provider = relationship("AIProvider", back_populates="task_assignments")
