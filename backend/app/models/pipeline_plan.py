import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class PipelinePlan(Base):
    """Data-defined pipeline composition for a scope (global / category / feed).

    stages: {stage_name: {"enabled": bool, "config": {...}}} — partial; anything
    unspecified falls through to the next scope and ultimately to the values
    synthesized from the legacy Feed booleans (which stay authoritative until
    they're dropped in the phase-6 follow-up migration).
    """

    __tablename__ = "pipeline_plans"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    scope_type: Mapped[str] = mapped_column(String(10), nullable=False)  # global | category | feed
    scope_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    stages: Mapped[dict] = mapped_column(JSONB, default=dict)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        UniqueConstraint(
            "scope_type",
            "scope_id",
            name="uq_pipeline_plan_scope",
            postgresql_nulls_not_distinct=True,
        ),
    )
