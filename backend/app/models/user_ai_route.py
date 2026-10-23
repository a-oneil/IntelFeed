"""One person's AI routing: which of their keys answers which task.

Kept apart from ``ai_task_assignments`` on purpose. That table is the
site's, one row per task, and every admin reader (the Prompts rail,
``/assignments/all``, provisioning) assumes exactly that. Personal routes
in the same table would need a ``user_id IS NULL`` filter in each of them;
a table of their own needs none.
"""

import uuid
from datetime import datetime
from decimal import Decimal

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Numeric, String, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class UserAIRoute(Base):
    __tablename__ = "user_ai_routes"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    # NULL = this person's default key, used for every allowed task that has
    # no route of its own.
    task_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ai_tasks.id", ondelete="CASCADE"), nullable=True
    )
    provider_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ai_providers.id", ondelete="CASCADE"), nullable=False
    )
    model_name: Mapped[str] = mapped_column(String(100), nullable=False)
    config: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        Index("ix_user_ai_routes_user", "user_id"),
        Index("ix_user_ai_routes_provider", "provider_id"),
        Index(
            "uq_user_ai_routes_task", "user_id", "task_id", unique=True, postgresql_where=text("task_id IS NOT NULL")
        ),
        Index("uq_user_ai_routes_default", "user_id", unique=True, postgresql_where=text("task_id IS NULL")),
    )

    task = relationship("AITask")
    provider = relationship("AIProvider")


class UserAIPreferences(Base):
    """What one person wants when their own key can't answer, and their own cap."""

    __tablename__ = "user_ai_preferences"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    # Off: a task whose key is over its cap or failing stops with an error
    # instead of running on the instance's provider. Hidden under the
    # Required policy, where there is no fallback either way.
    fallback_to_site: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("true"), nullable=False)
    # NULL = the admin's default. A person can set this lower, never higher.
    monthly_cap_usd: Mapped[Decimal | None] = mapped_column(Numeric(10, 4), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
