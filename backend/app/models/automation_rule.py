import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class AutomationRule(Base):
    __tablename__ = "automation_rules"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    trigger_type: Mapped[str] = mapped_column(String(50), nullable=False)
    trigger_config: Mapped[dict] = mapped_column(JSONB, default=dict)
    conditions: Mapped[dict] = mapped_column(JSONB, default=dict)
    actions: Mapped[list] = mapped_column(JSONB, default=list)
    labels: Mapped[list] = mapped_column(JSONB, default=list)
    last_triggered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    run_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    # Relationships
    creator = relationship("User", back_populates="automation_rules")
    logs = relationship("AutomationLog", back_populates="rule", cascade="all, delete-orphan")
