import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class AutomationLog(Base):
    __tablename__ = "automation_logs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    rule_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("automation_rules.id", ondelete="CASCADE"), nullable=False, index=True
    )
    entry_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entries.id", ondelete="SET NULL")
    )
    trigger_type: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)  # success, error, skipped
    actions_executed: Mapped[list] = mapped_column(JSONB, default=list)
    error_message: Mapped[str | None] = mapped_column(Text)
    executed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    rule = relationship("AutomationRule", back_populates="logs")
    entry = relationship("Entry", back_populates="automation_logs")
