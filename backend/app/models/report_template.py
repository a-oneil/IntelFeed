"""User-defined report templates."""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class ReportTemplate(Base):
    __tablename__ = "report_templates"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    template_slug: Mapped[str] = mapped_column(String(50), unique=True, nullable=False, index=True)
    sections: Mapped[list] = mapped_column(JSONB, default=list)
    # [{name: str, title: str, description: str, ai_prompt_hint: str | None,
    #   required: bool, type: "narrative" | "data"}]
    is_builtin: Mapped[bool] = mapped_column(Boolean, default=False)
    is_shared: Mapped[bool] = mapped_column(Boolean, default=False)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    # Relationships
    creator = relationship("User", foreign_keys=[created_by], back_populates="report_templates")
