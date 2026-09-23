import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class DetectionRuleVersion(Base):
    __tablename__ = "detection_rule_versions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    rule_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("detection_rules.id", ondelete="CASCADE"), index=True
    )
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)
    rule_content: Mapped[str] = mapped_column(Text, nullable=False)
    rule_type: Mapped[str | None] = mapped_column(String(30))
    change_description: Mapped[str | None] = mapped_column(Text)
    changed_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    rule = relationship("DetectionRule", back_populates="versions")
