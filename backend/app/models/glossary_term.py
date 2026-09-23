import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class GlossaryTerm(Base):
    __tablename__ = "glossary_terms"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    is_system: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    category: Mapped[str] = mapped_column(String(50), nullable=False)
    maturity: Mapped[str | None] = mapped_column(String(20), nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    long_description: Mapped[str | None] = mapped_column(Text, nullable=True)
    technologies: Mapped[list] = mapped_column(JSONB, default=list, server_default="[]")
    search_terms: Mapped[list] = mapped_column(JSONB, default=list, server_default="[]")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (UniqueConstraint("name", name="uq_glossary_terms_name"),)

    creator = relationship("User", foreign_keys=[created_by], back_populates="glossary_terms")
