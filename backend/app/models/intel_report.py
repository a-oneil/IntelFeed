import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class IntelReport(Base):
    __tablename__ = "intel_reports"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    template_type: Mapped[str] = mapped_column(String(30), nullable=False)
    # ioc_bulletin, actor_profile, campaign_tracker, flash_alert, landscape_report, custom
    tlp_marking: Mapped[str] = mapped_column(String(20), default="TLP:GREEN")
    status: Mapped[str] = mapped_column(String(20), default="draft", index=True)
    # draft, published, archived
    content: Mapped[dict] = mapped_column(JSONB, default=dict)
    summary: Mapped[str | None] = mapped_column(Text)
    version: Mapped[int] = mapped_column(Integer, default=1)
    entry_ids: Mapped[list[uuid.UUID]] = mapped_column(ARRAY(UUID(as_uuid=True)), default=list)
    entity_ids: Mapped[dict] = mapped_column(JSONB, default=dict)
    # {iocs: [...], ttps: [...], actors: [...], malware: [...], cves: [...]}
    tags: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Relationships
    creator = relationship("User", back_populates="intel_reports")
    versions = relationship("IntelReportVersion", back_populates="report", cascade="all, delete-orphan")


class IntelReportVersion(Base):
    __tablename__ = "intel_report_versions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    report_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("intel_reports.id", ondelete="CASCADE"), index=True
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    content: Mapped[dict] = mapped_column(JSONB, nullable=False)
    change_description: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    report = relationship("IntelReport", back_populates="versions")
