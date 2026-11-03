import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class AIProvider(Base):
    __tablename__ = "ai_providers"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    # claude, claude_code, ollama, openai_compatible
    provider_type: Mapped[str] = mapped_column(String(30), nullable=False)
    base_url: Mapped[str | None] = mapped_column(Text)
    api_key_encrypted: Mapped[str | None] = mapped_column(Text)
    models: Mapped[list] = mapped_column(JSONB, default=list)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    config: Mapped[dict] = mapped_column(JSONB, default=dict)
    # NULL = the instance's provider. Set = one person's key: only they can
    # list, test, edit or route it, and it goes when their account does.
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True
    )
    # Auto-set by the engine when a provider raises QuotaExhaustedError. While
    # paused_until > now(), get_task_assignment skips the provider; tasks that
    # would have used it re-queue themselves with countdown = paused_until - now.
    paused_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    paused_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)
    # The last connectivity test, so the keys list can say "Tested 2h ago"
    # or "Last test failed" without contacting the provider again.
    last_tested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_test_error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    @property
    def supports_tools(self) -> bool:
        from app.ai.capabilities import provider_type_supports_tools

        return provider_type_supports_tools(self.provider_type, self.config)

    @property
    def is_personal(self) -> bool:
        return self.user_id is not None

    # Relationships
    owner = relationship("User")
    task_assignments = relationship("AITaskAssignment", back_populates="provider", cascade="all, delete-orphan")
    # passive_deletes="all": the database nulls ai_results.provider_id (ON
    # DELETE SET NULL); the ORM must not load a busy key's thousands of
    # result rows to do it one by one.
    results = relationship("AIResult", back_populates="provider", passive_deletes="all")
