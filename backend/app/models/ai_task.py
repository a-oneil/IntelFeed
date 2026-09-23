import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class AITask(Base):
    __tablename__ = "ai_tasks"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    category: Mapped[str | None] = mapped_column(String(50))  # extraction, analysis, generation, custom
    default_prompt_template: Mapped[str] = mapped_column(Text, nullable=False)
    # Optional stable system-prompt block. When set, sent as a cacheable
    # system message (Anthropic prompt caching) so the role/instructions/
    # output spec are billed at ~10% on repeat calls. The user message
    # (`default_prompt_template`) carries the per-call variable content.
    default_system_template: Mapped[str | None] = mapped_column(Text, nullable=True)
    output_schema: Mapped[dict | None] = mapped_column(JSONB)
    # UI-edited replacement for `output_schema`. Kept in a separate column
    # because the startup seeder re-syncs `output_schema` from defaults.py on
    # every deploy — an in-place edit would be silently clobbered.
    output_schema_override: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    variables: Mapped[list] = mapped_column(JSONB, default=list)
    is_system: Mapped[bool] = mapped_column(Boolean, default=True)
    # Superseded system tasks (e.g. per-entity extraction replaced by entry_analysis).
    # Kept so their ai_results history survives; hidden from run pickers.
    is_deprecated: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    # Reader AI panel: whether this task renders as an action button on an
    # article, and its position within its category group (lower = first).
    show_in_entry_actions: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    entry_action_order: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Entity profile AI tab: whether this task renders as an action row on
    # entity profiles (actors, malware, CVEs, …). Ordering reuses
    # entry_action_order so both panels stay consistent.
    show_in_entity_actions: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    @property
    def effective_output_schema(self) -> dict | None:
        return self.output_schema_override or self.output_schema

    @property
    def requires_tools(self) -> bool:
        from app.ai.capabilities import task_requires_tools

        return task_requires_tools(self.name)

    # Relationships
    prompt_templates = relationship("AIPromptTemplate", back_populates="task", cascade="all, delete-orphan")
    assignments = relationship("AITaskAssignment", back_populates="task", cascade="all, delete-orphan")
    results = relationship("AIResult", back_populates="task")
