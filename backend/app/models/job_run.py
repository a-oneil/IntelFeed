import uuid
from datetime import datetime

from sqlalchemy import DateTime, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class JobRun(Base):
    """Execution record for a scheduled (JOB_REGISTRY) Celery task.

    Written by the celery signal handlers in app/workers/task_tracking.py —
    filtered to registry tasks only; per-entry pipeline tasks are tracked in
    entry_pipeline_runs instead. Pruned after 30 days by prune_engine_tables.
    """

    __tablename__ = "job_runs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    task_name: Mapped[str] = mapped_column(String(200), nullable=False)
    job_key: Mapped[str | None] = mapped_column(String(60))  # JOB_REGISTRY key
    celery_task_id: Mapped[str | None] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(12), nullable=False)  # success, error, retry
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    error: Mapped[str | None] = mapped_column(Text)
    # Clipped {"args": [...], "kwargs": {...}, "result": ...} from the celery
    # signals — the "what did it run against / what did it do" context.
    detail: Mapped[dict | None] = mapped_column(JSONB)

    __table_args__ = (Index("ix_job_runs_task_started", "task_name", "started_at"),)
