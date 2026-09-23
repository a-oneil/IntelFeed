"""Signal engine (shadow) + job observability tables.

Adds:
- entry_signals — one explainable signal per (entry, signal_type), upserted
- entries.priority_score / entries.scored_at + (published_at, priority_score) index
- GIN index on entity_relationships.evidence_entry_ids (new_pairing signal probe)
- job_runs — execution records for scheduled JOB_REGISTRY tasks
"""

import sqlalchemy as sa
from sqlalchemy import text
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

revision = "n2b3c4d5e6f7"
down_revision = "m2a2b3c4d5g9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "entry_signals",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "entry_id",
            UUID(as_uuid=True),
            sa.ForeignKey("entries.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("signal_type", sa.String(40), nullable=False),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("payload", JSONB(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("entry_id", "signal_type", name="uq_entry_signals_entry_type"),
    )
    op.create_index("ix_entry_signals_entry_id", "entry_signals", ["entry_id"])
    op.create_index("ix_entry_signals_type_created", "entry_signals", ["signal_type", "created_at"])

    op.add_column("entries", sa.Column("priority_score", sa.Float(), nullable=True))
    op.add_column("entries", sa.Column("scored_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_entries_priority_score", "entries", ["priority_score"])
    op.create_index("ix_entries_published_priority", "entries", ["published_at", "priority_score"])

    op.execute(
        text(
            "CREATE INDEX IF NOT EXISTS ix_entity_relationships_evidence_gin "
            "ON entity_relationships USING gin (evidence_entry_ids)"
        )
    )

    op.create_table(
        "job_runs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("task_name", sa.String(200), nullable=False),
        sa.Column("job_key", sa.String(60), nullable=True),
        sa.Column("celery_task_id", sa.String(64), nullable=True),
        sa.Column("status", sa.String(12), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
    )
    op.create_index("ix_job_runs_task_started", "job_runs", ["task_name", "started_at"])


def downgrade() -> None:
    op.drop_table("job_runs")
    op.execute(text("DROP INDEX IF EXISTS ix_entity_relationships_evidence_gin"))
    op.drop_index("ix_entries_published_priority", table_name="entries")
    op.drop_index("ix_entries_priority_score", table_name="entries")
    op.drop_column("entries", "scored_at")
    op.drop_column("entries", "priority_score")
    op.drop_table("entry_signals")
