"""One-pass AI analysis queue (engine phase 4) + ai_tasks.is_deprecated.

Creates the batch-extraction bookkeeping tables and marks superseded
extraction task seeds as deprecated (kept for ai_results history, hidden
from run pickers). Also rewrites any automation rule actions that referenced
a deprecated task name to entry_analysis.
"""

import sqlalchemy as sa
from sqlalchemy import text
from sqlalchemy.dialects.postgresql import UUID

from alembic import op

revision = "p2d4e5f6g7h9"
down_revision = "o2c3d4e5f6g8"
branch_labels = None
depends_on = None

DEPRECATED_TASKS = (
    "threat_actor_id",
    "malware_id",
    "tool_extraction",
    "country_id",
    "sector_id",
    "article_metadata",
    "mitigation_extraction",
    "cve_extraction",
)


def upgrade() -> None:
    op.add_column(
        "ai_tasks",
        sa.Column("is_deprecated", sa.Boolean(), nullable=False, server_default="false"),
    )

    op.create_table(
        "ai_analysis_requests",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "entry_id",
            UUID(as_uuid=True),
            sa.ForeignKey("entries.id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
        ),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("batch_id", sa.String(80), nullable=True),
        sa.Column("custom_id", sa.String(64), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("reused_from_entry_id", UUID(as_uuid=True), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("submitted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_ai_analysis_requests_entry_id", "ai_analysis_requests", ["entry_id"])
    op.create_index("ix_ai_analysis_requests_batch_id", "ai_analysis_requests", ["batch_id"])
    op.create_index("ix_ai_analysis_status_created", "ai_analysis_requests", ["status", "created_at"])

    op.create_table(
        "ai_batch_jobs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("provider_batch_id", sa.String(80), nullable=False, unique=True),
        sa.Column(
            "provider_id",
            UUID(as_uuid=True),
            sa.ForeignKey("ai_providers.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("status", sa.String(20), nullable=False, server_default="in_progress"),
        sa.Column("request_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("succeeded", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("errored", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("expired", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("cost_estimate", sa.Numeric(12, 6), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
    )

    # Data fix: automation rule actions referencing deprecated task names
    names_sql = ", ".join(f"'{n}'" for n in DEPRECATED_TASKS)
    op.execute(
        text(
            f"""
            UPDATE automation_rules
            SET actions = (
                SELECT jsonb_agg(
                    CASE
                        WHEN a->>'type' = 'run_ai_task'
                             AND a->'config'->>'task_name' IN ({names_sql})
                        THEN jsonb_set(a, '{{config,task_name}}', '"entry_analysis"')
                        ELSE a
                    END
                )
                FROM jsonb_array_elements(actions) AS a
            )
            WHERE actions::text LIKE '%run_ai_task%'
              AND EXISTS (
                  SELECT 1 FROM jsonb_array_elements(actions) AS a
                  WHERE a->>'type' = 'run_ai_task'
                    AND a->'config'->>'task_name' IN ({names_sql})
              )
            """
        )
    )


def downgrade() -> None:
    op.drop_table("ai_batch_jobs")
    op.drop_table("ai_analysis_requests")
    op.drop_column("ai_tasks", "is_deprecated")
