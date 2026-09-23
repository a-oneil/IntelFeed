"""Add polymorphic target columns to ai_results.

Revision ID: 042
Revises: 041
Create Date: 2026-03-15
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "042"
down_revision = "041_matched_name"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("ai_results", sa.Column("target_type", sa.String(20), nullable=True))
    op.add_column("ai_results", sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column("ai_results", sa.Column("is_current", sa.Boolean(), nullable=False, server_default=sa.text("true")))

    op.create_index("ix_ai_results_target_type", "ai_results", ["target_type"])
    op.create_index("ix_ai_results_target_id", "ai_results", ["target_id"])
    op.create_index("ix_ai_results_is_current", "ai_results", ["is_current"])
    op.create_index(
        "ix_ai_results_target_task_current",
        "ai_results",
        ["target_type", "target_id", "task_id", "is_current"],
    )

    # Backfill existing rows
    op.execute("UPDATE ai_results SET target_type = 'entry', target_id = entry_id WHERE entry_id IS NOT NULL")


def downgrade() -> None:
    op.drop_index("ix_ai_results_target_task_current", table_name="ai_results")
    op.drop_index("ix_ai_results_is_current", table_name="ai_results")
    op.drop_index("ix_ai_results_target_id", table_name="ai_results")
    op.drop_index("ix_ai_results_target_type", table_name="ai_results")
    op.drop_column("ai_results", "is_current")
    op.drop_column("ai_results", "target_id")
    op.drop_column("ai_results", "target_type")
