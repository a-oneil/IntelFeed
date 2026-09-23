"""ai_task entry actions — per-task visibility + ordering for the reader AI panel

Revision ID: y5r7s9t1u3v4
Revises: y4p6q8r0s2t3
Create Date: 2026-08-12
"""

import sqlalchemy as sa

from alembic import op

revision = "y5r7s9t1u3v4"
down_revision = "y4p6q8r0s2t3"
branch_labels = None
depends_on = None

# Tasks previously hidden by the frontend's hardcoded EXCLUDED_TASKS list.
_HIDDEN_BY_DEFAULT = ("detection_engineering_summary", "report_section", "reddit_digest")


def upgrade() -> None:
    op.add_column(
        "ai_tasks",
        sa.Column("show_in_entry_actions", sa.Boolean(), nullable=False, server_default="true"),
    )
    op.add_column(
        "ai_tasks",
        sa.Column("entry_action_order", sa.Integer(), nullable=True),
    )
    op.execute(
        sa.text("UPDATE ai_tasks SET show_in_entry_actions = false WHERE name IN :names").bindparams(
            sa.bindparam("names", _HIDDEN_BY_DEFAULT, expanding=True)
        )
    )


def downgrade() -> None:
    op.drop_column("ai_tasks", "entry_action_order")
    op.drop_column("ai_tasks", "show_in_entry_actions")
