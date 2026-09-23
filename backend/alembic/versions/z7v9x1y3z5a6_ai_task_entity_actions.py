"""ai_task entity actions — per-task visibility for the entity profile AI tab

Revision ID: z7v9x1y3z5a6
Revises: z6u8w0x2y4z5
Create Date: 2026-08-13
"""

import sqlalchemy as sa

from alembic import op

revision = "z7v9x1y3z5a6"
down_revision = "z6u8w0x2y4z5"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "ai_tasks",
        sa.Column("show_in_entity_actions", sa.Boolean(), nullable=False, server_default="true"),
    )
    # Start from the entry-panel visibility so tasks the user already hid
    # (e.g. detection_engineering_summary, report_section) stay hidden here too.
    op.execute("UPDATE ai_tasks SET show_in_entity_actions = show_in_entry_actions")


def downgrade() -> None:
    op.drop_column("ai_tasks", "show_in_entity_actions")
