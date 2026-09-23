"""ai_tasks + ai_prompt_templates system_template columns

Splits prompts into a stable system block (eligible for Anthropic
prompt caching at ~10% cost per repeat call) and a per-call user
block. Both columns are nullable — when null, behavior matches the
pre-split single-message pattern.

Revision ID: y1a2b3c4d5f5
Revises: x1a2b3c4d5f4
Create Date: 2026-05-24

"""

import sqlalchemy as sa

from alembic import op

revision = "y1a2b3c4d5f5"
down_revision = "x1a2b3c4d5f4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "ai_tasks",
        sa.Column("default_system_template", sa.Text(), nullable=True),
    )
    op.add_column(
        "ai_prompt_templates",
        sa.Column("system_text", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("ai_prompt_templates", "system_text")
    op.drop_column("ai_tasks", "default_system_template")
