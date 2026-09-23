"""ai_task output schema override — UI-editable per-task schema that survives
the startup seeder's defaults sync; also normalize prompt templates to one
active row per task (overrides become global rather than per-user).

Revision ID: z6u8w0x2y4z5
Revises: y5r7s9t1u3v4
Create Date: 2026-08-13
"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision = "z6u8w0x2y4z5"
down_revision = "y5r7s9t1u3v4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "ai_tasks",
        sa.Column("output_schema_override", JSONB(), nullable=True),
    )
    # Prompt overrides are now resolved per task (newest active row wins,
    # regardless of author). Deactivate all but the newest active row per
    # task so the old per-user data can't leave two rows both "active".
    op.execute(
        sa.text(
            """
            UPDATE ai_prompt_templates SET is_active = false
            WHERE is_active = true AND id NOT IN (
                SELECT DISTINCT ON (task_id) id FROM ai_prompt_templates
                WHERE is_active = true
                ORDER BY task_id, version DESC, created_at DESC
            )
            """
        )
    )


def downgrade() -> None:
    op.drop_column("ai_tasks", "output_schema_override")
