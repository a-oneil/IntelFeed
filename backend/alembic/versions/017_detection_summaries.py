"""Add detection_summaries table.

Revision ID: 017_detection_summaries
Revises: 843bfb9c6b4c
Create Date: 2026-03-08
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "017_detection_summaries"
down_revision = "843bfb9c6b4c"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "detection_summaries",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("entry_ids", postgresql.ARRAY(postgresql.UUID(as_uuid=True)), server_default="{}"),
        sa.Column("analysis_focus", sa.String(30), nullable=False, server_default="campaign"),
        sa.Column("summary_content", postgresql.JSONB, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("detection_summaries")
