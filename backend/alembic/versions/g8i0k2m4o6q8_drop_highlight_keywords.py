"""Drop highlight_keywords — the per-user keyword highlighting feature is gone

Revision ID: g8i0k2m4o6q8
Revises: f7h9k1m3o5q7
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "g8i0k2m4o6q8"
down_revision = "f7h9k1m3o5q7"
branch_labels = None
depends_on = None


def upgrade():
    op.drop_table("highlight_keywords")


def downgrade():
    """Recreate the table as it stood at the drop (rows are not recoverable)."""
    op.create_table(
        "highlight_keywords",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("keyword", sa.String(100), nullable=False),
        sa.Column("color", sa.String(7), nullable=False, server_default="#FFEB3B"),
        sa.Column("is_enabled", sa.Boolean, nullable=False, server_default=sa.text("true")),
        sa.Column("alert_enabled", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("user_id", "keyword", name="uq_highlight_keywords_user_keyword"),
    )
    op.create_index("ix_highlight_keywords_user_id", "highlight_keywords", ["user_id"])
    op.create_index("ix_highlight_keywords_keyword", "highlight_keywords", ["keyword"])
