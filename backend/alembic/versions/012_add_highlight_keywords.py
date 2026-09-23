"""Add highlight_keywords table

Revision ID: 012
Revises: 011
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "012"
down_revision = "011"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "highlight_keywords",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("keyword", sa.String(100), nullable=False),
        sa.Column("color", sa.String(7), nullable=False, server_default="#FFEB3B"),
        sa.Column("is_enabled", sa.Boolean, nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("user_id", "keyword", name="uq_highlight_keywords_user_keyword"),
    )


def downgrade():
    op.drop_table("highlight_keywords")
