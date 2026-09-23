"""add share_token to ai_conversations

Revision ID: l2a2b3c4d5g8
Revises: k2a2b3c4d5g7
Create Date: 2026-07-08

"""

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = "l2a2b3c4d5g8"
down_revision = "k2a2b3c4d5g7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "ai_conversations",
        sa.Column("share_token", sa.String(length=64), nullable=True),
    )
    op.create_index(
        "ix_ai_conversations_share_token",
        "ai_conversations",
        ["share_token"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ix_ai_conversations_share_token", table_name="ai_conversations")
    op.drop_column("ai_conversations", "share_token")
