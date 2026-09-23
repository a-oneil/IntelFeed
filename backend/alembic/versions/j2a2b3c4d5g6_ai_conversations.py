"""AI copilot conversations (chat threads)

Adds:
- ai_conversations: server-side persistence for AI copilot chat threads,
  scoped per user. Each row holds a scope (entry / multi_entry / entity /
  global) and a JSONB list of chat messages.

Revision ID: j2a2b3c4d5g6
Revises: i2a2b3c4d5g5
Create Date: 2026-07-07

"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

revision = "j2a2b3c4d5g6"
down_revision = "i2a2b3c4d5g5"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ai_conversations",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("title", sa.String(200), nullable=True),
        sa.Column("scope_type", sa.String(20), nullable=False),
        sa.Column("scope_id", sa.String(200), nullable=True),
        sa.Column("entry_ids", JSONB, nullable=True),
        sa.Column(
            "messages",
            JSONB,
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index("ix_ai_conversations_user_id", "ai_conversations", ["user_id"])
    op.create_index("ix_ai_conversations_scope_type", "ai_conversations", ["scope_type"])


def downgrade() -> None:
    op.drop_index("ix_ai_conversations_scope_type", table_name="ai_conversations")
    op.drop_index("ix_ai_conversations_user_id", table_name="ai_conversations")
    op.drop_table("ai_conversations")
