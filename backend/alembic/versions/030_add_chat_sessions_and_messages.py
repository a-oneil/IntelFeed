"""Add chat_sessions and chat_messages tables

Revision ID: 030_add_chat_tables
Revises: 029_add_execution_mode
Create Date: 2026-03-12
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "030_add_chat_tables"
down_revision: str | None = "029_add_execution_mode"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "chat_sessions",
        sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("title", sa.String(500), server_default="New conversation"),
        sa.Column("model", sa.String(100), nullable=False),
        sa.Column(
            "context_entry_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("entries.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("active_skill_ids", sa.dialects.postgresql.JSONB, server_default="[]"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_chat_sessions_user_id", "chat_sessions", ["user_id"])

    op.create_table(
        "chat_messages",
        sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "session_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("chat_sessions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("role", sa.String(20), nullable=False),
        sa.Column("content", sa.Text, nullable=True),
        sa.Column("tool_name", sa.String(100), nullable=True),
        sa.Column("tool_input", sa.dialects.postgresql.JSONB, nullable=True),
        sa.Column("tool_output", sa.dialects.postgresql.JSONB, nullable=True),
        sa.Column("tokens_input", sa.Integer, nullable=True),
        sa.Column("tokens_output", sa.Integer, nullable=True),
        sa.Column("cost_estimate", sa.Numeric(12, 6), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_chat_messages_session_id", "chat_messages", ["session_id"])


def downgrade() -> None:
    op.drop_table("chat_messages")
    op.drop_table("chat_sessions")
