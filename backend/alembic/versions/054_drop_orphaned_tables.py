"""drop orphaned tables (chat_sessions, chat_messages, agent_skills, agent_knowledge)

These tables were created in migrations 030/032 but never had corresponding
SQLAlchemy models, making them unusable via ORM. The features they were
intended for were never implemented.

Revision ID: 054_drop_orphaned
Revises: 053_sort_order
Create Date: 2026-03-29 12:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "054_drop_orphaned"
down_revision: str | None = "053_sort_order"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Drop in order: children first (FK constraints)
    op.execute("DROP TABLE IF EXISTS chat_messages")
    op.execute("DROP TABLE IF EXISTS chat_sessions")
    op.execute("DROP TABLE IF EXISTS agent_knowledge")
    op.execute("DROP TABLE IF EXISTS agent_skills")


def downgrade() -> None:
    # Recreate tables with original schema from migrations 030/032
    op.create_table(
        "agent_skills",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False, unique=True),
        sa.Column("description", sa.Text),
        sa.Column("skill_type", sa.String(30), nullable=False),
        sa.Column("config", postgresql.JSONB, server_default="{}"),
        sa.Column("is_enabled", sa.Boolean, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_table(
        "agent_knowledge",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "skill_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("agent_skills.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("content", sa.Text, nullable=False),
        sa.Column("metadata", postgresql.JSONB, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_table(
        "chat_sessions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("title", sa.String(500)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_table(
        "chat_messages",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "session_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("chat_sessions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("role", sa.String(20), nullable=False),
        sa.Column("content", sa.Text, nullable=False),
        sa.Column("metadata", postgresql.JSONB, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
