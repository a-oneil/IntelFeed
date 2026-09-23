"""Add sdk_session_id to chat_sessions

Revision ID: 033_add_sdk_session_id
Revises: 032_add_agent_skills
Create Date: 2026-03-13
"""

import sqlalchemy as sa

from alembic import op

revision: str = "033_add_sdk_session_id"
down_revision: str | None = "032_add_agent_skills"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "chat_sessions",
        sa.Column("sdk_session_id", sa.String(200), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("chat_sessions", "sdk_session_id")
