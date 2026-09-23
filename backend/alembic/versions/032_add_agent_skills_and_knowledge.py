"""Add agent_skills and agent_knowledge tables

Revision ID: 032_add_agent_skills
Revises: 031_add_schedule_interval
Create Date: 2026-03-12
"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

revision: str = "032_add_agent_skills"
down_revision: str | None = "031_add_schedule_interval"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "agent_skills",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(100), unique=True, nullable=False),
        sa.Column("display_name", sa.String(200), nullable=False),
        sa.Column("description", sa.Text, nullable=False, server_default=""),
        sa.Column("system_prompt", sa.Text, nullable=False, server_default=""),
        sa.Column("is_system", sa.Boolean, server_default="false"),
        sa.Column("is_active", sa.Boolean, server_default="true"),
        sa.Column("suggested_tools", JSONB, server_default="[]"),
        sa.Column("created_by", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "agent_knowledge",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("skill_id", UUID(as_uuid=True), sa.ForeignKey("agent_skills.id", ondelete="CASCADE"), nullable=False),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("content", sa.Text, nullable=False),
        sa.Column("content_type", sa.String(50), nullable=False, server_default="reference"),
        sa.Column("sort_order", sa.Integer, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_index("ix_agent_knowledge_skill_id", "agent_knowledge", ["skill_id"])


def downgrade() -> None:
    op.drop_table("agent_knowledge")
    op.drop_table("agent_skills")
