"""Add schedule_interval_hours and next_scheduled_at to enrichment_sources

Revision ID: 031_add_schedule_interval
Revises: 030_add_chat_tables
Create Date: 2026-03-12
"""

import sqlalchemy as sa

from alembic import op

revision: str = "031_add_schedule_interval"
down_revision: str | None = "030_add_chat_tables"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "enrichment_sources",
        sa.Column("schedule_interval_hours", sa.Integer(), server_default="24", nullable=False),
    )
    op.add_column(
        "enrichment_sources",
        sa.Column("next_scheduled_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("enrichment_sources", "next_scheduled_at")
    op.drop_column("enrichment_sources", "schedule_interval_hours")
