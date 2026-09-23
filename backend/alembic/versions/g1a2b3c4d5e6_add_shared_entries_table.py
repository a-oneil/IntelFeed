"""add shared_entries table

Revision ID: g1a2b3c4d5e6
Revises: f3b5239577e0
Create Date: 2026-04-19 12:00:00.000000

"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "g1a2b3c4d5e6"
down_revision = "060_remove_ioc_tables"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "shared_entries",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column(
            "entry_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("entries.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("token", sa.String(64), unique=True, nullable=False),
        sa.Column(
            "created_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True
        ),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("shared_entries")
