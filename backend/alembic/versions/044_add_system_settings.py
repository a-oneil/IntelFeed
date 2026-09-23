"""Add system_settings table

Revision ID: 044
Revises: 043
Create Date: 2026-03-15

"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "044"
down_revision: str | None = "043"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "system_settings",
        sa.Column("id", sa.Integer(), primary_key=True, default=1),
        sa.Column("settings", JSONB(), nullable=False, server_default="{}"),
        sa.Column("secrets", JSONB(), nullable=False, server_default="{}"),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.CheckConstraint("id = 1", name="singleton_row"),
    )
    # Insert the singleton row
    op.execute("INSERT INTO system_settings (id, settings, secrets) VALUES (1, '{}', '{}')")


def downgrade() -> None:
    op.drop_table("system_settings")
