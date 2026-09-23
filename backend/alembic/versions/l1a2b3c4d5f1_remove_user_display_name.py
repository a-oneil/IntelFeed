"""remove display_name from users table

Revision ID: l1a2b3c4d5f1
Revises: k1a2b3c4d5f0
Create Date: 2026-04-22 12:00:00.000000

"""

import sqlalchemy as sa

from alembic import op

revision = "l1a2b3c4d5f1"
down_revision = "k1a2b3c4d5f0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_column("users", "display_name")


def downgrade() -> None:
    op.add_column("users", sa.Column("display_name", sa.String(100), nullable=True))
