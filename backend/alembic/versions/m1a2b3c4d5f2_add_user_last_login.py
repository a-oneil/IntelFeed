"""add last_login to users table

Revision ID: m1a2b3c4d5f2
Revises: l1a2b3c4d5f1
Create Date: 2026-04-22 18:00:00.000000

"""

import sqlalchemy as sa

from alembic import op

revision = "m1a2b3c4d5f2"
down_revision = "l1a2b3c4d5f1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("last_login", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "last_login")
