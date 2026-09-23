"""Add tags TEXT[] column to notes table

Revision ID: 004
Revises: 003
Create Date: 2026-03-03
"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import ARRAY

from alembic import op

revision = "004"
down_revision = "003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "notes",
        sa.Column(
            "tags",
            ARRAY(sa.Text),
            server_default="{}",
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_column("notes", "tags")
