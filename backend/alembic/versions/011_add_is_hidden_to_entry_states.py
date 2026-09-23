"""Add is_hidden to user_entry_states

Revision ID: 011
Revises: 010
Create Date: 2026-03-04
"""

import sqlalchemy as sa

from alembic import op

revision = "011"
down_revision = "010"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("user_entry_states", sa.Column("is_hidden", sa.Boolean(), nullable=False, server_default="false"))


def downgrade():
    op.drop_column("user_entry_states", "is_hidden")
