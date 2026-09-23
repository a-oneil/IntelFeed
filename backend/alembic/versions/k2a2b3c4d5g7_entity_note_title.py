"""Add optional title to entity_notes

Entity-profile notes gain an optional title so they render in the same
unified note card as entry/sidebar notes.

Revision ID: k2a2b3c4d5g7
Revises: j2a2b3c4d5g6
Create Date: 2026-07-08

"""

import sqlalchemy as sa

from alembic import op

revision = "k2a2b3c4d5g7"
down_revision = "j2a2b3c4d5g6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "entity_notes",
        sa.Column("title", sa.String(500), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("entity_notes", "title")
