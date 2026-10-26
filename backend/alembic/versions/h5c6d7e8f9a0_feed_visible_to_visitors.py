"""feeds.visible_to_visitors: which feeds public read-only mode shows.

Off for every feed, so turning the mode on publishes nothing until an admin
picks feeds.

Revision ID: h5c6d7e8f9a0
Revises: g4b5c6d7e8f9
"""

import sqlalchemy as sa

from alembic import op

revision = "h5c6d7e8f9a0"
down_revision = "g4b5c6d7e8f9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "feeds",
        sa.Column("visible_to_visitors", sa.Boolean(), nullable=False, server_default="false"),
    )


def downgrade() -> None:
    op.drop_column("feeds", "visible_to_visitors")
