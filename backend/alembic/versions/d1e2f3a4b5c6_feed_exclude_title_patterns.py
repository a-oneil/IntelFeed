"""A feed can drop articles by title before they are saved.

``exclude_title_patterns`` holds plain phrases, one per line; an incoming
article whose title contains one (case-insensitive) is never stored, so it
never reaches tagging, the AI or scoring. See app/services/title_filter.py.

Revision ID: d1e2f3a4b5c6
Revises: c9d0e1f2a3b4
"""

import sqlalchemy as sa

from alembic import op

revision = "d1e2f3a4b5c6"
down_revision = "c9d0e1f2a3b4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("feeds", sa.Column("exclude_title_patterns", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("feeds", "exclude_title_patterns")
