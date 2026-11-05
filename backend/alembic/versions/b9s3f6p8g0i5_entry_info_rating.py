"""entries.info_rating*: the per-article Admiralty information-credibility number (1-6).

Revision ID: b9s3f6p8g0i5
Revises: a8r2e5o7f9h4
"""

import sqlalchemy as sa

from alembic import op

revision = "b9s3f6p8g0i5"
down_revision = "a8r2e5o7f9h4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("entries", sa.Column("info_rating", sa.SmallInteger(), nullable=True))
    op.add_column("entries", sa.Column("info_rating_ai", sa.SmallInteger(), nullable=True))
    op.add_column("entries", sa.Column("info_rating_by", sa.String(10), nullable=True))
    op.add_column("entries", sa.Column("info_rating_access", sa.String(12), nullable=True))
    op.add_column("entries", sa.Column("info_rating_note", sa.Text(), nullable=True))


def downgrade() -> None:
    for column in ("info_rating_note", "info_rating_access", "info_rating_by", "info_rating_ai", "info_rating"):
        op.drop_column("entries", column)
