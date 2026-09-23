"""add translated_title column on entries

Auto-translate-on-ingest needs the title translated alongside the body so
non-English channels render with a readable headline in feed lists.

Revision ID: s1a2b3c4d5f9
Revises: r1a2b3c4d5f8
Create Date: 2026-05-04

"""

import sqlalchemy as sa

from alembic import op

revision = "s1a2b3c4d5f9"
down_revision = "r1a2b3c4d5f8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("entries", sa.Column("translated_title", sa.String(length=2000), nullable=True))


def downgrade() -> None:
    op.drop_column("entries", "translated_title")
