"""Add image_url column to entries table and backfill from content_html.

Revision ID: 007
Revises: 006
Create Date: 2026-03-04
"""

import sqlalchemy as sa

from alembic import op

revision = "007"
down_revision = "006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("entries", sa.Column("image_url", sa.Text(), nullable=True))

    # Backfill: extract first <img src="..."> from content_html
    op.execute("""
        UPDATE entries
        SET image_url = (regexp_match(content_html, '<img[^>]+src=[\"'']([^\"'']+)[\"'']', 'i'))[1]
        WHERE content_html IS NOT NULL
          AND image_url IS NULL
    """)


def downgrade() -> None:
    op.drop_column("entries", "image_url")
