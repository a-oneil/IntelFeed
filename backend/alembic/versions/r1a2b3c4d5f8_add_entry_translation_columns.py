"""add entry translation columns

Adds nullable columns on `entries` to cache on-demand translations:

- translated_html: HTML translation of content_html
- translation_source_language: detected source language (ISO-639-1)
- translation_target_language: language we translated into
- translated_at: when the translation was generated

Translations are populated lazily by POST /entries/{id}/translate. A target
language change invalidates the cached translation.

Revision ID: r1a2b3c4d5f8
Revises: q1a2b3c4d5f7
Create Date: 2026-05-03

"""

import sqlalchemy as sa

from alembic import op

revision = "r1a2b3c4d5f8"
down_revision = "q1a2b3c4d5f7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("entries", sa.Column("translated_html", sa.Text(), nullable=True))
    op.add_column("entries", sa.Column("translation_source_language", sa.String(length=10), nullable=True))
    op.add_column("entries", sa.Column("translation_target_language", sa.String(length=10), nullable=True))
    op.add_column("entries", sa.Column("translated_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("entries", "translated_at")
    op.drop_column("entries", "translation_target_language")
    op.drop_column("entries", "translation_source_language")
    op.drop_column("entries", "translated_html")
