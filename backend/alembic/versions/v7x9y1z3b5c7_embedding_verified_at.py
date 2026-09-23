"""Verification marker on entry_embeddings

Revision ID: v7x9y1z3b5c7
Revises: u6w8x0y2z4a6
Create Date: 2026-09-13

``content_hash`` always covered the exact string that was embedded, but nothing
ever re-read it: the sweeper only selected entries with no row for the current
model, so an entry whose text changed — re-sanitized, re-fetched, or embedded
under an older ``build_text`` recipe — kept a vector describing text that no
longer existed.

This column is the rotation marker for the re-hash pass. It runs only when
nothing is pending and no model has changed, walks the least-recently-verified
slice, and stamps what it confirms so the slice moves on. Null means never
verified, which sorts first.
"""

import sqlalchemy as sa

from alembic import op

revision = "v7x9y1z3b5c7"
down_revision = "u6w8x0y2z4a6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("entry_embeddings", sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_entry_embeddings_verified", "entry_embeddings", ["verified_at"])


def downgrade() -> None:
    op.drop_index("ix_entry_embeddings_verified", table_name="entry_embeddings")
    op.drop_column("entry_embeddings", "verified_at")
