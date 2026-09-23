"""Thread scan marker on entry_embeddings

Revision ID: u6w8x0y2z4a6
Revises: t5u7w9x1y3z5
Create Date: 2026-09-13

Most articles never join a thread — that is the normal outcome, not a failure.
Without a marker recording that an entry has been looked at, every sweep
re-examined the same oldest unthreaded entries and never reached the rest of
the window: six passes over a three-week window all considered the same 400
articles.

An entry stays re-checkable while it is still inside the gap window (the story
it belongs to may not have broken yet); after that, one look is final.
"""

import sqlalchemy as sa

from alembic import op

revision = "u6w8x0y2z4a6"
down_revision = "t5u7w9x1y3z5"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("entry_embeddings", sa.Column("threaded_checked_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_entry_embeddings_unchecked", "entry_embeddings", ["threaded_checked_at"])


def downgrade() -> None:
    op.drop_index("ix_entry_embeddings_unchecked", table_name="entry_embeddings")
    op.drop_column("entry_embeddings", "threaded_checked_at")
