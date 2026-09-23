"""add covering index on entries(feed_id, published_at) for Atlas calendar

Revision ID: n1a2b3c4d5f3
Revises: 061_matched_names_array
Create Date: 2026-05-02 00:00:00.000000

"""

from alembic import op

revision = "n1a2b3c4d5f3"
down_revision = "061_matched_names_array"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "ix_entries_feed_id_published_at",
        "entries",
        ["feed_id", "published_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_entries_feed_id_published_at", table_name="entries")
