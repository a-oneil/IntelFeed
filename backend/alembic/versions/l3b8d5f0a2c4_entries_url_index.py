"""Add a hash index on entries.url.

Revision ID: l3b8d5f0a2c4
Revises: k2a7c4e9f1b3
Create Date: 2026-11-24

The browser extension checks whether the page it is on is already in
IntelFeed (GET /api/entries/ingest/lookup), an equality lookup on
entries.url. A hash index, not a btree: the lookup only tests equality, and
a btree rejects keys longer than about 2.7 kB, which long tracking URLs
exceed.
"""

from alembic import op

revision = "l3b8d5f0a2c4"
down_revision = "k2a7c4e9f1b3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # CONCURRENTLY so ingest keeps writing while the index builds; it cannot run
    # inside the migration's transaction, hence the autocommit block.
    with op.get_context().autocommit_block():
        op.execute("CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_entries_url_hash ON entries USING hash (url)")


def downgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS ix_entries_url_hash")
