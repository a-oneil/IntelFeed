"""Index the dedup sort key on entries; make autovacuum analyze it far more often.

Two fixes for the same measured problem — ``/api/entries`` and
``/api/entries/count`` were spending ~1.4s apiece inside the dedup subquery
(``DISTINCT ON (content_hash) ... ORDER BY content_hash, created_at``).

1. ``ix_entries_content_hash`` covers only ``content_hash``, so the DISTINCT ON
   still had to sort 143k rows on ``(content_hash, created_at)``. With
   ``work_mem`` too small that sort ran as ``external merge Disk: 12648kB`` on
   every request. The composite index lets the planner walk the rows already
   ordered and skip the sort entirely; it also subsumes the single-column
   index, which is dropped.

2. ``entries`` was last analyzed four days before this migration with 20,873
   dead tuples, because autovacuum's default ``analyze_scale_factor`` of 0.1
   waits for ~14k rows of churn on a table this size. Stale stats had the
   planner estimating 4,922 rows for ``feed_id = ANY(...)`` where 143,492 came
   back — a 29x miss that drove the bad plan above. The per-table overrides
   bring analyze forward to ~2% churn.

Revision ID: o4f6h8j0l2n4
Revises: n3e5g7i9k1m3
Create Date: 2026-09-22
"""

from collections.abc import Sequence

from alembic import op

revision: str | None = "o4f6h8j0l2n4"
down_revision: str | None = "n3e5g7i9k1m3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # CONCURRENTLY so ingest keeps writing while the index builds; it cannot run
    # inside the migration's transaction, hence the autocommit block.
    with op.get_context().autocommit_block():
        op.execute(
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_entries_content_hash_created_at "
            "ON entries (content_hash, created_at)"
        )
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS ix_entries_content_hash")

    op.execute(
        "ALTER TABLE entries SET (autovacuum_analyze_scale_factor = 0.02, autovacuum_vacuum_scale_factor = 0.05)"
    )


def downgrade() -> None:
    op.execute("ALTER TABLE entries RESET (autovacuum_analyze_scale_factor, autovacuum_vacuum_scale_factor)")
    with op.get_context().autocommit_block():
        op.execute("CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_entries_content_hash ON entries (content_hash)")
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS ix_entries_content_hash_created_at")
