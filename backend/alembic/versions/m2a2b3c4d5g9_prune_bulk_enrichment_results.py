"""Prune accumulated bulk-sync enrichment results; rename morningriefing task.

The EPSS (and to a lesser extent GitHub PoC) bulk syncs appended a new
enrichment_results row per entity per run instead of overwriting — ~40 rows per
CVE, ~1.9M rows total in production. The sync tasks now upsert (see
app/enrichment/results.py); this migration deletes everything but the newest
row per (entity_type, entity_id) for those two sources.

Deletes run in 50k batches to keep transactions and WAL small on modest hosts.
Disk note: this leaves ~1.87M dead tuples for autovacuum to reclaim gradually —
do NOT run VACUUM FULL here; deploy off-peak and check disk headroom first.

Wikipedia results are intentionally NOT pruned: that source stores long-lived
``user_cleared`` marker rows whose duplicates are semantically meaningful.

Also fixes a typo'd custom AI task name in production data:
``morningriefing`` -> ``morning_briefing`` (idempotent, skipped if taken).
"""

from sqlalchemy import text

from alembic import op

revision = "m2a2b3c4d5g9"
down_revision = "l2a2b3c4d5g8"
branch_labels = None
depends_on = None

PRUNE_SOURCE_TYPES = ("epss", "github_poc")
BATCH_SIZE = 50_000


def upgrade() -> None:
    conn = op.get_bind()

    types_sql = ", ".join(f"'{t}'" for t in PRUNE_SOURCE_TYPES)
    while True:
        result = conn.execute(
            text(
                f"""
                DELETE FROM enrichment_results WHERE id IN (
                    SELECT id FROM (
                        SELECT id, row_number() OVER (
                            PARTITION BY entity_type, entity_id, source_type
                            ORDER BY enriched_at DESC, id DESC
                        ) AS rn
                        FROM enrichment_results
                        WHERE source_type IN ({types_sql})
                    ) ranked
                    WHERE rn > 1
                    LIMIT {BATCH_SIZE}
                )
                """
            )
        )
        if result.rowcount == 0:
            break

    conn.execute(
        text(
            """
            UPDATE ai_tasks SET name = 'morning_briefing'
            WHERE name = 'morningriefing'
              AND NOT EXISTS (SELECT 1 FROM ai_tasks WHERE name = 'morning_briefing')
            """
        )
    )


def downgrade() -> None:
    # Pruned duplicate rows cannot be reconstructed; the task rename is benign.
    pass
