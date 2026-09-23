"""Collapse duplicate is_current entry AIResult rows to one per (entry, task).

``_current_analysis_result`` read the entry's current ``entry_analysis`` result
with ``scalar_one_or_none()``, so a target carrying more than one
``is_current=True`` row raised ``MultipleResultsFound``. That read happens
per-entry inside ``submit_analysis_batches``' self-healing sweep, so a single
affected entry aborted the whole hourly run and nothing was dispatched for
anyone — prod sat at 1,784 pending analyses for ~2.5 days with 87 affected
(entry, task) pairs.

The reader is now newest-first + ``limit(1)`` and the ``entry`` write paths
retire the incumbent row before inserting, so this only has to clean up the
rows the old paths already left behind. Keeps the newest row per
(target_id, task_id) and demotes the rest; re-running is a no-op.

Scoped deliberately to ``target_type = 'entry'``. ``entry_validation`` has a
far larger population of duplicate current rows (~21.5k pairs, systematically
two apiece) written by the batch link-validation path — that needs its writer
understood first and is not touched here. Rows with a NULL ``target_type`` are
also left alone; they predate the target columns and no reader keys off them.

Revision ID: p5g7i9k1m3o5
Revises: o4f6h8j0l2n4
Create Date: 2026-09-23
"""

from collections.abc import Sequence

from alembic import op

revision: str | None = "p5g7i9k1m3o5"
down_revision: str | None = "o4f6h8j0l2n4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # created_at DESC, id DESC so the ordering is total — created_at alone ties
    # on rows written inside the same batch, which would leave two winners.
    op.execute(
        """
        UPDATE ai_results SET is_current = false
        WHERE id IN (
            SELECT id FROM (
                SELECT id, row_number() OVER (
                    PARTITION BY target_id, task_id
                    ORDER BY created_at DESC, id DESC
                ) AS rn
                FROM ai_results
                WHERE is_current = true AND target_type = 'entry'
            ) ranked
            WHERE ranked.rn > 1
        )
        """
    )


def downgrade() -> None:
    # One-way data repair: which row held is_current is not recoverable once
    # collapsed, and restoring duplicates would only re-break the reader.
    pass
