"""Retire the five hygiene jobs the adjudicate stage replaced.

Revision ID: b1c2d3e4f5a6
Revises: a0b1c2d3e4f5
Create Date: 2026-10-08

The nightly link validator, hygiene proposal reviewer, weekly merge engine,
nightly relationship adjudicator and weekly stale-entity sweep are gone from
the code. This revision retires their data:

- the four AI tasks they ran are marked deprecated (the task seeder adds and
  re-syncs system tasks but never removes them) and their assignments deleted;
- the reviewer's verdict columns on both proposal logs are dropped — nothing
  writes or reads them any more;
- the sweep's stale flags and the merge engine's cluster summaries are deleted:
  stale is now a live filter on the AI-entities view, and duplicates are
  caught at creation (and by the adjudication backfill for history), with the
  on-demand duplicate-candidates chip still available.

Downgrade restores the columns (empty) and un-deprecates the tasks; the
deleted rows and assignments are not recoverable, by design.
"""

import sqlalchemy as sa

from alembic import op

revision = "b1c2d3e4f5a6"
down_revision = "a0b1c2d3e4f5"
branch_labels = None
depends_on = None

RETIRED_TASKS = (
    "entity_link_validation",
    "hygiene_proposal_review",
    "relationship_adjudication",
    "entity_merge_maintenance",
)


def upgrade() -> None:
    conn = op.get_bind()
    names = ", ".join(f"'{n}'" for n in RETIRED_TASKS)
    conn.execute(
        sa.text(f"DELETE FROM ai_task_assignments WHERE task_id IN (SELECT id FROM ai_tasks WHERE name IN ({names}))")
    )
    conn.execute(sa.text(f"UPDATE ai_tasks SET is_deprecated = true WHERE name IN ({names})"))
    conn.execute(
        sa.text(
            "DELETE FROM entity_maintenance_log "
            "WHERE action IN ('stale_entity_review', 'merge_cluster_summary') AND applied = false"
        )
    )
    for table in ("entity_link_validation_log", "entity_maintenance_log"):
        op.drop_column(table, "reviewed_at")
        op.drop_column(table, "review_reason")
        op.drop_column(table, "review_decision")


def downgrade() -> None:
    for table in ("entity_link_validation_log", "entity_maintenance_log"):
        op.add_column(table, sa.Column("review_decision", sa.String(length=10), nullable=True))
        op.add_column(table, sa.Column("review_reason", sa.Text(), nullable=True))
        op.add_column(table, sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True))
    names = ", ".join(f"'{n}'" for n in RETIRED_TASKS)
    op.get_bind().execute(sa.text(f"UPDATE ai_tasks SET is_deprecated = false WHERE name IN ({names})"))
