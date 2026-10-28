"""enrichment_sources: drop the scheduled trigger mode and its columns.

Sources declare their scheduled jobs in their manifests, so the "scheduled"
trigger mode (a bulk_sync no adapter implemented) goes: its rows become
"manual", and schedule_interval_hours / next_scheduled_at go with it.
daily_budget_used goes too; the gateway counts each source's usage in Redis.

A source's jobs now skip while its row is disabled, where they used to run
regardless. So that every job keeps running, the disabled rows of sources that
have jobs are switched on in manual mode, which sends nothing on its own:
manual mode only answers lookups a person or a backfill asks for. Downgrade
can't tell those rows from ones an admin enabled, so it leaves them on.

Wikipedia's default rate goes from 10 to 20 requests a minute on rows still at
the old default.

Revision ID: d5m6a7n8f9s0
Revises: c4q8e2n6j0d4
"""

import sqlalchemy as sa

from alembic import op

revision = "d5m6a7n8f9s0"
down_revision = "c4q8e2n6j0d4"
branch_labels = None
depends_on = None

#: Sources with rows before this revision that have scheduled jobs.
JOB_SOURCES = ("epss", "nvd", "cisa_kev", "mitre_attack", "malpedia", "github_poc", "wikipedia")

_WIKIPEDIA_OLD = '{"requests_per_period": 10, "period_seconds": 60}'
_WIKIPEDIA_NEW = '{"requests_per_period": 20, "period_seconds": 60}'


def _wikipedia_rate(old: str, new: str) -> None:
    op.get_bind().execute(
        sa.text(
            "UPDATE enrichment_sources SET rate_limit_config = CAST(:new AS jsonb) "
            "WHERE source_type = 'wikipedia' AND rate_limit_config = CAST(:old AS jsonb)"
        ),
        {"old": old, "new": new},
    )


def upgrade() -> None:
    bind = op.get_bind()
    bind.execute(sa.text("UPDATE enrichment_sources SET trigger_mode = 'manual' WHERE trigger_mode = 'scheduled'"))
    bind.execute(
        sa.text(
            "UPDATE enrichment_sources SET is_enabled = true, trigger_mode = 'manual' "
            "WHERE is_enabled = false AND source_type IN :job_sources"
        ).bindparams(sa.bindparam("job_sources", expanding=True)),
        {"job_sources": list(JOB_SOURCES)},
    )
    _wikipedia_rate(_WIKIPEDIA_OLD, _WIKIPEDIA_NEW)
    op.drop_column("enrichment_sources", "next_scheduled_at")
    op.drop_column("enrichment_sources", "schedule_interval_hours")
    op.drop_column("enrichment_sources", "daily_budget_used")


def downgrade() -> None:
    _wikipedia_rate(_WIKIPEDIA_NEW, _WIKIPEDIA_OLD)
    op.add_column(
        "enrichment_sources",
        sa.Column("daily_budget_used", sa.Integer(), server_default="0", nullable=False),
    )
    op.add_column(
        "enrichment_sources",
        sa.Column("schedule_interval_hours", sa.Integer(), server_default="24", nullable=False),
    )
    op.add_column(
        "enrichment_sources",
        sa.Column("next_scheduled_at", sa.DateTime(timezone=True), nullable=True),
    )
