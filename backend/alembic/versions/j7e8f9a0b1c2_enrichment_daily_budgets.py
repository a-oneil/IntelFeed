"""enrichment_sources.daily_budget gets a default on every source that has none.

The gateway refuses a source's requests for the rest of the UTC day once its
budget is spent; a NULL budget never refuses. Each default is about twice the
requests a busy day sends through the source: scheduled jobs plus per-entity
lookups. Budgets an admin set are left alone. The same numbers seed new
installs (default_daily_budget in app/enrichment/registry.py).

Revision ID: j7e8f9a0b1c2
Revises: i6d7e8f9a0b1
"""

import sqlalchemy as sa

from alembic import op

revision = "j7e8f9a0b1c2"
down_revision = "i6d7e8f9a0b1"
branch_labels = None
depends_on = None

DAILY_BUDGETS = {
    # backfill (<=1,100 keyed) + refresh 100 + reenrich 150 + KEV 4x50 + CVE extraction (~400)
    "nvd": 5000,
    # one CSV a day; per-CVE lookups only from manual or gap enrichment
    "epss": 500,
    # one catalog a day per KEV sync (4) and per-CVE lookup
    "cisa_kev": 500,
    # three STIX bundles a week
    "mitre_attack": 100,
    # two catalog calls a week + per-entity lookups
    "malpedia": 1000,
    # up to 300 searches a day (github_poc_batch_limit) + gap enrichment
    "github_poc": 1000,
    # ~3-5 requests per entity: ~110 auto lookups a day, plus the weekly sync's ~560
    "wikipedia": 2000,
    # free tier allows 500 a day
    "virustotal": 500,
    # community API allowance is small; the bucket allows 240 a day
    "greynoise": 100,
    # ~100 freshly judged IPs a day
    "shodan": 1000,
    # one lookup per new CVE (~400 a day) when enabled
    "osv": 2000,
    "cvedetails": 1000,
    "vulncheck": 1000,
}


def upgrade() -> None:
    for source_type, budget in DAILY_BUDGETS.items():
        op.get_bind().execute(
            sa.text(
                "UPDATE enrichment_sources SET daily_budget = :budget "
                "WHERE source_type = :source_type AND daily_budget IS NULL"
            ),
            {"budget": budget, "source_type": source_type},
        )


def downgrade() -> None:
    # Clears only budgets still at the value upgrade() set.
    for source_type, budget in DAILY_BUDGETS.items():
        op.get_bind().execute(
            sa.text(
                "UPDATE enrichment_sources SET daily_budget = NULL "
                "WHERE source_type = :source_type AND daily_budget = :budget"
            ),
            {"budget": budget, "source_type": source_type},
        )
