"""remove reseeded IOC enrichment sources

q1a2b3c4d5f7 deleted these rows once, but the startup seeder kept re-adding
them from DEFAULT_SOURCES (because the adapters were still wired up). The
adapters are gone now and DEFAULT_SOURCES no longer lists these, so we can
wipe the rows for good.

Revision ID: b2a2b3c4d5f8
Revises: a2a2b3c4d5f7
Create Date: 2026-06-09

"""

from alembic import op

revision = "b2a2b3c4d5f8"
down_revision = "a2a2b3c4d5f7"
branch_labels = None
depends_on = None


ORPHANED_SOURCE_TYPES = (
    "shodan",
    "threatfox",
    "urlhaus",
    "malbazaar",
    "greynoise",
    "abuseipdb",
    "virustotal",
    "urlscan",
)


def upgrade() -> None:
    types_sql = ", ".join(f"'{t}'" for t in ORPHANED_SOURCE_TYPES)
    op.execute(f"DELETE FROM enrichment_results WHERE source_type IN ({types_sql})")
    op.execute(f"DELETE FROM enrichment_sources WHERE source_type IN ({types_sql})")


def downgrade() -> None:
    pass
