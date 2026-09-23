"""remove orphaned IOC enrichment sources

Deletes rows for the 8 IOC-only enrichment sources whose adapter code was
removed after the platform stopped tracking IOC entities: shodan,
threatfox, urlhaus, malbazaar, greynoise, abuseipdb, virustotal, urlscan.

`enrichment_sources` rows are deleted directly. `user_enrichment_overrides`
rows cascade via FK. `enrichment_results` rows are keyed by source_type
(plain string) and must be deleted explicitly.

Revision ID: q1a2b3c4d5f7
Revises: p1a2b3c4d5f6
Create Date: 2026-05-03

"""

from alembic import op

revision = "q1a2b3c4d5f7"
down_revision = "p1a2b3c4d5f6"
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
    # Source rows can be re-seeded by the application startup hook if the
    # adapters are restored; cached results cannot be reconstructed.
    pass
