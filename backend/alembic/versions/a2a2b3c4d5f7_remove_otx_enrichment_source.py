"""remove otx enrichment source

Deletes rows for the AlienVault OTX enrichment source, whose adapter code
was removed alongside the IOC-only sources cleaned up in q1a2b3c4d5f7.

Revision ID: a2a2b3c4d5f7
Revises: z1a2b3c4d5f6
Create Date: 2026-06-08

"""

from alembic import op

revision = "a2a2b3c4d5f7"
down_revision = "z1a2b3c4d5f6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("DELETE FROM enrichment_results WHERE source_type = 'otx'")
    op.execute("DELETE FROM enrichment_sources WHERE source_type = 'otx'")


def downgrade() -> None:
    pass
