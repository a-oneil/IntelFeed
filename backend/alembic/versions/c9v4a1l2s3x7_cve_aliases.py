"""cves.aliases: other ids for the same vulnerability (GHSA-…, distro ids).

Filled by the OSV enrichment source, unioned with what the column holds.

Revision ID: c9v4a1l2s3x7
Revises: n5v6d7k8l9q0
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "c9v4a1l2s3x7"
down_revision = "n5v6d7k8l9q0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "cves",
        sa.Column("aliases", postgresql.ARRAY(sa.Text()), server_default="{}", nullable=False),
    )


def downgrade() -> None:
    op.drop_column("cves", "aliases")
