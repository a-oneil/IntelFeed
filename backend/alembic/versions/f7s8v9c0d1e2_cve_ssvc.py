"""cves: CISA's SSVC decision points from the CVE record's CISA-ADP container.

Three nullable columns the cvelist enrichment source writes: exploitation
(none / poc / active), automatable (yes / no) and technical impact
(partial / total).

Revision ID: f7s8v9c0d1e2
Revises: e6c7t8x9a0b1
"""

import sqlalchemy as sa

from alembic import op

revision = "f7s8v9c0d1e2"
down_revision = "e6c7t8x9a0b1"
branch_labels = None
depends_on = None

COLUMNS = ("ssvc_exploitation", "ssvc_automatable", "ssvc_technical_impact")


def upgrade() -> None:
    for name in COLUMNS:
        op.add_column("cves", sa.Column(name, sa.String(10), nullable=True))


def downgrade() -> None:
    for name in COLUMNS:
        op.drop_column("cves", name)
