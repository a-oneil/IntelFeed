"""remove IOC entity relationships and source_iocs column

Revision ID: j1a2b3c4d5e9
Revises: i1a2b3c4d5e8
Create Date: 2026-04-21

"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision = "j1a2b3c4d5e9"
down_revision = "i1a2b3c4d5e8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Delete all entity relationships involving IOCs
    op.execute(sa.text("DELETE FROM entity_relationships WHERE source_type = 'ioc' OR target_type = 'ioc'"))

    # Drop the source_iocs column from detection_rules
    op.drop_column("detection_rules", "source_iocs")


def downgrade() -> None:
    # Re-add source_iocs column (data is lost)
    op.add_column(
        "detection_rules",
        sa.Column("source_iocs", JSONB, server_default="[]", nullable=True),
    )
    # Cannot restore deleted entity_relationships rows
