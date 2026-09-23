"""add metadata to detection_rules

Revision ID: 047_add_metadata
Revises: 046
Create Date: 2026-03-15
"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision = "047_add_metadata"
down_revision = "046"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("detection_rules", sa.Column("metadata", JSONB, nullable=True))


def downgrade() -> None:
    op.drop_column("detection_rules", "metadata")
