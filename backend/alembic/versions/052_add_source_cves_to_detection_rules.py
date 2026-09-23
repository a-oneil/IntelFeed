"""add source_cves to detection_rules

Revision ID: 052_source_cves
Revises: cf799bf83445
Create Date: 2026-03-23 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "052_source_cves"
down_revision: str | None = "cf799bf83445"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "detection_rules",
        sa.Column("source_cves", JSONB, server_default="[]", nullable=False),
    )


def downgrade() -> None:
    op.drop_column("detection_rules", "source_cves")
