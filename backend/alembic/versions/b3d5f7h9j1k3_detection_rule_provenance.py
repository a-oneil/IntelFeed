"""add provenance/reuse fields to detection_rules

Adds license, upstream_updated_at, references, source_products to support the
detection-rules research redesign (phase 1): surfacing where a rule came from,
whether it can be reused, and what product it detects against.

Revision ID: b3d5f7h9j1k3
Revises: a1b2c3d4e5f6
Create Date: 2026-08-19 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import ARRAY, JSONB

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b3d5f7h9j1k3"
down_revision: str | None = "a1b2c3d4e5f6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("detection_rules", sa.Column("license", sa.String(length=60), nullable=True))
    op.add_column("detection_rules", sa.Column("upstream_updated_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        "detection_rules",
        sa.Column("references", ARRAY(sa.Text()), server_default="{}", nullable=False),
    )
    op.add_column(
        "detection_rules",
        sa.Column("source_products", JSONB, server_default="[]", nullable=False),
    )


def downgrade() -> None:
    op.drop_column("detection_rules", "source_products")
    op.drop_column("detection_rules", "references")
    op.drop_column("detection_rules", "upstream_updated_at")
    op.drop_column("detection_rules", "license")
