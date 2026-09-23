"""add sort_order to dashboards

Revision ID: 053_sort_order
Revises: 052_source_cves
Create Date: 2026-03-23 23:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "053_sort_order"
down_revision: str | None = "052_source_cves"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "dashboards",
        sa.Column("sort_order", sa.Integer(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_column("dashboards", "sort_order")
