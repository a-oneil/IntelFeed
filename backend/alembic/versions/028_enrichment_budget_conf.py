"""Add confidence threshold and daily budget to enrichment sources

Revision ID: 028_enrichment_budget_conf
Revises: 027_add_countries_entity
Create Date: 2026-03-12
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "028_enrichment_budget_conf"
down_revision: str | None = "027_add_countries_entity"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "enrichment_sources",
        sa.Column("min_confidence_threshold", sa.String(10), server_default="low", nullable=False),
    )
    op.add_column(
        "enrichment_sources",
        sa.Column("daily_budget", sa.Integer(), nullable=True),
    )
    op.add_column(
        "enrichment_sources",
        sa.Column("daily_budget_used", sa.Integer(), server_default="0", nullable=False),
    )


def downgrade() -> None:
    op.drop_column("enrichment_sources", "daily_budget_used")
    op.drop_column("enrichment_sources", "daily_budget")
    op.drop_column("enrichment_sources", "min_confidence_threshold")
