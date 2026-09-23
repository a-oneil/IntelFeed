"""Add intel_extraction_mode to feeds.

Revision ID: 021_intel_extraction_mode
Revises: 020_mitre_profiles_rels
Create Date: 2026-03-09
"""

import sqlalchemy as sa

from alembic import op

revision = "021_intel_extraction_mode"
down_revision = "020_mitre_profiles_rels"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "feeds",
        sa.Column(
            "intel_extraction_mode",
            sa.String(20),
            nullable=False,
            server_default="selective",
        ),
    )


def downgrade() -> None:
    op.drop_column("feeds", "intel_extraction_mode")
