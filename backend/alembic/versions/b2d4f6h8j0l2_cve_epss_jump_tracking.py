"""CVE EPSS jump tracking: previous score + change timestamp

Revision ID: b2d4f6h8j0l2
Revises: a9x1z3b5c7d9
Create Date: 2026-08-15
"""

import sqlalchemy as sa

from alembic import op

revision = "b2d4f6h8j0l2"
down_revision = "a9x1z3b5c7d9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("cves", sa.Column("epss_previous_score", sa.Float(), nullable=True))
    op.add_column("cves", sa.Column("epss_changed_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("cves", "epss_changed_at")
    op.drop_column("cves", "epss_previous_score")
