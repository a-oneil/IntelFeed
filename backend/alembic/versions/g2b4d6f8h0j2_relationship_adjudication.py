"""AI adjudication columns on entity_relationships

The nightly relationship adjudicator records its verdict per edge:
``corroborated`` upgrades confidence to confirmed; ``coincidental`` demotes to
possible and blocks future co-occurrence re-promotion. ``adjudicated_at``
lets the batch skip already-reviewed edges until new evidence arrives.

Revision ID: g2b4d6f8h0j2
Revises: f1a3c5e7g9i1
Create Date: 2026-08-24
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "g2b4d6f8h0j2"
down_revision: str = "f1a3c5e7g9i1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("entity_relationships", sa.Column("adjudication_verdict", sa.String(20), nullable=True))
    op.add_column("entity_relationships", sa.Column("adjudicated_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("entity_relationships", "adjudicated_at")
    op.drop_column("entity_relationships", "adjudication_verdict")
