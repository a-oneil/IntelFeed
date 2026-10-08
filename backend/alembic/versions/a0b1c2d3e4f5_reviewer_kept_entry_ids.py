"""Adjudicate stage: per-edge keep counter that replaces nightly promotion.

Revision ID: a0b1c2d3e4f5
Revises: z8w0y2a4c6e8
Create Date: 2026-10-08

The nightly relationship adjudicator promoted a probable edge to confirmed
after re-reading its evidence headlines. With that job retired, promotion
becomes a counter: every time the adjudicate stage, in apply mode, keeps the
same edge while reviewing a different entry, that entry id is appended here;
at relationship_evidence_promote_count distinct entries the edge is promoted.
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "a0b1c2d3e4f5"
down_revision = "z8w0y2a4c6e8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "entity_relationships",
        sa.Column(
            "reviewer_kept_entry_ids",
            postgresql.ARRAY(postgresql.UUID(as_uuid=True)),
            nullable=False,
            server_default="{}",
        ),
    )


def downgrade() -> None:
    op.drop_column("entity_relationships", "reviewer_kept_entry_ids")
