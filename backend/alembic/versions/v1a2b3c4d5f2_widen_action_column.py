"""widen entity_link_validation_log.action to fit 'needs_reclassification'

The original 20-char limit fit shadow_remove / removed / restored, but the
new RECLASSIFY decision uses action='needs_reclassification' (23 chars).

Revision ID: v1a2b3c4d5f2
Revises: u1a2b3c4d5f1
Create Date: 2026-05-23

"""

import sqlalchemy as sa

from alembic import op

revision = "v1a2b3c4d5f2"
down_revision = "u1a2b3c4d5f1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        "entity_link_validation_log",
        "action",
        existing_type=sa.String(length=20),
        type_=sa.String(length=40),
        existing_nullable=False,
    )


def downgrade() -> None:
    op.alter_column(
        "entity_link_validation_log",
        "action",
        existing_type=sa.String(length=40),
        type_=sa.String(length=20),
        existing_nullable=False,
    )
