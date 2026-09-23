"""add suggested_entity_type column for RECLASSIFY decisions

Extends the entity-link validator audit log to support a third decision type:
RECLASSIFY. Used when the article correctly references an entity but the
entity is filed under the wrong entity_type (e.g. a threat actor stored as
a malware family). The link is preserved; only the entity classification
is flagged for fixing.

Revision ID: u1a2b3c4d5f1
Revises: t1a2b3c4d5f0
Create Date: 2026-05-23

"""

import sqlalchemy as sa

from alembic import op

revision = "u1a2b3c4d5f1"
down_revision = "t1a2b3c4d5f0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "entity_link_validation_log",
        sa.Column("suggested_entity_type", sa.String(length=20), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("entity_link_validation_log", "suggested_entity_type")
