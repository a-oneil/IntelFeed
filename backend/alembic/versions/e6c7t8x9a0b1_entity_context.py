"""entity_context: what each enrichment source says about an entity.

One row per (entity, source, declared Context output), holding the value
shaped for its display. The primary key leads with (entity_type, entity_id),
which is how the profile reads it; expires_at is indexed for the nightly prune.

Revision ID: e6c7t8x9a0b1
Revises: d5m6a7n8f9s0
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "e6c7t8x9a0b1"
down_revision = "d5m6a7n8f9s0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "entity_context",
        sa.Column("entity_type", sa.String(20), nullable=False),
        sa.Column("entity_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("source_type", sa.String(30), nullable=False),
        sa.Column("key", sa.String(64), nullable=False),
        sa.Column("value", postgresql.JSONB(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("entity_type", "entity_id", "source_type", "key"),
    )
    op.create_index("ix_entity_context_expires_at", "entity_context", ["expires_at"])


def downgrade() -> None:
    op.drop_index("ix_entity_context_expires_at", table_name="entity_context")
    op.drop_table("entity_context")
