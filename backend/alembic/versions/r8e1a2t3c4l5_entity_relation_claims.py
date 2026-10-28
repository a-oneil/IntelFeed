"""entity_relation_claims: each enrichment source's claims that an entity is
connected to another.

One row per (entity, source, Relation output, target name). ``target_id`` is
the existing entity the name resolved to, null while the claim is held. The
target index serves "does another claim still hold this connection?" when one
is withdrawn; the source index serves the console's linked and held counts.

Revision ID: r8e1a2t3c4l5
Revises: c4p3d3f5n6d7
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "r8e1a2t3c4l5"
down_revision = "c4p3d3f5n6d7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "entity_relation_claims",
        sa.Column("entity_type", sa.String(20), nullable=False),
        sa.Column("entity_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("source_type", sa.String(30), nullable=False),
        sa.Column("output", sa.String(64), nullable=False),
        sa.Column("target_key", sa.String(255), nullable=False),
        sa.Column("relation", sa.String(30), nullable=False),
        sa.Column("target_name", sa.Text(), nullable=False),
        sa.Column("target_type", sa.String(20), nullable=True),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("held_reason", sa.String(20), nullable=True),
        sa.Column("evidence", sa.Text(), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("entity_type", "entity_id", "source_type", "output", "target_key"),
    )
    op.create_index("ix_entity_relation_claims_target", "entity_relation_claims", ["target_type", "target_id"])
    op.create_index("ix_entity_relation_claims_source", "entity_relation_claims", ["source_type", "output"])


def downgrade() -> None:
    op.drop_index("ix_entity_relation_claims_source", table_name="entity_relation_claims")
    op.drop_index("ix_entity_relation_claims_target", table_name="entity_relation_claims")
    op.drop_table("entity_relation_claims")
