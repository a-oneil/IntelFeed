"""Cross-type reclassify tombstones (suppress resurrection of folded entities)."""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

from alembic import op

revision = "u7i9j0k1l2m3"
down_revision = "t6h8i9j0k1l2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "entity_reclassify_tombstones",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("normalized_name", sa.String(length=255), nullable=False),
        sa.Column("source_type", sa.String(length=30), nullable=False),
        sa.Column("target_type", sa.String(length=30), nullable=False),
        sa.Column("target_id", UUID(as_uuid=True), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.UniqueConstraint("source_type", "normalized_name", name="uq_reclassify_tombstone_src_name"),
    )
    op.create_index(
        "ix_reclassify_tombstone_lookup",
        "entity_reclassify_tombstones",
        ["source_type", "normalized_name", "active"],
    )
    op.create_index(
        "ix_entity_reclassify_tombstones_target_id",
        "entity_reclassify_tombstones",
        ["target_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_entity_reclassify_tombstones_target_id", table_name="entity_reclassify_tombstones")
    op.drop_index("ix_reclassify_tombstone_lookup", table_name="entity_reclassify_tombstones")
    op.drop_table("entity_reclassify_tombstones")
