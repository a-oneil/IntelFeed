"""pending_autolink_matches — dictionary-word autolink matches held for AI confirmation

Revision ID: y4p6q8r0s2t3
Revises: x2m4n6p8r0s1
Create Date: 2026-08-12
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "y4p6q8r0s2t3"
down_revision = "x2m4n6p8r0s1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "pending_autolink_matches",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "entry_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("entries.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("entity_type", sa.String(20), nullable=False),
        sa.Column("entity_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("canonical_name", sa.String(500), nullable=False),
        sa.Column("matched_names", postgresql.ARRAY(sa.Text()), nullable=True),
        sa.Column("paragraph_indices", postgresql.ARRAY(sa.SmallInteger()), nullable=True),
        sa.Column("confidence", sa.String(10), nullable=True),
        sa.Column("source_weight", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolution", sa.String(20), nullable=True),
        sa.UniqueConstraint("entry_id", "entity_type", "entity_id", name="uq_pending_autolink_entry_entity"),
    )
    op.create_index("ix_pending_autolink_matches_entry_id", "pending_autolink_matches", ["entry_id"])
    op.create_index("ix_pending_autolink_matches_created_at", "pending_autolink_matches", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_pending_autolink_matches_created_at", table_name="pending_autolink_matches")
    op.drop_index("ix_pending_autolink_matches_entry_id", table_name="pending_autolink_matches")
    op.drop_table("pending_autolink_matches")
