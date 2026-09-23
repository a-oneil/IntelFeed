"""Per-user learned Radar signal weights

Revision ID: q2r4s6t8u0w2
Revises: p1q3r5s7t9v1
Create Date: 2026-09-12

Adds user_signal_weights: one fitted family multiplier per (user, family),
produced nightly from that analyst's own Radar thumbs and applied as a
read-time lift on the Radar ordering. Stored Entry.priority_score is
untouched, so personalisation is reversible with one toggle.
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "q2r4s6t8u0w2"
down_revision = "p1q3r5s7t9v1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "user_signal_weights",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("family", sa.String(20), nullable=False),
        sa.Column("weight", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("up_votes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("down_votes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("sample_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("user_id", "family", name="uq_user_signal_weights_user_family"),
    )
    op.create_index("ix_user_signal_weights_user_id", "user_signal_weights", ["user_id"])


def downgrade() -> None:
    op.drop_index("ix_user_signal_weights_user_id", table_name="user_signal_weights")
    op.drop_table("user_signal_weights")
