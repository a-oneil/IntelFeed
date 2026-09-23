"""Radar feedback table (engine phase 7)."""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

from alembic import op

revision = "s5g7h8i9j0k1"
down_revision = "r4f6g7h8i9j0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "entry_signal_feedback",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("entry_id", UUID(as_uuid=True), sa.ForeignKey("entries.id", ondelete="CASCADE"), nullable=False),
        sa.Column("created_by", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("verdict", sa.SmallInteger(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("entry_id", "created_by", name="uq_signal_feedback_entry_user"),
    )
    op.create_index("ix_entry_signal_feedback_entry_id", "entry_signal_feedback", ["entry_id"])
    op.create_index("ix_entry_signal_feedback_created_by", "entry_signal_feedback", ["created_by"])


def downgrade() -> None:
    op.drop_table("entry_signal_feedback")
