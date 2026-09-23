"""Entity watchlist/mute table (signal engine phase 3)."""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

from alembic import op

revision = "o2c3d4e5f6g8"
down_revision = "n2b3c4d5e6f7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "user_entity_watches",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "created_by",
            UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("entity_type", sa.String(20), nullable=False),
        sa.Column("entity_id", UUID(as_uuid=True), nullable=False),
        sa.Column("mode", sa.String(10), nullable=False),
        sa.Column("boost", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("created_by", "entity_type", "entity_id", name="uq_user_entity_watch"),
    )
    op.create_index("ix_user_entity_watches_created_by", "user_entity_watches", ["created_by"])


def downgrade() -> None:
    op.drop_table("user_entity_watches")
