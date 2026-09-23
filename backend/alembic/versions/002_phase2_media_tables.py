"""Phase 2: Media tables (entry_media, podcasts, playback_progress)

Revision ID: 002
Revises: 001
Create Date: 2026-03-03
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "002"
down_revision: str = "001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Entry Media
    op.create_table(
        "entry_media",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column(
            "entry_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("entries.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("media_type", sa.String(20), nullable=False),  # audio, video, image, document
        sa.Column("url", sa.Text, nullable=False),
        sa.Column("mime_type", sa.String(100)),
        sa.Column("file_size", sa.BigInteger),
        sa.Column("duration_seconds", sa.Integer),
        sa.Column("thumbnail_url", sa.Text),
        sa.Column("transcript_text", sa.Text),
        sa.Column("metadata", postgresql.JSONB, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("idx_entry_media_entry", "entry_media", ["entry_id"])
    op.create_index("idx_entry_media_type", "entry_media", ["media_type"])

    # Podcasts (show-level metadata)
    op.create_table(
        "podcasts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column(
            "feed_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("feeds.id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
        ),
        sa.Column("author", sa.String(255)),
        sa.Column("categories", postgresql.ARRAY(sa.Text), server_default="{}"),
        sa.Column("is_explicit", sa.Boolean, server_default=sa.text("false")),
        sa.Column("podcast_type", sa.String(20), server_default="episodic"),  # episodic, serial
        sa.Column("artwork_url", sa.Text),
        sa.Column("metadata", postgresql.JSONB, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # Playback Progress (per-user media position tracking)
    op.create_table(
        "playback_progress",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column(
            "user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column(
            "entry_media_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("entry_media.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("position_seconds", sa.Integer, nullable=False, server_default="0"),
        sa.Column("is_completed", sa.Boolean, server_default=sa.text("false")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("user_id", "entry_media_id"),
    )


def downgrade() -> None:
    op.drop_table("playback_progress")
    op.drop_table("podcasts")
    op.drop_table("entry_media")
