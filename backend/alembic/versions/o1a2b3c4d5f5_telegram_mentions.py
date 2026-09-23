"""telegram_channel_mentions and telegram_link_mentions tables

Captures Telegram channel/invite URLs found in ingested entry content so the
Workbench can show analysts which Telegram channels are being referenced by
their RSS sources but aren't yet wired up as IntelFeed feeds.

Revision ID: o1a2b3c4d5f5
Revises: n2a3b4c5d6f4
Create Date: 2026-05-03

"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "o1a2b3c4d5f5"
down_revision = "n2a3b4c5d6f4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "telegram_channel_mentions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("handle", sa.String(255), nullable=False),
        sa.Column("display_handle", sa.String(255), nullable=True),
        sa.Column("canonical_url", sa.Text(), nullable=False),
        sa.Column("primary_link_type", sa.String(20), nullable=False, server_default="channel"),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("mention_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("distinct_feed_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column(
            "feed_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("feeds.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("dismissed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "dismissed_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("notes", sa.Text(), nullable=True),
    )
    op.create_unique_constraint("uq_telegram_channel_mentions_handle", "telegram_channel_mentions", ["handle"])
    op.create_index("ix_telegram_channel_mentions_handle", "telegram_channel_mentions", ["handle"])
    op.create_index("ix_telegram_channel_mentions_last_seen", "telegram_channel_mentions", ["last_seen_at"])

    op.create_table(
        "telegram_link_mentions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "channel_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("telegram_channel_mentions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "entry_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("entries.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "feed_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("feeds.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("link_type", sa.String(20), nullable=False, server_default="channel"),
        sa.Column("message_id", sa.BigInteger(), nullable=True),
        sa.Column("invite_hash", sa.String(255), nullable=True),
        sa.Column("discovered_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_telegram_link_mentions_channel", "telegram_link_mentions", ["channel_id"])
    op.create_index("ix_telegram_link_mentions_entry", "telegram_link_mentions", ["entry_id"])
    op.create_index("ix_telegram_link_mentions_feed", "telegram_link_mentions", ["feed_id"])
    op.create_unique_constraint("uq_telegram_link_entry_url", "telegram_link_mentions", ["entry_id", "url"])


def downgrade() -> None:
    op.drop_table("telegram_link_mentions")
    op.drop_table("telegram_channel_mentions")
