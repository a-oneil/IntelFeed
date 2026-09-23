"""Initial Phase 1 schema

Revision ID: 001
Revises:
Create Date: 2026-03-03
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Users
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("email", sa.String(255), nullable=False, unique=True, index=True),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("display_name", sa.String(100)),
        sa.Column("role", sa.String(20), nullable=False, server_default="user"),
        sa.Column("settings", postgresql.JSONB, server_default="{}"),
        sa.Column("is_active", sa.Boolean, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # Feeds
    op.create_table(
        "feeds",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("url", sa.Text, nullable=False, unique=True),
        sa.Column("feed_type", sa.String(30), nullable=False, server_default="rss", index=True),
        sa.Column("site_url", sa.Text),
        sa.Column("icon_url", sa.Text),
        sa.Column("description", sa.Text),
        sa.Column("language", sa.String(10)),
        sa.Column("last_fetched_at", sa.DateTime(timezone=True)),
        sa.Column("fetch_interval_minutes", sa.Integer, nullable=False, server_default="30"),
        sa.Column("etag", sa.String(255)),
        sa.Column("last_modified", sa.String(255)),
        sa.Column("error_count", sa.Integer, server_default="0"),
        sa.Column("last_error", sa.Text),
        sa.Column("is_active", sa.Boolean, server_default=sa.text("true"), index=True),
        sa.Column("adapter_config", postgresql.JSONB, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # Categories
    op.create_table(
        "categories",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column(
            "parent_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("categories.id", ondelete="SET NULL"), index=True
        ),
        sa.Column("position", sa.Integer, nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # User Feed Subscriptions
    op.create_table(
        "user_feed_subscriptions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "feed_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("feeds.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "category_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("categories.id", ondelete="SET NULL"),
            index=True,
        ),
        sa.Column("custom_title", sa.String(500)),
        sa.Column("is_muted", sa.Boolean, server_default=sa.text("false")),
        sa.Column("retention_days", sa.Integer),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("user_id", "feed_id"),
    )

    # Entries
    op.create_table(
        "entries",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column(
            "feed_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("feeds.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("guid", sa.String(2000)),
        sa.Column("url", sa.Text),
        sa.Column("title", sa.String(2000), nullable=False),
        sa.Column("author", sa.String(500)),
        sa.Column("content_html", sa.Text),
        sa.Column("content_text", sa.Text),
        sa.Column("summary", sa.Text),
        sa.Column("published_at", sa.DateTime(timezone=True), index=True),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("word_count", sa.Integer),
        sa.Column("language", sa.String(10)),
        sa.Column("metadata", postgresql.JSONB, server_default="{}"),
        sa.Column("content_hash", sa.String(64), index=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("feed_id", "guid"),
    )

    # User Entry States
    op.create_table(
        "user_entry_states",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "entry_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("entries.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("is_read", sa.Boolean, server_default=sa.text("false")),
        sa.Column("is_starred", sa.Boolean, server_default=sa.text("false")),
        sa.Column("is_bookmarked", sa.Boolean, server_default=sa.text("false")),
        sa.Column("read_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("user_id", "entry_id"),
    )


def downgrade() -> None:
    op.drop_table("user_entry_states")
    op.drop_table("entries")
    op.drop_table("user_feed_subscriptions")
    op.drop_table("categories")
    op.drop_table("feeds")
    op.drop_table("users")
