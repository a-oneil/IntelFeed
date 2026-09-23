"""Phase 3: notes, saved_searches, tags, entry_tags tables

Revision ID: 003
Revises: 002
Create Date: 2026-03-03
"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

revision = "003"
down_revision = "002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Notes table
    op.create_table(
        "notes",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("entry_id", UUID(as_uuid=True), sa.ForeignKey("entries.id", ondelete="SET NULL"), nullable=True),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("content_markdown", sa.Text, nullable=False, server_default=""),
        sa.Column("content_html", sa.Text, nullable=True),
        sa.Column("is_pinned", sa.Boolean, server_default=sa.text("FALSE"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("idx_notes_user", "notes", ["user_id"])
    op.create_index("idx_notes_entry", "notes", ["entry_id"])
    op.create_index("idx_notes_pinned", "notes", ["user_id", "is_pinned"], postgresql_where=sa.text("is_pinned = TRUE"))

    # Saved searches table
    op.create_table(
        "saved_searches",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("query", sa.Text, nullable=True),
        sa.Column("filters", JSONB, server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("idx_saved_searches_user", "saved_searches", ["user_id"])

    # Tags table
    op.create_table(
        "tags",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("color", sa.String(7), server_default="'#6B7280'", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("user_id", "name", name="uq_tags_user_name"),
    )
    op.create_index("idx_tags_user", "tags", ["user_id"])

    # Entry-tags junction table
    op.create_table(
        "entry_tags",
        sa.Column("entry_id", UUID(as_uuid=True), sa.ForeignKey("entries.id", ondelete="CASCADE"), nullable=False),
        sa.Column("tag_id", UUID(as_uuid=True), sa.ForeignKey("tags.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.PrimaryKeyConstraint("entry_id", "tag_id", "user_id"),
    )
    op.create_index("idx_entry_tags_user", "entry_tags", ["user_id"])
    op.create_index("idx_entry_tags_tag", "entry_tags", ["tag_id"])


def downgrade() -> None:
    op.drop_table("entry_tags")
    op.drop_table("tags")
    op.drop_table("saved_searches")
    op.drop_table("notes")
