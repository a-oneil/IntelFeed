"""Bulk ingest: ingest_batches, ingest_batch_items and ingest_files.

A batch groups the entries one drop produced; an item is one file, URL or
paste with its own outcome; a file row is the original bytes kept on disk so
an upload can be re-opened later. Entries themselves are unchanged — the link
back is ``metadata.batch_id``.

Revision ID: g4b5c6d7e8f9
Revises: f3a4b5c6d7e8
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "g4b5c6d7e8f9"
down_revision = "f3a4b5c6d7e8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ingest_batches",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("label", sa.String(200)),
        sa.Column("source", sa.String(20), nullable=False, server_default="ui"),
        sa.Column("options", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_ingest_batches_user_id", "ingest_batches", ["user_id"])

    op.create_table(
        "ingest_batch_items",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "batch_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("ingest_batches.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "parent_item_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("ingest_batch_items.id", ondelete="SET NULL"),
        ),
        sa.Column("position", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("filename", sa.String(500)),
        sa.Column("content_type", sa.String(120)),
        sa.Column("size_bytes", sa.BigInteger()),
        sa.Column("sha256", sa.String(64)),
        sa.Column("title", sa.String(2000)),
        sa.Column("source_url", sa.Text()),
        sa.Column("is_ioc_list", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("entry_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("entries.id", ondelete="SET NULL")),
        sa.Column("error", sa.Text()),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("extra", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_ingest_batch_items_batch_id", "ingest_batch_items", ["batch_id"])
    op.create_index("ix_ingest_batch_items_status", "ingest_batch_items", ["status"])
    op.create_index("ix_ingest_batch_items_entry_id", "ingest_batch_items", ["entry_id"])
    op.create_index("ix_ingest_batch_items_batch_position", "ingest_batch_items", ["batch_id", "position"])

    op.create_table(
        "ingest_files",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "item_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("ingest_batch_items.id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
        ),
        sa.Column(
            "batch_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("ingest_batches.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("entry_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("entries.id", ondelete="SET NULL")),
        sa.Column("filename", sa.String(500), nullable=False),
        sa.Column("content_type", sa.String(120), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("path", sa.String(600), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("evicted_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_ingest_files_batch_id", "ingest_files", ["batch_id"])
    op.create_index("ix_ingest_files_entry_id", "ingest_files", ["entry_id"])
    op.create_index("ix_ingest_files_sha256", "ingest_files", ["sha256"])


def downgrade() -> None:
    op.drop_table("ingest_files")
    op.drop_table("ingest_batch_items")
    op.drop_table("ingest_batches")
