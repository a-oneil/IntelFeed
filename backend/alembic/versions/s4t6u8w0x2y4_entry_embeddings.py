"""Per-entry embeddings (pgvector)

Revision ID: s4t6u8w0x2y4
Revises: r3s5t7u9w1x3
Create Date: 2026-09-13

The vector substrate behind Story Threads and "find articles like this one".
Kept in its own table rather than a column on ``entries``: the entries table is
the hottest in the schema and a 1.5KB vector per row would bloat every
sequential scan that never touches it.

``halfvec`` (2 bytes per dimension) rather than ``vector`` (4): at 134k rows the
difference is 200MB the production box does not have to keep resident, and
recall loss at 768 dimensions is negligible.

The HNSW index is created empty, before the backfill. Building it afterwards
over 134k rows needs a maintenance_work_mem the 8GB host cannot spare; paying
the cost incrementally on insert cannot OOM.

Requires the ``vector`` extension — the db image is built from ./db/Dockerfile.
If this migration fails on CREATE EXTENSION, the database container is still
stock postgres:16-alpine and needs rebuilding.
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op
from app.models.vector_types import HalfVec

revision = "s4t6u8w0x2y4"
down_revision = "r3s5t7u9w1x3"
branch_labels = None
depends_on = None

EMBEDDING_DIM = 768


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")

    op.create_table(
        "entry_embeddings",
        sa.Column(
            "entry_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("entries.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("embedding", HalfVec(EMBEDDING_DIM), nullable=False),
        sa.Column("model", sa.String(80), nullable=False),
        # Hash of the text that was embedded: lets the sweeper skip entries
        # whose content has not changed and re-embed the ones whose has.
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.execute("CREATE INDEX ix_entry_embeddings_hnsw ON entry_embeddings USING hnsw (embedding halfvec_cosine_ops)")
    op.create_index("ix_entry_embeddings_model", "entry_embeddings", ["model"])


def downgrade() -> None:
    op.drop_index("ix_entry_embeddings_model", table_name="entry_embeddings")
    op.execute("DROP INDEX IF EXISTS ix_entry_embeddings_hnsw")
    op.drop_table("entry_embeddings")
    # The extension is left in place — dropping it would take any other vector
    # column with it.
