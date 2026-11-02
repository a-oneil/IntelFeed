"""enrichment_jobs: the durable queue of pending enrichment lookups.

One row per (entity, source) waiting to run. The enrichment dispatcher claims
due rows by lane priority and due_at, so a lookup a source refuses is deferred
rather than dropped.

Revision ID: c4q8e2n6j0d4
Revises: j7e8f9a0b1c2
"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

from alembic import op

revision = "c4q8e2n6j0d4"
down_revision = "j7e8f9a0b1c2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "enrichment_jobs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("entity_type", sa.String(20), nullable=False),
        sa.Column("entity_id", UUID(as_uuid=True), nullable=False),
        sa.Column("entity_value", sa.Text(), nullable=False),
        sa.Column("source_type", sa.String(30), nullable=False),
        sa.Column("lane", sa.String(10), nullable=False),
        sa.Column("priority", sa.SmallInteger(), nullable=False),
        sa.Column("status", sa.String(10), nullable=False, server_default="queued"),
        sa.Column("due_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_status", sa.String(30), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column(
            "requested_by",
            UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("entity_confidence", sa.String(10), nullable=True),
        sa.Column("entity_base_confidence", sa.Float(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("entity_type", "entity_id", "source_type", name="uq_enrichment_jobs_entity_source"),
    )
    op.create_index("ix_enrichment_jobs_claim", "enrichment_jobs", ["status", "priority", "due_at"])


def downgrade() -> None:
    op.drop_index("ix_enrichment_jobs_claim", table_name="enrichment_jobs")
    op.drop_table("enrichment_jobs")
