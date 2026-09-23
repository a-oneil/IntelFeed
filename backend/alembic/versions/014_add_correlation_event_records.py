"""Add correlation_event_records table

Revision ID: 014
Revises: 013
"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

from alembic import op

revision = "014"
down_revision = "013"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "correlation_event_records",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("event_type", sa.String(50), nullable=False),
        sa.Column("entry_id", UUID(as_uuid=True), sa.ForeignKey("entries.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source_entity_type", sa.String(30), nullable=False),
        sa.Column("source_entity_id", UUID(as_uuid=True), nullable=False),
        sa.Column("source_entity_label", sa.String(500), nullable=False),
        sa.Column("related_entity_type", sa.String(30), nullable=False),
        sa.Column("related_entity_id", UUID(as_uuid=True), nullable=False),
        sa.Column("related_entity_label", sa.String(500), nullable=False),
        sa.Column("context", sa.Text, nullable=False),
        sa.Column("is_read", sa.Boolean, default=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_corr_events_event_type", "correlation_event_records", ["event_type"])
    op.create_index("ix_corr_events_entry_id", "correlation_event_records", ["entry_id"])
    op.create_index("ix_corr_events_is_read", "correlation_event_records", ["is_read"])
    op.create_index("ix_corr_events_created_at", "correlation_event_records", ["created_at"])
    op.create_index("ix_corr_events_unread_created", "correlation_event_records", ["is_read", "created_at"])


def downgrade():
    op.drop_table("correlation_event_records")
