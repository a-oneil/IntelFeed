"""Add false_positive_records table, correlation event severity/occurrence_count columns.

Revision ID: 018_fp_corr_enhancements
Revises: 017_detection_summaries
Create Date: 2026-03-08
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "018_fp_corr_enhancements"
down_revision = "017_detection_summaries"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create false_positive_records table
    op.create_table(
        "false_positive_records",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("entity_type", sa.String(20), nullable=False, index=True),
        sa.Column("entity_id", postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column("entity_value", sa.String(500), nullable=False),
        sa.Column(
            "source_entry_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("entries.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("reason", sa.Text, nullable=True),
        sa.Column("marked_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("extraction_source", sa.String(20), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # Add severity and occurrence_count to correlation_event_records
    op.add_column(
        "correlation_event_records",
        sa.Column("severity", sa.String(10), nullable=False, server_default="medium"),
    )
    op.add_column(
        "correlation_event_records",
        sa.Column("occurrence_count", sa.Integer, nullable=False, server_default="1"),
    )
    op.create_index("ix_corr_events_severity", "correlation_event_records", ["severity"])


def downgrade() -> None:
    op.drop_index("ix_corr_events_severity", table_name="correlation_event_records")
    op.drop_column("correlation_event_records", "occurrence_count")
    op.drop_column("correlation_event_records", "severity")
    op.drop_table("false_positive_records")
