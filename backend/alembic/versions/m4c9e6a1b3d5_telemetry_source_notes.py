"""Add telemetry_source_notes: shared notes and saved links per telemetry source.

Revision ID: m4c9e6a1b3d5
Revises: l3b8d5f0a2c4
Create Date: 2026-11-25

Keyed by source name rather than a telemetry_sources row, so a catalog
source that nobody has enabled yet can still collect notes.
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "m4c9e6a1b3d5"
down_revision = "l3b8d5f0a2c4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "telemetry_source_notes",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("source_name", sa.String(255), nullable=False),
        sa.Column(
            "user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("url", sa.Text(), nullable=True),
        sa.Column("page_title", sa.String(500), nullable=True),
        sa.Column("quote", sa.Text(), nullable=True),
        sa.Column("content", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.CheckConstraint("url IS NOT NULL OR content IS NOT NULL", name="ck_telemetry_source_notes_url_or_content"),
    )
    op.create_index("ix_telemetry_source_notes_source_name", "telemetry_source_notes", ["source_name"])
    op.create_index("ix_telemetry_source_notes_user_id", "telemetry_source_notes", ["user_id"])


def downgrade() -> None:
    op.drop_index("ix_telemetry_source_notes_user_id", table_name="telemetry_source_notes")
    op.drop_index("ix_telemetry_source_notes_source_name", table_name="telemetry_source_notes")
    op.drop_table("telemetry_source_notes")
