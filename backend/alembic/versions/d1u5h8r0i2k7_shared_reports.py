"""shared_reports: public share links for intel reports.

Same shape as shared_entries — one row per (report, sharer), a random
token the public URL is keyed on, an is_active switch for revoking.

Revision ID: d1u5h8r0i2k7
Revises: c0t4g7q9h1j6
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "d1u5h8r0i2k7"
down_revision = "c0t4g7q9h1j6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "shared_reports",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column(
            "report_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("intel_reports.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("token", sa.String(64), unique=True, nullable=False),
        sa.Column(
            "created_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True
        ),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("shared_reports")
