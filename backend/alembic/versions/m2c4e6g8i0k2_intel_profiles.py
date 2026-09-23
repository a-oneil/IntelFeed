"""intel profiles — named reusable report scopes (regions × verticals)

Revision ID: m2c4e6g8i0k2
Revises: l5n7p9r1t3v5
Create Date: 2026-09-20
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "m2c4e6g8i0k2"
down_revision = "l5n7p9r1t3v5"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "intel_profiles",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False, unique=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "country_ids",
            postgresql.ARRAY(postgresql.UUID(as_uuid=True)),
            nullable=False,
            server_default=sa.text("'{}'::uuid[]"),
        ),
        sa.Column("sectors", postgresql.ARRAY(sa.Text()), nullable=False, server_default=sa.text("'{}'::text[]")),
        sa.Column("window_days", sa.Integer(), nullable=False, server_default="90"),
        sa.Column("curation", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column(
            "created_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )
    op.create_index("ix_intel_profiles_created_by", "intel_profiles", ["created_by"])


def downgrade() -> None:
    op.drop_index("ix_intel_profiles_created_by", table_name="intel_profiles")
    op.drop_table("intel_profiles")
