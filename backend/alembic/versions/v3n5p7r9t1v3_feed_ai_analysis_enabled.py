"""Per-feed switch for the one-pass AI analysis.

Revision ID: v3n5p7r9t1v3
Revises: u2m4o6q8s0u2
Create Date: 2026-10-04

Before this, `intel_extraction_mode = "none"` was the only way to stop the AI
reading a feed — and it also disabled autolinking, scoring and everything else.
A high-volume, low-signal source you still wanted matched against your existing
catalog had no setting that said so. Defaults to true, so existing feeds keep
behaving exactly as they do today.
"""

import sqlalchemy as sa

from alembic import op

revision = "v3n5p7r9t1v3"
down_revision = "u2m4o6q8s0u2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "feeds",
        sa.Column("ai_analysis_enabled", sa.Boolean(), nullable=False, server_default="true"),
    )


def downgrade() -> None:
    op.drop_column("feeds", "ai_analysis_enabled")
