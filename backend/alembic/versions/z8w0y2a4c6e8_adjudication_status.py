"""Adjudicate stage: per-entry review state on the AI analysis request row.

Revision ID: z8w0y2a4c6e8
Revises: z7r9t1v3x5z7
Create Date: 2026-10-08

The post-analysis adjudicate stage (docs/engine-settings.md) decides,
right after an entry's one-pass analysis lands, whether that entry gets an AI
review of everything the analysis wrote. The decision and its outcome live on
the same per-entry row that already tracks the analysis lifecycle:

  adjudication_status  pending | completed | failed | skipped_<reason>
                       (off, plan, echo, nothing_new, score, budget);
                       NULL = not yet decided, which the resweep picks up
  adjudicated_at       when the review finished

Both nullable, so existing rows need no backfill and the columns are free
until adjudication_mode is switched on.
"""

import sqlalchemy as sa

from alembic import op

revision = "z8w0y2a4c6e8"
down_revision = "z7r9t1v3x5z7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("ai_analysis_requests", sa.Column("adjudication_status", sa.String(length=24), nullable=True))
    op.add_column("ai_analysis_requests", sa.Column("adjudicated_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index(
        "ix_ai_analysis_requests_adjudication_status",
        "ai_analysis_requests",
        ["adjudication_status"],
    )


def downgrade() -> None:
    op.drop_index("ix_ai_analysis_requests_adjudication_status", table_name="ai_analysis_requests")
    op.drop_column("ai_analysis_requests", "adjudicated_at")
    op.drop_column("ai_analysis_requests", "adjudication_status")
