"""Held matches in the adjudicator: pending_autolink_matches.reviewed_at and
ai_analysis_requests.adjudication_recheck_since.

``reviewed_at`` is when the adjudicator judged a held match's reject. Rows
resolved before this revision count as reviewed, so the adjudicator only
judges rejects from here on. ``adjudication_recheck_since`` scopes a re-review
to the held matches settled after that moment.

Revision ID: z7q1d4n6e8g3
Revises: y6p9c3m5d7f2
"""

import sqlalchemy as sa

from alembic import op

revision = "z7q1d4n6e8g3"
down_revision = "y6p9c3m5d7f2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("pending_autolink_matches", sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True))
    op.execute("UPDATE pending_autolink_matches SET reviewed_at = resolved_at WHERE resolved_at IS NOT NULL")
    op.add_column(
        "ai_analysis_requests", sa.Column("adjudication_recheck_since", sa.DateTime(timezone=True), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("ai_analysis_requests", "adjudication_recheck_since")
    op.drop_column("pending_autolink_matches", "reviewed_at")
