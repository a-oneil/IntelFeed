"""Adjudicate stage: when the review was queued.

Revision ID: c2d3e4f5a6b7
Revises: b1c2d3e4f5a6
Create Date: 2026-10-08

``adjudication_status = 'pending'`` says a review is queued or running; it
says nothing about how long. The hourly sweep needs that to tell a row the
AI queue is still draining from one whose task was lost (worker crash,
dispatch failure, retries exhausted), so the enqueue path stamps
``adjudication_queued_at`` and the sweep re-enqueues pending rows older than
its stale window.
"""

import sqlalchemy as sa

from alembic import op

revision = "c2d3e4f5a6b7"
down_revision = "b1c2d3e4f5a6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "ai_analysis_requests", sa.Column("adjudication_queued_at", sa.DateTime(timezone=True), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("ai_analysis_requests", "adjudication_queued_at")
