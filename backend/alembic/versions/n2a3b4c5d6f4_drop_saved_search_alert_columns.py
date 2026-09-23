"""drop dead saved_search alert columns

Drops `saved_searches.alert_enabled` and `saved_searches.last_alert_count`,
which were added in migration `039_notification_alerts` but never had a
functional consumer. The `_dispatch_saved_search_alert` helper only emitted
SSE events that nothing on the frontend listened for, and the
`alert_enabled` field was silently never persisted by `update_saved_search`.

Saved-search alerting now ships via the automation engine's new
`on_saved_search_match` trigger type (no schema column needed; the rule
itself owns the watermark via `automation_rules.last_triggered_at`).

The `highlight_keywords.alert_enabled` column from migration 039 is left
intact — that one has a real consumer in `feed_tasks.py`.

Revision ID: n2a3b4c5d6f4
Revises: m1a2b3c4d5f2
Create Date: 2026-05-02

"""

import sqlalchemy as sa

from alembic import op

revision = "n2a3b4c5d6f4"
down_revision = "m1a2b3c4d5f2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_column("saved_searches", "last_alert_count")
    op.drop_column("saved_searches", "alert_enabled")


def downgrade() -> None:
    op.add_column(
        "saved_searches",
        sa.Column("alert_enabled", sa.Boolean(), server_default="false", nullable=False),
    )
    op.add_column(
        "saved_searches",
        sa.Column("last_alert_count", sa.Integer(), server_default="0", nullable=False),
    )
