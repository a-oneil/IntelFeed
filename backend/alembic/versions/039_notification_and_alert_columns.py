"""Add alert columns to saved_searches and highlight_keywords

Revision ID: 039_notification_alerts
Revises: 038_drop_vuln_advisories
Create Date: 2026-03-14

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "039_notification_alerts"
down_revision: str | None = "038_drop_vuln_advisories"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Saved search alerting
    op.add_column("saved_searches", sa.Column("alert_enabled", sa.Boolean(), server_default="false", nullable=False))
    op.add_column("saved_searches", sa.Column("last_alert_count", sa.Integer(), server_default="0", nullable=False))

    # Highlight keyword alerting
    op.add_column(
        "highlight_keywords", sa.Column("alert_enabled", sa.Boolean(), server_default="false", nullable=False)
    )


def downgrade() -> None:
    op.drop_column("highlight_keywords", "alert_enabled")
    op.drop_column("saved_searches", "last_alert_count")
    op.drop_column("saved_searches", "alert_enabled")
