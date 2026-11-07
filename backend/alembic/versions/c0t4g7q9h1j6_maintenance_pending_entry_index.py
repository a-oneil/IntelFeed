"""entity_maintenance_log: index pending proposals by the article they are about.

The adjudicate stage looks up an article's pending verdicts on every review
(its second look settles them), and before->>'entry_id' had no index.

Revision ID: c0t4g7q9h1j6
Revises: b9s3f6p8g0i5
"""

from alembic import op

revision = "c0t4g7q9h1j6"
down_revision = "b9s3f6p8g0i5"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_entity_maintenance_log_pending_entry "
        "ON entity_maintenance_log ((before->>'entry_id')) WHERE applied = false"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_entity_maintenance_log_pending_entry")
