"""AI review verdict columns on both hygiene log tables.

The hygiene proposal reviewer (workers/hygiene_review_tasks.py) records a
per-proposal approve/reject/unsure verdict + reasoning so the workbench can
show which pending proposals the AI vouches for and bulk-apply the approved
ones. NULL review_decision means not yet reviewed.
"""

import sqlalchemy as sa

from alembic import op

revision = "w9l1m2n3o4p5"
down_revision = "v8j0k1l2m3n4"
branch_labels = None
depends_on = None

_TABLES = ("entity_link_validation_log", "entity_maintenance_log")


def upgrade() -> None:
    for table in _TABLES:
        op.add_column(table, sa.Column("review_decision", sa.String(10), nullable=True))
        op.add_column(table, sa.Column("review_reason", sa.Text(), nullable=True))
        op.add_column(table, sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    for table in _TABLES:
        op.drop_column(table, "reviewed_at")
        op.drop_column(table, "review_reason")
        op.drop_column(table, "review_decision")
