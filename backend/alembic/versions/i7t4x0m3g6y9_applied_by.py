"""Who applied a Review change: applied_by on both maintenance logs.

Revision ID: i7t4x0m3g6y9
Revises: h6s3w9l2f5x8
Create Date: 2026-11-22

History's "Applied by" column names the person who clicked Apply, Restore or
unlinked by hand. Rows the adjudicate stage or the duplicate review applied
on their own keep NULL here and are named by their origin instead.
"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

from alembic import op

revision = "i7t4x0m3g6y9"
down_revision = "h6s3w9l2f5x8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for table in ("entity_maintenance_log", "entity_link_validation_log"):
        op.add_column(
            table,
            sa.Column(
                "applied_by",
                UUID(as_uuid=True),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
        )
        op.create_index(f"ix_{table}_applied_by", table, ["applied_by"])


def downgrade() -> None:
    for table in ("entity_maintenance_log", "entity_link_validation_log"):
        op.drop_index(f"ix_{table}_applied_by", table_name=table)
        op.drop_column(table, "applied_by")
