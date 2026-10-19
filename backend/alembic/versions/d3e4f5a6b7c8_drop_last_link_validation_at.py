"""Drop entries.last_link_validation_at.

Revision ID: d3e4f5a6b7c8
Revises: c2d3e4f5a6b7
Create Date: 2026-10-11

The column dated the entry's last link review for the validator job, which
the adjudicate stage replaced. ``ai_analysis_requests.adjudicated_at``
answers the same question and carries the status and queue timestamps with
it, so this one was written and never read. Its index went too.
"""

import sqlalchemy as sa

from alembic import op

revision = "d3e4f5a6b7c8"
down_revision = "c2d3e4f5a6b7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_index("ix_entries_last_link_validation_at", table_name="entries")
    op.drop_column("entries", "last_link_validation_at")


def downgrade() -> None:
    op.add_column("entries", sa.Column("last_link_validation_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index(
        "ix_entries_last_link_validation_at",
        "entries",
        ["last_link_validation_at"],
        postgresql_ops={"last_link_validation_at": "NULLS FIRST"},
    )
