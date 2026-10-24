"""A provider remembers its last connectivity test.

The keys list says "Tested 2h ago" or "Last test failed" from these two
columns instead of contacting the provider again on every render.

Revision ID: c9d0e1f2a3b4
Revises: b8c9d0e1f2a3
"""

import sqlalchemy as sa

from alembic import op

revision = "c9d0e1f2a3b4"
down_revision = "b8c9d0e1f2a3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("ai_providers", sa.Column("last_tested_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("ai_providers", sa.Column("last_test_error", sa.String(500), nullable=True))


def downgrade() -> None:
    op.drop_column("ai_providers", "last_test_error")
    op.drop_column("ai_providers", "last_tested_at")
