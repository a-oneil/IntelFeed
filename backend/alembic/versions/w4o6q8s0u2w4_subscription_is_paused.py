"""Per-user pause on a feed subscription.

Revision ID: w4o6q8s0u2w4
Revises: v3n5p7r9t1v3
Create Date: 2026-10-04

`Feed.is_active` is one shared switch: an admin pausing a feed stops new
articles for every reader. With per-user subscriptions on, that is the wrong
granularity — each reader should be able to stop receiving a feed without
taking it away from anyone else. This is the per-user half, mirroring how
`is_muted` already splits across the same flag.
"""

import sqlalchemy as sa

from alembic import op

revision = "w4o6q8s0u2w4"
down_revision = "v3n5p7r9t1v3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "user_feed_subscriptions",
        sa.Column("is_paused", sa.Boolean(), nullable=False, server_default="false"),
    )


def downgrade() -> None:
    op.drop_column("user_feed_subscriptions", "is_paused")
