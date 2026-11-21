"""Archive feeds instead of deleting them.

Revision ID: f4y9l2v5m7p1
Revises: e2w7j0t3k5m9
Create Date: 2026-11-21

Deleting a feed cascaded to its articles, and with them every entity link,
campaign and thread membership, and link-history row they carried. A deleted
feed is now archived: ``archived_at`` takes it off every feed list and stops it
fetching, and its articles stay. A feed whose last subscriber left is archived
too; the ones already sitting inactive with no subscriber are backfilled, unless
the install has per-user subscriptions switched off (there, no subscriber rows
means nothing).
"""

import sqlalchemy as sa

from alembic import op

revision = "f4y9l2v5m7p1"
down_revision = "e2w7j0t3k5m9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("feeds", sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_feeds_archived_at", "feeds", ["archived_at"])
    op.execute(
        sa.text(
            """
            UPDATE feeds AS f SET archived_at = now()
            WHERE NOT f.is_active
              AND NOT EXISTS (SELECT 1 FROM user_feed_subscriptions s WHERE s.feed_id = f.id)
              AND NOT EXISTS (
                  SELECT 1 FROM system_settings
                  WHERE settings -> 'per_user_subscriptions_enabled' = 'false'::jsonb
              )
            """
        )
    )


def downgrade() -> None:
    op.drop_index("ix_feeds_archived_at", table_name="feeds")
    op.drop_column("feeds", "archived_at")
