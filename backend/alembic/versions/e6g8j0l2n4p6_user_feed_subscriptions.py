"""user_feed_subscriptions — each analyst's view over the shared feed pool

The feed pool (fetching, entries, category tree, curation) stays shared; this
table records which feeds each user sees and their personal mute. Behavior is
gated by the `per_user_subscriptions_enabled` system setting (default off).

The backfill subscribes every existing human user to every existing feed and
copies the feed's current global mute, so flipping the flag on changes nothing
visually until someone actually unsubscribes or mutes.

Revision ID: e6g8j0l2n4p6
Revises: d5f7h9j1l3n5
Create Date: 2026-09-15
"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

from alembic import op

revision = "e6g8j0l2n4p6"
down_revision = "d5f7h9j1l3n5"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "user_feed_subscriptions",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "feed_id",
            UUID(as_uuid=True),
            sa.ForeignKey("feeds.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("is_muted", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("user_id", "feed_id", name="uq_user_feed_subscription"),
    )

    # Everyone who exists today was seeing every feed — keep it that way.
    op.execute(
        """
        INSERT INTO user_feed_subscriptions (id, user_id, feed_id, is_muted, created_at)
        SELECT gen_random_uuid(), u.id, f.id, f.is_muted, now()
        FROM users u
        CROSS JOIN feeds f
        WHERE u.role != 'system'
        """
    )


def downgrade() -> None:
    op.drop_table("user_feed_subscriptions")
