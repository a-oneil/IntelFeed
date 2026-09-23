"""Which feeds a user sees, and which they've muted.

With `per_user_subscriptions_enabled` off (the default), behavior is the
pre-multi-user one: a single shared feed list whose mute state is the global
`Feed.is_muted` column. With it on, a user sees the feeds they hold a
`user_feed_subscriptions` row for, and mute comes from that row.

Deliberately still on the global column regardless of the flag: search's
`is:muted` operator, the atlas/strategic map, backup export, the public RSS
proxy, and the CLI feed tools — those are instance-level concepts.
"""

import uuid

from sqlalchemy import Select, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.feed import Feed
from app.models.user_feed_subscription import UserFeedSubscription


async def subscriptions_enabled(db: AsyncSession) -> bool:
    from app.services.system_settings import get_setting

    return bool(await get_setting("per_user_subscriptions_enabled", db))


def visible_feed_ids_query(
    user_id: uuid.UUID | None,
    *,
    enabled: bool,
    include_muted: bool = False,
    active_only: bool = False,
    category_id: uuid.UUID | None = None,
) -> Select:
    """Subquery of feed ids the user should see.

    Matches the legacy semantics call-for-call: a category view keeps muted
    feeds (pass include_muted=True there), the home view drops them.
    """
    if enabled and user_id is not None:
        q = (
            select(UserFeedSubscription.feed_id)
            .join(Feed, Feed.id == UserFeedSubscription.feed_id)
            .where(UserFeedSubscription.user_id == user_id)
        )
        if not include_muted:
            q = q.where(UserFeedSubscription.is_muted.is_(False))
    else:
        q = select(Feed.id)
        if not include_muted:
            q = q.where(Feed.is_muted.is_(False))
    if category_id is not None:
        q = q.where(Feed.category_id == category_id)
    if active_only:
        q = q.where(Feed.is_active.is_(True))
    return q


async def get_subscription(db: AsyncSession, user_id: uuid.UUID, feed_id: uuid.UUID) -> UserFeedSubscription | None:
    result = await db.execute(
        select(UserFeedSubscription).where(
            UserFeedSubscription.user_id == user_id,
            UserFeedSubscription.feed_id == feed_id,
        )
    )
    return result.scalar_one_or_none()


async def ensure_subscription(
    db: AsyncSession, user_id: uuid.UUID, feed_id: uuid.UUID, *, is_muted: bool = False
) -> None:
    """Idempotently subscribe a user to a feed."""
    await db.execute(
        pg_insert(UserFeedSubscription)
        .values(id=uuid.uuid4(), user_id=user_id, feed_id=feed_id, is_muted=is_muted)
        .on_conflict_do_nothing(constraint="uq_user_feed_subscription")
    )


async def subscribe_all_users(db: AsyncSession, feed_id: uuid.UUID) -> None:
    """Subscribe every human user to a feed (used while the flag is off, so a
    later flip finds the table consistent with what everyone was seeing)."""
    from sqlalchemy import text

    await db.execute(
        text(
            "INSERT INTO user_feed_subscriptions (id, user_id, feed_id, is_muted, created_at) "
            "SELECT gen_random_uuid(), u.id, :feed_id, false, now() FROM users u "
            "WHERE u.role != 'system' "
            "ON CONFLICT ON CONSTRAINT uq_user_feed_subscription DO NOTHING"
        ),
        {"feed_id": str(feed_id)},
    )


async def seed_subscriptions_for_new_user(db: AsyncSession, user_id: uuid.UUID) -> None:
    """Give a fresh account the instance's default feed list: a copy of the
    earliest admin's subscriptions (mutes included) — same convention as the
    default dashboards."""
    from sqlalchemy import text

    await db.execute(
        text(
            "INSERT INTO user_feed_subscriptions (id, user_id, feed_id, is_muted, created_at) "
            "SELECT gen_random_uuid(), :user_id, s.feed_id, s.is_muted, now() "
            "FROM user_feed_subscriptions s "
            "JOIN users a ON a.id = s.user_id "
            "WHERE a.role = 'admin' AND a.created_at = ("
            "  SELECT min(created_at) FROM users WHERE role = 'admin'"
            ") "
            "ON CONFLICT ON CONSTRAINT uq_user_feed_subscription DO NOTHING"
        ),
        {"user_id": str(user_id)},
    )


async def subscriber_map(db: AsyncSession, feed_ids: list[uuid.UUID]) -> dict[uuid.UUID, list[dict]]:
    """feed_id -> [{user_id, username, is_muted}], for admin "who is affected" reads.

    One grouped query for the whole batch — the feed-health views call this with
    every erroring/stale/disabled feed at once.
    """
    if not feed_ids:
        return {}
    from app.models.user import User

    result = await db.execute(
        select(
            UserFeedSubscription.feed_id,
            UserFeedSubscription.user_id,
            UserFeedSubscription.is_muted,
            User.username,
        )
        .join(User, User.id == UserFeedSubscription.user_id)
        .where(UserFeedSubscription.feed_id.in_(feed_ids))
        .order_by(User.username)
    )
    out: dict[uuid.UUID, list[dict]] = {}
    for row in result.all():
        out.setdefault(row.feed_id, []).append(
            {"user_id": str(row.user_id), "username": row.username, "is_muted": row.is_muted}
        )
    return out


def reach_payload(subscribers: list[dict]) -> dict:
    """The per-feed "who is affected" block the admin feed-health views render."""
    return {
        "subscriber_count": len(subscribers),
        "muted_count": sum(1 for s in subscribers if s["is_muted"]),
        "subscribers": subscribers,
    }


async def subscription_mute_map(
    db: AsyncSession, user_id: uuid.UUID, feed_ids: list[uuid.UUID]
) -> dict[uuid.UUID, bool]:
    """feed_id -> is_muted for the user's subscriptions among feed_ids."""
    if not feed_ids:
        return {}
    result = await db.execute(
        select(UserFeedSubscription.feed_id, UserFeedSubscription.is_muted).where(
            UserFeedSubscription.user_id == user_id,
            UserFeedSubscription.feed_id.in_(feed_ids),
        )
    )
    return {row.feed_id: row.is_muted for row in result.all()}
