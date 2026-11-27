"""Archived feeds: hidden everywhere as if deleted, but kept in the database.

Deleting a feed row would cascade to its articles, and with them every entity
link, campaign and thread membership and link-history row: intelligence the
analysis had already extracted and the adjudicator had already judged. A feed
is archived instead, when it is deleted or loses its last subscriber:

- it stops fetching and drops out of every feed list (``visible_feed_ids_query``
  and the listings that query ``Feed`` directly), and default search;
- its articles stay, and stay reachable where they are evidence: an entity's,
  campaign's or thread's article list, relationships, reports;
- search reaches it only with ``is:archived``.

Nothing in the UI names the state. Adding or subscribing to the feed again
brings it back (``unarchive_feed``).
"""

import uuid
from datetime import UTC, datetime

from sqlalchemy import Select, delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.feed import Feed
from app.models.user_feed_subscription import UserFeedSubscription


def archived_feed_ids_query() -> Select:
    return select(Feed.id).where(Feed.archived_at.is_not(None))


async def archive_feed(db: AsyncSession, feed: Feed) -> list[uuid.UUID]:
    """Archive a feed and drop every subscription to it. Returns the readers
    it was taken from, whose cached unread counts the caller invalidates."""
    readers = list(
        (
            await db.execute(
                delete(UserFeedSubscription)
                .where(UserFeedSubscription.feed_id == feed.id)
                .returning(UserFeedSubscription.user_id)
            )
        ).scalars()
    )
    if feed.archived_at is None:
        feed.archived_at = datetime.now(UTC)
    feed.is_active = False
    db.add(feed)
    await db.flush()
    return readers


def unarchive_feed(feed: Feed) -> bool:
    """Bring an archived feed back to fetching. True when it was archived.
    The caller subscribes whoever brought it back."""
    if feed.archived_at is None:
        return False
    feed.archived_at = None
    feed.is_active = True
    return True


async def revive_feed(db: AsyncSession, feed: Feed, user_id: uuid.UUID) -> bool:
    """Bring back an archived feed someone added again, onto their list (or
    everyone's, with per-user subscriptions off). True when it was archived."""
    from app.services.feed_visibility import ensure_subscription, subscribe_all_users, subscriptions_enabled

    if not unarchive_feed(feed):
        return False
    if await subscriptions_enabled(db):
        await ensure_subscription(db, user_id, feed.id)
    else:
        await subscribe_all_users(db, feed.id)
    db.add(feed)
    await db.flush()
    return True
