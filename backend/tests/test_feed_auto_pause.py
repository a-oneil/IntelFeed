"""Dead-feed auto-pause: a 4xx streak past the window pauses the feed; a
quiet blog, a 5xx, a timeout or a young streak never does."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.feed import Feed
from app.workers.feed_tasks import _auto_pause_dead_feeds, _note_fetch_error, _note_fetch_success


def test_fetch_error_streak_starts_once_and_ends_on_success():
    feed = Feed(title="t", url="https://t.example/rss", feed_type="rss", error_count=0)

    _note_fetch_error(feed, "HTTP 404")
    first = feed.error_since
    assert feed.error_count == 1 and feed.last_error == "HTTP 404"
    assert first is not None and feed.last_fetched_at is not None

    _note_fetch_error(feed, "HTTP 404")
    assert feed.error_count == 2
    assert feed.error_since == first, "the streak start must not move on later failures"

    _note_fetch_success(feed)
    assert feed.error_count == 0 and feed.last_error is None and feed.error_since is None


@pytest.mark.asyncio
async def test_auto_pause_only_old_4xx_streaks(db_session: AsyncSession):
    now = datetime.now(UTC)

    def mk(name: str, **kw) -> Feed:
        return Feed(title=name, url=f"https://{name}.example/rss", feed_type="rss", **kw)

    gone = mk("gone", error_count=400, last_error="HTTP 404", error_since=now - timedelta(days=31))
    blocked = mk("blocked", error_count=50, last_error="HTTP 403", error_since=now - timedelta(days=40))
    recent = mk("recent", error_count=10, last_error="HTTP 404", error_since=now - timedelta(days=10))
    server = mk("server", error_count=400, last_error="HTTP 503", error_since=now - timedelta(days=60))
    network = mk(
        "network", error_count=400, last_error="All connection attempts failed", error_since=now - timedelta(days=60)
    )
    html = mk(
        "html",
        error_count=400,
        last_error="Non-feed response: HTTP 200 with content-type 'text/html'",
        error_since=now - timedelta(days=60),
    )
    quiet = mk("quiet", error_count=0)  # seldom posts, always answers 200
    flaky = mk("flaky", error_count=2, last_error="HTTP 404", error_since=now - timedelta(days=60))
    feeds = [gone, blocked, recent, server, network, html, quiet, flaky]
    db_session.add_all(feeds)
    await db_session.flush()

    assert await _auto_pause_dead_feeds(db_session, 30) == 2

    for f in feeds:
        await db_session.refresh(f)
    assert not gone.is_active and gone.auto_paused_at is not None
    assert not blocked.is_active and blocked.auto_paused_at is not None
    for f in (recent, server, network, html, quiet, flaky):
        assert f.is_active and f.auto_paused_at is None, f.title

    # Already paused feeds are not counted again.
    assert await _auto_pause_dead_feeds(db_session, 30) == 0
