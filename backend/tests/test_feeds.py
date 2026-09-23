from types import SimpleNamespace
from unittest.mock import patch

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.feed import Feed
from app.models.user import User


@pytest.mark.asyncio
async def test_list_feeds_empty(client: AsyncClient, auth_headers: dict):
    response = await client.get("/api/feeds", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["items"] == []
    assert data["total"] == 0
    assert data["has_more"] is False


@pytest.mark.asyncio
async def test_create_feed(client: AsyncClient, auth_headers: dict):
    mock_result = SimpleNamespace(
        title="Test Blog",
        url="https://example.com/feed.xml",
        feed_type="rss",
        description="A test blog feed",
    )

    with (
        patch("app.api.feeds.discover_feed", return_value=mock_result) as mock_discover,
        patch("app.workers.feed_tasks.fetch_feed.delay") as mock_fetch,
    ):
        response = await client.post(
            "/api/feeds",
            json={"url": "https://example.com/feed.xml"},
            headers=auth_headers,
        )

    assert response.status_code == 201
    data = response.json()
    # The response is a flat FeedResponse; it used to be a subscription
    # wrapper with the feed nested under a "feed" key.
    assert data["title"] == "Test Blog"
    assert data["url"] == "https://example.com/feed.xml"
    assert data["feed_type"] == "rss"
    assert data["description"] == "A test blog feed"
    assert data["unread_count"] == 0
    assert data["is_muted"] is False

    mock_discover.assert_called_once_with("https://example.com/feed.xml")
    mock_fetch.assert_called_once()


@pytest.mark.asyncio
async def test_create_feed_duplicate(
    client: AsyncClient, auth_headers: dict, test_user: User, db_session: AsyncSession
):
    # Create a feed directly in the DB
    feed = Feed(
        title="Existing Feed",
        url="https://existing.com/feed.xml",
        feed_type="rss",
    )
    db_session.add(feed)
    await db_session.flush()

    # Attempt to add again -- discover_feed won't be called because the
    # Feed URL already exists in the DB, but we still need to mock fetch_feed.delay
    # since the code path checks for existing feed first.
    with patch("app.workers.feed_tasks.fetch_feed.delay"):
        response = await client.post(
            "/api/feeds",
            json={"url": "https://existing.com/feed.xml"},
            headers=auth_headers,
        )

    assert response.status_code == 409
    data = response.json()
    assert data["error"]["code"] == "conflict"


@pytest.mark.asyncio
async def test_get_feed(client: AsyncClient, auth_headers: dict, test_user: User, db_session: AsyncSession):
    feed = Feed(
        title="My Feed",
        url="https://myfeed.com/rss",
        feed_type="rss",
    )
    db_session.add(feed)
    await db_session.flush()

    response = await client.get(f"/api/feeds/{feed.id}", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["title"] == "My Feed"
    assert data["url"] == "https://myfeed.com/rss"


@pytest.mark.asyncio
async def test_get_feed_not_found(client: AsyncClient, auth_headers: dict):
    import uuid as _uuid

    fake_id = _uuid.uuid4()
    response = await client.get(f"/api/feeds/{fake_id}", headers=auth_headers)
    assert response.status_code == 404
    data = response.json()
    assert data["error"]["code"] == "not_found"


@pytest.mark.asyncio
async def test_delete_feed(client: AsyncClient, admin_headers: dict, test_user: User, db_session: AsyncSession):
    feed = Feed(
        title="To Delete",
        url="https://delete.com/rss",
        feed_type="rss",
    )
    db_session.add(feed)
    await db_session.flush()

    response = await client.delete(f"/api/feeds/{feed.id}", headers=admin_headers)
    assert response.status_code == 204

    # Verify feed is no longer in the list
    response = await client.get("/api/feeds", headers=admin_headers)
    assert response.status_code == 200
    assert response.json()["total"] == 0


@pytest.mark.asyncio
async def test_delete_feed_requires_admin(
    client: AsyncClient, auth_headers: dict, test_user: User, db_session: AsyncSession
):
    """Feed deletion is admin-only; a regular user gets 403 and the feed survives."""
    feed = Feed(
        title="Protected",
        url="https://protected.com/rss",
        feed_type="rss",
    )
    db_session.add(feed)
    await db_session.flush()

    response = await client.delete(f"/api/feeds/{feed.id}", headers=auth_headers)
    assert response.status_code == 403

    response = await client.get("/api/feeds", headers=auth_headers)
    assert response.status_code == 200
    assert response.json()["total"] == 1


@pytest.mark.asyncio
async def test_failing_feeds(client: AsyncClient, auth_headers: dict, test_user: User, db_session: AsyncSession):
    healthy = Feed(title="Healthy", url="https://ok.com/rss", feed_type="rss", error_count=0)
    below_threshold = Feed(title="Flaky", url="https://flaky.com/rss", feed_type="rss", error_count=3)
    failing = Feed(
        title="Broken",
        url="https://broken.com/rss",
        feed_type="rss",
        error_count=10,
        last_error="HTTP 403",
    )
    failing_high_value = Feed(
        title="CISA KEV",
        url="https://cisa.gov/feed.xml",
        feed_type="rss",
        error_count=6,
        last_error="HTTP 403",
        reliability_rating="A",
    )
    inactive = Feed(title="Disabled", url="https://off.com/rss", feed_type="rss", error_count=99, is_active=False)
    for f in (healthy, below_threshold, failing, failing_high_value, inactive):
        db_session.add(f)
    await db_session.flush()

    response = await client.get("/api/feeds/health/failing", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["threshold"] == 5
    assert data["total"] == 2
    assert data["high_value_count"] == 1
    # High-value feeds sort first, then by error count
    assert [f["title"] for f in data["feeds"]] == ["CISA KEV", "Broken"]
    assert data["feeds"][0]["is_high_value"] is True
    assert data["feeds"][1]["last_error"] == "HTTP 403"

    # Custom threshold picks up the flaky feed too
    response = await client.get("/api/feeds/health/failing?threshold=3", headers=auth_headers)
    assert response.status_code == 200
    assert response.json()["total"] == 3


@pytest.mark.asyncio
async def test_refresh_feed(client: AsyncClient, auth_headers: dict, test_user: User, db_session: AsyncSession):
    feed = Feed(
        title="Refresh Me",
        url="https://refresh.com/rss",
        feed_type="rss",
    )
    db_session.add(feed)
    await db_session.flush()

    with patch("app.workers.feed_tasks.fetch_feed.delay") as mock_fetch:
        response = await client.post(f"/api/feeds/{feed.id}/refresh", headers=auth_headers)

    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "Feed refresh queued"
    mock_fetch.assert_called_once_with(str(feed.id))


@pytest.mark.asyncio
async def test_feed_health_includes_reliability(
    client: AsyncClient, auth_headers: dict, test_user: User, db_session: AsyncSession
):
    """Feed health rows carry the reliability rating for the UI badge."""
    from datetime import UTC, datetime, timedelta

    stale_rated = Feed(
        title="Stale Rated",
        url="https://stale-rated.com/rss",
        feed_type="rss",
        reliability_rating="B",
        last_fetched_at=datetime.now(UTC) - timedelta(days=30),
    )
    unrated = Feed(title="Unrated Off", url="https://off2.com/rss", feed_type="rss", is_active=False)
    db_session.add_all([stale_rated, unrated])
    await db_session.flush()

    response = await client.get("/api/feeds/health", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()

    stale_row = next(f for f in data["stale_feeds"] if f["id"] == str(stale_rated.id))
    assert stale_row["reliability_rating"] == "B"
    disabled_row = next(f for f in data["disabled_feeds"] if f["id"] == str(unrated.id))
    assert disabled_row["reliability_rating"] is None
