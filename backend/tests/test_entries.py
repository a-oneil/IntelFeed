from datetime import UTC, datetime

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.entry import Entry
from app.models.feed import Feed
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.user_entity_watch import UserEntityWatch


@pytest_asyncio.fixture
async def test_feed(db_session: AsyncSession) -> Feed:
    """Create a feed for tests."""
    feed = Feed(
        title="Test Feed",
        url="https://entries-test.com/rss",
        feed_type="rss",
    )
    db_session.add(feed)
    await db_session.flush()
    return feed


@pytest_asyncio.fixture
async def sample_entry(db_session: AsyncSession, test_feed: Feed) -> Entry:
    """Create a sample entry attached to the test feed."""
    feed = test_feed
    entry = Entry(
        feed_id=feed.id,
        guid="unique-guid-001",
        url="https://entries-test.com/post/1",
        title="Sample Entry Title",
        author="Test Author",
        content_html="<p>Full article content here.</p>",
        content_text="Full article content here.",
        summary="A brief summary of the article.",
        published_at=datetime(2025, 1, 15, 12, 0, 0, tzinfo=UTC),
        word_count=5,
        content_hash="abc123hash",
    )
    db_session.add(entry)
    await db_session.flush()
    return entry


@pytest.mark.asyncio
async def test_list_entries_empty(client: AsyncClient, auth_headers: dict, test_feed: Feed):
    response = await client.get("/api/entries", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["items"] == []
    assert data["has_more"] is False


@pytest.mark.asyncio
async def test_list_entries_with_data(client: AsyncClient, auth_headers: dict, sample_entry: Entry):
    response = await client.get("/api/entries", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert len(data["items"]) == 1

    item = data["items"][0]
    assert item["title"] == "Sample Entry Title"
    assert item["author"] == "Test Author"
    assert item["summary"] == "A brief summary of the article."
    assert item["is_read"] is False
    assert item["is_starred"] is False
    assert item["is_bookmarked"] is False
    assert item["feed_title"] == "Test Feed"


@pytest.mark.asyncio
async def test_list_entries_watched_filter(
    client: AsyncClient, auth_headers: dict, db_session: AsyncSession, test_user, sample_entry: Entry, test_feed: Feed
):
    """?watched=true should only return entries linked to one of the user's watched entities."""
    actor = ThreatActor(name="Watched Filter Actor")
    db_session.add(actor)
    await db_session.flush()
    db_session.add(
        EntryThreatActor(entry_id=sample_entry.id, threat_actor_id=actor.id, confidence="high", source="test")
    )
    db_session.add(
        UserEntityWatch(created_by=test_user.id, entity_type="threat_actor", entity_id=actor.id, mode="watch")
    )

    unwatched_entry = Entry(
        feed_id=test_feed.id,
        guid="unwatched-guid",
        url="https://entries-test.com/post/unwatched",
        title="Unwatched Entry",
        published_at=datetime(2025, 1, 16, 12, 0, 0, tzinfo=UTC),
        content_hash="unwatchedhash",
    )
    db_session.add(unwatched_entry)
    await db_session.flush()

    response = await client.get("/api/entries", params={"watched": "true"}, headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    ids = {item["id"] for item in data["items"]}
    assert str(sample_entry.id) in ids
    assert str(unwatched_entry.id) not in ids


@pytest.mark.asyncio
async def test_list_entries_watched_filter_no_watches_returns_empty(
    client: AsyncClient, auth_headers: dict, sample_entry: Entry
):
    response = await client.get("/api/entries", params={"watched": "true"}, headers=auth_headers)
    assert response.status_code == 200
    assert response.json()["items"] == []


@pytest.mark.asyncio
async def test_get_entry_detail(client: AsyncClient, auth_headers: dict, sample_entry: Entry):
    response = await client.get(f"/api/entries/{sample_entry.id}", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["title"] == "Sample Entry Title"
    assert data["content_html"] == "<p>Full article content here.</p>"
    assert data["content_text"] == "Full article content here."
    assert data["is_read"] is False
    assert data["duplicates"] == []


@pytest.mark.asyncio
async def test_mark_read(client: AsyncClient, auth_headers: dict, sample_entry: Entry):
    response = await client.put(f"/api/entries/{sample_entry.id}/read", headers=auth_headers)
    assert response.status_code == 200
    assert response.json()["message"] == "Marked as read"

    # Verify the entry is now marked as read in the list
    response = await client.get(f"/api/entries/{sample_entry.id}", headers=auth_headers)
    assert response.status_code == 200
    assert response.json()["is_read"] is True


@pytest.mark.asyncio
async def test_toggle_star(client: AsyncClient, auth_headers: dict, sample_entry: Entry):
    # First toggle: star it
    response = await client.put(f"/api/entries/{sample_entry.id}/star", headers=auth_headers)
    assert response.status_code == 200
    assert response.json()["is_starred"] is True

    # Second toggle: unstar it
    response = await client.put(f"/api/entries/{sample_entry.id}/star", headers=auth_headers)
    assert response.status_code == 200
    assert response.json()["is_starred"] is False


@pytest.mark.asyncio
async def test_toggle_bookmark(client: AsyncClient, auth_headers: dict, sample_entry: Entry):
    # First toggle: bookmark it
    response = await client.put(f"/api/entries/{sample_entry.id}/bookmark", headers=auth_headers)
    assert response.status_code == 200
    assert response.json()["is_bookmarked"] is True

    # Second toggle: unbookmark it
    response = await client.put(f"/api/entries/{sample_entry.id}/bookmark", headers=auth_headers)
    assert response.status_code == 200
    assert response.json()["is_bookmarked"] is False


@pytest.mark.asyncio
async def test_mark_all_read(
    client: AsyncClient,
    auth_headers: dict,
    db_session: AsyncSession,
    test_feed: Feed,
):
    feed = test_feed

    # Create multiple entries
    for i in range(3):
        entry = Entry(
            feed_id=feed.id,
            guid=f"mark-all-guid-{i}",
            url=f"https://entries-test.com/post/{i}",
            title=f"Entry {i}",
            published_at=datetime(2025, 1, 15, 12, i, 0, tzinfo=UTC),
        )
        db_session.add(entry)
    await db_session.flush()

    # Mark all as read
    response = await client.post(
        "/api/entries/mark-all-read",
        json={},
        headers=auth_headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["marked"] == 3

    # Verify all entries are now read
    response = await client.get("/api/entries", params={"is_read": "true"}, headers=auth_headers)
    assert response.status_code == 200
    assert len(response.json()["items"]) == 3
