"""Tests for media attachment CRUD and playback progress API."""

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.entry import Entry
from app.models.entry_media import EntryMedia
from app.models.feed import Feed


@pytest_asyncio.fixture
async def feed_with_media(db_session: AsyncSession, test_user):
    """Create a feed with an entry that has media attachments."""
    feed = Feed(title="Test Podcast", url="https://example.com/podcast.xml", feed_type="podcast")
    db_session.add(feed)
    await db_session.flush()

    entry = Entry(
        feed_id=feed.id,
        guid="ep-001",
        title="Episode 1",
        url="https://example.com/ep1",
    )
    db_session.add(entry)
    await db_session.flush()

    media = EntryMedia(
        entry_id=entry.id,
        media_type="audio",
        url="https://cdn.example.com/ep1.mp3",
        mime_type="audio/mpeg",
        file_size=50000000,
        duration_seconds=3600,
        thumbnail_url="https://example.com/artwork.jpg",
    )
    db_session.add(media)
    await db_session.flush()

    return feed, entry, media


@pytest.mark.asyncio
async def test_entry_list_includes_media(client: AsyncClient, auth_headers: dict, feed_with_media):
    """Entry list responses should include media attachments."""
    _, entry, media = feed_with_media
    response = await client.get("/api/entries", headers=auth_headers)
    assert response.status_code == 200
    items = response.json()["items"]
    assert len(items) > 0
    item = next(i for i in items if i["id"] == str(entry.id))
    assert len(item["media"]) == 1
    assert item["media"][0]["media_type"] == "audio"
    assert item["media"][0]["duration_seconds"] == 3600


@pytest.mark.asyncio
async def test_entry_detail_includes_media(client: AsyncClient, auth_headers: dict, feed_with_media):
    """Entry detail response should include media attachments."""
    _, entry, media = feed_with_media
    response = await client.get(f"/api/entries/{entry.id}", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["feed_type"] == "podcast"
    assert len(data["media"]) == 1


@pytest.mark.asyncio
async def test_entry_includes_feed_type(client: AsyncClient, auth_headers: dict, feed_with_media):
    """Entry responses should include feed_type."""
    response = await client.get("/api/entries", headers=auth_headers)
    items = response.json()["items"]
    assert items[0]["feed_type"] == "podcast"
