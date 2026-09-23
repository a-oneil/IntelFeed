"""Tests for playback progress tracking API."""

import uuid

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.entry import Entry
from app.models.entry_media import EntryMedia
from app.models.feed import Feed


@pytest_asyncio.fixture
async def podcast_media(db_session: AsyncSession, test_user):
    """Create a podcast feed with an episode that has audio media."""
    feed = Feed(title="Playback Test Podcast", url="https://example.com/playback.xml", feed_type="podcast")
    db_session.add(feed)
    await db_session.flush()

    entry = Entry(
        feed_id=feed.id,
        guid="playback-ep-001",
        title="Playback Episode",
        url="https://example.com/playback-ep1",
    )
    db_session.add(entry)
    await db_session.flush()

    media = EntryMedia(
        entry_id=entry.id,
        media_type="audio",
        url="https://cdn.example.com/playback-ep1.mp3",
        mime_type="audio/mpeg",
        duration_seconds=1800,
    )
    db_session.add(media)
    await db_session.flush()

    return feed, entry, media


@pytest.mark.asyncio
async def test_update_playback_progress(client: AsyncClient, auth_headers: dict, podcast_media):
    """Should create/update playback progress."""
    _, _, media = podcast_media
    response = await client.put(
        f"/api/playback/{media.id}/progress",
        json={"position_seconds": 300},
        headers=auth_headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["position_seconds"] == 300
    assert data["is_completed"] is False


@pytest.mark.asyncio
async def test_get_playback_progress(client: AsyncClient, auth_headers: dict, podcast_media):
    """Should retrieve playback progress after setting it."""
    _, _, media = podcast_media
    # First set progress
    await client.put(
        f"/api/playback/{media.id}/progress",
        json={"position_seconds": 600},
        headers=auth_headers,
    )
    # Then get it
    response = await client.get(
        f"/api/playback/{media.id}/progress",
        headers=auth_headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["position_seconds"] == 600


@pytest.mark.asyncio
async def test_mark_complete(client: AsyncClient, auth_headers: dict, podcast_media):
    """Should mark media as completed."""
    _, _, media = podcast_media
    response = await client.put(
        f"/api/playback/{media.id}/complete",
        headers=auth_headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["is_completed"] is True


@pytest.mark.asyncio
async def test_in_progress_list(client: AsyncClient, auth_headers: dict, podcast_media):
    """Should list in-progress media items."""
    _, _, media = podcast_media
    # Set some progress
    await client.put(
        f"/api/playback/{media.id}/progress",
        json={"position_seconds": 450},
        headers=auth_headers,
    )
    response = await client.get("/api/playback/in-progress", headers=auth_headers)
    assert response.status_code == 200
    items = response.json()
    assert len(items) >= 1
    assert items[0]["position_seconds"] == 450


@pytest.mark.asyncio
async def test_completed_not_in_progress(client: AsyncClient, auth_headers: dict, podcast_media):
    """Completed items should not appear in in-progress list."""
    _, _, media = podcast_media
    # Set progress then mark complete
    await client.put(
        f"/api/playback/{media.id}/progress",
        json={"position_seconds": 1800},
        headers=auth_headers,
    )
    await client.put(f"/api/playback/{media.id}/complete", headers=auth_headers)

    response = await client.get("/api/playback/in-progress", headers=auth_headers)
    items = response.json()
    media_ids = [i["entry_media_id"] for i in items]
    assert str(media.id) not in media_ids


@pytest.mark.asyncio
async def test_progress_not_found_media(client: AsyncClient, auth_headers: dict):
    """Should return 404 for non-existent media."""
    fake_id = str(uuid.uuid4())
    response = await client.put(
        f"/api/playback/{fake_id}/progress",
        json={"position_seconds": 100},
        headers=auth_headers,
    )
    assert response.status_code == 404
