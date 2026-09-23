"""Tests for the podcasts API (/api/podcasts)."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.entry import Entry
from app.models.entry_media import EntryMedia
from app.models.feed import Feed
from app.models.playback_progress import PlaybackProgress
from app.models.podcast import Podcast
from app.models.user import User

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def podcast_feed(db_session: AsyncSession) -> Feed:
    """Create a bare podcast-type feed (no subscription)."""
    feed = Feed(
        title="Security Weekly",
        url="https://example.com/security-weekly.xml",
        feed_type="podcast",
        description="Weekly security podcast covering threats and defenses.",
    )
    db_session.add(feed)
    await db_session.flush()
    return feed


@pytest_asyncio.fixture
async def podcast_metadata(db_session: AsyncSession, podcast_feed: Feed) -> Podcast:
    """Create the Podcast metadata row linked to the podcast feed."""
    podcast = Podcast(
        feed_id=podcast_feed.id,
        author="SecOps Team",
        categories=["Technology", "Security"],
        is_explicit=False,
        podcast_type="episodic",
        artwork_url="https://example.com/artwork.jpg",
    )
    db_session.add(podcast)
    await db_session.flush()
    return podcast


@pytest_asyncio.fixture
async def podcast_subscription(podcast_feed: Feed) -> Feed:
    """Return the podcast feed directly (all feeds visible to all users)."""
    return podcast_feed


@pytest_asyncio.fixture
async def podcast_episodes(db_session: AsyncSession, podcast_feed: Feed) -> list[tuple[Entry, EntryMedia]]:
    """Create 5 podcast episodes with audio media, published at staggered times."""
    now = datetime.now(UTC)
    episodes: list[tuple[Entry, EntryMedia]] = []
    for i in range(5):
        entry = Entry(
            feed_id=podcast_feed.id,
            guid=f"ep-{i + 1:03d}",
            title=f"Episode {i + 1}: Topic {i + 1}",
            url=f"https://example.com/ep{i + 1}",
            author="SecOps Team",
            summary=f"Summary of episode {i + 1}.",
            published_at=now - timedelta(days=i),
        )
        db_session.add(entry)
        await db_session.flush()

        media = EntryMedia(
            entry_id=entry.id,
            media_type="audio",
            url=f"https://cdn.example.com/ep{i + 1}.mp3",
            mime_type="audio/mpeg",
            file_size=50_000_000 + i * 1_000_000,
            duration_seconds=1800 + i * 300,
            thumbnail_url=f"https://example.com/ep{i + 1}_thumb.jpg",
        )
        db_session.add(media)
        await db_session.flush()

        episodes.append((entry, media))
    return episodes


@pytest_asyncio.fixture
async def rss_feed(db_session: AsyncSession) -> Feed:
    """Create a regular RSS feed (non-podcast)."""
    feed = Feed(
        title="Security Blog",
        url="https://example.com/blog/feed.xml",
        feed_type="rss",
        description="A security blog.",
    )
    db_session.add(feed)
    await db_session.flush()
    return feed


@pytest_asyncio.fixture
async def other_user(db_session: AsyncSession) -> User:
    """Create a second user for isolation tests."""
    user = User(
        username="otheruser",
        password_hash=hash_password("otherpassword"),
        role="user",
    )
    db_session.add(user)
    await db_session.flush()
    return user


@pytest_asyncio.fixture
async def other_user_headers(other_user: User) -> dict:
    """Auth headers for the other user."""
    token = create_access_token(other_user.id, other_user.role)
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture
async def other_user_podcast(db_session: AsyncSession, other_user: User) -> tuple[Feed, Podcast]:
    """Create a podcast feed owned by the other user."""
    feed = Feed(
        title="Other Podcast",
        url="https://example.com/other-podcast.xml",
        feed_type="podcast",
        description="Another podcast feed.",
    )
    db_session.add(feed)
    await db_session.flush()

    podcast = Podcast(
        feed_id=feed.id,
        author="Other Author",
        categories=["News"],
        is_explicit=True,
        podcast_type="serial",
        artwork_url="https://example.com/other-artwork.jpg",
    )
    db_session.add(podcast)
    await db_session.flush()

    return feed, podcast


# ---------------------------------------------------------------------------
# GET /api/podcasts  —  List podcast subscriptions
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_podcasts_empty(client: AsyncClient, auth_headers: dict, test_user: User):
    """Listing podcasts when the user has no podcast subscriptions returns an empty list."""
    response = await client.get("/api/podcasts", headers=auth_headers)
    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.asyncio
async def test_list_podcasts_with_data(
    client: AsyncClient,
    auth_headers: dict,
    podcast_feed: Feed,
    podcast_metadata: Podcast,
    podcast_subscription: Feed,
    podcast_episodes: list[tuple[Entry, EntryMedia]],
):
    """Listing podcasts returns podcast details with correct episode count."""
    response = await client.get("/api/podcasts", headers=auth_headers)
    assert response.status_code == 200

    data = response.json()
    assert len(data) == 1

    podcast = data[0]
    assert podcast["feed_id"] == str(podcast_feed.id)
    assert podcast["feed_title"] == "Security Weekly"
    assert podcast["feed_url"] == "https://example.com/security-weekly.xml"
    assert podcast["description"] == "Weekly security podcast covering threats and defenses."
    assert podcast["author"] == "SecOps Team"
    assert podcast["categories"] == ["Technology", "Security"]
    assert podcast["is_explicit"] is False
    assert podcast["podcast_type"] == "episodic"
    assert podcast["artwork_url"] == "https://example.com/artwork.jpg"
    assert podcast["episode_count"] == 5


@pytest.mark.asyncio
async def test_list_podcasts_excludes_rss_feeds(
    client: AsyncClient,
    auth_headers: dict,
    rss_feed: Feed,
    podcast_feed: Feed,
    podcast_metadata: Podcast,
    podcast_subscription: Feed,
):
    """Listing podcasts should only include podcast-type feeds, not regular RSS feeds."""
    response = await client.get("/api/podcasts", headers=auth_headers)
    assert response.status_code == 200

    data = response.json()
    feed_ids = [p["feed_id"] for p in data]
    assert str(podcast_feed.id) in feed_ids
    assert str(rss_feed.id) not in feed_ids


@pytest.mark.asyncio
async def test_list_podcasts_shows_all_podcasts(
    client: AsyncClient,
    auth_headers: dict,
    other_user_podcast: tuple[Feed, Podcast],
):
    """All podcast feeds are visible to all authenticated users."""
    response = await client.get("/api/podcasts", headers=auth_headers)
    assert response.status_code == 200

    other_feed, _ = other_user_podcast
    feed_ids = [p["feed_id"] for p in response.json()]
    assert str(other_feed.id) in feed_ids


@pytest.mark.asyncio
async def test_list_podcasts_other_user_sees_all(
    client: AsyncClient,
    other_user_headers: dict,
    other_user_podcast: tuple[Feed, Podcast],
    podcast_feed: Feed,
    podcast_metadata: Podcast,
    podcast_subscription: Feed,
):
    """All authenticated users see all podcast feeds."""
    response = await client.get("/api/podcasts", headers=other_user_headers)
    assert response.status_code == 200

    data = response.json()
    assert len(data) == 2
    feed_ids = {p["feed_id"] for p in data}
    assert str(other_user_podcast[0].id) in feed_ids
    assert str(podcast_feed.id) in feed_ids


@pytest.mark.asyncio
async def test_list_podcasts_no_auth(client: AsyncClient):
    """Listing podcasts without authentication should return 401/403."""
    response = await client.get("/api/podcasts")
    assert response.status_code in (401, 403)


# ---------------------------------------------------------------------------
# GET /api/podcasts/{feed_id}  —  Get podcast show details
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_podcast_detail(
    client: AsyncClient,
    auth_headers: dict,
    podcast_feed: Feed,
    podcast_metadata: Podcast,
    podcast_subscription: Feed,
    podcast_episodes: list[tuple[Entry, EntryMedia]],
):
    """Getting a podcast by feed_id returns full show details."""
    response = await client.get(f"/api/podcasts/{podcast_feed.id}", headers=auth_headers)
    assert response.status_code == 200

    data = response.json()
    assert data["id"] == str(podcast_metadata.id)
    assert data["feed_id"] == str(podcast_feed.id)
    assert data["feed_title"] == "Security Weekly"
    assert data["feed_url"] == "https://example.com/security-weekly.xml"
    assert data["description"] == "Weekly security podcast covering threats and defenses."
    assert data["author"] == "SecOps Team"
    assert data["categories"] == ["Technology", "Security"]
    assert data["is_explicit"] is False
    assert data["podcast_type"] == "episodic"
    assert data["artwork_url"] == "https://example.com/artwork.jpg"
    assert data["episode_count"] == 5
    assert "created_at" in data


@pytest.mark.asyncio
async def test_get_podcast_not_found(client: AsyncClient, auth_headers: dict):
    """Getting a podcast with a non-existent feed_id returns 404."""
    fake_id = uuid.uuid4()
    response = await client.get(f"/api/podcasts/{fake_id}", headers=auth_headers)
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_get_podcast_non_podcast_feed(client: AsyncClient, auth_headers: dict, rss_feed: Feed):
    """Getting details for a subscribed RSS feed (non-podcast) returns 404
    because there is no Podcast metadata row for it."""
    response = await client.get(f"/api/podcasts/{rss_feed.id}", headers=auth_headers)
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_get_podcast_any_user_can_access(
    client: AsyncClient,
    auth_headers: dict,
    other_user_podcast: tuple[Feed, Podcast],
):
    """Any authenticated user can access any podcast's details."""
    other_feed, _ = other_user_podcast
    response = await client.get(f"/api/podcasts/{other_feed.id}", headers=auth_headers)
    assert response.status_code == 200
    assert response.json()["feed_title"] == "Other Podcast"


@pytest.mark.asyncio
async def test_get_podcast_no_auth(client: AsyncClient, podcast_feed: Feed):
    """Getting podcast details without authentication should return 401/403."""
    response = await client.get(f"/api/podcasts/{podcast_feed.id}")
    assert response.status_code in (401, 403)


@pytest.mark.asyncio
async def test_get_podcast_episode_count_zero(
    client: AsyncClient,
    auth_headers: dict,
    podcast_feed: Feed,
    podcast_metadata: Podcast,
    podcast_subscription: Feed,
):
    """A podcast with no entries should report episode_count=0."""
    response = await client.get(f"/api/podcasts/{podcast_feed.id}", headers=auth_headers)
    assert response.status_code == 200
    assert response.json()["episode_count"] == 0


# ---------------------------------------------------------------------------
# GET /api/podcasts/{feed_id}/episodes  —  List podcast episodes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_episodes(
    client: AsyncClient,
    auth_headers: dict,
    podcast_feed: Feed,
    podcast_metadata: Podcast,
    podcast_subscription: Feed,
    podcast_episodes: list[tuple[Entry, EntryMedia]],
):
    """Listing episodes returns all episodes with media info, sorted by published_at desc."""
    response = await client.get(f"/api/podcasts/{podcast_feed.id}/episodes", headers=auth_headers)
    assert response.status_code == 200

    data = response.json()
    assert len(data) == 5

    # Verify descending order by published_at (most recent first)
    for i in range(len(data) - 1):
        if data[i]["published_at"] and data[i + 1]["published_at"]:
            assert data[i]["published_at"] >= data[i + 1]["published_at"]

    # Verify first episode (most recent) has correct data
    ep = data[0]
    assert ep["title"] == "Episode 1: Topic 1"
    assert ep["feed_id"] == str(podcast_feed.id)
    assert ep["author"] == "SecOps Team"
    assert ep["summary"] == "Summary of episode 1."
    assert ep["media_url"] == "https://cdn.example.com/ep1.mp3"
    assert ep["media_id"] is not None
    assert ep["duration_seconds"] == 1800
    assert ep["thumbnail_url"] == "https://example.com/ep1_thumb.jpg"
    assert ep["position_seconds"] == 0
    assert ep["is_completed"] is False


@pytest.mark.asyncio
async def test_list_episodes_empty(
    client: AsyncClient,
    auth_headers: dict,
    podcast_feed: Feed,
    podcast_metadata: Podcast,
    podcast_subscription: Feed,
):
    """Listing episodes for a podcast with no entries returns an empty list."""
    response = await client.get(f"/api/podcasts/{podcast_feed.id}/episodes", headers=auth_headers)
    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.asyncio
async def test_list_episodes_pagination_limit(
    client: AsyncClient,
    auth_headers: dict,
    podcast_feed: Feed,
    podcast_metadata: Podcast,
    podcast_subscription: Feed,
    podcast_episodes: list[tuple[Entry, EntryMedia]],
):
    """Limiting episode results with the limit parameter."""
    response = await client.get(
        f"/api/podcasts/{podcast_feed.id}/episodes",
        params={"limit": 2},
        headers=auth_headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2
    # Should be the 2 most recent episodes
    assert data[0]["title"] == "Episode 1: Topic 1"
    assert data[1]["title"] == "Episode 2: Topic 2"


@pytest.mark.asyncio
async def test_list_episodes_pagination_offset(
    client: AsyncClient,
    auth_headers: dict,
    podcast_feed: Feed,
    podcast_metadata: Podcast,
    podcast_subscription: Feed,
    podcast_episodes: list[tuple[Entry, EntryMedia]],
):
    """Offsetting episode results skips earlier items."""
    response = await client.get(
        f"/api/podcasts/{podcast_feed.id}/episodes",
        params={"limit": 2, "offset": 2},
        headers=auth_headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2
    # Episodes are sorted desc by published_at; offset=2 skips the first two
    assert data[0]["title"] == "Episode 3: Topic 3"
    assert data[1]["title"] == "Episode 4: Topic 4"


@pytest.mark.asyncio
async def test_list_episodes_pagination_offset_past_end(
    client: AsyncClient,
    auth_headers: dict,
    podcast_feed: Feed,
    podcast_metadata: Podcast,
    podcast_subscription: Feed,
    podcast_episodes: list[tuple[Entry, EntryMedia]],
):
    """Offset beyond the number of episodes returns an empty list."""
    response = await client.get(
        f"/api/podcasts/{podcast_feed.id}/episodes",
        params={"offset": 100},
        headers=auth_headers,
    )
    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.asyncio
async def test_list_episodes_with_playback_progress(
    db_session: AsyncSession,
    client: AsyncClient,
    auth_headers: dict,
    test_user: User,
    podcast_feed: Feed,
    podcast_metadata: Podcast,
    podcast_subscription: Feed,
    podcast_episodes: list[tuple[Entry, EntryMedia]],
):
    """Episodes should include playback progress when present for the user."""
    # Set playback progress on the first episode
    entry, media = podcast_episodes[0]
    progress = PlaybackProgress(
        user_id=test_user.id,
        entry_media_id=media.id,
        position_seconds=450,
        is_completed=False,
    )
    db_session.add(progress)
    await db_session.flush()

    # Mark second episode as completed
    entry2, media2 = podcast_episodes[1]
    progress2 = PlaybackProgress(
        user_id=test_user.id,
        entry_media_id=media2.id,
        position_seconds=2100,
        is_completed=True,
    )
    db_session.add(progress2)
    await db_session.flush()

    response = await client.get(f"/api/podcasts/{podcast_feed.id}/episodes", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()

    # Find the episodes by title
    ep1 = next(e for e in data if e["title"] == "Episode 1: Topic 1")
    ep2 = next(e for e in data if e["title"] == "Episode 2: Topic 2")
    ep3 = next(e for e in data if e["title"] == "Episode 3: Topic 3")

    assert ep1["position_seconds"] == 450
    assert ep1["is_completed"] is False

    assert ep2["position_seconds"] == 2100
    assert ep2["is_completed"] is True

    # Episode without progress should default to 0 / False
    assert ep3["position_seconds"] == 0
    assert ep3["is_completed"] is False


@pytest.mark.asyncio
async def test_list_episodes_any_user_can_access(
    client: AsyncClient,
    auth_headers: dict,
    other_user_podcast: tuple[Feed, Podcast],
):
    """Any authenticated user can list episodes for any podcast."""
    other_feed, _ = other_user_podcast
    response = await client.get(f"/api/podcasts/{other_feed.id}/episodes", headers=auth_headers)
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_list_episodes_nonexistent_feed(client: AsyncClient, auth_headers: dict):
    """Listing episodes for a non-existent feed returns 404."""
    fake_id = uuid.uuid4()
    response = await client.get(f"/api/podcasts/{fake_id}/episodes", headers=auth_headers)
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_list_episodes_no_auth(client: AsyncClient, podcast_feed: Feed):
    """Listing episodes without authentication should return 401/403."""
    response = await client.get(f"/api/podcasts/{podcast_feed.id}/episodes")
    assert response.status_code in (401, 403)


@pytest.mark.asyncio
async def test_list_episodes_entry_without_media(
    db_session: AsyncSession,
    client: AsyncClient,
    auth_headers: dict,
    podcast_feed: Feed,
    podcast_metadata: Podcast,
    podcast_subscription: Feed,
):
    """An episode entry without any media attachment should still appear,
    with media fields set to None and defaults for progress."""
    entry = Entry(
        feed_id=podcast_feed.id,
        guid="no-media-ep",
        title="No Media Episode",
        url="https://example.com/no-media",
        published_at=datetime.now(UTC),
    )
    db_session.add(entry)
    await db_session.flush()

    response = await client.get(f"/api/podcasts/{podcast_feed.id}/episodes", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1

    ep = data[0]
    assert ep["title"] == "No Media Episode"
    assert ep["media_url"] is None
    assert ep["media_id"] is None
    assert ep["duration_seconds"] is None
    assert ep["thumbnail_url"] is None
    assert ep["position_seconds"] == 0
    assert ep["is_completed"] is False


@pytest.mark.asyncio
async def test_list_episodes_playback_isolation(
    db_session: AsyncSession,
    client: AsyncClient,
    auth_headers: dict,
    other_user: User,
    test_user: User,
    podcast_feed: Feed,
    podcast_metadata: Podcast,
    podcast_subscription: Feed,
    podcast_episodes: list[tuple[Entry, EntryMedia]],
):
    """Playback progress from another user should not leak into the current
    user's episode listing."""
    # Set playback progress for the OTHER user
    _, media = podcast_episodes[0]
    other_progress = PlaybackProgress(
        user_id=other_user.id,
        entry_media_id=media.id,
        position_seconds=999,
        is_completed=True,
    )
    db_session.add(other_progress)
    await db_session.flush()

    # Test user should see 0 progress (not the other user's progress)
    response = await client.get(f"/api/podcasts/{podcast_feed.id}/episodes", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    ep1 = next(e for e in data if e["title"] == "Episode 1: Topic 1")
    assert ep1["position_seconds"] == 0
    assert ep1["is_completed"] is False
