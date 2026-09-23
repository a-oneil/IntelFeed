"""Per-user feed subscriptions (per_user_subscriptions_enabled flag)."""

from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings as env_settings
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.user import User
from app.models.user_feed_subscription import UserFeedSubscription


@pytest.fixture
def subscriptions_on(monkeypatch):
    monkeypatch.setattr(env_settings, "per_user_subscriptions_enabled", True)


async def _make_feed(db: AsyncSession, url: str, title: str = "Feed", **kwargs) -> Feed:
    feed = Feed(title=title, url=url, feed_type="rss", **kwargs)
    db.add(feed)
    await db.flush()
    return feed


async def _subscribe(db: AsyncSession, user: User, feed: Feed, is_muted: bool = False) -> None:
    db.add(UserFeedSubscription(user_id=user.id, feed_id=feed.id, is_muted=is_muted))
    await db.flush()


@pytest.mark.asyncio
async def test_flag_off_lists_all_feeds(client: AsyncClient, auth_headers: dict, db_session: AsyncSession):
    await _make_feed(db_session, "https://a.example/feed", "A")
    await _make_feed(db_session, "https://b.example/feed", "B")

    resp = await client.get("/api/feeds", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 2
    assert all(item["per_user"] is False for item in data["items"])


@pytest.mark.asyncio
async def test_flag_on_lists_only_subscribed(
    client: AsyncClient, auth_headers: dict, test_user: User, db_session: AsyncSession, subscriptions_on
):
    feed_a = await _make_feed(db_session, "https://a.example/feed", "A")
    await _make_feed(db_session, "https://b.example/feed", "B")
    await _subscribe(db_session, test_user, feed_a)

    resp = await client.get("/api/feeds", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert data["items"][0]["title"] == "A"
    assert data["items"][0]["per_user"] is True


@pytest.mark.asyncio
async def test_flag_on_mute_is_personal(
    client: AsyncClient,
    auth_headers: dict,
    admin_headers: dict,
    test_user: User,
    admin_user: User,
    db_session: AsyncSession,
    subscriptions_on,
):
    feed = await _make_feed(db_session, "https://a.example/feed", "A")
    await _subscribe(db_session, test_user, feed)
    await _subscribe(db_session, admin_user, feed)

    resp = await client.put(f"/api/feeds/{feed.id}", json={"is_muted": True}, headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["is_muted"] is True

    # The other subscriber is unaffected, and so is the shared column
    resp = await client.get(f"/api/feeds/{feed.id}", headers=admin_headers)
    assert resp.json()["is_muted"] is False
    await db_session.refresh(feed)
    assert feed.is_muted is False


@pytest.mark.asyncio
async def test_flag_on_muted_feed_leaves_all_feeds_view(
    client: AsyncClient, auth_headers: dict, test_user: User, db_session: AsyncSession, subscriptions_on
):
    feed = await _make_feed(db_session, "https://a.example/feed", "A")
    await _subscribe(db_session, test_user, feed, is_muted=True)
    db_session.add(
        Entry(
            feed_id=feed.id,
            title="hidden by mute",
            url="https://a.example/1",
            guid="a-1",
            published_at=datetime.now(UTC),
        )
    )
    await db_session.flush()

    resp = await client.get("/api/entries", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["items"] == []

    # But the feed-scoped view still shows it (mute hides from aggregation only)
    resp = await client.get(f"/api/entries?feed_id={feed.id}", headers=auth_headers)
    assert len(resp.json()["items"]) == 1


@pytest.mark.asyncio
async def test_flag_on_entries_exclude_unsubscribed_feeds(
    client: AsyncClient, auth_headers: dict, test_user: User, db_session: AsyncSession, subscriptions_on
):
    mine = await _make_feed(db_session, "https://mine.example/feed", "Mine")
    other = await _make_feed(db_session, "https://other.example/feed", "Other")
    await _subscribe(db_session, test_user, mine)
    for feed, guid in ((mine, "m-1"), (other, "o-1")):
        db_session.add(
            Entry(
                feed_id=feed.id,
                title=guid,
                url=f"https://x.example/{guid}",
                guid=guid,
                published_at=datetime.now(UTC),
            )
        )
    await db_session.flush()

    resp = await client.get("/api/entries", headers=auth_headers)
    titles = [i["title"] for i in resp.json()["items"]]
    assert titles == ["m-1"]


@pytest.mark.asyncio
async def test_flag_on_unsubscribe_keeps_feed_for_others(
    client: AsyncClient,
    auth_headers: dict,
    test_user: User,
    admin_user: User,
    db_session: AsyncSession,
    subscriptions_on,
):
    feed = await _make_feed(db_session, "https://a.example/feed", "A")
    await _subscribe(db_session, test_user, feed)
    await _subscribe(db_session, admin_user, feed)

    resp = await client.delete(f"/api/feeds/{feed.id}", headers=auth_headers)
    assert resp.status_code == 204

    await db_session.refresh(feed)
    assert feed.is_active is True  # someone still reads it
    remaining = (
        (await db_session.execute(select(UserFeedSubscription).where(UserFeedSubscription.feed_id == feed.id)))
        .scalars()
        .all()
    )
    assert [s.user_id for s in remaining] == [admin_user.id]


@pytest.mark.asyncio
async def test_flag_on_last_unsubscribe_deactivates_feed(
    client: AsyncClient, auth_headers: dict, test_user: User, db_session: AsyncSession, subscriptions_on
):
    feed = await _make_feed(db_session, "https://a.example/feed", "A")
    await _subscribe(db_session, test_user, feed)

    resp = await client.delete(f"/api/feeds/{feed.id}", headers=auth_headers)
    assert resp.status_code == 204

    await db_session.refresh(feed)
    assert feed.is_active is False  # nobody reads it — stop fetching, keep entries


@pytest.mark.asyncio
async def test_flag_on_purge_is_admin_only(
    client: AsyncClient,
    auth_headers: dict,
    admin_headers: dict,
    test_user: User,
    db_session: AsyncSession,
    subscriptions_on,
):
    feed = await _make_feed(db_session, "https://a.example/feed", "A")
    await _subscribe(db_session, test_user, feed)

    resp = await client.delete(f"/api/feeds/{feed.id}?purge=true", headers=auth_headers)
    assert resp.status_code == 403

    resp = await client.delete(f"/api/feeds/{feed.id}?purge=true", headers=admin_headers)
    assert resp.status_code == 204
    assert await db_session.get(Feed, feed.id) is None


@pytest.mark.asyncio
async def test_flag_on_adding_existing_url_subscribes(
    client: AsyncClient,
    auth_headers: dict,
    test_user: User,
    admin_user: User,
    db_session: AsyncSession,
    subscriptions_on,
):
    feed = await _make_feed(db_session, "https://a.example/feed", "A")
    await _subscribe(db_session, admin_user, feed)

    resp = await client.post("/api/feeds", json={"url": "https://a.example/feed"}, headers=auth_headers)
    assert resp.status_code == 201
    assert resp.json()["per_user"] is True

    sub = (
        await db_session.execute(
            select(UserFeedSubscription).where(
                UserFeedSubscription.user_id == test_user.id,
                UserFeedSubscription.feed_id == feed.id,
            )
        )
    ).scalar_one_or_none()
    assert sub is not None

    # Subscribing twice is a conflict
    resp = await client.post("/api/feeds", json={"url": "https://a.example/feed"}, headers=auth_headers)
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_first_registered_user_is_admin(client: AsyncClient, db_session: AsyncSession):
    resp = await client.post("/api/auth/register", json={"username": "founder", "password": "hunter22"})
    assert resp.status_code == 201
    founder = (await db_session.execute(select(User).where(User.username == "founder"))).scalar_one()
    assert founder.role == "admin"

    resp = await client.post("/api/auth/register", json={"username": "second", "password": "hunter22"})
    assert resp.status_code == 201
    second = (await db_session.execute(select(User).where(User.username == "second"))).scalar_one()
    assert second.role == "user"


@pytest.mark.asyncio
async def test_register_seeds_subscriptions_from_earliest_admin(
    client: AsyncClient, admin_user: User, db_session: AsyncSession
):
    feed_a = await _make_feed(db_session, "https://a.example/feed", "A")
    feed_b = await _make_feed(db_session, "https://b.example/feed", "B")
    await _subscribe(db_session, admin_user, feed_a, is_muted=True)
    await _subscribe(db_session, admin_user, feed_b)

    resp = await client.post("/api/auth/register", json={"username": "newbie", "password": "hunter22"})
    assert resp.status_code == 201

    newbie = (await db_session.execute(select(User).where(User.username == "newbie"))).scalar_one()
    subs = {
        s.feed_id: s.is_muted
        for s in (
            await db_session.execute(select(UserFeedSubscription).where(UserFeedSubscription.user_id == newbie.id))
        )
        .scalars()
        .all()
    }
    assert subs == {feed_a.id: True, feed_b.id: False}
