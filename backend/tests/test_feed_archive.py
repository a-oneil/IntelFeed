"""A deleted feed is archived: off every list, its articles kept as evidence."""

from datetime import UTC, datetime

import pytest
from sqlalchemy import select

from app.config import settings as env_settings
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.user_feed_subscription import UserFeedSubscription
from app.search.query_parser import parse_query
from app.search.query_planner import build_execution_plan, resolve_deferred_filters
from app.tools.feeds_automation import _delete_feed


@pytest.fixture
def subscriptions_on(monkeypatch):
    monkeypatch.setattr(env_settings, "per_user_subscriptions_enabled", True)


async def _feed_with_evidence(db_session, *readers):
    feed = Feed(title="Gone Feed", url="https://gone.example/rss", feed_type="rss")
    actor = ThreatActor(name="UNC5337")
    db_session.add_all([feed, actor])
    await db_session.flush()
    entry = Entry(feed_id=feed.id, title="Ivanti zero-day", guid="gone-1", published_at=datetime.now(UTC))
    db_session.add(entry)
    await db_session.flush()
    db_session.add(EntryThreatActor(entry_id=entry.id, threat_actor_id=actor.id, source="ai"))
    for user in readers:
        db_session.add(UserFeedSubscription(user_id=user.id, feed_id=feed.id))
    await db_session.commit()
    return feed, actor, entry


async def _entry_ids(client, headers, **params):
    resp = await client.get("/api/entries", params=params, headers=headers)
    assert resp.status_code == 200, resp.text
    return [e["id"] for e in resp.json()["items"]]


async def test_a_deleted_feed_leaves_the_lists_but_its_articles_stay_evidence(
    client, admin_headers, admin_user, db_session, subscriptions_on
):
    feed, actor, entry = await _feed_with_evidence(db_session, admin_user)

    assert (await client.delete(f"/api/feeds/{feed.id}?purge=true", headers=admin_headers)).status_code == 204
    await db_session.refresh(feed)
    assert feed.archived_at is not None and feed.is_active is False
    assert await db_session.get(Entry, entry.id) is not None

    assert (await client.get("/api/feeds", headers=admin_headers)).json()["total"] == 0
    assert str(entry.id) not in await _entry_ids(client, admin_headers)
    evidence = await _entry_ids(client, admin_headers, entity_type="threat_actor", entity_id=str(actor.id))
    assert evidence == [str(entry.id)]


async def test_adding_a_deleted_feed_again_brings_it_back(
    client, auth_headers, test_user, db_session, subscriptions_on
):
    feed, _, entry = await _feed_with_evidence(db_session, test_user)
    assert (await client.delete(f"/api/feeds/{feed.id}", headers=auth_headers)).status_code == 204
    await db_session.refresh(feed)
    assert feed.archived_at is not None  # its last reader left

    resp = await client.post("/api/feeds", json={"url": feed.url}, headers=auth_headers)
    assert resp.status_code == 201, resp.text
    await db_session.refresh(feed)
    assert feed.archived_at is None and feed.is_active is True
    assert str(entry.id) in await _entry_ids(client, auth_headers)


async def test_the_delete_feed_tool_archives(db_session, admin_user):
    feed, _, entry = await _feed_with_evidence(db_session, admin_user)
    prompt = await _delete_feed(db_session, admin_user.id, str(feed.id))
    done = await _delete_feed(db_session, admin_user.id, str(feed.id), prompt["confirmation_token"])
    assert done["status"] == "deleted"
    await db_session.refresh(feed)
    assert feed.archived_at is not None
    assert await db_session.get(Entry, entry.id) is not None
    left = await db_session.execute(select(UserFeedSubscription).where(UserFeedSubscription.feed_id == feed.id))
    assert left.scalars().all() == []


async def test_search_leaves_archived_feeds_out_unless_asked(db_session):
    gone = Feed(title="Gone", url="https://gone2.example/rss", feed_type="rss", archived_at=datetime.now(UTC))
    db_session.add(gone)
    await db_session.flush()

    plan = build_execution_plan(parse_query("ivanti"))
    await resolve_deferred_filters(db_session, plan)
    assert f'feed_id NOT IN ["{gone.id}"]' in plan.meili_filters

    plan = build_execution_plan(parse_query("ivanti is:archived"))
    await resolve_deferred_filters(db_session, plan)
    assert f'feed_id = "{gone.id}"' in plan.meili_filters
    assert not any("NOT IN" in f for f in plan.meili_filters)
