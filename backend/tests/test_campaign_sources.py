"""Campaign sources — intake that follows the campaign's own curation.

A linked saved search is a query kept alongside the campaign and drifts from it.
These tests pin the two alternatives: following the entity a campaign names, and
following a story it already holds part of.
"""

import uuid
from datetime import UTC, datetime

import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.campaign import Campaign, CampaignEntity, CampaignEntry
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.story_thread import StoryThread, StoryThreadEntry
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.user import User


@pytest_asyncio.fixture
async def user(db_session: AsyncSession) -> User:
    u = User(username="campaign_sources_user", password_hash=hash_password("pw"), role="user")
    db_session.add(u)
    await db_session.flush()
    return u


@pytest_asyncio.fixture
async def headers(user: User) -> dict:
    return {"Authorization": f"Bearer {create_access_token(user.id, user.role)}"}


@pytest_asyncio.fixture
async def feed(db_session: AsyncSession) -> Feed:
    f = Feed(title="Sources Feed", url="https://sources.example.com/feed", feed_type="rss")
    db_session.add(f)
    await db_session.flush()
    return f


@pytest_asyncio.fixture
async def campaign(db_session: AsyncSession, user: User) -> Campaign:
    c = Campaign(created_by=user.id, name="Sources Campaign", status="active")
    db_session.add(c)
    await db_session.flush()
    return c


async def _entry(db_session: AsyncSession, feed: Feed, guid: str, day: int = 1) -> Entry:
    e = Entry(feed_id=feed.id, title=f"Article {guid}", guid=guid, published_at=datetime(2026, 3, day, tzinfo=UTC))
    db_session.add(e)
    await db_session.flush()
    return e


# ── Following a story ────────────────────────────────────────────────


async def test_following_a_story_pulls_in_the_waves_you_have_not_accepted(
    client: AsyncClient, headers: dict, db_session: AsyncSession, feed: Feed, campaign: Campaign, user: User
):
    """The case a saved search cannot express: you accepted this story, so its
    later waves belong too — without re-accepting a suggestion every time."""
    thread = StoryThread(slug="a-running-story", title="A running story", status="open", entry_count=4, source_count=3)
    db_session.add(thread)
    await db_session.flush()

    entries = [await _entry(db_session, feed, f"story-{i}", day=i + 1) for i in range(4)]
    for e in entries:
        db_session.add(StoryThreadEntry(thread_id=thread.id, entry_id=e.id, role="beat"))
    # The campaign already holds the first article.
    db_session.add(CampaignEntry(campaign_id=campaign.id, entry_id=entries[0].id, added_by=user.id))
    await db_session.flush()

    resp = await client.post(
        f"/api/campaigns/{campaign.id}/sources",
        json={"kind": "story", "ref_id": str(thread.id)},
        headers=headers,
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["label"] == "A running story"
    assert body["entries_added"] == 3

    timeline = await client.get(f"/api/campaigns/{campaign.id}/timeline", headers=headers)
    assert len(timeline.json()) == 4


async def test_syncing_a_source_twice_adds_nothing_the_second_time(
    client: AsyncClient, headers: dict, db_session: AsyncSession, feed: Feed, campaign: Campaign
):
    thread = StoryThread(slug="idempotent", title="Idempotent", status="open", entry_count=2, source_count=2)
    db_session.add(thread)
    await db_session.flush()
    for i in range(2):
        e = await _entry(db_session, feed, f"idem-{i}")
        db_session.add(StoryThreadEntry(thread_id=thread.id, entry_id=e.id, role="beat"))
    await db_session.flush()

    created = await client.post(
        f"/api/campaigns/{campaign.id}/sources",
        json={"kind": "story", "ref_id": str(thread.id)},
        headers=headers,
    )
    source_id = created.json()["id"]

    again = await client.post(f"/api/campaigns/{campaign.id}/sources/{source_id}/sync", headers=headers)
    assert again.status_code == 200
    assert again.json()["entries_added"] == 0
    assert again.json()["total_entries_added"] == 2


# ── Following an entity ──────────────────────────────────────────────


async def test_following_an_entity_pulls_in_its_articles(
    client: AsyncClient, headers: dict, db_session: AsyncSession, feed: Feed, campaign: Campaign
):
    actor = ThreatActor(name="Followed Actor", aliases=[], country="Unknown")
    db_session.add(actor)
    await db_session.flush()
    for i in range(3):
        e = await _entry(db_session, feed, f"actor-{i}")
        db_session.add(EntryThreatActor(entry_id=e.id, threat_actor_id=actor.id))
    await db_session.flush()

    resp = await client.post(
        f"/api/campaigns/{campaign.id}/sources",
        json={"kind": "entity", "entity_type": "threat_actor", "ref_id": str(actor.id)},
        headers=headers,
    )
    assert resp.status_code == 201
    assert resp.json()["label"] == "Followed Actor"
    assert resp.json()["entries_added"] == 3


async def test_an_entity_source_needs_a_type(client: AsyncClient, headers: dict, campaign: Campaign):
    resp = await client.post(
        f"/api/campaigns/{campaign.id}/sources",
        json={"kind": "entity", "ref_id": str(uuid.uuid4())},
        headers=headers,
    )
    assert resp.status_code == 422


async def test_following_the_same_thing_twice_is_a_conflict(
    client: AsyncClient, headers: dict, db_session: AsyncSession, campaign: Campaign
):
    """Two sources racing to add the same articles is never what was meant."""
    actor = ThreatActor(name="Twice", aliases=[], country="Unknown")
    db_session.add(actor)
    await db_session.flush()

    body = {"kind": "entity", "entity_type": "threat_actor", "ref_id": str(actor.id)}
    assert (await client.post(f"/api/campaigns/{campaign.id}/sources", json=body, headers=headers)).status_code == 201
    assert (await client.post(f"/api/campaigns/{campaign.id}/sources", json=body, headers=headers)).status_code == 409


# ── Lifecycle ────────────────────────────────────────────────────────


async def test_a_closed_campaign_stops_collecting(
    client: AsyncClient, headers: dict, db_session: AsyncSession, feed: Feed, campaign: Campaign
):
    """Closing a campaign that kept growing would quietly undo the act of closing it."""
    from app.services.campaign_sources import sync_campaign_sources

    actor = ThreatActor(name="Still Active", aliases=[], country="Unknown")
    db_session.add(actor)
    await db_session.flush()
    e = await _entry(db_session, feed, "closed-1")
    db_session.add(EntryThreatActor(entry_id=e.id, threat_actor_id=actor.id))
    await db_session.flush()

    await client.post(
        f"/api/campaigns/{campaign.id}/sources",
        json={"kind": "entity", "entity_type": "threat_actor", "ref_id": str(actor.id)},
        headers=headers,
    )

    # A new article arrives after the campaign is closed.
    campaign.status = "closed"
    later = await _entry(db_session, feed, "closed-2", day=9)
    db_session.add(EntryThreatActor(entry_id=later.id, threat_actor_id=actor.id))
    await db_session.flush()

    result = await sync_campaign_sources(db_session)
    assert result == {"sources": 0, "entries_added": 0}


async def test_unfollowing_keeps_the_articles_it_already_added(
    client: AsyncClient, headers: dict, db_session: AsyncSession, feed: Feed, campaign: Campaign
):
    """They were added to the campaign, not borrowed by the source."""
    actor = ThreatActor(name="Unfollowed", aliases=[], country="Unknown")
    db_session.add(actor)
    await db_session.flush()
    e = await _entry(db_session, feed, "unfollow-1")
    db_session.add(EntryThreatActor(entry_id=e.id, threat_actor_id=actor.id))
    await db_session.flush()

    created = await client.post(
        f"/api/campaigns/{campaign.id}/sources",
        json={"kind": "entity", "entity_type": "threat_actor", "ref_id": str(actor.id)},
        headers=headers,
    )
    source_id = created.json()["id"]

    assert (
        await client.delete(f"/api/campaigns/{campaign.id}/sources/{source_id}", headers=headers)
    ).status_code == 204
    timeline = await client.get(f"/api/campaigns/{campaign.id}/timeline", headers=headers)
    assert len(timeline.json()) == 1


async def test_pausing_a_source_keeps_the_row_and_its_history(
    client: AsyncClient, headers: dict, db_session: AsyncSession, campaign: Campaign
):
    actor = ThreatActor(name="Paused", aliases=[], country="Unknown")
    db_session.add(actor)
    await db_session.flush()

    created = await client.post(
        f"/api/campaigns/{campaign.id}/sources",
        json={"kind": "entity", "entity_type": "threat_actor", "ref_id": str(actor.id)},
        headers=headers,
    )
    source_id = created.json()["id"]

    paused = await client.patch(
        f"/api/campaigns/{campaign.id}/sources/{source_id}",
        json={"auto_sync": False},
        headers=headers,
    )
    assert paused.status_code == 200
    assert paused.json()["auto_sync"] is False

    listing = await client.get(f"/api/campaigns/{campaign.id}/sources", headers=headers)
    assert len(listing.json()) == 1


# ── Suggestions ──────────────────────────────────────────────────────


async def test_suggestions_come_from_what_the_campaign_already_declared(
    client: AsyncClient, headers: dict, db_session: AsyncSession, feed: Feed, campaign: Campaign, user: User
):
    """Entities it named, and stories it already holds part of — each with the
    number of articles following it would add, so the click is informed."""
    actor = ThreatActor(name="Named Subject", aliases=[], country="Unknown")
    db_session.add(actor)
    await db_session.flush()
    db_session.add(
        CampaignEntity(campaign_id=campaign.id, entity_type="threat_actor", entity_id=actor.id, role="primary")
    )
    for i in range(2):
        e = await _entry(db_session, feed, f"sugg-actor-{i}")
        db_session.add(EntryThreatActor(entry_id=e.id, threat_actor_id=actor.id))

    thread = StoryThread(slug="partly-held", title="Partly held", status="open", entry_count=3, source_count=2)
    db_session.add(thread)
    await db_session.flush()
    story_entries = [await _entry(db_session, feed, f"sugg-story-{i}") for i in range(3)]
    for e in story_entries:
        db_session.add(StoryThreadEntry(thread_id=thread.id, entry_id=e.id, role="beat"))
    db_session.add(CampaignEntry(campaign_id=campaign.id, entry_id=story_entries[0].id, added_by=user.id))
    await db_session.flush()

    resp = await client.get(f"/api/campaigns/{campaign.id}/sources/suggested", headers=headers)
    assert resp.status_code == 200
    by_kind = {s["kind"]: s for s in resp.json()}

    assert by_kind["entity"]["label"] == "Named Subject"
    assert by_kind["entity"]["why"] == "named as primary in this campaign"
    assert by_kind["entity"]["would_add"] == 2

    assert by_kind["story"]["label"] == "Partly held"
    assert by_kind["story"]["why"] == "you hold 1 of 3 articles"
    assert by_kind["story"]["would_add"] == 2


async def test_something_already_followed_is_not_suggested_again(
    client: AsyncClient, headers: dict, db_session: AsyncSession, campaign: Campaign
):
    actor = ThreatActor(name="Already Followed", aliases=[], country="Unknown")
    db_session.add(actor)
    await db_session.flush()
    db_session.add(
        CampaignEntity(campaign_id=campaign.id, entity_type="threat_actor", entity_id=actor.id, role="primary")
    )
    await db_session.flush()

    before = await client.get(f"/api/campaigns/{campaign.id}/sources/suggested", headers=headers)
    assert len(before.json()) == 1

    await client.post(
        f"/api/campaigns/{campaign.id}/sources",
        json={"kind": "entity", "entity_type": "threat_actor", "ref_id": str(actor.id)},
        headers=headers,
    )
    after = await client.get(f"/api/campaigns/{campaign.id}/sources/suggested", headers=headers)
    assert after.json() == []
