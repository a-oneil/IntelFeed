"""Campaign sources — standing intake owned by the campaign itself.

A linked saved search belongs to one analyst and can only be linked if it
already exists. These tests pin the three alternatives that belong to the
campaign: the entity it names, a story it already holds part of, and a query
typed straight into it — plus the dry run that precedes any of them.
"""

import uuid
from datetime import UTC, datetime
from unittest.mock import patch

import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import select
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


# ── A typed query ────────────────────────────────────────────────────


def _meili(*entries) -> dict:
    """What Meilisearch would answer for a query matching these entries."""
    return {"hits": [{"id": str(e.id)} for e in entries], "estimatedTotalHits": len(entries)}


async def test_a_typed_query_is_campaign_owned_intake(
    client: AsyncClient, headers: dict, db_session: AsyncSession, feed: Feed, campaign: Campaign
):
    """The reach of a saved search without the ownership: no SavedSearch row is
    created, the text lives on the campaign, and the row is readable as itself."""
    from app.models.saved_search import SavedSearch

    hits = [await _entry(db_session, feed, f"query-{i}") for i in range(3)]
    with patch("app.search.meili_builder.execute_entry_search", return_value=_meili(*hits)):
        resp = await client.post(
            f"/api/campaigns/{campaign.id}/sources",
            json={"kind": "query", "query": "ransomware AND healthcare"},
            headers=headers,
        )
    assert resp.status_code == 201
    body = resp.json()
    assert body["kind"] == "query"
    assert body["query"] == "ransomware AND healthcare"
    assert body["label"] == "ransomware AND healthcare"
    assert body["ref_id"] is None
    assert body["entries_added"] == 3

    # Nobody's personal saved-search list grew to make this work.
    assert (await db_session.execute(select(SavedSearch))).scalars().all() == []


async def test_a_query_source_recomputes_rather_than_diffing(
    client: AsyncClient, headers: dict, db_session: AsyncSession, feed: Feed, campaign: Campaign
):
    """An article that starts matching later still arrives.

    The saved-search sweep diffs against what the campaign holds at the moment
    it runs, so an article it missed once it misses forever. A query source
    recomputes its whole claimed set every run, like every other source.
    """
    first = await _entry(db_session, feed, "recompute-1")
    with patch("app.search.meili_builder.execute_entry_search", return_value=_meili(first)):
        created = await client.post(
            f"/api/campaigns/{campaign.id}/sources",
            json={"kind": "query", "query": "akira"},
            headers=headers,
        )
    source_id = created.json()["id"]
    assert created.json()["entries_added"] == 1

    later = await _entry(db_session, feed, "recompute-2", day=9)
    with patch("app.search.meili_builder.execute_entry_search", return_value=_meili(first, later)):
        again = await client.post(f"/api/campaigns/{campaign.id}/sources/{source_id}/sync", headers=headers)
    assert again.json() == {"entries_added": 1, "total_entries_added": 2}


async def test_a_query_that_does_not_parse_is_refused(client: AsyncClient, headers: dict, campaign: Campaign):
    """It would resolve to the empty set forever, and the row would not say why."""
    resp = await client.post(
        f"/api/campaigns/{campaign.id}/sources",
        json={"kind": "query", "query": "akira AND"},
        headers=headers,
    )
    assert resp.status_code == 422
    assert "does not parse" in resp.json()["error"]["message"]


async def test_a_query_source_takes_no_ref_id(client: AsyncClient, headers: dict, campaign: Campaign):
    resp = await client.post(
        f"/api/campaigns/{campaign.id}/sources",
        json={"kind": "query", "query": "akira", "ref_id": str(uuid.uuid4())},
        headers=headers,
    )
    assert resp.status_code == 422


async def test_the_same_query_twice_is_a_conflict(
    client: AsyncClient, headers: dict, db_session: AsyncSession, feed: Feed, campaign: Campaign
):
    body = {"kind": "query", "query": "lockbit"}
    with patch("app.search.meili_builder.execute_entry_search", return_value=_meili()):
        first = await client.post(f"/api/campaigns/{campaign.id}/sources", json=body, headers=headers)
        second = await client.post(f"/api/campaigns/{campaign.id}/sources", json=body, headers=headers)
    assert first.status_code == 201
    assert second.status_code == 409


async def test_a_query_source_can_be_rewritten_in_place(
    client: AsyncClient, headers: dict, db_session: AsyncSession, feed: Feed, campaign: Campaign
):
    """Fixing a too-broad query should not mean unfollowing and starting over —
    the row keeps what it already added."""
    hit = await _entry(db_session, feed, "rewrite-1")
    with patch("app.search.meili_builder.execute_entry_search", return_value=_meili(hit)):
        created = await client.post(
            f"/api/campaigns/{campaign.id}/sources",
            json={"kind": "query", "query": "ransomware"},
            headers=headers,
        )
    source_id = created.json()["id"]

    resp = await client.patch(
        f"/api/campaigns/{campaign.id}/sources/{source_id}",
        json={"query": 'malware:"Akira"'},
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["query"] == 'malware:"Akira"'
    # The label is the query for this kind, so it moves with it.
    assert resp.json()["label"] == 'malware:"Akira"'
    assert resp.json()["entries_added"] == 1


async def test_rewriting_a_query_to_something_unparseable_is_refused(
    client: AsyncClient, headers: dict, db_session: AsyncSession, feed: Feed, campaign: Campaign
):
    with patch("app.search.meili_builder.execute_entry_search", return_value=_meili()):
        created = await client.post(
            f"/api/campaigns/{campaign.id}/sources",
            json={"kind": "query", "query": "good"},
            headers=headers,
        )
    source_id = created.json()["id"]
    resp = await client.patch(
        f"/api/campaigns/{campaign.id}/sources/{source_id}",
        json={"query": "akira AND"},
        headers=headers,
    )
    assert resp.status_code == 422


async def test_a_story_source_has_no_query_to_rewrite(
    client: AsyncClient, headers: dict, db_session: AsyncSession, campaign: Campaign
):
    thread = StoryThread(slug="no-query", title="No query", status="open", entry_count=0, source_count=0)
    db_session.add(thread)
    await db_session.flush()
    created = await client.post(
        f"/api/campaigns/{campaign.id}/sources",
        json={"kind": "story", "ref_id": str(thread.id)},
        headers=headers,
    )
    resp = await client.patch(
        f"/api/campaigns/{campaign.id}/sources/{created.json()['id']}",
        json={"query": "anything"},
        headers=headers,
    )
    assert resp.status_code == 422


# ── Followable types ─────────────────────────────────────────────────


async def test_following_a_type_that_owns_no_articles_is_refused(
    client: AsyncClient, headers: dict, campaign: Campaign
):
    """``source_entry_ids`` answers the empty set for a type with no entry
    junction, so the source would be created and then never add anything."""
    resp = await client.post(
        f"/api/campaigns/{campaign.id}/sources",
        json={"kind": "entity", "entity_type": "detection_rule", "ref_id": str(uuid.uuid4())},
        headers=headers,
    )
    assert resp.status_code == 422
    assert "owns no articles" in resp.json()["error"]["message"]


async def test_source_options_names_what_the_pickers_may_offer(client: AsyncClient, headers: dict):
    resp = await client.get("/api/campaigns/source-options", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["kinds"] == ["entity", "story", "query"]
    assert "threat_actor" in body["followable_entity_types"]
    assert "detection_rule" not in body["followable_entity_types"]
    # Followable but not findable by name through /intelligence/search.
    assert "observable" in body["followable_entity_types"]
    assert "observable" not in body["pickable_entity_types"]


# ── Preview (the dry run) ────────────────────────────────────────────


async def test_preview_names_the_articles_a_query_would_add(
    client: AsyncClient, headers: dict, db_session: AsyncSession, feed: Feed, campaign: Campaign, user: User
):
    """ "adds 700" tells you the size of a decision but not whether to make it."""
    held = await _entry(db_session, feed, "preview-held", day=1)
    fresh = await _entry(db_session, feed, "preview-new", day=5)
    db_session.add(CampaignEntry(campaign_id=campaign.id, entry_id=held.id, added_by=user.id))
    await db_session.flush()

    with patch("app.search.meili_builder.execute_entry_search", return_value=_meili(held, fresh)):
        resp = await client.post(
            f"/api/campaigns/{campaign.id}/sources/preview",
            json={"kind": "query", "query": "ransomware"},
            headers=headers,
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["would_add"] == 1
    assert body["already_held"] == 1
    assert [p["title"] for p in body["preview"]] == ["Article preview-new"]
    assert body["label"] == "ransomware"
    assert body["error"] is None

    # A dry run creates nothing.
    listed = await client.get(f"/api/campaigns/{campaign.id}/sources", headers=headers)
    assert listed.json() == []


async def test_preview_reports_a_parse_error_instead_of_failing(client: AsyncClient, headers: dict, campaign: Campaign):
    """The UI previews as you type, and a half-typed query is not a failed request."""
    resp = await client.post(
        f"/api/campaigns/{campaign.id}/sources/preview",
        json={"kind": "query", "query": "half AND"},
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["would_add"] == 0
    assert resp.json()["error"]


async def test_preview_of_an_empty_query_asks_nothing(client: AsyncClient, headers: dict, campaign: Campaign):
    resp = await client.post(
        f"/api/campaigns/{campaign.id}/sources/preview",
        json={"kind": "query", "query": "   "},
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json() == {
        "kind": "query",
        "entity_type": None,
        "ref_id": None,
        "query": None,
        "label": "",
        "would_add": 0,
        "already_held": 0,
        "preview": [],
        "error": None,
        "unknown_fields": [],
    }


async def test_preview_names_a_field_the_query_language_does_not_have(
    client: AsyncClient, headers: dict, campaign: Campaign
):
    """`actor:` is not a field — the real one is `threat_actor:`. The planner
    folds the unknown one into a text term, so the query keeps answering with a
    plausible number instead of failing. On a standing source that is the worst
    kind of wrong, so the dry run says it out loud."""
    with patch("app.search.meili_builder.execute_entry_search", return_value=_meili()):
        resp = await client.post(
            f"/api/campaigns/{campaign.id}/sources/preview",
            json={"kind": "query", "query": 'actor:"Scattered Spider"'},
            headers=headers,
        )
    assert resp.status_code == 200
    assert resp.json()["unknown_fields"] == ["actor"]
    # Not fatal: it still previews, and following it is still allowed.
    assert resp.json()["error"] is None


async def test_preview_of_a_sound_query_names_no_unknown_fields(
    client: AsyncClient, headers: dict, db_session: AsyncSession, campaign: Campaign
):
    actor = ThreatActor(name="Known Field Actor", aliases=[], country="Unknown")
    db_session.add(actor)
    await db_session.flush()

    resp = await client.post(
        f"/api/campaigns/{campaign.id}/sources/preview",
        json={"kind": "query", "query": 'threat_actor:"Known Field Actor"'},
        headers=headers,
    )
    assert resp.json()["unknown_fields"] == []


async def test_preview_works_for_an_entity_the_campaign_never_named(
    client: AsyncClient, headers: dict, db_session: AsyncSession, feed: Feed, campaign: Campaign
):
    """The thing the suggestions could never offer: an entity it does not hold."""
    actor = ThreatActor(name="Unrelated Actor", aliases=[], country="Unknown")
    db_session.add(actor)
    await db_session.flush()
    for i in range(2):
        e = await _entry(db_session, feed, f"unrelated-{i}")
        db_session.add(EntryThreatActor(entry_id=e.id, threat_actor_id=actor.id))
    await db_session.flush()

    resp = await client.post(
        f"/api/campaigns/{campaign.id}/sources/preview",
        json={"kind": "entity", "entity_type": "threat_actor", "ref_id": str(actor.id)},
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["would_add"] == 2
    assert resp.json()["label"] == "Unrelated Actor"
    assert len(resp.json()["preview"]) == 2


async def test_previewing_an_unfollowable_type_is_refused(client: AsyncClient, headers: dict, campaign: Campaign):
    resp = await client.post(
        f"/api/campaigns/{campaign.id}/sources/preview",
        json={"kind": "entity", "entity_type": "detection_rule", "ref_id": str(uuid.uuid4())},
        headers=headers,
    )
    assert resp.status_code == 422
