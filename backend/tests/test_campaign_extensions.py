"""Tests for Campaign extension endpoints (timeline, attack-layer, suggest)."""

import uuid
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.campaign import Campaign, CampaignEntry
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.ttp import TTP, EntryTTP
from app.models.user import User


@pytest_asyncio.fixture
async def test_user(db_session: AsyncSession) -> User:
    user = User(
        username="campaign_ext_testuser",
        password_hash=hash_password("testpassword"),
        role="user",
    )
    db_session.add(user)
    await db_session.flush()
    return user


@pytest_asyncio.fixture
async def auth_headers(test_user: User) -> dict:
    token = create_access_token(test_user.id, test_user.role)
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture
async def test_feed(db_session: AsyncSession) -> Feed:
    feed = Feed(title="Campaign Test Feed", url="https://camp-test.example.com/feed", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()
    return feed


@pytest_asyncio.fixture
async def campaign_with_entries(db_session: AsyncSession, test_user: User, test_feed: Feed):
    """Create a campaign with 2 entries and TTPs."""
    campaign = Campaign(
        created_by=test_user.id,
        name="Test Campaign",
        status="active",
        tlp_marking="TLP:GREEN",
    )
    db_session.add(campaign)
    await db_session.flush()

    entries = []
    for i in range(2):
        entry = Entry(
            feed_id=test_feed.id,
            title=f"Campaign Entry {i + 1}",
            guid=f"camp-entry-{i + 1}",
            published_at=datetime(2026, 3, 1 + i, tzinfo=UTC),
        )
        db_session.add(entry)
        await db_session.flush()
        entries.append(entry)

        db_session.add(
            CampaignEntry(
                campaign_id=campaign.id,
                entry_id=entry.id,
                added_by=test_user.id,
            )
        )

    # Add TTPs
    ttp1 = TTP(technique_id="T1059.001", technique_name="PowerShell", tactic="execution")
    ttp2 = TTP(technique_id="T1566.001", technique_name="Spearphishing", tactic="initial-access")
    db_session.add_all([ttp1, ttp2])
    await db_session.flush()

    db_session.add(EntryTTP(entry_id=entries[0].id, ttp_id=ttp1.id))
    db_session.add(EntryTTP(entry_id=entries[1].id, ttp_id=ttp2.id))

    await db_session.flush()
    return campaign, entries, [ttp1, ttp2]


async def test_campaign_timeline(client: AsyncClient, auth_headers: dict, campaign_with_entries):
    campaign, entries, _ = campaign_with_entries

    resp = await client.get(f"/api/campaigns/{campaign.id}/timeline", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 2
    # Should be sorted by published_at descending (newest first)
    assert data[0]["title"] == "Campaign Entry 2"
    assert data[1]["title"] == "Campaign Entry 1"


async def test_campaign_attack_layer(client: AsyncClient, auth_headers: dict, campaign_with_entries):
    campaign, _, _ = campaign_with_entries

    resp = await client.get(f"/api/campaigns/{campaign.id}/attack-layer", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "Test Campaign" in data["name"]
    assert "techniques" in data
    assert len(data["techniques"]) >= 1


async def test_campaign_attack_layer_dedupes_techniques(
    client: AsyncClient, auth_headers: dict, campaign_with_entries, db_session: AsyncSession
):
    """Regression (B6): a technique linked to multiple entries with different
    confidence values must appear only once, keeping the highest confidence."""
    campaign, entries, ttps = campaign_with_entries

    # Link ttp1 to the second entry as well, with a different confidence —
    # previously this produced duplicate techniques in the layer.
    db_session.add(EntryTTP(entry_id=entries[0].id, ttp_id=ttps[1].id, confidence="low"))
    db_session.add(EntryTTP(entry_id=entries[1].id, ttp_id=ttps[0].id, confidence="high"))
    await db_session.flush()

    resp = await client.get(f"/api/campaigns/{campaign.id}/attack-layer", headers=auth_headers)
    assert resp.status_code == 200
    techniques = resp.json()["techniques"]

    technique_ids = [t["techniqueID"] for t in techniques]
    assert len(technique_ids) == len(set(technique_ids)), "duplicate techniques in layer"
    assert sorted(set(technique_ids)) == ["T1059.001", "T1566.001"]

    # Highest confidence wins: T1059.001 was linked with None and "high"
    t1059 = next(t for t in techniques if t["techniqueID"] == "T1059.001")
    assert t1059["score"] == 100


async def test_campaign_suggest(
    client: AsyncClient, auth_headers: dict, campaign_with_entries, db_session: AsyncSession, test_feed: Feed
):
    campaign, _, ttps = campaign_with_entries

    # Create an entry NOT in the campaign that shares TTPs
    entry3 = Entry(
        feed_id=test_feed.id,
        title="Related but not in campaign",
        guid="camp-entry-3",
        published_at=datetime(2026, 3, 5, tzinfo=UTC),
    )
    db_session.add(entry3)
    await db_session.flush()

    # Link the same TTPs to entry3
    db_session.add(EntryTTP(entry_id=entry3.id, ttp_id=ttps[0].id))
    db_session.add(EntryTTP(entry_id=entry3.id, ttp_id=ttps[1].id))
    await db_session.flush()

    resp = await client.get(
        f"/api/campaigns/{campaign.id}/suggest?min_overlap=2",
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) >= 1
    assert any(s["entry_id"] == str(entry3.id) for s in data)
    assert data[0]["overlap_count"] >= 2


async def test_campaign_not_found(client: AsyncClient, auth_headers: dict):
    fake_id = uuid.uuid4()
    resp = await client.get(f"/api/campaigns/{fake_id}/timeline", headers=auth_headers)
    assert resp.status_code == 404


# ── Timeline: story threads ──────────────────────────────────────────


async def test_campaign_timeline_carries_story_threads(
    client: AsyncClient, auth_headers: dict, db_session: AsyncSession, campaign_with_entries
):
    """A campaign entry the sweeper threaded reports its story; one it didn't reports null."""
    from app.models.story_thread import StoryThread, StoryThreadEntry

    campaign, entries, _ = campaign_with_entries

    thread = StoryThread(
        slug="a-story-the-campaign-swept-up",
        title="A story the campaign swept up",
        status="open",
        entry_count=2,
        source_count=2,
    )
    db_session.add(thread)
    await db_session.flush()
    db_session.add(StoryThreadEntry(thread_id=thread.id, entry_id=entries[0].id, role="origin"))
    db_session.add(StoryThreadEntry(thread_id=thread.id, entry_id=entries[1].id, role="echo"))
    await db_session.flush()

    resp = await client.get(f"/api/campaigns/{campaign.id}/timeline", headers=auth_headers)
    assert resp.status_code == 200
    rows = {row["title"]: row for row in resp.json()}

    assert rows["Campaign Entry 1"]["thread_slug"] == "a-story-the-campaign-swept-up"
    assert rows["Campaign Entry 1"]["thread_title"] == "A story the campaign swept up"
    assert rows["Campaign Entry 1"]["thread_role"] == "origin"
    assert rows["Campaign Entry 2"]["thread_role"] == "echo"
    assert rows["Campaign Entry 2"]["thread_id"] == rows["Campaign Entry 1"]["thread_id"]


async def test_campaign_timeline_unthreaded_entries_report_no_story(
    client: AsyncClient, auth_headers: dict, campaign_with_entries
):
    """Pre-embeddings articles and hand-added advisories have no thread and must not 500."""
    campaign, _, _ = campaign_with_entries

    resp = await client.get(f"/api/campaigns/{campaign.id}/timeline", headers=auth_headers)
    assert resp.status_code == 200
    rows = resp.json()
    assert len(rows) == 2
    assert all(row["thread_id"] is None and row["thread_role"] is None for row in rows)


# ── Suggestions: the rest of a story ─────────────────────────────────


async def test_suggest_offers_the_rest_of_a_story_the_campaign_holds(
    client: AsyncClient, auth_headers: dict, db_session: AsyncSession, test_feed, campaign_with_entries
):
    """The tenth article about a breach may share no entity with the first nine.

    Entity overlap cannot reach it; belonging to the same story can.
    """
    from app.models.story_thread import StoryThread, StoryThreadEntry

    campaign, entries, _ = campaign_with_entries

    thread = StoryThread(
        slug="one-story-partly-tracked",
        title="One story, partly tracked",
        status="open",
        entry_count=4,
        source_count=3,
    )
    db_session.add(thread)
    await db_session.flush()
    # The campaign already holds one of the story's articles…
    db_session.add(StoryThreadEntry(thread_id=thread.id, entry_id=entries[0].id, role="origin"))

    # …and these three, which share no entity with it, are the rest.
    missing = []
    for i in range(3):
        entry = Entry(
            feed_id=test_feed.id,
            title=f"Later wave {i + 1}",
            guid=f"same-story-{i}",
            published_at=datetime(2026, 3, 5 + i, tzinfo=UTC),
        )
        db_session.add(entry)
        await db_session.flush()
        db_session.add(StoryThreadEntry(thread_id=thread.id, entry_id=entry.id, role="beat"))
        missing.append(entry)
    await db_session.flush()

    resp = await client.get(f"/api/campaigns/{campaign.id}/suggest", headers=auth_headers)
    assert resp.status_code == 200
    rows = {row["title"]: row for row in resp.json()}

    for entry in missing:
        assert entry.title in rows, f"{entry.title} should be suggested on story membership alone"
        row = rows[entry.title]
        assert row["reason"] == "same_story"
        assert row["overlap_count"] == 0  # no entity overlap reached it
        assert row["thread_slug"] == "one-story-partly-tracked"
        assert row["thread_in_campaign"] == 1
        assert row["thread_article_count"] == 4

    # Surest first.
    assert resp.json()[0]["reason"] == "same_story"


async def test_suggest_still_offers_entity_matches_that_never_clustered(
    client: AsyncClient, auth_headers: dict, db_session: AsyncSession, test_feed, campaign_with_entries
):
    """Coverage that never became a story is still reachable by entity overlap."""
    campaign, entries, ttps = campaign_with_entries

    entry = Entry(
        feed_id=test_feed.id,
        title="Unclustered but overlapping",
        guid="overlap-only",
        published_at=datetime(2026, 3, 9, tzinfo=UTC),
    )
    db_session.add(entry)
    await db_session.flush()
    db_session.add(EntryTTP(entry_id=entry.id, ttp_id=ttps[0].id))
    await db_session.flush()

    resp = await client.get(f"/api/campaigns/{campaign.id}/suggest?min_overlap=1", headers=auth_headers)
    assert resp.status_code == 200
    row = next(r for r in resp.json() if r["title"] == "Unclustered but overlapping")
    assert row["reason"] == "shared_entities"
    assert row["overlap_count"] >= 1
    assert row["thread_slug"] is None


# ── Bulk add ─────────────────────────────────────────────────────────


async def test_bulk_add_adds_a_story_in_one_call(
    client: AsyncClient, auth_headers: dict, db_session: AsyncSession, test_feed, campaign_with_entries
):
    campaign, entries, _ = campaign_with_entries

    fresh = []
    for i in range(3):
        entry = Entry(feed_id=test_feed.id, title=f"Bulk {i}", guid=f"bulk-{i}")
        db_session.add(entry)
        await db_session.flush()
        fresh.append(entry)
    await db_session.flush()

    resp = await client.post(
        f"/api/campaigns/{campaign.id}/entries/bulk",
        json={"entry_ids": [str(e.id) for e in fresh]},
        headers=auth_headers,
    )
    assert resp.status_code == 201
    assert resp.json() == {"added": 3, "skipped": 0}

    timeline = await client.get(f"/api/campaigns/{campaign.id}/timeline", headers=auth_headers)
    assert len(timeline.json()) == 5


async def test_bulk_add_skips_what_is_already_there_instead_of_conflicting(
    client: AsyncClient, auth_headers: dict, campaign_with_entries
):
    """Re-adding a story that grew since you last looked adds only the new part."""
    campaign, entries, _ = campaign_with_entries

    resp = await client.post(
        f"/api/campaigns/{campaign.id}/entries/bulk",
        json={"entry_ids": [str(e.id) for e in entries]},
        headers=auth_headers,
    )
    assert resp.status_code == 201
    assert resp.json() == {"added": 0, "skipped": 2}


async def test_bulk_add_ignores_ids_that_match_no_entry(client: AsyncClient, auth_headers: dict, campaign_with_entries):
    """One bad id must not take the whole batch down with a foreign key error."""
    campaign, entries, _ = campaign_with_entries

    resp = await client.post(
        f"/api/campaigns/{campaign.id}/entries/bulk",
        json={"entry_ids": [str(uuid.uuid4()), str(uuid.uuid4())]},
        headers=auth_headers,
    )
    assert resp.status_code == 201
    assert resp.json() == {"added": 0, "skipped": 2}


# ── Gone quiet ───────────────────────────────────────────────────────


async def test_campaign_reports_when_its_newest_article_was_published(
    client: AsyncClient, auth_headers: dict, campaign_with_entries
):
    """last_activity_at is what a gone-quiet campaign is measured from."""
    campaign, entries, _ = campaign_with_entries

    resp = await client.get(f"/api/campaigns/{campaign.id}", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["last_activity_at"].startswith("2026-03-02")

    listing = await client.get("/api/campaigns", headers=auth_headers)
    row = next(c for c in listing.json()["items"] if c["id"] == str(campaign.id))
    assert row["last_activity_at"].startswith("2026-03-02")


async def test_campaign_holding_nothing_reports_no_activity(
    client: AsyncClient, auth_headers: dict, db_session: AsyncSession, test_user
):
    campaign = Campaign(created_by=test_user.id, name="Empty", status="active")
    db_session.add(campaign)
    await db_session.flush()

    resp = await client.get(f"/api/campaigns/{campaign.id}", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["last_activity_at"] is None


# ── Campaign as a pivot source ───────────────────────────────────────


async def test_campaign_pivots_to_the_entities_on_its_articles(
    client: AsyncClient, auth_headers: dict, campaign_with_entries
):
    """A campaign's seed is a curated list rather than an extraction junction.

    Everything downstream of the seed is the same, so the pivot resolves a
    campaign to the entities its articles carry — which is what lets campaigns
    render through the shared profile shell.
    """
    campaign, entries, ttps = campaign_with_entries

    resp = await client.get(f"/api/intelligence/pivot/campaign/{campaign.id}", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    assert data["entity"]["type"] == "campaign"
    assert data["entity"]["name"] == "Test Campaign"
    assert data["entity"]["status"] == "active"
    assert data["entity"]["tlp_marking"] == "TLP:GREEN"
    assert len(data["entries"]) == 2
    assert data["related_counts"]["ttps"] == 2
    assert {t["technique_id"] for t in data["related"]["ttps"]} == {t.technique_id for t in ttps}


async def test_campaign_pivot_skips_proximity_rather_than_erroring(
    client: AsyncClient, auth_headers: dict, campaign_with_entries
):
    """A campaign has no paragraph position, so related rows fall back to co-occurrence.

    The strength machinery looks the source up in the extraction junctions; a
    campaign has no row in any of them, and the co-occurrence-only path is both
    correct and the reason this doesn't raise.
    """
    campaign, _, _ = campaign_with_entries

    resp = await client.get(f"/api/intelligence/pivot/campaign/{campaign.id}", headers=auth_headers)
    assert resp.status_code == 200
    for ttp in resp.json()["related"]["ttps"]:
        assert ttp["co_occurrence_count"] >= 1


async def test_campaign_timeline_endpoint_returns_its_articles(
    client: AsyncClient, auth_headers: dict, campaign_with_entries
):
    campaign, entries, _ = campaign_with_entries

    resp = await client.get(f"/api/intelligence/timeline/campaign/{campaign.id}", headers=auth_headers)
    assert resp.status_code == 200
    articles = [e for e in resp.json()["events"] if e["event_type"] == "article"]
    assert {a["title"] for a in articles} == {e.title for e in entries}


async def test_campaign_graph_is_labelled_and_connected(client: AsyncClient, auth_headers: dict, campaign_with_entries):
    """Superseding an earlier assertion that an empty map was correct.

    It was reasoned from the claims-only rule and was wrong in practice: a lone
    unconnected node is a broken graph however defensible the reasoning. What a
    campaign claims is its membership.
    """
    campaign, _, _ = campaign_with_entries

    resp = await client.get(f"/api/intelligence/graph/campaign/{campaign.id}", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    root = next(n for n in data["nodes"] if n["id"] == f"campaign-{campaign.id}")
    assert root["label"] == "Test Campaign"
    assert len(data["nodes"]) > 1
    assert data["edges"]


async def test_campaign_is_not_a_related_entity_type(client: AsyncClient, auth_headers: dict, campaign_with_entries):
    """Pivotable as a source, but never reportable as a false positive or
    exportable as an entity — those gate on the extraction vocabulary."""
    campaign, _, _ = campaign_with_entries

    resp = await client.post(
        "/api/false-positives",
        json={
            "entity_type": "campaign",
            "entity_id": str(campaign.id),
            "entity_value": campaign.name,
            "scope": "global",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 422
    assert "campaign" not in resp.json()["error"]["message"]

    # And the pivot, which gates on the wider set, does take it.
    assert (
        await client.get(f"/api/intelligence/pivot/campaign/{campaign.id}", headers=auth_headers)
    ).status_code == 200


async def test_campaign_serves_the_shared_attack_and_gap_endpoints(
    client: AsyncClient, auth_headers: dict, campaign_with_entries
):
    """The ATT&CK and Detection tabs read the entity-scoped endpoints, not the
    campaign-scoped ones — so a campaign has to answer them to render those tabs."""
    campaign, _, ttps = campaign_with_entries

    techniques = await client.get(f"/api/entities/campaign/{campaign.id}/attack-techniques", headers=auth_headers)
    assert techniques.status_code == 200
    rows = techniques.json()
    rows = rows if isinstance(rows, list) else rows.get("items", [])
    assert {r["technique_id"] for r in rows} == {t.technique_id for t in ttps}

    gaps = await client.get(f"/api/entities/campaign/{campaign.id}/detection-gaps", headers=auth_headers)
    assert gaps.status_code == 200
    assert gaps.json()["total_ttps"] == 2

    layer = await client.get(f"/api/entities/campaign/{campaign.id}/attack-layer", headers=auth_headers)
    assert layer.status_code == 200
    assert layer.json()["name"]


async def test_campaign_story_threads_endpoint_reaches_its_stories(
    client: AsyncClient, auth_headers: dict, db_session: AsyncSession, campaign_with_entries
):
    """ActiveStoryCard and the timeline's STORY rows both read this."""
    from app.models.story_thread import StoryThread, StoryThreadEntry

    campaign, entries, _ = campaign_with_entries
    thread = StoryThread(
        slug="a-campaign-story", title="A campaign story", status="open", entry_count=2, source_count=2
    )
    db_session.add(thread)
    await db_session.flush()
    for entry in entries:
        db_session.add(StoryThreadEntry(thread_id=thread.id, entry_id=entry.id, role="beat"))
    await db_session.flush()

    resp = await client.get(f"/api/entities/campaign/{campaign.id}/story-threads?status=any", headers=auth_headers)
    assert resp.status_code == 200
    assert [t["slug"] for t in resp.json()["items"]] == ["a-campaign-story"]


# ── Every surface the shared profile shell calls ─────────────────────


@pytest.mark.parametrize(
    "path,params",
    [
        ("/api/intelligence/pivot/campaign/{id}", {}),
        ("/api/intelligence/graph/campaign/{id}", {}),
        ("/api/intelligence/timeline/campaign/{id}", {}),
        ("/api/entities/campaign/{id}/provenance", {}),
        ("/api/entities/campaign/{id}/mentions-timeseries", {"window": "90d"}),
        ("/api/entities/campaign/{id}/story-threads", {"status": "any"}),
        ("/api/entities/campaign/{id}/top-entries", {}),
        ("/api/entities/campaign/{id}/attack-layer", {}),
        ("/api/entities/campaign/{id}/attack-techniques", {}),
        ("/api/entities/campaign/{id}/detection-gaps", {}),
        ("/api/engine/entities/campaign/{id}/whats-new", {}),
        ("/api/entities/campaign/{id}/entries-window", {"start": "2026-01-01T00:00:00", "end": "2026-12-31T00:00:00"}),
    ],
)
async def test_every_profile_shell_endpoint_accepts_a_campaign(
    client: AsyncClient, auth_headers: dict, campaign_with_entries, path: str, params: dict
):
    """The shell fires all of these on one page load.

    Each gates on its own entity-type map, so folding campaigns in means every
    one of them has to answer — a single holdout renders as a broken panel or a
    toast on an otherwise working page. This list is why they are now routed
    through one `entry_scope_junction` helper instead of a map per module.
    """
    campaign, _, _ = campaign_with_entries

    resp = await client.get(path.format(id=campaign.id), params=params, headers=auth_headers)
    assert resp.status_code == 200, f"{path} rejected a campaign: {resp.text[:200]}"


async def test_campaign_provenance_is_empty_rather_than_an_error(
    client: AsyncClient, auth_headers: dict, campaign_with_entries
):
    """Nothing writes field claims for a campaign, and the header reads this on
    every profile — so the answer is an empty set in the normal shape."""
    campaign, _, _ = campaign_with_entries

    resp = await client.get(f"/api/entities/campaign/{campaign.id}/provenance", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json() == {"entity_type": "campaign", "entity_id": str(campaign.id), "fields": {}}


async def test_campaign_graph_claims_its_membership(
    client: AsyncClient, auth_headers: dict, db_session: AsyncSession, campaign_with_entries
):
    """The map shows claims, and a campaign's claim is what it holds.

    Nothing writes entity_relationship rows for a campaign — it is not in the
    relationship matrix — so the claims-only rule left its map a single
    unconnected node. Membership is an analyst assertion, and the curated
    CampaignEntity role is the verb.
    """
    from app.models.campaign import CampaignEntity

    campaign, _, ttps = campaign_with_entries
    db_session.add(CampaignEntity(campaign_id=campaign.id, entity_type="ttp", entity_id=ttps[0].id, role="primary"))
    await db_session.flush()

    resp = await client.get(f"/api/intelligence/graph/campaign/{campaign.id}", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    root = f"campaign-{campaign.id}"
    direct = [e for e in data["edges"] if root in (e["source"], e["target"])]
    assert len(direct) == 2, "both techniques on its articles should be claimed"
    assert all(e["provenance"] == "analyst" for e in direct)

    by_label = {e["label"] for e in direct}
    assert by_label == {"primary", "related"}, "the curated role is the verb; the rest are plain membership"


async def test_campaign_graph_keeps_the_curated_entity_when_the_cap_bites(
    client: AsyncClient, auth_headers: dict, db_session: AsyncSession, test_feed, test_user, campaign_with_entries
):
    """Curation outranks volume.

    A campaign's proximity is co-occurrence only, so a plain score sort spends
    the neighbour budget on whatever co-occurs most and drops the one entity the
    analyst called primary.
    """
    from app.models.campaign import CampaignEntity, CampaignEntry
    from app.models.threat_actor import EntryThreatActor, ThreatActor

    campaign, entries, ttps = campaign_with_entries

    # An actor named on one article only — outranked by every technique on
    # co-occurrence, but explicitly the campaign's subject.
    actor = ThreatActor(name="Quiet Subject", aliases=[], country="Unknown")
    db_session.add(actor)
    await db_session.flush()
    db_session.add(EntryThreatActor(entry_id=entries[0].id, threat_actor_id=actor.id))
    db_session.add(
        CampaignEntity(campaign_id=campaign.id, entity_type="threat_actor", entity_id=actor.id, role="primary")
    )

    # Bulk up the co-occurring techniques so the actor is the weakest candidate.
    for i in range(6):
        entry = Entry(feed_id=test_feed.id, title=f"Filler {i}", guid=f"graph-filler-{i}")
        db_session.add(entry)
        await db_session.flush()
        db_session.add(CampaignEntry(campaign_id=campaign.id, entry_id=entry.id, added_by=test_user.id))
        for ttp in ttps:
            db_session.add(EntryTTP(entry_id=entry.id, ttp_id=ttp.id))
    await db_session.flush()

    resp = await client.get(f"/api/intelligence/graph/campaign/{campaign.id}", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    root = f"campaign-{campaign.id}"
    direct = [e for e in data["edges"] if root in (e["source"], e["target"])]
    primary = [e for e in direct if e["label"] == "primary"]
    assert len(primary) == 1, "the primary entity must survive the neighbour cap"
    assert primary[0]["confidence"] == "confirmed"


async def test_campaign_gets_the_same_detection_workspace_as_an_actor(
    client: AsyncClient, auth_headers: dict, campaign_with_entries
):
    """The Detection tab's Build lane is gated on the coverage workspace serving
    the type; without it a campaign fell back to a bare coverage list that looked
    nothing like the other profiles."""
    campaign, _, _ = campaign_with_entries

    resp = await client.get(
        f"/api/coverage-workspace/campaign/{campaign.id}", params={"window": "30d"}, headers=auth_headers
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["entity_type"] == "campaign"
    assert data["label"] == "Test Campaign"
