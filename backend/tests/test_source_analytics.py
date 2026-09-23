"""Tests for INTEL-3: Source reliability scoring / feed analytics."""

import uuid

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.entry import Entry
from app.models.feed import Feed
from app.models.ttp import TTP, EntryTTP
from app.models.user import User


@pytest_asyncio.fixture
async def test_feed_with_entries(db_session: AsyncSession, test_user: User):
    """Create a feed with entries and some linked TTPs."""
    feed = Feed(
        title="Security Blog",
        url="https://example.com/feed.xml",
        feed_type="rss",
    )
    db_session.add(feed)
    await db_session.flush()

    # Create 3 entries
    entries = []
    for i in range(3):
        entry = Entry(
            feed_id=feed.id,
            guid=f"guid-{i}",
            url=f"https://example.com/article-{i}",
            title=f"Article {i}",
        )
        db_session.add(entry)
        entries.append(entry)
    await db_session.flush()

    # Create TTP and link to first entry
    ttp = TTP(technique_id="T1059", technique_name="Command and Scripting Interpreter", tactic="Execution")
    db_session.add(ttp)
    await db_session.flush()
    db_session.add(EntryTTP(entry_id=entries[0].id, ttp_id=ttp.id))

    await db_session.commit()
    return feed, entries


@pytest.mark.asyncio
async def test_get_feed_analytics(client: AsyncClient, auth_headers: dict, test_feed_with_entries):
    feed, entries = test_feed_with_entries
    response = await client.get(f"/api/feeds/{feed.id}/analytics", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()

    assert data["feed_id"] == str(feed.id)
    assert data["feed_title"] == "Security Blog"
    assert data["total_articles"] == 3
    assert data["unique_ttps_contributed"] == 1
    assert data["entity_extraction_rate"] >= 0


@pytest.mark.asyncio
async def test_feed_analytics_no_entities(
    client: AsyncClient, auth_headers: dict, test_user: User, db_session: AsyncSession
):
    """Feed with entries but no linked entities."""
    feed = Feed(title="Bare Feed", url="https://bare.com/feed.xml", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()
    entry = Entry(feed_id=feed.id, guid="bare-1", url="https://bare.com/1", title="Bare Article")
    db_session.add(entry)
    await db_session.commit()

    response = await client.get(f"/api/feeds/{feed.id}/analytics", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["total_articles"] == 1
    assert data["articles_with_entities"] == 0
    assert data["entity_extraction_rate"] == 0.0


@pytest.mark.asyncio
async def test_feed_analytics_any_feed_visible(client: AsyncClient, auth_headers: dict, db_session: AsyncSession):
    """Any feed is visible to any authenticated user (no subscriptions)."""
    feed = Feed(title="Other Feed", url="https://other.com/feed.xml", feed_type="rss")
    db_session.add(feed)
    await db_session.commit()

    response = await client.get(f"/api/feeds/{feed.id}/analytics", headers=auth_headers)
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_feed_analytics_not_found(client: AsyncClient, auth_headers: dict):
    """Non-existent feed ID."""
    fake_id = uuid.uuid4()
    response = await client.get(f"/api/feeds/{fake_id}/analytics", headers=auth_headers)
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_feed_reliability_update(
    client: AsyncClient, auth_headers: dict, test_user: User, db_session: AsyncSession
):
    """Test updating feed reliability ratings."""
    feed = Feed(title="Rating Test", url="https://rate.com/feed.xml", feed_type="rss")
    db_session.add(feed)
    await db_session.commit()

    response = await client.put(
        f"/api/feeds/{feed.id}",
        json={
            "reliability_rating": "B",
            "timeliness_rating": "good",
            "relevance_rating": "high",
            "analyst_notes": "Solid source for APT tracking",
        },
        headers=auth_headers,
    )
    assert response.status_code == 200
    # Verify via analytics endpoint
    analytics_resp = await client.get(f"/api/feeds/{feed.id}/analytics", headers=auth_headers)
    assert analytics_resp.status_code == 200
    analytics = analytics_resp.json()
    assert analytics["reliability_rating"] == "B"
    assert analytics["timeliness_rating"] == "good"
    assert analytics["relevance_rating"] == "high"


@pytest.mark.asyncio
async def test_feed_reliability_rating_validation(
    client: AsyncClient, auth_headers: dict, test_user: User, db_session: AsyncSession
):
    """Test invalid reliability rating is rejected."""
    feed = Feed(title="Validation Test", url="https://val.com/feed.xml", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()
    await db_session.commit()

    response = await client.put(
        f"/api/feeds/{feed.id}",
        json={"reliability_rating": "Z"},
        headers=auth_headers,
    )
    assert response.status_code == 400


# ── Feed value scoring: PIR matches + review candidates ─────────────


@pytest_asyncio.fixture
async def pir_feeds(db_session: AsyncSession, test_user: User):
    """One feed with PIR matches, one active feed with zero intel value."""
    from app.models.intelligence_requirement import IntelligenceRequirement, RequirementMatch

    pir_feed = Feed(title="PIR Feed", url="https://pir.com/feed.xml", feed_type="rss", is_active=True)
    quiet_feed = Feed(title="Quiet Feed", url="https://quiet.com/feed.xml", feed_type="rss", is_active=True)
    db_session.add_all([pir_feed, quiet_feed])
    await db_session.flush()

    matched_entries = []
    for i in range(2):
        entry = Entry(feed_id=pir_feed.id, guid=f"pir-{i}", url=f"https://pir.com/{i}", title=f"PIR {i}")
        db_session.add(entry)
        matched_entries.append(entry)
    db_session.add(Entry(feed_id=quiet_feed.id, guid="quiet-1", url="https://quiet.com/1", title="Quiet"))
    await db_session.flush()

    requirement = IntelligenceRequirement(
        title="Track ransomware targeting healthcare",
        priority="high",
        created_by=test_user.id,
    )
    db_session.add(requirement)
    await db_session.flush()
    for entry in matched_entries:
        db_session.add(
            RequirementMatch(
                requirement_id=requirement.id,
                entry_id=entry.id,
                match_type="keyword",
                matched_on="ransomware",
            )
        )
    await db_session.commit()
    return pir_feed, quiet_feed


@pytest.mark.asyncio
async def test_feed_value_counts_pir_matches(db_session: AsyncSession, pir_feeds):
    from app.intelligence.source_analytics import compute_feed_value_scores

    pir_feed, quiet_feed = pir_feeds
    scores = await compute_feed_value_scores(db_session, feed_ids=[pir_feed.id, quiet_feed.id], days=90)
    by_id = {s["feed_id"]: s for s in scores}

    assert by_id[str(pir_feed.id)]["pir_matches"] == 2
    assert by_id[str(quiet_feed.id)]["pir_matches"] == 0
    # PIR matches alone give the feed a nonzero value score
    assert by_id[str(pir_feed.id)]["score"] > 0
    assert by_id[str(quiet_feed.id)]["score"] == 0
    assert by_id[str(pir_feed.id)]["dimensions"]["pir_matches"] == 100.0
    assert by_id[str(quiet_feed.id)]["dimensions"]["pir_matches"] == 0.0


@pytest.mark.asyncio
async def test_feed_value_review_candidates(client: AsyncClient, auth_headers: dict, pir_feeds):
    """Zero-value + zero-PIR feeds surface as removal review candidates."""
    pir_feed, quiet_feed = pir_feeds

    response = await client.get("/api/analytics/feed-value", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()

    candidate_ids = [c["feed_id"] for c in data["review_candidates"]]
    assert str(quiet_feed.id) in candidate_ids
    assert str(pir_feed.id) not in candidate_ids
    candidate = next(c for c in data["review_candidates"] if c["feed_id"] == str(quiet_feed.id))
    assert candidate["feed_title"] == "Quiet Feed"
    assert candidate["articles"] == 1
