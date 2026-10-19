"""Tests for the triage priority queue — scoring, reasons, and component breakdown."""

from datetime import UTC, datetime, timedelta

import pytest

from app.models.cve import CVE, EntryCVE
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.intelligence_requirement import IntelligenceRequirement, RequirementMatch
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.user_entity_watch import UserEntityWatch
from app.services.triage import DEFAULT_TRIAGE_WEIGHTS, get_triage_entries, get_triage_entries_signals


async def _seed_scored_entry(db_session, test_user):
    """Feed + fresh entry with 2 PIR matches and a KEV CVE linked."""
    feed = Feed(title="Triage Feed", url="https://example.com/triage.xml", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()

    entry = Entry(
        feed_id=feed.id,
        title="KEV exploitation in the wild",
        guid="triage-guid-001",
        url="https://example.com/triage/1",
        content_text="Active exploitation of CVE-2024-0001.",
        published_at=datetime.now(UTC) - timedelta(hours=1),
    )
    db_session.add(entry)
    await db_session.flush()

    # Two PIR matches (composite PK is requirement_id+entry_id, so two requirements)
    for i in range(2):
        req = IntelligenceRequirement(
            created_by=test_user.id,
            title=f"PIR {i}",
            priority="high",
            keywords=["exploitation"],
        )
        db_session.add(req)
        await db_session.flush()
        db_session.add(
            RequirementMatch(
                requirement_id=req.id,
                entry_id=entry.id,
                match_type="keyword",
                matched_on="exploitation",
            )
        )

    # KEV CVE link — risk tier rank 3
    cve = CVE(cve_id="CVE-2024-0001", is_kev=True)
    db_session.add(cve)
    await db_session.flush()
    db_session.add(EntryCVE(entry_id=entry.id, cve_id=cve.id))
    await db_session.flush()

    return entry


@pytest.mark.asyncio
async def test_triage_score_components_breakdown(db_session, test_user):
    entry = await _seed_scored_entry(db_session, test_user)

    result = await get_triage_entries(db_session, test_user.id, days=7, limit=50)

    assert result["total"] == 1
    item = result["items"][0]
    assert item["entry"]["id"] == str(entry.id)

    # Expected: 2 PIR × 10 + KEV tier 3 × 3 + unrated reliability 3 = 32
    w = DEFAULT_TRIAGE_WEIGHTS
    assert item["priority_score"] == 2 * w["pir_weight"] + 3 * w["cve_risk_weight"] + 3

    # Reasons stay for compat
    assert "2 PIR matches" in item["priority_reasons"]
    assert "KEV CVE (actively exploited)" in item["priority_reasons"]

    # Components carry per-factor numeric contributions
    components = item["priority_components"]
    by_label = {c["label"]: c for c in components}

    pir = by_label["PIR matches"]
    assert pir["count"] == 2
    assert pir["weight"] == w["pir_weight"]
    assert pir["contribution"] == 2 * w["pir_weight"]

    kev = by_label["KEV CVE risk tier"]
    assert kev["count"] == 3
    assert kev["weight"] == w["cve_risk_weight"]
    assert kev["contribution"] == 3 * w["cve_risk_weight"]

    reliability = by_label["Feed reliability (unrated)"]
    assert reliability["contribution"] == 3

    # Contributions sum to the composite score
    assert sum(c["contribution"] for c in components) == pytest.approx(item["priority_score"])


@pytest.mark.asyncio
async def test_triage_components_respect_custom_weights(db_session, test_user):
    entry = await _seed_scored_entry(db_session, test_user)

    result = await get_triage_entries(
        db_session,
        test_user.id,
        days=7,
        limit=50,
        user_settings={"triage_settings": {"pir_weight": 4, "cve_risk_weight": 2}},
    )

    item = result["items"][0]
    assert item["entry"]["id"] == str(entry.id)
    by_label = {c["label"]: c for c in item["priority_components"]}
    assert by_label["PIR matches"]["weight"] == 4
    assert by_label["PIR matches"]["contribution"] == 8
    assert by_label["KEV CVE risk tier"]["weight"] == 2
    assert by_label["KEV CVE risk tier"]["contribution"] == 6
    assert sum(c["contribution"] for c in item["priority_components"]) == pytest.approx(item["priority_score"])


async def _seed_watch_entry(db_session, feed, priority_score, actor, watched_delta_hours=1):
    """Below-threshold entry linked to `actor` (for watch-boost tests)."""
    entry = Entry(
        feed_id=feed.id,
        title=f"Watch-boost entry ({priority_score})",
        guid=f"triage-watch-{priority_score}-{watched_delta_hours}",
        url=f"https://example.com/triage/watch-{priority_score}-{watched_delta_hours}",
        content_text="Some activity.",
        published_at=datetime.now(UTC) - timedelta(hours=watched_delta_hours),
        priority_score=priority_score,
        priority_raw=priority_score,
    )
    db_session.add(entry)
    await db_session.flush()
    if actor is not None:
        db_session.add(EntryThreatActor(entry_id=entry.id, threat_actor_id=actor.id, confidence="high", source="test"))
        await db_session.flush()
    return entry


@pytest.mark.asyncio
async def test_watched_entity_bypasses_priority_threshold(db_session, test_user):
    """An entry below the score threshold should still surface if it's linked to a watched entity."""
    feed = Feed(title="Watch Feed", url="https://example.com/watch.xml", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()

    actor = ThreatActor(name="Watched Actor")
    db_session.add(actor)
    await db_session.flush()
    db_session.add(
        UserEntityWatch(
            created_by=test_user.id, entity_type="threat_actor", entity_id=actor.id, mode="watch", boost=2.0
        )
    )
    await db_session.flush()

    watched_low = await _seed_watch_entry(db_session, feed, priority_score=0.1, actor=actor, watched_delta_hours=1)
    unwatched_low = await _seed_watch_entry(db_session, feed, priority_score=0.05, actor=None, watched_delta_hours=2)

    result = await get_triage_entries_signals(
        db_session, test_user.id, days=7, min_score=0.5, user_id_for_watches=test_user.id
    )

    ids = {item["entry"]["id"] for item in result["items"]}
    assert str(watched_low.id) in ids, "watched entry below threshold should bypass the priority floor"
    assert str(unwatched_low.id) not in ids, "unwatched entry below threshold should stay excluded"


@pytest.mark.asyncio
async def test_watch_boost_value_affects_ranking(db_session, test_user):
    """Per-watch `boost` should differentiate ranking, not apply a flat bump to every watch."""
    feed = Feed(title="Boost Feed", url="https://example.com/boost.xml", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()

    high_boost_actor = ThreatActor(name="High Boost Actor")
    low_boost_actor = ThreatActor(name="Low Boost Actor")
    db_session.add_all([high_boost_actor, low_boost_actor])
    await db_session.flush()
    db_session.add_all(
        [
            UserEntityWatch(
                created_by=test_user.id,
                entity_type="threat_actor",
                entity_id=high_boost_actor.id,
                mode="watch",
                boost=2.0,
            ),
            UserEntityWatch(
                created_by=test_user.id,
                entity_type="threat_actor",
                entity_id=low_boost_actor.id,
                mode="watch",
                boost=0.1,
            ),
        ]
    )
    await db_session.flush()

    # Lower raw priority_score but much higher watch boost — should still rank first.
    low_score_high_boost = await _seed_watch_entry(
        db_session, feed, priority_score=0.1, actor=high_boost_actor, watched_delta_hours=1
    )
    higher_score_low_boost = await _seed_watch_entry(
        db_session, feed, priority_score=0.3, actor=low_boost_actor, watched_delta_hours=2
    )

    result = await get_triage_entries_signals(
        db_session, test_user.id, days=7, min_score=0.5, user_id_for_watches=test_user.id
    )

    ids_in_order = [item["entry"]["id"] for item in result["items"]]
    assert ids_in_order.index(str(low_score_high_boost.id)) < ids_in_order.index(str(higher_score_low_boost.id))


@pytest.mark.asyncio
async def test_triage_endpoint_returns_components(client, auth_headers, db_session, test_user):
    await _seed_scored_entry(db_session, test_user)

    resp = await client.get("/api/entries/triage", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    item = data["items"][0]
    assert item["priority_reasons"]
    assert item["priority_components"]
    for c in item["priority_components"]:
        assert set(c) == {"label", "count", "weight", "contribution"}
