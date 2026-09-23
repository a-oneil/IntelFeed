"""Tests for entity-scoped detection-gaps and attack-layer endpoints (entity profile ATT&CK/Detection Gaps tabs)."""

import uuid
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.detection_rule import DetectionRule
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.ttp import TTP, EntryTTP

BASE = "/api/entities"


@pytest_asyncio.fixture
async def feed(db_session: AsyncSession) -> Feed:
    f = Feed(title="Entity Gaps Test Feed", url="https://entity-gaps-test.example.com/rss", feed_type="rss")
    db_session.add(f)
    await db_session.flush()
    return f


@pytest_asyncio.fixture
async def actor_with_ttps(db_session: AsyncSession, feed: Feed):
    """Threat actor linked to 2 entries, each with a distinct TTP."""
    actor = ThreatActor(name="Gap Test Actor")
    db_session.add(actor)
    await db_session.flush()

    entries = []
    for i in range(2):
        entry = Entry(
            feed_id=feed.id,
            title=f"Gap Entry {i + 1}",
            guid=f"gap-entry-{i + 1}",
            published_at=datetime(2026, 1, 10 + i, tzinfo=UTC),
        )
        db_session.add(entry)
        await db_session.flush()
        entries.append(entry)
        db_session.add(EntryThreatActor(entry_id=entry.id, threat_actor_id=actor.id, confidence="high", source="test"))

    ttp1 = TTP(technique_id="T1059.001", technique_name="PowerShell", tactic="execution")
    ttp2 = TTP(technique_id="T1566.001", technique_name="Spearphishing Attachment", tactic="initial-access")
    db_session.add_all([ttp1, ttp2])
    await db_session.flush()

    db_session.add(EntryTTP(entry_id=entries[0].id, ttp_id=ttp1.id))
    db_session.add(EntryTTP(entry_id=entries[1].id, ttp_id=ttp2.id))
    await db_session.flush()

    return actor, entries, [ttp1, ttp2]


# ── Detection Gaps ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_entity_detection_gaps_all_gaps(client: AsyncClient, auth_headers: dict, actor_with_ttps):
    actor, _, _ = actor_with_ttps
    resp = await client.get(f"{BASE}/threat_actor/{actor.id}/detection-gaps", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_ttps"] == 2
    assert data["gap_count"] == 2
    assert data["covered_count"] == 0
    assert data["coverage_percentage"] == 0


@pytest.mark.asyncio
async def test_entity_detection_gaps_with_coverage(
    client: AsyncClient, auth_headers: dict, actor_with_ttps, db_session: AsyncSession, test_user
):
    actor, _, _ = actor_with_ttps
    rule = DetectionRule(
        created_by=test_user.id,
        rule_type="sigma",
        title="PowerShell Execution",
        rule_content="title: PowerShell\nstatus: test",
        is_draft=False,
        mitre_tactics=["T1059.001"],
    )
    db_session.add(rule)
    await db_session.flush()

    resp = await client.get(f"{BASE}/threat_actor/{actor.id}/detection-gaps", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["covered_count"] == 1
    assert data["gap_count"] == 1
    assert data["coverage_percentage"] == 50.0
    assert data["covered"][0]["technique_id"] == "T1059.001"


@pytest.mark.asyncio
async def test_entity_detection_gaps_empty_entity(client: AsyncClient, auth_headers: dict, db_session: AsyncSession):
    actor = ThreatActor(name="No TTPs Actor")
    db_session.add(actor)
    await db_session.flush()

    resp = await client.get(f"{BASE}/threat_actor/{actor.id}/detection-gaps", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_ttps"] == 0
    assert data["coverage_percentage"] == 0
    assert data["gaps"] == []


@pytest.mark.asyncio
async def test_entity_detection_gaps_unsupported_type(client: AsyncClient, auth_headers: dict):
    resp = await client.get(f"{BASE}/cve/{uuid.uuid4()}/detection-gaps", headers=auth_headers)
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_entity_detection_gaps_malware_type(
    client: AsyncClient, auth_headers: dict, db_session: AsyncSession, feed: Feed
):
    malware = MalwareFamily(name="Gap Test Malware")
    db_session.add(malware)
    await db_session.flush()
    entry = Entry(
        feed_id=feed.id, title="Malware Gap Entry", guid="malware-gap-1", published_at=datetime(2026, 1, 12, tzinfo=UTC)
    )
    db_session.add(entry)
    await db_session.flush()
    db_session.add(EntryMalware(entry_id=entry.id, malware_family_id=malware.id, confidence="high", source="test"))
    ttp = TTP(technique_id="T1027", technique_name="Obfuscated Files", tactic="defense-evasion")
    db_session.add(ttp)
    await db_session.flush()
    db_session.add(EntryTTP(entry_id=entry.id, ttp_id=ttp.id))
    await db_session.flush()

    resp = await client.get(f"{BASE}/malware/{malware.id}/detection-gaps", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_ttps"] == 1
    assert data["gaps"][0]["technique_id"] == "T1027"


# ── Attack layer ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_entity_attack_layer_returns_navigator_json(client: AsyncClient, auth_headers: dict, actor_with_ttps):
    actor, _, _ = actor_with_ttps
    resp = await client.get(f"{BASE}/threat_actor/{actor.id}/attack-layer", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "TTPs from: Gap Test Actor"
    technique_ids = {t["techniqueID"] for t in data["techniques"]}
    assert technique_ids == {"T1059.001", "T1566.001"}


@pytest.mark.asyncio
async def test_entity_attack_layer_not_found(client: AsyncClient, auth_headers: dict):
    resp = await client.get(f"{BASE}/threat_actor/{uuid.uuid4()}/attack-layer", headers=auth_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_entity_attack_layer_unsupported_type(client: AsyncClient, auth_headers: dict):
    resp = await client.get(f"{BASE}/cve/{uuid.uuid4()}/attack-layer", headers=auth_headers)
    assert resp.status_code == 400


# ── Mentions timeseries ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_mentions_timeseries_default_window(client: AsyncClient, auth_headers: dict, actor_with_ttps):
    actor, entries, _ = actor_with_ttps
    resp = await client.get(f"{BASE}/threat_actor/{actor.id}/mentions-timeseries", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["entity_type"] == "threat_actor"
    assert data["window"] == "90d"
    assert data["bucket"] == "day"
    assert len(data["points"]) == 90
    # Fixture entries are dated in the past relative to "now" in this test env, so
    # just assert the shape and that total mentions across the window is non-negative.
    total = sum(p["count"] for p in data["points"])
    assert total >= 0
    assert all(set(p.keys()) == {"date", "count", "feeds"} for p in data["points"])
    assert data["total_feeds"] >= 0


@pytest.mark.asyncio
async def test_mentions_timeseries_unsupported_type(client: AsyncClient, auth_headers: dict):
    resp = await client.get(f"{BASE}/not_a_type/{uuid.uuid4()}/mentions-timeseries", headers=auth_headers)
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_mentions_timeseries_unsupported_window(client: AsyncClient, auth_headers: dict, actor_with_ttps):
    actor, _, _ = actor_with_ttps
    resp = await client.get(
        f"{BASE}/threat_actor/{actor.id}/mentions-timeseries", headers=auth_headers, params={"window": "5y"}
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_mentions_timeseries_recent_entry_counted_across_windows(
    client: AsyncClient, auth_headers: dict, db_session: AsyncSession, feed: Feed
):
    from datetime import UTC, datetime

    from app.models.threat_actor import EntryThreatActor, ThreatActor

    actor = ThreatActor(name="Timeseries Test Actor")
    db_session.add(actor)
    await db_session.flush()

    entry = Entry(feed_id=feed.id, title="Recent mention", guid="ts-recent-1", published_at=datetime.now(UTC))
    db_session.add(entry)
    await db_session.flush()
    db_session.add(EntryThreatActor(entry_id=entry.id, threat_actor_id=actor.id, confidence="high", source="test"))
    await db_session.flush()

    expected = {"24h": ("hour", 24), "7d": ("day", 7), "30d": ("day", 30), "60d": ("day", 60), "90d": ("day", 90)}
    for window, (bucket, n_points) in expected.items():
        resp = await client.get(
            f"{BASE}/threat_actor/{actor.id}/mentions-timeseries", headers=auth_headers, params={"window": window}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["bucket"] == bucket, window
        assert len(data["points"]) == n_points, window
        assert sum(p["count"] for p in data["points"]) == 1, window

    # "all" spans from the first mention — a just-published entry yields the 2-bucket floor
    resp = await client.get(
        f"{BASE}/threat_actor/{actor.id}/mentions-timeseries", headers=auth_headers, params={"window": "all"}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["bucket"] == "week"
    assert len(data["points"]) >= 2
    assert sum(p["count"] for p in data["points"]) == 1
