"""Tests for the simple intelligence API feed endpoint."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.cve import CVE
from app.models.malware_family import MalwareFamily
from app.models.threat_actor import ThreatActor
from app.models.ttp import TTP


@pytest_asyncio.fixture
async def seed_intel_data(db_session: AsyncSession):
    """Seed the database with intelligence entities for feed testing."""
    now = datetime.now(UTC)
    yesterday = now - timedelta(days=1)
    last_week = now - timedelta(days=7)

    cve1 = CVE(
        id=uuid.uuid4(),
        cve_id="CVE-2024-1234",
        cvss_score=9.8,
        severity="critical",
        description="Remote code execution in Example Product",
        first_seen_at=now,
    )
    cve2 = CVE(
        id=uuid.uuid4(),
        cve_id="CVE-2024-5678",
        cvss_score=7.5,
        severity="high",
        description="SQL injection in Another Product",
        first_seen_at=yesterday,
    )

    ttp1 = TTP(
        id=uuid.uuid4(),
        technique_id="T1059.001",
        technique_name="PowerShell",
        tactic="execution",
        first_seen_at=now,
        last_seen_at=now,
    )

    actor1 = ThreatActor(
        id=uuid.uuid4(),
        name="APT29",
        aliases=["Cozy Bear", "The Dukes"],
        description="Russian state-sponsored threat actor",
        country="Russia",
        motivation="espionage",
        first_seen_at=now,
        last_seen_at=now,
    )

    malware1 = MalwareFamily(
        id=uuid.uuid4(),
        name="Cobalt Strike",
        aliases=["CobaltStrike"],
        description="Commercial adversary simulation tool",
        malware_type="rat",
        first_seen_at=now,
        last_seen_at=now,
    )

    db_session.add_all([cve1, cve2, ttp1, actor1, malware1])
    await db_session.flush()

    return {
        "cves": [cve1, cve2],
        "ttps": [ttp1],
        "actors": [actor1],
        "malware": [malware1],
        "now": now,
        "yesterday": yesterday,
        "last_week": last_week,
    }


@pytest.mark.asyncio
async def test_get_feed_returns_all_entity_types(client: AsyncClient, auth_headers: dict, seed_intel_data: dict):
    """Feed with no filters returns items from all entity types."""
    resp = await client.get("/api/intelligence/feed", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    assert "items" in data
    assert "total" in data
    assert "limit" in data
    assert "offset" in data
    assert "has_more" in data

    # We seeded 2 CVEs + 1 TTP + 1 actor + 1 malware = 5
    assert data["total"] == 5
    assert len(data["items"]) == 5

    entity_types = {item["entity_type"] for item in data["items"]}
    assert "vulnerability" in entity_types
    assert "attack-pattern" in entity_types
    assert "threat-actor" in entity_types
    assert "malware" in entity_types


@pytest.mark.asyncio
async def test_filter_by_entity_type_cve(client: AsyncClient, auth_headers: dict, seed_intel_data: dict):
    """Filter to CVEs only."""
    resp = await client.get("/api/intelligence/feed?entity_type=cve", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 2
    for item in data["items"]:
        assert item["entity_type"] == "vulnerability"


@pytest.mark.asyncio
async def test_filter_by_multiple_entity_types(client: AsyncClient, auth_headers: dict, seed_intel_data: dict):
    """Filter to multiple types via comma-separated list."""
    resp = await client.get("/api/intelligence/feed?entity_type=ttp,actor", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 2
    entity_types = {item["entity_type"] for item in data["items"]}
    assert entity_types == {"attack-pattern", "threat-actor"}


@pytest.mark.asyncio
async def test_filter_by_since_date(client: AsyncClient, auth_headers: dict, seed_intel_data: dict):
    """Filter by since date excludes older entries."""
    # Use a timestamp between yesterday and last_week to exclude older data
    cutoff = seed_intel_data["yesterday"] - timedelta(hours=12)
    resp = await client.get(f"/api/intelligence/feed?since={cutoff.isoformat()}", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    # Should include everything seeded with now or yesterday
    # now: cve1, ttp1, actor1, malware1 = 4
    # yesterday: cve2 = 1
    assert data["total"] == 5
    for item in data["items"]:
        # No item should have a first_seen before the cutoff
        if item.get("first_seen"):
            assert item["first_seen"] >= cutoff.isoformat()


@pytest.mark.asyncio
async def test_filter_since_invalid_date(client: AsyncClient, auth_headers: dict, seed_intel_data: dict):
    """Invalid since date returns 400 error."""
    resp = await client.get("/api/intelligence/feed?since=not-a-date", headers=auth_headers)
    assert resp.status_code == 400
    data = resp.json()
    assert data["error"]["code"] == "invalid_param"


@pytest.mark.asyncio
async def test_pagination_limit(client: AsyncClient, auth_headers: dict, seed_intel_data: dict):
    """Limit parameter restricts number of returned items."""
    resp = await client.get("/api/intelligence/feed?limit=3", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["items"]) == 3
    assert data["total"] == 5
    assert data["has_more"] is True
    assert data["limit"] == 3
    assert data["offset"] == 0


@pytest.mark.asyncio
async def test_pagination_offset(client: AsyncClient, auth_headers: dict, seed_intel_data: dict):
    """Offset parameter skips items."""
    resp = await client.get("/api/intelligence/feed?limit=3&offset=4", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["items"]) == 1  # 5 total, offset 4, so 1 remaining
    assert data["total"] == 5
    assert data["has_more"] is False


@pytest.mark.asyncio
async def test_items_sorted_by_first_seen_desc(client: AsyncClient, auth_headers: dict, seed_intel_data: dict):
    """Items are sorted by first_seen descending."""
    resp = await client.get("/api/intelligence/feed", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    first_seen_dates = [item["first_seen"] for item in data["items"] if item.get("first_seen")]
    assert first_seen_dates == sorted(first_seen_dates, reverse=True)


@pytest.mark.asyncio
async def test_unauthenticated_returns_401(client: AsyncClient, seed_intel_data: dict):
    """Unauthenticated request returns 401."""
    resp = await client.get("/api/intelligence/feed")
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_empty_feed_returns_empty_list(client: AsyncClient, auth_headers: dict):
    """Feed with no data returns empty items list."""
    resp = await client.get("/api/intelligence/feed", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["items"] == []
    assert data["total"] == 0
    assert data["has_more"] is False


@pytest.mark.asyncio
async def test_cve_fields_in_response(client: AsyncClient, auth_headers: dict, seed_intel_data: dict):
    """CVE items contain expected fields."""
    resp = await client.get("/api/intelligence/feed?entity_type=cve", headers=auth_headers)
    assert resp.status_code == 200
    items = resp.json()["items"]
    cve = next(item for item in items if item.get("cve_id") == "CVE-2024-1234")
    assert cve["entity_type"] == "vulnerability"
    assert cve["cvss_score"] == 9.8
    assert cve["severity"] == "critical"
    assert cve["description"] == "Remote code execution in Example Product"


@pytest.mark.asyncio
async def test_malware_entity_type_filter(client: AsyncClient, auth_headers: dict, seed_intel_data: dict):
    """Filter to malware only."""
    resp = await client.get("/api/intelligence/feed?entity_type=malware", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert data["items"][0]["entity_type"] == "malware"
    assert data["items"][0]["name"] == "Cobalt Strike"
    assert data["items"][0]["malware_type"] == "rat"


@pytest.mark.asyncio
async def test_actor_entity_type_filter(client: AsyncClient, auth_headers: dict, seed_intel_data: dict):
    """Filter to threat actors only."""
    resp = await client.get("/api/intelligence/feed?entity_type=actor", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    actor = data["items"][0]
    assert actor["entity_type"] == "threat-actor"
    assert actor["name"] == "APT29"
    assert "Cozy Bear" in actor["aliases"]
    assert actor["country"] == "Russia"
    assert actor["motivation"] == "espionage"
