"""Tests for analytics API — trending, coverage, velocity, overview, insights, and feed health."""

import uuid

from httpx import AsyncClient

from app.models.threat_actor import ThreatActor
from app.models.ttp import TTP


async def test_analytics_overview(client: AsyncClient, auth_headers: dict, db_session):
    """Overview returns entity counts and event summary."""
    resp = await client.get("/api/analytics/overview", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "entity_counts" in data
    assert "detection" in data
    assert "events" in data


async def test_analytics_trending_actors(client: AsyncClient, auth_headers: dict, db_session):
    """Trending returns top entities by article count."""
    for i in range(3):
        actor = ThreatActor(
            name=f"AnalyticsActor{i}_{uuid.uuid4().hex[:6]}",
            article_count=10 * (i + 1),
        )
        db_session.add(actor)
    await db_session.flush()

    resp = await client.get(
        "/api/analytics/trending/threat_actor?days=30&limit=10",
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)


async def test_analytics_trending_invalid_type(client: AsyncClient, auth_headers: dict):
    """Trending with invalid entity type returns empty list."""
    resp = await client.get(
        "/api/analytics/trending/invalid_type",
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json() == []


async def test_analytics_detection_coverage(client: AsyncClient, auth_headers: dict, db_session):
    """Detection coverage returns TTP coverage analysis."""
    ttp = TTP(
        technique_id=f"T{uuid.uuid4().hex[:4]}",
        technique_name="TestTechnique",
        tactic="execution",
    )
    db_session.add(ttp)
    await db_session.flush()

    resp = await client.get(
        "/api/analytics/detection-coverage?include_gaps=true",
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "total_ttps" in data
    assert "covered_ttps" in data
    assert "coverage_percentage" in data
    assert "tactic_summary" in data
    assert "gaps" in data


async def test_analytics_velocity(client: AsyncClient, auth_headers: dict):
    """Velocity returns entity creation counts per day."""
    resp = await client.get(
        "/api/analytics/velocity?days=7",
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["days"] == 7
    assert "velocity" in data
    assert "cve" in data["velocity"]


async def test_analytics_entry_insights_not_found(client: AsyncClient, auth_headers: dict):
    """Insights for nonexistent entry returns empty list."""
    fake_id = uuid.uuid4()
    resp = await client.get(
        f"/api/analytics/entries/{fake_id}/insights",
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json() == []


async def test_feed_health(client: AsyncClient, auth_headers: dict):
    """Feed health endpoint returns summary."""
    resp = await client.get(
        "/api/feeds/health?stale_days=7",
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "summary" in data
    assert "stale_feeds" in data
    assert "erroring_feeds" in data
    assert "disabled_feeds" in data
    summary = data["summary"]
    assert "healthy" in summary
    assert "total" in summary
