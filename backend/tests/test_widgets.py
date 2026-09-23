"""Tests for widget data endpoints."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_feed_activity(client: AsyncClient, auth_headers: dict):
    resp = await client.get("/api/widgets/feed-activity", headers=auth_headers)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


@pytest.mark.asyncio
async def test_cve_severity(client: AsyncClient, auth_headers: dict):
    resp = await client.get("/api/widgets/cve-severity", headers=auth_headers)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


@pytest.mark.asyncio
async def test_threat_timeline(client: AsyncClient, auth_headers: dict):
    resp = await client.get("/api/widgets/threat-timeline", headers=auth_headers)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


@pytest.mark.asyncio
async def test_trending_cves(client: AsyncClient, auth_headers: dict):
    resp = await client.get("/api/widgets/trending-cves", headers=auth_headers)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


@pytest.mark.asyncio
async def test_attack_heatmap(client: AsyncClient, auth_headers: dict):
    resp = await client.get("/api/widgets/attack-heatmap", headers=auth_headers)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


@pytest.mark.asyncio
async def test_stats(client: AsyncClient, auth_headers: dict):
    resp = await client.get("/api/widgets/stats", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "entries" in data
    assert "cves" in data
    assert "unread" in data
    assert "count" in data["entries"]
    assert "trend" in data["entries"]


@pytest.mark.asyncio
async def test_stats_with_date_range(client: AsyncClient, auth_headers: dict):
    resp = await client.get(
        "/api/widgets/stats",
        params={"date_from": "2026-01-01", "date_to": "2026-03-04"},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "entries" in data


@pytest.mark.asyncio
async def test_feed_activity_with_date_range(client: AsyncClient, auth_headers: dict):
    resp = await client.get(
        "/api/widgets/feed-activity",
        params={"date_from": "2026-02-01"},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)
