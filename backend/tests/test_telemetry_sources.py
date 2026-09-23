"""Tests for DE-4: Telemetry source management."""

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.telemetry_source import TelemetrySource
from app.models.user import User


@pytest_asyncio.fixture
async def test_telemetry_source(db_session: AsyncSession, test_user: User) -> TelemetrySource:
    source = TelemetrySource(
        created_by=test_user.id,
        name="CrowdStrike Falcon",
        category="endpoint",
        vendor="CrowdStrike",
        product="Falcon",
        log_types=["process_creation", "network_connection"],
        ingested_into="splunk",
    )
    db_session.add(source)
    await db_session.flush()
    return source


@pytest.mark.asyncio
async def test_create_telemetry_source(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        "/api/telemetry-sources",
        json={
            "name": "Windows Event Log",
            "category": "endpoint",
            "vendor": "Microsoft",
            "product": "Windows",
            "log_types": ["Security", "System", "PowerShell"],
            "ingested_into": "elastic",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "Windows Event Log"
    assert data["category"] == "endpoint"
    assert len(data["log_types"]) == 3


@pytest.mark.asyncio
async def test_list_telemetry_sources(client: AsyncClient, auth_headers: dict, test_telemetry_source: TelemetrySource):
    resp = await client.get("/api/telemetry-sources", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1


@pytest.mark.asyncio
async def test_filter_by_category(client: AsyncClient, auth_headers: dict, test_telemetry_source: TelemetrySource):
    resp = await client.get("/api/telemetry-sources?category=endpoint", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["total"] >= 1


@pytest.mark.asyncio
async def test_update_telemetry_source(client: AsyncClient, auth_headers: dict, test_telemetry_source: TelemetrySource):
    resp = await client.put(
        f"/api/telemetry-sources/{test_telemetry_source.id}",
        json={"enabled": False, "notes": "Decommissioned"},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["enabled"] is False


@pytest.mark.asyncio
async def test_delete_telemetry_source(client: AsyncClient, auth_headers: dict, test_telemetry_source: TelemetrySource):
    resp = await client.delete(f"/api/telemetry-sources/{test_telemetry_source.id}", headers=auth_headers)
    assert resp.status_code == 204


@pytest.mark.asyncio
async def test_invalid_category(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        "/api/telemetry-sources",
        json={"name": "Test", "category": "invalid_category"},
        headers=auth_headers,
    )
    assert resp.status_code == 400
