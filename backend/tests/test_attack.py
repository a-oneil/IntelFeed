"""Tests for ATT&CK Navigator layer generation API."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_generate_layer(client: AsyncClient, auth_headers: dict):
    resp = await client.get("/api/attack/layer", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "name" in data
    assert "versions" in data
    assert data["domain"] == "enterprise-attack"
    assert "techniques" in data
    assert isinstance(data["techniques"], list)
    assert "gradient" in data


@pytest.mark.asyncio
async def test_generate_layer_with_date_range(client: AsyncClient, auth_headers: dict):
    resp = await client.get(
        "/api/attack/layer",
        params={"date_from": "2026-01-01", "date_to": "2026-03-04"},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["domain"] == "enterprise-attack"


@pytest.mark.asyncio
async def test_list_techniques(client: AsyncClient, auth_headers: dict):
    resp = await client.get("/api/attack/techniques", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)


@pytest.mark.asyncio
async def test_list_techniques_with_params(client: AsyncClient, auth_headers: dict):
    resp = await client.get(
        "/api/attack/techniques",
        params={"date_from": "2026-01-01", "limit": 10},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) <= 10
