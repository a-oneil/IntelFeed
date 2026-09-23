"""Tests for the system settings API endpoints."""

import pytest
from httpx import AsyncClient

BASE_URL = "/api/system-settings"


@pytest.mark.asyncio
async def test_list_settings_as_admin(client: AsyncClient, admin_headers: dict):
    """Admin can list all system settings."""
    resp = await client.get(BASE_URL, headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "settings" in data
    assert "groups" in data


@pytest.mark.asyncio
async def test_list_settings_as_non_admin(client: AsyncClient, auth_headers: dict):
    """Non-admin user gets 403 when listing system settings."""
    resp = await client.get(BASE_URL, headers=auth_headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_list_settings_unauthenticated(client: AsyncClient):
    """Unauthenticated request gets 401."""
    resp = await client.get(BASE_URL)
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_update_setting_as_admin(client: AsyncClient, admin_headers: dict):
    """Admin can update a system setting."""
    resp = await client.patch(
        BASE_URL,
        json={"settings": {"default_feed_fetch_interval": 600}},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "settings" in data


@pytest.mark.asyncio
async def test_update_setting_as_non_admin(client: AsyncClient, auth_headers: dict):
    """Non-admin user gets 403 when updating settings."""
    resp = await client.patch(
        BASE_URL,
        json={"settings": {"default_feed_fetch_interval": 600}},
        headers=auth_headers,
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_update_setting_unauthenticated(client: AsyncClient):
    """Unauthenticated request gets 401 when updating settings."""
    resp = await client.patch(
        BASE_URL,
        json={"settings": {"default_feed_fetch_interval": 600}},
    )
    assert resp.status_code == 401
