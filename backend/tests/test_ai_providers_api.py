"""Tests for AI Provider API endpoints."""

import uuid

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.user import User


@pytest_asyncio.fixture
async def admin_user(db_session: AsyncSession) -> User:
    user = User(
        username="adminuser",
        password_hash=hash_password("adminpassword"),
        role="admin",
    )
    db_session.add(user)
    await db_session.flush()
    return user


@pytest_asyncio.fixture
async def admin_headers(admin_user: User) -> dict:
    token = create_access_token(admin_user.id, admin_user.role)
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_create_provider(client: AsyncClient, admin_headers: dict):
    resp = await client.post(
        "/api/ai/providers",
        json={
            "name": "Test Claude",
            "provider_type": "claude",
        },
        headers=admin_headers,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "Test Claude"
    assert data["provider_type"] == "claude"
    assert data["is_active"] is True


@pytest.mark.asyncio
async def test_list_providers(client: AsyncClient, auth_headers: dict, admin_headers: dict):
    # Create a provider first
    await client.post(
        "/api/ai/providers",
        json={"name": "Listed Provider", "provider_type": "claude"},
        headers=admin_headers,
    )

    resp = await client.get("/api/ai/providers", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) >= 1


@pytest.mark.asyncio
async def test_update_provider(client: AsyncClient, admin_headers: dict):
    # Create
    create_resp = await client.post(
        "/api/ai/providers",
        json={"name": "Old Name", "provider_type": "claude"},
        headers=admin_headers,
    )
    provider_id = create_resp.json()["id"]

    # Update
    resp = await client.put(
        f"/api/ai/providers/{provider_id}",
        json={"name": "New Name", "is_active": False},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["name"] == "New Name"
    assert resp.json()["is_active"] is False


@pytest.mark.asyncio
async def test_delete_provider(client: AsyncClient, admin_headers: dict):
    create_resp = await client.post(
        "/api/ai/providers",
        json={"name": "To Delete", "provider_type": "claude"},
        headers=admin_headers,
    )
    provider_id = create_resp.json()["id"]

    resp = await client.delete(f"/api/ai/providers/{provider_id}", headers=admin_headers)
    assert resp.status_code == 204


@pytest.mark.asyncio
async def test_create_provider_requires_admin(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        "/api/ai/providers",
        json={"name": "Nope", "provider_type": "claude"},
        headers=auth_headers,
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_provider_not_found(client: AsyncClient, admin_headers: dict):
    fake_id = uuid.uuid4()
    resp = await client.put(
        f"/api/ai/providers/{fake_id}",
        json={"name": "Updated"},
        headers=admin_headers,
    )
    assert resp.status_code == 404
