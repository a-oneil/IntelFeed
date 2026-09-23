import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_refresh_token, hash_password
from app.models.user import User


@pytest.mark.asyncio
async def test_register_success(client: AsyncClient):
    resp = await client.post(
        "/api/auth/register",
        json={
            "username": "newuser",
            "password": "strongpassword",
        },
    )
    assert resp.status_code == 201
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_register_duplicate_username(client: AsyncClient, test_user: User):
    resp = await client.post(
        "/api/auth/register",
        json={
            "username": "testuser",
            "password": "anotherpassword",
        },
    )
    assert resp.status_code == 409
    data = resp.json()
    assert data["error"]["code"] == "conflict"
    assert "already taken" in data["error"]["message"].lower()


@pytest.mark.asyncio
async def test_login_success(client: AsyncClient, test_user: User):
    resp = await client.post(
        "/api/auth/login",
        json={"username": "testuser", "password": "testpassword"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_login_wrong_password(client: AsyncClient, test_user: User):
    resp = await client.post(
        "/api/auth/login",
        json={"username": "testuser", "password": "wrongpassword"},
    )
    assert resp.status_code == 401
    data = resp.json()
    assert data["error"]["code"] == "unauthorized"


@pytest.mark.asyncio
async def test_login_inactive_user(client: AsyncClient, db_session: AsyncSession):
    inactive = User(
        username="inactiveuser",
        password_hash=hash_password("testpassword"),
        role="user",
        is_active=False,
    )
    db_session.add(inactive)
    await db_session.flush()

    resp = await client.post(
        "/api/auth/login",
        json={"username": "inactiveuser", "password": "testpassword"},
    )
    assert resp.status_code == 403
    data = resp.json()
    assert data["error"]["code"] == "forbidden"


@pytest.mark.asyncio
async def test_refresh_token(client: AsyncClient, test_user: User):
    refresh = create_refresh_token(test_user.id)
    resp = await client.post(
        "/api/auth/refresh",
        json={"refresh_token": refresh},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data


@pytest.mark.asyncio
async def test_get_me(client: AsyncClient, auth_headers: dict, test_user: User):
    resp = await client.get("/api/auth/me", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["username"] == "testuser"
    assert data["role"] == "user"
    assert data["is_active"] is True
    assert "id" in data


@pytest.mark.asyncio
async def test_update_me(client: AsyncClient, auth_headers: dict, test_user: User):
    resp = await client.put(
        "/api/auth/me",
        headers=auth_headers,
        json={"settings": {"theme": "dark"}},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["settings"]["theme"] == "dark"


@pytest.mark.asyncio
async def test_patch_me_settings_merges_top_level_keys(
    client: AsyncClient, auth_headers: dict, test_user: User
):
    """A settings patch must leave keys it doesn't mention alone — independent
    client-side auto-savers share this blob."""
    await client.put(
        "/api/auth/me",
        headers=auth_headers,
        json={"settings": {"triage_view": {"global_range": "24h"}, "theme": "dark"}},
    )

    resp = await client.patch(
        "/api/auth/me/settings",
        headers=auth_headers,
        json={"settings": {"table_layouts": {"entries": {"columnOrder": ["title"]}}}},
    )
    assert resp.status_code == 200
    settings = resp.json()["settings"]
    assert settings["table_layouts"]["entries"]["columnOrder"] == ["title"]
    assert settings["triage_view"] == {"global_range": "24h"}
    assert settings["theme"] == "dark"

    # A second patch replaces its own key wholesale, still sparing the others.
    resp = await client.patch(
        "/api/auth/me/settings",
        headers=auth_headers,
        json={"settings": {"table_layouts": {}}},
    )
    assert resp.status_code == 200
    settings = resp.json()["settings"]
    assert settings["table_layouts"] == {}
    assert settings["theme"] == "dark"

    # And it survives a round trip to the DB, not just the response model.
    resp = await client.get("/api/auth/me", headers=auth_headers)
    assert resp.json()["settings"]["theme"] == "dark"


@pytest.mark.asyncio
async def test_patch_me_settings_requires_auth(client: AsyncClient):
    resp = await client.patch("/api/auth/me/settings", json={"settings": {"a": 1}})
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_change_password(client: AsyncClient, auth_headers: dict, test_user: User):
    resp = await client.put(
        "/api/auth/me/password",
        headers=auth_headers,
        json={
            "current_password": "testpassword",
            "new_password": "newstrongpassword",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["message"] == "Password updated"

    # Verify the new password works for login
    login_resp = await client.post(
        "/api/auth/login",
        json={"username": "testuser", "password": "newstrongpassword"},
    )
    assert login_resp.status_code == 200
