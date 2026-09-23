import uuid

import pytest
from httpx import AsyncClient

from app.models.user import User


@pytest.mark.asyncio
async def test_app_error_format(client: AsyncClient, auth_headers: dict, test_user: User):
    """Trigger a 404 via GET /api/entries/{nonexistent-uuid} and verify the
    JSON error envelope structure."""
    fake_id = str(uuid.uuid4())
    resp = await client.get(f"/api/entries/{fake_id}", headers=auth_headers)
    assert resp.status_code == 404
    data = resp.json()
    assert "error" in data
    assert data["error"]["code"] == "not_found"
    assert "message" in data["error"]
    assert isinstance(data["error"]["details"], list)


@pytest.mark.asyncio
async def test_validation_error_format(client: AsyncClient, auth_headers: dict, test_user: User):
    """POST to /api/auth/register with an invalid body to trigger a
    validation error and verify the envelope."""
    resp = await client.post(
        "/api/auth/register",
        json={"username": "ab", "password": 12345},
    )
    assert resp.status_code == 400
    data = resp.json()
    assert "error" in data
    assert data["error"]["code"] == "validation_error"
    assert data["error"]["message"] == "Request validation failed"
    assert isinstance(data["error"]["details"], list)
    assert len(data["error"]["details"]) > 0
    # Each detail should have field, message, and code
    detail = data["error"]["details"][0]
    assert "field" in detail
    assert "message" in detail
    assert "code" in detail


@pytest.mark.asyncio
async def test_http_error_format(client: AsyncClient):
    """Request a protected endpoint without an auth header to trigger an
    HTTP error (401/403) and verify the JSON envelope."""
    resp = await client.get("/api/auth/me")
    assert resp.status_code in (401, 403)
    data = resp.json()
    assert "error" in data
    assert "code" in data["error"]
    assert "message" in data["error"]
    assert isinstance(data["error"]["details"], list)
