"""Tests for the Events (SSE) API at /api/events."""

from unittest.mock import patch

import pytest
from fastapi.responses import JSONResponse
from httpx import AsyncClient

from app.api.events import SSE_TICKET_PREFIX
from app.core.security import create_access_token
from app.models.user import User


async def _issue_ticket(client: AsyncClient, user: User) -> str:
    """Mint a real single-use SSE ticket the way the frontend does."""
    token = create_access_token(user.id, user.role)
    resp = await client.post("/api/events/ticket", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    return resp.json()["ticket"]


@pytest.mark.asyncio
async def test_missing_ticket(client: AsyncClient):
    """GET /api/events without a ticket query param fails validation.

    The app maps FastAPI validation errors onto 400 rather than 422.
    """
    response = await client.get("/api/events")
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "validation_error"


@pytest.mark.asyncio
async def test_unknown_ticket(client: AsyncClient):
    """A ticket that was never issued returns 401."""
    response = await client.get("/api/events", params={"ticket": "not-a-real-ticket"})
    assert response.status_code == 401
    assert "Invalid or expired ticket" in response.json()["error"]["message"]


@pytest.mark.asyncio
async def test_empty_ticket(client: AsyncClient):
    """An empty ticket string returns 401."""
    response = await client.get("/api/events", params={"ticket": ""})
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_ticket_requires_authentication(client: AsyncClient):
    """POST /api/events/ticket is itself behind normal JWT auth."""
    response = await client.post("/api/events/ticket")
    assert response.status_code in (401, 403)


@pytest.mark.asyncio
async def test_ticket_is_stored_against_the_issuing_user(client: AsyncClient, test_user: User):
    """The issued ticket resolves back to the user who asked for it."""
    import redis.asyncio as aioredis

    from app.config import settings

    ticket = await _issue_ticket(client, test_user)
    r = aioredis.from_url(settings.redis_url, decode_responses=True)
    try:
        assert await r.get(f"{SSE_TICKET_PREFIX}{ticket}") == str(test_user.id)
    finally:
        await r.aclose()


@pytest.mark.asyncio
async def test_valid_ticket_authenticates_and_is_single_use(client: AsyncClient, test_user: User):
    """A good ticket resolves to the right user, then cannot be replayed.

    ``EventSourceResponse`` never flushes its headers through httpx's in-process
    ASGI transport — it holds the connection open waiting for a disconnect the
    test client never sends — so the streaming response is stubbed out. What is
    under test here is the ticket exchange, not sse-starlette.
    """
    ticket = await _issue_ticket(client, test_user)

    with (
        patch("app.api.events._subscribe") as subscribe,
        patch("app.api.events.EventSourceResponse", lambda _gen: JSONResponse({"streaming": True})),
    ):
        first = await client.get("/api/events", params={"ticket": ticket})

    assert first.status_code == 200
    assert first.json() == {"streaming": True}
    subscribe.assert_called_once_with(str(test_user.id))

    # The ticket was consumed on claim, so replaying it is rejected.
    replay = await client.get("/api/events", params={"ticket": ticket})
    assert replay.status_code == 401


@pytest.mark.asyncio
async def test_access_token_is_not_accepted_as_a_ticket(client: AsyncClient, test_user: User):
    """A JWT must not work in the ticket slot.

    The whole point of the ticket indirection is to keep the JWT out of the
    EventSource query string, where it would leak into history and logs.
    """
    token = create_access_token(test_user.id, test_user.role)
    response = await client.get("/api/events", params={"ticket": token})
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_auth_header_not_used(client: AsyncClient, test_user: User):
    """The stream authenticates via the ticket param, not the Authorization header."""
    token = create_access_token(test_user.id, test_user.role)
    response = await client.get(
        "/api/events",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 400
