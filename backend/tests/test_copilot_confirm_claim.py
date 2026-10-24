"""A proposed copilot action executes once, however many approvals arrive."""

import json
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select

from app.models.campaign import Campaign
from app.models.user import User
from app.services.redis_client import get_redis


async def _stage(user: User, name: str) -> str:
    action_id = uuid.uuid4().hex
    r = await get_redis()
    await r.set(
        f"copilot:action:{action_id}",
        json.dumps({"user_id": str(user.id), "action_type": "create_campaign", "params": {"name": name}}),
        ex=300,
    )
    return action_id


@pytest.mark.asyncio
async def test_a_second_approval_in_flight_is_refused(client: AsyncClient, auth_headers: dict, test_user: User):
    action_id = await _stage(test_user, "claimed-elsewhere")
    r = await get_redis()
    await r.set(f"copilot:action:{action_id}:claim", "1", ex=60)  # another approval is running
    resp = await client.post(
        "/api/ai/copilot/confirm", json={"action_id": action_id, "approved": True}, headers=auth_headers
    )
    assert resp.status_code == 409
    await r.delete(f"copilot:action:{action_id}", f"copilot:action:{action_id}:claim")


@pytest.mark.asyncio
async def test_approved_action_runs_once(client: AsyncClient, auth_headers: dict, test_user: User, db_session):
    name = f"once-{uuid.uuid4().hex[:8]}"
    action_id = await _stage(test_user, name)
    first = await client.post(
        "/api/ai/copilot/confirm", json={"action_id": action_id, "approved": True}, headers=auth_headers
    )
    assert first.status_code == 200 and first.json()["status"] == "executed", first.text
    again = await client.post(
        "/api/ai/copilot/confirm", json={"action_id": action_id, "approved": True}, headers=auth_headers
    )
    assert again.status_code == 404
    count = await db_session.scalar(select(func.count()).select_from(Campaign).where(Campaign.name == name))
    assert count == 1
    r = await get_redis()
    assert not await r.exists(f"copilot:action:{action_id}:claim")
