"""Authorization on the tool-execution endpoint.

/api/tools/execute dispatches registry tools directly, so it must not be a
side door around the API layer's admin gates: tools in ADMIN_TOOLS refuse
non-admin callers, everything else runs under the caller's identity.
"""

import json

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.feed import Feed
from app.models.note import Note
from app.models.user import User
from app.tools import ADMIN_TOOLS, MUTATING_TOOLS


def test_admin_tools_are_registered_mutating():
    """Every ADMIN_TOOLS entry must exist in the registry as a mutating tool —
    a rename there would silently open the gate."""
    missing = ADMIN_TOOLS - MUTATING_TOOLS
    assert not missing, f"ADMIN_TOOLS entries not in the mutating registry: {missing}"


@pytest.mark.asyncio
async def test_admin_tool_refused_for_non_admin(client: AsyncClient, auth_headers: dict, db_session: AsyncSession):
    feed = Feed(title="Pool Feed", url="https://pool.example/feed", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()

    resp = await client.post(
        "/api/tools/execute",
        json={"tool_name": "delete_feed", "args": {"feed_id": str(feed.id), "confirm": True}},
        headers=auth_headers,
    )
    assert resp.status_code == 403
    assert await db_session.get(Feed, feed.id) is not None


@pytest.mark.asyncio
async def test_admin_tool_allowed_for_admin(client: AsyncClient, admin_headers: dict, db_session: AsyncSession):
    # The gate must pass for admins — the tool itself may still refuse
    # (confirmation handshake), but never with a 403.
    resp = await client.post(
        "/api/tools/execute",
        json={"tool_name": "delete_feed", "args": {"feed_id": "00000000-0000-0000-0000-000000000000"}},
        headers=admin_headers,
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_read_tool_open_to_any_user(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        "/api/tools/execute",
        json={"tool_name": "get_feeds", "args": {"limit": 1}},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert "error" not in json.loads(resp.json()["result"])


@pytest.mark.asyncio
async def test_note_tool_respects_authorship(
    client: AsyncClient, auth_headers: dict, admin_user: User, db_session: AsyncSession
):
    """update_note is not admin-gated, but the handler refuses non-authors."""
    note = Note(created_by=admin_user.id, title="Admin note", content_markdown="original", content_html="<p></p>")
    db_session.add(note)
    await db_session.flush()

    resp = await client.post(
        "/api/tools/execute",
        json={"tool_name": "update_note", "args": {"note_id": str(note.id), "content": "hijacked"}},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert "error" in json.loads(resp.json()["result"])
    await db_session.refresh(note)
    assert note.content_markdown == "original"
