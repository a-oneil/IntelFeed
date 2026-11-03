"""Authorization on the tool-execution endpoint.

/api/tools/execute dispatches registry tools directly, so it must not be a
side door around the API layer's admin gates: tools in ADMIN_TOOLS refuse
non-admin callers, everything else runs under the caller's identity.
"""

import json
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.feed import Feed
from app.models.note import Note
from app.models.user import User
from app.tools import ADMIN_TOOLS, MUTATING_TOOLS


def test_admin_tools_are_registered():
    """Every ADMIN_TOOLS entry must exist in the registry — a rename there
    would silently open the gate. Most are writes; the few reads mirror
    admin-only API views."""
    from app.tools import TOOL_DEFINITIONS

    names = {t["name"] for t in TOOL_DEFINITIONS}
    missing = ADMIN_TOOLS - names
    assert not missing, f"ADMIN_TOOLS entries not in the registry: {missing}"
    admin_reads = ADMIN_TOOLS - MUTATING_TOOLS
    assert admin_reads == {
        "get_hygiene_feed",
        "get_hygiene_stats",
        "get_extraction_stats",
        "list_extraction_entities",
        "list_review_groups",
        "get_review_rows",
    }


@pytest.mark.asyncio
async def test_admin_only_views_refused_for_non_admin(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        "/api/tools/execute", json={"tool_name": "get_hygiene_stats", "args": {}}, headers=auth_headers
    )
    assert resp.status_code == 403


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


@pytest.mark.asyncio
async def test_model_facing_executor_refuses_tools_it_was_not_offered():
    """The in-process tool loops (copilot, agentic engine tasks) show the model a
    filtered tool list. A model can still name any registry tool in its reply,
    because article text in its context asked it to or because the endpoint is
    hostile, so the executor must refuse anything outside the offered set."""
    import app.tools.gate as gate

    ran: list[str] = []

    async def isolated(db, name, args, user_id):
        ran.append(name)
        return "{}"

    defs = gate.model_tool_definitions(role="admin", names=["get_feeds", "delete_feed"], include_writes=False)
    offered = [d["name"] for d in defs]
    assert offered == ["get_feeds"], "read-only must drop the mutating tool from the offer"

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(gate, "execute_isolated", isolated)
        guarded = gate.UnattendedGate(db=None, user_id=uuid.uuid4(), role="admin", offered=offered)
        assert await guarded("get_feeds", {}) == "{}"
        refused = json.loads(await guarded("delete_feed", {"feed_id": "x", "confirm": True}))
        assert "error" in refused
        refused = json.loads(await guarded("merge_threat_actors", {}))
        assert "error" in refused
    assert ran == ["get_feeds"]


@pytest.mark.asyncio
async def test_create_feed_tool_encrypts_bluesky_app_password(db_session: AsyncSession, admin_user: User):
    """The tool path applies the same adapter_config handling as POST /api/feeds:
    a Bluesky app password is encrypted at rest, never stored as typed."""
    from app.core.encryption import decrypt_value
    from app.tools import execute_tool

    raw = await execute_tool(
        "create_feed",
        {
            "url": "https://bsky.app/profile/example.bsky.social",
            "feed_type": "bluesky",
            "adapter_config": {"handle": "example.bsky.social", "identifier": "me", "app_password": "abcd-efgh"},
        },
        db_session,
        admin_user.id,
    )
    assert "error" not in json.loads(raw), raw
    feed = (
        await db_session.execute(select(Feed).where(Feed.url == "https://bsky.app/profile/example.bsky.social"))
    ).scalar_one()
    stored = feed.adapter_config["app_password"]
    assert stored != "abcd-efgh" and decrypt_value(stored) == "abcd-efgh"
