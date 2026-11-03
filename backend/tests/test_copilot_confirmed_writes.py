"""Copilot writes run only on the user's click, through every path that reaches the registry.

The in-process providers call the tool gate directly; the Claude CLI reaches
/api/tools/execute with an agent token. Both stage a write instead of running
it, and /api/ai/copilot/confirm runs it as the user who clicked.
"""

import json
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select

import app.ai.engine as engine
from app.core.security import create_agent_token
from app.models.ai_conversation import AIConversation
from app.models.ai_provider import AIProvider
from app.models.ai_task import AITask
from app.models.ai_task_assignment import AITaskAssignment
from app.models.campaign import Campaign
from app.models.user import User
from app.tools.gate import STAGED_KEY_PREFIX, stage_tool_call, take_staged


async def _campaigns(db_session, name: str) -> int:
    return await db_session.scalar(select(func.count()).select_from(Campaign).where(Campaign.name == name))


def _propose_headers(user: User, conversation_id: uuid.UUID) -> dict:
    return {"Authorization": f"Bearer {create_agent_token(user.id, 300, conversation_id=conversation_id)}"}


# ------------------------------------------------- /api/tools/execute (the CLI)


@pytest.mark.asyncio
async def test_propose_token_stages_a_write_without_running_it(client: AsyncClient, test_user: User, db_session):
    conversation_id = uuid.uuid4()
    name = f"proposed-{uuid.uuid4().hex[:8]}"
    resp = await client.post(
        "/api/tools/execute",
        json={"tool_name": "create_campaign", "args": {"name": name}},
        headers=_propose_headers(test_user, conversation_id),
    )
    assert resp.status_code == 200, resp.text
    assert json.loads(resp.json()["result"])["status"] == "awaiting_confirmation"
    assert await _campaigns(db_session, name) == 0
    staged = await take_staged(conversation_id, test_user.id)
    assert [(s["tool_name"], s["args"]) for s in staged] == [("create_campaign", {"name": name})]


@pytest.mark.asyncio
async def test_propose_token_still_runs_reads(client: AsyncClient, test_user: User):
    resp = await client.post(
        "/api/tools/execute",
        json={"tool_name": "get_feeds", "args": {"limit": 1}},
        headers=_propose_headers(test_user, uuid.uuid4()),
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_propose_token_never_reaches_an_admin_tool_for_a_non_admin(client: AsyncClient, test_user: User):
    conversation_id = uuid.uuid4()
    resp = await client.post(
        "/api/tools/execute",
        json={"tool_name": "merge_entities", "args": {}},
        headers=_propose_headers(test_user, conversation_id),
    )
    assert resp.status_code == 403
    assert await take_staged(conversation_id, test_user.id) == []


@pytest.mark.asyncio
@pytest.mark.parametrize("propose", [False, True])
async def test_agent_tokens_may_not_carry_a_confirmation_token(client: AsyncClient, admin_user: User, propose: bool):
    token = create_agent_token(admin_user.id, 300, conversation_id=uuid.uuid4() if propose else None)
    resp = await client.post(
        "/api/tools/execute",
        json={"tool_name": "delete_feed", "args": {"feed_id": str(uuid.uuid4()), "confirmation_token": "x"}},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403
    assert "confirmation_token" in resp.json()["error"]["message"]


# ------------------------------------------------------- /api/ai/copilot/confirm


@pytest.mark.asyncio
async def test_confirm_runs_the_staged_call_once(client: AsyncClient, auth_headers, test_user: User, db_session):
    name = f"confirmed-{uuid.uuid4().hex[:8]}"
    action_id = await stage_tool_call(
        user_id=test_user.id, conversation_id=None, tool_name="create_campaign", args={"name": name}
    )
    first = await client.post(
        "/api/ai/copilot/confirm", json={"action_id": action_id, "approved": True}, headers=auth_headers
    )
    assert first.status_code == 200 and first.json()["status"] == "executed", first.text
    again = await client.post(
        "/api/ai/copilot/confirm", json={"action_id": action_id, "approved": True}, headers=auth_headers
    )
    assert again.status_code == 404
    assert await _campaigns(db_session, name) == 1


@pytest.mark.asyncio
async def test_confirm_belongs_to_the_user_who_was_asked(client: AsyncClient, admin_headers, test_user: User):
    action_id = await stage_tool_call(
        user_id=test_user.id, conversation_id=None, tool_name="create_campaign", args={"name": "not yours"}
    )
    resp = await client.post(
        "/api/ai/copilot/confirm", json={"action_id": action_id, "approved": True}, headers=admin_headers
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_confirm_rechecks_admin_tools(client: AsyncClient, auth_headers, test_user: User):
    # Staged while the user was an admin, say; they aren't now.
    action_id = await stage_tool_call(user_id=test_user.id, conversation_id=None, tool_name="merge_entities", args={})
    resp = await client.post(
        "/api/ai/copilot/confirm", json={"action_id": action_id, "approved": True}, headers=auth_headers
    )
    assert resp.json()["status"] == "error" and "admin" in resp.json()["message"]


@pytest.mark.asyncio
async def test_destructive_calls_cannot_be_edited(client: AsyncClient, admin_headers, admin_user: User):
    action_id = await stage_tool_call(
        user_id=admin_user.id, conversation_id=None, tool_name="delete_feed", args={"feed_id": str(uuid.uuid4())}
    )
    resp = await client.post(
        "/api/ai/copilot/confirm",
        json={"action_id": action_id, "approved": True, "edited_params": {"feed_id": str(uuid.uuid4())}},
        headers=admin_headers,
    )
    assert resp.json()["status"] == "error" and "can't be edited" in resp.json()["message"]
    from app.services.redis_client import get_redis

    await (await get_redis()).delete(f"{STAGED_KEY_PREFIX}{action_id}")


# --------------------------------------------------------- a whole copilot turn


class _ToolCallingStub:
    """A provider whose model runs a read, proposes a write, then tries an admin tool, then answers."""

    supports_tools = True

    def __init__(self, write_name: str):
        self.write_name = write_name
        self.offered: list[str] = []
        self.results: dict[str, str] = {}

    def render_tools(self, defs):
        self.offered = [d["name"] for d in defs]
        return defs

    async def stream_agent(self, *, tools, tool_executor, **kw):
        for key, name, args in (
            ("read", "call_tool", {"tool": "get_feeds", "args": {"limit": 1}}),
            ("write", "create_campaign", {"name": self.write_name}),
            ("admin", "call_tool", {"tool": "merge_entities", "args": {}}),
        ):
            yield {"kind": "tool_call", "id": key, "name": name, "args": args}
            self.results[key] = await tool_executor(name, args)
            yield {"kind": "tool_result", "id": key, "status": "success", "summary": self.results[key][:200]}
        yield {"kind": "text", "text": "I proposed a campaign."}
        yield {"kind": "done", "usage": {"tokens_input": 1, "tokens_output": 1, "total_cost_usd": 0.0}}


@pytest.mark.asyncio
@pytest.mark.parametrize("provider_type", ["claude", "openai_compatible", "ollama"])
async def test_copilot_turn_stages_writes_on_every_in_process_provider(
    client: AsyncClient, auth_headers, test_user: User, db_session, monkeypatch, provider_type
):
    provider = AIProvider(name=f"{provider_type} site", provider_type=provider_type, base_url="https://ai.example.com")
    db_session.add(provider)
    await db_session.flush()
    task = AITask(name="copilot", display_name="Copilot", default_prompt_template="{{ question }}")
    db_session.add(task)
    await db_session.flush()
    db_session.add(AITaskAssignment(task_id=task.id, provider_id=provider.id, model_name="m"))
    await db_session.flush()

    name = f"turn-{uuid.uuid4().hex[:8]}"
    stub = _ToolCallingStub(name)
    monkeypatch.setattr(engine, "_get_provider_instance", lambda pm, **kw: stub)

    resp = await client.post("/api/ai/copilot/stream", json={"question": "make a campaign"}, headers=auth_headers)
    assert resp.status_code == 200, resp.text
    frames = [json.loads(line[5:]) for line in resp.text.splitlines() if line.startswith("data:")]
    confirms = [f for f in frames if f["type"] == "confirm_request"]

    # Reads run, the admin tool is refused when reached for, and the write waits.
    assert "merge_entities" not in stub.offered and "call_tool" in stub.offered
    assert "error" not in json.loads(stub.results["read"])
    assert "not available" in stub.results["admin"]
    assert json.loads(stub.results["write"])["status"] == "awaiting_confirmation"
    assert [c["tool_name"] for c in confirms] == ["create_campaign"]
    assert confirms[0]["proposed"] == {"name": name} and confirms[0]["destructive"] is False
    assert await _campaigns(db_session, name) == 0

    done = await client.post(
        "/api/ai/copilot/confirm",
        json={"action_id": confirms[0]["action_id"], "approved": True},
        headers=auth_headers,
    )
    assert done.json()["status"] == "executed", done.text
    assert await _campaigns(db_session, name) == 1


# ------------------------------------------------- a failing tool mid-turn


@pytest.mark.asyncio
async def test_a_failing_tool_does_not_lose_the_turn_or_its_staged_writes(
    client: AsyncClient, auth_headers, test_user: User, db_session, monkeypatch
):
    """A handler that aborts the transaction must not take the conversation and the cards with it."""
    from sqlalchemy import text

    import app.tools as tools

    async def broken(db, user_id, **kw):
        await db.execute(text("SELECT * FROM no_such_table"))

    monkeypatch.setitem(tools._TOOL_HANDLERS, "get_feeds", broken)

    provider = AIProvider(name="claude site", provider_type="claude", base_url="https://ai.example.com")
    db_session.add(provider)
    await db_session.flush()
    task = AITask(name="copilot", display_name="Copilot", default_prompt_template="{{ question }}")
    db_session.add(task)
    await db_session.flush()
    db_session.add(AITaskAssignment(task_id=task.id, provider_id=provider.id, model_name="m"))
    await db_session.flush()

    name = f"after-error-{uuid.uuid4().hex[:8]}"
    stub = _ToolCallingStub(name)
    monkeypatch.setattr(engine, "_get_provider_instance", lambda pm, **kw: stub)
    resp = await client.post("/api/ai/copilot/stream", json={"question": "go"}, headers=auth_headers)
    assert resp.status_code == 200, resp.text
    frames = [json.loads(line[5:]) for line in resp.text.splitlines() if line.startswith("data:")]

    assert "error" in json.loads(stub.results["read"])
    assert [f["tool_name"] for f in frames if f["type"] == "confirm_request"] == ["create_campaign"]
    done = next(f for f in frames if f["type"] == "done")
    conv = (
        await db_session.execute(select(AIConversation).where(AIConversation.id == uuid.UUID(done["conversation_id"])))
    ).scalar_one()
    assert conv.messages[-1]["content"] == "I proposed a campaign."


# ------------------------------------------------- what a card names


@pytest.mark.asyncio
async def test_a_staged_delete_names_what_it_deletes(test_user: User, db_session):
    from app.tools.gate import ToolGate

    campaign = Campaign(created_by=test_user.id, name="Operation Lantern", status="active", tlp_marking="TLP:GREEN")
    db_session.add(campaign)
    await db_session.flush()
    conversation_id = uuid.uuid4()
    g = ToolGate(
        db=db_session,
        user_id=test_user.id,
        role=test_user.role,
        offered=["delete_campaign"],
        conversation_id=conversation_id,
    )

    reply = json.loads(await g("delete_campaign", {"campaign_id": str(campaign.id)}))

    assert reply["status"] == "awaiting_confirmation"
    (row,) = await take_staged(conversation_id, test_user.id)
    assert row["targets"] == {"campaign_id": "campaign 'Operation Lantern'"}
    assert "delete" in row["preview"].lower()
    # Staging only previewed it.
    assert await _campaigns(db_session, "Operation Lantern") == 1


# ------------------------------------------------- background agentic tasks


@pytest.mark.asyncio
@pytest.mark.parametrize("provider_type", ["claude", "openai_compatible", "ollama"])
async def test_background_agentic_tasks_get_read_tools_through_the_gate(
    db_session, test_user: User, monkeypatch, provider_type
):
    from app.ai.engine import run_task
    from app.tools.gate import UnattendedGate, needs_confirmation

    provider = AIProvider(name=provider_type, provider_type=provider_type, base_url="https://ai.example.com")
    db_session.add(provider)
    await db_session.flush()
    task = AITask(name="entity_enrichment_research", display_name="Research", default_prompt_template="{{ text }}")
    db_session.add(task)
    await db_session.flush()
    db_session.add(AITaskAssignment(task_id=task.id, provider_id=provider.id, model_name="m"))
    await db_session.flush()

    seen: dict = {}

    class Stub:
        async def complete(self, **kw):
            seen.update(kw)
            from app.ai.providers.base import AIResponse

            return AIResponse(content="{}", raw_response={}, tokens_input=1, tokens_output=1, model="m", latency_ms=1)

    monkeypatch.setattr(engine, "_get_provider_instance", lambda pm, **kw: Stub())
    await run_task(db_session, test_user.id, task.name, variables={"text": "hi"})

    names = [t.get("name") or t["function"]["name"] for t in seen["tools"]]
    assert names and not [n for n in names if needs_confirmation(n)]
    assert isinstance(seen["tool_executor"], UnattendedGate)
    refused = json.loads(
        await seen["tool_executor"]("delete_campaign", {"campaign_id": "c", "confirmation_token": "t"})
    )
    assert "error" in refused
