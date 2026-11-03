"""The copilot's tool gate and the in-process tool loops behind it (no database).

Every provider runs model tool calls through app.tools.gate: admin tools never
reach a non-admin, confirmation tokens never come from a model, a tool that
wasn't offered is refused, and a write is staged for the user's click instead
of run. These tests hold that for the gate itself and for the Anthropic API and
OpenAI-compatible loops that call it.
"""

import json
import uuid
from types import SimpleNamespace

import httpx
import pytest

import app.tools.gate as gate
from app.ai.agent_loop import complete_with_agent
from app.ai.providers.base import AIResponse
from app.ai.providers.claude_provider import ClaudeProvider
from app.ai.providers.openai_provider import OpenAICompatibleProvider
from app.tools import ADMIN_TOOLS, MUTATING_TOOLS, TOOL_DEFINITIONS

_RealAsyncClient = httpx.AsyncClient


class FakeRedis:
    def __init__(self):
        self.kv: dict[str, str] = {}
        self.lists: dict[str, list[str]] = {}

    async def set(self, key, value, ex=None, nx=False):
        if nx and key in self.kv:
            return False
        self.kv[key] = value
        return True

    async def get(self, key):
        return self.kv.get(key)

    async def rpush(self, key, value):
        self.lists.setdefault(key, []).append(value)

    async def expire(self, key, ttl):
        return True

    async def lrange(self, key, start, end):
        return list(self.lists.get(key, []))

    async def delete(self, *keys):
        for k in keys:
            self.kv.pop(k, None)
            self.lists.pop(k, None)


@pytest.fixture
def fake_redis(monkeypatch):
    r = FakeRedis()

    async def _get():
        return r

    monkeypatch.setattr("app.services.redis_client.get_redis", _get)
    return r


@pytest.fixture
def ran(monkeypatch):
    """Record every tool the gate actually executes instead of touching the DB."""
    calls: list[tuple[str, dict]] = []

    async def fake_execute(name, args, db, user_id):
        calls.append((name, args))
        return json.dumps({"ok": name})

    monkeypatch.setattr(gate, "execute_tool", fake_execute)
    return calls


class _Savepoint:
    def __init__(self):
        self.is_active, self.done = True, None

    async def rollback(self):
        self.is_active, self.done = False, "rollback"

    async def commit(self):
        self.is_active, self.done = False, "commit"


class _Session:
    sync_session = SimpleNamespace(is_active=True)

    async def begin_nested(self):
        return _Savepoint()

    async def commit(self):
        pass

    async def rollback(self):
        pass


def _gate(role="user", offered=None, auto_approve=frozenset()):
    names = offered if offered is not None else [d["name"] for d in gate.model_tool_definitions(role=role)]
    return gate.ToolGate(
        db=_Session(),
        user_id=uuid.uuid4(),
        role=role,
        offered=names,
        conversation_id=uuid.uuid4(),
        auto_approve=auto_approve,
    )


# --------------------------------------------------------------------- offer


def test_non_admin_is_never_offered_an_admin_tool():
    offered = {d["name"] for d in gate.model_tool_definitions(role="user")}
    assert not offered & ADMIN_TOOLS
    assert ADMIN_TOOLS <= {d["name"] for d in gate.model_tool_definitions(role="admin")}


def test_no_schema_shown_to_a_model_has_a_confirmation_token():
    token_tools = gate.confirmation_token_tools()
    assert len(token_tools) >= 5  # deletes in delete.py, feeds_automation.py, workspace.py
    for d in gate.model_tool_definitions(role="admin"):
        assert "confirmation_token" not in json.dumps(d), d["name"]
        if d["name"] in token_tools:
            assert d["description"].endswith("the user confirms it with a click."), d["name"]
    # The registry itself keeps it, for the skill CLI's two-step flow.
    registry = {t["name"]: t for t in TOOL_DEFINITIONS}
    assert all("confirmation_token" in registry[n]["input_schema"]["properties"] for n in token_tools)


def test_allowlist_narrows_and_reads_only_drops_writes():
    names = ["search_entries", "create_note", "merge_entities"]
    assert {d["name"] for d in gate.model_tool_definitions(role="user", names=names)} == {
        "search_entries",
        "create_note",
    }
    reads = gate.model_tool_definitions(role="admin", include_writes=False)
    assert not {d["name"] for d in reads} & MUTATING_TOOLS


def test_wire_shapes():
    defs = gate.model_tool_definitions(role="user", names=["search_entries"])
    (fn,) = gate.function_specs(defs)
    assert fn["type"] == "function" and fn["function"]["name"] == "search_entries"
    (an,) = ClaudeProvider().render_tools(defs)
    assert set(an) == {"name", "description", "input_schema"}


# ---------------------------------------------------------------------- gate


@pytest.mark.asyncio
async def test_reads_run(fake_redis, ran):
    result = await _gate()("search_entries", {"query": "x"})
    assert json.loads(result) == {"ok": "search_entries"}
    assert ran == [("search_entries", {"query": "x"})]


@pytest.mark.asyncio
async def test_writes_are_staged_not_run(fake_redis, ran):
    g = _gate()
    result = json.loads(await g("create_note", {"title": "t", "content": "c"}))
    assert result["status"] == "awaiting_confirmation"
    assert ran == []
    staged = await gate.take_staged(g.conversation_id, g.user_id)
    assert [(s["tool_name"], s["args"]) for s in staged] == [("create_note", {"title": "t", "content": "c"})]
    assert staged[0]["action_id"] == result["action_id"]
    # Taking empties the list; another user's staged call is never handed over.
    assert await gate.take_staged(g.conversation_id, g.user_id) == []


@pytest.mark.asyncio
async def test_storing_reads_wait_for_confirmation_too(fake_redis, ran):
    result = json.loads(await _gate()("run_ai_task", {"task_name": "x"}))
    assert result["status"] == "awaiting_confirmation" and ran == []


@pytest.mark.asyncio
async def test_auto_approved_writes_run(fake_redis, ran):
    result = await _gate(auto_approve=frozenset({"create_note"}))("create_note", {"title": "t", "content": "c"})
    assert json.loads(result) == {"ok": "create_note"}


@pytest.mark.asyncio
async def test_a_tool_not_offered_is_refused(fake_redis, ran):
    result = json.loads(await _gate(offered=["search_entries"])("create_note", {"title": "t"}))
    assert "not available" in result["error"] and ran == []


@pytest.mark.asyncio
async def test_admin_tool_refused_for_non_admin_even_if_offered(fake_redis, ran):
    # Offer it anyway: the executor checks again.
    result = json.loads(await _gate(offered=["merge_entities"])("merge_entities", {}))
    assert "admin" in result["error"] and ran == []
    assert fake_redis.kv == {}


@pytest.mark.asyncio
async def test_model_supplied_confirmation_token_is_refused(fake_redis, ran):
    result = json.loads(await _gate(role="admin")("delete_feed", {"feed_id": "x", "confirmation_token": "abc"}))
    assert "confirmation_token" in result["error"] and ran == [] and fake_redis.kv == {}


def test_auto_approve_setting_never_covers_admin_tools_or_reads(monkeypatch):
    from app.config import settings

    monkeypatch.setattr(
        type(settings),
        "get",
        lambda self, key: "create_note, merge_entities,search_entries,delete_feed,  add_tag,delete_detection_rule",
    )
    # Admin tools, reads and two-step deletes never skip the click.
    assert gate.auto_approve_tools() == frozenset({"create_note", "add_tag"})
    allowed = set(gate.auto_approvable_tools())
    assert not allowed & ADMIN_TOOLS and not allowed & gate.confirmation_token_tools()
    assert "create_note" in allowed and "search_entries" not in allowed


# ----------------------------------------------------------------- confirmed


@pytest.mark.asyncio
async def test_confirmed_delete_gets_its_token_server_side(monkeypatch):
    calls: list[dict] = []

    async def fake_execute(name, args, db, user_id):
        calls.append(dict(args))
        if "confirmation_token" not in args:
            return json.dumps({"status": "confirmation_required", "confirmation_token": "server-made"})
        return json.dumps({"deleted": True})

    monkeypatch.setattr(gate, "execute_tool", fake_execute)
    out = await gate.run_confirmed(
        _Session(), user_id=uuid.uuid4(), role="user", tool_name="delete_detection_rule", args={"rule_id": "r"}
    )
    assert json.loads(out) == {"deleted": True}
    assert calls == [{"rule_id": "r"}, {"rule_id": "r", "confirmation_token": "server-made"}]


@pytest.mark.asyncio
async def test_confirmed_admin_tool_refused_for_non_admin(ran):
    out = json.loads(
        await gate.run_confirmed(_Session(), user_id=uuid.uuid4(), role="user", tool_name="merge_entities", args={})
    )
    assert "admin" in out["error"] and ran == []


# ------------------------------------------------------- Anthropic tool loop


def _block(**kw):
    return SimpleNamespace(**kw)


class _FakeStream:
    def __init__(self, message, texts):
        self.message, self.texts = message, texts

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    @property
    def text_stream(self):
        async def _gen():
            for t in self.texts:
                yield t

        return _gen()

    async def get_final_message(self):
        return self.message


class _FakeMessages:
    def __init__(self, rounds):
        self.rounds = list(rounds)
        self.requests: list[dict] = []

    def stream(self, **kwargs):
        self.requests.append(json.loads(json.dumps(kwargs, default=str)))
        message, texts = self.rounds.pop(0)
        return _FakeStream(message, texts)


def _usage():
    return SimpleNamespace(input_tokens=10, output_tokens=5, cache_read_input_tokens=0, cache_creation_input_tokens=0)


def _claude_with(rounds):
    provider = ClaudeProvider(api_key="sk-ant-api03-test")
    messages = _FakeMessages(rounds)
    provider._client = SimpleNamespace(messages=messages, with_options=lambda **kw: provider._client)
    return provider, messages


@pytest.mark.asyncio
async def test_anthropic_loop_runs_offered_reads_and_refuses_the_rest(fake_redis, ran):
    tool_round = SimpleNamespace(
        content=[
            _block(type="text", text="Looking."),
            _block(type="tool_use", id="t1", name="search_entries", input={"query": "x"}),
            _block(type="tool_use", id="t2", name="merge_entities", input={}),
            _block(type="tool_use", id="t3", name="create_note", input={"title": "n"}),
        ],
        stop_reason="tool_use",
        usage=_usage(),
    )
    answer = SimpleNamespace(content=[_block(type="text", text="Done.")], stop_reason="end_turn", usage=_usage())
    provider, messages = _claude_with([(tool_round, ["Looking."]), (answer, ["Done."])])
    g = _gate()
    tools = provider.render_tools(gate.model_tool_definitions(role="user"))
    events = [ev async for ev in provider.stream_agent(prompt="q", tools=tools, tool_executor=g)]

    kinds = [e["kind"] for e in events]
    assert kinds.count("tool_call") == 3 and kinds[-1] == "done"
    assert ran == [("search_entries", {"query": "x"})]
    results = {e["id"]: e for e in events if e["kind"] == "tool_result"}
    assert results["t2"]["status"] == "error" and "not available" in results["t2"]["summary"]
    assert "awaiting_confirmation" in results["t3"]["summary"]
    # The tool results went back as one user turn of tool_result blocks.
    sent = messages.requests[1]["messages"][-1]["content"]
    assert [b["tool_use_id"] for b in sent] == ["t1", "t2", "t3"]
    assert sent[1]["is_error"] is True
    # The tool list is cached with the system prompt.
    assert messages.requests[0]["tools"][-1]["cache_control"] == {"type": "ephemeral"}
    assert events[-1]["usage"]["tokens_input"] == 20


# ---------------------------------------------------- OpenAI-compatible loop


def _mock_httpx(monkeypatch, handler):
    monkeypatch.setattr(
        httpx, "AsyncClient", lambda **kw: _RealAsyncClient(transport=httpx.MockTransport(handler), **kw)
    )


def _chat(message: dict, finish="stop") -> dict:
    return {
        "choices": [{"message": message, "finish_reason": finish}],
        "usage": {"prompt_tokens": 3, "completion_tokens": 2},
    }


@pytest.mark.asyncio
async def test_openai_loop_runs_reads_and_stages_writes(monkeypatch, fake_redis, ran):
    bodies: list[dict] = []
    replies = [
        _chat(
            {
                "content": "",
                "tool_calls": [
                    {
                        "id": "c1",
                        "type": "function",
                        "function": {"name": "search_entries", "arguments": '{"query":"x"}'},
                    },
                    {"id": "c2", "type": "function", "function": {"name": "create_note", "arguments": {"title": "n"}}},
                ],
            },
            finish="tool_calls",
        ),
        _chat({"content": "Proposed a note."}),
    ]

    def handler(request):
        bodies.append(json.loads(request.content))
        return httpx.Response(200, json=replies.pop(0))

    _mock_httpx(monkeypatch, handler)
    provider = OpenAICompatibleProvider(base_url="https://api.openai.com/v1", config={"default_model": "gpt-x"})
    g = _gate()
    tools = provider.render_tools(gate.model_tool_definitions(role="user"))
    events = [ev async for ev in provider.stream_agent(prompt="q", tools=tools, tool_executor=g)]

    assert ran == [("search_entries", {"query": "x"})]
    assert [s["tool_name"] for s in await gate.take_staged(g.conversation_id, g.user_id)] == ["create_note"]
    assert bodies[0]["tools"] and bodies[1]["messages"][-1] == {
        "role": "tool",
        "tool_call_id": "c2",
        "content": bodies[1]["messages"][-1]["content"],
    }
    assert "".join(e["text"] for e in events if e["kind"] == "text") == "Proposed a note."
    assert events[-1]["usage"] == {"tokens_input": 6, "tokens_output": 4, "total_cost_usd": None}


@pytest.mark.asyncio
async def test_openai_server_that_rejects_tools_answers_without_them(monkeypatch):
    bodies: list[dict] = []

    def handler(request):
        body = json.loads(request.content)
        bodies.append(body)
        if "tools" in body:
            return httpx.Response(400, json={"error": "tools are not supported by this model"})
        return httpx.Response(200, json=_chat({"content": "plain answer"}))

    _mock_httpx(monkeypatch, handler)
    provider = OpenAICompatibleProvider(base_url="http://localhost:1234/v1", config={"default_model": "m"})
    tools = provider.render_tools(gate.model_tool_definitions(role="user", names=["search_entries"]))

    async def never(name, args):
        raise AssertionError("no tool should run")

    events = [e async for e in provider.stream_agent(prompt="q", tools=tools, tool_executor=never)]
    text = "".join(e["text"] for e in events if e["kind"] == "text")
    assert "didn't accept tools" in text and text.endswith("plain answer")
    assert "tools" not in bodies[-1]


def test_openai_tools_can_be_turned_off_per_provider():
    off = OpenAICompatibleProvider(base_url="http://localhost:1234/v1", config={"tools_enabled": False})
    assert off.supports_tools is False


# ------------------------------------------------------------ engine collapse


@pytest.mark.asyncio
async def test_complete_with_agent_restates_the_answer_as_json():
    class Fake:
        async def stream_agent(self, **kw):
            await kw["tool_executor"]("search_entries", {"query": "x"})
            yield {"kind": "text", "text": "draft"}
            yield {"kind": "done", "usage": {"tokens_input": 1, "tokens_output": 1, "total_cost_usd": None}}

        async def complete(self, **kw):
            self.final_prompt = kw["prompt"]
            assert kw["response_format"] == {"type": "object"}
            return AIResponse(
                content='{"a": 1}', raw_response={}, tokens_input=2, tokens_output=3, model="m", latency_ms=1
            )

    async def executor(name, args):
        return '{"hits": ["evidence"]}'

    fake = Fake()
    out = await complete_with_agent(
        fake,
        prompt="q",
        system=None,
        model="m",
        tools=[{"type": "function"}],
        tool_executor=executor,
        temperature=0.0,
        max_tokens=100,
        timeout_seconds=None,
        response_format={"type": "object"},
    )
    assert out.content == '{"a": 1}' and (out.tokens_input, out.tokens_output) == (3, 4)
    assert "evidence" in fake.final_prompt and "draft" in fake.final_prompt


# ------------------------------------------------- find_tools / call_tool


def _meta_gate(role="user"):
    from app.api.copilot import _copilot_tool_plan

    direct, reachable = _copilot_tool_plan(role, {})
    g = _gate(role=role, offered=[d["name"] for d in direct])
    g.reachable = reachable
    g.reachable_names = frozenset(d["name"] for d in reachable)
    return g, direct, reachable


def test_default_plan_fits_every_provider():
    """Few enough tools to send to OpenAI (128 max) and a local model, yet every allowed tool is reachable."""
    for role in ("user", "admin"):
        direct, reachable = _meta_gate(role)[1:]
        names = {d["name"] for d in direct}
        assert {gate.FIND_TOOLS, gate.CALL_TOOL} <= names
        assert len(direct) < 40
        assert len(json.dumps(gate.function_specs(direct))) < 30_000
        assert {d["name"] for d in reachable} == {d["name"] for d in gate.model_tool_definitions(role=role)}
    assert not {d["name"] for d in _meta_gate("user")[2]} & ADMIN_TOOLS


def test_an_override_offers_exactly_its_tools():
    from app.api.copilot import _copilot_tool_plan

    direct, reachable = _copilot_tool_plan("user", {"agent_tools": ["search_entries", "merge_entities"]})
    assert [d["name"] for d in direct] == ["search_entries"] == [d["name"] for d in reachable]
    # The old key still works.
    direct, _ = _copilot_tool_plan("user", {"ollama_tools": ["get_cve"]})
    assert [d["name"] for d in direct] == ["get_cve"]


@pytest.mark.asyncio
async def test_find_tools_lists_and_describes_only_what_the_user_may_run(fake_redis, ran):
    g, _, _ = _meta_gate()
    listed = json.loads(await g(gate.FIND_TOOLS, {}))["tools"]
    assert "get_feeds" in listed and "merge_entities" not in listed
    found = json.loads(await g(gate.FIND_TOOLS, {"query": "delete detection rule"}))["tools"]
    assert found[0]["name"] == "delete_detection_rule" and found[0]["changes_data"] is True
    assert "confirmation_token" not in json.dumps(found)
    assert ran == []


@pytest.mark.asyncio
async def test_call_tool_goes_through_the_same_gate(fake_redis, ran):
    g, _, _ = _meta_gate()
    assert json.loads(await g(gate.CALL_TOOL, {"tool": "get_feeds", "args": {"limit": 1}})) == {"ok": "get_feeds"}
    staged = json.loads(await g(gate.CALL_TOOL, {"tool": "delete_detection_rule", "args": '{"rule_id": "r"}'}))
    assert staged["status"] == "awaiting_confirmation"
    # Not reachable for a non-admin at all.
    assert "not available" in json.loads(await g(gate.CALL_TOOL, {"tool": "merge_entities", "args": {}}))["error"]
    # A non-admin delete, so the refusal is about the token, not the role.
    token = json.loads(
        await g(gate.CALL_TOOL, {"tool": "delete_detection_rule", "args": {"rule_id": "r", "confirmation_token": "x"}})
    )
    assert "confirmation_token" in token["error"]
    nested = json.loads(await g(gate.CALL_TOOL, {"tool": gate.CALL_TOOL, "args": {"tool": "get_feeds"}}))
    assert "error" in nested
    # Staging the delete ran only its harmless first step (no token), for the card's preview.
    assert ran == [("get_feeds", {"limit": 1}), ("delete_detection_rule", {"rule_id": "r"})]
    (row,) = await gate.take_staged(g.conversation_id, g.user_id)
    assert row["tool_name"] == "delete_detection_rule" and row["preview"]


def test_read_only_plan_has_no_writes():
    """The docs-page copilot shows no confirm cards, so it is offered reads only."""
    from app.api.copilot import _copilot_tool_plan

    for config in ({}, {"agent_tools": ["search_entries", "create_note"]}):
        direct, reachable = _copilot_tool_plan("admin", config, read_only=True)
        names = {d["name"] for d in direct} | {d["name"] for d in reachable}
        assert not {n for n in names if gate.needs_confirmation(n)}
        assert "search_entries" in names


# --------------------------------------------------- Anthropic web search


@pytest.mark.asyncio
async def test_anthropic_web_search_is_offered_and_a_paused_turn_resumes():
    search_block = _block(type="server_tool_use", id="s1", name="web_search", input={"query": "x"})
    search_block.model_dump = lambda exclude_none=True: {
        "type": "server_tool_use",
        "id": "s1",
        "name": "web_search",
        "input": {"query": "x"},
    }
    paused = SimpleNamespace(content=[search_block], stop_reason="pause_turn", usage=_usage())
    answer = SimpleNamespace(content=[_block(type="text", text="Found it.")], stop_reason="end_turn", usage=_usage())
    provider, messages = _claude_with([(paused, []), (answer, ["Found it."])])

    events = [ev async for ev in provider.stream_agent(prompt="research", web_search=True)]

    assert messages.requests[0]["tools"][0]["type"] == "web_search_20250305"
    # The paused turn went back as the assistant's content, server block included.
    assert messages.requests[1]["messages"][-1] == {
        "role": "assistant",
        "content": [{"type": "server_tool_use", "id": "s1", "name": "web_search", "input": {"query": "x"}}],
    }
    assert "".join(e["text"] for e in events if e["kind"] == "text") == "Found it."


def test_research_task_routing_rules():
    from app.ai.capabilities import provider_type_supports_web_search, task_requires_web_search

    assert task_requires_web_search("entity_enrichment_research")
    assert provider_type_supports_web_search("claude") and provider_type_supports_web_search("claude_code")
    assert not provider_type_supports_web_search("ollama")
    assert not provider_type_supports_web_search("openai_compatible")


# ------------------------------------------------ engine (unattended) gate


@pytest.mark.asyncio
async def test_unattended_gate_keeps_the_copilot_refusals(monkeypatch, ran):
    """Background agentic tasks have nobody to click Confirm: same refusals, no staging."""
    defs = gate.model_tool_definitions(role="user", include_writes=False)
    g = gate.UnattendedGate(db=_Session(), user_id=uuid.uuid4(), role="user", offered=[d["name"] for d in defs])

    assert json.loads(await g("search_entries", {})) == {"ok": "search_entries"}
    assert "not available" in json.loads(await g("create_note", {"title": "t"}))["error"]
    assert "not available" in json.loads(await g("run_ai_task", {}))["error"]  # stores results
    assert "not available" in json.loads(await g("merge_entities", {}))["error"]  # never offered to a user
    # Even with writes opted in, a model can't confirm its own delete.
    writes = gate.UnattendedGate(db=_Session(), user_id=uuid.uuid4(), role="system", offered=["delete_campaign"])
    refused = json.loads(await writes("delete_campaign", {"campaign_id": "c", "confirmation_token": "t"}))
    assert "confirmation_token" in refused["error"]
    assert ran == [("search_entries", {})]


class _NestingSession(_Session):
    def __init__(self):
        self.savepoints: list[_Savepoint] = []
        self.full_rollbacks = 0

    async def begin_nested(self):
        sp = _Savepoint()
        self.savepoints.append(sp)
        return sp

    async def rollback(self):
        self.full_rollbacks += 1


@pytest.mark.asyncio
async def test_a_failing_tool_rolls_back_only_its_savepoint(monkeypatch):
    """A whole-session rollback would expire the copilot's conversation and lose the turn."""
    results = iter(['{"error": "boom"}', '{"ok": 1}'])

    async def fake_execute(name, args, db, user_id):
        return next(results)

    monkeypatch.setattr(gate, "execute_tool", fake_execute)
    db = _NestingSession()
    await gate.execute_isolated(db, "get_feeds", {}, uuid.uuid4())
    await gate.execute_isolated(db, "get_feeds", {}, uuid.uuid4())
    assert [sp.done for sp in db.savepoints] == ["rollback", "commit"]
    assert db.full_rollbacks == 0
