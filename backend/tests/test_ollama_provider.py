"""Unit tests for the Ollama provider (mocked HTTP transport)."""

import json

import httpx
import pytest

from app.ai.providers.claude_code_provider import QuotaExhaustedError
from app.ai.providers.ollama_provider import OllamaProvider

BASE_URL = "https://ollama.example.com"

# Captured before any monkeypatching so the factory below doesn't recurse.
_RealAsyncClient = httpx.AsyncClient


def _mock_client_factory(handler):
    """Return a stand-in for httpx.AsyncClient that routes through a MockTransport."""

    def factory(**kwargs):
        kwargs.pop("transport", None)
        return _RealAsyncClient(transport=httpx.MockTransport(handler), **kwargs)

    return factory


def _chat_response(content: str = "hello", model: str = "llama3.1:8b") -> dict:
    return {
        "model": model,
        "message": {"role": "assistant", "content": content},
        "done": True,
        "done_reason": "stop",
        "total_duration": 123456789,
        "prompt_eval_count": 42,
        "eval_count": 17,
    }


@pytest.mark.asyncio
async def test_complete_parses_response_and_reports_zero_cost(monkeypatch):
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["payload"] = json.loads(request.content)
        captured["auth"] = request.headers.get("authorization")
        return httpx.Response(200, json=_chat_response())

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))
    provider = OllamaProvider(base_url=BASE_URL, api_key="tok123", config={})

    resp = await provider.complete(
        prompt="user text",
        system="system text",
        temperature=0.2,
        max_tokens=512,
        response_format={"type": "object", "properties": {"x": {"type": "string"}}},
        model="llama3.1:8b",
    )

    assert captured["url"] == f"{BASE_URL}/api/chat"
    assert captured["auth"] == "Bearer tok123"
    payload = captured["payload"]
    assert payload["model"] == "llama3.1:8b"
    assert payload["stream"] is False
    assert payload["messages"] == [
        {"role": "system", "content": "system text"},
        {"role": "user", "content": "user text"},
    ]
    assert payload["options"]["temperature"] == 0.2
    assert payload["options"]["num_predict"] == 512
    assert payload["options"]["num_ctx"] == 4096  # short prompt → floor
    assert payload["format"]["type"] == "object"
    # Thinking disabled by default; schema properties forced required
    assert payload["think"] is False
    assert payload["format"]["required"] == ["x"]

    assert resp.content == "hello"
    assert resp.tokens_input == 42
    assert resp.tokens_output == 17
    assert resp.model == "llama3.1:8b"
    assert resp.cost_usd == 0.0


@pytest.mark.asyncio
async def test_complete_omits_system_and_format_when_absent(monkeypatch):
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["payload"] = json.loads(request.content)
        captured["auth"] = request.headers.get("authorization")
        return httpx.Response(200, json=_chat_response())

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))
    provider = OllamaProvider(base_url=BASE_URL, config={})

    await provider.complete(prompt="just user", model="llama3.1:8b")

    payload = captured["payload"]
    assert payload["messages"] == [{"role": "user", "content": "just user"}]
    assert "format" not in payload
    assert captured["auth"] is None  # no api_key → no Authorization header


@pytest.mark.asyncio
async def test_complete_requires_model():
    provider = OllamaProvider(base_url=BASE_URL, config={})
    with pytest.raises(ValueError, match="model"):
        await provider.complete(prompt="hi")


@pytest.mark.asyncio
async def test_complete_default_model_from_config(monkeypatch):
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["payload"] = json.loads(request.content)
        return httpx.Response(200, json=_chat_response(model="qwen2.5:14b"))

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))
    provider = OllamaProvider(base_url=BASE_URL, config={"default_model": "qwen2.5:14b"})

    resp = await provider.complete(prompt="hi")
    assert captured["payload"]["model"] == "qwen2.5:14b"
    assert resp.model == "qwen2.5:14b"


@pytest.mark.asyncio
async def test_think_config_override_and_nested_required(monkeypatch):
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["payload"] = json.loads(request.content)
        return httpx.Response(200, json=_chat_response())

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))
    provider = OllamaProvider(base_url=BASE_URL, config={"think": True})

    schema = {
        "type": "object",
        "properties": {
            "items": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {"a": {"type": "string"}, "b": {"type": "number"}},
                },
            },
            "note": {"type": "string"},
        },
        "required": ["note"],  # explicit list preserved
    }
    await provider.complete(prompt="hi", model="llama3.1:8b", response_format=schema)

    payload = captured["payload"]
    assert payload["think"] is True
    assert payload["format"]["required"] == ["note"]
    nested = payload["format"]["properties"]["items"]["items"]
    assert sorted(nested["required"]) == ["a", "b"]


@pytest.mark.asyncio
async def test_num_ctx_autosizes_to_fit_prompt(monkeypatch):
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["payload"] = json.loads(request.content)
        return httpx.Response(200, json=_chat_response())

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))

    # ~30k chars ≈ 10k estimated tokens + 4096 output → well above the 4096 floor
    provider = OllamaProvider(base_url=BASE_URL, config={})
    await provider.complete(prompt="x" * 30_000, model="llama3.1:8b")
    grown = captured["payload"]["options"]["num_ctx"]
    assert 14_000 < grown <= 32_768

    # Cap respected for absurd prompts
    await provider.complete(prompt="x" * 500_000, model="llama3.1:8b")
    assert captured["payload"]["options"]["num_ctx"] == 32_768

    # Custom cap
    provider = OllamaProvider(base_url=BASE_URL, config={"num_ctx_max": 8192})
    await provider.complete(prompt="x" * 30_000, model="llama3.1:8b")
    assert captured["payload"]["options"]["num_ctx"] == 8192

    # Explicit num_ctx disables auto-sizing entirely
    provider = OllamaProvider(base_url=BASE_URL, config={"num_ctx": 16384})
    await provider.complete(prompt="hi", model="llama3.1:8b")
    assert captured["payload"]["options"]["num_ctx"] == 16384


@pytest.mark.asyncio
async def test_model_overrides_layer_over_provider_config(monkeypatch):
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["payload"] = json.loads(request.content)
        return httpx.Response(200, json=_chat_response())

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))
    provider = OllamaProvider(
        base_url=BASE_URL,
        config={
            "num_ctx": 8192,
            "think": False,
            "model_overrides": {"qwen3.5:9b": {"think": True, "num_ctx": 16384}},
        },
    )

    # Overridden model gets its own knobs
    await provider.complete(prompt="hi", model="qwen3.5:9b")
    assert captured["payload"]["think"] is True
    assert captured["payload"]["options"]["num_ctx"] == 16384

    # Other models fall through to provider-level config
    await provider.complete(prompt="hi", model="llama3.1:8b")
    assert captured["payload"]["think"] is False
    assert captured["payload"]["options"]["num_ctx"] == 8192


@pytest.mark.asyncio
async def test_complete_retries_without_think_on_400(monkeypatch):
    calls: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        calls.append(payload)
        if "think" in payload:
            return httpx.Response(400, json={"error": '"think" is not supported by this model'})
        return httpx.Response(200, json=_chat_response())

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))
    provider = OllamaProvider(base_url=BASE_URL, config={})

    resp = await provider.complete(prompt="hi", model="llama3.1:8b")
    assert resp.content == "hello"
    assert len(calls) == 2
    assert "think" not in calls[1]


@pytest.mark.asyncio
async def test_complete_429_raises_quota_exhausted(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, text="slow down")

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))
    provider = OllamaProvider(base_url=BASE_URL, config={})

    with pytest.raises(QuotaExhaustedError):
        await provider.complete(prompt="hi", model="llama3.1:8b")


@pytest.mark.asyncio
async def test_stream_complete_yields_chunks(monkeypatch):
    lines = [
        json.dumps({"message": {"role": "assistant", "content": "Hel"}, "done": False}),
        json.dumps({"message": {"role": "assistant", "content": "lo"}, "done": False}),
        json.dumps(
            {"message": {"role": "assistant", "content": ""}, "done": True, "prompt_eval_count": 9, "eval_count": 2}
        ),
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="\n".join(lines) + "\n")

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))
    provider = OllamaProvider(base_url=BASE_URL, config={})

    chunks = [c async for c in provider.stream_complete(prompt="hi", model="llama3.1:8b")]
    assert chunks == ["Hel", "lo"]
    # The final chunk's counts are kept so a streamed turn still counts.
    assert provider.last_stream_usage == {"tokens_input": 9, "tokens_output": 2, "cost_usd": 0.0}


@pytest.mark.asyncio
async def test_list_models_parses_tags(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/tags"
        return httpx.Response(
            200,
            json={"models": [{"name": "qwen2.5:14b"}, {"name": "llama3.1:8b"}]},
        )

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))
    provider = OllamaProvider(base_url=BASE_URL, config={})

    assert await provider.list_models() == ["llama3.1:8b", "qwen2.5:14b"]


@pytest.mark.asyncio
async def test_check_health(monkeypatch):
    def ok_handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/version"
        return httpx.Response(200, json={"version": "0.5.7"})

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(ok_handler))
    provider = OllamaProvider(base_url=BASE_URL, config={})
    assert await provider.check_health() is True

    def down_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(down_handler))
    provider = OllamaProvider(base_url=BASE_URL, config={})
    assert await provider.check_health() is False


@pytest.mark.asyncio
async def test_stream_agent_runs_tool_loop(monkeypatch):
    """A tool_call round is executed, fed back, then a final answer is emitted."""
    rounds: list[dict] = []
    executed: list[tuple[str, dict]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        rounds.append(payload)
        # First round: model asks for a tool. Second round: final answer.
        if len(rounds) == 1:
            return httpx.Response(
                200,
                json={
                    "model": "llama3.1:8b",
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [{"function": {"name": "search_entries", "arguments": {"query": "apt29"}}}],
                    },
                    "done": True,
                    "prompt_eval_count": 10,
                    "eval_count": 5,
                },
            )
        return httpx.Response(
            200,
            json={
                "model": "llama3.1:8b",
                "message": {"role": "assistant", "content": "Found 3 entries about APT29."},
                "done": True,
                "prompt_eval_count": 20,
                "eval_count": 8,
            },
        )

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))
    provider = OllamaProvider(base_url=BASE_URL, config={})

    async def executor(name: str, args: dict) -> str:
        executed.append((name, args))
        return json.dumps({"results": ["e1", "e2", "e3"]})

    tools = [
        {
            "type": "function",
            "function": {
                "name": "search_entries",
                "description": "search",
                "parameters": {"type": "object", "properties": {"query": {"type": "string"}}},
            },
        }
    ]

    events = [
        ev
        async for ev in provider.stream_agent(
            prompt="Find APT29 activity",
            system="You are a copilot.",
            model="llama3.1:8b",
            tools=tools,
            tool_executor=executor,
        )
    ]

    kinds = [e["kind"] for e in events]
    assert kinds == ["tool_call", "tool_result", "text", "done"]
    # The tool was actually executed with the model-supplied args.
    assert executed == [("search_entries", {"query": "apt29"})]
    # The second round carried the tool result back as a tool-role message.
    second = rounds[1]
    assert second["messages"][-1]["role"] == "tool"
    assert "e1" in second["messages"][-1]["content"]
    # Tools spec forwarded on every round.
    assert rounds[0]["tools"] == tools
    # Final answer + accumulated usage.
    assert events[2]["text"] == "Found 3 entries about APT29."
    done = events[-1]
    assert done["usage"]["tokens_input"] == 30
    assert done["usage"]["tokens_output"] == 13
    assert done["usage"]["total_cost_usd"] == 0.0


@pytest.mark.asyncio
async def test_complete_with_tools_collapses_to_response(monkeypatch):
    """complete() with tools returns the final answer text as an AIResponse."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "model": "llama3.1:8b",
                "message": {"role": "assistant", "content": "no tools needed"},
                "done": True,
                "prompt_eval_count": 7,
                "eval_count": 3,
            },
        )

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))
    provider = OllamaProvider(base_url=BASE_URL, config={})

    async def executor(name: str, args: dict) -> str:  # never called here
        return "{}"

    resp = await provider.complete(
        prompt="hi",
        model="llama3.1:8b",
        tools=[{"type": "function", "function": {"name": "x", "description": "", "parameters": {}}}],
        tool_executor=executor,
    )
    assert resp.content == "no tools needed"
    assert resp.tokens_input == 7
    assert resp.cost_usd == 0.0


@pytest.mark.asyncio
async def test_stream_agent_tool_iteration_cap(monkeypatch):
    """A model that never stops calling tools is bounded by max_tool_iterations."""

    def handler(request: httpx.Request) -> httpx.Response:
        # Always ask for a tool — never a final answer.
        return httpx.Response(
            200,
            json={
                "model": "llama3.1:8b",
                "message": {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [{"function": {"name": "get_search_facets", "arguments": {}}}],
                },
                "done": True,
                "prompt_eval_count": 1,
                "eval_count": 1,
            },
        )

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))
    provider = OllamaProvider(base_url=BASE_URL, config={"max_tool_iterations": 3})

    calls = 0

    async def executor(name: str, args: dict) -> str:
        nonlocal calls
        calls += 1
        return "{}"

    events = [
        ev
        async for ev in provider.stream_agent(
            prompt="loop",
            model="llama3.1:8b",
            tools=[
                {"type": "function", "function": {"name": "get_search_facets", "description": "", "parameters": {}}}
            ],
            tool_executor=executor,
        )
    ]
    # 3 iterations, each one tool call; ends with a done (no final text).
    assert calls == 3
    assert events[-1]["kind"] == "done"
    assert "text" not in [e["kind"] for e in events]


@pytest.mark.asyncio
async def test_stream_agent_degrades_when_model_rejects_tools(monkeypatch):
    """A model without tool support (Ollama 400) falls back to a text-only answer."""
    rounds: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        rounds.append(payload)
        if "tools" in payload:
            return httpx.Response(400, json={"error": "registry.ollama.ai/library/gemma2 does not support tools"})
        return httpx.Response(
            200,
            json={
                "model": "gemma2:9b",
                "message": {"role": "assistant", "content": "plain answer"},
                "done": True,
                "prompt_eval_count": 5,
                "eval_count": 2,
            },
        )

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))
    provider = OllamaProvider(base_url=BASE_URL, config={})

    async def executor(name: str, args: dict) -> str:
        raise AssertionError("executor must not be called when tools are rejected")

    events = [
        ev
        async for ev in provider.stream_agent(
            prompt="hi",
            model="gemma2:9b",
            tools=[{"type": "function", "function": {"name": "x", "description": "", "parameters": {}}}],
            tool_executor=executor,
        )
    ]
    # First request carried tools (rejected), retry without succeeded.
    assert "tools" in rounds[0] and "tools" not in rounds[1]
    kinds = [e["kind"] for e in events]
    assert kinds == ["text", "done"]
    assert events[0]["text"] == "plain answer"


@pytest.mark.asyncio
async def test_complete_with_tools_final_schema_round(monkeypatch):
    """With response_format, a final format-constrained round re-expresses the answer as JSON."""
    rounds: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        rounds.append(payload)
        if len(rounds) == 1:  # tool round
            return httpx.Response(
                200,
                json={
                    "model": "llama3.1:8b",
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [{"function": {"name": "get_cve", "arguments": {"cve_id": "c1"}}}],
                    },
                    "done": True,
                    "prompt_eval_count": 5,
                    "eval_count": 2,
                },
            )
        if len(rounds) == 2:  # unconstrained final answer
            return httpx.Response(
                200,
                json={
                    "model": "llama3.1:8b",
                    "message": {"role": "assistant", "content": "CVE-2026-1 is critical."},
                    "done": True,
                    "prompt_eval_count": 5,
                    "eval_count": 3,
                },
            )
        # constrained formatting round
        return httpx.Response(
            200,
            json={
                "model": "llama3.1:8b",
                "message": {"role": "assistant", "content": '{"severity": "critical"}'},
                "done": True,
                "prompt_eval_count": 8,
                "eval_count": 4,
            },
        )

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))
    provider = OllamaProvider(base_url=BASE_URL, config={})

    async def executor(name: str, args: dict) -> str:
        return json.dumps({"cvss": 9.8})

    schema = {"type": "object", "properties": {"severity": {"type": "string"}}}
    resp = await provider.complete(
        prompt="how bad is CVE-2026-1?",
        model="llama3.1:8b",
        response_format=schema,
        tools=[{"type": "function", "function": {"name": "get_cve", "description": "", "parameters": {}}}],
        tool_executor=executor,
    )

    # Tool rounds ran unconstrained; only the last round carried `format`.
    assert "format" not in rounds[0] and "format" not in rounds[1]
    assert rounds[2]["format"]["required"] == ["severity"]
    assert "tools" not in rounds[2]
    # Schema-valid JSON is the final content; usage sums all three rounds.
    assert json.loads(resp.content) == {"severity": "critical"}
    assert resp.tokens_input == 18
    assert resp.tokens_output == 9


@pytest.mark.asyncio
async def test_stream_agent_emits_intermediate_narration(monkeypatch):
    """Content emitted alongside tool_calls is surfaced as a text event."""
    rounds: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        rounds.append(json.loads(request.content))
        if len(rounds) == 1:
            return httpx.Response(
                200,
                json={
                    "model": "llama3.1:8b",
                    "message": {
                        "role": "assistant",
                        "content": "Let me look that up.",
                        "tool_calls": [{"function": {"name": "get_search_facets", "arguments": {}}}],
                    },
                    "done": True,
                    "prompt_eval_count": 1,
                    "eval_count": 1,
                },
            )
        return httpx.Response(
            200,
            json={
                "model": "llama3.1:8b",
                "message": {"role": "assistant", "content": "Done."},
                "done": True,
                "prompt_eval_count": 1,
                "eval_count": 1,
            },
        )

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))
    provider = OllamaProvider(base_url=BASE_URL, config={})

    async def executor(name: str, args: dict) -> str:
        return "{}"

    events = [
        ev
        async for ev in provider.stream_agent(
            prompt="hi",
            model="llama3.1:8b",
            tools=[
                {"type": "function", "function": {"name": "get_search_facets", "description": "", "parameters": {}}}
            ],
            tool_executor=executor,
        )
    ]
    kinds = [e["kind"] for e in events]
    assert kinds == ["text", "tool_call", "tool_result", "text", "done"]
    assert events[0]["text"] == "Let me look that up.\n\n"


def test_ollama_tool_specs_shape_and_read_only():
    from app.tools import MUTATING_TOOLS, ollama_tool_specs, read_only_tool_definitions

    specs = ollama_tool_specs(read_only=True)
    assert specs, "expected at least one read-only tool"
    first = specs[0]
    assert first["type"] == "function"
    assert set(first["function"]) == {"name", "description", "parameters"}
    assert first["function"]["parameters"]["type"] == "object"
    # No mutating tool leaks into the read-only spec set.
    names = {s["function"]["name"] for s in specs}
    assert names.isdisjoint(MUTATING_TOOLS)
    assert len(specs) == len(read_only_tool_definitions())

    # Allowlist filtering narrows the set.
    narrowed = ollama_tool_specs(["search_entries"], read_only=True)
    assert [s["function"]["name"] for s in narrowed] == ["search_entries"]


def test_copilot_default_ollama_tools_all_resolve():
    """Every curated copilot tool name must exist in the registry (drift guard).

    ollama_tool_specs silently ignores unknown names, so a registry rename
    would otherwise shrink the copilot's toolbox without any error.
    """
    from app.api.copilot import _DEFAULT_OLLAMA_TOOLS
    from app.tools import ollama_tool_specs

    specs = ollama_tool_specs(_DEFAULT_OLLAMA_TOOLS, read_only=True)
    resolved = {s["function"]["name"] for s in specs}
    assert resolved == set(_DEFAULT_OLLAMA_TOOLS)


@pytest.mark.asyncio
async def test_agent_context_sizing_counts_tool_schemas(monkeypatch):
    """num_ctx for a tool round must budget for the serialized tool specs."""
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["payload"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "model": "llama3.1:8b",
                "message": {"role": "assistant", "content": "ok"},
                "done": True,
                "prompt_eval_count": 1,
                "eval_count": 1,
            },
        )

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))
    provider = OllamaProvider(base_url=BASE_URL, config={})

    async def executor(name: str, args: dict) -> str:
        return "{}"

    # ~24k chars of tool schema ≈ 8k tokens — without counting it the short
    # prompt would sit at the 4096 floor.
    fat_tools = [
        {
            "type": "function",
            "function": {"name": f"t{i}", "description": "x" * 1200, "parameters": {"type": "object"}},
        }
        for i in range(20)
    ]

    _ = [
        ev
        async for ev in provider.stream_agent(prompt="hi", model="llama3.1:8b", tools=fat_tools, tool_executor=executor)
    ]
    assert captured["payload"]["options"]["num_ctx"] > 4096


def test_engine_factory_routes_ollama():
    from app.ai.engine import _get_provider_instance
    from app.models.ai_provider import AIProvider as AIProviderModel

    row = AIProviderModel(
        name="Ollama Lab",
        provider_type="ollama",
        base_url=BASE_URL,
        config={"timeout_seconds": 120},
    )
    instance = _get_provider_instance(row)
    assert isinstance(instance, OllamaProvider)
    assert instance.base_url == BASE_URL
    assert instance.timeout == 120.0


@pytest.mark.asyncio
async def test_temperature_floor_prevents_greedy_decoding(monkeypatch):
    """Greedy decoding (0.0) under a grammar constraint sends local models into
    repetition loops that never close the JSON, so the provider floors it."""
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["payload"] = json.loads(request.content)
        return httpx.Response(200, json=_chat_response())

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))
    provider = OllamaProvider(base_url=BASE_URL, config={})

    # The engine's 0.0 default is raised to the floor.
    await provider.complete(prompt="hi", model="qwen3.5:9b", temperature=0.0)
    assert captured["payload"]["options"]["temperature"] == 0.2

    # A caller asking for more than the floor keeps its own value.
    await provider.complete(prompt="hi", model="qwen3.5:9b", temperature=0.7)
    assert captured["payload"]["options"]["temperature"] == 0.7


@pytest.mark.asyncio
async def test_temperature_floor_is_configurable(monkeypatch):
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["payload"] = json.loads(request.content)
        return httpx.Response(200, json=_chat_response())

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))

    # Opt out entirely (restores true greedy decoding).
    provider = OllamaProvider(base_url=BASE_URL, config={"min_temperature": 0})
    await provider.complete(prompt="hi", model="qwen3.5:9b", temperature=0.0)
    assert captured["payload"]["options"]["temperature"] == 0.0

    # Per-model override wins over the provider-level floor.
    provider = OllamaProvider(
        base_url=BASE_URL,
        config={"min_temperature": 0.2, "model_overrides": {"qwen3.5:9b": {"min_temperature": 0.5}}},
    )
    await provider.complete(prompt="hi", model="qwen3.5:9b", temperature=0.0)
    assert captured["payload"]["options"]["temperature"] == 0.5
    await provider.complete(prompt="hi", model="llama3.1:8b", temperature=0.0)
    assert captured["payload"]["options"]["temperature"] == 0.2
