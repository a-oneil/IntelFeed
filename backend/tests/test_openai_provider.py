"""Unit tests for the OpenAI-compatible provider (mocked HTTP transport)."""

import json

import httpx
import pytest

from app.ai.providers.claude_code_provider import QuotaExhaustedError
from app.ai.providers.openai_provider import OpenAICompatibleProvider
from app.ai.providers.schema_utils import to_openai_strict

BASE_URL = "https://api.example.com/v1"

_RealAsyncClient = httpx.AsyncClient


def _mock_client_factory(handler):
    def factory(**kwargs):
        kwargs.pop("transport", None)
        return _RealAsyncClient(transport=httpx.MockTransport(handler), **kwargs)

    return factory


def _chat_response(content: str = "hello", model: str = "gpt-test") -> dict:
    return {
        "id": "chatcmpl-1",
        "model": model,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5},
    }


# ── construction ─────────────────────────────────────────────────────


def test_requires_base_url():
    with pytest.raises(ValueError):
        OpenAICompatibleProvider(base_url=None, api_key=None, config={})
    with pytest.raises(ValueError):
        OpenAICompatibleProvider(base_url="   ", api_key=None, config={})


# ── complete() payload shape ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_complete_sends_bearer_only_when_key_set(monkeypatch):
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["auth"] = request.headers.get("authorization")
        return httpx.Response(200, json=_chat_response())

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))

    provider = OpenAICompatibleProvider(base_url=BASE_URL, api_key=None, config={})
    await provider.complete(prompt="hi", model="gpt-test")
    assert captured["auth"] is None

    provider = OpenAICompatibleProvider(base_url=BASE_URL, api_key="sk-abc", config={})
    await provider.complete(prompt="hi", model="gpt-test")
    assert captured["auth"] == "Bearer sk-abc"


@pytest.mark.asyncio
async def test_complete_payload_shape_default_max_tokens_param(monkeypatch):
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["payload"] = json.loads(request.content)
        return httpx.Response(200, json=_chat_response())

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))
    provider = OpenAICompatibleProvider(base_url=BASE_URL, api_key="k", config={})

    await provider.complete(prompt="user text", system="system text", temperature=0.3, max_tokens=256, model="gpt-test")

    assert captured["url"] == f"{BASE_URL}/chat/completions"
    payload = captured["payload"]
    assert payload["model"] == "gpt-test"
    assert payload["messages"] == [
        {"role": "system", "content": "system text"},
        {"role": "user", "content": "user text"},
    ]
    assert payload["max_tokens"] == 256
    assert "max_completion_tokens" not in payload
    assert payload["temperature"] == 0.3


@pytest.mark.asyncio
async def test_complete_reasoning_model_config(monkeypatch):
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["payload"] = json.loads(request.content)
        return httpx.Response(200, json=_chat_response())

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))
    provider = OpenAICompatibleProvider(
        base_url=BASE_URL,
        api_key="k",
        config={"max_tokens_param": "max_completion_tokens", "send_temperature": False, "system_role": "developer"},
    )

    await provider.complete(prompt="hi", system="sys", model="o-reasoning")

    payload = captured["payload"]
    assert "max_tokens" not in payload
    assert payload["max_completion_tokens"] == 4096
    assert "temperature" not in payload
    assert payload["messages"][0]["role"] == "developer"


@pytest.mark.asyncio
async def test_complete_merges_extra_body(monkeypatch):
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["payload"] = json.loads(request.content)
        return httpx.Response(200, json=_chat_response())

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))
    provider = OpenAICompatibleProvider(
        base_url=BASE_URL,
        api_key="k",
        config={"extra_body": {"chat_template_kwargs": {"enable_thinking": False}}},
    )
    await provider.complete(prompt="hi", model="qwen3")
    assert captured["payload"]["chat_template_kwargs"] == {"enable_thinking": False}


# ── structured output modes ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_response_format_json_schema_default(monkeypatch):
    captured: dict = {}
    schema = {"type": "object", "properties": {"x": {"type": "string"}}}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["payload"] = json.loads(request.content)
        return httpx.Response(200, json=_chat_response())

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))
    provider = OpenAICompatibleProvider(base_url=BASE_URL, api_key="k", config={})
    await provider.complete(prompt="hi", model="gpt-test", response_format=schema)

    rf = captured["payload"]["response_format"]
    assert rf["type"] == "json_schema"
    assert rf["json_schema"]["strict"] is False
    assert rf["json_schema"]["schema"]["required"] == ["x"]
    assert rf["json_schema"]["name"] == "intelfeed_output"


@pytest.mark.asyncio
async def test_response_format_json_object_mode_uses_schema_instruction(monkeypatch):
    captured: dict = {}
    schema = {"type": "object", "properties": {"x": {"type": "string"}}}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["payload"] = json.loads(request.content)
        return httpx.Response(200, json=_chat_response())

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))
    provider = OpenAICompatibleProvider(base_url=BASE_URL, api_key="k", config={"structured_output": "json_object"})
    await provider.complete(prompt="hi", system="sys", model="gpt-test", response_format=schema)

    payload = captured["payload"]
    assert payload["response_format"] == {"type": "json_object"}
    assert "schema" in payload["messages"][0]["content"].lower() or "JSON schema" in payload["messages"][0]["content"]


@pytest.mark.asyncio
async def test_downgrade_chain_on_response_format_rejection(monkeypatch):
    calls: list[dict] = []
    schema = {"type": "object", "properties": {"x": {"type": "string"}}}

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        calls.append(payload)
        rf = payload.get("response_format")
        if rf and rf.get("json_schema", {}).get("strict"):
            return httpx.Response(400, json={"error": {"message": "strict json_schema not supported"}})
        if rf and rf.get("type") == "json_schema":
            return httpx.Response(200, json=_chat_response())
        return httpx.Response(200, json=_chat_response())

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))
    provider = OpenAICompatibleProvider(
        base_url=BASE_URL, api_key="k", config={"structured_output": "json_schema_strict"}
    )
    resp = await provider.complete(prompt="hi", model="gpt-test", response_format=schema)

    assert len(calls) == 2  # strict rejected, non-strict json_schema succeeded
    assert resp.raw_response["structured_output_mode_used"] == "json_schema"


# ── to_openai_strict normalizer ───────────────────────────────────────


def test_to_openai_strict_fills_required_and_nullable():
    schema = {
        "type": "object",
        "properties": {
            "a": {"type": "string"},
            "b": {"type": "string", "enum": ["x", "y"]},
            "c": {"type": "string", "minLength": 1, "maxLength": 10},
        },
        "required": ["a"],
    }
    strict = to_openai_strict(schema)
    assert set(strict["required"]) == {"a", "b", "c"}
    assert strict["additionalProperties"] is False
    # "a" was already required -> stays as-is (not made nullable)
    assert strict["properties"]["a"]["type"] == "string"
    # "b"/"c" were optional -> made nullable
    assert strict["properties"]["b"]["type"] == ["string", "null"]
    assert None in strict["properties"]["b"]["enum"]
    assert strict["properties"]["c"]["type"] == ["string", "null"]
    assert "minLength" not in strict["properties"]["c"]
    assert "maxLength" not in strict["properties"]["c"]


# ── errors ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_429_maps_to_quota_exhausted(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, text="rate limited", headers={"retry-after": "30"})

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))
    provider = OpenAICompatibleProvider(base_url=BASE_URL, api_key="k", config={})
    with pytest.raises(QuotaExhaustedError):
        await provider.complete(prompt="hi", model="gpt-test")


@pytest.mark.asyncio
async def test_usage_defaults_to_zero_when_absent(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "model": "gpt-test",
                "choices": [{"message": {"role": "assistant", "content": "hi"}, "finish_reason": "stop"}],
            },
        )

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))
    provider = OpenAICompatibleProvider(base_url=BASE_URL, api_key="k", config={})
    resp = await provider.complete(prompt="hi", model="gpt-test")
    assert resp.tokens_input == 0
    assert resp.tokens_output == 0
    assert resp.cost_usd is None


# ── cost resolution ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_cost_from_configured_pricing(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_chat_response())

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))
    provider = OpenAICompatibleProvider(
        base_url=BASE_URL,
        api_key="k",
        config={"pricing": {"input_per_mtok": 1.0, "output_per_mtok": 2.0}},
    )
    resp = await provider.complete(prompt="hi", model="gpt-test")
    # usage: 10 input, 5 output tokens
    assert resp.cost_usd == round((10 / 1_000_000) * 1.0 + (5 / 1_000_000) * 2.0, 6)


@pytest.mark.asyncio
async def test_cost_from_openrouter_usage_field(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        data = _chat_response()
        data["usage"]["cost"] = 0.00123
        return httpx.Response(200, json=data)

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))
    provider = OpenAICompatibleProvider(base_url=BASE_URL, api_key="k", config={"report_cost": True})
    resp = await provider.complete(prompt="hi", model="gpt-test")
    assert resp.cost_usd == 0.00123


@pytest.mark.asyncio
async def test_cost_local_flag_forces_zero(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_chat_response())

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))
    provider = OpenAICompatibleProvider(base_url=BASE_URL, api_key=None, config={"local": True})
    resp = await provider.complete(prompt="hi", model="gpt-test")
    assert resp.cost_usd == 0.0


# ── list_models / check_health ───────────────────────────────────────


@pytest.mark.asyncio
async def test_list_models_sorted_and_filtered(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"data": [{"id": "gpt-4o"}, {"id": "whisper-1"}, {"id": "gpt-3.5-turbo"}]},
        )

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))
    provider = OpenAICompatibleProvider(base_url=BASE_URL, api_key="k", config={"model_filter": r"^gpt-"})
    models = await provider.list_models()
    assert models == ["gpt-3.5-turbo", "gpt-4o"]


@pytest.mark.asyncio
async def test_check_health_true_on_200(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": []})

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))
    provider = OpenAICompatibleProvider(base_url=BASE_URL, api_key=None, config={})
    assert await provider.check_health() is True


# ── embed() ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_embed_reorders_by_index(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": [
                    {"index": 1, "embedding": [0.2]},
                    {"index": 0, "embedding": [0.1]},
                ]
            },
        )

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))
    provider = OpenAICompatibleProvider(base_url=BASE_URL, api_key="k", config={})
    vectors = await provider.embed(["a", "b"], model="text-embedding-3-small")
    assert vectors == [[0.1], [0.2]]


@pytest.mark.asyncio
async def test_embed_count_mismatch_raises(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": [{"index": 0, "embedding": [0.1]}]})

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))
    provider = OpenAICompatibleProvider(base_url=BASE_URL, api_key="k", config={})
    with pytest.raises(ValueError):
        await provider.embed(["a", "b"], model="text-embedding-3-small")


@pytest.mark.asyncio
async def test_embed_dimensions_only_sent_when_configured(monkeypatch):
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["payload"] = json.loads(request.content)
        return httpx.Response(200, json={"data": [{"index": 0, "embedding": [0.1]}]})

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))
    provider = OpenAICompatibleProvider(base_url=BASE_URL, api_key="k", config={})
    await provider.embed(["a"], model="m")
    assert "dimensions" not in captured["payload"]

    provider = OpenAICompatibleProvider(base_url=BASE_URL, api_key="k", config={"embedding_dimensions": 768})
    await provider.embed(["a"], model="m")
    assert captured["payload"]["dimensions"] == 768


# ── stream_complete() SSE parsing ─────────────────────────────────────


@pytest.mark.asyncio
async def test_stream_complete_parses_sse(monkeypatch):
    body = (
        b": OPENROUTER PROCESSING\n\n"
        b'data: {"choices":[{"delta":{"content":"Hel"}}]}\n\n'
        b'data: {"choices":[{"delta":{"content":"lo"}}]}\n\n'
        b'data: {"choices":[],"usage":{"prompt_tokens":1}}\n\n'
        b"data: [DONE]\n\n"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=body, headers={"content-type": "text/event-stream"})

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))
    provider = OpenAICompatibleProvider(base_url=BASE_URL, api_key="k", config={})
    chunks = [c async for c in provider.stream_complete(prompt="hi", model="gpt-test")]
    assert chunks == ["Hel", "lo"]
