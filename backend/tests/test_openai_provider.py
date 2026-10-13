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


@pytest.mark.asyncio
async def test_downgrade_chain_falls_all_the_way_to_prompt(monkeypatch):
    """A server that rejects every structured response_format still gets a
    schema instruction injected into the prompt on the final fallback step.
    """
    calls: list[dict] = []
    schema = {"type": "object", "properties": {"x": {"type": "string"}}}

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        calls.append(payload)
        if "response_format" in payload:
            return httpx.Response(400, json={"error": {"message": "response_format not supported"}})
        return httpx.Response(200, json=_chat_response())

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))
    provider = OpenAICompatibleProvider(base_url=BASE_URL, api_key="k", config={})
    resp = await provider.complete(prompt="hi", model="gpt-test", response_format=schema)

    assert len(calls) == 3  # json_schema, json_object, prompt
    assert resp.raw_response["structured_output_mode_used"] == "prompt"
    final_payload = calls[-1]
    assert "response_format" not in final_payload
    assert "JSON schema" in final_payload["messages"][0]["content"]


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


def test_to_openai_strict_normalizes_optional_nested_object():
    """A nested object under an OPTIONAL property must still get its own
    required/additionalProperties — the property's own type is widened to
    ["object", "null"] only AFTER its children are normalized, otherwise the
    object-handling branch never recognizes it as an object.
    """
    schema = {
        "type": "object",
        "properties": {
            "summary": {"type": "string"},
            "indicators": {
                "type": "object",
                "properties": {"ip": {"type": "string"}, "domain": {"type": "string"}},
                "required": ["ip"],
            },
        },
        "required": ["summary"],
    }
    strict = to_openai_strict(schema)
    nested = strict["properties"]["indicators"]
    assert set(nested["required"]) == {"ip", "domain"}
    assert nested["additionalProperties"] is False
    assert "object" in nested["type"]
    assert "null" in nested["type"]
    # the nested optional "domain" field was itself made nullable
    assert nested["properties"]["domain"]["type"] == ["string", "null"]
    assert nested["properties"]["ip"]["type"] == "string"


def test_to_openai_strict_normalizes_through_array_items():
    schema = {
        "type": "object",
        "properties": {
            "tools": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {"name": {"type": "string"}, "detection_artifacts": {"type": "string"}},
                    "required": ["name"],
                },
            }
        },
        "required": ["tools"],
    }
    strict = to_openai_strict(schema)
    item_schema = strict["properties"]["tools"]["items"]
    assert set(item_schema["required"]) == {"name", "detection_artifacts"}
    assert item_schema["additionalProperties"] is False


def test_to_openai_strict_leaves_free_form_object_untouched():
    """A free-form object (no declared properties) has nothing strict mode
    can enumerate as required — left as-is rather than fabricating one.
    """
    schema = {
        "type": "object",
        "properties": {"metadata": {"type": "object"}},
        "required": ["metadata"],
    }
    strict = to_openai_strict(schema)
    assert strict["properties"]["metadata"] == {"type": "object"}


def test_to_openai_strict_makes_anyof_only_property_nullable():
    """A property with neither `type` nor `enum` — described only via
    anyOf/oneOf — gets a {"type": "null"} branch appended instead of being
    silently skipped.
    """
    schema = {
        "type": "object",
        "properties": {
            "a": {"type": "string"},
            "b": {"anyOf": [{"type": "string"}, {"type": "integer"}]},
        },
        "required": ["a"],
    }
    strict = to_openai_strict(schema)
    options = strict["properties"]["b"]["anyOf"]
    assert any(isinstance(o, dict) and o.get("type") == "null" for o in options)


def test_to_openai_strict_strip_does_not_touch_property_named_like_a_keyword():
    """The strip pass removes schema KEYWORDS from schema nodes, never a
    property whose NAME happens to match one (e.g. a field literally called
    "maxLength") — that would silently delete the field's definition while
    leaving it listed in `required`, producing an invalid schema.
    """
    schema = {
        "type": "object",
        "properties": {
            "maxLength": {"type": "integer"},
            "a": {"type": "string"},
        },
        "required": ["a"],
    }
    strict = to_openai_strict(schema)
    assert "maxLength" in strict["properties"]
    assert strict["properties"]["maxLength"]["type"] == ["integer", "null"]
    assert "maxLength" in strict["required"]


# ── errors ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_429_maps_to_quota_exhausted(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, text="rate limited", headers={"retry-after": "30"})

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))
    provider = OpenAICompatibleProvider(base_url=BASE_URL, api_key="k", config={})
    with pytest.raises(QuotaExhaustedError) as exc_info:
        await provider.complete(prompt="hi", model="gpt-test")

    from datetime import UTC, datetime

    reset_at = exc_info.value.reset_at
    assert reset_at is not None
    delta = (reset_at - datetime.now(UTC)).total_seconds()
    assert 25 < delta < 35


async def _quota_error(monkeypatch, response: httpx.Response) -> QuotaExhaustedError:
    def handler(request: httpx.Request) -> httpx.Response:
        return response

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))
    provider = OpenAICompatibleProvider(base_url=BASE_URL, api_key="k", config={})
    with pytest.raises(QuotaExhaustedError) as exc_info:
        await provider.complete(prompt="hi", model="gpt-test")
    return exc_info.value


def _seconds_until(reset_at) -> float:
    from datetime import UTC, datetime

    return (reset_at - datetime.now(UTC)).total_seconds()


@pytest.mark.asyncio
async def test_429_without_retry_after_pauses_briefly(monkeypatch):
    """A bare 429 is a per-minute rate limit, not an hour-long quota pause."""
    err = await _quota_error(monkeypatch, httpx.Response(429, text="rate limited"))
    assert err.reset_at is not None
    assert 0 < _seconds_until(err.reset_at) <= 60


@pytest.mark.asyncio
async def test_429_insufficient_quota_leaves_long_pause_to_engine(monkeypatch):
    body = {"error": {"type": "insufficient_quota", "code": "insufficient_quota", "message": "out of credits"}}
    err = await _quota_error(monkeypatch, httpx.Response(429, json=body))
    assert err.reset_at is None


@pytest.mark.asyncio
async def test_429_retry_after_http_date(monkeypatch):
    from datetime import UTC, datetime, timedelta
    from email.utils import format_datetime

    when = format_datetime(datetime.now(UTC) + timedelta(seconds=120), usegmt=True)
    err = await _quota_error(monkeypatch, httpx.Response(429, text="slow down", headers={"retry-after": when}))
    assert 100 < _seconds_until(err.reset_at) <= 120


@pytest.mark.asyncio
async def test_stream_429_honours_retry_after(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, text="rate limited", headers={"retry-after": "30"})

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))
    provider = OpenAICompatibleProvider(base_url=BASE_URL, api_key="k", config={})
    with pytest.raises(QuotaExhaustedError) as exc_info:
        async for _ in provider.stream_complete(prompt="hi", model="gpt-test"):
            pass
    assert 25 < _seconds_until(exc_info.value.reset_at) <= 30


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
async def test_report_cost_sends_usage_include_on_openrouter(monkeypatch):
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["payload"] = json.loads(request.content)
        data = _chat_response()
        data["usage"]["cost"] = 0.005
        return httpx.Response(200, json=data)

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))
    provider = OpenAICompatibleProvider(
        base_url="https://openrouter.ai/api/v1", api_key="k", config={"report_cost": True}
    )
    resp = await provider.complete(prompt="hi", model="gpt-test")
    assert captured["payload"]["usage"] == {"include": True}
    assert resp.cost_usd == 0.005


@pytest.mark.asyncio
async def test_report_cost_does_not_send_usage_include_off_openrouter(monkeypatch):
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["payload"] = json.loads(request.content)
        return httpx.Response(200, json=_chat_response())

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))
    provider = OpenAICompatibleProvider(base_url=BASE_URL, api_key="k", config={"report_cost": True})
    await provider.complete(prompt="hi", model="gpt-test")
    assert "usage" not in captured["payload"]


@pytest.mark.asyncio
async def test_cost_local_flag_forces_zero(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_chat_response())

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))
    provider = OpenAICompatibleProvider(base_url=BASE_URL, api_key=None, config={"local": True})
    resp = await provider.complete(prompt="hi", model="gpt-test")
    assert resp.cost_usd == 0.0


@pytest.mark.asyncio
async def test_cost_from_litellm_response_header(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_chat_response(), headers={"x-litellm-response-cost": "0.00042"})

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))
    provider = OpenAICompatibleProvider(base_url=BASE_URL, api_key="k", config={"report_cost": True})
    resp = await provider.complete(prompt="hi", model="gpt-test")
    assert resp.cost_usd == 0.00042


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


@pytest.mark.asyncio
async def test_check_health_false_on_error(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))
    provider = OpenAICompatibleProvider(base_url=BASE_URL, api_key=None, config={})
    assert await provider.check_health() is False


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


@pytest.mark.asyncio
async def test_stream_complete_raises_on_error_frame(monkeypatch):
    body = b'data: {"choices":[{"delta":{"content":"Hel"}}]}\n\ndata: {"error":{"message":"model overloaded"}}\n\n'

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=body, headers={"content-type": "text/event-stream"})

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(handler))
    provider = OpenAICompatibleProvider(base_url=BASE_URL, api_key="k", config={})
    with pytest.raises(RuntimeError, match="model overloaded"):
        async for _ in provider.stream_complete(prompt="hi", model="gpt-test"):
            pass
