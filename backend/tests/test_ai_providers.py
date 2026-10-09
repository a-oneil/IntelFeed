"""Tests for the AI Providers API (/api/ai/providers)."""

import uuid

import pytest
from httpx import AsyncClient

# ── Helper ───────────────────────────────────────────────────────────

PROVIDERS_URL = "/api/ai/providers"


async def _create_provider(
    client: AsyncClient,
    admin_headers: dict,
    name: str = "Test Claude",
    provider_type: str = "claude",
    **extra,
) -> dict:
    """Convenience wrapper that creates a provider and returns its JSON."""
    resp = await client.post(
        PROVIDERS_URL,
        json={"name": name, "provider_type": provider_type, **extra},
        headers=admin_headers,
    )
    assert resp.status_code == 201
    return resp.json()


# ── List providers ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_providers_empty(client: AsyncClient, auth_headers: dict):
    resp = await client.get(PROVIDERS_URL, headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_list_providers_after_create(client: AsyncClient, auth_headers: dict, admin_headers: dict):
    await _create_provider(client, admin_headers, name="Provider A")
    await _create_provider(client, admin_headers, name="Provider B")

    resp = await client.get(PROVIDERS_URL, headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) == 2
    names = {p["name"] for p in data}
    assert names == {"Provider A", "Provider B"}


# ── Create provider ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_provider_as_admin(client: AsyncClient, admin_headers: dict):
    data = await _create_provider(
        client,
        admin_headers,
        name="My Claude Provider",
        provider_type="claude",
        base_url="https://api.anthropic.com",
        api_key="sk-test-key",
        config={"temperature": 0.7},
    )
    assert data["name"] == "My Claude Provider"
    assert data["provider_type"] == "claude"
    assert data["is_active"] is True
    assert "id" in data
    # api_key should not be returned in the response
    assert "api_key" not in data


@pytest.mark.asyncio
async def test_create_ollama_provider(client: AsyncClient, admin_headers: dict):
    data = await _create_provider(
        client,
        admin_headers,
        name="Ollama Lab",
        provider_type="ollama",
        base_url="https://ollama.example.com",
    )
    assert data["provider_type"] == "ollama"
    assert data["base_url"] == "https://ollama.example.com"


@pytest.mark.asyncio
async def test_create_provider_unknown_type_rejected(client: AsyncClient, admin_headers: dict):
    resp = await client.post(
        PROVIDERS_URL,
        json={"name": "Nope", "provider_type": "bogus"},
        headers=admin_headers,
    )
    # App-wide handler maps request validation errors to 400
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_create_openai_compatible_provider_no_key(client: AsyncClient, admin_headers: dict):
    """LM Studio / llama.cpp need no API key — creation must succeed without one."""
    data = await _create_provider(
        client,
        admin_headers,
        name="LM Studio",
        provider_type="openai_compatible",
        base_url="http://localhost:1234/v1",
    )
    assert data["provider_type"] == "openai_compatible"
    assert data["base_url"] == "http://localhost:1234/v1"
    assert data["supports_tools"] is False


@pytest.mark.asyncio
async def test_create_openai_compatible_provider_missing_base_url_rejected(client: AsyncClient, admin_headers: dict):
    resp = await client.post(
        PROVIDERS_URL,
        json={"name": "No URL", "provider_type": "openai_compatible"},
        headers=admin_headers,
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_create_provider_regular_user_forbidden(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        PROVIDERS_URL,
        json={"name": "Nope", "provider_type": "claude"},
        headers=auth_headers,
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_create_provider_no_auth(client: AsyncClient):
    resp = await client.post(
        PROVIDERS_URL,
        json={"name": "Nope", "provider_type": "claude"},
    )
    assert resp.status_code == 401


# ── Update provider ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_update_provider(client: AsyncClient, admin_headers: dict):
    created = await _create_provider(client, admin_headers, name="Old Name")
    provider_id = created["id"]

    resp = await client.put(
        f"{PROVIDERS_URL}/{provider_id}",
        json={"name": "New Name", "is_active": False},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "New Name"
    assert data["is_active"] is False


@pytest.mark.asyncio
async def test_update_provider_rejects_empty_base_url_for_openai_compatible(client: AsyncClient, admin_headers: dict):
    created = await _create_provider(
        client, admin_headers, name="LM Studio", provider_type="openai_compatible", base_url="http://x/v1"
    )
    resp = await client.put(
        f"{PROVIDERS_URL}/{created['id']}",
        json={"base_url": ""},
        headers=admin_headers,
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_update_provider_regular_user_forbidden(client: AsyncClient, auth_headers: dict, admin_headers: dict):
    created = await _create_provider(client, admin_headers, name="Immutable")
    provider_id = created["id"]

    resp = await client.put(
        f"{PROVIDERS_URL}/{provider_id}",
        json={"name": "Hacked"},
        headers=auth_headers,
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_update_provider_no_auth(client: AsyncClient, admin_headers: dict):
    created = await _create_provider(client, admin_headers, name="NoAuth")
    provider_id = created["id"]

    resp = await client.put(
        f"{PROVIDERS_URL}/{provider_id}",
        json={"name": "Hacked"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_update_provider_not_found(client: AsyncClient, admin_headers: dict):
    fake_id = uuid.uuid4()
    resp = await client.put(
        f"{PROVIDERS_URL}/{fake_id}",
        json={"name": "Ghost"},
        headers=admin_headers,
    )
    assert resp.status_code == 404


# ── Delete provider ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_delete_provider(client: AsyncClient, admin_headers: dict):
    created = await _create_provider(client, admin_headers, name="To Delete")
    provider_id = created["id"]

    resp = await client.delete(f"{PROVIDERS_URL}/{provider_id}", headers=admin_headers)
    assert resp.status_code == 204

    # Verify it no longer appears in the list
    list_resp = await client.get(PROVIDERS_URL, headers=admin_headers)
    assert list_resp.status_code == 200
    ids = [p["id"] for p in list_resp.json()]
    assert provider_id not in ids


@pytest.mark.asyncio
async def test_delete_provider_regular_user_forbidden(client: AsyncClient, auth_headers: dict, admin_headers: dict):
    created = await _create_provider(client, admin_headers, name="Protected")
    provider_id = created["id"]

    resp = await client.delete(f"{PROVIDERS_URL}/{provider_id}", headers=auth_headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_delete_provider_no_auth(client: AsyncClient, admin_headers: dict):
    created = await _create_provider(client, admin_headers, name="NoAuth Delete")
    provider_id = created["id"]

    resp = await client.delete(f"{PROVIDERS_URL}/{provider_id}")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_delete_provider_not_found(client: AsyncClient, admin_headers: dict):
    fake_id = uuid.uuid4()
    resp = await client.delete(f"{PROVIDERS_URL}/{fake_id}", headers=admin_headers)
    assert resp.status_code == 404


# ── Get models ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_models_not_found(client: AsyncClient, auth_headers: dict):
    fake_id = uuid.uuid4()
    resp = await client.get(f"{PROVIDERS_URL}/{fake_id}/models", headers=auth_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_get_models_no_auth(client: AsyncClient):
    fake_id = uuid.uuid4()
    resp = await client.get(f"{PROVIDERS_URL}/{fake_id}/models")
    assert resp.status_code == 401


# ── Test connectivity ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_test_provider_regular_user_forbidden(client: AsyncClient, auth_headers: dict, admin_headers: dict):
    created = await _create_provider(client, admin_headers, name="Test Target")
    provider_id = created["id"]

    resp = await client.post(f"{PROVIDERS_URL}/{provider_id}/test", headers=auth_headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_test_provider_no_auth(client: AsyncClient, admin_headers: dict):
    created = await _create_provider(client, admin_headers, name="Test NoAuth")
    provider_id = created["id"]

    resp = await client.post(f"{PROVIDERS_URL}/{provider_id}/test")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_test_provider_not_found(client: AsyncClient, admin_headers: dict):
    fake_id = uuid.uuid4()
    resp = await client.post(f"{PROVIDERS_URL}/{fake_id}/test", headers=admin_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_test_provider_unreachable_host_returns_success_false(client: AsyncClient, admin_headers: dict):
    """A bad/unreachable row must come back as success=false, not a 500."""
    created = await _create_provider(
        client,
        admin_headers,
        name="Unreachable",
        provider_type="openai_compatible",
        base_url="http://127.0.0.1:1/v1",
    )
    resp = await client.post(f"{PROVIDERS_URL}/{created['id']}/test", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is False


@pytest.mark.asyncio
async def test_provider_response_includes_supports_tools(client: AsyncClient, admin_headers: dict):
    # Ollama runs a native tool-calling loop, so it is tool-capable. A plain
    # Anthropic-API provider ("claude") is not.
    data = await _create_provider(
        client,
        admin_headers,
        name="Ollama Tools Check",
        provider_type="ollama",
        base_url="https://ollama.example.com",
    )
    assert data["supports_tools"] is True

    api_data = await _create_provider(
        client,
        admin_headers,
        name="Anthropic API Tools Check",
        provider_type="claude",
        base_url="https://api.anthropic.com",
    )
    assert api_data["supports_tools"] is False


def test_provider_classes_agree_with_capability_registry():
    """supports_tools class attrs must match TOOL_CAPABLE_PROVIDER_TYPES."""
    from app.ai.capabilities import provider_type_supports_tools
    from app.ai.providers.claude_code_provider import ClaudeCodeProvider
    from app.ai.providers.claude_provider import ClaudeProvider
    from app.ai.providers.ollama_provider import OllamaProvider
    from app.ai.providers.openai_provider import OpenAICompatibleProvider

    assert ClaudeCodeProvider.supports_tools is provider_type_supports_tools("claude_code")
    assert ClaudeProvider.supports_tools is provider_type_supports_tools("claude")
    assert OllamaProvider.supports_tools is provider_type_supports_tools("ollama")
    assert OpenAICompatibleProvider.supports_tools is provider_type_supports_tools("openai_compatible")


def test_engine_factory_raises_on_unknown_provider_type():
    """An unrecognized provider_type must raise, not silently fall through to ClaudeProvider.

    Guards against the historical bug where any value other than
    "claude_code"/"ollama" sent Anthropic-shaped requests to whatever
    base_url happened to be set.
    """
    from app.ai.engine import UnsupportedProviderTypeError, _get_provider_instance
    from app.models.ai_provider import AIProvider as AIProviderModel

    bogus = AIProviderModel(name="Bogus", provider_type="bogus", base_url="http://example.com")
    with pytest.raises(UnsupportedProviderTypeError):
        _get_provider_instance(bogus)


def test_engine_factory_routes_openai_compatible():
    from app.ai.engine import _get_provider_instance
    from app.ai.providers.openai_provider import OpenAICompatibleProvider
    from app.models.ai_provider import AIProvider as AIProviderModel

    row = AIProviderModel(name="LM Studio", provider_type="openai_compatible", base_url="http://localhost:1234/v1")
    instance = _get_provider_instance(row)
    assert isinstance(instance, OpenAICompatibleProvider)


@pytest.mark.asyncio
async def test_run_task_with_unknown_provider_type_records_provider_error(db_session, test_user):
    """The schema blocks an unknown provider_type at create time, so this can
    only happen via a manually-edited row — run_task must still degrade to a
    provider_error result rather than crash the Celery task that called it.
    """
    from app.ai.engine import run_task
    from app.models.ai_provider import AIProvider as AIProviderModel
    from app.models.ai_task import AITask
    from app.models.ai_task_assignment import AITaskAssignment

    task = AITask(
        name="unknown_provider_type_test_task",
        display_name="Unknown Provider Type Test",
        default_prompt_template="{{ text }}",
    )
    db_session.add(task)
    await db_session.flush()

    provider = AIProviderModel(name="Bogus", provider_type="bogus", base_url="http://example.com")
    db_session.add(provider)
    await db_session.flush()

    db_session.add(AITaskAssignment(task_id=task.id, provider_id=provider.id, model_name="whatever"))
    await db_session.flush()

    result = await run_task(db_session, test_user.id, task.name, variables={"text": "hi"})
    assert result["_extraction_status"] == "provider_error"
