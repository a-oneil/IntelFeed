"""Tests for AI Task and Assignment API endpoints."""

import uuid

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ai_provider import AIProvider
from app.models.ai_task import AITask
from app.models.user import User

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def ai_provider(db_session: AsyncSession) -> AIProvider:
    """Create a test AI provider for use in assignment tests."""
    provider = AIProvider(
        name="Test Claude",
        provider_type="claude",
        models=["claude-sonnet-4-6"],
        is_active=True,
        config={},
    )
    db_session.add(provider)
    await db_session.flush()
    return provider


@pytest_asyncio.fixture
async def system_task(db_session: AsyncSession) -> AITask:
    """Create a built-in (system) AI task."""
    task = AITask(
        name="threat_analysis",
        display_name="Threat Analysis",
        description="Analyze threats described in the article",
        category="analysis",
        default_prompt_template="Analyze threats in {{ entry.content_text }}",
        output_schema={"type": "object"},
        is_system=True,
    )
    db_session.add(task)
    await db_session.flush()
    return task


@pytest_asyncio.fixture
async def second_task(db_session: AsyncSession) -> AITask:
    """Create a second AI task for ordering/listing tests."""
    task = AITask(
        name="article_summary",
        display_name="Article Summary",
        description="Generate a concise summary",
        category="analysis",
        default_prompt_template="Summarize {{ entry.content_text }}",
        output_schema={"type": "object"},
        is_system=True,
    )
    db_session.add(task)
    await db_session.flush()
    return task


# ---------------------------------------------------------------------------
# List Tasks
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_tasks_empty(client: AsyncClient, auth_headers: dict):
    """Listing tasks when none exist returns an empty list."""
    resp = await client.get("/api/ai/tasks", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_list_tasks_returns_system_tasks(
    client: AsyncClient, auth_headers: dict, system_task: AITask, second_task: AITask
):
    """Listing tasks returns all tasks ordered by category then name."""
    resp = await client.get("/api/ai/tasks", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 2
    # Tasks should be ordered by category, name: both are analysis, so article_summary < threat_analysis
    assert data[0]["name"] == "article_summary"
    assert data[0]["category"] == "analysis"
    assert data[0]["is_system"] is True
    assert data[1]["name"] == "threat_analysis"
    assert data[1]["category"] == "analysis"


@pytest.mark.asyncio
async def test_list_tasks_response_shape(client: AsyncClient, auth_headers: dict, system_task: AITask):
    """Each task in the list includes all expected fields."""
    resp = await client.get("/api/ai/tasks", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    task = data[0]
    assert "id" in task
    assert task["name"] == "threat_analysis"
    assert task["display_name"] == "Threat Analysis"
    assert task["description"] == "Analyze threats described in the article"
    assert task["category"] == "analysis"
    assert task["is_system"] is True
    assert "created_at" in task


@pytest.mark.asyncio
async def test_list_tasks_requires_auth(client: AsyncClient):
    """Listing tasks without auth returns 401."""
    resp = await client.get("/api/ai/tasks")
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Create Custom Task
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_custom_task(client: AsyncClient, admin_headers: dict):
    """Creating a custom task returns 201 with correct data."""
    payload = {
        "name": "my_custom_task",
        "display_name": "My Custom Task",
        "description": "A user-defined extraction task",
        "category": "custom",
        "default_prompt_template": "Analyze {{ entry.content_text }}",
        "output_schema": {"type": "object", "properties": {"result": {"type": "string"}}},
    }
    resp = await client.post("/api/ai/tasks", json=payload, headers=admin_headers)
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "my_custom_task"
    assert data["display_name"] == "My Custom Task"
    assert data["description"] == "A user-defined extraction task"
    assert data["category"] == "custom"
    assert data["is_system"] is False
    assert "id" in data
    assert "created_at" in data


@pytest.mark.asyncio
async def test_create_custom_task_defaults_category(client: AsyncClient, admin_headers: dict):
    """When category is omitted, it defaults to 'custom'."""
    payload = {
        "name": "no_category_task",
        "display_name": "No Category",
        "default_prompt_template": "Do something with {{ entry.title }}",
    }
    resp = await client.post("/api/ai/tasks", json=payload, headers=admin_headers)
    assert resp.status_code == 201
    assert resp.json()["category"] == "custom"


@pytest.mark.asyncio
async def test_create_custom_task_optional_fields(client: AsyncClient, admin_headers: dict):
    """Description and output_schema can be omitted."""
    payload = {
        "name": "minimal_task",
        "display_name": "Minimal Task",
        "default_prompt_template": "Just do it {{ entry.title }}",
    }
    resp = await client.post("/api/ai/tasks", json=payload, headers=admin_headers)
    assert resp.status_code == 201
    data = resp.json()
    assert data["description"] is None


@pytest.mark.asyncio
async def test_create_custom_task_duplicate_name(client: AsyncClient, admin_headers: dict, system_task: AITask):
    """Creating a task with a duplicate name returns 409."""
    payload = {
        "name": "threat_analysis",  # already exists via system_task fixture
        "display_name": "Duplicate",
        "default_prompt_template": "Extract {{ entry.content_text }}",
    }
    resp = await client.post("/api/ai/tasks", json=payload, headers=admin_headers)
    assert resp.status_code == 409
    error = resp.json()["error"]
    assert error["code"] == "conflict"
    assert "already exists" in error["message"]


@pytest.mark.asyncio
async def test_create_custom_task_duplicate_name_between_custom_tasks(client: AsyncClient, admin_headers: dict):
    """Creating two custom tasks with the same name is rejected."""
    payload = {
        "name": "unique_task",
        "display_name": "First",
        "default_prompt_template": "Template {{ entry.title }}",
    }
    resp1 = await client.post("/api/ai/tasks", json=payload, headers=admin_headers)
    assert resp1.status_code == 201

    payload["display_name"] = "Second attempt"
    resp2 = await client.post("/api/ai/tasks", json=payload, headers=admin_headers)
    assert resp2.status_code == 409


@pytest.mark.asyncio
async def test_create_custom_task_validation_empty_name(client: AsyncClient, admin_headers: dict):
    """Empty name fails validation."""
    payload = {
        "name": "",
        "display_name": "Valid Display",
        "default_prompt_template": "Template",
    }
    resp = await client.post("/api/ai/tasks", json=payload, headers=admin_headers)
    assert resp.status_code in (400, 422)


@pytest.mark.asyncio
async def test_create_custom_task_validation_empty_display_name(client: AsyncClient, admin_headers: dict):
    """Empty display_name fails validation."""
    payload = {
        "name": "valid_name",
        "display_name": "",
        "default_prompt_template": "Template",
    }
    resp = await client.post("/api/ai/tasks", json=payload, headers=admin_headers)
    assert resp.status_code in (400, 422)


@pytest.mark.asyncio
async def test_create_custom_task_validation_empty_prompt(client: AsyncClient, admin_headers: dict):
    """Empty prompt template fails validation."""
    payload = {
        "name": "valid_name",
        "display_name": "Valid",
        "default_prompt_template": "",
    }
    resp = await client.post("/api/ai/tasks", json=payload, headers=admin_headers)
    assert resp.status_code in (400, 422)


@pytest.mark.asyncio
async def test_task_writes_require_admin(
    client: AsyncClient, auth_headers: dict, system_task: AITask, ai_provider: AIProvider
):
    """Task create/update/delete and assignment writes are admin-only (403 for regular users)."""
    resp = await client.post(
        "/api/ai/tasks",
        json={"name": "not_allowed", "display_name": "Nope", "default_prompt_template": "x"},
        headers=auth_headers,
    )
    assert resp.status_code == 403

    resp = await client.patch(
        f"/api/ai/tasks/{system_task.id}",
        json={"entry_action_order": 1},
        headers=auth_headers,
    )
    assert resp.status_code == 403

    resp = await client.delete(f"/api/ai/tasks/{system_task.id}", headers=auth_headers)
    assert resp.status_code == 403

    resp = await client.put(
        f"/api/ai/tasks/{system_task.id}/assignments",
        json={"provider_id": str(ai_provider.id), "model_name": "llama3"},
        headers=auth_headers,
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_create_custom_task_requires_auth(client: AsyncClient):
    """Creating a task without auth returns 401."""
    payload = {
        "name": "unauthed_task",
        "display_name": "No Auth",
        "default_prompt_template": "Template",
    }
    resp = await client.post("/api/ai/tasks", json=payload)
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_create_custom_task_appears_in_list(client: AsyncClient, admin_headers: dict):
    """A newly created custom task appears when listing all tasks."""
    payload = {
        "name": "listed_task",
        "display_name": "Listed Task",
        "default_prompt_template": "Template {{ entry.title }}",
    }
    create_resp = await client.post("/api/ai/tasks", json=payload, headers=admin_headers)
    assert create_resp.status_code == 201
    task_id = create_resp.json()["id"]

    list_resp = await client.get("/api/ai/tasks", headers=admin_headers)
    assert list_resp.status_code == 200
    ids = [t["id"] for t in list_resp.json()]
    assert task_id in ids


# ---------------------------------------------------------------------------
# Get Task Assignment
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_assignment_none(client: AsyncClient, auth_headers: dict, system_task: AITask):
    """Getting an assignment for a task with no assignment returns null."""
    resp = await client.get(f"/api/ai/tasks/{system_task.id}/assignments", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json() is None


@pytest.mark.asyncio
async def test_get_assignment_requires_auth(client: AsyncClient, system_task: AITask):
    """Getting an assignment without auth returns 401."""
    resp = await client.get(f"/api/ai/tasks/{system_task.id}/assignments")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_get_assignment_after_create(
    client: AsyncClient,
    admin_headers: dict,
    admin_user: User,
    system_task: AITask,
    ai_provider: AIProvider,
):
    """After upserting an assignment, GET returns it correctly."""
    # Create the assignment
    put_resp = await client.put(
        f"/api/ai/tasks/{system_task.id}/assignments",
        json={
            "provider_id": str(ai_provider.id),
            "model_name": "llama3",
            "is_enabled": True,
            "config": {"temperature": 0.7},
        },
        headers=admin_headers,
    )
    assert put_resp.status_code == 200

    # Now GET it
    resp = await client.get(f"/api/ai/tasks/{system_task.id}/assignments", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data is not None
    assert data["task_id"] == str(system_task.id)
    assert data["provider_id"] == str(ai_provider.id)
    assert data["model_name"] == "llama3"
    assert data["is_enabled"] is True
    assert data["config"] == {"temperature": 0.7}
    assert data["task_name"] == "threat_analysis"
    assert data["provider_name"] == "Test Claude"
    assert data["created_by"] == str(admin_user.id)


# ---------------------------------------------------------------------------
# Upsert Task Assignment (PUT)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_upsert_assignment_create(
    client: AsyncClient,
    admin_headers: dict,
    admin_user: User,
    system_task: AITask,
    ai_provider: AIProvider,
):
    """PUT creates a new assignment when none exists."""
    resp = await client.put(
        f"/api/ai/tasks/{system_task.id}/assignments",
        json={
            "provider_id": str(ai_provider.id),
            "model_name": "llama3",
            "is_enabled": True,
            "config": {},
        },
        headers=admin_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["task_id"] == str(system_task.id)
    assert data["provider_id"] == str(ai_provider.id)
    assert data["model_name"] == "llama3"
    assert data["is_enabled"] is True
    assert data["config"] == {}
    assert data["task_name"] == "threat_analysis"
    assert data["provider_name"] == "Test Claude"
    assert data["created_by"] == str(admin_user.id)
    assert "id" in data


@pytest.mark.asyncio
async def test_upsert_assignment_update(
    client: AsyncClient,
    admin_headers: dict,
    system_task: AITask,
    ai_provider: AIProvider,
):
    """PUT updates an existing assignment (upsert behavior)."""
    # Create initial assignment
    resp1 = await client.put(
        f"/api/ai/tasks/{system_task.id}/assignments",
        json={
            "provider_id": str(ai_provider.id),
            "model_name": "llama3",
            "is_enabled": True,
            "config": {},
        },
        headers=admin_headers,
    )
    assert resp1.status_code == 200
    assignment_id = resp1.json()["id"]

    # Update it via another PUT
    resp2 = await client.put(
        f"/api/ai/tasks/{system_task.id}/assignments",
        json={
            "provider_id": str(ai_provider.id),
            "model_name": "llama3:70b",
            "is_enabled": False,
            "config": {"temperature": 0.3},
        },
        headers=admin_headers,
    )
    assert resp2.status_code == 200
    data = resp2.json()
    # Same assignment ID (updated, not duplicated)
    assert data["id"] == assignment_id
    assert data["model_name"] == "llama3:70b"
    assert data["is_enabled"] is False
    assert data["config"] == {"temperature": 0.3}


@pytest.mark.asyncio
async def test_upsert_assignment_task_not_found(client: AsyncClient, admin_headers: dict, ai_provider: AIProvider):
    """PUT for a nonexistent task returns 404."""
    fake_task_id = uuid.uuid4()
    resp = await client.put(
        f"/api/ai/tasks/{fake_task_id}/assignments",
        json={
            "provider_id": str(ai_provider.id),
            "model_name": "llama3",
        },
        headers=admin_headers,
    )
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "not_found"
    assert "Task" in resp.json()["error"]["message"]


@pytest.mark.asyncio
async def test_upsert_assignment_provider_not_found(client: AsyncClient, admin_headers: dict, system_task: AITask):
    """PUT with a nonexistent provider_id returns 404."""
    fake_provider_id = uuid.uuid4()
    resp = await client.put(
        f"/api/ai/tasks/{system_task.id}/assignments",
        json={
            "provider_id": str(fake_provider_id),
            "model_name": "llama3",
        },
        headers=admin_headers,
    )
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "not_found"
    assert "Provider" in resp.json()["error"]["message"]


@pytest.mark.asyncio
async def test_upsert_assignment_requires_auth(client: AsyncClient, system_task: AITask, ai_provider: AIProvider):
    """PUT without auth returns 401."""
    resp = await client.put(
        f"/api/ai/tasks/{system_task.id}/assignments",
        json={
            "provider_id": str(ai_provider.id),
            "model_name": "llama3",
        },
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_upsert_assignment_validation_empty_model_name(
    client: AsyncClient, admin_headers: dict, system_task: AITask, ai_provider: AIProvider
):
    """Empty model_name fails validation."""
    resp = await client.put(
        f"/api/ai/tasks/{system_task.id}/assignments",
        json={
            "provider_id": str(ai_provider.id),
            "model_name": "",
        },
        headers=admin_headers,
    )
    assert resp.status_code in (400, 422)


@pytest.mark.asyncio
async def test_upsert_assignment_defaults(
    client: AsyncClient,
    admin_headers: dict,
    system_task: AITask,
    ai_provider: AIProvider,
):
    """is_enabled defaults to True and config defaults to {} when omitted."""
    resp = await client.put(
        f"/api/ai/tasks/{system_task.id}/assignments",
        json={
            "provider_id": str(ai_provider.id),
            "model_name": "llama3",
        },
        headers=admin_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_enabled"] is True
    assert data["config"] == {}


# ---------------------------------------------------------------------------
# Assignments are global: one row per task, shared by every user
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_assignment_is_shared_across_users(
    client: AsyncClient,
    auth_headers: dict,
    admin_headers: dict,
    admin_user: User,
    system_task: AITask,
    ai_provider: AIProvider,
):
    """A task has a single, platform-wide assignment; a later PUT replaces it.

    Assignments used to be scoped per user. They are now platform-wide config
    (written by admins, with ``created_by`` kept only as an audit trail), so
    the second write wins and every user reads back the same row.
    """
    # Admin creates the assignment
    resp_create = await client.put(
        f"/api/ai/tasks/{system_task.id}/assignments",
        json={
            "provider_id": str(ai_provider.id),
            "model_name": "llama3",
            "config": {"set_by": "first write"},
        },
        headers=admin_headers,
    )
    assert resp_create.status_code == 200
    assert resp_create.json()["created_by"] == str(admin_user.id)
    assignment_id = resp_create.json()["id"]

    # A second PUT overwrites the same assignment rather than creating another
    resp_update = await client.put(
        f"/api/ai/tasks/{system_task.id}/assignments",
        json={
            "provider_id": str(ai_provider.id),
            "model_name": "llama3:70b",
            "config": {"set_by": "second write"},
        },
        headers=admin_headers,
    )
    assert resp_update.status_code == 200
    assert resp_update.json()["id"] == assignment_id

    # Both users read back the same, most recently written assignment
    for headers in (auth_headers, admin_headers):
        got = await client.get(f"/api/ai/tasks/{system_task.id}/assignments", headers=headers)
        assert got.json()["id"] == assignment_id
        assert got.json()["model_name"] == "llama3:70b"
        assert got.json()["config"] == {"set_by": "second write"}


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_assignment_nonexistent_task_id(client: AsyncClient, auth_headers: dict):
    """GET assignment for a UUID that does not correspond to any task returns null.

    The endpoint does a join on AITask, so if the task_id doesn't match any
    assignment rows, the result is simply None (200 with null body).
    """
    fake_id = uuid.uuid4()
    resp = await client.get(f"/api/ai/tasks/{fake_id}/assignments", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json() is None


@pytest.mark.asyncio
async def test_create_task_name_max_length(client: AsyncClient, admin_headers: dict):
    """Task name at 100 chars (the max) should succeed."""
    long_name = "a" * 100
    payload = {
        "name": long_name,
        "display_name": "Long Name Task",
        "default_prompt_template": "Template {{ entry.title }}",
    }
    resp = await client.post("/api/ai/tasks", json=payload, headers=admin_headers)
    assert resp.status_code == 201
    assert resp.json()["name"] == long_name


@pytest.mark.asyncio
async def test_create_task_name_exceeds_max_length(client: AsyncClient, admin_headers: dict):
    """Task name over 100 chars fails validation."""
    payload = {
        "name": "a" * 101,
        "display_name": "Too Long",
        "default_prompt_template": "Template",
    }
    resp = await client.post("/api/ai/tasks", json=payload, headers=admin_headers)
    assert resp.status_code in (400, 422)


@pytest.mark.asyncio
async def test_upsert_assignment_with_complex_config(
    client: AsyncClient,
    admin_headers: dict,
    system_task: AITask,
    ai_provider: AIProvider,
):
    """Config can hold arbitrary nested JSON."""
    config = {
        "temperature": 0.8,
        "max_tokens": 4096,
        "stop_sequences": ["\n\n"],
        "nested": {"key": "value", "list": [1, 2, 3]},
    }
    resp = await client.put(
        f"/api/ai/tasks/{system_task.id}/assignments",
        json={
            "provider_id": str(ai_provider.id),
            "model_name": "llama3",
            "config": config,
        },
        headers=admin_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["config"] == config


@pytest.mark.asyncio
async def test_create_task_with_output_schema(client: AsyncClient, admin_headers: dict):
    """Output schema is stored and returned when provided."""
    schema = {
        "type": "object",
        "properties": {
            "summary": {"type": "string"},
            "entities": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["summary"],
    }
    payload = {
        "name": "schema_task",
        "display_name": "Schema Task",
        "default_prompt_template": "Template {{ entry.title }}",
        "output_schema": schema,
    }
    resp = await client.post("/api/ai/tasks", json=payload, headers=admin_headers)
    assert resp.status_code == 201
    # output_schema is not in the response schema (AITaskResponse doesn't include it),
    # but the task is created successfully
    assert resp.json()["name"] == "schema_task"


@pytest.mark.asyncio
async def test_upsert_assignment_invalid_task_id_format(
    client: AsyncClient, admin_headers: dict, ai_provider: AIProvider
):
    """PUT with an invalid UUID for task_id returns 422."""
    resp = await client.put(
        "/api/ai/tasks/not-a-uuid/assignments",
        json={
            "provider_id": str(ai_provider.id),
            "model_name": "llama3",
        },
        headers=admin_headers,
    )
    assert resp.status_code in (400, 422)


@pytest.mark.asyncio
async def test_upsert_assignment_invalid_provider_id_format(
    client: AsyncClient, admin_headers: dict, system_task: AITask
):
    """PUT with an invalid UUID for provider_id returns 422."""
    resp = await client.put(
        f"/api/ai/tasks/{system_task.id}/assignments",
        json={
            "provider_id": "not-a-uuid",
            "model_name": "llama3",
        },
        headers=admin_headers,
    )
    assert resp.status_code in (400, 422)


# ---------------------------------------------------------------------------
# PATCH /api/ai/tasks/{task_id} — reader AI-panel presentation fields
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_update_task_entry_action_fields(client: AsyncClient, admin_headers: dict, system_task: AITask):
    """PATCH updates show_in_entry_actions and entry_action_order."""
    resp = await client.patch(
        f"/api/ai/tasks/{system_task.id}",
        json={"show_in_entry_actions": False, "entry_action_order": 3},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["show_in_entry_actions"] is False
    assert body["entry_action_order"] == 3

    # Fields persist and come back in the list response
    resp = await client.get("/api/ai/tasks", headers=admin_headers)
    task = next(t for t in resp.json() if t["id"] == str(system_task.id))
    assert task["show_in_entry_actions"] is False
    assert task["entry_action_order"] == 3


@pytest.mark.asyncio
async def test_update_task_partial_patch_keeps_other_fields(
    client: AsyncClient, admin_headers: dict, system_task: AITask
):
    """Omitted fields are left untouched by a partial PATCH."""
    resp = await client.patch(
        f"/api/ai/tasks/{system_task.id}",
        json={"entry_action_order": 1},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["entry_action_order"] == 1
    assert body["show_in_entry_actions"] is True  # default untouched


@pytest.mark.asyncio
async def test_update_task_not_found(client: AsyncClient, admin_headers: dict):
    resp = await client.patch(
        f"/api/ai/tasks/{uuid.uuid4()}",
        json={"show_in_entry_actions": False},
        headers=admin_headers,
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# PATCH /api/ai/tasks/{task_id} — output schema override
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def schema_task(db_session: AsyncSession) -> AITask:
    """System task with a structured default schema (no pipeline contract)."""
    task = AITask(
        name="summary_with_schema",
        display_name="Summary With Schema",
        category="analysis",
        default_prompt_template="Summarize {{ entry.content_text }}",
        output_schema={
            "type": "object",
            "properties": {"summary": {"type": "string"}, "key_points": {"type": "array"}},
        },
        is_system=True,
    )
    db_session.add(task)
    await db_session.flush()
    return task


@pytest_asyncio.fixture
async def pipeline_task(db_session: AsyncSession) -> AITask:
    """System task whose default marks fields required (pipeline-parsed)."""
    task = AITask(
        name="pipeline_extraction",
        display_name="Pipeline Extraction",
        category="extraction",
        default_prompt_template="Extract from {{ entry.content_text }}",
        output_schema={
            "type": "object",
            "properties": {"summary": {"type": "string"}, "ttps": {"type": "array"}},
            "required": ["summary", "ttps"],
        },
        is_system=True,
    )
    db_session.add(task)
    await db_session.flush()
    return task


@pytest_asyncio.fixture
async def freeform_task(db_session: AsyncSession) -> AITask:
    """Task with no structured output schema (free-form text)."""
    task = AITask(
        name="freeform_chat",
        display_name="Freeform Chat",
        category="analysis",
        default_prompt_template="Answer: {{ question }}",
        output_schema=None,
        is_system=True,
    )
    db_session.add(task)
    await db_session.flush()
    return task


@pytest.mark.asyncio
async def test_schema_override_save_and_expose(client: AsyncClient, admin_headers: dict, schema_task: AITask):
    """A valid override is stored and returned alongside the untouched default."""
    override = {
        "type": "object",
        "properties": {"summary": {"type": "string"}, "confidence": {"type": "string"}},
        "required": ["summary"],
    }
    resp = await client.patch(
        f"/api/ai/tasks/{schema_task.id}",
        json={"output_schema_override": override},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["output_schema_override"] == override
    # The shipped default is untouched (seeder keeps syncing it on deploy)
    assert body["output_schema"] == schema_task.output_schema


@pytest.mark.asyncio
async def test_schema_override_clear_with_null(client: AsyncClient, admin_headers: dict, schema_task: AITask):
    """Explicit null removes the override; the default becomes effective again."""
    override = {"type": "object", "properties": {"summary": {"type": "string"}}}
    await client.patch(
        f"/api/ai/tasks/{schema_task.id}",
        json={"output_schema_override": override},
        headers=admin_headers,
    )
    resp = await client.patch(
        f"/api/ai/tasks/{schema_task.id}",
        json={"output_schema_override": None},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["output_schema_override"] is None


@pytest.mark.asyncio
async def test_schema_override_omitted_field_untouched(client: AsyncClient, admin_headers: dict, schema_task: AITask):
    """A PATCH without output_schema_override leaves an existing override alone."""
    override = {"type": "object", "properties": {"summary": {"type": "string"}}}
    await client.patch(
        f"/api/ai/tasks/{schema_task.id}",
        json={"output_schema_override": override},
        headers=admin_headers,
    )
    resp = await client.patch(
        f"/api/ai/tasks/{schema_task.id}",
        json={"entry_action_order": 5},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["output_schema_override"] == override


@pytest.mark.asyncio
async def test_schema_override_rejects_non_object_type(client: AsyncClient, admin_headers: dict, schema_task: AITask):
    resp = await client.patch(
        f"/api/ai/tasks/{schema_task.id}",
        json={"output_schema_override": {"type": "array", "items": {"type": "string"}}},
        headers=admin_headers,
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "invalid_schema"


@pytest.mark.asyncio
async def test_schema_override_rejects_empty_properties(client: AsyncClient, admin_headers: dict, schema_task: AITask):
    resp = await client.patch(
        f"/api/ai/tasks/{schema_task.id}",
        json={"output_schema_override": {"type": "object", "properties": {}}},
        headers=admin_headers,
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "invalid_schema"


@pytest.mark.asyncio
async def test_schema_override_rejects_malformed_json_schema(
    client: AsyncClient, admin_headers: dict, schema_task: AITask
):
    """A schema that fails JSON Schema meta-validation is rejected."""
    resp = await client.patch(
        f"/api/ai/tasks/{schema_task.id}",
        json={
            "output_schema_override": {
                "type": "object",
                "properties": {"x": {"type": "not_a_real_type"}},
            }
        },
        headers=admin_headers,
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "invalid_schema"


@pytest.mark.asyncio
async def test_schema_override_rejects_required_not_in_properties(
    client: AsyncClient, admin_headers: dict, schema_task: AITask
):
    resp = await client.patch(
        f"/api/ai/tasks/{schema_task.id}",
        json={
            "output_schema_override": {
                "type": "object",
                "properties": {"summary": {"type": "string"}},
                "required": ["summary", "ghost_field"],
            }
        },
        headers=admin_headers,
    )
    assert resp.status_code == 400
    assert "ghost_field" in resp.json()["error"]["message"]


@pytest.mark.asyncio
async def test_schema_override_protects_pipeline_required_fields(
    client: AsyncClient, admin_headers: dict, pipeline_task: AITask
):
    """Fields required by the default (parsed by workers) cannot be dropped."""
    resp = await client.patch(
        f"/api/ai/tasks/{pipeline_task.id}",
        json={
            "output_schema_override": {
                "type": "object",
                "properties": {"summary": {"type": "string"}},
                "required": ["summary"],  # drops "ttps"
            }
        },
        headers=admin_headers,
    )
    assert resp.status_code == 400
    assert "ttps" in resp.json()["error"]["message"]


@pytest.mark.asyncio
async def test_schema_override_allows_extending_pipeline_schema(
    client: AsyncClient, admin_headers: dict, pipeline_task: AITask
):
    """Adding fields on top of the pipeline contract is fine."""
    override = {
        "type": "object",
        "properties": {
            "summary": {"type": "string"},
            "ttps": {"type": "array"},
            "notes": {"type": "string"},
        },
        "required": ["summary", "ttps", "notes"],
    }
    resp = await client.patch(
        f"/api/ai/tasks/{pipeline_task.id}",
        json={"output_schema_override": override},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["output_schema_override"] == override


@pytest.mark.asyncio
async def test_custom_task_can_add_schema(client: AsyncClient, admin_headers: dict):
    """A schema-less custom task can gain an output schema via PATCH output_schema."""
    resp = await client.post(
        "/api/ai/tasks",
        json={
            "name": "my_custom_analysis",
            "display_name": "My Custom Analysis",
            "default_prompt_template": "Analyze {{ entry.content_text }}",
        },
        headers=admin_headers,
    )
    assert resp.status_code == 201
    task_id = resp.json()["id"]
    assert resp.json()["output_schema"] is None

    schema = {
        "type": "object",
        "properties": {"verdict": {"type": "string"}, "notes": {"type": "string"}},
        "required": ["verdict"],
    }
    resp = await client.patch(
        f"/api/ai/tasks/{task_id}",
        json={"output_schema": schema},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["output_schema"] == schema

    # Explicit null makes the task free-form again
    resp = await client.patch(
        f"/api/ai/tasks/{task_id}",
        json={"output_schema": None},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["output_schema"] is None


@pytest.mark.asyncio
async def test_custom_task_schema_is_validated(client: AsyncClient, admin_headers: dict):
    """Structural validation applies to custom-task schemas too."""
    resp = await client.post(
        "/api/ai/tasks",
        json={
            "name": "my_custom_bad_schema",
            "display_name": "Bad Schema Task",
            "default_prompt_template": "Analyze {{ entry.content_text }}",
        },
        headers=admin_headers,
    )
    task_id = resp.json()["id"]

    resp = await client.patch(
        f"/api/ai/tasks/{task_id}",
        json={"output_schema": {"type": "object", "properties": {}}},
        headers=admin_headers,
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "invalid_schema"


@pytest.mark.asyncio
async def test_create_custom_task_rejects_invalid_schema(client: AsyncClient, admin_headers: dict):
    """POST /ai/tasks validates output_schema at creation time."""
    resp = await client.post(
        "/api/ai/tasks",
        json={
            "name": "born_broken",
            "display_name": "Born Broken",
            "default_prompt_template": "x",
            "output_schema": {"type": "array"},
        },
        headers=admin_headers,
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "invalid_schema"


@pytest.mark.asyncio
async def test_system_task_default_schema_not_editable(client: AsyncClient, admin_headers: dict, schema_task: AITask):
    """PATCH output_schema on a system task is forbidden (seeder owns it)."""
    resp = await client.patch(
        f"/api/ai/tasks/{schema_task.id}",
        json={"output_schema": {"type": "object", "properties": {"x": {"type": "string"}}}},
        headers=admin_headers,
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_schema_override_rejected_for_freeform_task(
    client: AsyncClient, admin_headers: dict, freeform_task: AITask
):
    resp = await client.patch(
        f"/api/ai/tasks/{freeform_task.id}",
        json={"output_schema_override": {"type": "object", "properties": {"x": {"type": "string"}}}},
        headers=admin_headers,
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "invalid_schema"


# ---------------------------------------------------------------------------
# Tool-capability guardrails
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def ollama_provider(db_session: AsyncSession) -> AIProvider:
    provider = AIProvider(
        name="Local Ollama",
        provider_type="ollama",
        base_url="http://ollama:11434",
        models=["qwen3:14b"],
        is_active=True,
        config={},
    )
    db_session.add(provider)
    await db_session.flush()
    return provider


@pytest_asyncio.fixture
async def claude_code_provider(db_session: AsyncSession) -> AIProvider:
    provider = AIProvider(
        name="Claude Code CLI",
        provider_type="claude_code",
        models=["sonnet", "opus", "haiku"],
        is_active=True,
        config={"cli_path": "claude"},
    )
    db_session.add(provider)
    await db_session.flush()
    return provider


@pytest_asyncio.fixture
async def tool_required_task(db_session: AsyncSession) -> AITask:
    """A seeded agentic task — name must be in TOOL_REQUIRED_TASKS."""
    task = AITask(
        name="entity_merge_maintenance",
        display_name="Entity Merge Maintenance",
        category="maintenance",
        default_prompt_template="Judge cluster {{ cluster }}",
        output_schema={"type": "object"},
        is_system=True,
    )
    db_session.add(task)
    await db_session.flush()
    return task


@pytest.mark.asyncio
async def test_upsert_tool_required_task_on_toolless_provider_rejected(
    client: AsyncClient,
    admin_headers: dict,
    tool_required_task: AITask,
    ai_provider: AIProvider,
):
    """Assigning an agentic task to a tool-less provider (Anthropic API) returns 400."""
    resp = await client.put(
        f"/api/ai/tasks/{tool_required_task.id}/assignments",
        json={
            "provider_id": str(ai_provider.id),
            "model_name": "claude-sonnet-4-6",
        },
        headers=admin_headers,
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "provider_incompatible"


@pytest.mark.asyncio
async def test_upsert_tool_required_task_on_ollama_ok(
    client: AsyncClient,
    admin_headers: dict,
    tool_required_task: AITask,
    ollama_provider: AIProvider,
):
    """Ollama runs a native tool loop, so agentic tasks may be assigned to it."""
    resp = await client.put(
        f"/api/ai/tasks/{tool_required_task.id}/assignments",
        json={
            "provider_id": str(ollama_provider.id),
            "model_name": "qwen3:14b",
        },
        headers=admin_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["provider_id"] == str(ollama_provider.id)


@pytest.mark.asyncio
async def test_upsert_tool_required_task_on_claude_code_ok(
    client: AsyncClient,
    admin_headers: dict,
    tool_required_task: AITask,
    claude_code_provider: AIProvider,
):
    resp = await client.put(
        f"/api/ai/tasks/{tool_required_task.id}/assignments",
        json={
            "provider_id": str(claude_code_provider.id),
            "model_name": "sonnet",
        },
        headers=admin_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["provider_id"] == str(claude_code_provider.id)


@pytest.mark.asyncio
async def test_toolless_task_assignable_to_any_provider(
    client: AsyncClient,
    admin_headers: dict,
    system_task: AITask,
    ollama_provider: AIProvider,
):
    """Non-agentic tasks are not restricted by the capability guard."""
    resp = await client.put(
        f"/api/ai/tasks/{system_task.id}/assignments",
        json={
            "provider_id": str(ollama_provider.id),
            "model_name": "qwen3:14b",
        },
        headers=admin_headers,
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_list_tasks_includes_requires_tools(
    client: AsyncClient,
    auth_headers: dict,
    system_task: AITask,
    tool_required_task: AITask,
):
    resp = await client.get("/api/ai/tasks", headers=auth_headers)
    assert resp.status_code == 200
    by_name = {t["name"]: t for t in resp.json()}
    assert by_name["entity_merge_maintenance"]["requires_tools"] is True
    assert by_name["threat_analysis"]["requires_tools"] is False


# ---------------------------------------------------------------------------
# Category updates (prompt workspace Routing tab)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_update_category_rejected_for_system_task(client: AsyncClient, admin_headers: dict, system_task: AITask):
    resp = await client.patch(
        f"/api/ai/tasks/{system_task.id}",
        json={"category": "generation"},
        headers=admin_headers,
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_update_category_allowed_for_custom_task(client: AsyncClient, admin_headers: dict):
    create = await client.post(
        "/api/ai/tasks",
        json={
            "name": "my_recat_task",
            "display_name": "My Recat Task",
            "category": "custom",
            "default_prompt_template": "Do {{ entry.title }}",
        },
        headers=admin_headers,
    )
    assert create.status_code == 201
    task_id = create.json()["id"]

    resp = await client.patch(
        f"/api/ai/tasks/{task_id}",
        json={"category": "generation"},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["category"] == "generation"
