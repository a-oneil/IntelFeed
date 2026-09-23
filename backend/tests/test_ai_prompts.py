"""Tests for AI Prompt Template API endpoints."""

import uuid

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ai_prompt_template import AIPromptTemplate
from app.models.ai_task import AITask
from app.models.user import User

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def ai_task(db_session: AsyncSession) -> AITask:
    """Create a sample AI task for prompt tests."""
    task = AITask(
        name="article_summary",
        display_name="Article Summary",
        description="Generate a concise summary of the article",
        category="analysis",
        default_prompt_template="Default template for {{ entry.title }}",
        output_schema={"type": "object", "properties": {"summary": {"type": "string"}}},
        is_system=True,
    )
    db_session.add(task)
    await db_session.flush()
    return task


@pytest_asyncio.fixture
async def second_ai_task(db_session: AsyncSession) -> AITask:
    """Create a second AI task to test multi-task scenarios."""
    task = AITask(
        name="ttp_extraction",
        display_name="TTP Extraction",
        description="Extract TTPs from articles",
        category="analysis",
        default_prompt_template="Extract TTPs from {{ entry.title }}",
        output_schema={"type": "object", "properties": {"ttps": {"type": "array"}}},
        is_system=True,
    )
    db_session.add(task)
    await db_session.flush()
    return task


@pytest_asyncio.fixture
async def system_prompt(db_session: AsyncSession, ai_task: AITask) -> AIPromptTemplate:
    """Create a system-level (user_id=None) prompt template."""
    prompt = AIPromptTemplate(
        task_id=ai_task.id,
        created_by=None,
        name="Article Summary System Default",
        template_text="System default template for {{ entry.title }}",
        variables=["entry"],
        is_active=True,
        version=1,
    )
    db_session.add(prompt)
    await db_session.flush()
    return prompt


@pytest_asyncio.fixture
async def user_prompt(db_session: AsyncSession, ai_task: AITask, test_user: User) -> AIPromptTemplate:
    """Create a user-authored prompt template override (newest version)."""
    prompt = AIPromptTemplate(
        task_id=ai_task.id,
        created_by=test_user.id,
        name="My Custom Summary Prompt",
        template_text="Custom user template for {{ entry.title }}",
        variables=["entry"],
        is_active=True,
        version=2,
    )
    db_session.add(prompt)
    await db_session.flush()
    return prompt


# ---------------------------------------------------------------------------
# List prompts
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_prompts_returns_system_defaults(
    client: AsyncClient, auth_headers: dict, system_prompt: AIPromptTemplate
):
    """Listing prompts includes system-level defaults (user_id=None)."""
    resp = await client.get("/api/ai/prompts", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) >= 1
    ids = [p["id"] for p in data]
    assert str(system_prompt.id) in ids


@pytest.mark.asyncio
async def test_list_prompts_includes_user_overrides(
    client: AsyncClient,
    auth_headers: dict,
    system_prompt: AIPromptTemplate,
    user_prompt: AIPromptTemplate,
):
    """Listing prompts returns both system defaults and the authenticated user's overrides."""
    resp = await client.get("/api/ai/prompts", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    ids = [p["id"] for p in data]
    assert str(system_prompt.id) in ids
    assert str(user_prompt.id) in ids


@pytest.mark.asyncio
async def test_list_prompts_includes_all_users(
    client: AsyncClient,
    admin_headers: dict,
    system_prompt: AIPromptTemplate,
    user_prompt: AIPromptTemplate,
):
    """Overrides are per-task, so every user sees every template."""
    resp = await client.get("/api/ai/prompts", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    ids = [p["id"] for p in data]
    assert str(system_prompt.id) in ids
    assert str(user_prompt.id) in ids


@pytest.mark.asyncio
async def test_list_prompts_empty_when_no_prompts(client: AsyncClient, auth_headers: dict, ai_task: AITask):
    """Listing prompts returns an empty list when there are no templates."""
    resp = await client.get("/api/ai/prompts", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) == 0


# ---------------------------------------------------------------------------
# Get active prompt for a task
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_active_prompt_returns_system_default(
    client: AsyncClient, auth_headers: dict, system_prompt: AIPromptTemplate
):
    """When no user override exists, the system default is returned."""
    resp = await client.get(f"/api/ai/prompts/{system_prompt.task_id}", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == str(system_prompt.id)
    assert data["created_by"] is None
    assert data["is_active"] is True
    assert data["template_text"] == system_prompt.template_text


@pytest.mark.asyncio
async def test_get_active_prompt_newest_version_takes_precedence(
    client: AsyncClient,
    auth_headers: dict,
    system_prompt: AIPromptTemplate,
    user_prompt: AIPromptTemplate,
):
    """The newest active template wins regardless of who authored it."""
    resp = await client.get(f"/api/ai/prompts/{user_prompt.task_id}", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == str(user_prompt.id)
    assert data["created_by"] is not None
    assert data["template_text"] == user_prompt.template_text


@pytest.mark.asyncio
async def test_get_active_prompt_falls_back_to_task_default(client: AsyncClient, auth_headers: dict, ai_task: AITask):
    """When no prompt templates exist at all, falls back to the task's own default_prompt_template."""
    resp = await client.get(f"/api/ai/prompts/{ai_task.id}", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    # Fallback generates a synthetic response from the task
    assert data["created_by"] is None
    assert data["template_text"] == ai_task.default_prompt_template
    assert data["version"] == 0
    assert data["name"] == f"{ai_task.display_name} Default"
    assert data["is_active"] is True


@pytest.mark.asyncio
async def test_get_active_prompt_not_found_for_invalid_task(client: AsyncClient, auth_headers: dict):
    """Requesting an active prompt for a non-existent task returns 404."""
    fake_task_id = uuid.uuid4()
    resp = await client.get(f"/api/ai/prompts/{fake_task_id}", headers=auth_headers)
    assert resp.status_code == 404
    data = resp.json()
    assert data["error"]["code"] == "not_found"


# ---------------------------------------------------------------------------
# Create / update user override (PUT)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_user_override(client: AsyncClient, admin_headers: dict, ai_task: AITask):
    """PUT creates a new user override prompt for the given task."""
    resp = await client.put(
        f"/api/ai/prompts/{ai_task.id}",
        json={
            "name": "My Custom Prompt",
            "template_text": "Extract IOCs from {{ entry.content_text }}",
        },
        headers=admin_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["task_id"] == str(ai_task.id)
    assert data["created_by"] is not None
    assert data["name"] == "My Custom Prompt"
    assert data["template_text"] == "Extract IOCs from {{ entry.content_text }}"
    assert data["is_active"] is True
    assert data["version"] == 1


@pytest.mark.asyncio
async def test_update_override_increments_version(
    client: AsyncClient,
    admin_headers: dict,
    ai_task: AITask,
    user_prompt: AIPromptTemplate,
):
    """PUT on a task with an existing override creates a new version and deactivates the old one."""
    resp = await client.put(
        f"/api/ai/prompts/{ai_task.id}",
        json={
            "name": "Updated Prompt",
            "template_text": "New improved template for {{ entry.title }}",
        },
        headers=admin_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["version"] == user_prompt.version + 1
    assert data["is_active"] is True
    assert data["name"] == "Updated Prompt"
    assert data["template_text"] == "New improved template for {{ entry.title }}"


@pytest.mark.asyncio
async def test_update_override_deactivates_previous(
    client: AsyncClient,
    admin_headers: dict,
    ai_task: AITask,
    user_prompt: AIPromptTemplate,
):
    """After PUT, the previous version is no longer active; the new version is the active one."""
    # Create new version
    await client.put(
        f"/api/ai/prompts/{ai_task.id}",
        json={"template_text": "Version 2 template"},
        headers=admin_headers,
    )

    # The active prompt should be the new version
    resp = await client.get(f"/api/ai/prompts/{ai_task.id}", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["template_text"] == "Version 2 template"
    assert data["version"] == user_prompt.version + 1


@pytest.mark.asyncio
async def test_create_override_uses_default_name_when_omitted(
    client: AsyncClient, admin_headers: dict, ai_task: AITask
):
    """When name is omitted in the PUT body, a default name is generated from the task display_name."""
    resp = await client.put(
        f"/api/ai/prompts/{ai_task.id}",
        json={"template_text": "Custom template text"},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert ai_task.display_name in data["name"]


@pytest.mark.asyncio
async def test_create_override_uses_task_template_when_text_omitted(
    client: AsyncClient, admin_headers: dict, ai_task: AITask
):
    """When template_text is omitted, the task's default_prompt_template is used."""
    resp = await client.put(
        f"/api/ai/prompts/{ai_task.id}",
        json={"name": "Override with default text"},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["template_text"] == ai_task.default_prompt_template


@pytest.mark.asyncio
async def test_update_prompt_not_found_for_invalid_task(client: AsyncClient, admin_headers: dict):
    """PUT for a non-existent task returns 404."""
    fake_task_id = uuid.uuid4()
    resp = await client.put(
        f"/api/ai/prompts/{fake_task_id}",
        json={"template_text": "Doesn't matter"},
        headers=admin_headers,
    )
    assert resp.status_code == 404
    data = resp.json()
    assert data["error"]["code"] == "not_found"


@pytest.mark.asyncio
async def test_multiple_updates_create_version_chain(client: AsyncClient, admin_headers: dict, ai_task: AITask):
    """Multiple PUTs create an incrementing version chain."""
    for i in range(1, 4):
        resp = await client.put(
            f"/api/ai/prompts/{ai_task.id}",
            json={"template_text": f"Version {i} template"},
            headers=admin_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["version"] == i
        assert data["is_active"] is True


# ---------------------------------------------------------------------------
# Reset user override (POST reset)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reset_prompt_deactivates_all_overrides(
    client: AsyncClient,
    admin_headers: dict,
    ai_task: AITask,
    system_prompt: AIPromptTemplate,
    user_prompt: AIPromptTemplate,
):
    """POST reset deactivates every template for the task and returns the task default."""
    resp = await client.post(f"/api/ai/prompts/{user_prompt.task_id}/reset", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    # After reset, the shipped task default is authoritative again
    assert data["created_by"] is None
    assert data["template_text"] == ai_task.default_prompt_template
    assert data["version"] == 0
    assert data["is_active"] is True


@pytest.mark.asyncio
async def test_reset_returns_task_fallback_when_no_system_prompt(
    client: AsyncClient,
    admin_headers: dict,
    ai_task: AITask,
    user_prompt: AIPromptTemplate,
):
    """Reset with no system default falls back to the task's default_prompt_template."""
    resp = await client.post(f"/api/ai/prompts/{ai_task.id}/reset", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["created_by"] is None
    assert data["template_text"] == ai_task.default_prompt_template
    assert data["version"] == 0


@pytest.mark.asyncio
async def test_reset_is_idempotent(
    client: AsyncClient,
    admin_headers: dict,
    ai_task: AITask,
    system_prompt: AIPromptTemplate,
):
    """Resetting twice still lands on the task default."""
    for _ in range(2):
        resp = await client.post(f"/api/ai/prompts/{system_prompt.task_id}/reset", headers=admin_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["template_text"] == ai_task.default_prompt_template
        assert data["version"] == 0


@pytest.mark.asyncio
async def test_reset_then_get_active_returns_task_default(
    client: AsyncClient,
    admin_headers: dict,
    ai_task: AITask,
    system_prompt: AIPromptTemplate,
    user_prompt: AIPromptTemplate,
):
    """After reset, GET active prompt returns the task default, not a deactivated override."""
    # Reset
    await client.post(f"/api/ai/prompts/{user_prompt.task_id}/reset", headers=admin_headers)

    # Verify active prompt is now the task default
    resp = await client.get(f"/api/ai/prompts/{user_prompt.task_id}", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["created_by"] is None
    assert data["template_text"] == ai_task.default_prompt_template
    assert data["version"] == 0


@pytest.mark.asyncio
async def test_reset_not_found_for_invalid_task(client: AsyncClient, admin_headers: dict):
    """Resetting a non-existent task returns 404."""
    fake_task_id = uuid.uuid4()
    resp = await client.post(f"/api/ai/prompts/{fake_task_id}/reset", headers=admin_headers)
    assert resp.status_code == 404
    data = resp.json()
    assert data["error"]["code"] == "not_found"


# ---------------------------------------------------------------------------
# Prompt history
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_history_includes_all_versions(
    client: AsyncClient,
    admin_headers: dict,
    ai_task: AITask,
    system_prompt: AIPromptTemplate,
):
    """History endpoint returns all versions (system + user) ordered by version descending."""
    # Create two user overrides
    await client.put(
        f"/api/ai/prompts/{ai_task.id}",
        json={"template_text": "User v1"},
        headers=admin_headers,
    )
    await client.put(
        f"/api/ai/prompts/{ai_task.id}",
        json={"template_text": "User v2"},
        headers=admin_headers,
    )

    resp = await client.get(f"/api/ai/prompts/{ai_task.id}/history", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    # Should have system default + 2 user versions = 3
    assert len(data) == 3

    # Ordered by version descending
    versions = [p["version"] for p in data]
    assert versions == sorted(versions, reverse=True)


@pytest.mark.asyncio
async def test_get_history_shows_active_flags(
    client: AsyncClient,
    admin_headers: dict,
    ai_task: AITask,
    system_prompt: AIPromptTemplate,
):
    """History shows which versions are active and which have been deactivated."""
    # Create two versions — only the latest should be active
    await client.put(
        f"/api/ai/prompts/{ai_task.id}",
        json={"template_text": "First override"},
        headers=admin_headers,
    )
    await client.put(
        f"/api/ai/prompts/{ai_task.id}",
        json={"template_text": "Second override"},
        headers=admin_headers,
    )

    resp = await client.get(f"/api/ai/prompts/{ai_task.id}/history", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()

    active_prompts = [p for p in data if p["is_active"]]
    inactive_prompts = [p for p in data if not p["is_active"]]

    # Only the newest version stays active — saving deactivates every prior
    # template for the task, the seeded system default included.
    assert len(active_prompts) == 1
    assert len(inactive_prompts) == 2


@pytest.mark.asyncio
async def test_get_history_empty_for_task_with_no_templates(client: AsyncClient, auth_headers: dict, ai_task: AITask):
    """History returns an empty list when no prompt templates exist for the task."""
    resp = await client.get(f"/api/ai/prompts/{ai_task.id}/history", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data == []


@pytest.mark.asyncio
async def test_get_history_includes_all_users_prompts(
    client: AsyncClient,
    admin_headers: dict,
    ai_task: AITask,
    system_prompt: AIPromptTemplate,
    user_prompt: AIPromptTemplate,
):
    """History is per-task: every user sees every author's versions."""
    resp = await client.get(f"/api/ai/prompts/{ai_task.id}/history", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    ids = [p["id"] for p in data]
    assert str(system_prompt.id) in ids
    assert str(user_prompt.id) in ids


# ---------------------------------------------------------------------------
# Invalid task_id handling
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_prompt_invalid_uuid_format(client: AsyncClient, auth_headers: dict):
    """A malformed UUID in the path returns 422 (validation error)."""
    resp = await client.get("/api/ai/prompts/not-a-uuid", headers=auth_headers)
    assert resp.status_code in (400, 422)


@pytest.mark.asyncio
async def test_put_prompt_invalid_uuid_format(client: AsyncClient, admin_headers: dict):
    """PUT with a malformed UUID returns 422."""
    resp = await client.put(
        "/api/ai/prompts/not-a-uuid",
        json={"template_text": "test"},
        headers=admin_headers,
    )
    assert resp.status_code in (400, 422)


@pytest.mark.asyncio
async def test_reset_prompt_invalid_uuid_format(client: AsyncClient, admin_headers: dict):
    """POST reset with a malformed UUID returns 422."""
    resp = await client.post("/api/ai/prompts/not-a-uuid/reset", headers=admin_headers)
    assert resp.status_code in (400, 422)


@pytest.mark.asyncio
async def test_history_prompt_invalid_uuid_format(client: AsyncClient, auth_headers: dict):
    """GET history with a malformed UUID returns 422."""
    resp = await client.get("/api/ai/prompts/not-a-uuid/history", headers=auth_headers)
    assert resp.status_code in (400, 422)


@pytest.mark.asyncio
async def test_get_prompt_nonexistent_task_id(client: AsyncClient, auth_headers: dict):
    """A valid UUID that doesn't correspond to any task returns 404."""
    fake_id = uuid.uuid4()
    resp = await client.get(f"/api/ai/prompts/{fake_id}", headers=auth_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_put_prompt_nonexistent_task_id(client: AsyncClient, admin_headers: dict):
    """PUT to a non-existent task returns 404."""
    fake_id = uuid.uuid4()
    resp = await client.put(
        f"/api/ai/prompts/{fake_id}",
        json={"template_text": "anything"},
        headers=admin_headers,
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_reset_prompt_nonexistent_task_id(client: AsyncClient, admin_headers: dict):
    """POST reset for a non-existent task returns 404."""
    fake_id = uuid.uuid4()
    resp = await client.post(f"/api/ai/prompts/{fake_id}/reset", headers=admin_headers)
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Authentication required
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_prompts_requires_auth(client: AsyncClient, ai_task: AITask):
    """GET /api/ai/prompts without auth returns 401."""
    resp = await client.get("/api/ai/prompts")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_get_active_prompt_requires_auth(client: AsyncClient, ai_task: AITask):
    """GET /api/ai/prompts/{task_id} without auth returns 401."""
    resp = await client.get(f"/api/ai/prompts/{ai_task.id}")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_update_prompt_requires_auth(client: AsyncClient, ai_task: AITask):
    """PUT /api/ai/prompts/{task_id} without auth returns 401."""
    resp = await client.put(
        f"/api/ai/prompts/{ai_task.id}",
        json={"template_text": "Unauthorized"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_reset_prompt_requires_auth(client: AsyncClient, ai_task: AITask):
    """POST /api/ai/prompts/{task_id}/reset without auth returns 401."""
    resp = await client.post(f"/api/ai/prompts/{ai_task.id}/reset")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_history_requires_auth(client: AsyncClient, ai_task: AITask):
    """GET /api/ai/prompts/{task_id}/history without auth returns 401."""
    resp = await client.get(f"/api/ai/prompts/{ai_task.id}/history")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_prompt_writes_require_admin(client: AsyncClient, auth_headers: dict, ai_task: AITask):
    """PUT and reset are admin-only; a regular user gets 403."""
    resp = await client.put(
        f"/api/ai/prompts/{ai_task.id}",
        json={"template_text": "not allowed"},
        headers=auth_headers,
    )
    assert resp.status_code == 403

    resp = await client.post(f"/api/ai/prompts/{ai_task.id}/reset", headers=auth_headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_invalid_token_rejected(client: AsyncClient, ai_task: AITask):
    """A request with an invalid JWT is rejected with 401."""
    headers = {"Authorization": "Bearer invalid.token.here"}
    resp = await client.get("/api/ai/prompts", headers=headers)
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Response schema validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_prompt_response_has_expected_fields(
    client: AsyncClient, auth_headers: dict, system_prompt: AIPromptTemplate
):
    """Prompt response includes all expected fields from AIPromptTemplateResponse."""
    resp = await client.get(f"/api/ai/prompts/{system_prompt.task_id}", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    expected_fields = {
        "id",
        "task_id",
        "created_by",
        "name",
        "template_text",
        "variables",
        "is_active",
        "version",
        "created_at",
    }
    assert expected_fields.issubset(data.keys())


@pytest.mark.asyncio
async def test_prompt_variables_is_list(client: AsyncClient, admin_headers: dict, ai_task: AITask):
    """The variables field is a list."""
    resp = await client.put(
        f"/api/ai/prompts/{ai_task.id}",
        json={"template_text": "Template with {{ entry.title }}"},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data["variables"], list)
    assert "entry" in data["variables"]


# ---------------------------------------------------------------------------
# Per-task (global) override behavior
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_override_applies_to_all_users(
    client: AsyncClient,
    auth_headers: dict,
    admin_headers: dict,
    ai_task: AITask,
):
    """An override saved by an admin is the active prompt for everyone."""
    # admin_user creates an override
    await client.put(
        f"/api/ai/prompts/{ai_task.id}",
        json={"template_text": "admin custom template"},
        headers=admin_headers,
    )

    # A regular user gets the same task-wide override
    resp = await client.get(f"/api/ai/prompts/{ai_task.id}", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["template_text"] == "admin custom template"
    assert data["version"] == 1


@pytest.mark.asyncio
async def test_reset_clears_override_for_everyone(
    client: AsyncClient,
    auth_headers: dict,
    admin_headers: dict,
    ai_task: AITask,
    system_prompt: AIPromptTemplate,
):
    """Reset is task-wide: after it, every user is back on the task default."""
    # Admin saves successive versions
    await client.put(
        f"/api/ai/prompts/{ai_task.id}",
        json={"template_text": "first template"},
        headers=admin_headers,
    )
    await client.put(
        f"/api/ai/prompts/{ai_task.id}",
        json={"template_text": "second template"},
        headers=admin_headers,
    )

    # Admin resets — the task-wide override is gone for everyone
    await client.post(f"/api/ai/prompts/{ai_task.id}/reset", headers=admin_headers)

    for headers in (auth_headers, admin_headers):
        resp = await client.get(f"/api/ai/prompts/{ai_task.id}", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["template_text"] == ai_task.default_prompt_template
        assert data["version"] == 0


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_override_then_reset_then_create_again(
    client: AsyncClient,
    admin_headers: dict,
    ai_task: AITask,
    system_prompt: AIPromptTemplate,
):
    """Full lifecycle: create override -> reset -> create new override (version continues)."""
    # Version counter spans all rows for the task, so the first override
    # continues from the seeded system default (v1).
    resp = await client.put(
        f"/api/ai/prompts/{ai_task.id}",
        json={"template_text": "Override v1"},
        headers=admin_headers,
    )
    first_version = resp.json()["version"]
    assert first_version == system_prompt.version + 1

    # Reset
    await client.post(f"/api/ai/prompts/{ai_task.id}/reset", headers=admin_headers)

    # New override — version counter continues past the deactivated rows
    resp = await client.put(
        f"/api/ai/prompts/{ai_task.id}",
        json={"template_text": "Override v2"},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["version"] == first_version + 1
    assert resp.json()["template_text"] == "Override v2"
    assert resp.json()["is_active"] is True


@pytest.mark.asyncio
async def test_multiple_tasks_independent_prompts(
    client: AsyncClient,
    admin_headers: dict,
    ai_task: AITask,
    second_ai_task: AITask,
):
    """Overrides for one task do not affect another task."""
    # Override first task
    await client.put(
        f"/api/ai/prompts/{ai_task.id}",
        json={"template_text": "Summary override"},
        headers=admin_headers,
    )

    # Second task should still fall back to its own default
    resp = await client.get(f"/api/ai/prompts/{second_ai_task.id}", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["template_text"] == second_ai_task.default_prompt_template
    assert data["version"] == 0


# ---------------------------------------------------------------------------
# Preview rendering
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_preview_renders_against_specific_entry(
    client: AsyncClient,
    auth_headers: dict,
    ai_task: AITask,
    test_entry,
):
    """entry_id renders the template against that entry's fields."""
    resp = await client.post(
        f"/api/ai/prompts/{ai_task.id}/preview",
        json={"template_text": "Title: {{ entry.title }}", "entry_id": str(test_entry.id)},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["error"] is None
    assert data["sample_source"] == "entry"
    assert "Title: Test Entry" in data["rendered_user"]


@pytest.mark.asyncio
async def test_preview_use_sample_ignores_real_entries(
    client: AsyncClient,
    auth_headers: dict,
    ai_task: AITask,
    test_entry,
):
    """use_sample forces the built-in placeholder even when entries exist."""
    resp = await client.post(
        f"/api/ai/prompts/{ai_task.id}/preview",
        json={"template_text": "Title: {{ entry.title }}", "use_sample": True},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["sample_source"] == "placeholder"
    assert "Test Entry" not in data["rendered_user"]


@pytest.mark.asyncio
async def test_preview_unknown_entry_404(
    client: AsyncClient,
    auth_headers: dict,
    ai_task: AITask,
):
    resp = await client.post(
        f"/api/ai/prompts/{ai_task.id}/preview",
        json={"template_text": "x", "entry_id": str(uuid.uuid4())},
        headers=auth_headers,
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_preview_reports_jinja_errors(
    client: AsyncClient,
    auth_headers: dict,
    ai_task: AITask,
):
    resp = await client.post(
        f"/api/ai/prompts/{ai_task.id}/preview",
        json={"template_text": "{% if entry %}unclosed"},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["error"] is not None
    assert data["rendered_user"] is None
