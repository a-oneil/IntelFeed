"""Tests for AI Results API endpoints."""

import uuid

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ai_task import AITask
from app.models.entry import Entry

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def ai_task(db_session: AsyncSession) -> AITask:
    """Create a sample AI task for result tests."""
    task = AITask(
        name="article_summary",
        display_name="Article Summary",
        description="Generate a concise summary of the article",
        category="analysis",
        default_prompt_template="Summarize {{ entry.content_text }}",
        output_schema={"type": "object"},
        is_system=True,
    )
    db_session.add(task)
    await db_session.flush()
    return task


# ---------------------------------------------------------------------------
# GET /api/ai/results/{target_type}/{target_id} — list results for entity
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_results_empty(client: AsyncClient, auth_headers: dict, test_entry: Entry):
    """Getting results for an entity with no AI results returns empty list."""
    resp = await client.get(f"/api/ai/results/entry/{test_entry.id}", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_get_results_invalid_target_type(client: AsyncClient, auth_headers: dict):
    """Using an invalid target_type returns 400."""
    fake_id = uuid.uuid4()
    resp = await client.get(f"/api/ai/results/invalid_type/{fake_id}", headers=auth_headers)
    assert resp.status_code == 400
    # App reshapes HTTPException via http_error_handler → {"error": {code, message, details}}
    assert "Invalid target_type" in resp.json()["error"]["message"]


@pytest.mark.asyncio
async def test_get_results_requires_auth(client: AsyncClient, test_entry: Entry):
    """Requests without auth token are rejected with 401."""
    resp = await client.get(f"/api/ai/results/entry/{test_entry.id}")
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# GET /api/ai/results/{target_type}/{target_id}/{task_name} — single task
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_result_for_task_no_results(
    client: AsyncClient,
    auth_headers: dict,
    test_entry: Entry,
    ai_task: AITask,
):
    """Getting a specific task result when none exist returns null."""
    resp = await client.get(
        f"/api/ai/results/entry/{test_entry.id}/{ai_task.name}",
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json() is None


@pytest.mark.asyncio
async def test_get_result_for_task_not_found(client: AsyncClient, auth_headers: dict, test_entry: Entry):
    """Requesting results for a non-existent task name returns 404."""
    resp = await client.get(
        f"/api/ai/results/entry/{test_entry.id}/nonexistent_task",
        headers=auth_headers,
    )
    assert resp.status_code == 404
    assert "not found" in resp.json()["error"]["message"]


@pytest.mark.asyncio
async def test_get_result_for_task_invalid_target_type(client: AsyncClient, auth_headers: dict):
    """Invalid target_type on task-specific endpoint returns 400."""
    fake_id = uuid.uuid4()
    resp = await client.get(f"/api/ai/results/bogus/{fake_id}/some_task", headers=auth_headers)
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_get_result_for_task_requires_auth(client: AsyncClient, test_entry: Entry):
    """Task-specific endpoint requires authentication."""
    resp = await client.get(f"/api/ai/results/entry/{test_entry.id}/article_summary")
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# GET /api/ai/results/{target_type}/{target_id}/{task_name}/history
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_result_history_empty(
    client: AsyncClient,
    auth_headers: dict,
    test_entry: Entry,
    ai_task: AITask,
):
    """History for a task with no results returns empty list."""
    resp = await client.get(
        f"/api/ai/results/entry/{test_entry.id}/{ai_task.name}/history",
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_get_result_history_task_not_found(client: AsyncClient, auth_headers: dict, test_entry: Entry):
    """History for a non-existent task returns 404."""
    resp = await client.get(
        f"/api/ai/results/entry/{test_entry.id}/nonexistent_task/history",
        headers=auth_headers,
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_get_result_history_invalid_target_type(client: AsyncClient, auth_headers: dict):
    """Invalid target_type on history endpoint returns 400."""
    fake_id = uuid.uuid4()
    resp = await client.get(f"/api/ai/results/wrong/{fake_id}/some_task/history", headers=auth_headers)
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# POST /api/ai/results/{target_type}/{target_id}/run — run AI task
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_ai_task_not_configured(client: AsyncClient, auth_headers: dict, test_entry: Entry):
    """Running a task with no AI provider configured returns 422."""
    resp = await client.post(
        f"/api/ai/results/entry/{test_entry.id}/run",
        json={"task_name": "article_summary", "force": False},
        headers=auth_headers,
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_run_ai_task_invalid_target_type(client: AsyncClient, auth_headers: dict):
    """Running a task with invalid target_type returns 400."""
    fake_id = uuid.uuid4()
    resp = await client.post(
        f"/api/ai/results/nope/{fake_id}/run",
        json={"task_name": "article_summary", "force": False},
        headers=auth_headers,
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_run_ai_task_requires_auth(client: AsyncClient, test_entry: Entry):
    """Run endpoint requires authentication."""
    resp = await client.post(
        f"/api/ai/results/entry/{test_entry.id}/run",
        json={"task_name": "article_summary", "force": False},
    )
    assert resp.status_code == 401
