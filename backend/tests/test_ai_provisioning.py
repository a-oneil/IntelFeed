"""Turning a provider row into a working AI configuration.

The bug these cover: registering a provider told the admin "saved" and left the
instance doing zero AI, because work runs off `ai_task_assignments` and nothing
created those rows for a provider added after boot.
"""

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.prompts.defaults import SYSTEM_TASKS
from app.ai.provisioning import pick_model, route_tasks_to_provider, usable_models
from app.models.ai_provider import AIProvider
from app.models.ai_task import AITask
from app.models.ai_task_assignment import AITaskAssignment


@pytest.fixture
async def system_tasks(db_session: AsyncSession) -> list[AITask]:
    """The real system task catalog.

    main.py seeds these at startup, which tests don't run. Seeding the genuine
    list rather than a stand-in matters here: these tests are about which tasks
    are agentic and which model each one asks for, so a fake catalog would prove
    nothing about the behaviour that broke.
    """
    tasks = [
        AITask(
            name=t["name"],
            display_name=t["display_name"],
            description=t.get("description"),
            category=t.get("category"),
            default_prompt_template=t["default_prompt_template"],
            default_system_template=t.get("default_system_template"),
            is_system=True,
        )
        for t in SYSTEM_TASKS
    ]
    db_session.add_all(tasks)
    await db_session.flush()
    return tasks


def test_pick_model_keeps_a_name_the_provider_serves():
    assert pick_model("claude-sonnet-4-6", ["claude-sonnet-4-6", "claude-haiku-4-5"]) == "claude-sonnet-4-6"


def test_pick_model_resolves_an_alias_by_substring():
    # "sonnet" is the alias the CLI provider takes; the API serves a full id.
    assert pick_model("sonnet", ["claude-opus-4-6", "claude-sonnet-4-6"]) == "claude-sonnet-4-6"


def test_pick_model_falls_back_to_a_real_model_rather_than_404ing():
    # The Claude-family defaults are meaningless on an Ollama host.
    assert pick_model("claude-haiku-4-5-20251001", ["qwen3.5:9b", "gemma4:12b"]) == "qwen3.5:9b"


def test_pick_model_never_picks_an_embedding_model():
    """Embedding models sit alongside chat models in an Ollama listing and cannot
    answer a prompt, so choosing one makes every call fail."""
    assert pick_model("claude-sonnet-4-6", ["nomic-embed-text", "qwen3.5:9b"]) == "qwen3.5:9b"
    assert usable_models(["nomic-embed-text", "mxbai-embed-large"]) == []


def test_pick_model_keeps_the_preferred_name_when_nothing_is_known():
    """An untested provider has no model list. Inventing a model would hide the
    real problem behind a wrong-model error."""
    assert pick_model("claude-sonnet-4-6", None) == "claude-sonnet-4-6"
    assert pick_model("claude-sonnet-4-6", []) == "claude-sonnet-4-6"


@pytest.mark.asyncio
async def test_routing_assigns_every_compatible_task(db_session: AsyncSession, admin_user, system_tasks):
    provider = AIProvider(
        name="Ollama", provider_type="ollama", is_active=True, models=["qwen3.5:9b", "nomic-embed-text"]
    )
    db_session.add(provider)
    await db_session.flush()

    routing = await route_tasks_to_provider(db_session, provider, created_by=admin_user.id, take_over=False)

    assert routing.total > 20, "the system task catalog should be wired wholesale, not a handful"
    assert routing.model == "qwen3.5:9b"
    rows = (await db_session.execute(select(AITaskAssignment))).scalars().all()
    assert len(rows) == routing.total
    assert all(r.provider_id == provider.id and r.is_enabled for r in rows)
    # Never an embedding model, which cannot answer a prompt at all.
    assert all("embed" not in r.model_name for r in rows)


@pytest.mark.asyncio
async def test_routing_leaves_agentic_tasks_on_a_tool_less_provider(db_session: AsyncSession, admin_user, system_tasks):
    """A chat-only provider running an agentic task returns tool-less output that
    reads like success — the merge task reporting merges it never applied."""
    provider = AIProvider(name="Claude", provider_type="claude", is_active=True, models=["claude-sonnet-4-6"])
    db_session.add(provider)
    await db_session.flush()

    routing = await route_tasks_to_provider(db_session, provider, created_by=admin_user.id, take_over=False)

    assert "entity_merge_maintenance" in routing.skipped_agentic
    assert "copilot" in routing.skipped_agentic
    assert "article_summary" in routing.assigned
    names = {
        t.name
        for t in (await db_session.execute(select(AITask))).scalars().all()
        if t.id in {r.task_id for r in (await db_session.execute(select(AITaskAssignment))).scalars().all()}
    }
    assert "entity_merge_maintenance" not in names


@pytest.mark.asyncio
async def test_routing_without_take_over_leaves_existing_assignments_alone(
    db_session: AsyncSession, admin_user, system_tasks
):
    """A first-run fill must not move whatever the operator set up by hand."""
    cli = AIProvider(name="CLI", provider_type="claude_code", is_active=True, models=["sonnet"])
    ollama = AIProvider(name="Ollama", provider_type="ollama", is_active=True, models=["qwen3.5:9b"])
    db_session.add_all([cli, ollama])
    await db_session.flush()
    task = (await db_session.execute(select(AITask).where(AITask.name == "article_summary"))).scalar_one()
    db_session.add(AITaskAssignment(task_id=task.id, provider_id=cli.id, model_name="sonnet", is_enabled=True))
    await db_session.flush()

    routing = await route_tasks_to_provider(db_session, ollama, created_by=admin_user.id, take_over=False)

    assert "article_summary" not in routing.assigned
    assert routing.reassigned == []
    kept = (await db_session.execute(select(AITaskAssignment).where(AITaskAssignment.task_id == task.id))).scalar_one()
    assert kept.provider_id == cli.id


@pytest.mark.asyncio
async def test_take_over_moves_tasks_the_startup_seeder_parked_on_the_cli(
    db_session: AsyncSession, admin_user, system_tasks
):
    """On a fresh install the seeder routes what it can at the auto-created CLI
    provider. Without take_over, onboarding could never move those — which is
    why adding Ollama in the wizard changed nothing."""
    cli = AIProvider(name="CLI", provider_type="claude_code", is_active=True, models=["sonnet"])
    ollama = AIProvider(name="Ollama", provider_type="ollama", is_active=True, models=["qwen3.5:9b"])
    db_session.add_all([cli, ollama])
    await db_session.flush()
    task = (await db_session.execute(select(AITask).where(AITask.name == "article_summary"))).scalar_one()
    db_session.add(AITaskAssignment(task_id=task.id, provider_id=cli.id, model_name="sonnet", is_enabled=True))
    await db_session.flush()

    routing = await route_tasks_to_provider(db_session, ollama, created_by=admin_user.id, take_over=True)

    assert "article_summary" in routing.reassigned
    moved = (await db_session.execute(select(AITaskAssignment).where(AITaskAssignment.task_id == task.id))).scalar_one()
    assert moved.provider_id == ollama.id
    assert moved.model_name == "qwen3.5:9b"


@pytest.mark.asyncio
async def test_routing_is_idempotent(db_session: AsyncSession, admin_user, system_tasks):
    provider = AIProvider(name="Ollama", provider_type="ollama", is_active=True, models=["qwen3.5:9b"])
    db_session.add(provider)
    await db_session.flush()

    first = await route_tasks_to_provider(db_session, provider, created_by=admin_user.id, take_over=True)
    second = await route_tasks_to_provider(db_session, provider, created_by=admin_user.id, take_over=True)

    assert second.assigned == [] and second.reassigned == []
    rows = (await db_session.execute(select(AITaskAssignment))).scalars().all()
    assert len(rows) == first.total


@pytest.mark.asyncio
async def test_commission_refuses_an_unreachable_provider(
    client: AsyncClient, admin_headers: dict, db_session: AsyncSession
):
    """Routing 30 tasks at a host that can't be reached just moves the error
    somewhere harder to find, so the connectivity check gates everything."""
    provider = AIProvider(name="Nowhere", provider_type="ollama", base_url="http://127.0.0.1:1", is_active=True)
    db_session.add(provider)
    await db_session.flush()

    response = await client.post(f"/api/ai/providers/{provider.id}/commission", headers=admin_headers)

    assert response.status_code == 200
    assert response.json()["success"] is False
    assert (await db_session.execute(select(AITaskAssignment))).scalars().first() is None


@pytest.mark.asyncio
async def test_commission_is_admin_only(client: AsyncClient, auth_headers: dict, db_session: AsyncSession):
    provider = AIProvider(name="Ollama", provider_type="ollama", is_active=True)
    db_session.add(provider)
    await db_session.flush()

    response = await client.post(f"/api/ai/providers/{provider.id}/commission", headers=auth_headers)
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_commission_404s_on_an_unknown_provider(client: AsyncClient, admin_headers: dict):
    import uuid

    response = await client.post(f"/api/ai/providers/{uuid.uuid4()}/commission", headers=admin_headers)
    assert response.status_code == 404
