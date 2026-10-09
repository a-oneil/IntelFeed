"""The readiness probe behind the onboarding wizard's first and last steps."""

from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ai_provider import AIProvider
from app.models.ai_task import AITask
from app.models.ai_task_assignment import AITaskAssignment
from app.models.country import Country
from app.models.feed import Feed


@pytest.mark.asyncio
async def test_status_reports_an_empty_instance_as_unseeded(client: AsyncClient, auth_headers: dict):
    response = await client.get("/api/onboarding/status", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()

    ref = data["reference_data"]
    assert ref["ok"] is False
    # Every seeder is named, so the step can list what's missing rather than
    # just saying "something is wrong".
    assert {"countries", "attack", "cwe", "vendors", "products"} <= set(ref["missing"])
    assert ref["remedy"].endswith("seed_all.py")
    assert "autolinker" in ref["consequence"]
    assert data["ready"] is False


@pytest.mark.asyncio
async def test_status_counts_feeds_by_poll_outcome(client: AsyncClient, auth_headers: dict, db_session: AsyncSession):
    from datetime import UTC, datetime

    db_session.add_all(
        [
            Feed(title="polled", url="https://a.example/feed", last_fetched_at=datetime.now(UTC), error_count=0),
            Feed(title="broken", url="https://b.example/feed", last_fetched_at=datetime.now(UTC), error_count=9),
            Feed(title="fresh", url="https://c.example/feed", last_fetched_at=None, error_count=0),
        ]
    )
    await db_session.flush()

    data = (await client.get("/api/onboarding/status", headers=auth_headers)).json()
    assert data["feeds"] == {"total": 3, "polled_ok": 1, "errored": 1, "never_polled": 1}


@pytest.mark.asyncio
async def test_status_ignores_inactive_feeds(client: AsyncClient, auth_headers: dict, db_session: AsyncSession):
    """A disabled feed shouldn't make the verify step claim coverage it hasn't got."""
    db_session.add(Feed(title="off", url="https://off.example/feed", is_active=False))
    await db_session.flush()

    data = (await client.get("/api/onboarding/status", headers=auth_headers)).json()
    assert data["feeds"]["total"] == 0


@pytest.mark.asyncio
async def test_reference_check_needs_a_real_catalog_not_one_row(
    client: AsyncClient, auth_headers: dict, db_session: AsyncSession
):
    """The floors exist so a hand-inserted row can't read as a finished seed."""
    db_session.add(Country(name="Testland", iso_code="TL"))
    await db_session.flush()

    data = (await client.get("/api/onboarding/status", headers=auth_headers)).json()
    countries = next(c for c in data["reference_data"]["checks"] if c["key"] == "countries")
    assert countries["count"] == 1
    assert countries["ok"] is False


@pytest.mark.asyncio
async def test_status_requires_authentication(client: AsyncClient):
    assert (await client.get("/api/onboarding/status")).status_code == 401


@pytest.mark.asyncio
async def test_status_is_open_to_non_admins(client: AsyncClient, auth_headers: dict):
    """A non-admin hitting an unusable instance deserves to be told why."""
    assert (await client.get("/api/onboarding/status", headers=auth_headers)).status_code == 200


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("provider_type", "is_active", "expected"),
    [("ollama", True, "ollama"), ("claude", True, "claude"), ("ollama", False, "claude_code")],
)
async def test_status_prefers_configured_provider_over_startup_cli(
    client: AsyncClient,
    auth_headers: dict,
    db_session: AsyncSession,
    provider_type: str,
    is_active: bool,
    expected: str,
):
    now = datetime.now(UTC)
    db_session.add_all(
        [
            AIProvider(
                name="Startup CLI", provider_type="claude_code", is_active=True, created_at=now - timedelta(days=1)
            ),
            AIProvider(name="Configured provider", provider_type=provider_type, is_active=is_active, created_at=now),
        ]
    )
    await db_session.flush()
    response = await client.get("/api/onboarding/status", headers=auth_headers)
    assert response.status_code == 200
    # tasks_assigned is 0 throughout: these providers exist but nothing is routed
    # at them, which is exactly the state that used to read as configured AI.
    assert response.json()["ai"] == {"providers": 2, "active": expected, "tasks_assigned": 0}


@pytest.mark.asyncio
async def test_remedy_is_a_command_the_reader_can_paste(client: AsyncClient, auth_headers: dict):
    """The UI used to wrap this in a hardcoded `-f docker-compose.prod.yml`, which was
    wrong on every dev install. The whole line comes from the server now."""
    data = (await client.get("/api/onboarding/status", headers=auth_headers)).json()
    remedy = data["reference_data"]["remedy"]
    assert remedy.startswith("docker compose -f docker-compose.")
    assert remedy.endswith("exec api python scripts/seed/seed_all.py")


@pytest.mark.asyncio
async def test_a_provider_with_no_tasks_routed_at_it_is_not_configured_ai(
    client: AsyncClient, admin_headers: dict, db_session: AsyncSession
):
    """The gap the wizard's AI step used to leave: a provider row exists, the step
    reads as done, and the instance runs nothing because no task points at it."""
    db_session.add(AIProvider(name="Ollama", provider_type="ollama", is_active=True))
    await db_session.flush()

    data = (await client.get("/api/onboarding/status", headers=admin_headers)).json()
    assert data["ai"]["active"] == "ollama"
    assert data["ai"]["tasks_assigned"] == 0


@pytest.mark.asyncio
async def test_tasks_assigned_counts_only_work_on_a_chosen_provider(
    client: AsyncClient, admin_headers: dict, db_session: AsyncSession
):
    """The startup seeder routes agentic tasks at the auto-created CLI provider on
    every install, so counting those would report a bare install as AI-ready."""
    cli = AIProvider(name="CLI", provider_type="claude_code", is_active=True)
    ollama = AIProvider(name="Ollama", provider_type="ollama", is_active=True)
    task_a = AITask(name="t_cli", display_name="CLI task", default_prompt_template="x", is_system=True)
    task_b = AITask(name="t_real", display_name="Real task", default_prompt_template="x", is_system=True)
    db_session.add_all([cli, ollama, task_a, task_b])
    await db_session.flush()
    db_session.add_all(
        [
            AITaskAssignment(task_id=task_a.id, provider_id=cli.id, model_name="sonnet", is_enabled=True),
            AITaskAssignment(task_id=task_b.id, provider_id=ollama.id, model_name="qwen3.5:9b", is_enabled=True),
        ]
    )
    await db_session.flush()

    data = (await client.get("/api/onboarding/status", headers=admin_headers)).json()
    assert data["ai"]["tasks_assigned"] == 1


@pytest.mark.asyncio
async def test_a_disabled_assignment_does_not_count_as_wired(
    client: AsyncClient, admin_headers: dict, db_session: AsyncSession
):
    ollama = AIProvider(name="Ollama", provider_type="ollama", is_active=True)
    task = AITask(name="t_off", display_name="Off", default_prompt_template="x", is_system=True)
    db_session.add_all([ollama, task])
    await db_session.flush()
    db_session.add(AITaskAssignment(task_id=task.id, provider_id=ollama.id, model_name="qwen3.5:9b", is_enabled=False))
    await db_session.flush()

    data = (await client.get("/api/onboarding/status", headers=admin_headers)).json()
    assert data["ai"]["tasks_assigned"] == 0
