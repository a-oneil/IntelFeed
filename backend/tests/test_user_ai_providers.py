"""Personal AI keys: who a key belongs to, which calls it may answer, and what the caps do.

The lookup (``resolve_assignment``) is the whole feature: every branch is
pinned here, with the policy off by default so an untouched instance
behaves exactly as before. The API tests are about isolation: another
person's key is invisible, unroutable and untestable, and share, automation
and system callers never see a personal key at all.
"""

import uuid
from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import select

from app.ai.caller import Caller
from app.config import settings as env_settings
from app.core.security import create_access_token, hash_password
from app.models.ai_provider import AIProvider
from app.models.ai_result import AIResult
from app.models.ai_task import AITask
from app.models.ai_task_assignment import AITaskAssignment
from app.models.shared_entry import SharedEntry
from app.models.user import User
from app.models.user_ai_route import UserAIPreferences, UserAIRoute

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------- fixtures


@pytest_asyncio.fixture
async def site_provider(db_session) -> AIProvider:
    row = AIProvider(name="Lab Ollama", provider_type="ollama", base_url="http://ollama.test:11434")
    db_session.add(row)
    await db_session.flush()
    return row


@pytest_asyncio.fixture
async def my_key(db_session, test_user: User) -> AIProvider:
    row = AIProvider(
        name="OpenRouter personal",
        provider_type="openai_compatible",
        base_url="https://openrouter.ai/api/v1",
        user_id=test_user.id,
    )
    db_session.add(row)
    await db_session.flush()
    return row


@pytest_asyncio.fixture
async def other_user(db_session) -> User:
    user = User(username="mreyes", password_hash=hash_password("pw"), role="user")
    db_session.add(user)
    await db_session.flush()
    return user


@pytest_asyncio.fixture
async def other_headers(other_user: User) -> dict:
    return {"Authorization": f"Bearer {create_access_token(other_user.id, other_user.role)}"}


@pytest_asyncio.fixture
async def other_key(db_session, other_user: User) -> AIProvider:
    row = AIProvider(name="mreyes key", provider_type="claude", user_id=other_user.id)
    db_session.add(row)
    await db_session.flush()
    return row


@pytest_asyncio.fixture
def public_dns(monkeypatch):
    """Resolve every hostname to a public address, so no test depends on the network."""
    import ipaddress

    import app.core.outbound as outbound

    monkeypatch.setattr(outbound, "resolve_host", AsyncMock(return_value=[ipaddress.ip_address("8.8.4.4")]))


@pytest_asyncio.fixture
def policy_on(monkeypatch, public_dns):
    monkeypatch.setattr(env_settings, "allow_user_ai_providers", True)
    monkeypatch.setattr(env_settings, "require_user_ai_provider", False)
    monkeypatch.setattr(env_settings, "user_ai_provider_types", "claude,openai_compatible,ollama")
    monkeypatch.setattr(env_settings, "user_ai_allow_private_endpoints", False)
    monkeypatch.setattr(env_settings, "user_ai_default_monthly_usd", 25.0)
    monkeypatch.setattr(env_settings, "user_ai_daily_request_cap", 300)
    monkeypatch.setattr(env_settings, "site_ai_user_daily_requests", 0)


async def _task(db_session, provider: AIProvider | None, name: str, *, allows: bool = True, **extra) -> AITask:
    task = AITask(
        name=name,
        display_name=name.replace("_", " ").title(),
        default_prompt_template="{{ text }}",
        allows_user_provider=allows,
        **extra,
    )
    db_session.add(task)
    await db_session.flush()
    if provider is not None:
        db_session.add(AITaskAssignment(task_id=task.id, provider_id=provider.id, model_name="qwen"))
        await db_session.flush()
    return task


async def _route(
    db_session, user: User, provider: AIProvider, task: AITask | None, model: str = "sonnet"
) -> UserAIRoute:
    route = UserAIRoute(user_id=user.id, task_id=task.id if task else None, provider_id=provider.id, model_name=model)
    db_session.add(route)
    await db_session.flush()
    return route


def _stub_provider(monkeypatch, content='{"answer": "ok"}', cost_usd=None):
    import app.ai.engine as engine

    response = MagicMock(
        content=content, model="stub", tokens_input=12, tokens_output=4, latency_ms=7, cost_usd=cost_usd
    )
    stub = MagicMock()
    stub.complete = AsyncMock(return_value=response)
    seen: list[AIProvider] = []

    def factory(pm, **kw):
        seen.append(pm)
        return stub

    monkeypatch.setattr(engine, "_get_provider_instance", factory)
    stub.seen = seen
    return stub


async def _only_result(db_session, task: AITask) -> AIResult:
    rows = (await db_session.execute(select(AIResult).where(AIResult.task_id == task.id))).scalars().all()
    assert len(rows) == 1, f"expected one result row, found {len(rows)}"
    return rows[0]


async def _spend(db_session, task: AITask, provider: AIProvider, owner: User, cost: str, n: int = 1) -> None:
    for _ in range(n):
        db_session.add(
            AIResult(
                task_id=task.id,
                provider_id=provider.id,
                provider_name=provider.name,
                is_current=False,
                caller_kind="user",
                user_id=owner.id,
                key_owner_id=owner.id,
                cost_estimate=Decimal(cost),
            )
        )
    await db_session.flush()


# ---------------------------------------------------------------- the lookup


async def test_policy_off_is_todays_behaviour(db_session, test_user, site_provider, my_key, monkeypatch):
    """A route exists, but with the policy off the site provider answers and nothing is attributed to a key."""
    from app.ai.engine import resolve_assignment, run_task

    task = await _task(db_session, site_provider, "detection_rules")
    await _route(db_session, test_user, my_key, task)
    monkeypatch.setattr(env_settings, "allow_user_ai_providers", False)

    resolved = await resolve_assignment(db_session, Caller.user(test_user.id), task.name)
    assert resolved.source == "site" and resolved.provider.id == site_provider.id
    assert resolved.fallback_reason is None and resolved.key_owner_id is None

    _stub_provider(monkeypatch)
    await run_task(db_session, test_user.id, task.name, variables={"text": "x"})
    row = await _only_result(db_session, task)
    assert row.key_owner_id is None and row.provider_name == "Lab Ollama"


async def test_a_persons_key_answers_their_own_task(
    db_session, test_user, site_provider, my_key, policy_on, monkeypatch
):
    from app.ai.engine import resolve_assignment, run_task

    task = await _task(db_session, site_provider, "detection_rules")
    await _route(db_session, test_user, my_key, task, model="anthropic/claude-sonnet-4.6")

    resolved = await resolve_assignment(db_session, Caller.user(test_user.id), task.name)
    assert resolved.source == "user"
    assert resolved.provider.id == my_key.id
    assert resolved.model_name == "anthropic/claude-sonnet-4.6"
    assert resolved.key_owner_id == test_user.id

    stub = _stub_provider(monkeypatch, cost_usd=0.012)
    await run_task(db_session, test_user.id, task.name, variables={"text": "x"})
    assert stub.seen[0].id == my_key.id
    stub.complete.assert_awaited_once()
    assert stub.complete.await_args.kwargs["model"] == "anthropic/claude-sonnet-4.6"
    row = await _only_result(db_session, task)
    assert row.key_owner_id == test_user.id
    assert row.user_id == test_user.id and row.caller_kind == "user"
    assert row.provider_name == "OpenRouter personal"
    assert row.cost_estimate == Decimal("0.012")


async def test_a_personal_key_does_not_spend_the_site_allowance(
    db_session, test_user, site_provider, my_key, policy_on, monkeypatch
):
    from app.ai.engine import run_task, site_requests_today

    task = await _task(db_session, site_provider, "detection_rules")
    await _route(db_session, test_user, my_key, task)
    monkeypatch.setattr(env_settings, "site_ai_user_daily_requests", 1)
    _stub_provider(monkeypatch)

    for i in range(3):
        await run_task(db_session, test_user.id, task.name, variables={"text": str(i)}, force=True)
    assert await site_requests_today(db_session, test_user.id) == 0


async def test_background_automation_and_share_callers_ignore_personal_keys(
    db_session, test_user, site_provider, my_key, policy_on
):
    from app.ai.engine import resolve_assignment

    task = await _task(db_session, site_provider, "detection_rules")
    await _route(db_session, test_user, my_key, None)  # default key, so every allowed task would use it

    for caller in (Caller.system(test_user.id), Caller.automation(test_user.id), Caller.share(test_user.id)):
        resolved = await resolve_assignment(db_session, caller, task.name)
        assert resolved.source == "site", caller
        assert resolved.provider.id == site_provider.id
        assert resolved.key_owner_id is None


async def test_a_task_closed_to_personal_keys_stays_on_the_site(
    db_session, test_user, site_provider, my_key, policy_on
):
    from app.ai.engine import resolve_assignment

    task = await _task(db_session, site_provider, "entry_analysis", allows=False)
    await _route(db_session, test_user, my_key, None)

    resolved = await resolve_assignment(db_session, Caller.user(test_user.id), task.name)
    assert resolved.source == "site" and resolved.fallback_reason is None


async def test_no_key_under_optional_is_the_site_without_a_fallback_note(
    db_session, test_user, site_provider, policy_on
):
    from app.ai.engine import resolve_assignment

    task = await _task(db_session, site_provider, "detection_rules")
    resolved = await resolve_assignment(db_session, Caller.user(test_user.id), task.name)
    assert resolved.source == "site"
    # Most people have no key; that is not a fallback worth a warning stripe.
    assert resolved.fallback_reason is None


async def test_default_key_covers_every_allowed_task_and_a_task_route_wins(
    db_session, test_user, site_provider, my_key, policy_on
):
    from app.ai.engine import resolve_assignment

    rules = await _task(db_session, site_provider, "detection_rules")
    summary = await _task(db_session, site_provider, "article_summary")
    work_key = AIProvider(name="Anthropic work key", provider_type="claude", user_id=test_user.id)
    db_session.add(work_key)
    await db_session.flush()
    await _route(db_session, test_user, my_key, None, model="default-model")
    await _route(db_session, test_user, work_key, rules, model="claude-sonnet-4-6")

    on_rules = await resolve_assignment(db_session, Caller.user(test_user.id), rules.name)
    assert on_rules.provider.id == work_key.id and on_rules.model_name == "claude-sonnet-4-6"
    on_summary = await resolve_assignment(db_session, Caller.user(test_user.id), summary.name)
    assert on_summary.provider.id == my_key.id and on_summary.model_name == "default-model"


async def test_monthly_cap_falls_back_to_the_site_and_says_why(
    db_session, test_user, site_provider, my_key, policy_on, monkeypatch
):
    from app.ai.engine import resolve_assignment, run_task

    task = await _task(db_session, site_provider, "detection_rules")
    await _route(db_session, test_user, my_key, task)
    await _spend(db_session, task, my_key, test_user, "25.00")

    resolved = await resolve_assignment(db_session, Caller.user(test_user.id), task.name)
    assert resolved.source == "site" and resolved.fallback_reason == "monthly_cap"
    assert "monthly spend cap" in resolved.fallback_message

    _stub_provider(monkeypatch)
    out = await run_task(db_session, test_user.id, task.name, variables={"text": "x"}, force=True)
    assert out["_fallback_reason"] == "monthly_cap"
    rows = (await db_session.execute(select(AIResult).where(AIResult.task_id == task.id))).scalars().all()
    fresh = [r for r in rows if r.provider_id == site_provider.id]
    assert len(fresh) == 1 and fresh[0].key_owner_id is None


async def test_a_persons_own_lower_cap_applies(db_session, test_user, site_provider, my_key, policy_on):
    from app.ai.engine import resolve_assignment

    task = await _task(db_session, site_provider, "detection_rules")
    await _route(db_session, test_user, my_key, task)
    db_session.add(UserAIPreferences(user_id=test_user.id, monthly_cap_usd=Decimal("10")))
    await _spend(db_session, task, my_key, test_user, "10.00")

    resolved = await resolve_assignment(db_session, Caller.user(test_user.id), task.name)
    assert resolved.fallback_reason == "monthly_cap"


async def test_daily_request_cap_counts_calls_not_dollars(
    db_session, test_user, site_provider, my_key, policy_on, monkeypatch
):
    """Ollama reports $0, so a dollar cap would never trigger; the request cap does."""
    from app.ai.engine import resolve_assignment

    task = await _task(db_session, site_provider, "detection_rules")
    await _route(db_session, test_user, my_key, task)
    monkeypatch.setattr(env_settings, "user_ai_daily_request_cap", 3)
    await _spend(db_session, task, my_key, test_user, "0", n=3)

    resolved = await resolve_assignment(db_session, Caller.user(test_user.id), task.name)
    assert resolved.source == "site" and resolved.fallback_reason == "daily_cap"


async def test_disabled_paused_disallowed_type_and_private_endpoint_all_fall_back(
    db_session, test_user, site_provider, my_key, policy_on, monkeypatch
):
    from datetime import UTC, datetime, timedelta

    from app.ai.engine import resolve_assignment

    task = await _task(db_session, site_provider, "detection_rules")
    await _route(db_session, test_user, my_key, task)
    caller = Caller.user(test_user.id)

    my_key.is_active = False
    await db_session.flush()
    assert (await resolve_assignment(db_session, caller, task.name)).fallback_reason == "key_disabled"

    my_key.is_active = True
    my_key.paused_until = datetime.now(UTC) + timedelta(hours=1)
    await db_session.flush()
    assert (await resolve_assignment(db_session, caller, task.name)).fallback_reason == "key_paused"

    my_key.paused_until = None
    await db_session.flush()
    monkeypatch.setattr(env_settings, "user_ai_provider_types", "claude")
    assert (await resolve_assignment(db_session, caller, task.name)).fallback_reason == "type_not_allowed"

    monkeypatch.setattr(env_settings, "user_ai_provider_types", "openai_compatible")
    my_key.base_url = "http://10.20.0.2:11434/v1"
    await db_session.flush()
    assert (await resolve_assignment(db_session, caller, task.name)).fallback_reason == "endpoint_blocked"

    # The admin's switch lets the homelab case through.
    monkeypatch.setattr(env_settings, "user_ai_allow_private_endpoints", True)
    assert (await resolve_assignment(db_session, caller, task.name)).source == "user"


async def test_required_policy_refuses_instead_of_falling_back(
    db_session, test_user, site_provider, my_key, policy_on, monkeypatch
):
    from app.ai.engine import UserKeyRequired, resolve_assignment, run_task

    task = await _task(db_session, site_provider, "detection_rules")
    monkeypatch.setattr(env_settings, "require_user_ai_provider", True)

    with pytest.raises(UserKeyRequired) as exc:
        await resolve_assignment(db_session, Caller.user(test_user.id), task.name)
    assert exc.value.status_code == 403
    assert exc.value.code == "user_ai_key_required"
    assert exc.value.reason == "no_key"

    await _route(db_session, test_user, my_key, task)
    await _spend(db_session, task, my_key, test_user, "25.00")
    with pytest.raises(UserKeyRequired) as exc:
        await run_task(db_session, test_user.id, task.name, variables={"text": "x"}, force=True)
    assert exc.value.reason == "monthly_cap"

    # Pipeline tasks are untouched by Required: nobody needs a key for them.
    pipeline = await _task(db_session, site_provider, "entry_analysis", allows=False)
    assert (await resolve_assignment(db_session, Caller.user(test_user.id), pipeline.name)).source == "site"


async def test_fallback_off_refuses_only_when_a_key_exists(db_session, test_user, site_provider, my_key, policy_on):
    from app.ai.engine import UserKeyRequired, resolve_assignment

    task = await _task(db_session, site_provider, "detection_rules")
    db_session.add(UserAIPreferences(user_id=test_user.id, fallback_to_site=False))
    await db_session.flush()

    # No key: there is nothing to fall back from, so the site answers.
    assert (await resolve_assignment(db_session, Caller.user(test_user.id), task.name)).source == "site"

    await _route(db_session, test_user, my_key, task)
    await _spend(db_session, task, my_key, test_user, "25.00")
    with pytest.raises(UserKeyRequired) as exc:
        await resolve_assignment(db_session, Caller.user(test_user.id), task.name)
    assert exc.value.reason == "monthly_cap"
    assert "turned off falling back" in exc.value.message


async def test_a_route_to_someone_elses_key_is_ignored(db_session, test_user, other_key, site_provider, policy_on):
    from app.ai.engine import resolve_assignment

    task = await _task(db_session, site_provider, "detection_rules")
    await _route(db_session, test_user, other_key, task)

    resolved = await resolve_assignment(db_session, Caller.user(test_user.id), task.name)
    assert resolved.source == "site" and resolved.fallback_reason is None


async def test_a_personal_key_answers_a_task_the_site_never_assigned(db_session, test_user, my_key, policy_on):
    from app.ai.engine import resolve_assignment

    task = await _task(db_session, None, "detection_rules")
    assert await resolve_assignment(db_session, Caller.user(test_user.id), task.name) is None
    await _route(db_session, test_user, my_key, task)
    resolved = await resolve_assignment(db_session, Caller.user(test_user.id), task.name)
    assert resolved is not None and resolved.source == "user"


async def test_preflight_refuses_a_report_before_it_is_queued(
    client: AsyncClient, db_session, auth_headers, test_user, site_provider, policy_on, monkeypatch
):
    from app.models.intel_report import IntelReport

    await _task(db_session, site_provider, "report_section")
    monkeypatch.setattr(env_settings, "require_user_ai_provider", True)
    report = IntelReport(created_by=test_user.id, title="T", template_type="threat_brief", content={}, status="draft")
    db_session.add(report)
    await db_session.flush()

    resp = await client.post(f"/api/intel-reports/{report.id}/regenerate", headers=auth_headers)
    assert resp.status_code == 403, resp.text
    assert resp.json()["error"]["code"] == "user_ai_key_required"


# ---------------------------------------------------------------- direct callers


async def test_rule_conversion_ledgers_the_key_owner(
    client: AsyncClient, db_session, auth_headers, test_user, site_provider, my_key, policy_on, monkeypatch
):
    from app.models.detection_rule import DetectionRule

    task = await _task(db_session, site_provider, "detection_rules")
    await _route(db_session, test_user, my_key, task, model="gpt-x")
    rule = DetectionRule(
        created_by=test_user.id,
        rule_type="sigma",
        title="r",
        rule_content="title: r\n",
        severity="high",
        is_draft=False,
    )
    db_session.add(rule)
    await db_session.flush()
    stub = _stub_provider(monkeypatch, content="process where true")

    resp = await client.post(
        f"/api/detection-rules/{rule.id}/convert", json={"target_type": "elastic_ql"}, headers=auth_headers
    )

    assert resp.status_code == 200, resp.text
    assert stub.seen[0].id == my_key.id
    assert stub.complete.await_args.kwargs["model"] == "gpt-x"
    row = await _only_result(db_session, task)
    assert row.key_owner_id == test_user.id and row.provider_name == "OpenRouter personal"


async def test_shared_ask_agent_never_uses_the_sharers_key(
    client: AsyncClient, db_session, test_user, test_entry, site_provider, my_key, policy_on, monkeypatch
):
    task = await _task(db_session, site_provider, "entry_qa")
    await _route(db_session, test_user, my_key, None)
    share = SharedEntry(entry_id=test_entry.id, created_by=test_user.id, is_active=True)
    db_session.add(share)
    await db_session.flush()
    stub = _stub_provider(monkeypatch, content="Gen 7 only.")

    resp = await client.post(f"/api/shared/{share.token}/ask-agent", json={"question": "Affected?"})

    assert resp.status_code == 200, resp.text
    assert stub.seen[0].id == site_provider.id
    row = await _only_result(db_session, task)
    assert row.caller_kind == "share" and row.key_owner_id is None


async def test_copilot_config_reports_whose_key_and_refusals(
    client: AsyncClient, db_session, auth_headers, test_user, site_provider, my_key, policy_on, monkeypatch
):
    task = await _task(db_session, site_provider, "copilot")

    resp = await client.get("/api/ai/copilot/config", headers=auth_headers)
    assert resp.json()["source"] == "site" and resp.json()["supports_tools"] is True

    await _route(db_session, test_user, my_key, task, model="gpt-x")
    body = (await client.get("/api/ai/copilot/config", headers=auth_headers)).json()
    assert body["configured"] is True
    assert body["source"] == "user" and body["provider_name"] == "OpenRouter personal"
    assert body["model"] == "gpt-x"
    # An openai_compatible key has no tool loop: the dock says so.
    assert body["supports_tools"] is False

    await _spend(db_session, task, my_key, test_user, "25.00")
    monkeypatch.setattr(env_settings, "require_user_ai_provider", True)
    body = (await client.get("/api/ai/copilot/config", headers=auth_headers)).json()
    assert body["configured"] is False
    assert body["refused"]["reason"] == "monthly_cap"


class _StreamStub:
    """A text-only provider (no tool loop) that reports usage after the stream, like the Anthropic API."""

    supports_tools = False

    def __init__(self, text: str, usage: dict | None):
        self.text, self.usage, self.last_stream_usage = text, usage, None
        self.seen: list[AIProvider] = []

    async def stream_complete(self, **kwargs):
        self.last_stream_usage = None
        for piece in self.text.split(" "):
            yield piece + " "
        self.last_stream_usage = self.usage


async def test_streamed_turns_count_toward_the_dollar_cap(
    client: AsyncClient, db_session, auth_headers, test_user, site_provider, policy_on, monkeypatch
):
    """Copilot and rule chat stream text; the usage the provider reports afterwards is what the cap sees."""
    import app.ai.engine as engine

    key = AIProvider(name="Anthropic work key", provider_type="claude", user_id=test_user.id)
    db_session.add(key)
    await db_session.flush()
    copilot = await _task(db_session, site_provider, "copilot")
    rules = await _task(db_session, site_provider, "detection_rules")
    await _route(db_session, test_user, key, None, model="claude-sonnet-4-6")
    stub = _StreamStub("some answer", {"tokens_input": 1000, "tokens_output": 500, "cost_usd": None})
    monkeypatch.setattr(engine, "_get_provider_instance", lambda pm, **kw: stub)
    monkeypatch.setattr(engine, "_estimate_cost", lambda model, i, o, batch=False: Decimal("0.0105"))

    turn = await client.post("/api/ai/copilot/stream", json={"question": "hi"}, headers=auth_headers)
    assert turn.status_code == 200, turn.text
    assert '"answered_by"' in turn.text and '"source": "user"' in turn.text and '"cost_usd": 0.0105' in turn.text
    row = await _only_result(db_session, copilot)
    assert (row.tokens_input, row.tokens_output) == (1000, 500)
    assert row.cost_estimate == Decimal("0.0105") and row.key_owner_id == test_user.id

    chat = await client.post(
        "/api/detection-rules/chat", json={"message": "help", "rule_type": "sigma", "history": []}, headers=auth_headers
    )
    assert chat.status_code == 200, chat.text
    row = await _only_result(db_session, rules)
    assert (row.tokens_input, row.tokens_output) == (1000, 500)
    assert row.cost_estimate == Decimal("0.0105") and row.key_owner_id == test_user.id

    assert await engine.user_key_spend_month(db_session, test_user.id) == Decimal("0.0210")


# ---------------------------------------------------------------- providers API


async def test_list_shows_the_sites_providers_and_my_own_only(
    client: AsyncClient, auth_headers, other_headers, admin_headers, site_provider, my_key, other_key
):
    mine = {p["name"] for p in (await client.get("/api/ai/providers", headers=auth_headers)).json()}
    assert mine == {"Lab Ollama", "OpenRouter personal"}
    theirs = {p["name"] for p in (await client.get("/api/ai/providers", headers=other_headers)).json()}
    assert theirs == {"Lab Ollama", "mreyes key"}
    admin = {p["name"] for p in (await client.get("/api/ai/providers", headers=admin_headers)).json()}
    assert admin == {"Lab Ollama"}

    keys = await client.get("/api/ai/providers/user-keys", headers=admin_headers)
    assert keys.status_code == 200
    assert {(k["name"], k["owner_username"]) for k in keys.json()} == {
        ("OpenRouter personal", "testuser"),
        ("mreyes key", "mreyes"),
    }
    assert (await client.get("/api/ai/providers/user-keys", headers=auth_headers)).status_code == 403


async def test_adding_a_personal_key_follows_the_admins_policy(
    client: AsyncClient, db_session, auth_headers, test_user, monkeypatch, public_dns
):
    body = {"name": "Mine", "provider_type": "openai_compatible", "base_url": "https://openrouter.ai/api/v1"}

    off = await client.post("/api/ai/providers", json=body, headers=auth_headers)
    assert off.status_code == 403
    assert "hasn't enabled personal AI keys" in off.json()["error"]["message"]

    monkeypatch.setattr(env_settings, "allow_user_ai_providers", True)
    monkeypatch.setattr(env_settings, "user_ai_provider_types", "claude")
    wrong_type = await client.post("/api/ai/providers", json=body, headers=auth_headers)
    assert wrong_type.status_code == 400
    assert wrong_type.json()["error"]["message"] == "This instance allows personal keys of type claude only."

    cli = await client.post("/api/ai/providers", json={**body, "provider_type": "claude_code"}, headers=auth_headers)
    assert cli.status_code == 400
    assert "can't be a personal key" in cli.json()["error"]["message"]

    monkeypatch.setattr(env_settings, "user_ai_provider_types", "claude,openai_compatible")
    private = await client.post(
        "/api/ai/providers", json={**body, "base_url": "http://10.20.0.2:11434/v1"}, headers=auth_headers
    )
    assert private.status_code == 400
    assert "private address (10.20.0.2)" in private.json()["error"]["message"]

    ok = await client.post("/api/ai/providers", json={**body, "api_key": "sk-or-x"}, headers=auth_headers)
    assert ok.status_code == 201, ok.text
    assert ok.json()["user_id"] == str(test_user.id)
    row = await db_session.get(AIProvider, uuid.UUID(ok.json()["id"]))
    assert row.user_id == test_user.id and row.api_key_encrypted and "sk-or-x" not in row.api_key_encrypted


async def test_admin_registers_site_providers_or_their_own_key(
    client: AsyncClient, admin_headers, admin_user, policy_on
):
    site = await client.post(
        "/api/ai/providers", json={"name": "Site", "provider_type": "claude"}, headers=admin_headers
    )
    assert site.status_code == 201 and site.json()["user_id"] is None
    own = await client.post(
        "/api/ai/providers", json={"name": "Own", "provider_type": "claude", "personal": True}, headers=admin_headers
    )
    assert own.status_code == 201 and own.json()["user_id"] == str(admin_user.id)
    cli = await client.post(
        "/api/ai/providers", json={"name": "CLI", "provider_type": "claude_code"}, headers=admin_headers
    )
    assert cli.status_code == 400


async def test_test_and_save_writes_nothing_when_the_key_cannot_answer(
    client: AsyncClient, db_session, auth_headers, policy_on, monkeypatch
):
    import app.api.ai_providers as providers_api

    broken = MagicMock()
    broken.check_health = AsyncMock(side_effect=RuntimeError("401 Unauthorized"))
    monkeypatch.setattr(providers_api, "_get_provider_instance", lambda pm: broken)
    body = {"name": "Mine", "provider_type": "openai_compatible", "base_url": "https://openrouter.ai/api/v1"}

    resp = await client.post("/api/ai/providers?test=true", json=body, headers=auth_headers)

    assert resp.status_code == 400
    assert "401 Unauthorized" in resp.json()["error"]["message"]
    assert "Nothing was saved" in resp.json()["error"]["message"]
    assert (await db_session.execute(select(AIProvider))).scalars().all() == []

    working = MagicMock()
    working.check_health = AsyncMock(return_value=True)
    working.list_models = AsyncMock(return_value=["a", "b"])
    monkeypatch.setattr(providers_api, "_get_provider_instance", lambda pm: working)
    resp = await client.post("/api/ai/providers?test=true", json=body, headers=auth_headers)
    assert resp.status_code == 201 and resp.json()["models"] == ["a", "b"]


async def test_someone_elses_key_is_invisible(
    client: AsyncClient, auth_headers, admin_headers, other_key, site_provider, policy_on
):
    url = f"/api/ai/providers/{other_key.id}"
    for headers in (auth_headers, admin_headers):
        # Using someone else's key (a call to their endpoint) is nobody's to do.
        assert (await client.post(f"{url}/test", headers=headers)).status_code == 404
        assert (await client.get(f"{url}/models", headers=headers)).status_code == 404
    assert (await client.put(url, json={"name": "x"}, headers=auth_headers)).status_code == 404
    assert (await client.post(f"{url}/resume", headers=auth_headers)).status_code == 404
    assert (await client.delete(url, headers=auth_headers)).status_code == 404
    # The admin may disable or resume anyone's key (author-or-admin), still without using it.
    disabled = await client.put(url, json={"is_active": False}, headers=admin_headers)
    assert disabled.status_code == 200 and disabled.json()["is_active"] is False
    assert (await client.post(f"{url}/resume", headers=admin_headers)).status_code == 200
    # The site's rows are the admin's to use; a person can read them and nothing more.
    assert (await client.get(f"/api/ai/providers/{site_provider.id}/models", headers=auth_headers)).status_code == 403
    assert (await client.delete(f"/api/ai/providers/{site_provider.id}", headers=auth_headers)).status_code == 403
    # The admin may delete a personal key from the User keys tab.
    assert (await client.delete(url, headers=admin_headers)).status_code == 204


async def test_a_person_manages_their_own_key(
    client: AsyncClient, db_session, auth_headers, my_key, policy_on, monkeypatch
):
    url = f"/api/ai/providers/{my_key.id}"
    renamed = await client.put(url, json={"name": "Renamed"}, headers=auth_headers)
    assert renamed.status_code == 200 and renamed.json()["name"] == "Renamed"
    private = await client.put(url, json={"base_url": "http://192.168.1.20:11434/v1"}, headers=auth_headers)
    assert private.status_code == 400

    import app.api.ai_providers as providers_api

    working = MagicMock()
    working.check_health = AsyncMock(return_value=True)
    working.list_models = AsyncMock(return_value=["m1"])
    monkeypatch.setattr(providers_api, "_get_provider_instance", lambda pm: working)
    tested = await client.post(f"{url}/test", headers=auth_headers)
    assert tested.status_code == 200 and tested.json()["success"] is True
    assert (await client.get(f"{url}/models", headers=auth_headers)).json() == ["m1"]
    assert (await client.delete(url, headers=auth_headers)).status_code == 204
    assert await db_session.get(AIProvider, my_key.id) is None


async def test_a_personal_key_cannot_be_commissioned_or_site_assigned(
    client: AsyncClient, db_session, admin_headers, admin_user, site_provider, policy_on
):
    own = AIProvider(name="Admin own", provider_type="claude", user_id=admin_user.id)
    db_session.add(own)
    await db_session.flush()
    task = await _task(db_session, site_provider, "detection_rules")

    resp = await client.post(f"/api/ai/providers/{own.id}/commission", headers=admin_headers)
    assert resp.status_code == 400 and resp.json()["error"]["code"] == "personal_provider"

    resp = await client.put(
        f"/api/ai/tasks/{task.id}/assignments",
        json={"provider_id": str(own.id), "model_name": "sonnet"},
        headers=admin_headers,
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------- task eligibility


async def test_admin_opens_and_closes_tasks_but_not_pipeline_ones(
    client: AsyncClient, db_session, admin_headers, site_provider
):
    rules = await _task(db_session, site_provider, "detection_rules")
    pipeline = await _task(db_session, site_provider, "entry_analysis", allows=False)
    custom = await _task(db_session, site_provider, "my_custom", allows=False, is_system=False)

    listed = {t["name"]: t for t in (await client.get("/api/ai/tasks", headers=admin_headers)).json()}
    assert listed["detection_rules"]["allows_user_provider"] is True
    assert listed["detection_rules"]["user_provider_locked"] is False
    assert listed["entry_analysis"]["user_provider_locked"] is True
    assert listed["my_custom"]["user_provider_locked"] is False

    closed = await client.patch(
        f"/api/ai/tasks/{rules.id}", json={"allows_user_provider": False}, headers=admin_headers
    )
    assert closed.status_code == 200 and closed.json()["allows_user_provider"] is False
    locked = await client.patch(
        f"/api/ai/tasks/{pipeline.id}", json={"allows_user_provider": True}, headers=admin_headers
    )
    assert locked.status_code == 403 and locked.json()["error"]["code"] == "task_site_only"
    opened = await client.patch(
        f"/api/ai/tasks/{custom.id}", json={"allows_user_provider": True}, headers=admin_headers
    )
    assert opened.status_code == 200 and opened.json()["allows_user_provider"] is True


async def test_eligible_set_matches_the_migrations_data_step():
    from app.ai.capabilities import USER_PROVIDER_ELIGIBLE_TASKS
    from app.ai.prompts.defaults import SYSTEM_TASKS

    names = {t["name"] for t in SYSTEM_TASKS}
    assert USER_PROVIDER_ELIGIBLE_TASKS <= names
    assert len(USER_PROVIDER_ELIGIBLE_TASKS) == 14
    for name in ("entry_analysis", "entry_adjudication", "daily_summary", "threat_brief", "entry_qa"):
        assert name not in USER_PROVIDER_ELIGIBLE_TASKS


# ---------------------------------------------------------------- My AI


async def test_routes_are_mine_and_only_for_open_tasks(
    client: AsyncClient, db_session, auth_headers, other_headers, test_user, my_key, other_key, site_provider, policy_on
):
    rules = await _task(db_session, site_provider, "detection_rules")
    pipeline = await _task(db_session, site_provider, "entry_analysis", allows=False)

    default = await client.put(
        "/api/ai/me/routes",
        json={"task_id": None, "provider_id": str(my_key.id), "model_name": "m"},
        headers=auth_headers,
    )
    assert default.status_code == 200, default.text
    assert default.json()["task_id"] is None and default.json()["provider_name"] == "OpenRouter personal"
    # The overview names the default key even when every task has a route of its own.
    overview = (await client.get("/api/ai/me/overview", headers=auth_headers)).json()
    assert overview["default_route"]["provider_id"] == str(my_key.id)

    per_task = await client.put(
        "/api/ai/me/routes",
        json={"task_id": str(rules.id), "provider_id": str(my_key.id), "model_name": "m2"},
        headers=auth_headers,
    )
    assert per_task.status_code == 200 and per_task.json()["task_name"] == "detection_rules"
    # Same target again replaces, never duplicates.
    again = await client.put(
        "/api/ai/me/routes",
        json={"task_id": str(rules.id), "provider_id": str(my_key.id), "model_name": "m3"},
        headers=auth_headers,
    )
    assert again.json()["id"] == per_task.json()["id"] and again.json()["model_name"] == "m3"

    not_mine = await client.put(
        "/api/ai/me/routes",
        json={"task_id": None, "provider_id": str(other_key.id), "model_name": "m"},
        headers=auth_headers,
    )
    assert not_mine.status_code == 404
    site_row = await client.put(
        "/api/ai/me/routes",
        json={"task_id": None, "provider_id": str(site_provider.id), "model_name": "m"},
        headers=auth_headers,
    )
    assert site_row.status_code == 404
    closed = await client.put(
        "/api/ai/me/routes",
        json={"task_id": str(pipeline.id), "provider_id": str(my_key.id), "model_name": "m"},
        headers=auth_headers,
    )
    assert closed.status_code == 400 and closed.json()["error"]["code"] == "task_site_only"

    mine = (await client.get("/api/ai/me/routes", headers=auth_headers)).json()
    assert [r["task_name"] for r in mine] == [None, "detection_rules"]
    assert (await client.get("/api/ai/me/routes", headers=other_headers)).json() == []
    assert (await client.delete(f"/api/ai/me/routes/{per_task.json()['id']}", headers=other_headers)).status_code == 404
    assert (await client.delete(f"/api/ai/me/routes/{per_task.json()['id']}", headers=auth_headers)).status_code == 204
    assert len((await client.get("/api/ai/me/routes", headers=auth_headers)).json()) == 1


async def test_overview_shows_policy_spend_and_routable_tasks(
    client: AsyncClient, db_session, auth_headers, test_user, my_key, site_provider, policy_on, monkeypatch
):
    rules = await _task(db_session, site_provider, "detection_rules")
    await _task(db_session, site_provider, "entry_analysis", allows=False)
    await _route(db_session, test_user, my_key, rules, model="gpt-x")
    await _spend(db_session, rules, my_key, test_user, "0.81", n=2)
    db_session.add(
        AIResult(
            task_id=rules.id, provider_id=site_provider.id, is_current=False, caller_kind="user", user_id=test_user.id
        )
    )
    await db_session.flush()
    monkeypatch.setattr(env_settings, "site_ai_user_daily_requests", 150)

    body = (await client.get("/api/ai/me/overview", headers=auth_headers)).json()

    assert body["policy"]["allow_user_ai_providers"] is True
    assert body["policy"]["provider_types"] == ["claude", "ollama", "openai_compatible"]
    assert body["policy"]["site_allowance_per_user"] == 150
    assert body["fallback_to_site"] is True and body["monthly_cap_usd"] is None
    usage = body["usage"]
    assert Decimal(usage["month_cost"]) == Decimal("1.62")
    assert Decimal(usage["monthly_cap_usd"]) == Decimal("25")
    assert usage["requests_today"] == 2 and usage["daily_request_cap"] == 300
    assert usage["site_requests_today"] == 1 and usage["site_allowance_per_user"] == 150
    assert usage["by_key"][0]["provider_name"] == "OpenRouter personal"
    assert Decimal(usage["by_key"][0]["month_cost"]) == Decimal("1.62")
    assert [t["task_name"] for t in body["tasks"]] == ["detection_rules"]
    assert body["default_route"] is None
    row = body["tasks"][0]
    assert row["site_provider_name"] == "Lab Ollama" and row["site_model_name"] == "qwen"
    assert row["route"]["model_name"] == "gpt-x" and Decimal(row["month_cost"]) == Decimal("1.62")


async def test_preferences_cap_cannot_exceed_the_admins(
    client: AsyncClient, db_session, auth_headers, test_user, policy_on
):
    too_high = await client.patch("/api/ai/me/preferences", json={"monthly_cap_usd": "40"}, headers=auth_headers)
    assert too_high.status_code == 400
    # Zero would read as "unlimited" to the cap check: not a lower cap.
    assert (
        await client.patch("/api/ai/me/preferences", json={"monthly_cap_usd": "0"}, headers=auth_headers)
    ).status_code == 400
    assert too_high.json()["error"]["message"] == "The highest cap allowed here is $25.00 a month."

    ok = await client.patch(
        "/api/ai/me/preferences", json={"monthly_cap_usd": "10", "fallback_to_site": False}, headers=auth_headers
    )
    assert ok.status_code == 200, ok.text
    assert Decimal(ok.json()["monthly_cap_usd"]) == Decimal("10") and ok.json()["fallback_to_site"] is False
    assert Decimal(ok.json()["usage"]["monthly_cap_usd"]) == Decimal("10")

    back = await client.patch("/api/ai/me/preferences", json={"monthly_cap_usd": None}, headers=auth_headers)
    assert back.json()["monthly_cap_usd"] is None
    assert Decimal(back.json()["usage"]["monthly_cap_usd"]) == Decimal("25")
    prefs = await db_session.get(UserAIPreferences, test_user.id)
    assert prefs.fallback_to_site is False and prefs.monthly_cap_usd is None


async def test_deleting_a_key_removes_its_routes_and_keeps_its_results(
    client: AsyncClient, db_session, auth_headers, test_user, my_key, site_provider, policy_on
):
    task = await _task(db_session, site_provider, "detection_rules")
    await _route(db_session, test_user, my_key, task)
    await _spend(db_session, task, my_key, test_user, "0.5")

    key_id, task_id = my_key.id, task.id

    assert (await client.delete(f"/api/ai/providers/{key_id}", headers=auth_headers)).status_code == 204
    assert (await db_session.execute(select(UserAIRoute.id))).all() == []
    assert (await db_session.execute(select(AIProvider.id).where(AIProvider.id == key_id))).all() == []
    row = (await db_session.execute(select(AIResult).where(AIResult.task_id == task_id))).scalar_one()
    assert row.provider_id is None and row.provider_name == "OpenRouter personal"
    assert row.key_owner_id == test_user.id


async def test_claude_stream_reports_usage_from_the_final_message(monkeypatch):
    """The Anthropic SDK's stream carries usage on its final message; the provider keeps it."""
    from app.ai.providers.claude_provider import ClaudeProvider

    class _TextStream:
        def __init__(self):
            self.text_stream = self._chunks()

        async def _chunks(self):
            yield "Hel"
            yield "lo"

        async def get_final_message(self):
            return MagicMock(usage=MagicMock(input_tokens=42, output_tokens=7))

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

    client = MagicMock()
    client.messages.stream = lambda **kw: _TextStream()
    provider = ClaudeProvider(api_key="k", config={})
    monkeypatch.setattr(provider, "_build_client", lambda: client)

    chunks = [c async for c in provider.stream_complete(prompt="hi", model="claude-sonnet-4-6")]

    assert chunks == ["Hel", "lo"]
    assert provider.last_stream_usage == {"tokens_input": 42, "tokens_output": 7, "cost_usd": None}


# ---------------------------------------------------------------- review fixes


async def test_a_zero_cap_row_reads_as_the_default(db_session, test_user, site_provider, my_key, policy_on):
    from app.ai.engine import user_monthly_cap

    db_session.add(UserAIPreferences(user_id=test_user.id, monthly_cap_usd=Decimal("0")))
    await db_session.flush()
    assert await user_monthly_cap(db_session, await db_session.get(UserAIPreferences, test_user.id)) == Decimal("25")


async def test_a_key_without_an_address_is_refused_and_never_routed(
    client: AsyncClient, db_session, auth_headers, test_user, site_provider, policy_on
):
    """No base_url means the provider's localhost default: the server's own Ollama under a personal key."""
    from app.ai.engine import resolve_assignment

    resp = await client.post(
        "/api/ai/providers", json={"name": "Mine", "provider_type": "ollama"}, headers=auth_headers
    )
    assert resp.status_code == 400 and "address" in resp.json()["error"]["message"]

    bare = AIProvider(name="bare", provider_type="ollama", user_id=test_user.id)
    db_session.add(bare)
    await db_session.flush()
    task = await _task(db_session, site_provider, "detection_rules")
    await _route(db_session, test_user, bare, task)
    resolved = await resolve_assignment(db_session, Caller.user(test_user.id), task.name)
    assert resolved.source == "site" and resolved.fallback_reason == "endpoint_blocked"
    assert (await client.post(f"/api/ai/providers/{bare.id}/test", headers=auth_headers)).json()["success"] is False
    assert (await client.get(f"/api/ai/providers/{bare.id}/models", headers=auth_headers)).status_code == 400


async def test_test_and_models_recheck_the_endpoint(
    client: AsyncClient, db_session, auth_headers, my_key, policy_on, monkeypatch
):
    """A hostname that now resolves privately is not contacted by the test or model-listing routes either."""
    import ipaddress

    import app.core.outbound as outbound

    monkeypatch.setattr(outbound, "resolve_host", AsyncMock(return_value=[ipaddress.ip_address("10.0.0.5")]))
    tested = await client.post(f"/api/ai/providers/{my_key.id}/test", headers=auth_headers)
    assert tested.json()["success"] is False and "private address (10.0.0.5)" in tested.json()["message"]
    models = await client.get(f"/api/ai/providers/{my_key.id}/models", headers=auth_headers)
    assert models.status_code == 400 and models.json()["error"]["code"] == "endpoint_not_allowed"


async def test_url_refusals_only_blame_the_private_switch_when_it_applies(
    client: AsyncClient, auth_headers, policy_on, monkeypatch
):
    body = {"name": "Mine", "provider_type": "openai_compatible", "base_url": "ftp://api.example/v1"}
    resp = await client.post("/api/ai/providers", json=body, headers=auth_headers)
    assert resp.status_code == 400
    assert resp.json()["error"]["message"] == "Unsupported URL scheme: ftp."
    monkeypatch.setattr(env_settings, "user_ai_allow_private_endpoints", True)
    resp = await client.post("/api/ai/providers", json={**body, "base_url": "https://"}, headers=auth_headers)
    assert resp.json()["error"]["message"] == "No hostname in URL."


async def test_a_blocked_key_with_no_site_provider_says_why(db_session, test_user, my_key, policy_on):
    from app.ai.engine import UserKeyRequired, resolve_assignment

    task = await _task(db_session, None, "detection_rules")
    await _route(db_session, test_user, my_key, task)
    await _spend(db_session, task, my_key, test_user, "25.00")
    with pytest.raises(UserKeyRequired) as exc:
        await resolve_assignment(db_session, Caller.user(test_user.id), task.name)
    assert exc.value.reason == "monthly_cap"


async def test_report_preflight_follows_the_templates_own_task(
    db_session, test_user, site_provider, my_key, policy_on, monkeypatch
):
    from app.ai.engine import UserKeyRequired, preflight_report

    await _task(db_session, site_provider, "report_section")
    exposure = await _task(db_session, None, "report_section_exposure")
    monkeypatch.setattr(env_settings, "require_user_ai_provider", True)
    caller = Caller.user(test_user.id)

    # Only the family task is routed to the key: an exposure report passes, a flash alert does not.
    await _route(db_session, test_user, my_key, exposure)
    await preflight_report(db_session, caller, "exposure_report")
    with pytest.raises(UserKeyRequired):
        await preflight_report(db_session, caller, "flash_alert")


async def test_route_config_follows_the_provider_shape_rules(client: AsyncClient, auth_headers, my_key, policy_on):
    resp = await client.put(
        "/api/ai/me/routes",
        json={
            "task_id": None,
            "provider_id": str(my_key.id),
            "model_name": "m",
            "config": {"extra_body": "stream=false"},
        },
        headers=auth_headers,
    )
    assert resp.status_code in (400, 422), resp.text


async def test_deleting_a_user_with_a_key_and_results(
    client: AsyncClient, db_session, admin_headers, other_user, other_key, site_provider
):
    task = await _task(db_session, site_provider, "detection_rules")
    await _spend(db_session, task, other_key, other_user, "0.3")
    user_id, task_id = other_user.id, task.id

    resp = await client.delete(f"/api/admin/users/{user_id}", headers=admin_headers)

    assert resp.status_code == 204, resp.text
    assert (await db_session.execute(select(AIProvider.id).where(AIProvider.user_id == user_id))).all() == []
    row = (await db_session.execute(select(AIResult).where(AIResult.task_id == task_id))).scalar_one()
    assert row.provider_id is None and row.key_owner_id is None and row.provider_name == "mreyes key"


async def test_results_record_the_prompt_version_that_ran(db_session, test_user, site_provider, monkeypatch):
    from app.ai.engine import run_task
    from app.models.ai_prompt_template import AIPromptTemplate

    task = await _task(db_session, site_provider, "detection_rules")
    _stub_provider(monkeypatch)
    out = await run_task(db_session, test_user.id, task.name, variables={"text": "x"}, force=True)
    assert "_prompt_version" not in out  # the task's own default ran

    db_session.add(AIPromptTemplate(task_id=task.id, name="v7", template_text="{{ text }}!", version=7, is_active=True))
    await db_session.flush()
    out = await run_task(db_session, test_user.id, task.name, variables={"text": "x"}, force=True)
    assert out["_prompt_version"] == 7


async def test_a_task_can_opt_out_of_the_default_key(
    client: AsyncClient, db_session, auth_headers, test_user, site_provider, my_key, policy_on, monkeypatch
):
    """A default key covers every task; a per-task route with no key sends one task back to the instance."""
    from app.ai.engine import UserKeyRequired, resolve_assignment

    copilot = await _task(db_session, site_provider, "copilot")
    rules = await _task(db_session, site_provider, "detection_rules")
    await _route(db_session, test_user, my_key, None)

    # The default route itself can't be an opt-out.
    bad = await client.put("/api/ai/me/routes", json={"task_id": None, "provider_id": None}, headers=auth_headers)
    assert bad.status_code == 400
    # A key without a model is refused.
    no_model = await client.put(
        "/api/ai/me/routes", json={"task_id": str(rules.id), "provider_id": str(my_key.id)}, headers=auth_headers
    )
    assert no_model.status_code == 400

    out = await client.put(
        "/api/ai/me/routes", json={"task_id": str(copilot.id), "provider_id": None}, headers=auth_headers
    )
    assert out.status_code == 200, out.text
    assert out.json()["provider_id"] is None and out.json()["model_name"] is None

    caller = Caller.user(test_user.id)
    on_copilot = await resolve_assignment(db_session, caller, copilot.name)
    assert on_copilot.source == "site" and on_copilot.fallback_reason is None
    assert (await resolve_assignment(db_session, caller, rules.name)).source == "user"

    overview = (await client.get("/api/ai/me/overview", headers=auth_headers)).json()
    row = next(t for t in overview["tasks"] if t["task_name"] == "copilot")
    assert row["route"]["provider_id"] is None
    assert overview["default_route"]["provider_id"] == str(my_key.id)

    # Under Required an opt-out is still "no key" for that task.
    monkeypatch.setattr(env_settings, "require_user_ai_provider", True)
    with pytest.raises(UserKeyRequired):
        await resolve_assignment(db_session, caller, copilot.name)
