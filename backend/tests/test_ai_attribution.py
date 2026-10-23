"""Every AI result says who asked and who answered.

The provider lookup is still instance-wide here; what these tests pin is
the attribution record that per-user routing and per-user caps will later
count on: ``caller_kind`` branches the cost dashboard, ``user_id`` is the
person a user-kind call is billed to, and ``key_owner_id`` stays empty
until a personal provider answers.
"""

import uuid
from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import select

from app.ai.caller import SENTINEL_USER_ID, Caller, caller_scope
from app.models.ai_provider import AIProvider
from app.models.ai_result import AIResult
from app.models.ai_task import AITask
from app.models.ai_task_assignment import AITaskAssignment
from app.models.shared_entry import SharedEntry
from app.models.user import User

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def provider(db_session) -> AIProvider:
    row = AIProvider(name="Lab Ollama", provider_type="ollama", base_url="http://ollama.test:11434")
    db_session.add(row)
    await db_session.flush()
    return row


async def _assigned_task(db_session, provider: AIProvider, name: str, template: str = "{{ text }}") -> AITask:
    task = AITask(name=name, display_name=name.replace("_", " ").title(), default_prompt_template=template)
    db_session.add(task)
    await db_session.flush()
    db_session.add(AITaskAssignment(task_id=task.id, provider_id=provider.id, model_name="qwen"))
    await db_session.flush()
    return task


def _stub_provider(monkeypatch, content='{"answer": "ok"}', cost_usd=None):
    import app.ai.engine as engine

    response = MagicMock(
        content=content, model="qwen", tokens_input=12, tokens_output=4, latency_ms=7, cost_usd=cost_usd
    )
    stub = MagicMock()
    stub.complete = AsyncMock(return_value=response)
    monkeypatch.setattr(engine, "_get_provider_instance", lambda pm, **kw: stub)
    return stub


async def _only_result(db_session, task: AITask) -> AIResult:
    rows = (await db_session.execute(select(AIResult).where(AIResult.task_id == task.id))).scalars().all()
    assert len(rows) == 1, f"expected one result row, found {len(rows)}"
    return rows[0]


# ---------------------------------------------------------------- Caller


async def test_caller_kinds_and_sentinel():
    uid = uuid.uuid4()
    assert Caller.user(uid) == Caller("user", uid)
    # A worker that passes the all-zero sentinel is background work, and the
    # sentinel must never reach a foreign key.
    assert Caller.user(SENTINEL_USER_ID) == Caller("system", None)
    assert Caller.system(SENTINEL_USER_ID).user_id is None
    assert Caller.automation(uid) == Caller("automation", uid)
    assert Caller.share(uid) == Caller("share", uid)
    assert Caller.of_kind("share", uid) == Caller.share(uid)
    assert Caller.of_kind("user", None) == Caller.system()
    with pytest.raises(ValueError):
        Caller.of_kind("robot", uid)
    assert Caller.user(uid).is_user and not Caller.automation(uid).is_user


# ---------------------------------------------------------------- run_task


async def test_run_task_defaults_to_a_user_caller(db_session, test_user: User, provider, monkeypatch):
    from app.ai.engine import run_task

    task = await _assigned_task(db_session, provider, "attrib_default")
    _stub_provider(monkeypatch)

    await run_task(db_session, test_user.id, task.name, variables={"text": "hi"})

    row = await _only_result(db_session, task)
    assert row.caller_kind == "user"
    assert row.user_id == test_user.id
    assert row.key_owner_id is None
    assert row.provider_name == "Lab Ollama"


async def test_run_task_sentinel_user_is_system(db_session, provider, monkeypatch):
    from app.ai.engine import run_task

    task = await _assigned_task(db_session, provider, "attrib_sentinel")
    _stub_provider(monkeypatch)

    await run_task(db_session, SENTINEL_USER_ID, task.name, variables={"text": "hi"})

    row = await _only_result(db_session, task)
    assert row.caller_kind == "system"
    assert row.user_id is None


async def test_run_task_service_account_is_system(db_session, provider, monkeypatch):
    from app.ai.engine import run_task
    from app.core.security import hash_password

    system_account = User(username="system", password_hash=hash_password("x"), role="system")
    db_session.add(system_account)
    await db_session.flush()
    task = await _assigned_task(db_session, provider, "attrib_service_account")
    _stub_provider(monkeypatch)

    # A worker that passes the service account's id without a caller is still
    # background work, not a person.
    await run_task(db_session, system_account.id, task.name, variables={"text": "hi"})

    row = await _only_result(db_session, task)
    assert row.caller_kind == "system"
    assert row.user_id == system_account.id


async def test_run_task_unknown_user_id_is_system(db_session, provider, monkeypatch):
    from app.ai.engine import run_task

    task = await _assigned_task(db_session, provider, "attrib_unknown_user")
    _stub_provider(monkeypatch)

    # An id with no users row (a deleted account) must not reach the foreign key.
    await run_task(db_session, uuid.uuid4(), task.name, variables={"text": "hi"})

    row = await _only_result(db_session, task)
    assert row.caller_kind == "system"
    assert row.user_id is None


async def test_caller_scope_is_the_default_beneath_a_boundary(db_session, test_user: User, provider, monkeypatch):
    from app.ai.engine import run_task

    task = await _assigned_task(db_session, provider, "attrib_scope")
    _stub_provider(monkeypatch)

    # The automation dispatcher sets this scope; an action that forgets the
    # keyword still can't bill the rule's author as a person.
    with caller_scope(Caller.automation(test_user.id)):
        await run_task(db_session, test_user.id, task.name, variables={"text": "hi"})

    row = await _only_result(db_session, task)
    assert row.caller_kind == "automation"
    assert row.user_id == test_user.id


async def test_run_task_explicit_caller_wins(db_session, test_user: User, provider, monkeypatch):
    from app.ai.engine import run_task

    task = await _assigned_task(db_session, provider, "attrib_automation")
    _stub_provider(monkeypatch)

    await run_task(
        db_session, test_user.id, task.name, variables={"text": "hi"}, caller=Caller.automation(test_user.id)
    )

    row = await _only_result(db_session, task)
    # The author is recorded, but the kind says a rule ran it, not the person.
    assert row.caller_kind == "automation"
    assert row.user_id == test_user.id


async def test_run_task_error_rows_are_attributed_too(db_session, test_user: User, provider, monkeypatch):
    import app.ai.engine as engine
    from app.ai.engine import run_task

    task = await _assigned_task(db_session, provider, "attrib_error")
    broken = MagicMock()
    broken.complete = AsyncMock(side_effect=RuntimeError("boom"))
    monkeypatch.setattr(engine, "_get_provider_instance", lambda pm, **kw: broken)

    result = await run_task(db_session, test_user.id, task.name, variables={"text": "hi"})

    assert result["_extraction_status"] == "provider_error"
    row = await _only_result(db_session, task)
    assert row.caller_kind == "user"
    assert row.user_id == test_user.id
    assert row.provider_name == "Lab Ollama"


# ------------------------------------------------------- direct-call ledger


async def test_record_direct_result_is_a_spend_row_not_an_answer(db_session, test_user: User, provider):
    from app.ai.engine import record_direct_result

    task = await _assigned_task(db_session, provider, "attrib_direct")
    response = MagicMock(
        content="converted", model="qwen", tokens_input=100, tokens_output=50, latency_ms=3, cost_usd=0.0123
    )

    row = await record_direct_result(
        db_session,
        caller=Caller.user(test_user.id),
        task=task,
        provider_model=provider,
        model_name="qwen",
        prompt_used="convert this",
        response=response,
        target_type="detection_rule",
        target_id=uuid.uuid4(),
    )

    assert row.is_current is False
    assert row.cost_estimate == Decimal("0.0123")
    assert row.tokens_input == 100
    assert row.caller_kind == "user"
    assert row.user_id == test_user.id
    assert row.provider_name == "Lab Ollama"
    assert row.parsed_result["_extraction_status"] == "success"


async def test_record_direct_result_streamed_call_counts_one_request(db_session, test_user: User, provider):
    from app.ai.engine import record_direct_result

    task = await _assigned_task(db_session, provider, "attrib_stream")
    row = await record_direct_result(
        db_session,
        caller=Caller.user(test_user.id),
        task=task,
        provider_model=provider,
        model_name="qwen",
        prompt_used="chat",
        response=None,
        content="streamed answer",
        error="timed out",
        target_type="rule_chat",
    )
    assert row.tokens_input == 0 and row.cost_estimate == Decimal("0")
    assert row.parsed_result == {"_extraction_status": "provider_error", "_error": "timed out"}
    assert row.raw_response == "timed out"


# ------------------------------------------------------------ share links


async def test_shared_ask_agent_is_share_traffic(
    client: AsyncClient, db_session, test_user: User, test_entry, provider, monkeypatch
):
    task = await _assigned_task(db_session, provider, "entry_qa", template="{{ question }}")
    share = SharedEntry(entry_id=test_entry.id, created_by=test_user.id, is_active=True)
    db_session.add(share)
    await db_session.flush()
    _stub_provider(monkeypatch, content="Gen 7 only.")

    resp = await client.post(f"/api/shared/{share.token}/ask-agent", json={"question": "Is SMA 100 affected?"})

    assert resp.status_code == 200, resp.text
    assert resp.json()["answer"] == "Gen 7 only."
    row = await _only_result(db_session, task)
    # The sharer is recorded for provenance; the caller is the anonymous link.
    assert row.caller_kind == "share"
    assert row.user_id == test_user.id
    assert row.target_type == "share_qa"
    assert row.target_id == share.id
    assert row.is_current is False


async def test_shared_ask_agent_failure_still_counts(
    client: AsyncClient, db_session, test_user: User, test_entry, provider, monkeypatch
):
    import app.ai.engine as engine

    task = await _assigned_task(db_session, provider, "entry_qa", template="{{ question }}")
    share = SharedEntry(entry_id=test_entry.id, created_by=test_user.id, is_active=True)
    db_session.add(share)
    await db_session.flush()
    broken = MagicMock()
    broken.complete = AsyncMock(side_effect=RuntimeError("upstream 502"))
    monkeypatch.setattr(engine, "_get_provider_instance", lambda pm, **kw: broken)

    resp = await client.post(f"/api/shared/{share.token}/ask-agent", json={"question": "Anything?"})

    assert resp.status_code == 502
    # A failed call is still a request against the link's allowance.
    row = await _only_result(db_session, task)
    assert row.caller_kind == "share"
    assert row.parsed_result["_error"] == "upstream 502"
    assert row.cost_estimate == Decimal("0")


async def test_shared_run_ai_task_is_share_traffic(
    client: AsyncClient, db_session, test_user: User, test_entry, provider, monkeypatch
):
    task = await _assigned_task(db_session, provider, "threat_assessment", template="{{ entry.title }}")
    task.category = "analysis"
    share = SharedEntry(entry_id=test_entry.id, created_by=test_user.id, is_active=True)
    db_session.add(share)
    await db_session.flush()
    _stub_provider(monkeypatch, content='{"what": "x", "so_what": "y"}')

    resp = await client.post(f"/api/shared/{share.token}/run-ai-task", json={"task_name": "threat_assessment"})

    assert resp.status_code == 200, resp.text
    row = await _only_result(db_session, task)
    assert row.caller_kind == "share"
    assert row.user_id == test_user.id


# --------------------------------------------------------- cost dashboard


async def test_cost_breakdown_is_admin_only(client: AsyncClient, auth_headers: dict, admin_headers: dict):
    assert (await client.get("/api/ai/cost-breakdown", headers=auth_headers)).status_code == 403
    assert (await client.get("/api/ai/cost-breakdown", headers=admin_headers)).status_code == 200


async def test_cost_breakdown_rolls_up_by_caller(
    client: AsyncClient, db_session, admin_headers: dict, test_user: User, admin_user: User, provider, monkeypatch
):
    from app.config import settings as env_settings

    monkeypatch.setattr(env_settings, "site_ai_user_daily_requests", 150)
    task = await _assigned_task(db_session, provider, "attrib_dashboard")

    def row(kind, user_id=None, cost="0.10", key_owner_id=None):
        return AIResult(
            target_type="entry",
            target_id=uuid.uuid4(),
            is_current=False,
            task_id=task.id,
            provider_id=provider.id,
            model_name="qwen",
            tokens_input=10,
            tokens_output=5,
            cost_estimate=Decimal(cost),
            caller_kind=kind,
            user_id=user_id,
            key_owner_id=key_owner_id,
            provider_name=provider.name,
        )

    db_session.add_all(
        [
            row("user", test_user.id, "0.10"),
            row("user", test_user.id, "0.30", key_owner_id=test_user.id),
            row("user", admin_user.id, "0.20"),
            row("automation", test_user.id, "0.05"),
            row("system", None, "0.00"),
            row(None, None, "0.02"),
        ]
    )
    await db_session.flush()

    body = (await client.get("/api/ai/cost-breakdown", headers=admin_headers)).json()

    assert Decimal(body["instance_cost_30d"]) == Decimal("0.37")
    assert Decimal(body["user_key_cost_30d"]) == Decimal("0.30")
    assert body["unpriced_requests_30d"] == 1

    by = {(r["caller_kind"], r["username"]): r for r in body["by_caller"]}
    me = by[("user", test_user.username)]
    assert me["requests"] == 2
    assert Decimal(me["instance_cost"]) == Decimal("0.10")
    assert Decimal(me["own_key_cost"]) == Decimal("0.30")
    # Only the instance-key call counts toward today's allowance.
    assert me["requests_today"] == 1
    assert body["site_allowance_per_user"] == 150
    assert by[("user", admin_user.username)]["requests"] == 1
    # Automation records the rule author but never bills them: it folds into
    # one row with no username, like the pipeline and old unattributed rows.
    assert by[("automation", None)]["requests"] == 1
    assert by[("system", None)]["requests"] == 1
    assert by[("unattributed", None)]["requests"] == 1
