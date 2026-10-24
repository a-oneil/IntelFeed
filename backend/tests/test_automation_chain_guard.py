"""chain_rule runs the chained rule as its owner, so it may only reach rules
of the same owner (or the chaining owner must be an admin), and a chain stops
when it loops or gets too deep."""

import pytest
from sqlalchemy import func, select

from app.automation.actions import MAX_CHAIN_DEPTH, _action_chain_rule
from app.automation.engine import execute_automation
from app.models.automation_log import AutomationLog
from app.models.automation_rule import AutomationRule


def _rule(owner, name, actions):
    return AutomationRule(
        created_by=owner.id,
        name=name,
        trigger_type="on_new_entry",
        conditions={"operator": "AND", "conditions": []},
        actions=actions,
    )


@pytest.mark.asyncio
async def test_cannot_chain_to_another_users_rule(db_session, test_user, admin_user, test_entry):
    admins = _rule(admin_user, "admin's webhook", [{"type": "add_tags", "config": {"tags": ["x"]}}])
    db_session.add(admins)
    await db_session.flush()

    result = await _action_chain_rule(db_session, test_entry, {"rule_id": str(admins.id)}, test_user.id)
    assert result["status"] == "error"
    assert "same user" in result["message"]


@pytest.mark.asyncio
async def test_admin_may_chain_to_any_rule(db_session, test_user, admin_user, test_entry):
    users = _rule(test_user, "user's rule", [{"type": "add_tags", "config": {"tags": ["y"]}}])
    db_session.add(users)
    await db_session.flush()

    result = await _action_chain_rule(db_session, test_entry, {"rule_id": str(users.id)}, admin_user.id)
    assert result["status"] != "error", result


@pytest.mark.asyncio
async def test_self_chain_stops_without_rerunning(db_session, test_user, test_entry):
    loop = _rule(test_user, "loop", [])
    db_session.add(loop)
    await db_session.flush()
    loop.actions = [{"type": "chain_rule", "config": {"rule_id": str(loop.id)}}]
    await db_session.flush()

    log = await execute_automation(db_session, test_entry, loop)
    runs = await db_session.scalar(
        select(func.count()).select_from(AutomationLog).where(AutomationLog.rule_id == loop.id)
    )
    assert runs == 1
    assert "loops back" in str(log.actions_executed)


@pytest.mark.asyncio
async def test_chain_depth_is_capped(db_session, test_user, test_entry):
    rules = [_rule(test_user, f"r{i}", []) for i in range(MAX_CHAIN_DEPTH + 3)]
    db_session.add_all(rules)
    await db_session.flush()
    for a, b in zip(rules, rules[1:], strict=False):
        a.actions = [{"type": "chain_rule", "config": {"rule_id": str(b.id)}}]
    await db_session.flush()

    await execute_automation(db_session, test_entry, rules[0])
    ran = await db_session.scalar(
        select(func.count()).select_from(AutomationLog).where(AutomationLog.rule_id.in_([r.id for r in rules]))
    )
    assert ran == MAX_CHAIN_DEPTH
