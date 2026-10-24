"""Automation rules are visible to every user, but their webhook URLs and auth
headers are credentials: only the rule's owner and admins may read them."""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.automation_rule import AutomationRule
from app.models.user import User

_HOOK = "https://hooks.slack.com/services/T000/B000/secretpart"
_TOKEN = "Bearer hunter2"


@pytest.fixture
async def admins_rule(db_session: AsyncSession, admin_user: User) -> AutomationRule:
    rule = AutomationRule(
        created_by=admin_user.id,
        name="Admin's Slack alert",
        trigger_type="on_new_entry",
        conditions={"operator": "AND", "conditions": []},
        actions=[
            {"type": "send_notification", "config": {"webhook_url": _HOOK}},
            {"type": "run_webhook", "config": {"url": _HOOK, "headers": {"Authorization": _TOKEN}}},
        ],
    )
    db_session.add(rule)
    await db_session.flush()
    return rule


def _leaks(payload) -> bool:
    text = str(payload)
    return "secretpart" in text or "hunter2" in text


@pytest.mark.asyncio
async def test_non_owner_reads_are_redacted(client: AsyncClient, auth_headers: dict, admins_rule: AutomationRule):
    listed = await client.get("/api/automation/rules", headers=auth_headers)
    assert listed.status_code == 200
    mine = [r for r in listed.json()["items"] if r["id"] == str(admins_rule.id)]
    assert mine and not _leaks(mine)
    assert mine[0]["name"] == "Admin's Slack alert"

    one = await client.get(f"/api/automation/rules/{admins_rule.id}", headers=auth_headers)
    assert one.status_code == 200 and not _leaks(one.json())

    for path in ("/api/automation/rules/export", f"/api/automation/rules/export/{admins_rule.id}"):
        exported = await client.get(path, params={"include_secrets": "true"}, headers=auth_headers)
        assert exported.status_code == 200
        assert not _leaks(exported.json()), path


@pytest.mark.asyncio
async def test_owner_and_admin_still_see_secrets(
    client: AsyncClient, admin_headers: dict, admins_rule: AutomationRule, db_session: AsyncSession
):
    one = await client.get(f"/api/automation/rules/{admins_rule.id}", headers=admin_headers)
    assert one.status_code == 200 and _leaks(one.json())
    exported = await client.get(
        f"/api/automation/rules/export/{admins_rule.id}", params={"include_secrets": "true"}, headers=admin_headers
    )
    assert _leaks(exported.json())
    # Redacting a non-owner's view never touches the stored row.
    await db_session.refresh(admins_rule)
    assert admins_rule.actions[0]["config"]["webhook_url"] == _HOOK
