"""The built-in automation templates only use tasks, platforms and variables
that exist. A template naming a missing task is skipped at run time with no
error the user sees, so these drift silently unless pinned here."""

import re
import uuid
from unittest.mock import AsyncMock, patch

import pytest

from app.ai.prompts.defaults import SYSTEM_TASKS
from app.automation import actions
from app.automation.templates import AUTOMATION_TEMPLATES
from app.automation.variables import NOTIFICATION_TEMPLATE_FIELDS
from app.models.entry import Entry

TASK_NAMES = {t["name"] for t in SYSTEM_TASKS}


def _actions(action_type):
    return [(t["id"], a["config"]) for t in AUTOMATION_TEMPLATES for a in t["actions"] if a["type"] == action_type]


@pytest.mark.parametrize("template_id,config", _actions("run_ai_task"))
def test_run_ai_task_names_a_real_task(template_id, config):
    task = config.get("task_id") or config.get("task_name")
    assert task in TASK_NAMES, f"{template_id}: unknown AI task {task!r}"


@pytest.mark.parametrize("template_id,config", _actions("send_notification"))
def test_notification_uses_a_supported_platform_and_known_variables(template_id, config):
    assert config.get("platform", "discord") in ("slack", "discord", "custom"), template_id
    assert "message" not in config, f"{template_id}: the action reads message_template"
    unknown = set(re.findall(r"\{(\w+)\}", config.get("message_template", ""))) - set(NOTIFICATION_TEMPLATE_FIELDS)
    assert not unknown, f"{template_id}: unknown variables {unknown}"


def test_render_template_fills_app_url():
    entry = Entry(id=uuid.uuid4(), title="Loader update")
    rendered = actions._render_template("{title}\n{app_url}", entry)
    assert rendered.endswith(f"/?entry={entry.id}")
    assert "{app_url}" not in actions._render_template_json_safe("{app_url}", entry)


@pytest.mark.asyncio
async def test_per_entry_ai_task_sets_ai_summary_for_any_task():
    entry = Entry(id=uuid.uuid4(), title="t", content_text="body")
    context: dict = {}
    with patch("app.ai.engine.run_task", new=AsyncMock(return_value={"summary": "Short summary."})):
        result = await actions._action_run_ai_task(None, entry, {"task_id": "article_summary"}, uuid.uuid4(), context)
    assert result["status"] == "success"
    assert context["ai_summary"] == "Short summary."
