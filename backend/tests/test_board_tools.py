"""The workbench-board tools run their API routes with real values (never a
FastAPI Query default) and come back as JSON-safe dicts."""

import json
import uuid

import pytest

from app.models.ttp import TTP
from app.models.user import User
from app.tools import MUTATING_TOOLS, TOOL_DEFINITIONS, execute_tool

NEW = [
    "get_threat_board",
    "list_intel_profiles",
    "get_intel_profile",
    "get_profile_threat_surface",
    "get_coverage_workspace",
    "list_tags",
    "get_entity_whats_new",
]


def test_board_tools_are_registered_read_only():
    names = {t["name"] for t in TOOL_DEFINITIONS}
    assert set(NEW) <= names
    assert not set(NEW) & MUTATING_TOOLS


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "name,args",
    [
        ("get_threat_board", {}),
        ("get_threat_board", {"facet": "all", "window": "30d", "limit": 5}),
        ("list_intel_profiles", {}),
        ("list_tags", {}),
        ("get_coverage_workspace", {"entity_type": "ttp", "entity_key": "T1059"}),
        ("get_entity_whats_new", {"entity_type": "threat_actor", "entity_id": str(uuid.uuid4())}),
    ],
)
async def test_board_tools_run(db_session, test_user: User, name, args):
    db_session.add(TTP(technique_id="T1059", technique_name="Command and Scripting Interpreter", tactic="execution"))
    await db_session.flush()
    raw = await execute_tool(name, args, db_session, test_user.id)
    result = json.loads(raw)
    assert isinstance(result, dict)
    assert "error" not in result, result
    assert "Query(" not in raw and "FieldInfo" not in raw


@pytest.mark.asyncio
async def test_unknown_profile_is_an_error_not_a_crash(db_session, test_user: User):
    for name in ("get_intel_profile", "get_profile_threat_surface"):
        result = json.loads(await execute_tool(name, {"profile_id": str(uuid.uuid4())}, db_session, test_user.id))
        assert "error" in result
        result = json.loads(await execute_tool(name, {"profile_id": "nope"}, db_session, test_user.id))
        assert "error" in result
