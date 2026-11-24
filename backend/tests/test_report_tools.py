"""create_intel_report: saved templates (Manual) and a markdown body."""

import json
import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.intel_report import IntelReport
from app.models.report_template import ReportTemplate
from app.models.user import User
from app.tools import execute_tool


async def _call(db: AsyncSession, user: User, args: dict) -> dict:
    return json.loads(await execute_tool("create_intel_report", args, db, user.id))


@pytest.mark.asyncio
async def test_manual_report_with_body(db_session: AsyncSession, test_user: User):
    db_session.add(ReportTemplate(name="Manual", template_slug="manual", sections=[], is_builtin=True))
    await db_session.flush()
    body = "# ARTEX briefing\n\n| a | b |\n|---|---|\n| 1 | 2 |\n"
    result = await _call(
        db_session,
        test_user,
        {"title": "Pasted", "template_type": "manual", "body": body, "summary": "Short", "tags": ["artex"]},
    )
    assert result.get("created") is True, result
    report = await db_session.get(IntelReport, uuid.UUID(result["id"]))
    assert report.content["sections"] == {}
    assert report.content["body"] == body
    assert report.summary == "Short"
    assert report.tags == ["artex"]


@pytest.mark.asyncio
async def test_sectioned_template_still_scaffolds(db_session: AsyncSession, test_user: User):
    result = await _call(db_session, test_user, {"title": "Flash", "template_type": "flash_alert"})
    report = await db_session.get(IntelReport, uuid.UUID(result["id"]))
    assert "summary" in report.content["sections"]
    assert "body" not in report.content


@pytest.mark.asyncio
async def test_private_template_of_another_user_is_refused(db_session: AsyncSession, test_user: User, admin_user: User):
    db_session.add(ReportTemplate(name="Mine", template_slug="admins_private", sections=[], created_by=admin_user.id))
    await db_session.flush()
    result = await _call(db_session, test_user, {"title": "x", "template_type": "admins_private"})
    assert "error" in result
    assert "admins_private" not in result["error"].split("valid:")[1]

    unknown = await _call(db_session, test_user, {"title": "x", "template_type": "no_such_template"})
    assert "unknown template_type" in unknown["error"]
