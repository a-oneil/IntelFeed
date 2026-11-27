"""Custom-template generation must enforce the same visibility as cloning."""

import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from app.api import intel_reports
from app.core.exceptions import AppError
from app.schemas.intel_report import IntelReportGenerate


@pytest.mark.parametrize(
    ("role", "owner", "shared", "builtin", "allowed"),
    [
        ("user", False, False, False, False),
        ("user", True, False, False, True),
        ("admin", False, False, False, True),
        ("user", False, True, False, True),
        ("user", False, False, True, True),
    ],
)
async def test_generate_custom_template_visibility(monkeypatch, role, owner, shared, builtin, allowed):
    user = SimpleNamespace(id=uuid.uuid4(), role=role)
    template = SimpleNamespace(
        name="Private template",
        is_builtin=builtin,
        is_shared=shared,
        created_by=user.id if owner else uuid.uuid4(),
    )
    rows = Mock()
    rows.scalar_one_or_none.return_value = template
    db = Mock(execute=AsyncMock(return_value=rows), flush=AsyncMock(), refresh=AsyncMock())
    generate = AsyncMock(return_value={"sections": []})
    monkeypatch.setattr(intel_reports, "generate_report_content", generate)
    monkeypatch.setattr(intel_reports.IntelReportResponse, "model_validate", lambda report: report)
    body = IntelReportGenerate(template_type="private_custom", entry_ids=[], entity_ids={})

    if not allowed:
        with pytest.raises(AppError) as exc:
            await intel_reports.generate_intel_report(body=body, user=user, db=db)
        assert exc.value.status_code == 403
        generate.assert_not_awaited()
        db.add.assert_not_called()
    else:
        report = await intel_reports.generate_intel_report(body=body, user=user, db=db)
        assert report.created_by == user.id
        assert report.title.startswith("Private template")
        generate.assert_awaited_once()
        db.add.assert_called_once_with(report)


async def test_every_route_taking_a_slug_refuses_someone_elses_private_template(
    client, db_session, auth_headers, admin_user
):
    """Not just /generate: create and clone-as-type read the template's sections too."""
    from app.models.report_template import ReportTemplate

    db_session.add(
        ReportTemplate(
            name="Admin only",
            template_slug="admins_private_tmpl",
            sections=[{"name": "secret_section", "title": "Secret", "type": "narrative"}],
            is_shared=False,
            created_by=admin_user.id,
        )
    )
    await db_session.flush()

    created = await client.post(
        "/api/intel-reports", json={"title": "x", "template_type": "admins_private_tmpl"}, headers=auth_headers
    )
    assert created.status_code == 403, created.text

    own = await client.post(
        "/api/intel-reports", json={"title": "y", "template_type": "flash_alert"}, headers=auth_headers
    )
    assert own.status_code == 201, own.text
    cloned = await client.post(
        f"/api/intel-reports/{own.json()['id']}/clone",
        json={"template_type": "admins_private_tmpl", "generate": False},
        headers=auth_headers,
    )
    assert cloned.status_code == 403, cloned.text

    # A slug with no template at all creates a plain report.
    plain = await client.post(
        "/api/intel-reports", json={"title": "z", "template_type": "no_such_template"}, headers=auth_headers
    )
    assert plain.status_code == 201, plain.text
