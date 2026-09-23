"""Tests for BE-8: Intel report management API with export and generation."""

import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.intelligence.reporting import render_markdown
from app.models.detection_rule import DetectionRule
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.intel_report import IntelReport, IntelReportVersion
from app.models.report_template import ReportTemplate
from app.models.ttp import TTP
from app.models.user import User


@pytest_asyncio.fixture
async def builtin_templates(db_session: AsyncSession) -> list[str]:
    """Seed the builtin report templates.

    In production these rows are inserted by the Alembic migrations, but the
    test schema is built straight from the models, so nothing seeds them here.
    """
    slugs = [
        "flash_alert",
        "actor_profile",
        "campaign_tracker",
        "landscape_report",
        "detection_report",
    ]
    for slug in slugs:
        db_session.add(
            ReportTemplate(
                name=slug.replace("_", " ").title(),
                description=f"Builtin {slug} template",
                template_slug=slug,
                sections=[{"name": "executive_summary", "title": "Executive Summary", "type": "narrative"}],
                is_builtin=True,
                is_shared=True,
            )
        )
    await db_session.flush()
    return slugs


@pytest_asyncio.fixture
async def test_report(db_session: AsyncSession, test_user: User) -> IntelReport:
    report = IntelReport(
        created_by=test_user.id,
        title="Flash Alert: Critical RCE Vulnerability",
        template_type="flash_alert",
        tlp_marking="TLP:AMBER",
        content={
            "sections": {
                "summary": {"title": "Summary", "body": "Critical RCE found in Apache Log4j"},
                "key_findings": {"title": "Key Findings", "body": "Remote code execution via JNDI lookups"},
                "recommended_actions": {"title": "Recommended Actions", "body": "Patch immediately"},
                "references": {
                    "title": "References",
                    "items": [{"title": "Apache Advisory", "url": "https://apache.org/advisory"}],
                },
            }
        },
        summary="Critical vulnerability requires immediate action",
        tags=["critical", "rce", "log4j"],
    )
    db_session.add(report)
    await db_session.flush()
    return report


@pytest_asyncio.fixture
async def test_report_with_versions(db_session: AsyncSession, test_user: User) -> IntelReport:
    """Create a report with version history."""
    report = IntelReport(
        created_by=test_user.id,
        title="Versioned Report",
        template_type="landscape_report",
        tlp_marking="TLP:GREEN",
        content={"sections": {"summary": {"title": "Summary", "body": "Version 3 content"}}},
        version=3,
        tags=["versioned"],
    )
    db_session.add(report)
    await db_session.flush()

    # Add version history
    for v in [1, 2]:
        version = IntelReportVersion(
            report_id=report.id,
            version=v,
            content={"sections": {"summary": {"title": "Summary", "body": f"Version {v} content"}}},
            change_description=f"Update to version {v + 1}",
            created_by=test_user.id,
        )
        db_session.add(version)
    await db_session.flush()

    return report


@pytest_asyncio.fixture
async def test_feed(db_session: AsyncSession) -> Feed:
    feed = Feed(
        title="Security Blog",
        url="https://securityblog.example.com/rss",
        feed_type="rss",
    )
    db_session.add(feed)
    await db_session.flush()
    return feed


@pytest_asyncio.fixture
async def test_entries(db_session: AsyncSession, test_feed: Feed) -> list[Entry]:
    entries = []
    for i in range(3):
        entry = Entry(
            feed_id=test_feed.id,
            guid=f"entry-guid-{i}",
            url=f"https://securityblog.example.com/post/{i}",
            title=f"Security Advisory {i}",
            content_text=f"Details about vulnerability {i}",
            published_at=datetime(2026, 1, 15 + i, 12, 0, 0, tzinfo=UTC),
            content_hash=f"hash{i}",
        )
        db_session.add(entry)
        entries.append(entry)
    await db_session.flush()
    return entries


@pytest_asyncio.fixture
async def test_ttps(db_session: AsyncSession) -> list[TTP]:
    ttps = [
        TTP(technique_id="T1059", technique_name="Command and Scripting Interpreter", tactic="Execution"),
        TTP(technique_id="T1566", technique_name="Phishing", tactic="Initial Access"),
    ]
    for ttp in ttps:
        db_session.add(ttp)
    await db_session.flush()
    return ttps


# ---- Existing CRUD tests ----


@pytest.mark.asyncio
async def test_create_report(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        "/api/intel-reports",
        json={
            "title": "Landscape Report Q1 2026",
            "template_type": "landscape_report",
            "tlp_marking": "TLP:GREEN",
            "content": {"summary": "Q1 IOC summary"},
            "tags": ["quarterly"],
        },
        headers=auth_headers,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["title"] == "Landscape Report Q1 2026"
    assert data["status"] == "draft"
    assert data["version"] == 1


@pytest.mark.asyncio
async def test_list_reports(client: AsyncClient, auth_headers: dict, test_report: IntelReport):
    resp = await client.get("/api/intel-reports", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["total"] >= 1


@pytest.mark.asyncio
async def test_get_report(client: AsyncClient, auth_headers: dict, test_report: IntelReport):
    resp = await client.get(f"/api/intel-reports/{test_report.id}", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["title"] == "Flash Alert: Critical RCE Vulnerability"


@pytest.mark.asyncio
async def test_update_report_content_creates_version(client: AsyncClient, auth_headers: dict, test_report: IntelReport):
    resp = await client.put(
        f"/api/intel-reports/{test_report.id}",
        json={
            "content": {"executive_summary": "Updated summary"},
            "change_description": "Updated executive summary",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["version"] == 2


@pytest.mark.asyncio
async def test_publish_report(client: AsyncClient, auth_headers: dict, test_report: IntelReport):
    resp = await client.put(
        f"/api/intel-reports/{test_report.id}",
        json={"status": "published"},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "published"


@pytest.mark.asyncio
async def test_delete_report(client: AsyncClient, auth_headers: dict, test_report: IntelReport):
    resp = await client.delete(f"/api/intel-reports/{test_report.id}", headers=auth_headers)
    assert resp.status_code == 204


@pytest.mark.asyncio
async def test_filter_reports_by_template_type(client: AsyncClient, auth_headers: dict, test_report: IntelReport):
    resp = await client.get("/api/intel-reports?template_type=flash_alert", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["total"] >= 1


# ---- Version history tests ----


@pytest.mark.asyncio
async def test_version_history(client: AsyncClient, auth_headers: dict, test_report_with_versions: IntelReport):
    resp = await client.get(
        f"/api/intel-reports/{test_report_with_versions.id}/versions",
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 2
    # Versions should be ordered descending
    assert data[0]["version"] == 2
    assert data[1]["version"] == 1
    # Each version should have required fields
    for v in data:
        assert "id" in v
        assert "report_id" in v
        assert "content" in v
        assert "created_by" in v
        assert "created_at" in v


@pytest.mark.asyncio
async def test_version_history_not_found(client: AsyncClient, auth_headers: dict):
    fake_id = uuid.uuid4()
    resp = await client.get(f"/api/intel-reports/{fake_id}/versions", headers=auth_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_version_history_empty(client: AsyncClient, auth_headers: dict, test_report: IntelReport):
    """A report with no prior edits should have empty version history."""
    resp = await client.get(
        f"/api/intel-reports/{test_report.id}/versions",
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json() == []


# ---- Export tests ----


@pytest.mark.asyncio
async def test_export_markdown(client: AsyncClient, auth_headers: dict, test_report: IntelReport):
    resp = await client.get(
        f"/api/intel-reports/{test_report.id}/export?format=markdown",
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert "text/markdown" in resp.headers["content-type"]
    assert "attachment" in resp.headers["content-disposition"]

    content = resp.text
    # Check TLP banner
    assert "**TLP:AMBER**" in content
    # Check title
    assert "# Flash Alert: Critical RCE Vulnerability" in content
    # Check summary
    assert "Critical vulnerability requires immediate action" in content
    # Check section headers
    assert "## Summary" in content
    assert "## Key Findings" in content
    # Check metadata
    assert "**Template:** Flash Alert" in content
    assert "**Version:** 1" in content
    # Check tags
    assert "critical, rce, log4j" in content
    # Check footer
    assert "Generated by IntelFeed" in content


@pytest.mark.asyncio
async def test_export_html(client: AsyncClient, auth_headers: dict, test_report: IntelReport):
    resp = await client.get(
        f"/api/intel-reports/{test_report.id}/export?format=html",
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "attachment" in resp.headers["content-disposition"]

    content = resp.text
    assert "<!DOCTYPE html>" in content
    assert "<title>" in content
    assert "Flash Alert: Critical RCE Vulnerability" in content
    assert "tlp-banner" in content
    assert "TLP:AMBER" in content


@pytest.mark.asyncio
async def test_export_pdf(client: AsyncClient, auth_headers: dict, test_report: IntelReport):
    """With WeasyPrint installed, PDF export returns a real PDF."""
    resp = await client.get(
        f"/api/intel-reports/{test_report.id}/export?format=pdf",
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert "application/pdf" in resp.headers["content-type"]
    assert resp.content.startswith(b"%PDF-")


@pytest.mark.asyncio
async def test_export_pdf_fallback_to_html(client: AsyncClient, auth_headers: dict, test_report: IntelReport):
    """PDF export should fall back to HTML when WeasyPrint is not installed.

    A ``None`` entry in sys.modules makes ``import weasyprint`` raise
    ImportError, which is what a deployment without the optional dependency
    would hit.
    """
    import sys

    with patch.dict(sys.modules, {"weasyprint": None}):
        resp = await client.get(
            f"/api/intel-reports/{test_report.id}/export?format=pdf",
            headers=auth_headers,
        )
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    content = resp.text
    assert "PDF export requires WeasyPrint" in content
    assert "<!DOCTYPE html>" in content


@pytest.mark.asyncio
async def test_export_invalid_format(client: AsyncClient, auth_headers: dict, test_report: IntelReport):
    resp = await client.get(
        f"/api/intel-reports/{test_report.id}/export?format=docx",
        headers=auth_headers,
    )
    # Query validation should reject the format
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_export_not_found(client: AsyncClient, auth_headers: dict):
    fake_id = uuid.uuid4()
    resp = await client.get(f"/api/intel-reports/{fake_id}/export?format=markdown", headers=auth_headers)
    assert resp.status_code == 404


# ---- Generate from template tests ----


@pytest.mark.asyncio
async def test_generate_flash_alert(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        "/api/intel-reports/generate",
        json={
            "template_type": "flash_alert",
            "title": "Flash Alert: Zero-Day in Exchange",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["title"] == "Flash Alert: Zero-Day in Exchange"
    assert data["template_type"] == "flash_alert"
    assert data["status"] == "draft"
    assert data["version"] == 1

    # Content should have template sections
    content = data["content"]
    assert "sections" in content
    sections = content["sections"]
    assert "summary" in sections
    assert "key_findings" in sections
    assert "recommended_actions" in sections
    assert "references" in sections


@pytest.mark.asyncio
async def test_generate_with_entry_ids(
    client: AsyncClient,
    auth_headers: dict,
    test_entries: list[Entry],
):
    entry_ids = [str(e.id) for e in test_entries]
    resp = await client.post(
        "/api/intel-reports/generate",
        json={
            "template_type": "flash_alert",
            "entry_ids": entry_ids,
            "title": "Report With Entries",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 201
    data = resp.json()

    # References section should be populated from entries
    references = data["content"]["sections"]["references"]
    assert len(references["items"]) == 3
    assert references["items"][0]["title"] == "Security Advisory 0"
    assert references["items"][0]["url"] == "https://securityblog.example.com/post/0"


@pytest.mark.asyncio
async def test_generate_with_entity_ids(
    client: AsyncClient,
    auth_headers: dict,
    test_ttps: list[TTP],
):
    ttp_ids = [str(t.id) for t in test_ttps]
    resp = await client.post(
        "/api/intel-reports/generate",
        json={
            "template_type": "campaign_tracker",
            "entity_ids": {"ttps": ttp_ids},
            "title": "Campaign: APT-999 Tracker",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 201
    data = resp.json()

    # TTPs section should be populated
    ttps_section = data["content"]["sections"]["ttps"]
    assert len(ttps_section["items"]) == 2
    assert ttps_section["items"][0]["technique_id"] == "T1059"


@pytest.mark.asyncio
async def test_generate_default_title(client: AsyncClient, auth_headers: dict):
    """When no title is provided, a default should be generated."""
    resp = await client.post(
        "/api/intel-reports/generate",
        json={"template_type": "landscape_report"},
        headers=auth_headers,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["title"]  # Should have some non-empty title
    assert data["template_type"] == "landscape_report"


@pytest.mark.asyncio
async def test_generate_invalid_template(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        "/api/intel-reports/generate",
        json={"template_type": "nonexistent"},
        headers=auth_headers,
    )
    # Should be rejected by schema validation
    assert resp.status_code == 400


# ---- Template listing test ----


@pytest.mark.asyncio
async def test_list_templates(client: AsyncClient, auth_headers: dict, builtin_templates: list[str]):
    resp = await client.get("/api/intel-reports/templates", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "templates" in data
    templates = data["templates"]
    assert len(templates) == len(builtin_templates)

    template_types = {t["type"] for t in templates}
    assert template_types == set(builtin_templates)
    assert all(t["is_builtin"] for t in templates)

    # Each template should have required fields
    for t in templates:
        assert "name" in t
        assert "sections" in t
        assert "description" in t
        assert isinstance(t["sections"], list)
        assert len(t["sections"]) > 0


# ---- Markdown rendering unit tests ----


@pytest.mark.asyncio
async def test_render_markdown_no_sections(client: AsyncClient, auth_headers: dict):
    """Report with empty content should still render valid markdown."""
    resp = await client.post(
        "/api/intel-reports",
        json={
            "title": "Empty Report",
            "template_type": "custom",
            "content": {},
        },
        headers=auth_headers,
    )
    assert resp.status_code == 201
    report_id = resp.json()["id"]

    export_resp = await client.get(
        f"/api/intel-reports/{report_id}/export?format=markdown",
        headers=auth_headers,
    )
    assert export_resp.status_code == 200
    content = export_resp.text
    assert "# Empty Report" in content
    assert "Generated by IntelFeed" in content


# ---- Full AI report generation tests (Phase 4.1) ----


@pytest.mark.asyncio
async def test_generate_full_report_from_entry(
    client: AsyncClient,
    auth_headers: dict,
    test_entries: list[Entry],
):
    """Generate a full report from a single entry source."""
    entry = test_entries[0]
    with patch("app.workers.report_tasks.generate_full_report") as mock_task:
        mock_task.delay.return_value = MagicMock(id="mock-task-id")
        resp = await client.post(
            "/api/intel-reports/generate-full",
            json={
                "source_type": "entry",
                "entry_id": str(entry.id),
                "template_type": "flash_alert",
                "title": "Flash Alert from Entry",
                "tlp_marking": "TLP:AMBER",
                "focus": "Detection opportunities",
                "audience": "SOC analysts",
                "tags": ["test"],
            },
            headers=auth_headers,
        )
    assert resp.status_code == 201
    data = resp.json()
    assert data["task_id"] == "mock-task-id"
    report = data["report"]
    assert report["title"] == "Flash Alert from Entry"
    assert report["template_type"] == "flash_alert"
    assert report["tlp_marking"] == "TLP:AMBER"
    assert report["status"] == "draft"
    assert report["tags"] == ["test"]
    # Focus/audience should be in metadata
    assert report["content"]["metadata"]["focus"] == "Detection opportunities"
    assert report["content"]["metadata"]["audience"] == "SOC analysts"
    # Celery task should have been dispatched
    mock_task.delay.assert_called_once()


@pytest.mark.asyncio
async def test_generate_full_report_from_entries(
    client: AsyncClient,
    auth_headers: dict,
    test_entries: list[Entry],
):
    """Generate a full report from multiple entry sources."""
    entry_ids = [str(e.id) for e in test_entries]
    with patch("app.workers.report_tasks.generate_full_report") as mock_task:
        mock_task.delay.return_value = MagicMock(id="mock-task-id-2")
        resp = await client.post(
            "/api/intel-reports/generate-full",
            json={
                "source_type": "entries",
                "entry_ids": entry_ids,
                "template_type": "campaign_tracker",
            },
            headers=auth_headers,
        )
    assert resp.status_code == 201
    data = resp.json()
    report = data["report"]
    assert report["template_type"] == "campaign_tracker"
    # All 3 entry IDs should be linked
    assert len(report["entry_ids"]) == 3
    # All entry IDs should be linked to the report
    assert set(report["entry_ids"]) == set(entry_ids)


@pytest.mark.asyncio
async def test_generate_full_report_from_search(
    client: AsyncClient,
    auth_headers: dict,
    test_entries: list[Entry],
):
    """Generate a full report from a search query (mock Meilisearch)."""
    search_hits = [{"id": str(e.id)} for e in test_entries[:2]]
    with (
        patch("app.services.meilisearch_client.search_entries", return_value={"hits": search_hits}),
        patch("app.workers.report_tasks.generate_full_report") as mock_task,
    ):
        mock_task.delay.return_value = MagicMock(id="mock-task-search")
        resp = await client.post(
            "/api/intel-reports/generate-full",
            json={
                "source_type": "search",
                "search_query": "ransomware",
                "search_limit": 20,
                "template_type": "flash_alert",
            },
            headers=auth_headers,
        )
    assert resp.status_code == 201
    data = resp.json()
    report = data["report"]
    assert len(report["entry_ids"]) == 2
    mock_task.delay.assert_called_once()


@pytest.mark.asyncio
async def test_generate_full_report_from_saved_search(
    client: AsyncClient,
    auth_headers: dict,
    db_session: AsyncSession,
    test_user: User,
    test_entries: list[Entry],
):
    """Generate a full report from a saved search (mock Meilisearch)."""
    from app.models.saved_search import SavedSearch

    saved = SavedSearch(
        created_by=test_user.id,
        name="my-search",
        display_name="My Search",
        query="apt29",
    )
    db_session.add(saved)
    await db_session.flush()

    search_hits = [{"id": str(test_entries[0].id)}]
    with (
        patch("app.services.meilisearch_client.search_entries", return_value={"hits": search_hits}),
        patch("app.workers.report_tasks.generate_full_report") as mock_task,
    ):
        mock_task.delay.return_value = MagicMock(id="mock-task-saved")
        resp = await client.post(
            "/api/intel-reports/generate-full",
            json={
                "source_type": "saved_search",
                "saved_search_id": str(saved.id),
                "template_type": "landscape_report",
            },
            headers=auth_headers,
        )
    assert resp.status_code == 201
    data = resp.json()
    report = data["report"]
    assert report["template_type"] == "landscape_report"
    assert len(report["entry_ids"]) == 1


@pytest.mark.asyncio
async def test_generate_full_validation(client: AsyncClient, auth_headers: dict):
    """Validation should reject missing required fields per source type."""
    # entry without entry_id
    resp = await client.post(
        "/api/intel-reports/generate-full",
        json={"source_type": "entry", "template_type": "flash_alert"},
        headers=auth_headers,
    )
    assert resp.status_code in (400, 422)

    # entries without entry_ids
    resp = await client.post(
        "/api/intel-reports/generate-full",
        json={"source_type": "entries", "template_type": "flash_alert"},
        headers=auth_headers,
    )
    assert resp.status_code in (400, 422)

    # search without search_query
    resp = await client.post(
        "/api/intel-reports/generate-full",
        json={"source_type": "search", "template_type": "flash_alert"},
        headers=auth_headers,
    )
    assert resp.status_code in (400, 422)

    # saved_search without saved_search_id
    resp = await client.post(
        "/api/intel-reports/generate-full",
        json={"source_type": "saved_search", "template_type": "flash_alert"},
        headers=auth_headers,
    )
    assert resp.status_code in (400, 422)

    # invalid template_type pattern
    resp = await client.post(
        "/api/intel-reports/generate-full",
        json={
            "source_type": "entry",
            "entry_id": str(uuid.uuid4()),
            "template_type": "INVALID!",
        },
        headers=auth_headers,
    )
    assert resp.status_code in (400, 422)


@pytest.mark.asyncio
async def test_resolve_report_sources(
    db_session: AsyncSession,
    test_user: User,
    test_entries: list[Entry],
    test_ttps: list[TTP],
):
    """Unit test for resolve_report_sources with entity collection from junction tables."""
    from app.intelligence.reporting import resolve_report_sources
    from app.models.ttp import EntryTTP

    # Link a TTP to an entry via junction table
    link = EntryTTP(entry_id=test_entries[0].id, ttp_id=test_ttps[0].id)
    db_session.add(link)
    await db_session.flush()

    entry_ids, entity_ids = await resolve_report_sources(
        db=db_session,
        source_type="entries",
        entry_id=None,
        entry_ids=[e.id for e in test_entries],
        search_query=None,
        saved_search_id=None,
        user_id=test_user.id,
    )

    assert len(entry_ids) == 3
    assert "ttps" in entity_ids
    assert str(test_ttps[0].id) in entity_ids["ttps"]


@pytest.mark.asyncio
async def test_generate_section_with_focus_audience(
    db_session: AsyncSession,
    test_user: User,
    test_entries: list[Entry],
):
    """Verify focus and audience are passed through to AI run_task."""
    from app.intelligence.reporting import generate_section_content

    report = IntelReport(
        created_by=test_user.id,
        title="Test Focus Report",
        template_type="flash_alert",
        tlp_marking="TLP:GREEN",
        content={"sections": {"summary": {"title": "Summary", "body": ""}}},
        entry_ids=[e.id for e in test_entries],
        entity_ids={},
    )
    db_session.add(report)
    await db_session.flush()

    with patch("app.ai.engine.run_task", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = {"content": "AI generated summary text"}
        result = await generate_section_content(
            db=db_session,
            user_id=test_user.id,
            report=report,
            section_name="summary",
            focus="lateral movement",
            audience="detection engineers",
        )

    assert result["content"] == "AI generated summary text"
    # run_task is called with keyword args: db, user_id, task_name, variables, target_type, target_id
    mock_run.assert_called_once()
    call_kwargs = mock_run.call_args.kwargs
    # flash_alert reports route to their tailored prompt task; the generic
    # report_section task is the fallback for custom/DB templates.
    assert call_kwargs["task_name"] == "report_section_flash_alert"
    variables = call_kwargs["variables"]
    assert variables["focus"] == "lateral movement"
    assert variables["audience"] == "detection engineers"
    assert variables["section_name"] == "summary"


# --- Observables in reports -------------------------------------------------
# The "iocs" data section is the observables ledger: judged rows sighted in the
# report's source entries, defanged in the render, carrying attribution claims.


async def _seed_report_observables(db_session, test_user, entries):
    from app.intelligence.observables import get_or_create_observable, record_sighting
    from app.models.entity_relationship import EntityRelationship
    from app.models.malware_family import MalwareFamily

    mal = MalwareFamily(name="Qakbot")
    db_session.add(mal)
    await db_session.flush()

    c2 = await get_or_create_observable(
        db_session, "ipv4", "91.92.240.37", via="ai_extraction", role="c2", evidence="beacons to it"
    )
    await record_sighting(db_session, entries[0].id, c2, source="ai")
    dom = await get_or_create_observable(db_session, "domain", "update-checker.net", via="manual")
    await record_sighting(db_session, entries[1].id, dom, source="manual")
    denied = await get_or_create_observable(db_session, "ipv4", "193.149.176.201", via="manual")
    await record_sighting(db_session, entries[0].id, denied, source="manual")
    denied.is_denied = True

    db_session.add(
        EntityRelationship(
            source_type="malware",
            source_id=mal.id,
            target_type="observable",
            target_id=c2.id,
            relationship_type="communicates_with",
            source="ai_extraction",
        )
    )
    await db_session.flush()
    return c2, dom, denied


@pytest.mark.asyncio
async def test_report_content_fills_iocs_section_from_ledger(
    db_session: AsyncSession, test_user: User, test_entries: list[Entry]
):
    from app.intelligence.reporting import generate_report_content, resolve_report_sources

    await _seed_report_observables(db_session, test_user, test_entries)

    entry_ids, entity_ids = await resolve_report_sources(
        db=db_session,
        source_type="entries",
        entry_id=None,
        entry_ids=[e.id for e in test_entries],
        search_query=None,
        saved_search_id=None,
        user_id=test_user.id,
    )
    assert "observables" in entity_ids

    content = await generate_report_content("flash_alert", entry_ids, entity_ids, db_session)
    section = content["sections"]["iocs"]
    assert section["title"] == "Indicators of Compromise"
    values = {i["value"] for i in section["items"]}
    assert values == {"91.92.240.37", "update-checker.net"}  # denied row excluded
    # The attribution-claimed row sorts first and carries its claim label.
    assert section["items"][0]["value"] == "91.92.240.37"
    assert section["items"][0]["claimed_by"] == ["Qakbot · communicates with"]


@pytest.mark.asyncio
async def test_report_markdown_renders_defanged_indicator_table(
    db_session: AsyncSession, test_user: User, test_entries: list[Entry]
):
    from app.intelligence.reporting import generate_report_content, render_markdown

    await _seed_report_observables(db_session, test_user, test_entries)
    content = await generate_report_content("flash_alert", [e.id for e in test_entries], {}, db_session)

    report = IntelReport(
        created_by=test_user.id,
        title="Qakbot flash",
        template_type="flash_alert",
        tlp_marking="TLP:AMBER",
        status="draft",
        content=content,
        entry_ids=[e.id for e in test_entries],
    )
    db_session.add(report)
    await db_session.flush()
    md = render_markdown(report)
    assert "| Kind | Value (defanged) |" in md
    assert "`91[.]92[.]240[.]37`" in md  # defanged, code-quoted
    assert "91.92.240.37" not in md.replace("91[.]92[.]240[.]37", "")  # never fanged
    assert "193" not in md  # denied row absent
    assert "Qakbot · communicates with" in md


@pytest.mark.asyncio
async def test_report_iocs_section_empty_is_honest(db_session: AsyncSession, test_user: User):
    from app.intelligence.reporting import generate_report_content

    content = await generate_report_content("flash_alert", [], {}, db_session)
    section = content["sections"]["iocs"]
    assert section["items"] == []
    assert "No judged observables" in section["body"]


@pytest.mark.asyncio
async def test_db_template_sections_are_honored(db_session: AsyncSession, test_user: User, test_entries: list[Entry]):
    """A DB-only template (ioc_bulletin-style) pre-fills ITS sections, not flash_alert's."""
    from app.intelligence.reporting import generate_report_content

    db_session.add(
        ReportTemplate(
            name="IOC Bulletin",
            description="test",
            template_slug="ioc_bulletin_test",
            sections=[
                {"name": "summary", "title": "Summary", "type": "narrative"},
                {"name": "ioc_table", "title": "IOC Table", "type": "data"},
            ],
            is_builtin=True,
            is_shared=True,
        )
    )
    await db_session.flush()
    await _seed_report_observables(db_session, test_user, test_entries)

    content = await generate_report_content("ioc_bulletin_test", [e.id for e in test_entries], {}, db_session)
    assert set(content["sections"]) == {"summary", "ioc_table"}
    assert len(content["sections"]["ioc_table"]["items"]) == 2


# ── Rules as report evidence ────────────────────────────────────────────────
# A coverage set's whole output is the rules it adopted. Before this, attach
# took entries and entities only, so sending a set dropped exactly the part
# worth sending.


@pytest_asyncio.fixture
async def attachable_rules(db_session: AsyncSession) -> list[DetectionRule]:
    rules = [
        DetectionRule(
            title="Fortinet - Beacon pattern detected",
            rule_type="kql",
            rule_content="SecurityEvent | where true",
            license="MIT",
            is_draft=False,
            source_ttps=["T1071", "T1571"],
            metadata_={"repo": "Azure-Sentinel"},
        ),
        DetectionRule(
            title="Locally drafted coverage rule",
            rule_type="sigma",
            rule_content="detection: {condition: selection}",
            license=None,
            is_draft=True,
            source_ttps=["T1071"],
        ),
    ]
    for rule in rules:
        db_session.add(rule)
    await db_session.flush()
    return rules


async def test_attach_carries_detection_rules(
    client: AsyncClient,
    auth_headers: dict,
    test_report: IntelReport,
    attachable_rules: list[DetectionRule],
):
    """Attached rules become a Detections section with their attribution."""
    resp = await client.post(
        f"/api/intel-reports/{test_report.id}/attach",
        headers=auth_headers,
        json={
            "entry_ids": [],
            "entity_ids": {"detection_rules": [str(r.id) for r in attachable_rules]},
        },
    )
    assert resp.status_code == 200
    section = resp.json()["content"]["sections"]["detections"]
    assert section["title"] == "Detections"

    by_title = {i["rule_title"]: i for i in section["items"]}
    assert by_title["Fortinet - Beacon pattern detected"]["repo"] == "Azure-Sentinel"
    assert by_title["Fortinet - Beacon pattern detected"]["license"] == "MIT"
    # A locally authored rule has no upstream repo to credit.
    assert by_title["Locally drafted coverage rule"]["repo"] == "local"
    assert by_title["Locally drafted coverage rule"]["is_draft"] is True


async def test_attach_note_seeds_the_detections_body(
    client: AsyncClient,
    auth_headers: dict,
    test_report: IntelReport,
    attachable_rules: list[DetectionRule],
):
    """A set's skipped rules ride along as known gaps."""
    resp = await client.post(
        f"/api/intel-reports/{test_report.id}/attach",
        headers=auth_headers,
        json={
            "entity_ids": {"detection_rules": [str(attachable_rules[0].id)]},
            "note": "Known gaps — 1 rule considered and not adopted:\n\n- YARA sig — cannot fire here",
        },
    )
    assert resp.status_code == 200
    assert "cannot fire here" in resp.json()["content"]["sections"]["detections"]["body"]


async def test_attach_note_never_overwrites_analyst_prose(
    client: AsyncClient,
    auth_headers: dict,
    test_report: IntelReport,
    attachable_rules: list[DetectionRule],
    db_session: AsyncSession,
):
    """A body someone wrote outranks whatever the sending surface wanted to say."""
    await client.post(
        f"/api/intel-reports/{test_report.id}/attach",
        headers=auth_headers,
        json={"entity_ids": {"detection_rules": [str(attachable_rules[0].id)]}, "note": "first note"},
    )
    content = dict(test_report.content or {})
    sections = dict(content["sections"])
    sections["detections"] = {**sections["detections"], "body": "Analyst wrote this"}
    content["sections"] = sections
    test_report.content = content
    db_session.add(test_report)
    await db_session.flush()

    resp = await client.post(
        f"/api/intel-reports/{test_report.id}/attach",
        headers=auth_headers,
        json={"entity_ids": {"detection_rules": [str(attachable_rules[1].id)]}, "note": "second note"},
    )
    assert resp.status_code == 200
    section = resp.json()["content"]["sections"]["detections"]
    assert section["body"] == "Analyst wrote this"
    # …while the new rule still joins the table.
    assert len(section["items"]) == 2


async def test_detections_render_as_an_attributed_table(
    client: AsyncClient,
    auth_headers: dict,
    test_report: IntelReport,
    attachable_rules: list[DetectionRule],
    db_session: AsyncSession,
):
    """The markdown export names the repo and licence for every rule."""
    await client.post(
        f"/api/intel-reports/{test_report.id}/attach",
        headers=auth_headers,
        json={"entity_ids": {"detection_rules": [str(r.id) for r in attachable_rules]}},
    )
    await db_session.refresh(test_report)
    md = render_markdown(test_report)

    assert "## Detections" in md
    assert "| Rule | Format | Source | Licence | ATT&CK |" in md
    assert "Azure\\-Sentinel" in md
    assert "MIT" in md
    # A rule with no recorded licence says so rather than reading as unencumbered.
    assert "unstated" in md


async def test_no_rules_attached_means_no_detections_section(
    client: AsyncClient,
    auth_headers: dict,
    test_report: IntelReport,
):
    """The section appears only when there is something to put in it."""
    resp = await client.post(
        f"/api/intel-reports/{test_report.id}/attach",
        headers=auth_headers,
        json={"entry_ids": [], "entity_ids": {}},
    )
    assert resp.status_code == 200
    assert "detections" not in resp.json()["content"]["sections"]
