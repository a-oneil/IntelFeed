"""Public share links for intel reports — mint, read, revoke, export, preview."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.intel_report import IntelReport
from app.models.report_template import ReportTemplate
from app.models.shared_report import SharedReport
from app.models.user import User

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def flash_template(db_session: AsyncSession) -> ReportTemplate:
    """The builtin template, which decides section order and titles on the public page."""
    row = ReportTemplate(
        name="Flash Alert",
        description="Rapid notification",
        template_slug="flash_alert",
        sections=[
            {"name": "summary", "title": "Summary", "type": "narrative"},
            {"name": "key_findings", "title": "Key Findings", "type": "narrative"},
            {"name": "iocs", "title": "Indicators", "type": "data"},
            {"name": "references", "title": "References", "type": "data"},
        ],
        is_builtin=True,
        is_shared=True,
    )
    db_session.add(row)
    await db_session.flush()
    return row


@pytest_asyncio.fixture
async def report(db_session: AsyncSession, test_user: User, flash_template: ReportTemplate) -> IntelReport:
    row = IntelReport(
        created_by=test_user.id,
        title="Flash Alert: Log4Shell",
        template_type="flash_alert",
        tlp_marking="TLP:GREEN",
        summary="Active exploitation of CVE-2021-44228",
        content={
            "sections": {
                # Stored out of template order on purpose: JSONB does not keep
                # key order, so the public page must not rely on it.
                "references": {"title": "References", "items": [{"title": "Advisory", "url": "https://x.test/a"}]},
                "key_findings": {"body": "## Key Findings\n\nJNDI lookups reach attacker-controlled LDAP."},
                "summary": {"title": "Summary", "body": "Critical RCE in log4j 2.x."},
            }
        },
        tags=["rce", "log4j"],
    )
    db_session.add(row)
    await db_session.flush()
    return row


async def _mint(client: AsyncClient, report: IntelReport, headers: dict) -> str:
    resp = await client.post(f"/api/intel-reports/{report.id}/share", headers=headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["url"] == f"/shared/report/{body['token']}"
    return body["token"]


async def test_share_link_is_minted_once_per_sharer(client: AsyncClient, report: IntelReport, auth_headers: dict):
    first = await _mint(client, report, auth_headers)
    second = await _mint(client, report, auth_headers)
    assert first == second

    resp = await client.get(f"/api/intel-reports/{report.id}/share", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["token"] == first


async def test_no_link_reads_as_null(client: AsyncClient, report: IntelReport, auth_headers: dict):
    resp = await client.get(f"/api/intel-reports/{report.id}/share", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json() is None


@pytest.mark.parametrize("marking", ["TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"])
async def test_amber_and_red_cannot_be_shared(
    client: AsyncClient, db_session: AsyncSession, report: IntelReport, auth_headers: dict, marking: str
):
    report.tlp_marking = marking
    await db_session.flush()
    resp = await client.post(f"/api/intel-reports/{report.id}/share", headers=auth_headers)
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "tlp_restricted"


@pytest.mark.parametrize("marking", ["TLP:CLEAR", "TLP:GREEN"])
async def test_clear_and_green_can_be_shared(
    client: AsyncClient, db_session: AsyncSession, report: IntelReport, auth_headers: dict, marking: str
):
    report.tlp_marking = marking
    await db_session.flush()
    await db_session.refresh(report)
    token = await _mint(client, report, auth_headers)
    assert (await client.get(f"/api/shared/report/{token}")).status_code == 200


async def test_remarking_a_shared_report_amber_pauses_its_link(
    client: AsyncClient, db_session: AsyncSession, report: IntelReport, auth_headers: dict
):
    """The rule holds at read time, not only when the link is made."""
    token = await _mint(client, report, auth_headers)
    assert (await client.get(f"/api/shared/report/{token}")).status_code == 200

    report.tlp_marking = "TLP:AMBER"
    await db_session.flush()
    await db_session.refresh(report)
    resp = await client.get(f"/api/shared/report/{token}")
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "tlp_restricted"
    assert (await client.get(f"/api/shared/report/{token}/export")).status_code == 403
    assert (await client.get(f"/api/shared/report/{token}/og")).status_code == 404

    # Back to GREEN and the same link works again — nothing was revoked.
    report.tlp_marking = "TLP:GREEN"
    await db_session.flush()
    await db_session.refresh(report)
    assert (await client.get(f"/api/shared/report/{token}")).status_code == 200


async def test_public_view_orders_sections_by_template_and_hides_author(
    client: AsyncClient, report: IntelReport, auth_headers: dict
):
    token = await _mint(client, report, auth_headers)

    resp = await client.get(f"/api/shared/report/{token}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["title"] == "Flash Alert: Log4Shell"
    assert body["template_name"] == "Flash Alert"
    assert body["tlp_marking"] == "TLP:GREEN"
    assert body["tags"] == ["rce", "log4j"]
    assert "created_by" not in body
    assert "entry_ids" not in body

    sections = body["sections"]
    assert [s["name"] for s in sections] == ["summary", "key_findings", "references"]
    assert [s["type"] for s in sections] == ["narrative", "narrative", "data"]
    # The template supplies the title the saved section lacks, and a body's own
    # "## heading" is dropped so the page does not draw it twice.
    assert sections[1]["title"] == "Key Findings"
    assert sections[1]["body"] == "JNDI lookups reach attacker-controlled LDAP."
    assert sections[2]["items"] == [{"title": "Advisory", "url": "https://x.test/a"}]


async def test_revoked_link_stops_resolving(client: AsyncClient, report: IntelReport, auth_headers: dict):
    token = await _mint(client, report, auth_headers)
    assert (await client.get(f"/api/shared/report/{token}")).status_code == 200

    resp = await client.delete(f"/api/intel-reports/{report.id}/share", headers=auth_headers)
    assert resp.status_code == 200
    assert (await client.get(f"/api/shared/report/{token}")).status_code == 404
    assert (await client.get(f"/api/shared/report/{token}/export")).status_code == 404
    assert (await client.get(f"/api/shared/report/{token}/og")).status_code == 404

    # Nothing left to revoke.
    assert (await client.delete(f"/api/intel-reports/{report.id}/share", headers=auth_headers)).status_code == 404


async def test_admin_revokes_every_sharers_link(
    client: AsyncClient, db_session: AsyncSession, report: IntelReport, auth_headers: dict, admin_headers: dict
):
    token = await _mint(client, report, auth_headers)
    resp = await client.delete(f"/api/intel-reports/{report.id}/share", headers=admin_headers)
    assert resp.status_code == 200
    share = (await db_session.execute(SharedReport.__table__.select().where(SharedReport.token == token))).one()
    assert share.is_active is False


async def test_unknown_token_is_404(client: AsyncClient):
    assert (await client.get("/api/shared/report/nope")).status_code == 404


async def test_public_export_matches_the_builders(client: AsyncClient, report: IntelReport, auth_headers: dict):
    token = await _mint(client, report, auth_headers)

    public = await client.get(f"/api/shared/report/{token}/export", params={"format": "markdown"})
    assert public.status_code == 200
    assert public.headers["content-type"].startswith("text/markdown")
    assert 'filename="Flash Alert Log4Shell.md"' in public.headers["content-disposition"]
    assert "Critical RCE in log4j 2.x." in public.text

    private = await client.get(
        f"/api/intel-reports/{report.id}/export", params={"format": "markdown"}, headers=auth_headers
    )
    assert private.text == public.text

    html = await client.get(f"/api/shared/report/{token}/export", params={"format": "html"})
    assert html.status_code == 200
    assert html.headers["content-type"].startswith("text/html")
    assert "<h2>Summary</h2>" in html.text

    assert (await client.get(f"/api/shared/report/{token}/export", params={"format": "docx"})).status_code == 400


async def test_og_preview_carries_title_and_summary(client: AsyncClient, report: IntelReport, auth_headers: dict):
    token = await _mint(client, report, auth_headers)
    resp = await client.get(
        f"/api/shared/report/{token}/og", headers={"host": "intel.example", "x-forwarded-proto": "https"}
    )
    assert resp.status_code == 200
    assert 'property="og:title" content="Flash Alert: Log4Shell"' in resp.text
    assert 'content="Active exploitation of CVE-2021-44228"' in resp.text
    assert f'content="https://intel.example/shared/report/{token}"' in resp.text


# ── What a token holder can and cannot reach ────────────────────────


async def test_public_view_carries_no_metadata_or_source_ids(
    client: AsyncClient, db_session: AsyncSession, report: IntelReport, auth_headers: dict
):
    """content.metadata holds profile ids, focus and audience; none of it is the report."""
    report.content = {
        **report.content,
        "metadata": {"profile_id": "secret-profile", "profile_name": "Acme portfolio", "audience": "CISO"},
    }
    report.entry_ids = [uuid.uuid4()]
    report.entity_ids = {"actors": [str(uuid.uuid4())]}
    await db_session.flush()
    # The UPDATE expires the server-set updated_at; the request shares this
    # session in tests, so reload before the route reads the row.
    await db_session.refresh(report)
    token = await _mint(client, report, auth_headers)

    resp = await client.get(f"/api/shared/report/{token}")
    assert resp.status_code == 200
    text = resp.text
    for leaked in ("secret-profile", "Acme portfolio", "CISO", "metadata", "entry_ids", "entity_ids", "created_by"):
        assert leaked not in text, leaked

    exported = await client.get(f"/api/shared/report/{token}/export", params={"format": "markdown"})
    assert "Acme portfolio" not in exported.text
    assert "secret-profile" not in exported.text


async def test_token_opens_nothing_but_the_shared_routes(client: AsyncClient, report: IntelReport, auth_headers: dict):
    """Holding a share token is not a login: the report's own API stays closed."""
    token = await _mint(client, report, auth_headers)
    closed = [
        f"/api/intel-reports/{report.id}",
        f"/api/intel-reports/{report.id}/export",
        f"/api/intel-reports/{report.id}/versions",
        f"/api/intel-reports/{report.id}/share",
        "/api/intel-reports",
        "/api/intel-reports/templates",
    ]
    for path in closed:
        for params in ({}, {"token": token}):
            resp = await client.get(path, params=params)
            assert resp.status_code == 401, (path, params, resp.status_code)
    assert (await client.post(f"/api/intel-reports/{report.id}/share")).status_code == 401
    assert (await client.delete(f"/api/intel-reports/{report.id}/share")).status_code == 401


async def test_share_of_a_deleted_report_is_gone(
    client: AsyncClient, db_session: AsyncSession, report: IntelReport, auth_headers: dict
):
    token = await _mint(client, report, auth_headers)
    await db_session.delete(report)
    await db_session.flush()
    assert (await client.get(f"/api/shared/report/{token}")).status_code == 404
    assert (await client.get(f"/api/shared/report/{token}/og")).status_code == 404


async def test_expired_link_is_410(
    client: AsyncClient, db_session: AsyncSession, report: IntelReport, auth_headers: dict
):
    token = await _mint(client, report, auth_headers)
    share = (await db_session.execute(select(SharedReport).where(SharedReport.token == token))).scalar_one()
    share.expires_at = datetime.now(UTC) - timedelta(minutes=1)
    await db_session.flush()
    assert (await client.get(f"/api/shared/report/{token}")).status_code == 410
    assert (await client.get(f"/api/shared/report/{token}/export")).status_code == 410
    assert (await client.get(f"/api/shared/report/{token}/og")).status_code == 404


async def test_download_filename_is_header_safe(
    client: AsyncClient, db_session: AsyncSession, report: IntelReport, auth_headers: dict
):
    """A title with quotes, slashes or non-Latin text must not break (or inject into) the header."""
    report.title = 'Ünïcode "quoted" report / with\\slashes; filename="x.exe"'
    await db_session.flush()
    await db_session.refresh(report)
    token = await _mint(client, report, auth_headers)

    resp = await client.get(f"/api/shared/report/{token}/export", params={"format": "markdown"})
    assert resp.status_code == 200
    assert (
        resp.headers["content-disposition"]
        == 'attachment; filename="ncode quoted report  withslashes filenamex.exe.md"'
    )


async def test_malformed_section_items_do_not_break_the_page(
    client: AsyncClient, db_session: AsyncSession, report: IntelReport, auth_headers: dict
):
    report.content = {
        "sections": {
            "summary": {"body": "ok"},
            "references": {"items": ["not-a-row", {"title": "Row", "url": "https://x.test"}, 7]},
            "weird": "not even a dict",
        }
    }
    await db_session.flush()
    await db_session.refresh(report)
    token = await _mint(client, report, auth_headers)

    resp = await client.get(f"/api/shared/report/{token}")
    assert resp.status_code == 200
    by_name = {s["name"]: s for s in resp.json()["sections"]}
    assert by_name["references"]["items"] == [{"title": "Row", "url": "https://x.test"}]
    assert by_name["weird"]["body"] == "" and by_name["weird"]["items"] == []


# ── The registry tools (skill CLIs, MCP, copilot) ───────────────────


async def test_share_tools_mirror_the_api(
    client: AsyncClient, db_session: AsyncSession, report: IntelReport, test_user: User
):
    import json

    from app.tools import execute_tool

    made = json.loads(
        await execute_tool("create_report_share_link", {"report_id": str(report.id)}, db_session, test_user.id)
    )
    assert made["already_existed"] is False
    assert made["url"] == f"/shared/report/{made['token']}"
    again = json.loads(
        await execute_tool("create_report_share_link", {"report_id": str(report.id)}, db_session, test_user.id)
    )
    assert again["token"] == made["token"] and again["already_existed"] is True

    # The public page answers the tool-made link like an API-made one.
    assert (await client.get(f"/api/shared/report/{made['token']}")).status_code == 200

    got = json.loads(
        await execute_tool("get_report_share_link", {"report_id": str(report.id)}, db_session, test_user.id)
    )
    assert got["share"]["token"] == made["token"]

    gone = json.loads(
        await execute_tool("revoke_report_share_link", {"report_id": str(report.id)}, db_session, test_user.id)
    )
    assert gone["revoked"] is True
    assert (await client.get(f"/api/shared/report/{made['token']}")).status_code == 404
    got = json.loads(
        await execute_tool("get_report_share_link", {"report_id": str(report.id)}, db_session, test_user.id)
    )
    assert got["share"] is None


async def test_share_tool_refuses_amber_and_bad_ttl(db_session: AsyncSession, report: IntelReport, test_user: User):
    import json

    from app.tools import execute_tool

    bad = json.loads(
        await execute_tool(
            "create_report_share_link", {"report_id": str(report.id), "ttl_days": 0}, db_session, test_user.id
        )
    )
    assert "ttl_days" in bad["error"]

    report.tlp_marking = "TLP:AMBER"
    await db_session.flush()
    refused = json.loads(
        await execute_tool("create_report_share_link", {"report_id": str(report.id)}, db_session, test_user.id)
    )
    assert "TLP:AMBER" in refused["error"]


async def test_public_view_highlights_entities_without_a_session(
    client: AsyncClient, db_session: AsyncSession, report: IntelReport, auth_headers: dict
):
    """The page gets the auto-linker's matches with the report, scanned
    server-side, so a reader with no login sees the same highlights as the
    builder. The summary, body and every section body are all scanned."""
    from app.intelligence.autolinker import refresh_vocabulary
    from app.models.threat_actor import ThreatActor

    db_session.add(ThreatActor(name="Shareline Bear", aliases=["SB-Share"], description="Named in a shared report."))
    await db_session.flush()
    report.summary = "Shareline Bear is exploiting CVE-2021-44228."
    report.content = {
        "body": "A note up top.",
        "sections": {
            **report.content["sections"],
            "key_findings": {"body": "## Key Findings\n\nSB-Share reached attacker-controlled LDAP."},
        },
    }
    await db_session.flush()
    # The update expires the server-set updated_at; reload it so the request
    # does not lazy-load it mid-response.
    await db_session.refresh(report)
    await refresh_vocabulary(db_session)
    token = await _mint(client, report, auth_headers)

    resp = await client.get(f"/api/shared/report/{token}")
    assert resp.status_code == 200
    matches = resp.json()["entities"]
    actor = next(m for m in matches if m["entity_type"] == "threat_actor")
    assert actor["canonical_name"] == "Shareline Bear"
    # Both the canonical name (summary) and the alias (section body) matched.
    assert {sf.lower() for sf in actor["surface_forms"]} == {"shareline bear", "sb-share"}
    # The popover's payload rides along, exactly as POST /autolink/scan returns it.
    assert actor["entity"]["description"] == "Named in a shared report."


async def test_public_view_sorts_the_timeline(
    client: AsyncClient, db_session: AsyncSession, report: IntelReport, auth_headers: dict
):
    """A timeline saved in query order reads oldest first; undated rows go last."""
    report.content = {
        "sections": {
            **report.content["sections"],
            "timeline": {
                "title": "Timeline",
                "items": [
                    {"date": "2026-03-02T10:00:00+00:00", "title": "Third"},
                    {"date": None, "title": "Undated"},
                    {"date": "2026-01-29T10:00:00+00:00", "title": "First"},
                    {"date": "2026-02-02T10:00:00+00:00", "title": "Second"},
                ],
            },
        },
    }
    await db_session.flush()
    await db_session.refresh(report)
    token = await _mint(client, report, auth_headers)

    resp = await client.get(f"/api/shared/report/{token}")
    assert resp.status_code == 200
    timeline = next(s for s in resp.json()["sections"] if s["name"] == "timeline")
    assert [i["title"] for i in timeline["items"]] == ["First", "Second", "Third", "Undated"]

    # The markdown export walks the same order.
    md = (await client.get(f"/api/shared/report/{token}/export", params={"format": "markdown"})).text
    assert md.index("First") < md.index("Second") < md.index("Third") < md.index("Undated")
    # The export shows the day, not the full timestamp with its offset.
    assert "**2026\\-01\\-29**: First" in md  # _escape_md escapes the hyphens
    assert "+00:00" not in md
    html = (await client.get(f"/api/shared/report/{token}/export", params={"format": "html"})).text
    assert "+00:00" not in html
