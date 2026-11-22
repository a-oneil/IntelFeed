"""Public share links for intel reports.

The report counterpart of ``app.api.shared``: a signed-in user mints a token
for a report, and anyone holding the token reads the rendered report at
``/shared/report/{token}`` with no login — the same shape as a shared article.
"""

import html
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Path, Query, Request
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.intelligence import scan_text_matches
from app.api.shared import _OG_DESCRIPTION_LIMIT, ShareLinkResponse, _truncate
from app.core.exceptions import AppError
from app.core.security import get_current_user
from app.database import get_db
from app.intelligence.reporting import REPORT_TEMPLATES, attachment_headers, export_report, ordered_sections
from app.models.intel_report import IntelReport
from app.models.report_template import ReportTemplate
from app.models.shared_report import SharedReport
from app.models.user import User

router = APIRouter()

#: A public link contradicts these markings. TLP:RED is "not for disclosure,
#: restricted to participants only"; TLP:AMBER (and AMBER+STRICT) is limited
#: to the recipient's organization. Only CLEAR and GREEN may be shared, and the
#: rule is checked when the link is made and again on every public read, so
#: re-marking a report pauses any link already out there.
_UNSHAREABLE_TLP = frozenset({"TLP:RED", "TLP:AMBER", "TLP:AMBER+STRICT"})


def _tlp_allows_sharing(report: IntelReport) -> bool:
    return report.tlp_marking not in _UNSHAREABLE_TLP


class SharedReportSection(BaseModel):
    name: str
    title: str
    type: str
    body: str
    items: list[dict]


class SharedReportResponse(BaseModel):
    """A report as the public page shows it — no author, no source ids."""

    id: uuid.UUID
    title: str
    template_type: str
    template_name: str
    tlp_marking: str
    status: str
    summary: str | None
    version: int
    tags: list[str]
    body: str
    sections: list[SharedReportSection]
    #: Auto-linker matches over the summary, body and every section body — the
    #: same shape ``POST /autolink/scan`` returns — so the page highlights
    #: entities without a session. Each carries the entity payload its popover shows.
    entities: list[dict]
    created_at: datetime
    updated_at: datetime
    published_at: datetime | None
    shared_at: datetime


def _share_url(share: SharedReport) -> str:
    return f"/shared/report/{share.token}"


def _link(share: SharedReport) -> ShareLinkResponse:
    return ShareLinkResponse(
        token=share.token, url=_share_url(share), created_at=share.created_at, expires_at=share.expires_at
    )


# --- Authenticated: manage a report's share link ---


@router.post("/intel-reports/{report_id}/share", response_model=ShareLinkResponse)
async def create_report_share_link(
    report_id: uuid.UUID = Path(..., description="ID of the report to share"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a public share link for a report, or return the caller's existing active one.
    TLP:AMBER and TLP:RED reports are refused — the marking rules out a public link."""
    report = await db.get(IntelReport, report_id)
    if not report:
        raise AppError(code="not_found", message="Report not found", status_code=404)
    if not _tlp_allows_sharing(report):
        raise AppError(
            code="tlp_restricted",
            message=f"{report.tlp_marking} reports cannot be shared by public link. Only TLP:CLEAR and TLP:GREEN can.",
            status_code=400,
        )

    existing = await db.execute(
        select(SharedReport).where(
            SharedReport.report_id == report_id,
            SharedReport.created_by == user.id,
            SharedReport.is_active.is_(True),
        )
    )
    share = existing.scalar_one_or_none()
    if not share:
        share = SharedReport(report_id=report_id, created_by=user.id)
        db.add(share)
        await db.flush()
    return _link(share)


@router.delete("/intel-reports/{report_id}/share")
async def revoke_report_share_link(
    report_id: uuid.UUID = Path(..., description="ID of the report whose share link to revoke"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Deactivate the caller's active share link for this report so the public URL stops resolving.

    Admins deactivate every active share for the report."""
    query = select(SharedReport).where(SharedReport.report_id == report_id, SharedReport.is_active.is_(True))
    if user.role != "admin":
        query = query.where(SharedReport.created_by == user.id)
    shares = (await db.execute(query)).scalars().all()
    if not shares:
        raise AppError(code="not_found", message="No active share link", status_code=404)
    for share in shares:
        share.is_active = False
    return {"message": "Share link revoked"}


@router.get("/intel-reports/{report_id}/share", response_model=ShareLinkResponse | None)
async def get_report_share_link(
    report_id: uuid.UUID = Path(..., description="ID of the report to look up"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return the caller's active share link for this report, or null if they have not shared it."""
    share = (
        await db.execute(
            select(SharedReport).where(
                SharedReport.report_id == report_id,
                SharedReport.created_by == user.id,
                SharedReport.is_active.is_(True),
            )
        )
    ).scalar_one_or_none()
    return _link(share) if share else None


# --- Public: read a shared report (no auth) ---


async def _resolve_share(token: str, db: AsyncSession) -> tuple[SharedReport, IntelReport]:
    share = (
        await db.execute(select(SharedReport).where(SharedReport.token == token, SharedReport.is_active.is_(True)))
    ).scalar_one_or_none()
    if not share:
        raise AppError(code="not_found", message="Share link not found or expired", status_code=404)
    if share.expires_at and share.expires_at < datetime.now(UTC):
        raise AppError(code="expired", message="Share link has expired", status_code=410)
    report = await db.get(IntelReport, share.report_id)
    if not report:
        raise AppError(code="not_found", message="Report not found", status_code=404)
    if not _tlp_allows_sharing(report):
        raise AppError(
            code="tlp_restricted",
            message=f"This report is marked {report.tlp_marking} and is not available by public link",
            status_code=403,
        )
    return share, report


async def _template_for(report: IntelReport, db: AsyncSession) -> tuple[str, list]:
    """``(display name, section definitions)`` for the report's template."""
    row = (
        await db.execute(select(ReportTemplate).where(ReportTemplate.template_slug == report.template_type))
    ).scalar_one_or_none()
    if row:
        return row.name, list(row.sections or [])
    builtin = REPORT_TEMPLATES.get(report.template_type)
    name = builtin["name"] if builtin else report.template_type.replace("_", " ").title()
    return name, []


@router.get("/shared/report/{token}", response_model=SharedReportResponse)
async def get_shared_report(
    token: str = Path(..., description="Share link token"),
    db: AsyncSession = Depends(get_db),
):
    """Public, unauthenticated view of a shared report: its sections in template
    order, each with its narrative body and data rows. Returns 410 if the link has expired."""
    share, report = await _resolve_share(token, db)
    template_name, template_sections = await _template_for(report, db)
    content = report.content or {}
    body = content.get("body") if isinstance(content.get("body"), str) else ""
    sections = ordered_sections(report, template_sections)
    out = SharedReportResponse(
        id=report.id,
        title=report.title,
        template_type=report.template_type,
        template_name=template_name,
        tlp_marking=report.tlp_marking,
        status=report.status,
        summary=report.summary,
        version=report.version,
        tags=list(report.tags or []),
        body=body,
        sections=[SharedReportSection(**s) for s in sections],
        entities=[],
        created_at=report.created_at,
        updated_at=report.updated_at,
        published_at=report.published_at,
        shared_at=share.created_at,
    )
    # One scan over everything the page renders as markdown: the builder scans
    # per block, but the matches are the same and one pass is cheaper. It runs
    # after the response is built because a cold worker rebuilds the
    # auto-linker vocabulary here, and that leaves the report row expired.
    scannable = "\n\n".join(t for t in [out.summary or "", out.body, *(s.body for s in out.sections)] if t)
    out.entities = await scan_text_matches(db, scannable)
    return out


@router.get("/shared/report/{token}/export")
async def export_shared_report(
    token: str = Path(..., description="Share link token"),
    format: str = Query(
        "markdown",
        pattern=r"^(markdown|html|pdf)$",
        description="Export format. pdf requires WeasyPrint; without it, HTML is returned instead.",
    ),
    db: AsyncSession = Depends(get_db),
):
    """Download the shared report as Markdown, HTML or PDF — the same files the
    report builder exports."""
    _, report = await _resolve_share(token, db)
    content, media_type, filename = export_report(report, format)
    return Response(content=content, media_type=media_type, headers=attachment_headers(filename))


@router.get("/shared/report/{token}/og", response_class=HTMLResponse, include_in_schema=False)
async def get_shared_report_og(
    token: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    """Link-preview page for crawlers (the SPA serves people). Anything that
    stops the report resolving — revoked, expired, re-marked — is a plain 404
    here, which crawlers handle; a person gets the SPA's own message."""
    try:
        _, report = await _resolve_share(token, db)
    except AppError:
        return HTMLResponse(status_code=404, content="<!doctype html><title>Not found</title>")

    template_name, template_sections = await _template_for(report, db)
    first_body = next((s["body"] for s in ordered_sections(report, template_sections) if s["body"]), "")
    description = _truncate(report.summary or first_body, _OG_DESCRIPTION_LIMIT) or template_name
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.hostname or ""
    canonical_url = f"{proto}://{host}/shared/report/{token}"

    e = html.escape
    body = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>{e(report.title)}</title>
<link rel="canonical" href="{e(canonical_url)}" />
<meta name="description" content="{e(description)}" />
<meta property="og:type" content="article" />
<meta property="og:site_name" content="IntelFeed" />
<meta property="og:title" content="{e(report.title)}" />
<meta property="og:description" content="{e(description)}" />
<meta property="og:url" content="{e(canonical_url)}" />
<meta property="article:section" content="{e(template_name)}" />
<meta name="twitter:card" content="summary" />
<meta name="twitter:title" content="{e(report.title)}" />
<meta name="twitter:description" content="{e(description)}" />
</head>
<body>
<h1>{e(report.title)}</h1>
<p>{e(report.tlp_marking)} · {e(template_name)}</p>
<p>{e(description)}</p>
<p><a href="{e(canonical_url)}">Open in IntelFeed</a></p>
</body>
</html>
"""
    return HTMLResponse(content=body, headers={"Cache-Control": "public, max-age=300"})
