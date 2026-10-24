import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Body, Depends, Path, Query
from fastapi.responses import Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppError
from app.core.pagination import PaginatedResponse
from app.core.security import get_current_user
from app.database import get_db
from app.intelligence.reporting import (
    REPORT_TEMPLATES,
    generate_report_content,
    generate_section_content,
    narrative_sections,
    render_html,
    render_markdown,
    resolve_report_sources,
)
from app.models.intel_report import IntelReport, IntelReportVersion
from app.models.report_template import ReportTemplate
from app.models.user import User
from app.schemas.intel_report import (
    IntelReportAttach,
    IntelReportCreate,
    IntelReportExposureGenerate,
    IntelReportFullGenerate,
    IntelReportGenerate,
    IntelReportResponse,
    IntelReportUpdate,
    IntelReportVersionResponse,
)

router = APIRouter()


async def _preflight(db: AsyncSession, user: User, template_type: str, content: dict) -> None:
    """Refuse a report the worker could not finish today, before anything is written.

    ``content`` is the report body as it would be saved (built in memory, no
    write yet); the pre-flight asks for exactly the sections the worker will
    generate from it, so a person with two requests left is refused a
    three-section report now rather than after section two, and a template's
    data sections (IOC tables, references) are not counted against them.
    """
    from app.ai.caller import Caller
    from app.ai.engine import preflight_report

    template = REPORT_TEMPLATES.get(template_type)
    names = list(template["sections"]) if template else None
    sections = max(1, len(narrative_sections(content, names)))
    await preflight_report(db, Caller.user(user.id), template_type, sections=sections)


@router.get("", response_model=PaginatedResponse[IntelReportResponse])
async def list_intel_reports(
    status: str | None = Query(None, description="Filter by report status (draft, published, archived)."),
    template_type: str | None = Query(None, description="Filter by template slug (e.g. flash_alert, actor_profile)."),
    sort_by: str = Query(
        "updated_at",
        pattern="^(title|template_type|tlp_marking|status|version|updated_at|created_at)$",
        description="Column to sort by.",
    ),
    sort_order: str = Query("desc", pattern="^(asc|desc)$", description="Sort direction."),
    limit: int = Query(50, ge=1, le=500, description="Maximum number of reports to return."),
    offset: int = Query(0, ge=0, description="Number of reports to skip for pagination."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List intel reports, filterable by status and template type, sortable and paginated."""
    base = select(IntelReport)
    count_base = select(func.count()).select_from(IntelReport)

    if status:
        base = base.where(IntelReport.status == status)
        count_base = count_base.where(IntelReport.status == status)
    if template_type:
        base = base.where(IntelReport.template_type == template_type)
        count_base = count_base.where(IntelReport.template_type == template_type)

    total = (await db.execute(count_base)).scalar() or 0

    col = getattr(IntelReport, sort_by)
    order = col.asc() if sort_order == "asc" else col.desc()
    query = base.order_by(order).limit(limit).offset(offset)
    result = await db.execute(query)
    reports = result.scalars().all()

    items = [IntelReportResponse.model_validate(r) for r in reports]
    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset, has_more=(offset + limit) < total)


@router.post("", response_model=IntelReportResponse, status_code=201)
async def create_intel_report(
    body: IntelReportCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create an intel report with the given template type, content, and linked entries/entities.
    When no section content is supplied, the template's section scaffolding is built up front —
    data sections (TTPs, references, timeline, observables) fill from the linked entries/entities
    immediately, so a fresh report starts structured instead of empty."""
    report_content = body.content
    if not (report_content or {}).get("sections"):
        entity_ids = body.entity_ids or {}
        if body.entry_ids and not entity_ids:
            from app.intelligence.reporting import collect_entity_ids_for_entries

            entity_ids = await collect_entity_ids_for_entries(db, body.entry_ids)
        generated = await generate_report_content(body.template_type, body.entry_ids, entity_ids, db)
        # Caller-supplied top-level keys (e.g. legacy free-form body) survive.
        report_content = {**generated, **{k: v for k, v in (report_content or {}).items() if k != "sections"}}
        body.entity_ids = entity_ids or body.entity_ids

    report = IntelReport(
        created_by=user.id,
        title=body.title,
        template_type=body.template_type,
        tlp_marking=body.tlp_marking,
        content=report_content,
        summary=body.summary,
        entry_ids=body.entry_ids,
        entity_ids=body.entity_ids,
        tags=body.tags,
    )
    db.add(report)
    await db.flush()
    await db.refresh(report)
    return IntelReportResponse.model_validate(report)


@router.get("/templates")
async def list_report_templates(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all available report templates (builtin + user-created + shared)."""
    result = await db.execute(
        select(ReportTemplate)
        .where(
            (ReportTemplate.is_builtin == True)  # noqa: E712
            | (ReportTemplate.is_shared == True)  # noqa: E712
            | (ReportTemplate.created_by == user.id)
        )
        .order_by(ReportTemplate.is_builtin.desc(), ReportTemplate.name)
    )
    templates = result.scalars().all()

    return {
        "templates": [
            {
                "id": str(t.id),
                "type": t.template_slug,
                "name": t.name,
                "sections": t.sections,
                "description": t.description,
                "is_builtin": t.is_builtin,
                "is_shared": t.is_shared,
                "created_by": str(t.created_by) if t.created_by else None,
            }
            for t in templates
        ]
    }


@router.post("/templates", status_code=201)
async def create_report_template(
    body: dict = Body(
        ...,
        description="Template definition: template_slug (required), plus name, description, sections, is_shared.",
        json_schema_extra={
            "example": {
                "template_slug": "ransomware_brief",
                "name": "Ransomware Brief",
                "description": "Short-form briefing on a ransomware incident",
                "sections": ["summary", "key_findings", "recommended_actions", "references"],
                "is_shared": False,
            }
        },
    ),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a custom report template."""
    slug = body.get("template_slug", "").strip()
    if not slug:
        raise AppError(code="validation", message="template_slug is required", status_code=400)

    # Check slug uniqueness
    existing = await db.execute(select(ReportTemplate).where(ReportTemplate.template_slug == slug))
    if existing.scalar_one_or_none():
        raise AppError(code="duplicate", message=f"Template slug '{slug}' already exists", status_code=409)

    template = ReportTemplate(
        name=body.get("name", slug),
        description=body.get("description"),
        template_slug=slug,
        sections=body.get("sections", []),
        is_shared=body.get("is_shared", False),
        created_by=user.id,
    )
    db.add(template)
    await db.flush()
    await db.refresh(template)

    return {
        "id": str(template.id),
        "type": template.template_slug,
        "name": template.name,
        "sections": template.sections,
        "description": template.description,
        "is_builtin": template.is_builtin,
        "is_shared": template.is_shared,
    }


@router.put("/templates/{template_id}")
async def update_report_template(
    template_id: uuid.UUID = Path(..., description="Report template UUID."),
    body: dict = Body(
        ...,
        description="Fields to update: name, description, sections, is_shared. Only keys present are applied.",
        json_schema_extra={
            "example": {"name": "Ransomware Brief v2", "sections": ["summary", "key_findings", "iocs", "references"]}
        },
    ),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update a custom template. Builtin templates cannot be modified."""
    template = await db.get(ReportTemplate, template_id)
    if not template:
        raise AppError(code="not_found", message="Template not found", status_code=404)
    if template.is_builtin:
        raise AppError(code="forbidden", message="Builtin templates cannot be modified", status_code=403)
    if user.role != "admin" and template.created_by != user.id:
        raise AppError(code="forbidden", message="Only the template's owner or an admin can modify it", status_code=403)

    for field in ["name", "description", "sections", "is_shared"]:
        if field in body:
            setattr(template, field, body[field])

    await db.flush()
    await db.refresh(template)

    return {
        "id": str(template.id),
        "type": template.template_slug,
        "name": template.name,
        "sections": template.sections,
        "description": template.description,
        "is_builtin": template.is_builtin,
        "is_shared": template.is_shared,
    }


@router.delete("/templates/{template_id}", status_code=204)
async def delete_report_template(
    template_id: uuid.UUID = Path(..., description="Report template UUID."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete a custom template. Builtin templates cannot be deleted."""
    template = await db.get(ReportTemplate, template_id)
    if not template:
        raise AppError(code="not_found", message="Template not found", status_code=404)
    if template.is_builtin:
        raise AppError(code="forbidden", message="Builtin templates cannot be deleted", status_code=403)
    if user.role != "admin" and template.created_by != user.id:
        raise AppError(code="forbidden", message="Only the template's owner or an admin can delete it", status_code=403)

    await db.delete(template)
    await db.flush()


@router.post("/templates/{template_id}/clone", status_code=201)
async def clone_report_template(
    template_id: uuid.UUID = Path(..., description="Report template UUID."),
    body: dict | None = Body(
        None,
        description="Optional overrides for the clone: template_slug and name. Defaults derive from the source.",
        json_schema_extra={"example": {"template_slug": "flash_alert_custom", "name": "Flash Alert (Team Copy)"}},
    ),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Clone a template (builtin or shared) as a new custom template."""
    source = await db.get(ReportTemplate, template_id)
    if not source:
        raise AppError(code="not_found", message="Template not found", status_code=404)

    body = body or {}
    new_slug = body.get("template_slug", f"{source.template_slug}_custom")

    # Ensure unique slug
    existing = await db.execute(select(ReportTemplate).where(ReportTemplate.template_slug == new_slug))
    if existing.scalar_one_or_none():
        import time

        new_slug = f"{new_slug}_{int(time.time())}"

    clone = ReportTemplate(
        name=body.get("name", f"{source.name} (Copy)"),
        description=source.description,
        template_slug=new_slug,
        sections=list(source.sections),
        is_shared=False,
        created_by=user.id,
    )
    db.add(clone)
    await db.flush()
    await db.refresh(clone)

    return {
        "id": str(clone.id),
        "type": clone.template_slug,
        "name": clone.name,
        "sections": clone.sections,
        "description": clone.description,
        "is_builtin": clone.is_builtin,
        "is_shared": clone.is_shared,
    }


@router.post("/generate", response_model=IntelReportResponse, status_code=201)
async def generate_intel_report(
    body: IntelReportGenerate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate a new report pre-filled from a template and linked entities."""
    # Check builtin templates first, then DB templates
    if body.template_type not in REPORT_TEMPLATES:
        db_tmpl = await db.execute(select(ReportTemplate).where(ReportTemplate.template_slug == body.template_type))
        if not db_tmpl.scalar_one_or_none():
            raise AppError(
                code="invalid_template",
                message=f"Unknown template type: {body.template_type}",
                status_code=400,
            )

    content = await generate_report_content(
        template_type=body.template_type,
        entry_ids=body.entry_ids,
        entity_ids=body.entity_ids,
        db=db,
    )

    template = REPORT_TEMPLATES[body.template_type]
    title = body.title or f"{template['name']} - {datetime.now(UTC).strftime('%Y-%m-%d %H:%M')}"

    report = IntelReport(
        created_by=user.id,
        title=title,
        template_type=body.template_type,
        content=content,
        entry_ids=body.entry_ids,
        entity_ids=body.entity_ids,
    )
    db.add(report)
    await db.flush()
    await db.refresh(report)
    return IntelReportResponse.model_validate(report)


@router.post("/generate-full", status_code=201)
async def generate_full_intel_report(
    body: IntelReportFullGenerate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate a full AI-powered report from source material.

    Resolves sources, pre-fills data sections, creates the report,
    then dispatches a Celery task to generate all narrative sections via AI.
    """
    # 1. Resolve sources
    entry_ids, entity_ids = await resolve_report_sources(
        db=db,
        source_type=body.source_type,
        entry_id=body.entry_id,
        entry_ids=body.entry_ids,
        search_query=body.search_query,
        saved_search_id=body.saved_search_id,
        user_id=user.id,
        search_limit=body.search_limit,
    )

    if not entry_ids:
        raise AppError(
            code="no_sources",
            message="No entries found for the given source criteria",
            status_code=400,
        )

    # 2. Validate template
    template = REPORT_TEMPLATES.get(body.template_type)
    if not template:
        db_tmpl = await db.execute(select(ReportTemplate).where(ReportTemplate.template_slug == body.template_type))
        if not db_tmpl.scalar_one_or_none():
            raise AppError(
                code="invalid_template",
                message=f"Unknown template type: {body.template_type}",
                status_code=400,
            )
        template = REPORT_TEMPLATES.get(body.template_type, {"name": body.template_type.replace("_", " ").title()})

    # 3. Pre-fill data sections (in memory: nothing is written yet)
    content = await generate_report_content(
        template_type=body.template_type,
        entry_ids=entry_ids,
        entity_ids=entity_ids,
        db=db,
    )

    # 4. Refuse now what the worker would refuse later — before the row is
    # written, so a refusal leaves no blank report behind.
    await _preflight(db, user, body.template_type, content)

    # 5. Store focus/audience in metadata for Celery task
    if body.focus:
        content["metadata"]["focus"] = body.focus
    if body.audience:
        content["metadata"]["audience"] = body.audience

    title = body.title or f"{template.get('name', body.template_type)} - {datetime.now(UTC).strftime('%Y-%m-%d %H:%M')}"

    # 6. Create report
    report = IntelReport(
        created_by=user.id,
        title=title,
        template_type=body.template_type,
        tlp_marking=body.tlp_marking,
        content=content,
        entry_ids=entry_ids,
        entity_ids=entity_ids,
        tags=body.tags,
    )
    db.add(report)
    await db.flush()
    await db.refresh(report)

    # 7. Dispatch Celery task
    from app.workers.report_tasks import generate_full_report

    task = generate_full_report.delay(str(report.id), str(user.id))

    return {
        "report": IntelReportResponse.model_validate(report),
        "task_id": task.id,
    }


@router.post("/{report_id}/sections/{section_name}/generate")
async def generate_report_section(
    report_id: uuid.UUID = Path(..., description="Intel report UUID."),
    section_name: str = Path(
        ..., description="Template section slug to generate (e.g. executive_summary, key_findings)."
    ),
    focus: str | None = Query(default=None, max_length=1000, description="Optional guidance to steer the AI prose."),
    audience: str | None = Query(
        default=None, max_length=500, description="Optional intended audience (e.g. 'CISO', 'SOC analysts')."
    ),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate AI prose for a specific section of an existing report."""
    report = await db.get(IntelReport, report_id)
    if not report:
        raise AppError(code="not_found", message="Report not found", status_code=404)

    from app.ai.caller import Caller

    result = await generate_section_content(
        db=db,
        user_id=user.id,
        report=report,
        section_name=section_name,
        focus=focus,
        audience=audience,
        caller=Caller.user(user.id),
    )

    if result.get("refused"):
        # The allowance or key-policy refusal, with the code and reason the
        # UI keys its "Add a key" / "Raise my cap" links on.
        raise AppError(
            code=result["code"], message=result["error"], status_code=result["status_code"], details=result["details"]
        )
    if "error" in result:
        raise AppError(code="ai_error", message=result["error"], status_code=422)

    return {"section_name": section_name, "content": result["content"]}


@router.post("/{report_id}/regenerate")
async def regenerate_all_sections(
    report_id: uuid.UUID = Path(..., description="Intel report UUID."),
    focus: str | None = Query(default=None, max_length=1000, description="Optional guidance to steer the AI prose."),
    audience: str | None = Query(
        default=None, max_length=500, description="Optional intended audience (e.g. 'CISO', 'SOC analysts')."
    ),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Re-dispatch Celery task to regenerate all narrative sections for an existing report."""
    report = await db.get(IntelReport, report_id)
    if not report:
        raise AppError(code="not_found", message="Report not found", status_code=404)

    # Rebuild content from scratch: re-populates data sections (references, TTPs)
    # from current saved entry_ids and entity_ids, clears narrative sections for AI regeneration
    content = await generate_report_content(
        template_type=report.template_type,
        entry_ids=report.entry_ids,
        entity_ids=report.entity_ids or {},
        db=db,
    )

    # Preserve focus/audience metadata
    old_metadata = (report.content or {}).get("metadata", {})
    if focus is not None:
        old_metadata["focus"] = focus
    if audience is not None:
        old_metadata["audience"] = audience
    content["metadata"] = old_metadata

    # Refuse now what the worker would refuse later — before the sections
    # are cleared, so a refusal leaves the report as it was.
    await _preflight(db, user, report.template_type, content)

    from sqlalchemy.orm.attributes import flag_modified

    report.content = content
    flag_modified(report, "content")
    await db.commit()

    from app.workers.report_tasks import generate_full_report

    task = generate_full_report.delay(str(report.id), str(user.id))
    return {"report_id": str(report.id), "task_id": task.id}


@router.post("/generate-from-campaign", status_code=201)
async def generate_report_from_campaign(
    body: dict = Body(
        ...,
        description="campaign_id (required) plus optional template_type, title, tlp_marking, focus, audience.",
        json_schema_extra={
            "example": {
                "campaign_id": "d5b2f1c8-3a4e-4b6d-9c2f-8e7a1b3c5d4e",
                "template_type": "campaign_tracker",
                "focus": "LockBit affiliate activity against healthcare",
                "audience": "SOC analysts",
            }
        },
    ),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate a full AI-powered report from a campaign's entries and entities.

    Pulls all entry_ids from campaign_entries and entity_ids from campaign_entities,
    then creates a report and dispatches AI generation.
    """
    campaign_id = body.get("campaign_id")
    if not campaign_id:
        raise AppError(code="validation", message="campaign_id is required", status_code=400)

    try:
        campaign_uuid = uuid.UUID(campaign_id)
    except (ValueError, TypeError):
        raise AppError(code="validation", message="Invalid campaign_id", status_code=400)

    from app.models.campaign import Campaign, CampaignEntity, CampaignEntry

    campaign = await db.get(Campaign, campaign_uuid)
    if not campaign:
        raise AppError(code="not_found", message="Campaign not found", status_code=404)

    template_type = body.get("template_type", "campaign_tracker").strip()

    # Validate template
    if template_type not in REPORT_TEMPLATES:
        db_tmpl = await db.execute(select(ReportTemplate).where(ReportTemplate.template_slug == template_type))
        if not db_tmpl.scalar_one_or_none():
            raise AppError(
                code="invalid_template",
                message=f"Unknown template type: {template_type}",
                status_code=400,
            )

    # Collect entry_ids from campaign
    entry_rows = await db.execute(select(CampaignEntry.entry_id).where(CampaignEntry.campaign_id == campaign_uuid))
    entry_ids = [row[0] for row in entry_rows.all()]

    if not entry_ids:
        raise AppError(
            code="no_sources",
            message="Campaign has no entries to generate a report from",
            status_code=400,
        )

    # Collect entity_ids grouped by type from campaign_entities
    entity_rows = await db.execute(
        select(CampaignEntity.entity_type, CampaignEntity.entity_id).where(CampaignEntity.campaign_id == campaign_uuid)
    )
    entity_ids: dict[str, list[str]] = {}
    # Map entity_type to the plural key used by reports
    type_key_map = {
        "ttp": "ttps",
        "cve": "cves",
        "threat_actor": "actors",
        "malware": "malware",
        "observable": "observables",
    }
    for row in entity_rows.all():
        key = type_key_map.get(row[0], row[0])
        entity_ids.setdefault(key, []).append(str(row[1]))

    # Also collect entities from entry junction tables (same as resolve_report_sources)
    from app.models.cve import EntryCVE
    from app.models.malware_family import EntryMalware
    from app.models.observable import EntryObservable
    from app.models.threat_actor import EntryThreatActor
    from app.models.ttp import EntryTTP

    for Model, key in [
        (EntryTTP, "ttps"),
        (EntryCVE, "cves"),
        (EntryThreatActor, "actors"),
        (EntryMalware, "malware"),
        (EntryObservable, "observables"),
    ]:
        eid_col = (
            getattr(Model, "ttp_id", None)
            or getattr(Model, "cve_id", None)
            or getattr(Model, "threat_actor_id", None)
            or getattr(Model, "malware_family_id", None)
            or getattr(Model, "observable_id", None)
        )
        if eid_col is not None:
            rows = await db.execute(select(eid_col).where(Model.entry_id.in_(entry_ids)).distinct())
            for r in rows.all():
                eid_str = str(r[0])
                if eid_str not in entity_ids.get(key, []):
                    entity_ids.setdefault(key, []).append(eid_str)

    # Generate content structure (in memory: nothing is written yet)
    content = await generate_report_content(
        template_type=template_type,
        entry_ids=entry_ids,
        entity_ids=entity_ids,
        db=db,
    )

    # Refuse now what the worker would refuse later — before the row is
    # written, so a refusal leaves no blank report behind.
    await _preflight(db, user, template_type, content)

    # Set focus/audience from request
    focus = body.get("focus")
    audience = body.get("audience")
    if focus:
        content["metadata"]["focus"] = focus
    if audience:
        content["metadata"]["audience"] = audience

    template = REPORT_TEMPLATES.get(template_type, {"name": template_type.replace("_", " ").title()})
    title = body.get("title") or f"{template.get('name', template_type)} - {campaign.name}"

    report = IntelReport(
        created_by=user.id,
        title=title,
        template_type=template_type,
        tlp_marking=body.get("tlp_marking", campaign.tlp_marking),
        content=content,
        summary=campaign.description,
        entry_ids=entry_ids,
        entity_ids=entity_ids,
        tags=list(campaign.tags or []),
    )
    db.add(report)
    await db.flush()
    await db.refresh(report)

    # Dispatch AI generation
    from app.workers.report_tasks import generate_full_report

    task = generate_full_report.delay(str(report.id), str(user.id))

    return {
        "report": IntelReportResponse.model_validate(report),
        "task_id": task.id,
    }


@router.post("/{report_id}/clone", status_code=201)
async def clone_report_as_type(
    report_id: uuid.UUID = Path(..., description="Intel report UUID."),
    body: dict = Body(
        ...,
        description="template_type (required), optional title, and generate (default true) to run AI generation.",
        json_schema_extra={"example": {"template_type": "actor_profile", "title": "APT29 Profile", "generate": True}},
    ),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Clone a report with a different template type, preserving linked entries/entities/tags/TLP.

    Optionally dispatches AI generation for the new report's narrative sections.
    """
    source = await db.get(IntelReport, report_id)
    if not source:
        raise AppError(code="not_found", message="Report not found", status_code=404)

    new_template_type = body.get("template_type", "").strip()
    if not new_template_type:
        raise AppError(code="validation", message="template_type is required", status_code=400)

    # Validate template exists
    if new_template_type not in REPORT_TEMPLATES:
        db_tmpl = await db.execute(select(ReportTemplate).where(ReportTemplate.template_slug == new_template_type))
        if not db_tmpl.scalar_one_or_none():
            raise AppError(
                code="invalid_template",
                message=f"Unknown template type: {new_template_type}",
                status_code=400,
            )

    generate = bool(body.get("generate", True))

    # Generate content structure for new template with same entries/entities
    content = await generate_report_content(
        template_type=new_template_type,
        entry_ids=source.entry_ids or [],
        entity_ids=source.entity_ids or {},
        db=db,
    )
    if generate:
        # Refuse now what the worker would refuse later — before the row is
        # written, so a refusal leaves no blank report behind.
        await _preflight(db, user, new_template_type, content)

    # Preserve focus/audience from source
    source_metadata = (source.content or {}).get("metadata", {})
    if source_metadata.get("focus"):
        content["metadata"]["focus"] = source_metadata["focus"]
    if source_metadata.get("audience"):
        content["metadata"]["audience"] = source_metadata["audience"]

    template = REPORT_TEMPLATES.get(new_template_type, {"name": new_template_type.replace("_", " ").title()})
    new_title = body.get("title") or f"{source.title} ({template.get('name', new_template_type)})"

    report = IntelReport(
        created_by=user.id,
        title=new_title,
        template_type=new_template_type,
        tlp_marking=source.tlp_marking,
        content=content,
        summary=source.summary,
        entry_ids=list(source.entry_ids or []),
        entity_ids=dict(source.entity_ids or {}),
        tags=list(source.tags or []),
    )
    db.add(report)
    await db.flush()
    await db.refresh(report)

    # Optionally dispatch AI generation
    task_id = None
    if generate:
        from app.workers.report_tasks import generate_full_report

        task = generate_full_report.delay(str(report.id), str(user.id))
        task_id = task.id

    return {
        "report": IntelReportResponse.model_validate(report),
        "task_id": task_id,
    }


@router.get("/{report_id}/versions", response_model=list[IntelReportVersionResponse])
async def list_report_versions(
    report_id: uuid.UUID = Path(..., description="Intel report UUID."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List version history for a report."""
    report = await db.get(IntelReport, report_id)
    if not report:
        raise AppError(code="not_found", message="Report not found", status_code=404)

    result = await db.execute(
        select(IntelReportVersion)
        .where(IntelReportVersion.report_id == report_id)
        .order_by(IntelReportVersion.version.desc())
    )
    versions = result.scalars().all()
    return [IntelReportVersionResponse.model_validate(v) for v in versions]


@router.get("/{report_id}/export")
async def export_intel_report(
    report_id: uuid.UUID = Path(..., description="Intel report UUID."),
    format: str = Query(
        "markdown",
        pattern=r"^(markdown|html|pdf)$",
        description="Export format. pdf requires WeasyPrint; without it, HTML is returned instead.",
    ),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Export a report in the specified format."""
    report = await db.get(IntelReport, report_id)
    if not report:
        raise AppError(code="not_found", message="Report not found", status_code=404)

    safe_title = report.title[:50].replace("/", "-").replace("\\", "-")

    if format == "markdown":
        content = render_markdown(report)
        return Response(
            content=content,
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{safe_title}.md"'},
        )

    elif format == "html":
        content = render_html(report)
        return Response(
            content=content,
            media_type="text/html; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{safe_title}.html"'},
        )

    elif format == "pdf":
        # Try WeasyPrint if available; fall back to HTML with a note
        try:
            import weasyprint

            html_content = render_html(report)
            # WeasyPrint's default fetcher follows any URL in the document,
            # file:// included, and a <link rel="attachment"> embeds whatever
            # it fetched in the PDF. render_html sanitizes the body, and this
            # is the second wall: nothing but inline data: URIs is loaded.
            fetcher = weasyprint.URLFetcher(allowed_protocols={"data"})
            pdf_bytes = weasyprint.HTML(string=html_content, url_fetcher=fetcher).write_pdf()
            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={"Content-Disposition": f'attachment; filename="{safe_title}.pdf"'},
            )
        except ImportError:
            # WeasyPrint not installed — return HTML with a note
            html_content = render_html(report)
            note = "<!-- PDF export requires WeasyPrint. Install with: pip install weasyprint -->\n"
            return Response(
                content=note + html_content,
                media_type="text/html; charset=utf-8",
                headers={"Content-Disposition": f'attachment; filename="{safe_title}.html"'},
            )

    raise AppError(code="invalid_format", message=f"Unsupported export format: {format}", status_code=400)


@router.post("/{report_id}/publish", response_model=IntelReportResponse)
async def publish_intel_report(
    report_id: uuid.UUID = Path(..., description="Intel report UUID."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Publish a report, incrementing its version."""
    report = await db.get(IntelReport, report_id)
    if not report:
        raise AppError(code="not_found", message="Report not found", status_code=404)
    if report.status == "published":
        raise AppError(code="already_published", message="Report is already published", status_code=400)

    # Save current content as a version
    version = IntelReportVersion(
        report_id=report.id,
        version=report.version,
        content=report.content,
        change_description="Published",
        created_by=user.id,
    )
    db.add(version)
    report.version += 1
    report.status = "published"
    report.published_at = datetime.now(UTC)

    db.add(report)
    await db.flush()
    await db.refresh(report)
    return IntelReportResponse.model_validate(report)


@router.post("/{report_id}/archive", response_model=IntelReportResponse)
async def archive_intel_report(
    report_id: uuid.UUID = Path(..., description="Intel report UUID."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Archive a report."""
    report = await db.get(IntelReport, report_id)
    if not report:
        raise AppError(code="not_found", message="Report not found", status_code=404)
    if report.status == "archived":
        raise AppError(code="already_archived", message="Report is already archived", status_code=400)

    report.status = "archived"
    db.add(report)
    await db.flush()
    await db.refresh(report)
    return IntelReportResponse.model_validate(report)


@router.get("/{report_id}", response_model=IntelReportResponse)
async def get_intel_report(
    report_id: uuid.UUID = Path(..., description="Intel report UUID."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get a single intel report."""
    report = await db.get(IntelReport, report_id)
    if not report:
        raise AppError(code="not_found", message="Report not found", status_code=404)
    return IntelReportResponse.model_validate(report)


@router.put("/{report_id}", response_model=IntelReportResponse)
async def update_intel_report(
    report_id: uuid.UUID = Path(..., description="Intel report UUID."),
    body: IntelReportUpdate = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update report fields (non-null fields only). Changing content snapshots the previous content as a
    version and increments the version number; setting status to published stamps published_at."""
    report = await db.get(IntelReport, report_id)
    if not report:
        raise AppError(code="not_found", message="Report not found", status_code=404)
    # Save version before updating content
    if body.content is not None and body.content != report.content:
        version = IntelReportVersion(
            report_id=report.id,
            version=report.version,
            content=report.content,
            change_description=body.change_description,
            created_by=user.id,
        )
        db.add(version)
        report.version += 1

    if body.status == "published" and report.status != "published":
        from sqlalchemy import func as sa_func

        report.published_at = sa_func.now()

    for field in ["title", "tlp_marking", "status", "content", "summary", "entry_ids", "entity_ids", "tags"]:
        value = getattr(body, field, None)
        if value is not None:
            setattr(report, field, value)

    db.add(report)
    await db.flush()
    await db.refresh(report)
    return IntelReportResponse.model_validate(report)


@router.delete("/{report_id}", status_code=204)
async def delete_intel_report(
    report_id: uuid.UUID = Path(..., description="Intel report UUID."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete a draft report. Published or archived reports cannot be deleted (400)."""
    report = await db.get(IntelReport, report_id)
    if not report:
        raise AppError(code="not_found", message="Report not found", status_code=404)
    if report.status != "draft":
        raise AppError(code="invalid_status", message="Only draft reports can be deleted", status_code=400)
    if user.role != "admin" and report.created_by is not None and report.created_by != user.id:
        raise AppError(code="forbidden", message="Only the report's author or an admin can delete it", status_code=403)
    await db.delete(report)
    await db.flush()


@router.post("/generate-exposure", response_model=IntelReportResponse, status_code=201)
async def generate_exposure_report(
    body: IntelReportExposureGenerate = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Build a Threat Exposure Report from a saved intel profile and the
    analyst's keep/drop curation of its matched threat surface. Backing
    entries are the in-window articles linking a kept entity AND the scope;
    the keep/drop decisions are remembered on the profile for the next issue."""
    from app.intelligence.reporting import collect_entity_ids_for_entries
    from app.intelligence.sectors import sector_label
    from app.intelligence.threat_surface import build_threat_surface, collect_exposure_entries
    from app.models.intel_profile import IntelProfile

    profile = await db.get(IntelProfile, body.profile_id)
    if not profile:
        raise AppError(code="not_found", message="Intel profile not found", status_code=404)

    country_ids = list(profile.country_ids or [])
    sectors = list(profile.sectors or [])

    surface = await build_threat_surface(
        db, country_ids=country_ids, sectors=sectors, window_days=profile.window_days, limit=100
    )
    kept_actor_ids = {str(i) for i in body.actor_ids}
    kept_malware_ids = {str(i) for i in body.malware_ids}
    surface_items = [i for i in surface["actors"] if i["id"] in kept_actor_ids] + [
        i for i in surface["malware"] if i["id"] in kept_malware_ids
    ]
    surface_items.sort(key=lambda i: -i["score"])

    entry_ids = await collect_exposure_entries(
        db,
        actor_ids=list(body.actor_ids),
        malware_ids=list(body.malware_ids),
        country_ids=country_ids,
        sectors=sectors,
        window_days=profile.window_days,
    )
    entity_ids = await collect_entity_ids_for_entries(db, entry_ids)
    # Kept entities always ride along, even when no in-scope entry links them
    # (a claims-only match still belongs in the report).
    for key, kept in (("actors", kept_actor_ids), ("malware", kept_malware_ids)):
        merged = list(dict.fromkeys((entity_ids.get(key) or []) + sorted(kept)))
        if merged:
            entity_ids[key] = merged

    content = await generate_report_content("exposure_report", entry_ids, entity_ids, db)

    country_names = [c["name"] for c in (await _profile_countries(db, country_ids))]
    scope_line = (
        f"Regions: {', '.join(country_names) or '—'} · "
        f"Verticals: {', '.join(sector_label(s) for s in sectors) or '—'} · "
        f"Window: last {profile.window_days} days"
    )
    if "scope" in content["sections"]:
        content["sections"]["scope"]["body"] = scope_line
    if "threat_surface" in content["sections"]:
        content["sections"]["threat_surface"]["title"] = "Threat Surface"
        content["sections"]["threat_surface"]["items"] = surface_items
    content["metadata"]["profile_id"] = str(profile.id)
    content["metadata"]["profile_name"] = profile.name
    content["metadata"]["scope"] = {
        "countries": country_names,
        "sectors": sectors,
        "window_days": profile.window_days,
    }

    report = IntelReport(
        title=body.title or f"Threat exposure: {profile.name}",
        template_type="exposure_report",
        tlp_marking=body.tlp_marking,
        status="draft",
        content=content,
        entry_ids=entry_ids,
        entity_ids=entity_ids,
        tags=body.tags,
        created_by=user.id,
    )
    db.add(report)

    profile.curation = {
        "kept": {"actors": sorted(kept_actor_ids), "malware": sorted(kept_malware_ids)},
        "dropped": {
            "actors": sorted(str(i) for i in body.dropped_actor_ids),
            "malware": sorted(str(i) for i in body.dropped_malware_ids),
        },
    }
    db.add(profile)

    await db.flush()
    await db.refresh(report)
    return IntelReportResponse.model_validate(report)


async def _profile_countries(db: AsyncSession, country_ids: list) -> list[dict]:
    if not country_ids:
        return []
    from app.models.country import Country

    rows = await db.execute(select(Country.id, Country.name).where(Country.id.in_(country_ids)))
    return [{"id": str(cid), "name": name} for cid, name in rows.all()]


@router.post("/{report_id}/attach", response_model=IntelReportResponse)
async def attach_to_intel_report(
    report_id: uuid.UUID = Path(..., description="Intel report UUID."),
    body: IntelReportAttach = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Append entries and entities to a draft report (the send-to-report
    gesture). Merges and dedups; published/archived reports reject."""
    report = await db.get(IntelReport, report_id)
    if not report:
        raise AppError(code="not_found", message="Report not found", status_code=404)
    if report.status != "draft":
        raise AppError(code="invalid_status", message="Only draft reports accept new evidence", status_code=400)

    merged_entries = list(dict.fromkeys([*(report.entry_ids or []), *body.entry_ids]))
    merged_entities = dict(report.entity_ids or {})
    for key, ids in (body.entity_ids or {}).items():
        if not isinstance(ids, list):
            continue
        merged_entities[key] = list(dict.fromkeys([*(merged_entities.get(key) or []), *[str(i) for i in ids]]))

    report.entry_ids = merged_entries
    report.entity_ids = merged_entities

    # Refresh data sections (items-bearing: TTPs, references, timeline,
    # observables) from the merged evidence; analyst-written narrative bodies
    # are never touched.
    regenerated = await generate_report_content(report.template_type, merged_entries, merged_entities, db)
    content = dict(report.content or {})
    sections = dict(content.get("sections") or {})
    for key, fresh in regenerated.get("sections", {}).items():
        old = sections.get(key)
        if not isinstance(old, dict):
            sections[key] = fresh
        elif fresh.get("items") is not None:
            sections[key] = {**old, "items": fresh["items"], "body": old.get("body") or fresh.get("body", "")}

    # The sender's commentary seeds the detections body — a coverage set's
    # skipped rules read as known gaps, and a gap is worth as much to the reader
    # as a rule. Only ever fills an empty body: an analyst who has written there
    # outranks whatever the sending surface wanted to say.
    if body.note and isinstance(sections.get("detections"), dict) and not sections["detections"].get("body"):
        sections["detections"] = {**sections["detections"], "body": body.note}

    content["sections"] = sections
    report.content = content
    db.add(report)
    await db.flush()
    await db.refresh(report)
    return IntelReportResponse.model_validate(report)
