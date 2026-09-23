"""Coverage Workspace — the authoring lane behind the profile's Detection tab.

Its own router rather than another block in api/intelligence.py (4,632 lines).
Everything here is a read over stored rows: no AI call sits on any of these
paths, because `GET /detection-rules/{id}` already measures ~5s on this box and
the summary generator 503s under load.
"""

import uuid
from dataclasses import asdict

from fastapi import APIRouter, Body, Depends, Path, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppError
from app.core.security import get_current_user
from app.database import get_db
from app.models.detection_summary import DetectionSummary
from app.models.user import User
from app.schemas.coverage_workspace import (
    CoverageWorkspaceResponse,
    PriorRuleItem,
    PriorRulesResponse,
    SavedSet,
    SavedSetList,
    SetExportResponse,
    SetSaveRequest,
    WorkspaceArticle,
    WorkspaceBehaviour,
    WorkspaceChannel,
    WorkspaceQuote,
)
from app.services.coverage_workspace import (
    ENTITY_SOURCES,
    WORKSPACE_WINDOW_HOURS,
    build_set_bundle,
    build_workspace,
    get_prior_rules,
    list_sets,
    render_set_markdown,
    resolve_entity,
    save_set,
)

router = APIRouter()

# Export formats the UI offers today. The endpoint hands back the assembled set
# with its provenance intact; writing the bytes is the export layer's job, and
# no new format is introduced here.
EXPORT_FORMATS = ("bundle", "markdown", "intel_report")


def _require_supported(entity_type: str) -> None:
    if entity_type not in ENTITY_SOURCES:
        raise AppError(
            code="bad_request",
            message=f"Coverage workspace supports {', '.join(sorted(ENTITY_SOURCES))}",
            status_code=400,
        )


@router.get("/{entity_type}/{entity_key}", response_model=CoverageWorkspaceResponse)
async def get_coverage_workspace(
    entity_type: str = Path(..., description="threat_actor, malware, cve or ttp"),
    entity_key: str = Path(..., description="Entity UUID, CVE id or ATT&CK technique id"),
    window: str = Query(
        "14d",
        pattern="^(7d|14d|30d|90d|all)$",
        description="Recency window; 'all' drops the lower bound",
    ),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Articles and behaviours for one threat over the window.

    Behaviours carry the quote they were extracted from and the ATT&CK channels
    they need, classified against the enabled telemetry. A behaviour whose
    channels match nothing is flagged `below_line` — a rule for it could not
    fire, so it is a sourcing item and never counted as a detection gap.
    """
    _require_supported(entity_type)
    workspace = await build_workspace(db, entity_type, entity_key, window=window)
    if workspace is None:
        raise AppError(code="not_found", message="Entity not found", status_code=404)

    return CoverageWorkspaceResponse(
        entity_type=workspace.entity_type,
        entity_key=workspace.entity_key,
        label=workspace.label,
        window=workspace.window,
        articles=[WorkspaceArticle(**asdict(a)) for a in workspace.articles],
        article_total=workspace.article_total,
        article_contributed_total=workspace.article_contributed_total,
        behaviours=[
            WorkspaceBehaviour(
                technique_id=b.technique_id,
                technique_name=b.technique_name,
                tactic=b.tactic,
                entry_count=b.entry_count,
                first_seen=b.first_seen,
                is_new=b.is_new,
                quotes=[WorkspaceQuote(**asdict(q)) for q in b.quotes],
                channels=[WorkspaceChannel(source=src, tier=tier) for src, tier in b.channels],
                tier=b.tier,
                missing_channels=b.missing_channels,
                missing_categories=b.missing_categories,
                below_line=b.below_line,
                prior_rules=b.prior_rules,
                prior_rules_strong=b.prior_rules_strong,
            )
            for b in workspace.behaviours
        ],
        missing_categories=workspace.missing_categories,
        below_line_count=sum(1 for b in workspace.behaviours if b.below_line),
        threat_prior_rules=workspace.threat_prior_rules,
        threat_prior_rules_strong=workspace.threat_prior_rules_strong,
        cve=workspace.cve,
    )


@router.get("/{entity_type}/{entity_key}/behaviours/{technique_id}/rules", response_model=PriorRulesResponse)
async def get_behaviour_prior_rules(
    entity_type: str = Path(..., description="threat_actor, malware, cve or ttp"),
    entity_key: str = Path(..., description="Entity UUID, CVE id or ATT&CK technique id"),
    technique_id: str = Path(..., description="ATT&CK technique id, e.g. T1078.004"),
    limit: int = Query(40, ge=1, le=200, description="Maximum candidates returned"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Library rules that already resolve to this behaviour or to the threat.

    Ordered by telemetry tier, so the rules that can fire against the current
    inventory come first. Each row carries `via`, `confidence` and `matched_on`:
    a `low` row matched body text or a Splunk story tag and is a weaker claim
    than a rule that names the threat outright.
    """
    _require_supported(entity_type)
    found = await get_prior_rules(db, entity_type, entity_key, technique_id.upper(), limit=limit)
    return PriorRulesResponse(
        technique_id=technique_id.upper(),
        items=[PriorRuleItem(**asdict(r)) for r in found.items],
        total=len(found.items),
        total_candidates=found.total_candidates,
        strong=found.strong,
        weak=found.weak,
        technique_scope=found.technique_scope,
        threat_scope=found.threat_scope,
    )


def _saved(summary, upstream_moved: list[str] | None = None) -> SavedSet:
    content = summary.summary_content or {}
    return SavedSet(
        id=summary.id,
        title=summary.title,
        created_at=summary.created_at,
        updated_at=summary.updated_at,
        entry_ids=list(summary.entry_ids or []),
        item_count=len(content.get("items", [])),
        content=content,
        upstream_moved=upstream_moved or [],
    )


async def _upstream_moved(db: AsyncSession, summaries) -> dict[uuid.UUID, list[str]]:
    """Per set: adopted/extended rules whose upstream commit postdates the save.

    Detectable since repo sync started writing upstream_updated_at; surfaced
    nowhere until now. A moved upstream is a re-read, not an alarm — the badge
    says "the community changed a rule you adopted".
    """
    from sqlalchemy import text as sa_text

    wanted: dict[uuid.UUID, list[str]] = {}
    all_ids: set[str] = set()
    for s in summaries:
        ids = [
            i["rule_id"]
            for i in (s.summary_content or {}).get("items", [])
            if i.get("rule_id") and i.get("op") in ("adopt", "extend")
        ]
        wanted[s.id] = ids
        all_ids.update(ids)
    if not all_ids:
        return {}

    rows = (
        await db.execute(
            sa_text(
                "SELECT id, upstream_updated_at FROM detection_rules "
                "WHERE id = ANY(:ids) AND upstream_updated_at IS NOT NULL"
            ),
            {"ids": list(all_ids)},
        )
    ).all()
    moved_at = {str(r.id): r.upstream_updated_at for r in rows}
    return {
        sid: [
            rid
            for rid in ids
            if rid in moved_at and moved_at[rid] > next(s.updated_at for s in summaries if s.id == sid)
        ]
        for sid, ids in wanted.items()
    }


@router.get("/{entity_type}/{entity_key}/sets", response_model=SavedSetList)
async def get_saved_sets(
    entity_type: str = Path(..., description="threat_actor, malware, cve or ttp"),
    entity_key: str = Path(..., description="Entity UUID, CVE id or ATT&CK technique id"),
    limit: int = Query(20, ge=1, le=100, description="Maximum sets returned"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Sets already assembled for this threat, newest first."""
    _require_supported(entity_type)
    resolved = await resolve_entity(db, entity_type, entity_key)
    if resolved is None:
        raise AppError(code="not_found", message="Entity not found", status_code=404)
    summaries = await list_sets(db, user.id, entity_type, resolved.coverage_key, limit=limit)
    moved = await _upstream_moved(db, summaries)
    return SavedSetList(items=[_saved(s, moved.get(s.id)) for s in summaries], total=len(summaries))


@router.post("/{entity_type}/{entity_key}/sets", response_model=SavedSet, status_code=201)
async def save_coverage_set(
    entity_type: str = Path(..., description="threat_actor, malware, cve or ttp"),
    entity_key: str = Path(..., description="Entity UUID, CVE id or ATT&CK technique id"),
    body: SetSaveRequest = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Persist the assembled set into `detection_summaries`.

    Repo, licence and format are read from the library at save time rather than
    trusted from the client, so an adopted rule carries its attribution wherever
    the set is exported. Passing `summary_id` rewrites an existing set instead of
    accumulating a row per keystroke.
    """
    _require_supported(entity_type)
    # Only the resolution is needed here — reassembling the whole workspace
    # would run four aggregates on a save click. The canonical key is stored so
    # a profile (uuid) and the board (canonical id) land on the same sets.
    resolved = await resolve_entity(db, entity_type, entity_key)
    if resolved is None:
        raise AppError(code="not_found", message="Entity not found", status_code=404)

    summary = await save_set(
        db,
        user_id=user.id,
        entity_type=entity_type,
        entity_key=resolved.coverage_key,
        label=resolved.label,
        window=body.window,
        title=body.title,
        items=[i.model_dump() for i in body.items],
        entry_ids=list(body.entry_ids),
        summary_id=body.summary_id,
    )
    return _saved(summary)


async def _get_set(db: AsyncSession, summary_id: uuid.UUID) -> DetectionSummary:
    summary = await db.get(DetectionSummary, summary_id)
    if summary is None or (summary.summary_content or {}).get("kind") != "coverage_set":
        raise AppError(code="not_found", message="Saved set not found", status_code=404)
    return summary


@router.post("/sets/{summary_id}/export", response_model=SetExportResponse)
async def export_coverage_set(
    summary_id: uuid.UUID = Path(..., description="Saved set UUID"),
    export_format: str = Query("bundle", alias="format", description=f"One of {', '.join(EXPORT_FORMATS)}"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Export the assembled set.

    `markdown` renders the research report — intelligence with ¶-cited quotes,
    behaviours, the ruleset table with attribution, and skips as known gaps.
    `bundle` returns the file list the .zip download is built from (fetch
    `/sets/{id}/export.zip` for the archive itself). `intel_report` returns the
    raw payload for the report builder to attach.
    """
    if export_format not in EXPORT_FORMATS:
        raise AppError(code="bad_request", message=f"Unknown export format '{export_format}'", status_code=400)
    summary = await _get_set(db, summary_id)
    content = summary.summary_content or {}

    if export_format == "markdown":
        payload: dict = {"title": summary.title, "markdown": await render_set_markdown(db, summary)}
    elif export_format == "bundle":
        files = await build_set_bundle(db, summary)
        payload = {"title": summary.title, "files": [{"path": p, "content": c} for p, c in files]}
    else:
        payload = {"title": summary.title, **content}

    return SetExportResponse(
        format=export_format,
        item_count=len(content.get("items", [])),
        payload=payload,
    )


@router.get("/sets/{summary_id}/export.zip")
async def export_coverage_set_zip(
    summary_id: uuid.UUID = Path(..., description="Saved set UUID"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """The set as a .zip: one file per rule grouped by format, attribution
    header on every adopted rule, the research report as MANIFEST.md."""
    import io
    import zipfile

    from fastapi.responses import Response

    summary = await _get_set(db, summary_id)
    files = await build_set_bundle(db, summary)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, content in files:
            zf.writestr(path, content)

    safe = "".join(c for c in summary.title if c.isalnum() or c in " _-").strip().replace(" ", "_") or "coverage-set"
    return Response(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{safe}.zip"'},
    )


@router.get("/windows")
async def get_workspace_windows(user: User = Depends(get_current_user)):
    """Windows the workspace offers, matching the board's segmented control."""
    return {"windows": list(WORKSPACE_WINDOW_HOURS)}
