"""Engine API — signal-engine stats and settings (grows per engine plan phases 5–6)."""

import json

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel, ConfigDict, Field

from app.core.security import get_current_user
from app.database import get_db
from app.models.user import User

router = APIRouter()


def _require_admin(user: User) -> None:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")


class SignalSettingsUpdate(BaseModel):
    family_multipliers: dict[str, float] | None = None  # 0..2 per family
    threshold_override: float | None = Field(default=None, ge=0.0)
    clear_threshold_override: bool = False

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "family_multipliers": {"novelty": 1.5, "coverage": 1.0, "severity": 1.2},
                "threshold_override": 2.5,
                "clear_threshold_override": False,
            }
        }
    )


@router.get("/signals/stats")
async def signal_stats(
    user: User = Depends(get_current_user),
    db=Depends(get_db),
):
    """Current firing rates, effective weights, families, multipliers, threshold + health."""
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import func, select

    from app.intelligence.signals import (
        DEFAULT_FAMILY_MULTIPLIERS,
        SIGNAL_FAMILIES,
        get_family_multipliers,
        get_feedback_nudges,
        get_radar_threshold,
        get_signal_rates,
        idf_weight,
    )
    from app.models.entry import Entry
    from app.models.entry_signal import EntrySignal
    from app.models.entry_signal_feedback import EntrySignalFeedback
    from app.models.job_run import JobRun
    from app.services.system_settings import get_setting

    rates = await get_signal_rates()
    multipliers = await get_family_multipliers()
    threshold, threshold_is_auto = await get_radar_threshold()

    now = datetime.now(UTC)
    unscored_72h = (
        await db.execute(
            select(func.count())
            .select_from(Entry)
            .where(Entry.published_at >= now - timedelta(hours=72), Entry.scored_at.is_(None))
        )
    ).scalar_one()

    feedback_rows = (
        await db.execute(
            select(EntrySignal.signal_type, func.count())
            .join(EntrySignalFeedback, EntrySignalFeedback.entry_id == EntrySignal.entry_id)
            .where(EntrySignalFeedback.created_at >= now - timedelta(days=30))
            .group_by(EntrySignal.signal_type)
        )
    ).all()
    feedback_by_family: dict[str, int] = {}
    for signal_type, count in feedback_rows:
        family = SIGNAL_FAMILIES.get(signal_type)
        if family:
            feedback_by_family[family] = feedback_by_family.get(family, 0) + count

    async def _last_run(job_key: str) -> dict | None:
        run = (
            await db.execute(
                select(JobRun).where(JobRun.job_key == job_key).order_by(JobRun.finished_at.desc()).limit(1)
            )
        ).scalar_one_or_none()
        if run is None:
            return None
        return {
            "status": run.status,
            "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        }

    health = {
        "shadow_enabled": bool(await get_setting("signal_engine_shadow", db)),
        "surface_enabled": bool(await get_setting("signal_engine_surface", db)),
        "unscored_recent": unscored_72h,
        "feedback_min_samples": int(await get_setting("signal_feedback_min_samples", db) or 0),
        "feedback_counts": feedback_by_family,
        "feedback_nudges": await get_feedback_nudges(),
        "last_rate_recompute": await _last_run("signal-rate-recompute"),
        "last_rescore": await _last_run("signal-rescore-recent"),
    }

    return {
        "health": health,
        "signals": [
            {
                "signal_type": sig,
                "family": family,
                "firing_rate": rates.get(sig),
                "effective_weight": round(idf_weight(rates.get(sig, 0.05)), 3),
            }
            for sig, family in SIGNAL_FAMILIES.items()
        ],
        "family_multipliers": multipliers,
        "default_family_multipliers": DEFAULT_FAMILY_MULTIPLIERS,
        "threshold": threshold,
        "threshold_is_auto": threshold_is_auto,
    }


@router.put("/signals/settings")
async def update_signal_settings(
    body: SignalSettingsUpdate,
    user: User = Depends(get_current_user),
):
    """Admin: update global family multipliers / radar threshold; triggers a bounded rescore."""
    _require_admin(user)
    from app.intelligence.signals import (
        DEFAULT_FAMILY_MULTIPLIERS,
        MULTIPLIERS_REDIS_KEY,
        THRESHOLD_OVERRIDE_REDIS_KEY,
    )
    from app.services.redis_client import get_redis

    r = await get_redis()
    changed = False
    if body.family_multipliers is not None:
        unknown = set(body.family_multipliers) - set(DEFAULT_FAMILY_MULTIPLIERS)
        if unknown:
            raise HTTPException(status_code=422, detail=f"Unknown families: {sorted(unknown)}")
        clamped = {k: max(0.0, min(2.0, float(v))) for k, v in body.family_multipliers.items()}
        await r.set(MULTIPLIERS_REDIS_KEY, json.dumps({**DEFAULT_FAMILY_MULTIPLIERS, **clamped}))
        changed = True
    if body.clear_threshold_override:
        await r.delete(THRESHOLD_OVERRIDE_REDIS_KEY)
        changed = True
    elif body.threshold_override is not None:
        await r.set(THRESHOLD_OVERRIDE_REDIS_KEY, str(body.threshold_override))
        changed = True

    if changed and body.family_multipliers is not None:
        # Multiplier changes alter stored scores — propagate to recent entries now
        from app.workers.signal_tasks import rescore_recent_entries

        rescore_recent_entries.delay(hours=168, limit=2000)
    return {"updated": changed}


@router.get("/entities/{entity_type}/{entity_id}/whats-new")
async def entity_whats_new(
    entity_type: str = Path(..., description="Entity type slug (e.g. threat_actor, malware, cve, ttp, tool)"),
    entity_id: str = Path(..., description="Entity UUID"),
    days: int = Query(14, description="Look-back window in days (capped at 90)"),
    scoped: bool = Query(
        False,
        description=(
            "Keep only developments whose subject IS this entity (or article-level "
            "signals with no subject). The profile's Latest Developments passes true "
            "so an entity's page stops listing first-mentions of unrelated entities "
            "that merely co-occur in its articles."
        ),
    ),
    user: User = Depends(get_current_user),
    db=Depends(get_db),
):
    """Recent novelty/severity signals on entries linked to this entity (workbench strip)."""
    import uuid as _uuid
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import select

    from app.intelligence.correlation import entry_scope_junction
    from app.models.entry import Entry
    from app.models.entry_signal import EntrySignal

    # Not the watch/mute map: that one is about muting extraction entities, and
    # a campaign is never muted. This asks the narrower question the strip
    # actually needs — which entries belong to this thing.
    scope = entry_scope_junction(entity_type)
    if scope is None:
        raise HTTPException(status_code=422, detail=f"Unsupported entity_type: {entity_type}")
    junction, id_col = scope
    try:
        eid = _uuid.UUID(entity_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid entity id") from None

    interesting = (
        "novel_entity",
        "entity_resurgence",
        "new_pairing",
        "scoop",
        "kev_added",
        "epss_jump",
        "weaponized_poc",
        "under_reported",
    )
    cutoff = datetime.now(UTC) - timedelta(days=min(days, 90))
    rows = (
        await db.execute(
            select(EntrySignal, Entry.title, Entry.published_at)
            .join(Entry, Entry.id == EntrySignal.entry_id)
            .join(junction, junction.entry_id == EntrySignal.entry_id)
            .where(
                id_col == eid,
                EntrySignal.signal_type.in_(interesting),
                Entry.published_at >= cutoff,
            )
            .order_by(Entry.published_at.desc())
            .limit(50)
        )
    ).all()

    # Signals are per-entry, so several linked entries can carry the same event
    # (e.g. every article on a KEV-recent CVE gets its own "added to CISA KEV"
    # signal). Collapse identical events, keeping the oldest occurrence so the
    # timestamp reflects when the event first surfaced.
    deduped: dict[tuple[str, str], tuple] = {}
    for row in reversed(rows):  # oldest → newest; first write wins
        sig = row[0]
        deduped.setdefault((sig.signal_type, sig.explanation or ""), row)
    kept = sorted(
        deduped.values(),
        key=lambda r: r[2] or datetime.min.replace(tzinfo=UTC),
        reverse=True,
    )[:20]

    # Resolve each signal's subject entity so the UI can group events by what
    # they're about ("CVE-X: new + KEV") instead of listing one sentence each.
    enriched = [(sig, title, published_at, _whats_new_subject(sig)) for sig, title, published_at in kept]
    ids = await _resolve_subject_ids(db, [subj for *_, subj in enriched if subj])
    if scoped:
        # Subject-scoped view: a development belongs on this profile only when
        # it is about this entity itself (or carries no subject at all — a
        # scoop/under-reported signal about the linked article). Then collapse
        # repeats of the same (signal, subject) pair — the "First mention of
        # CVE-X (+7)" / "(+12)" duplication — keeping the newest.
        scoped_rows: dict[tuple[str, str], tuple] = {}
        for row in reversed(enriched):  # oldest → newest; newest wins
            sig, _title, _published, subj = row
            if subj is not None and str(ids.get(subj)) != str(eid):
                continue
            scoped_rows[(sig.signal_type, subj[1] if subj else "")] = row
        enriched = sorted(
            scoped_rows.values(),
            key=lambda r: r[2] or datetime.min.replace(tzinfo=UTC),
            reverse=True,
        )
    return {
        "items": [
            {
                "entry_id": str(sig.entry_id),
                "entry_title": title,
                "published_at": published_at.isoformat() if published_at else None,
                "signal_type": sig.signal_type,
                "explanation": sig.explanation,
                "subject": ({"type": subj[0], "name": subj[1], "id": ids.get(subj)} if subj else None),
            }
            for sig, title, published_at, subj in enriched
        ]
    }


_NOVEL_TYPE_SLUGS = {"CVE": "cve", "threat actor": "threat_actor", "malware": "malware", "tool": "tool"}
_CVE_SUBJECT_SIGNALS = ("kev_added", "epss_jump", "weaponized_poc", "under_reported", "critical_cvss")


def _whats_new_subject(sig) -> tuple[str, str] | None:
    """(entity_type_slug, display_name) a signal is about, if it has one."""
    import re

    payload = sig.payload or {}
    if sig.signal_type == "novel_entity":
        entities = payload.get("entities") or []
        if entities:
            slug = _NOVEL_TYPE_SLUGS.get(entities[0].get("type"))
            name = entities[0].get("name")
            if slug and name:
                return (slug, name)
    elif sig.signal_type == "entity_resurgence":
        slug = _NOVEL_TYPE_SLUGS.get(payload.get("entity_type"))
        if slug and payload.get("name"):
            return (slug, payload["name"])
    elif sig.signal_type in _CVE_SUBJECT_SIGNALS:
        # The explanation reliably names the subject CVE; payload cve_ids may
        # be ordered differently from the one the sentence highlights.
        m = re.search(r"CVE-\d{4}-\d{4,}", sig.explanation or "")
        if m:
            return ("cve", m.group(0))
    return None


async def _resolve_subject_ids(db, subjects: list[tuple[str, str]]) -> dict[tuple[str, str], str | None]:
    """Map (type_slug, name) subjects to entity UUIDs for profile links."""
    from sqlalchemy import select

    from app.models.cve import CVE
    from app.models.malware_family import MalwareFamily
    from app.models.threat_actor import ThreatActor
    from app.models.tool import Tool

    lookups = {
        "cve": (CVE, CVE.cve_id),
        "threat_actor": (ThreatActor, ThreatActor.name),
        "malware": (MalwareFamily, MalwareFamily.name),
        "tool": (Tool, Tool.name),
    }
    resolved: dict[tuple[str, str], str | None] = {}
    for slug, (model, name_col) in lookups.items():
        names = {name for s, name in subjects if s == slug}
        if not names:
            continue
        rows = (await db.execute(select(model.id, name_col).where(name_col.in_(names)))).all()
        found = {name: str(eid) for eid, name in rows}
        for name in names:
            resolved[(slug, name)] = found.get(name)
    return resolved


@router.get("/extraction/status")
async def extraction_status(
    user: User = Depends(get_current_user),
    db=Depends(get_db),
):
    """One-pass AI extraction health: queue depth, today's spend, last batch."""
    from datetime import UTC, datetime

    from sqlalchemy import func, select

    from app.models.ai_analysis import AIAnalysisRequest, AIBatchJob
    from app.models.ai_result import AIResult
    from app.models.ai_task import AITask
    from app.services.system_settings import get_setting

    status_counts = dict(
        (await db.execute(select(AIAnalysisRequest.status, func.count()).group_by(AIAnalysisRequest.status))).all()
    )
    task_id = (await db.execute(select(AITask.id).where(AITask.name == "entry_analysis"))).scalar_one_or_none()
    spent_today = 0.0
    if task_id:
        day_start = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
        spent_today = float(
            (
                await db.execute(
                    select(func.coalesce(func.sum(AIResult.cost_estimate), 0)).where(
                        AIResult.task_id == task_id, AIResult.created_at >= day_start
                    )
                )
            ).scalar_one()
        )
    last_batch = (
        await db.execute(select(AIBatchJob).order_by(AIBatchJob.created_at.desc()).limit(1))
    ).scalar_one_or_none()
    return {
        "enabled": bool(await get_setting("ai_one_pass_enabled", db)),
        "queue": status_counts,
        "spent_today_usd": round(spent_today, 4),
        "daily_budget_usd": float(await get_setting("ai_daily_budget_usd", db) or 2.0),
        "last_batch": {
            "provider_batch_id": last_batch.provider_batch_id,
            "status": last_batch.status,
            "request_count": last_batch.request_count,
            "succeeded": last_batch.succeeded,
            "errored": last_batch.errored,
            "created_at": last_batch.created_at.isoformat() if last_batch.created_at else None,
        }
        if last_batch
        else None,
    }


PIPELINE_STAGE_LABELS: dict[str, str] = {
    "autolink": "Entity autolink",
    "observables": "Observable scan",
    "telegram_links": "Telegram link scan",
    "extract": "Intel extraction",
    "cooccurrence": "Co-occurrence edges",
    "correlation": "Correlation events",
    "requirements": "Requirement matching",
    "score": "Signal scoring",
    "adjudicate": "AI review",
    "automate": "Automation rules",
    "translate": "Translation",
}

# Stages whose tasks accept a bare entry_id and are safe to re-dispatch.
# automate (needs feed_id) and translate (needs target language) are excluded.
RETRYABLE_STAGE_TASKS: dict[str, str] = {
    "autolink": "app.workers.intel_feed_tasks.autolink_entry_task",
    "observables": "app.workers.intel_feed_tasks.observables_entry_task",
    "telegram_links": "app.workers.telegram_link_tasks.scan_telegram_links_task",
    "extract": "app.workers.intel_feed_tasks.extract_entry_intel_task",
    "cooccurrence": "app.workers.intel_feed_tasks.create_cooccurrence_relationships_task",
    "correlation": "app.workers.automation_tasks.detect_correlation_events",
    "requirements": "app.workers.intel_feed_tasks.match_requirements_task",
    "score": "app.workers.signal_tasks.score_entry_task",
}


@router.get("/entries/{entry_id}/runs")
async def entry_pipeline_runs(
    entry_id: str = Path(..., description="Entry UUID"),
    user: User = Depends(get_current_user),
    db=Depends(get_db),
):
    """Latest run per pipeline stage for an entry (processing popover)."""
    import uuid as _uuid

    from sqlalchemy import select

    from app.models.entry_pipeline_run import EntryPipelineRun

    try:
        eid = _uuid.UUID(entry_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid entry id") from None
    rows = (
        (
            await db.execute(
                select(EntryPipelineRun)
                .where(EntryPipelineRun.entry_id == eid)
                .order_by(EntryPipelineRun.created_at.desc())
                .limit(50)
            )
        )
        .scalars()
        .all()
    )
    latest: dict[str, EntryPipelineRun] = {}
    for run in rows:  # rows are newest-first
        latest.setdefault(run.stage, run)
    return {
        "runs": [
            {
                "stage": run.stage,
                "label": PIPELINE_STAGE_LABELS.get(run.stage, run.stage),
                "status": run.status,
                "duration_ms": run.duration_ms,
                "error": run.error,
                "created_at": run.created_at.isoformat() if run.created_at else None,
                "retryable": run.stage in RETRYABLE_STAGE_TASKS,
            }
            for run in latest.values()
        ]
    }


@router.get("/pipeline/stages/{stage}/runs")
async def stage_runs(
    stage: str = Path(..., description="Pipeline stage name from the registry (e.g. autolink, extract, score)"),
    status: str | None = Query(None, description="Only runs with this status (success, error, retry)"),
    limit: int = Query(50, description="Max runs to return (clamped to 1-200)"),
    user: User = Depends(get_current_user),
    db=Depends(get_db),
):
    """Recent runs for one pipeline stage with entry context — the drill-down
    behind a stage card's ✓/✕ badges (Engine → Pipeline tab)."""
    from sqlalchemy import select

    from app.models.entry import Entry
    from app.models.entry_pipeline_run import EntryPipelineRun
    from app.pipeline.registry import PIPELINE_STAGES

    if stage not in PIPELINE_STAGES:
        raise HTTPException(status_code=422, detail=f"Unknown stage: {stage}")
    limit = max(1, min(limit, 200))
    query = (
        select(EntryPipelineRun, Entry.title, Entry.translated_title)
        .join(Entry, Entry.id == EntryPipelineRun.entry_id)
        .where(EntryPipelineRun.stage == stage)
        .order_by(EntryPipelineRun.created_at.desc())
        .limit(limit)
    )
    if status:
        query = query.where(EntryPipelineRun.status == status)
    rows = (await db.execute(query)).all()
    return {
        "runs": [
            {
                "id": str(run.id),
                "entry_id": str(run.entry_id),
                "entry_title": translated_title or title,
                "status": run.status,
                "duration_ms": run.duration_ms,
                "error": run.error,
                "created_at": run.created_at.isoformat() if run.created_at else None,
                "retryable": stage in RETRYABLE_STAGE_TASKS,
            }
            for run, title, translated_title in rows
        ]
    }


@router.post("/entries/{entry_id}/stages/{stage}/retry")
async def retry_pipeline_stage(
    entry_id: str = Path(..., description="Entry UUID"),
    stage: str = Path(..., description="Stage to re-dispatch; must be retryable (automate/translate are not)"),
    user: User = Depends(get_current_user),
):
    """Re-dispatch one pipeline stage task for an entry. Admin only."""
    _require_admin(user)
    import uuid as _uuid

    from app.workers.celery_app import celery_app

    if stage not in RETRYABLE_STAGE_TASKS:
        raise HTTPException(status_code=422, detail=f"Stage not retryable: {stage}")
    try:
        _uuid.UUID(entry_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid entry id") from None
    result = celery_app.send_task(RETRYABLE_STAGE_TASKS[stage], kwargs={"entry_id": entry_id})
    return {"dispatched": True, "task_id": result.id}


@router.get("/pipeline")
async def pipeline_overview(
    user: User = Depends(get_current_user),
    db=Depends(get_db),
):
    """Stage registry + 24h activity + engine flag state (Engine → Pipeline tab).

    ``success``/``retry`` are 24h run tallies (throughput). ``error`` is the count
    of entries whose *latest* run at the stage is an error — a stage the entry is
    still stuck on — so re-running to green immediately drops it, instead of the
    old behaviour where a superseded error lingered in the tally for 24h.
    """
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import and_, exists, func, select
    from sqlalchemy.orm import aliased

    from app.models.entry_pipeline_run import EntryPipelineRun
    from app.pipeline.registry import PIPELINE_STAGES
    from app.services.system_settings import get_setting

    cutoff = datetime.now(UTC) - timedelta(hours=24)
    Run = EntryPipelineRun
    counts = {
        (stage, status): n
        for stage, status, n in (
            await db.execute(
                select(Run.stage, Run.status, func.count())
                .where(Run.created_at >= cutoff)
                .group_by(Run.stage, Run.status)
            )
        ).all()
    }
    # Entries currently errored at a stage: an error run with no newer run at the
    # same stage (a later success/retry supersedes it). Newer-run check is NOT
    # window-bounded so a green re-run just outside 24h still clears the error.
    Newer = aliased(Run)
    errored_now = {
        stage: n
        for stage, n in (
            await db.execute(
                select(Run.stage, func.count(func.distinct(Run.entry_id)))
                .where(
                    Run.created_at >= cutoff,
                    Run.status == "error",
                    ~exists().where(
                        and_(
                            Newer.entry_id == Run.entry_id,
                            Newer.stage == Run.stage,
                            Newer.created_at > Run.created_at,
                        )
                    ),
                )
                .group_by(Run.stage)
            )
        ).all()
    }
    return {
        "pipeline_engine_enabled": bool(await get_setting("pipeline_engine_enabled", db)),
        "run_logging_enabled": bool(await get_setting("pipeline_run_logging_enabled", db)),
        "stages": [
            {
                "name": s.name,
                "kind": s.kind,
                "description": s.description,
                "default_enabled": s.default_enabled,
                "config_schema": s.config_schema,
                "runs_24h": {
                    "success": counts.get((s.name, "success"), 0),
                    "error": errored_now.get(s.name, 0),
                    "retry": counts.get((s.name, "retry"), 0),
                },
            }
            for s in PIPELINE_STAGES.values()
        ],
    }


# Dispatched (non-inline) pipeline stages that write per-entry run rows, in
# execution order — the column set for the Engine → Processing matrix. Mirrors
# PIPELINE_STAGE_LABELS (enrich runs per-entity, not per-entry, so it is absent).
PROCESSING_STAGE_ORDER: list[str] = [
    "translate",
    "autolink",
    "observables",
    "telegram_links",
    "extract",
    "cooccurrence",
    "correlation",
    "requirements",
    "score",
    "adjudicate",
    "automate",
]

_WINDOW_HOURS: dict[str, int] = {"1h": 1, "24h": 24, "7d": 24 * 7}


@router.get("/processing")
async def processing_flow(
    window: str = Query("24h", description="Stats window: 1h, 24h or 7d (unknown values fall back to 24h)"),
    status: str | None = Query(None, description="Bucket filter: complete, errored/error or in_flight/processing"),
    stage: str | None = Query(
        None, description="Entries whose latest run at this stage matches status (default error)"
    ),
    feed_id: str | None = Query(None, description="Only entries from this feed (UUID)"),
    search: str | None = Query(None, description="Substring match on entry title (original or translated)"),
    cursor: str | None = Query(None, description="Opaque cursor from the previous page's next_cursor"),
    limit: int = Query(50, description="Rows per page (clamped to 1-200)"),
    user: User = Depends(get_current_user),
    db=Depends(get_db),
):
    """Per-entry pipeline matrix + window stats (Engine → Processing tab).

    Pivots ``entry_pipeline_runs`` (latest run per stage) into one row per entry,
    newest first, cursor-paginated on ``entries.created_at``. ``status`` buckets:
    ``complete`` (score succeeded), ``errored`` (a stage's latest run failed and
    not yet complete), ``in_flight`` (neither). ``stage`` + ``status`` narrows to
    entries whose latest run at that stage matches (e.g. errored-at-extract).
    """
    import uuid as _uuid
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import and_, exists, func, literal, or_, select
    from sqlalchemy.orm import aliased

    from app.models.category import Category
    from app.models.cve import CVE, EntryCVE
    from app.models.entity_relationship import EntityRelationship
    from app.models.entry import Entry
    from app.models.entry_pipeline_run import EntryPipelineRun
    from app.models.entry_signal import EntrySignal
    from app.models.feed import Feed
    from app.models.malware_family import EntryMalware, MalwareFamily
    from app.models.product import EntryProduct, Product
    from app.models.threat_actor import EntryThreatActor, ThreatActor
    from app.models.tool import EntryTool, Tool
    from app.models.ttp import TTP, EntryTTP
    from app.models.vendor import EntryVendor, Vendor

    _require_admin(user)
    hours = _WINDOW_HOURS.get(window, 24)
    cutoff = datetime.now(UTC) - timedelta(hours=hours)
    limit = max(1, min(limit, 200))

    Run = EntryPipelineRun

    _Newer = aliased(Run)

    def _score_success_exists():
        return exists().where(and_(Run.entry_id == Entry.id, Run.stage == "score", Run.status == "success"))

    def _latest_is_error(stage: str | None = None):
        """Entry has an error run — at ``stage`` if given — that no later run at
        the same stage supersedes. A green re-run adds a newer success/retry run,
        so the entry immediately stops matching (unlike "any error run ever")."""
        conds = [Run.entry_id == Entry.id, Run.status == "error"]
        if stage is not None:
            conds.append(Run.stage == stage)
        superseded = exists().where(
            and_(
                _Newer.entry_id == Run.entry_id,
                _Newer.stage == Run.stage,
                _Newer.created_at > Run.created_at,
            )
        )
        return exists().where(and_(*conds, ~superseded))

    # --- base entry query (window + optional feed/search) -------------------
    base = select(Entry).where(Entry.created_at >= cutoff)
    if feed_id:
        try:
            base = base.where(Entry.feed_id == _uuid.UUID(feed_id))
        except ValueError:
            raise HTTPException(status_code=422, detail="Invalid feed_id") from None
    if search:
        like = f"%{search.strip()}%"
        base = base.where(or_(Entry.title.ilike(like), Entry.translated_title.ilike(like)))

    # --- status / stage filters --------------------------------------------
    if stage:
        if stage not in PROCESSING_STAGE_ORDER:
            raise HTTPException(status_code=422, detail=f"Unknown stage: {stage}")
        stage_status = status or "error"
        if stage_status == "error":
            # Only entries still stuck at this stage — not ones already re-run green.
            base = base.where(_latest_is_error(stage))
        else:
            base = base.where(
                exists().where(and_(Run.entry_id == Entry.id, Run.stage == stage, Run.status == stage_status))
            )
    elif status == "complete":
        base = base.where(_score_success_exists())
    elif status in ("error", "errored"):
        base = base.where(_latest_is_error(), ~_score_success_exists())
    elif status in ("in_flight", "processing"):
        base = base.where(~_score_success_exists(), ~_latest_is_error())

    # --- cursor pagination (created_at desc, id desc tiebreak) --------------
    if cursor:
        try:
            c_ts, c_id = cursor.split("|", 1)
            cur_dt = datetime.fromisoformat(c_ts)
            cur_id = _uuid.UUID(c_id)
        except (ValueError, AttributeError):
            raise HTTPException(status_code=422, detail="Invalid cursor") from None
        base = base.where(
            or_(
                Entry.created_at < cur_dt,
                and_(Entry.created_at == cur_dt, Entry.id < cur_id),
            )
        )

    page_q = base.order_by(Entry.created_at.desc(), Entry.id.desc()).limit(limit + 1)
    entries = (await db.execute(page_q)).scalars().all()
    has_more = len(entries) > limit
    entries = entries[:limit]

    next_cursor = None
    if has_more and entries:
        last = entries[-1]
        next_cursor = f"{last.created_at.isoformat()}|{last.id}"

    # --- feed titles + category for the page -------------------------------
    feed_titles: dict[_uuid.UUID, str] = {}
    feed_categories: dict[_uuid.UUID, str | None] = {}
    entity_map: dict[_uuid.UUID, list[dict]] = {}
    # Per-entry Output-lens counts: what each stage produced for the entry.
    _EMPTY_OUTPUTS = {
        "links_auto": 0,
        "links_ai": 0,
        "links_other": 0,
        "entities_created": 0,
        "rels_cooc": 0,
        "rels_other": 0,
        "signals": 0,
        "observables": 0,
    }
    outputs_map: dict[_uuid.UUID, dict[str, int]] = {}
    if entries:
        entry_ids = [e.id for e in entries]
        feed_ids = {e.feed_id for e in entries}
        for fid, title, custom, cat in (
            await db.execute(
                select(Feed.id, Feed.title, Feed.custom_title, Category.name)
                .outerjoin(Category, Category.id == Feed.category_id)
                .where(Feed.id.in_(feed_ids))
            )
        ).all():
            feed_titles[fid] = custom or title
            feed_categories[fid] = cat

        # --- linked entities per entry (drawer pills) ----------------------
        # (junction, junction entity-FK, entity model, entity name col, type, has_source)
        entity_sources = [
            (EntryCVE, EntryCVE.cve_id, CVE, CVE.cve_id, "cve", False),
            (EntryTTP, EntryTTP.ttp_id, TTP, TTP.technique_id, "ttp", False),
            (EntryThreatActor, EntryThreatActor.threat_actor_id, ThreatActor, ThreatActor.name, "threat_actor", True),
            (EntryMalware, EntryMalware.malware_family_id, MalwareFamily, MalwareFamily.name, "malware", True),
            (EntryVendor, EntryVendor.vendor_id, Vendor, Vendor.name, "vendor", True),
            (EntryProduct, EntryProduct.product_id, Product, Product.name, "product", True),
            (EntryTool, EntryTool.tool_id, Tool, Tool.name, "tool", True),
        ]
        for junction, fk, ent_model, name_col, type_label, has_source in entity_sources:
            source_col = junction.source if has_source else literal(None)
            for eid, name, src in (
                await db.execute(
                    select(junction.entry_id, name_col, source_col)
                    .join(ent_model, ent_model.id == fk)
                    .where(junction.entry_id.in_(entry_ids))
                )
            ).all():
                entity_map.setdefault(eid, []).append({"type": type_label, "name": name})
                out = outputs_map.setdefault(eid, dict(_EMPTY_OUTPUTS))
                if src == "auto_link":
                    out["links_auto"] += 1
                elif src in ("ai", "ai_reconcile"):
                    out["links_ai"] += 1
                else:
                    out["links_other"] += 1

        # --- Output-lens aggregates: what each stage produced per entry -----
        # Entities the AI created from these entries (extraction provenance).
        for ai_model in (ThreatActor, MalwareFamily, Tool, CVE, TTP):
            for eid, n in (
                await db.execute(
                    select(ai_model.created_from_entry_id, func.count())
                    .where(
                        ai_model.created_from_entry_id.in_(entry_ids),
                        ai_model.created_via == "ai_extraction",
                    )
                    .group_by(ai_model.created_from_entry_id)
                )
            ).all():
                out = outputs_map.setdefault(eid, dict(_EMPTY_OUTPUTS))
                out["entities_created"] += n

        # Observable sightings recorded for these entries (the ledger's output lens).
        from app.models.observable import EntryObservable

        obs_rows = (
            await db.execute(
                select(EntryObservable.entry_id, func.count())
                .where(EntryObservable.entry_id.in_(entry_ids))
                .group_by(EntryObservable.entry_id)
            )
        ).all()
        for eid, n in obs_rows:
            outputs_map.setdefault(eid, dict(_EMPTY_OUTPUTS))["observables"] += n

        # Relationships evidenced by these entries, split co-occurrence vs AI/other.
        rel_rows = (
            await db.execute(
                select(EntityRelationship.source, EntityRelationship.evidence_entry_ids).where(
                    EntityRelationship.evidence_entry_ids.overlap(entry_ids)
                )
            )
        ).all()
        page_ids = set(entry_ids)
        for rel_source, evidence in rel_rows:
            for eid in evidence or []:
                if eid not in page_ids:
                    continue
                out = outputs_map.setdefault(eid, dict(_EMPTY_OUTPUTS))
                if rel_source == "co_occurrence":
                    out["rels_cooc"] += 1
                else:
                    out["rels_other"] += 1

        # Signals fired at score time.
        for eid, n in (
            await db.execute(
                select(EntrySignal.entry_id, func.count())
                .where(EntrySignal.entry_id.in_(entry_ids))
                .group_by(EntrySignal.entry_id)
            )
        ).all():
            out = outputs_map.setdefault(eid, dict(_EMPTY_OUTPUTS))
            out["signals"] = n

    # --- latest run per (entry, stage) for the page ------------------------
    latest: dict[tuple[_uuid.UUID, str], EntryPipelineRun] = {}
    if entries:
        entry_ids = [e.id for e in entries]
        runs = (
            (
                await db.execute(
                    select(Run)
                    .where(Run.entry_id.in_(entry_ids))
                    .order_by(Run.entry_id, Run.stage, Run.created_at.desc())
                )
            )
            .scalars()
            .all()
        )
        for r in runs:
            latest.setdefault((r.entry_id, r.stage), r)

    def _row(e: Entry) -> dict:
        stages: dict[str, dict] = {}
        last_run_at = None
        for st in PROCESSING_STAGE_ORDER:
            r = latest.get((e.id, st))
            if r is None:
                continue
            stages[st] = {
                "status": r.status,
                "duration_ms": r.duration_ms,
                "error": r.error,
                "retryable": st in RETRYABLE_STAGE_TASKS,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                # Stage-specific run detail (the adjudicate stage's verdict counts).
                "detail": r.detail or None,
            }
            if r.created_at and (last_run_at is None or r.created_at > last_run_at):
                last_run_at = r.created_at
        has_err = any(s["status"] == "error" for s in stages.values())
        complete = stages.get("score", {}).get("status") == "success"
        overall = "complete" if complete else ("errored" if has_err else "in_flight")
        latency_ms = None
        if last_run_at and e.created_at:
            latency_ms = int((last_run_at - e.created_at).total_seconds() * 1000)
        return {
            "id": str(e.id),
            "title": e.translated_title or e.title,
            "feed": feed_titles.get(e.feed_id),
            "category": feed_categories.get(e.feed_id),
            "created_at": e.created_at.isoformat() if e.created_at else None,
            "radar_score": e.priority_score,
            "latency_ms": latency_ms,
            "status": overall,
            "stages": stages,
            "entities": entity_map.get(e.id, [])[:12],
            "outputs": {
                **outputs_map.get(e.id, _EMPTY_OUTPUTS),
                # Funnel numerator/denominator per entry: candidates staged by
                # the scan vs sightings that passed a judgment door.
                "observable_candidates": len(e.observable_candidates or []),
            },
        }

    # --- window stats (independent of the page) ----------------------------
    ingested = (
        await db.execute(select(func.count()).select_from(Entry).where(Entry.created_at >= cutoff))
    ).scalar_one()
    complete_ct = (
        await db.execute(
            select(func.count()).select_from(Entry).where(Entry.created_at >= cutoff, _score_success_exists())
        )
    ).scalar_one()
    errored_ct = (
        await db.execute(
            select(func.count())
            .select_from(Entry)
            .where(Entry.created_at >= cutoff, _latest_is_error(), ~_score_success_exists())
        )
    ).scalar_one()
    # Per-stage: entries whose latest run at the stage is an error (still stuck),
    # not raw error-run counts — so re-run-to-green entries drop out immediately.
    _NewerStat = aliased(Run)
    by_stage_errors = {
        st: n
        for st, n in (
            await db.execute(
                select(Run.stage, func.count(func.distinct(Run.entry_id)))
                .where(
                    Run.created_at >= cutoff,
                    Run.status == "error",
                    ~exists().where(
                        and_(
                            _NewerStat.entry_id == Run.entry_id,
                            _NewerStat.stage == Run.stage,
                            _NewerStat.created_at > Run.created_at,
                        )
                    ),
                )
                .group_by(Run.stage)
            )
        ).all()
    }
    # Observables precision funnel over the window: staged candidates vs
    # judgment-confirmed sightings. If the ratio drifts, this is where it shows
    # before the workbench feels it.
    from app.models.observable import EntryObservable as _EntryObs

    obs_candidates_ct = (
        await db.execute(
            select(func.coalesce(func.sum(func.jsonb_array_length(Entry.observable_candidates)), 0)).where(
                Entry.created_at >= cutoff, Entry.observable_candidates.isnot(None)
            )
        )
    ).scalar_one()
    obs_confirmed_ct = (
        await db.execute(
            select(func.count())
            .select_from(_EntryObs)
            .join(Entry, Entry.id == _EntryObs.entry_id)
            .where(Entry.created_at >= cutoff)
        )
    ).scalar_one()

    # median / p95 latency: score-success run time minus entry creation
    latency_row = (
        await db.execute(
            select(
                func.percentile_cont(0.5).within_group(func.extract("epoch", Run.created_at - Entry.created_at)),
                func.percentile_cont(0.95).within_group(func.extract("epoch", Run.created_at - Entry.created_at)),
            )
            .select_from(Run)
            .join(Entry, Entry.id == Run.entry_id)
            .where(
                Entry.created_at >= cutoff,
                Run.stage == "score",
                Run.status == "success",
            )
        )
    ).one()
    median_s, p95_s = latency_row

    # --- ingest sparkline: window split into 24 equal buckets --------------
    buckets = 24
    bucket_seconds = (hours * 3600) / buckets
    epoch_cutoff = cutoff.timestamp()
    bucket_expr = func.floor((func.extract("epoch", Entry.created_at) - epoch_cutoff) / bucket_seconds)
    counts_by_bucket = {
        int(b): n
        for b, n in (
            await db.execute(
                select(bucket_expr.label("b"), func.count()).where(Entry.created_at >= cutoff).group_by("b")
            )
        ).all()
        if b is not None
    }
    ingest_series = [counts_by_bucket.get(i, 0) for i in range(buckets)]

    return {
        "window": window,
        "stages": [{"name": st, "label": PIPELINE_STAGE_LABELS.get(st, st)} for st in PROCESSING_STAGE_ORDER],
        "stats": {
            "ingested": ingested,
            "complete": complete_ct,
            "errored": errored_ct,
            "processing": max(0, ingested - complete_ct - errored_ct),
            "by_stage_errors": by_stage_errors,
            "observable_candidates": int(obs_candidates_ct or 0),
            "observable_confirmed": int(obs_confirmed_ct or 0),
            "median_latency_ms": int(median_s * 1000) if median_s is not None else None,
            "p95_latency_ms": int(p95_s * 1000) if p95_s is not None else None,
            "ingest_series": ingest_series,
        },
        "entries": [_row(e) for e in entries],
        "next_cursor": next_cursor,
    }


@router.get("/plans")
async def list_plans(
    user: User = Depends(get_current_user),
    db=Depends(get_db),
):
    """All pipeline plans — global, per-category and per-feed — with their per-stage toggles/config."""
    from sqlalchemy import select

    from app.models.pipeline_plan import PipelinePlan

    rows = (
        (await db.execute(select(PipelinePlan).order_by(PipelinePlan.scope_type, PipelinePlan.created_at)))
        .scalars()
        .all()
    )
    return {
        "plans": [
            {
                "id": str(p.id),
                "name": p.name,
                "scope_type": p.scope_type,
                "scope_id": str(p.scope_id) if p.scope_id else None,
                "stages": p.stages,
                "is_active": p.is_active,
            }
            for p in rows
        ]
    }


class PlanUpsert(BaseModel):
    name: str
    scope_type: str = Field(pattern="^(global|category|feed)$")
    scope_id: str | None = None
    stages: dict = {}
    is_active: bool = True

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "Ransomware feeds — full extraction",
                "scope_type": "feed",
                "scope_id": "d5b2f1e8-3c4a-4b6d-9e2f-7a8b9c0d1e2f",
                "stages": {"extract": {"enabled": True, "config": {"mode": "selective"}}, "score": {"enabled": True}},
                "is_active": True,
            }
        }
    )


@router.put("/plans")
async def upsert_plan(
    body: PlanUpsert,
    user: User = Depends(get_current_user),
    db=Depends(get_db),
):
    """Create or update the plan for one (scope_type, scope_id) pair — admin only.

    Rejects unknown stage names; on success bumps the plan version so workers
    re-resolve feed plans on their next fetch.
    """
    import uuid as _uuid

    from sqlalchemy.dialects.postgresql import insert as pg_insert

    from app.models.pipeline_plan import PipelinePlan
    from app.pipeline.plans import bump_plan_version
    from app.pipeline.registry import PIPELINE_STAGES

    _require_admin(user)
    unknown = set(body.stages) - set(PIPELINE_STAGES)
    if unknown:
        raise HTTPException(status_code=422, detail=f"Unknown stages: {sorted(unknown)}")
    scope_id = None
    if body.scope_type != "global":
        if not body.scope_id:
            raise HTTPException(status_code=422, detail="scope_id required for category/feed plans")
        try:
            scope_id = _uuid.UUID(body.scope_id)
        except ValueError:
            raise HTTPException(status_code=422, detail="Invalid scope_id") from None

    stmt = pg_insert(PipelinePlan).values(
        id=_uuid.uuid4(),
        name=body.name,
        scope_type=body.scope_type,
        scope_id=scope_id,
        stages=body.stages,
        is_active=body.is_active,
    )
    stmt = stmt.on_conflict_do_update(
        constraint="uq_pipeline_plan_scope",
        set_={"name": stmt.excluded.name, "stages": stmt.excluded.stages, "is_active": stmt.excluded.is_active},
    )
    await db.execute(stmt)
    await db.commit()
    await bump_plan_version()
    return {"updated": True}


@router.delete("/plans/{plan_id}")
async def delete_plan(
    plan_id: str = Path(..., description="Plan UUID (the global plan cannot be deleted)"),
    user: User = Depends(get_current_user),
    db=Depends(get_db),
):
    """Delete a category- or feed-scoped plan (admin) and bump the plan version. 404 for the global plan."""
    import uuid as _uuid

    from sqlalchemy import delete as sa_delete

    from app.models.pipeline_plan import PipelinePlan
    from app.pipeline.plans import bump_plan_version

    _require_admin(user)
    try:
        pid = _uuid.UUID(plan_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid plan id") from None
    result = await db.execute(
        sa_delete(PipelinePlan).where(PipelinePlan.id == pid, PipelinePlan.scope_type != "global")
    )
    await db.commit()
    if not result.rowcount:
        raise HTTPException(status_code=404, detail="Plan not found (global plan cannot be deleted)")
    await bump_plan_version()
    return {"deleted": True}


@router.get("/job-runs")
async def job_runs(
    job_key: str | None = Query(None, description="Filter to one scheduled job key (e.g. signal-rate-recompute)"),
    limit: int = Query(100, description="Max runs to return (capped at 500)"),
    user: User = Depends(get_current_user),
    db=Depends(get_db),
):
    """Recent scheduled-job runs (Engine → Jobs tab run history)."""
    from sqlalchemy import select

    from app.models.job_run import JobRun

    query = select(JobRun).order_by(JobRun.finished_at.desc()).limit(min(limit, 500))
    if job_key:
        query = query.where(JobRun.job_key == job_key)
    rows = ((await db.execute(query)).scalars()).all()
    return {
        "runs": [
            {
                "id": str(r.id),
                "job_key": r.job_key,
                "task_name": r.task_name,
                "status": r.status,
                "finished_at": r.finished_at.isoformat() if r.finished_at else None,
                "duration_ms": r.duration_ms,
                "error": r.error,
                "detail": r.detail,
            }
            for r in rows
        ]
    }


class RadarFeedback(BaseModel):
    entry_id: str
    verdict: int = Field(ge=-1, le=1)

    model_config = ConfigDict(
        json_schema_extra={"example": {"entry_id": "3f9c2b1a-5d6e-4f70-8a9b-c0d1e2f3a4b5", "verdict": 1}}
    )


@router.put("/radar-feedback")
async def radar_feedback(
    body: RadarFeedback,
    user: User = Depends(get_current_user),
    db=Depends(get_db),
):
    """Thumbs on a Radar item (1 useful / -1 noise / 0 clears). Nudges family weights nightly."""
    import uuid as _uuid

    from sqlalchemy import delete as sa_delete
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    from app.models.entry_signal_feedback import EntrySignalFeedback

    try:
        eid = _uuid.UUID(body.entry_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid entry id") from None
    if body.verdict == 0:
        await db.execute(
            sa_delete(EntrySignalFeedback).where(
                EntrySignalFeedback.entry_id == eid, EntrySignalFeedback.created_by == user.id
            )
        )
    else:
        stmt = pg_insert(EntrySignalFeedback).values(
            id=_uuid.uuid4(), entry_id=eid, created_by=user.id, verdict=body.verdict
        )
        stmt = stmt.on_conflict_do_update(
            constraint="uq_signal_feedback_entry_user", set_={"verdict": stmt.excluded.verdict}
        )
        await db.execute(stmt)
    await db.commit()
    return {"ok": True}


# --- Personalised Radar (learned per-user signal weights) ------------------
# The global feedback nudge above pools every analyst's thumbs into one set of
# family multipliers baked into Entry.priority_score. These endpoints expose the
# per-analyst counterpart: weights fitted nightly from this user's own verdicts
# and applied as a read-time lift on their Radar ordering. Opting out restores
# the house ranking immediately — nothing is rewritten either way.


class MyRadarUpdate(BaseModel):
    personalized: bool

    model_config = ConfigDict(json_schema_extra={"example": {"personalized": True}})


@router.get("/my-radar")
async def get_my_radar(
    user: User = Depends(get_current_user),
    db=Depends(get_db),
):
    """This analyst's learned signal weights, the votes behind them, and the toggle state."""
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import func, select

    from app.intelligence.signals import (
        DEFAULT_FAMILY_MULTIPLIERS,
        SIGNAL_FAMILIES,
        attribute_feedback_votes,
        get_signal_rates,
    )
    from app.models.entry_signal import EntrySignal
    from app.models.entry_signal_feedback import EntrySignalFeedback
    from app.models.user_signal_weight import UserSignalWeight
    from app.services.radar_personalization import is_personalization_opted_in
    from app.services.system_settings import get_setting

    enabled = bool(await get_setting("radar_personalization_enabled", db))
    min_samples = int(await get_setting("radar_personalization_min_samples", db) or 5)
    window_days = int(await get_setting("radar_personalization_window_days", db) or 90)

    learned = {
        row.family: row
        for row in (await db.execute(select(UserSignalWeight).where(UserSignalWeight.user_id == user.id)))
        .scalars()
        .all()
    }

    # Run this user's verdicts through the same attribution the nightly fit uses,
    # so a family below the floor shows the count that will actually decide it —
    # not the number of votes it merely co-fired on, which is much larger and
    # would read as "38 votes but still neutral".
    cutoff = datetime.now(UTC) - timedelta(days=window_days)
    raw_rows = (
        await db.execute(
            select(
                EntrySignalFeedback.id,
                EntrySignalFeedback.verdict,
                EntrySignal.signal_type,
                EntrySignal.score,
            )
            .join(EntrySignal, EntrySignal.entry_id == EntrySignalFeedback.entry_id)
            .where(EntrySignalFeedback.created_by == user.id, EntrySignalFeedback.created_at >= cutoff)
        )
    ).all()
    attributed = attribute_feedback_votes(raw_rows, await get_signal_rates())
    votes_by_family = {family: len(votes) for family, votes in attributed.items()}
    # How often the family fired on a voted entry at all — the denominator that
    # explains why an attributed count can be far lower.
    seen_by_family: dict[str, int] = {}
    for _fb_id, _verdict, signal_type, _score in raw_rows:
        family = SIGNAL_FAMILIES.get(signal_type)
        if family:
            seen_by_family[family] = seen_by_family.get(family, 0) + 1

    total_votes = (
        await db.execute(
            select(func.count())
            .select_from(EntrySignalFeedback)
            .where(EntrySignalFeedback.created_by == user.id, EntrySignalFeedback.created_at >= cutoff)
        )
    ).scalar_one()

    families = []
    for family in DEFAULT_FAMILY_MULTIPLIERS:
        row = learned.get(family)
        families.append(
            {
                "family": family,
                "weight": round(float(row.weight), 3) if row else 1.0,
                "learned": row is not None,
                "up_votes": row.up_votes if row else 0,
                "down_votes": row.down_votes if row else 0,
                # Votes credited to this family by the fit's attribution — what
                # the sample floor is measured against.
                "sample_count": row.sample_count if row else votes_by_family.get(family, 0),
                # Times the family fired on a voted entry at all. Higher than
                # sample_count whenever another signal out-contributed it.
                "votes_seen": seen_by_family.get(family, 0),
                "updated_at": row.updated_at.isoformat() if row and row.updated_at else None,
            }
        )

    return {
        "enabled": enabled,
        "personalized": is_personalization_opted_in(user.settings),
        "active": enabled and is_personalization_opted_in(user.settings) and bool(learned),
        "min_samples": min_samples,
        "window_days": window_days,
        "total_votes": total_votes,
        "families": families,
    }


@router.put("/my-radar")
async def update_my_radar(
    body: MyRadarUpdate,
    user: User = Depends(get_current_user),
    db=Depends(get_db),
):
    """Opt this analyst's Radar in or out of their learned weights."""
    from sqlalchemy import select
    from sqlalchemy.orm.attributes import flag_modified

    from app.models.user import User as UserModel
    from app.services.radar_personalization import USER_SETTING_KEY

    row = (await db.execute(select(UserModel).where(UserModel.id == user.id))).scalar_one()
    row.settings = {**(row.settings or {}), USER_SETTING_KEY: body.personalized}
    flag_modified(row, "settings")
    await db.commit()
    return {"personalized": body.personalized}


@router.delete("/my-radar")
async def reset_my_radar(
    user: User = Depends(get_current_user),
    db=Depends(get_db),
):
    """Discard this analyst's learned weights. The nightly fit refits from surviving votes."""
    from sqlalchemy import delete as sa_delete

    from app.models.user_signal_weight import UserSignalWeight

    result = await db.execute(sa_delete(UserSignalWeight).where(UserSignalWeight.user_id == user.id))
    await db.commit()
    return {"cleared": result.rowcount or 0}


# --- Autolink false-positive names ----------------------------------------
# The `autolinker_false_positive_names` setting is one comma-separated string;
# at ~170 entries a textarea is unreadable and unsearchable. These endpoints let
# the Autolink panel render it as a table with per-name removal.


class FpNamesResponse(BaseModel):
    items: list[str]
    total: int
    limit: int
    offset: int


class FpNameRequest(BaseModel):
    name: str

    model_config = ConfigDict(json_schema_extra={"example": {"name": "prometheus"}})


async def _fp_names(db) -> list[str]:
    from app.services.system_settings import get_setting

    raw = str(await get_setting("autolinker_false_positive_names", db) or "")
    return sorted({n.strip().lower() for n in raw.split(",") if n.strip()})


@router.get("/autolink/fp-names", response_model=FpNamesResponse)
async def list_fp_names(
    q: str | None = Query(None, description="Substring match."),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user: User = Depends(get_current_user),
    db=Depends(get_db),
) -> FpNamesResponse:
    """Names excluded from autolinker matching, alphabetically."""
    _require_admin(user)
    names = await _fp_names(db)
    if q:
        needle = q.strip().lower()
        names = [n for n in names if needle in n]
    return FpNamesResponse(items=names[offset : offset + limit], total=len(names), limit=limit, offset=offset)


@router.post("/autolink/fp-names", status_code=201)
async def add_fp_name(
    body: FpNameRequest,
    user: User = Depends(get_current_user),
    db=Depends(get_db),
) -> dict:
    """Exclude a name from autolinker matching and rebuild the vocabulary."""
    _require_admin(user)
    from app.intelligence.autolinker import refresh_vocabulary
    from app.intelligence.entity_resolution import sync_fp_names

    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="name is required")
    changed = await sync_fp_names(db, add=[name])
    await db.commit()
    if changed:
        await refresh_vocabulary(db)
    return {"added": changed, "name": name.lower()}


@router.delete("/autolink/fp-names", status_code=204)
async def remove_fp_name(
    name: str = Query(..., description="Exact name to stop excluding."),
    user: User = Depends(get_current_user),
    db=Depends(get_db),
) -> None:
    """Let the autolinker match this name again."""
    _require_admin(user)
    from app.intelligence.autolinker import refresh_vocabulary
    from app.intelligence.entity_resolution import sync_fp_names

    changed = await sync_fp_names(db, remove=[name])
    await db.commit()
    if changed:
        await refresh_vocabulary(db)


# --- Autolink blocked surface forms ---------------------------------------
# Written by the reader's "Wrong? → never match this word anywhere" action. Kept
# apart from the curated fp-names list because these bind for every entity type,
# including vendor/product/tool/mitigation which bypass that list by design.

BLOCKED_FORMS_SETTING = "autolinker_blocked_surface_forms"


async def _blocked_forms(db) -> list[str]:
    from app.services.system_settings import get_setting

    raw = str(await get_setting(BLOCKED_FORMS_SETTING, db) or "")
    return sorted({n.strip().lower() for n in raw.split(",") if n.strip()})


@router.get("/autolink/blocked-names", response_model=FpNamesResponse)
async def list_blocked_names(
    q: str | None = Query(None, description="Substring match."),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user: User = Depends(get_current_user),
    db=Depends(get_db),
) -> FpNamesResponse:
    """Analyst-blocked surface forms, blocked for every entity type, alphabetically."""
    _require_admin(user)
    names = await _blocked_forms(db)
    if q:
        needle = q.strip().lower()
        names = [n for n in names if needle in n]
    return FpNamesResponse(items=names[offset : offset + limit], total=len(names), limit=limit, offset=offset)


@router.post("/autolink/blocked-names", status_code=201)
async def add_blocked_name(
    body: FpNameRequest,
    user: User = Depends(get_current_user),
    db=Depends(get_db),
) -> dict:
    """Block a surface form from matching any entity type and rebuild the vocabulary."""
    _require_admin(user)
    from app.intelligence.autolinker import refresh_vocabulary
    from app.intelligence.entity_resolution import sync_name_list_setting

    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="name is required")
    changed = await sync_name_list_setting(db, BLOCKED_FORMS_SETTING, add=[name])
    await db.commit()
    if changed:
        await refresh_vocabulary(db)
    return {"added": changed, "name": name.lower()}


@router.delete("/autolink/blocked-names", status_code=204)
async def remove_blocked_name(
    name: str = Query(..., description="Exact form to unblock."),
    user: User = Depends(get_current_user),
    db=Depends(get_db),
) -> None:
    """Let every entity type match this surface form again."""
    _require_admin(user)
    from app.intelligence.autolinker import refresh_vocabulary
    from app.intelligence.entity_resolution import sync_name_list_setting

    changed = await sync_name_list_setting(db, BLOCKED_FORMS_SETTING, remove=[name])
    await db.commit()
    if changed:
        await refresh_vocabulary(db)
