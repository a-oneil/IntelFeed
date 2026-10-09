"""Pipeline plan resolution: feed > category > global > legacy-boolean synthesis.

The legacy Feed booleans (intel_extraction_mode, auto_extract_on_ingest,
extract_detection_rules) remain the base layer until the follow-up migration
drops them — resolution synthesizes stage defaults from them at resolve time
(no snapshot drift), then overlays global → category → feed PipelinePlan rows.

Resolutions are cached in Redis per feed with a version key bumped on any plan
write (autolinker vocab pattern); resolve happens once per feed fetch, not per
entry.
"""

import json
import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.pipeline.registry import PIPELINE_STAGES

logger = logging.getLogger(__name__)

PLAN_CACHE_PREFIX = "intelfeed:pipeline_plan:"
PLAN_VERSION_KEY = "intelfeed:pipeline_plan:version"
PLAN_CACHE_TTL = 600


def synthesize_from_feed(feed) -> dict[str, dict]:
    """Stage plan equivalent to today's Feed-boolean behavior."""
    run_extraction = bool(
        getattr(feed, "auto_extract_on_ingest", False) or getattr(feed, "extract_detection_rules", False)
    )
    plan: dict[str, dict] = {}
    for stage in PIPELINE_STAGES.values():
        enabled = stage.default_enabled
        config: dict = {}
        if stage.name == "extract":
            enabled = run_extraction
            config = {
                "mode": getattr(feed, "intel_extraction_mode", "selective"),
                "detection_rules": bool(getattr(feed, "extract_detection_rules", False)),
            }
        plan[stage.name] = {"enabled": enabled, "config": config}
    return plan


def _merge(base: dict[str, dict], overlay: dict[str, dict]) -> dict[str, dict]:
    merged = {k: {"enabled": v["enabled"], "config": dict(v.get("config", {}))} for k, v in base.items()}
    for stage_name, spec in (overlay or {}).items():
        if stage_name not in merged:
            continue
        if "enabled" in spec:
            merged[stage_name]["enabled"] = bool(spec["enabled"])
        merged[stage_name]["config"].update(spec.get("config", {}))
    return merged


async def bump_plan_version() -> None:
    from app.services.redis_client import get_redis

    try:
        r = await get_redis()
        await r.incr(PLAN_VERSION_KEY)
    except Exception:
        logger.debug("Failed to bump pipeline plan version", exc_info=True)


async def explain_feed_plan(db: AsyncSession, feed) -> dict:
    """The resolved plan plus which scope decided each stage's `enabled`.

    Same merge order as `resolve_feed_plan` — the UI must not re-implement it in
    the client and drift. `decided_by` is "legacy" when no plan row touched the
    stage, so the value still comes from the Feed booleans and editing them in
    the feed modal still does something; otherwise it names the scope that won,
    and that stage is only changeable from the Engine's plan editor.
    """
    from app.models.pipeline_plan import PipelinePlan
    from app.services.system_settings import get_setting

    engine_enabled = bool(await get_setting("pipeline_engine_enabled", db))
    plan = synthesize_from_feed(feed)
    decided_by = dict.fromkeys(plan, "legacy")

    if not engine_enabled:
        return {"engine_enabled": False, "stages": plan, "decided_by": decided_by}

    rows = (
        (
            await db.execute(
                select(PipelinePlan).where(
                    PipelinePlan.is_active == True,  # noqa: E712
                    (
                        (PipelinePlan.scope_type == "global")
                        | ((PipelinePlan.scope_type == "category") & (PipelinePlan.scope_id == feed.category_id))
                        | ((PipelinePlan.scope_type == "feed") & (PipelinePlan.scope_id == feed.id))
                    ),
                )
            )
        )
        .scalars()
        .all()
    )
    by_scope = {row.scope_type: row for row in rows}
    for scope in ("global", "category", "feed"):
        row = by_scope.get(scope)
        if not row:
            continue
        for stage_name, spec in (row.stages or {}).items():
            if stage_name in plan and "enabled" in (spec or {}):
                decided_by[stage_name] = scope
        plan = _merge(plan, row.stages or {})

    return {"engine_enabled": True, "stages": plan, "decided_by": decided_by}


async def resolve_feed_plan(db: AsyncSession, feed) -> dict[str, dict] | None:
    """Resolved stage plan for a feed, or None when the pipeline engine is off
    (callers then use the legacy run_extraction boolean path)."""
    from app.models.pipeline_plan import PipelinePlan
    from app.services.redis_client import get_redis
    from app.services.system_settings import get_setting

    if not bool(await get_setting("pipeline_engine_enabled", db)):
        return None

    cache_key = None
    try:
        r = await get_redis()
        version = await r.get(PLAN_VERSION_KEY) or "0"
        cache_key = f"{PLAN_CACHE_PREFIX}{feed.id}:{version}"
        cached = await r.get(cache_key)
        if cached:
            return json.loads(cached)
    except Exception:
        logger.debug("Pipeline plan cache read failed", exc_info=True)

    plan = synthesize_from_feed(feed)
    rows = (
        (
            await db.execute(
                select(PipelinePlan).where(
                    PipelinePlan.is_active == True,  # noqa: E712
                    (
                        (PipelinePlan.scope_type == "global")
                        | ((PipelinePlan.scope_type == "category") & (PipelinePlan.scope_id == feed.category_id))
                        | ((PipelinePlan.scope_type == "feed") & (PipelinePlan.scope_id == feed.id))
                    ),
                )
            )
        )
        .scalars()
        .all()
    )
    by_scope = {row.scope_type: row for row in rows}
    for scope in ("global", "category", "feed"):
        if scope in by_scope:
            plan = _merge(plan, by_scope[scope].stages or {})

    if cache_key:
        try:
            r = await get_redis()
            await r.set(cache_key, json.dumps(plan), ex=PLAN_CACHE_TTL)
        except Exception:
            logger.debug("Pipeline plan cache write failed", exc_info=True)
    return plan
