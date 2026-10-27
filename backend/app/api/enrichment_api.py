"""Enrichment API — manage enrichment sources and trigger entity enrichment."""

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Body, Depends, Path, Query
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppError
from app.core.security import get_admin_user, get_current_user, get_viewer
from app.database import get_db
from app.models.enrichment import EnrichmentResult, EnrichmentSource, UserEnrichmentOverride
from app.models.user import User
from app.schemas.enrichment import (
    EnrichEntityRequest,
    EnrichmentBudgetSummaryItem,
    EnrichmentResultResponse,
    EnrichmentSourceResponse,
    EnrichmentSourceUpdate,
    UserEnrichmentOverrideCreate,
    UserEnrichmentOverrideResponse,
)

router = APIRouter()


def _source_to_response(s: EnrichmentSource) -> EnrichmentSourceResponse:
    from app.enrichment.registry import ADAPTER_REGISTRY

    adapter_cls = ADAPTER_REGISTRY.get(s.source_type)
    shared_key_group = getattr(adapter_cls, "shared_key_group", None) if adapter_cls else None
    supported_entity_types = getattr(adapter_cls, "supported_entity_types", []) if adapter_cls else []
    requires_api_key = getattr(adapter_cls, "requires_api_key", False) if adapter_cls else False

    return EnrichmentSourceResponse(
        id=s.id,
        source_type=s.source_type,
        display_name=s.display_name,
        is_enabled=s.is_enabled,
        trigger_mode=s.trigger_mode,
        has_api_key=bool(s.api_key_encrypted),
        requires_api_key=requires_api_key,
        shared_key_group=shared_key_group,
        rate_limit_config=s.rate_limit_config,
        min_confidence_threshold=s.min_confidence_threshold,
        daily_budget=s.daily_budget,
        daily_budget_used=s.daily_budget_used,
        schedule_interval_hours=s.schedule_interval_hours,
        next_scheduled_at=s.next_scheduled_at,
        supported_entity_types=supported_entity_types,
        last_synced_at=s.last_synced_at,
        health_status=s.health_status,
        config=s.config,
        created_at=s.created_at,
        updated_at=s.updated_at,
    )


# --- Admin: Source Management ---


@router.get("/sources", response_model=list[EnrichmentSourceResponse])
async def list_enrichment_sources(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """All configured enrichment sources with adapter metadata (key requirements, supported entity types)."""
    result = await db.execute(select(EnrichmentSource).order_by(EnrichmentSource.display_name))
    return [_source_to_response(s) for s in result.scalars().all()]


@router.put("/sources/{source_id}", response_model=EnrichmentSourceResponse)
async def update_enrichment_source(
    source_id: uuid.UUID = Path(..., description="Enrichment source UUID"),
    body: EnrichmentSourceUpdate = Body(...),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Admin: update a source's enablement, trigger mode, API key, rate limits, budget or schedule.
    Only fields present in the body are applied; switching to scheduled mode seeds next_scheduled_at.
    """
    source = await db.get(EnrichmentSource, source_id)
    if not source:
        raise AppError(code="not_found", message="Enrichment source not found", status_code=404)

    if body.is_enabled is not None:
        source.is_enabled = body.is_enabled
    if body.trigger_mode is not None:
        source.trigger_mode = body.trigger_mode
        # When switching to scheduled, seed next_scheduled_at if not set
        if body.trigger_mode == "scheduled" and not source.next_scheduled_at:
            from datetime import timedelta

            source.next_scheduled_at = datetime.now(UTC) + timedelta(hours=source.schedule_interval_hours)
    if body.api_key is not None:
        from app.core.encryption import encrypt_value

        source.api_key_encrypted = encrypt_value(body.api_key) if body.api_key else None
    if body.rate_limit_config is not None:
        source.rate_limit_config = body.rate_limit_config
    if body.config is not None:
        source.config = body.config
    if body.min_confidence_threshold is not None:
        source.min_confidence_threshold = body.min_confidence_threshold
    if body.clear_daily_budget:
        source.daily_budget = None
        source.daily_budget_used = 0
    elif body.daily_budget is not None:
        source.daily_budget = body.daily_budget
    if body.schedule_interval_hours is not None:
        source.schedule_interval_hours = body.schedule_interval_hours
        # Recalculate next_scheduled_at based on new interval
        if source.trigger_mode == "scheduled":
            from datetime import timedelta

            base = source.last_synced_at or datetime.now(UTC)
            source.next_scheduled_at = base + timedelta(hours=body.schedule_interval_hours)

    db.add(source)
    await db.flush()
    await db.refresh(source)
    return _source_to_response(source)


@router.post("/sources/{source_id}/test")
async def test_source_connection(
    source_id: uuid.UUID = Path(..., description="Enrichment source UUID"),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Test API key and connectivity for an enrichment source."""
    source = await db.get(EnrichmentSource, source_id)
    if not source:
        raise AppError(code="not_found", message="Enrichment source not found", status_code=404)

    from app.core.encryption import decrypt_value
    from app.enrichment.registry import ADAPTER_REGISTRY, get_adapter

    adapter_cls = ADAPTER_REGISTRY.get(source.source_type)
    requires_key = getattr(adapter_cls, "requires_api_key", False) if adapter_cls else False
    api_key = decrypt_value(source.api_key_encrypted) if source.api_key_encrypted else None

    if requires_key and not api_key:
        source.health_status = "down"
    else:
        try:
            adapter = get_adapter(source.source_type, api_key=api_key, config=source.config)
            healthy = await adapter.check_health()
            source.health_status = "healthy" if healthy else "down"
        except Exception:
            source.health_status = "down"

    db.add(source)
    await db.flush()
    return {"source_type": source.source_type, "health_status": source.health_status}


@router.get("/sources/{source_id}/health")
async def get_source_health(
    source_id: uuid.UUID = Path(..., description="Enrichment source UUID"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get current health status of an enrichment source."""
    source = await db.get(EnrichmentSource, source_id)
    if not source:
        raise AppError(code="not_found", message="Enrichment source not found", status_code=404)

    from app.enrichment.rate_limiter import RedisRateLimiter

    remaining = None
    try:
        limiter = RedisRateLimiter(source.source_type, source.rate_limit_config)
        remaining = await limiter.get_remaining()
    except Exception:
        pass

    return {
        "source_type": source.source_type,
        "health_status": source.health_status,
        "last_synced_at": source.last_synced_at.isoformat() if source.last_synced_at else None,
        "rate_limit_remaining": remaining,
    }


@router.get("/budget-summary", response_model=list[EnrichmentBudgetSummaryItem])
async def get_budget_summary(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get daily budget usage for all sources with budgets configured."""
    from app.enrichment.rate_limiter import RedisBudgetTracker

    result = await db.execute(select(EnrichmentSource).where(EnrichmentSource.daily_budget.isnot(None)))
    sources = result.scalars().all()

    if not sources:
        return []

    # Bulk fetch usage from Redis
    source_types = [s.source_type for s in sources]
    usage_map = await RedisBudgetTracker.get_used_bulk(source_types)

    summaries = []
    for source in sources:
        used = usage_map.get(source.source_type, 0)
        summaries.append(
            EnrichmentBudgetSummaryItem(
                source_type=source.source_type,
                display_name=source.display_name,
                daily_budget=source.daily_budget,
                used_today=used,
                remaining=max(0, source.daily_budget - used),
            )
        )
    return summaries


# --- User: API Key Overrides ---


@router.get("/user-overrides", response_model=list[UserEnrichmentOverrideResponse])
async def list_user_overrides(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List the current user's enrichment source overrides."""
    result = await db.execute(select(UserEnrichmentOverride).where(UserEnrichmentOverride.created_by == user.id))
    overrides = result.scalars().all()
    return [
        UserEnrichmentOverrideResponse(
            id=o.id,
            source_id=o.source_id,
            has_api_key=bool(o.api_key_encrypted),
            created_at=o.created_at,
        )
        for o in overrides
    ]


@router.put("/user-overrides/{source_id}", status_code=200)
async def upsert_user_override(
    source_id: uuid.UUID = Path(..., description="Enrichment source UUID the override applies to"),
    body: UserEnrichmentOverrideCreate = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create or update a user API key override for an enrichment source."""
    # Verify source exists
    source = await db.get(EnrichmentSource, source_id)
    if not source:
        raise AppError(code="not_found", message="Enrichment source not found", status_code=404)

    # Check for the caller's existing override
    result = await db.execute(
        select(UserEnrichmentOverride).where(
            UserEnrichmentOverride.source_id == source_id,
            UserEnrichmentOverride.created_by == user.id,
        )
    )
    override = result.scalar_one_or_none()

    if override:
        if body.api_key is not None:
            from app.core.encryption import encrypt_value

            override.api_key_encrypted = encrypt_value(body.api_key) if body.api_key else None
    else:
        override = UserEnrichmentOverride(
            created_by=user.id,
            source_id=source_id,
        )
        if body.api_key:
            from app.core.encryption import encrypt_value

            override.api_key_encrypted = encrypt_value(body.api_key)

    db.add(override)
    await db.flush()
    return {"status": "ok", "id": str(override.id)}


@router.delete("/user-overrides/{source_id}", status_code=204)
async def delete_user_override(
    source_id: uuid.UUID = Path(..., description="Enrichment source UUID whose override to remove"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Remove the current user's override for an enrichment source (revert to global)."""
    await db.execute(
        delete(UserEnrichmentOverride).where(
            UserEnrichmentOverride.source_id == source_id,
            UserEnrichmentOverride.created_by == user.id,
        )
    )
    await db.flush()


# --- Entity Enrichment ---


@router.post("/enrich")
async def enrich_entity(
    body: EnrichEntityRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """On-demand enrichment for a specific entity. Uses pipeline with caching and rate limiting."""
    from app.enrichment.pipeline import enrich_entity as pipeline_enrich

    # Resolve entity value and adapter entity type from the database
    entity_value: str | None = None
    adapter_entity_type = body.entity_type

    if body.entity_type == "cve":
        from app.models.cve import CVE

        cve = await db.get(CVE, body.entity_id)
        if not cve:
            raise AppError(code="not_found", message="CVE not found", status_code=404)
        entity_value = cve.cve_id
    elif body.entity_type == "threat_actor":
        from app.models.threat_actor import ThreatActor

        actor = await db.get(ThreatActor, body.entity_id)
        if not actor:
            raise AppError(code="not_found", message="Threat actor not found", status_code=404)
        entity_value = actor.name
    elif body.entity_type == "malware":
        from app.models.malware_family import MalwareFamily

        malware = await db.get(MalwareFamily, body.entity_id)
        if not malware:
            raise AppError(code="not_found", message="Malware family not found", status_code=404)
        entity_value = malware.name
    elif body.entity_type == "ttp":
        from app.models.ttp import TTP

        ttp = await db.get(TTP, body.entity_id)
        if not ttp:
            raise AppError(code="not_found", message="TTP not found", status_code=404)
        entity_value = ttp.technique_id
    elif body.entity_type == "observable":
        from app.models.observable import Observable

        obs = await db.get(Observable, body.entity_id)
        if not obs:
            raise AppError(code="not_found", message="Observable not found", status_code=404)
        # Values are stored refanged/canonical, so this is directly queryable;
        # adapters infer the kind from the value's shape.
        entity_value = obs.value
    else:
        raise AppError(code="invalid_entity_type", message="Unsupported entity type", status_code=400)

    results = await pipeline_enrich(
        entity_type=adapter_entity_type,
        entity_id=body.entity_id,
        entity_value=entity_value,
        db=db,
        user_id=user.id,
        trigger="manual",
        source_types=body.source_types,
    )

    return {"entity_type": body.entity_type, "entity_id": str(body.entity_id), "results": results}


@router.get("/results", response_model=list[EnrichmentResultResponse])
async def get_enrichment_results(
    entity_type: str = Query(..., description="Entity type the results belong to (cve, threat_actor, malware, ttp)"),
    entity_id: uuid.UUID = Query(..., description="Entity UUID"),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Stored enrichment results for one entity, newest first."""
    if user.is_anonymous:
        # Results are keyed by type and id, outside the visitor filter: answer
        # only for an entity the visitor can see.
        from app.services.public_view import entities_shown

        if entity_type in ("campaign", "observable") or (entity_type, entity_id) not in await entities_shown(
            db, {(entity_type, entity_id)}
        ):
            return []
    result = await db.execute(
        select(EnrichmentResult)
        .where(
            EnrichmentResult.entity_type == entity_type,
            EnrichmentResult.entity_id == entity_id,
        )
        .order_by(EnrichmentResult.enriched_at.desc())
    )
    return [EnrichmentResultResponse.model_validate(r) for r in result.scalars().all()]


@router.get("/status")
async def get_enrichment_status(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Overall enrichment system status."""
    from sqlalchemy import func

    sources_result = await db.execute(select(EnrichmentSource))
    sources = sources_result.scalars().all()

    enabled = sum(1 for s in sources if s.is_enabled)
    healthy = sum(1 for s in sources if s.health_status == "healthy")

    # Count recent enrichment results
    now = datetime.now(UTC)
    count_result = await db.execute(
        select(func.count(EnrichmentResult.id)).where(
            EnrichmentResult.enriched_at >= now.replace(hour=0, minute=0, second=0)
        )
    )
    today_count = count_result.scalar() or 0

    return {
        "total_sources": len(sources),
        "enabled_sources": enabled,
        "healthy_sources": healthy,
        "enrichments_today": today_count,
    }
