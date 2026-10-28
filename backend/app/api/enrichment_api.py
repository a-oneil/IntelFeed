"""Enrichment API — manage enrichment sources and trigger entity enrichment."""

import uuid
from datetime import UTC, datetime, timedelta

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
    EnrichmentBackfillRequest,
    EnrichmentPauseRequest,
    EnrichmentResultResponse,
    EnrichmentSourceResponse,
    EnrichmentSourceUpdate,
    UserEnrichmentOverrideCreate,
    UserEnrichmentOverrideResponse,
)

router = APIRouter()


async def _source_gateway(source: EnrichmentSource, db: AsyncSession):
    """The source's gateway under its global key: the allowance and budget the
    instance spends. A user's override key has its own, not shown here."""
    from app.enrichment.pipeline import resolve_api_key
    from app.enrichment.registry import source_gateway

    return source_gateway(source, await resolve_api_key(source, None, db))


async def _used_today(source: EnrichmentSource, db: AsyncSession) -> int:
    """Requests the source sent today, from its gateway; 0 when Redis can't
    answer (the gateway is the only counter)."""
    from app.enrichment.gateway import GatewayUnavailable

    try:
        return await (await _source_gateway(source, db)).used_today()
    except GatewayUnavailable:
        return 0


def _source_to_response(s: EnrichmentSource, used_today: int) -> EnrichmentSourceResponse:
    from app.enrichment.registry import SOURCE_REGISTRY

    source_cls = SOURCE_REGISTRY.get(s.source_type)
    shared_key_group = source_cls.shared_key_group if source_cls else None
    # The entity types a person can ask this source to enrich: none for a
    # catalog source, whose jobs fill entities in bulk.
    supported_entity_types = source_cls.supported_entity_types if source_cls and source_cls.kind == "lookup" else []
    requires_api_key = source_cls.requires_api_key if source_cls else False

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
        daily_budget_used=used_today,
        supported_entity_types=supported_entity_types,
        last_synced_at=s.last_synced_at,
        health_status=s.health_status,
        config=s.config,
        created_at=s.created_at,
        updated_at=s.updated_at,
    )


def _check_rate_ceiling(source_type: str, rate_limit_config: dict, has_key: bool) -> None:
    """Refuse a rate above what the source documents it allows."""
    from app.enrichment.registry import SOURCE_REGISTRY

    source_cls = SOURCE_REGISTRY.get(source_type)
    if source_cls is None:
        return
    quota = source_cls.quota.keyed if has_key and source_cls.quota.keyed else source_cls.quota
    requested = rate_limit_config.get("requests_per_period")
    if quota.ceiling_per_period is None or requested is None:
        return
    # The ceiling is per the manifest's period; compare as a rate.
    period = rate_limit_config.get("period_seconds") or quota.period_seconds
    if requested / period > quota.ceiling_per_period / quota.period_seconds:
        raise AppError(
            code="rate_above_ceiling",
            message=(
                f"{source_cls.display_name} allows at most {quota.ceiling_per_period} requests per "
                f"{quota.period_seconds} s{' with an API key' if quota is source_cls.quota.keyed else ''}"
            ),
            details=[{"ceiling_per_period": quota.ceiling_per_period, "period_seconds": quota.period_seconds}],
            status_code=400,
        )


# --- Admin: Source Management ---


@router.get("/sources", response_model=list[EnrichmentSourceResponse])
async def list_enrichment_sources(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """All configured enrichment sources with adapter metadata (key requirements, supported entity types)."""
    result = await db.execute(select(EnrichmentSource).order_by(EnrichmentSource.display_name))
    return [_source_to_response(s, await _used_today(s, db)) for s in result.scalars().all()]


@router.put("/sources/{source_id}", response_model=EnrichmentSourceResponse)
async def update_enrichment_source(
    source_id: uuid.UUID = Path(..., description="Enrichment source UUID"),
    body: EnrichmentSourceUpdate = Body(...),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Admin: update a source's enablement, trigger mode, API key, rate limit or budget.
    Only fields present in the body are applied. A rate above the source's documented
    ceiling (with a key, its keyed ceiling) is refused with 400.
    """
    source = await db.get(EnrichmentSource, source_id)
    if not source:
        raise AppError(code="not_found", message="Enrichment source not found", status_code=404)

    if body.rate_limit_config is not None:
        has_key = bool(body.api_key) if body.api_key is not None else bool(source.api_key_encrypted)
        _check_rate_ceiling(source.source_type, body.rate_limit_config, has_key)

    if body.is_enabled is not None:
        source.is_enabled = body.is_enabled
    if body.trigger_mode is not None:
        source.trigger_mode = body.trigger_mode
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
    elif body.daily_budget is not None:
        source.daily_budget = body.daily_budget

    db.add(source)
    await db.flush()
    await db.refresh(source)
    return _source_to_response(source, await _used_today(source, db))


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
    from app.enrichment.gateway import GatewayError, GatewayUnavailable
    from app.enrichment.registry import ADAPTER_REGISTRY, adapter_for_source

    adapter_cls = ADAPTER_REGISTRY.get(source.source_type)
    if adapter_cls is None:
        raise AppError(
            code="not_testable",
            message=f"{source.display_name} has no lookup to test; its jobs report in the Jobs view",
            status_code=400,
        )
    requires_key = adapter_cls.requires_api_key
    api_key = decrypt_value(source.api_key_encrypted) if source.api_key_encrypted else None

    if requires_key and not api_key:
        source.health_status = "down"
    else:
        # The probe goes through the gateway like any request, so it can be
        # refused; that says nothing about the source, so the status stays.
        try:
            healthy = await adapter_for_source(source, api_key).check_health()
        except GatewayError as e:
            raise AppError(
                code=e.status,
                message=str(e),
                status_code=503 if isinstance(e, GatewayUnavailable) else 429,
            ) from e
        except Exception:
            healthy = False
        source.health_status = "healthy" if healthy else "down"

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

    from app.enrichment.gateway import GatewayUnavailable

    remaining = None
    try:
        remaining = await (await _source_gateway(source, db)).remaining()
    except GatewayUnavailable:
        pass

    return {
        "source_type": source.source_type,
        "health_status": source.health_status,
        "last_synced_at": source.last_synced_at.isoformat() if source.last_synced_at else None,
        "rate_limit_remaining": remaining,
    }


# --- Admin: Console (Settings → Engine → Enrichment) ---


@router.get("/console")
async def get_enrichment_console(
    entity_type: str | None = Query(None, description="Only sources that apply to this entity type, e.g. cve"),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Admin: every source's status, what it fills and why it needs a look, plus
    a summary (sources on, attention, pause, Redis, the last 24h of activity) and
    the entity types with their source counts. Sources needing attention sort
    first, then enabled ones, then by label. The summary and entity types always
    cover every source; ``entity_type`` filters only ``sources``."""
    from app.enrichment.console import console

    return await console(db, entity_type)


@router.get("/sources/{source_type}/detail")
async def get_enrichment_source_detail(
    source_type: str = Path(..., description="Source type, e.g. nvd"),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Admin: one source's limits and use today, 24 hourly request counts, its
    queue, its outputs with fill rates, the gap a backfill would close, and its
    jobs' last 30 days."""
    from app.enrichment.console import detail

    result = await detail(db, source_type)
    if result is None:
        raise AppError(code="not_found", message=f"Unknown enrichment source: {source_type}", status_code=404)
    return result


@router.post("/pause")
async def pause_enrichment(
    body: EnrichmentPauseRequest,
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Admin: pause or resume every request to outside sources. While paused the
    gateway refuses each request, queued lookups wait and scheduled jobs stop."""
    from app.enrichment.pause import set_paused

    await set_paused(db, body.paused)
    return {"paused": body.paused}


@router.post("/sources/{source_type}/backfill")
async def backfill_enrichment_source(
    source_type: str = Path(..., description="Lookup source type, e.g. nvd"),
    body: EnrichmentBackfillRequest = Body(...),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Admin: queue backfill-lane lookups for the entities missing the source's
    first column, newest first. Skips entities the source can't look up and ones
    already waiting in its queue. 400 for a catalog source, a type it doesn't
    apply to, or a source that is off."""
    from app.enrichment.console import BackfillError, backfill

    try:
        queued = await backfill(db, source_type, body.entity_type, body.limit)
    except BackfillError as e:
        raise AppError(code=e.code, message=str(e), status_code=400) from e
    return {"queued": queued}


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
    """On-demand enrichment for a specific entity. Uses the pipeline: cache, then each source's gateway.

    Sources the gateway refused (rate limited, breaker open, budget used up)
    are queued to retry on the enrichment queue and listed in ``queued``."""
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

    # A source the gateway refused gets a manual-lane job: the lookup runs when
    # the source allows it, under this user's key, rather than being lost.
    from app.enrichment.queue import RETRYABLE, enqueue, next_utc_midnight

    queued: list[str] = []
    now = datetime.now(UTC)
    for r in results:
        if r["status"] not in RETRYABLE:
            continue
        if r["status"] == "budget_exhausted":
            due_at = next_utc_midnight(now)
        else:
            due_at = now + timedelta(seconds=r.get("retry_after") or 0)
        queued += await enqueue(
            db,
            adapter_entity_type,
            body.entity_id,
            entity_value,
            lane="manual",
            source_types=[r["source_type"]],
            requested_by=user.id,
            due_at=due_at,
        )

    return {
        "entity_type": body.entity_type,
        "entity_id": str(body.entity_id),
        "results": results,
        "queued": queued,
    }


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
