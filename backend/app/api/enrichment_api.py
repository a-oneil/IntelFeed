"""Enrichment API — manage enrichment sources and trigger entity enrichment."""

import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Body, Depends, Path, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppError
from app.core.security import get_admin_user, get_current_user
from app.database import get_db
from app.models.enrichment import EnrichmentSource
from app.models.user import User
from app.schemas.enrichment import (
    EnrichEntityRequest,
    EnrichmentActivityResponse,
    EnrichmentBackfillRequest,
    EnrichmentCoverageResponse,
    EnrichmentKeyResponse,
    EnrichmentKeyUpdate,
    EnrichmentPauseRequest,
    EnrichmentRetryResponse,
    EnrichmentSourceResponse,
    EnrichmentSourceUpdate,
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
    """Admin: update a source's enablement, trigger mode, rate limit or budget.
    Only fields present in the body are applied. A rate above the source's documented
    ceiling (with a key, its keyed ceiling) is refused with 400. Keys are set
    under ``/enrichment/keys``.
    """
    source = await db.get(EnrichmentSource, source_id)
    if not source:
        raise AppError(code="not_found", message="Enrichment source not found", status_code=404)

    if body.rate_limit_config is not None:
        from app.enrichment.pipeline import resolve_api_key

        has_key = bool(await resolve_api_key(source, None, db))
        _check_rate_ceiling(source.source_type, body.rate_limit_config, has_key)

    if body.is_enabled is not None:
        source.is_enabled = body.is_enabled
    if body.trigger_mode is not None:
        source.trigger_mode = body.trigger_mode
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


@router.get("/coverage", response_model=EnrichmentCoverageResponse)
async def get_enrichment_coverage(
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Admin: how full each column a source fills is, the sources that fill it,
    and what to do about the rest (``action``: a backfill through a lookup
    source, AI research, or none when jobs fill it on their ``cadence``)."""
    from app.enrichment.console import coverage

    return {"fields": await coverage(db)}


@router.get("/activity", response_model=EnrichmentActivityResponse)
async def get_enrichment_activity(
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Admin: the queue by lane (waiting, put off), the lookups that gave up per
    source, and each source's requests over the last 24 hours (null when Redis
    can't say)."""
    from app.enrichment.console import activity

    return await activity(db)


@router.post("/retry", response_model=EnrichmentRetryResponse)
async def retry_failed_lookups(
    source_type: str | None = Query(None, description="Only this source's lookups, e.g. greynoise"),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Admin: queue again the lookups that gave up after repeated errors, with
    their attempts reset."""
    from app.enrichment.queue import retry_failed

    return {"queued": await retry_failed(db, source_type)}


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


# --- Keys (Settings → Engine → Enrichment → Keys) ---


@router.get("/keys", response_model=list[EnrichmentKeyResponse])
async def list_enrichment_keys(
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Admin: one row per API key enrichment uses: the sources it serves, whether
    the shared key is set, rejected, missing or optional, and whether the caller
    has an own key. Keys are never returned."""
    from app.enrichment.keys import list_keys

    return await list_keys(db, user.id)


@router.put("/keys/{key_id}")
async def set_enrichment_key(
    key_id: str = Path(..., description="Credential id, e.g. nvd_api_key or abuse_ch"),
    body: EnrichmentKeyUpdate = Body(...),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Admin: set or (with an empty key) remove the shared key every lookup and
    job of the credential's sources uses."""
    from app.enrichment.keys import UnknownKey, set_shared_key

    try:
        await set_shared_key(db, key_id, body.api_key)
    except UnknownKey as e:
        raise AppError(code="not_found", message=f"Unknown key: {key_id}", status_code=404) from e
    return {"id": key_id, "set": bool(body.api_key)}


@router.put("/keys/{key_id}/mine")
async def set_my_enrichment_key(
    key_id: str = Path(..., description="Credential id, e.g. virustotal"),
    body: EnrichmentKeyUpdate = Body(...),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Set or (with an empty key) remove the caller's own key: it replaces the
    shared key for the lookups the caller starts."""
    from app.enrichment.keys import UnknownKey, set_my_key

    try:
        await set_my_key(db, key_id, user.id, body.api_key)
    except UnknownKey as e:
        raise AppError(code="not_found", message=f"Unknown key: {key_id}", status_code=404) from e
    return {"id": key_id, "mine": bool(body.api_key)}


@router.post("/keys/{key_id}/test")
async def test_enrichment_key(
    key_id: str = Path(..., description="Credential id"),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Admin: probe the shared key through one of its sources. ``status`` is ok,
    rejected (the source turned the key down), unreachable (it did not answer),
    missing or untestable. A probe the gateway refuses (rate limit, pause)
    answers 429/503 and says nothing about the key."""
    from app.enrichment.gateway import GatewayError, GatewayUnavailable
    from app.enrichment.keys import UnknownKey, test_key

    try:
        return await test_key(db, key_id)
    except UnknownKey as e:
        raise AppError(code="not_found", message=f"Unknown key: {key_id}", status_code=404) from e
    except GatewayError as e:
        raise AppError(
            code=e.status, message=str(e), status_code=503 if isinstance(e, GatewayUnavailable) else 429
        ) from e


# --- Entity Enrichment ---


#: The column each entity type is looked up by; every other type uses ``name``.
_LOOKUP_VALUE = {"cve": "cve_id", "ttp": "technique_id", "observable": "value", "ransomware_victim": "domain"}


def _lookup_column(entity_type: str, source_types: list[str] | None) -> str:
    """The column a lookup reads: the manifest's ``lookup_column`` when the
    request names one source that declares it, else ``_LOOKUP_VALUE``, else
    ``name``."""
    from app.enrichment.registry import SOURCE_REGISTRY

    if source_types and len(source_types) == 1:
        cls = SOURCE_REGISTRY.get(source_types[0])
        lookup = getattr(cls, "lookup_column", None) if cls else None
        if callable(lookup) and entity_type in getattr(cls, "applies_to", {}):
            column = lookup(entity_type)
            if column != "name":
                return column
    return _LOOKUP_VALUE.get(entity_type, "name")


@router.post("/enrich")
async def enrich_entity(
    body: EnrichEntityRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """On-demand enrichment for a specific entity. Uses the pipeline: cache, then each source's gateway.

    Sources the gateway refused (rate limited, breaker open, budget used up)
    are queued to retry on the enrichment queue and listed in ``queued``."""
    from app.enrichment.entity_updater import _get_model_map
    from app.enrichment.pipeline import enrich_entity as pipeline_enrich

    # The value each source looks up: the entity's identifier for CVEs, TTPs
    # and observables (stored refanged/canonical), its name for the rest.
    model_cls = _get_model_map().get(body.entity_type)
    if model_cls is None:
        raise AppError(code="invalid_entity_type", message="Unsupported entity type", status_code=400)
    entity = await db.get(model_cls, body.entity_id)
    if entity is None:
        raise AppError(code="not_found", message=f"{body.entity_type} not found", status_code=404)
    # A victim is looked up by its domain; one with no domain falls back to its name.
    entity_value: str | None = getattr(entity, _lookup_column(body.entity_type, body.source_types), None) or getattr(
        entity, "name", None
    )
    if not entity_value:
        raise AppError(code="no_lookup_value", message="Entity has nothing to look up by", status_code=400)
    adapter_entity_type = body.entity_type

    results = await pipeline_enrich(
        entity_type=adapter_entity_type,
        entity_id=body.entity_id,
        entity_value=entity_value,
        db=db,
        user_id=user.id,
        trigger="manual",
        source_types=body.source_types,
        refresh=body.refresh,
    )
    # Write what came back onto the entity's columns, as the queue does.
    from app.enrichment.entity_updater import apply_enrichment_results_to_entity

    await apply_enrichment_results_to_entity(db, adapter_entity_type, body.entity_id, results)

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
            lane=body.lane,
            source_types=[r["source_type"]],
            requested_by=user.id,
            due_at=due_at,
        )

    return {
        "entity_type": body.entity_type,
        "entity_id": str(body.entity_id),
        "lane": body.lane,
        "results": results,
        "queued": queued,
    }
