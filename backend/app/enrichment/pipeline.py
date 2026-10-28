"""Enrichment pipeline — orchestrates enrichment with caching, key resolution and the source gateways."""

import logging
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.encryption import decrypt_value
from app.enrichment.base import EnrichmentData
from app.enrichment.context import store_context
from app.enrichment.entity_updater import apply_enrichment_results_to_entity
from app.enrichment.gateway import MAX_TOKEN_WAIT, BreakerOpen, GatewayError, RateLimited, SourceGateway
from app.enrichment.registry import (
    ADAPTER_REGISTRY,
    SHARED_KEY_GROUPS,
    SOURCE_REGISTRY,
    adapter_for_source,
    source_gateway,
)
from app.models.enrichment import EnrichmentResult, EnrichmentSource, UserEnrichmentOverride

logger = logging.getLogger(__name__)

# Confidence level ordering for threshold comparison
_CONFIDENCE_LEVELS = {"high": 3, "medium": 2, "low": 1}
_CONFIDENCE_FLOAT_THRESHOLDS = {"high": 0.7, "medium": 0.4, "low": 0.0}


def _passes_confidence_threshold(
    source: "EnrichmentSource",
    entity_confidence: str | None,
    entity_base_confidence: float | None,
) -> bool:
    """Check if entity confidence meets the source's minimum threshold.

    Returns True if the entity should be enriched by this source.
    """
    threshold = source.min_confidence_threshold
    if not threshold or threshold == "low":
        return True  # "low" threshold means enrich everything

    if entity_confidence is None and entity_base_confidence is None:
        return True  # Non-IOC entities or IOCs without confidence — allow

    # Check by string confidence level
    if entity_confidence:
        entity_level = _CONFIDENCE_LEVELS.get(entity_confidence, 0)
        threshold_level = _CONFIDENCE_LEVELS.get(threshold, 0)
        if entity_level >= threshold_level:
            return True

    # Fallback: check by numeric base_confidence
    if entity_base_confidence is not None:
        min_float = _CONFIDENCE_FLOAT_THRESHOLDS.get(threshold, 0.0)
        if entity_base_confidence >= min_float:
            return True

    return False


async def resolve_api_key(
    source: EnrichmentSource,
    user_id: uuid.UUID | None,
    db: AsyncSession,
) -> str | None:
    """Resolve API key: user override > the source's key > a shared key group
    sibling > the source's ``key_setting`` instance setting."""
    # 1. User override for this specific source
    if user_id:
        result = await db.execute(
            select(UserEnrichmentOverride)
            .where(UserEnrichmentOverride.source_id == source.id)
            .where(UserEnrichmentOverride.created_by == user_id)
        )
        user_override = result.scalar_one_or_none()
        if user_override and user_override.api_key_encrypted:
            return decrypt_value(user_override.api_key_encrypted)

    # 2. Global key on this source
    if source.api_key_encrypted:
        return decrypt_value(source.api_key_encrypted)

    # 3. Shared key group fallback — check sibling sources for a key
    source_cls = SOURCE_REGISTRY.get(source.source_type)
    shared_group = source_cls.shared_key_group if source_cls else None
    if shared_group:
        sibling_types = [st for st in SHARED_KEY_GROUPS.get(shared_group, []) if st != source.source_type]
        if sibling_types:
            # Check user overrides for siblings first
            if user_id:
                sibling_overrides = await db.execute(
                    select(UserEnrichmentOverride)
                    .join(EnrichmentSource, UserEnrichmentOverride.source_id == EnrichmentSource.id)
                    .where(
                        UserEnrichmentOverride.created_by == user_id,
                        EnrichmentSource.source_type.in_(sibling_types),
                        UserEnrichmentOverride.api_key_encrypted.isnot(None),
                    )
                    .limit(1)
                )
                sib_override = sibling_overrides.scalar_one_or_none()
                if sib_override and sib_override.api_key_encrypted:
                    return decrypt_value(sib_override.api_key_encrypted)

            # Check global keys on siblings
            sibling_sources = await db.execute(
                select(EnrichmentSource)
                .where(
                    EnrichmentSource.source_type.in_(sibling_types),
                    EnrichmentSource.api_key_encrypted.isnot(None),
                )
                .limit(1)
            )
            sib_source = sibling_sources.scalar_one_or_none()
            if sib_source and sib_source.api_key_encrypted:
                return decrypt_value(sib_source.api_key_encrypted)

    # 4. The instance-wide setting the source names (nvd_api_key, github_token)
    return await _key_from_setting(source.source_type, db)


async def _key_from_setting(source_type: str, db: AsyncSession) -> str | None:
    source_cls = SOURCE_REGISTRY.get(source_type)
    if not (source_cls and source_cls.key_setting):
        return None
    from app.services.system_settings import get_setting

    return await get_setting(source_cls.key_setting, db) or None


async def gateway_for(
    db: AsyncSession,
    source_type: str,
    max_wait: float = MAX_TOKEN_WAIT,
) -> tuple[SourceGateway, str | None]:
    """The gateway and key for calls made outside ``enrich_entity`` (scheduled
    jobs, bulk syncs): the source row's rate limit, budget and key, resolved
    exactly as per-entity lookups resolve it, so both draw on one allowance.
    Without a row the manifest's quota applies."""
    source = (
        await db.execute(select(EnrichmentSource).where(EnrichmentSource.source_type == source_type))
    ).scalar_one_or_none()
    if source is None:
        quota = SOURCE_REGISTRY[source_type].quota
        source = EnrichmentSource(
            source_type=source_type,
            rate_limit_config=quota.rate_limit_config,
            daily_budget=quota.daily_budget,
        )
        api_key = await _key_from_setting(source_type, db)
    else:
        api_key = await resolve_api_key(source, None, db)
    return source_gateway(source, api_key, max_wait=max_wait), api_key


async def get_cached_result(
    db: AsyncSession,
    entity_type: str,
    entity_id: uuid.UUID,
    source_type: str,
) -> EnrichmentResult | None:
    """Get a cached enrichment result if it exists and hasn't expired."""
    result = await db.execute(
        select(EnrichmentResult)
        .where(
            EnrichmentResult.entity_type == entity_type,
            EnrichmentResult.entity_id == entity_id,
            EnrichmentResult.source_type == source_type,
            EnrichmentResult.status == "success",
        )
        .order_by(EnrichmentResult.enriched_at.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


async def store_result(
    db: AsyncSession,
    entity_type: str,
    entity_id: uuid.UUID,
    source_type: str,
    data: EnrichmentData,
    existing: EnrichmentResult | None,
) -> None:
    """Keep a source's fresh result for an entity and its context. A new
    enrichment_results row is written only when parsed_data changed from
    ``existing`` (the latest one); otherwise that row stands, as of now."""
    now = datetime.now(UTC)
    expires_at = now + timedelta(hours=data.ttl_hours)
    if existing and existing.parsed_data == data.parsed_data:
        existing.enriched_at, existing.expires_at = now, expires_at
    else:
        db.add(
            EnrichmentResult(
                entity_type=entity_type,
                entity_id=entity_id,
                source_type=source_type,
                raw_response=data.raw_response,
                parsed_data=data.parsed_data,
                enriched_at=now,
                expires_at=expires_at,
                status="success",
            )
        )
    await store_context(
        db, entity_type, entity_id, source_type, data.parsed_data, observed_at=now, expires_at=expires_at
    )


async def apply_catalog_result(
    db: AsyncSession, entity_type: str, entity_id: uuid.UUID, source_type: str, data: EnrichmentData
) -> bool:
    """A catalog job's answer for one entity, handled as a lookup's would be:
    stored, its Context written, its Column outputs applied. Returns True if
    the entity's columns changed."""
    existing = await get_cached_result(db, entity_type, entity_id, source_type)
    await store_result(db, entity_type, entity_id, source_type, data, existing)
    return await apply_enrichment_results_to_entity(
        db, entity_type, entity_id, [{"source_type": source_type, "status": "success", "parsed_data": data.parsed_data}]
    )


async def enrich_entity(
    entity_type: str,
    entity_id: uuid.UUID,
    entity_value: str,
    db: AsyncSession,
    user_id: uuid.UUID | None = None,
    trigger: str = "auto",
    source_types: list[str] | None = None,
    entity_confidence: str | None = None,
    entity_base_confidence: float | None = None,
) -> list[dict]:
    """Enrich an entity from all applicable enabled sources.

    Args:
        entity_type: The entity type (ioc, cve, threat_actor, malware, ttp).
                     For IOCs, pass the subtype (ioc_ipv4, ioc_domain, etc.)
                     as the adapter_entity_type when checking supports_entity.
        entity_id: UUID of the entity.
        entity_value: The entity value to look up (IP, CVE ID, name, etc.).
        db: Database session.
        user_id: Optional user ID for API key resolution.
        trigger: Trigger mode filter (auto, manual).
        source_types: Optional list of specific source types to use.
        entity_confidence: IOC confidence level (high/medium/low) for filtering.
        entity_base_confidence: IOC numeric confidence for filtering.
    """
    results = []

    # Get enabled sources matching trigger mode
    query = select(EnrichmentSource).where(EnrichmentSource.is_enabled == True)  # noqa: E712
    if not source_types:
        query = query.where(EnrichmentSource.trigger_mode == trigger)
    sources_result = await db.execute(query)

    for source in sources_result.scalars():
        if source_types and source.source_type not in source_types:
            continue
        if source.source_type not in ADAPTER_REGISTRY:
            continue  # a catalog source: jobs only, no per-entity lookup

        # Resolve API key (user override > global)
        api_key = await resolve_api_key(source, user_id, db)

        adapter = adapter_for_source(source, api_key)

        # Map base entity type to adapter entity type
        adapter_entity_type = entity_type
        if not adapter.supports_entity(adapter_entity_type):
            continue

        # Check confidence threshold (only for auto-enrichment; manual bypasses)
        if trigger == "auto" and not _passes_confidence_threshold(source, entity_confidence, entity_base_confidence):
            results.append(
                {
                    "source_type": source.source_type,
                    "status": "skipped_low_confidence",
                }
            )
            continue

        # Check cache — skip if fresh result exists (no budget consumed)
        existing = await get_cached_result(db, entity_type, entity_id, source.source_type)
        if existing and existing.expires_at and existing.expires_at > datetime.now(UTC):
            await store_context(
                db,
                entity_type,
                entity_id,
                source.source_type,
                existing.parsed_data,
                observed_at=existing.enriched_at,
                expires_at=existing.expires_at,
            )
            results.append(
                {
                    "source_type": source.source_type,
                    "status": "cached",
                    "parsed_data": existing.parsed_data,
                }
            )
            continue

        # Call adapter. Its gateway enforces the rate limit, daily budget and
        # circuit breaker on each HTTP request it makes.
        try:
            enrichment_data = await adapter.enrich(adapter_entity_type, entity_value)
            await store_result(db, entity_type, entity_id, source.source_type, enrichment_data, existing)

            results.append(
                {
                    "source_type": source.source_type,
                    "status": "success",
                    "parsed_data": enrichment_data.parsed_data,
                }
            )

        except GatewayError as e:
            # Refused or told to back off: not a result, so nothing is stored
            # and the next attempt isn't blocked by a cached error.
            logger.info("Enrichment skipped for %s/%s: %s", source.source_type, entity_value, e)
            outcome = {"source_type": source.source_type, "status": e.status}
            if isinstance(e, RateLimited | BreakerOpen):
                outcome["retry_after"] = round(e.retry_after)
            results.append(outcome)

        except Exception as e:
            logger.warning("Enrichment failed for %s/%s: %s", source.source_type, entity_value, e)
            now = datetime.now(UTC)
            db.add(
                EnrichmentResult(
                    entity_type=entity_type,
                    entity_id=entity_id,
                    source_type=source.source_type,
                    raw_response={"error": str(e)},
                    parsed_data={},
                    enriched_at=now,
                    expires_at=now + timedelta(hours=1),
                    status="error",
                )
            )
            results.append(
                {
                    "source_type": source.source_type,
                    "status": "error",
                    "error": str(e),
                }
            )

    await db.flush()

    return results


async def enrich_entity_auto(
    entity_type: str,
    entity_id: uuid.UUID,
    entity_value: str,
    db: AsyncSession,
    adapter_entity_type: str | None = None,
    entity_confidence: str | None = None,
    entity_base_confidence: float | None = None,
) -> list[dict]:
    """Auto-enrich an entity using sources with trigger_mode='auto'.

    Called automatically after entity extraction. Uses the base entity type
    for storage but the adapter_entity_type for adapter matching.
    """
    return await enrich_entity(
        entity_type=adapter_entity_type or entity_type,
        entity_id=entity_id,
        entity_value=entity_value,
        db=db,
        trigger="auto",
        entity_confidence=entity_confidence,
        entity_base_confidence=entity_base_confidence,
    )
