"""Enrichment pipeline — orchestrates enrichment with caching, rate limiting, and key resolution."""

import logging
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.encryption import decrypt_value
from app.enrichment.rate_limiter import RedisBudgetTracker, RedisRateLimiter
from app.enrichment.registry import ADAPTER_REGISTRY, SHARED_KEY_GROUPS, get_adapter
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
    """Resolve API key: user override > global default > shared key group sibling."""
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
    adapter_cls = ADAPTER_REGISTRY.get(source.source_type)
    shared_group = getattr(adapter_cls, "shared_key_group", None) if adapter_cls else None
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

    return None


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
        trigger: Trigger mode filter (auto, scheduled, manual).
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

        # Resolve API key (user override > global)
        api_key = await resolve_api_key(source, user_id, db)

        adapter = get_adapter(source.source_type, api_key=api_key, config=source.config)

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
            results.append(
                {
                    "source_type": source.source_type,
                    "status": "cached",
                    "parsed_data": existing.parsed_data,
                }
            )
            continue

        # Check daily budget (only for actual API calls, after cache check)
        if source.daily_budget is not None:
            try:
                budget_tracker = RedisBudgetTracker(source.source_type)
                within_budget = await budget_tracker.check_and_increment(source.daily_budget)
            except Exception:
                logger.warning("Budget tracker unavailable for %s, proceeding", source.source_type)
                within_budget = True
            if not within_budget:
                results.append(
                    {
                        "source_type": source.source_type,
                        "status": "budget_exhausted",
                    }
                )
                continue

        # Check rate limit
        limiter = RedisRateLimiter(source.source_type, source.rate_limit_config)
        try:
            allowed = await limiter.check()
        except Exception:
            logger.warning("Rate limiter unavailable for %s, proceeding", source.source_type)
            allowed = True

        if not allowed:
            logger.info("Rate limited for source %s, skipping", source.source_type)
            results.append(
                {
                    "source_type": source.source_type,
                    "status": "rate_limited",
                }
            )
            continue

        # Call adapter
        try:
            enrichment_data = await adapter.enrich(adapter_entity_type, entity_value)

            now = datetime.now(UTC)
            er = EnrichmentResult(
                entity_type=entity_type,
                entity_id=entity_id,
                source_type=source.source_type,
                raw_response=enrichment_data.raw_response,
                parsed_data=enrichment_data.parsed_data,
                enriched_at=now,
                expires_at=now + timedelta(hours=enrichment_data.ttl_hours),
                status="success",
            )
            db.add(er)

            results.append(
                {
                    "source_type": source.source_type,
                    "status": "success",
                    "parsed_data": enrichment_data.parsed_data,
                }
            )

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
