"""Redis cache-through layer for expensive correlation queries."""

import json
import logging

from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.services.redis_client import get_redis

logger = logging.getLogger(__name__)

# Prefix bumps cold-cut old cached payloads at deploy without a manual
# flush; stale prior-version keys age out via TTL.
# v2: specificity damping, context_role, adjudication fields.
# v3: graphs carry every claim tier + CWE/mitigation catalog layers; pivots
#     carry rule_coverage and catalog mitigation claim rows.
_PREFIX_PIVOT = "intelfeed:corr:pivot3"
_PREFIX_GRAPH = "intelfeed:corr:graph3"


def _default_ttl() -> int:
    return int(settings.get("correlation_cache_ttl_seconds") or settings.correlation_cache_ttl_seconds)


def pivot_cache_variant(
    *,
    limit_per_type: int = 50,
    min_tier: str | None = None,
    window_days: int | None = None,
    offset: int = 0,
    sort: str = "strength",
) -> str:
    """Cache-key suffix for pivot query parameters.

    Empty for the default parameters so the pre-warmer and default requests
    share a key; parameterized requests get their own entries. The
    relationship min-confidence setting is folded in so toggling it can't
    serve payloads built under a different visibility filter.
    """
    conf = confidence_cache_variant()
    if limit_per_type == 50 and min_tier is None and not window_days and not offset and sort == "strength":
        return conf
    return f":{limit_per_type}:{min_tier or '-'}:{window_days or 0}:{offset}:{sort}{conf}"


def confidence_cache_variant() -> str:
    """Cache-key component for the settings that shape relationship payloads.

    Covers the min-confidence filter plus the specificity/reporting-source
    tuning — changing any of them must miss the cache, not serve payloads
    built under the old values (the classic inert-settings bug). Empty at
    the defaults so the pre-warmer and default requests share keys.
    """
    from app.config import settings as env_settings
    from app.intelligence.relationship_matrix import hidden_relationship_confidences

    parts = []
    hidden = hidden_relationship_confidences()
    if hidden:
        parts.append(f"conf{len(hidden)}")
    raw_weight = env_settings.get("relationship_specificity_weight")
    weight = 0.5 if raw_weight is None else float(raw_weight)
    if weight != 0.5:
        parts.append(f"sw{weight}")
    raw_fold = env_settings.get("relationship_reporting_source_specificity")
    fold = 0.45 if raw_fold is None else float(raw_fold)
    if fold != 0.45:
        parts.append(f"rs{fold}")
    # Evidence structure changes the payload shape; fold the flag + threshold
    # in so toggling either can't serve payloads built under the other state.
    if env_settings.get("relationship_evidence_structure"):
        from app.intelligence.evidence_structure import story_threshold

        parts.append(f"es{story_threshold()}")
    # A visitor's pivots and graphs are built from visible feeds only: they
    # get keys of their own, so neither payload is ever served to the other.
    from app.core.public_access import viewer_is_anonymous

    if viewer_is_anonymous():
        parts.append("visitor")
    return (":" + ":".join(parts)) if parts else ""


def _pivot_key(entity_type: str, entity_id: str, variant: str = "") -> str:
    return f"{_PREFIX_PIVOT}:{entity_type}:{entity_id}{variant}"


def _graph_key(entity_type: str, entity_id: str, depth: int | str, variant: str = "") -> str:
    return f"{_PREFIX_GRAPH}:{entity_type}:{entity_id}:{depth}{variant}"


async def get_cached_pivot(entity_type: str, entity_id: str, variant: str = "") -> dict | None:
    """Get a cached pivot result."""
    try:
        r = await get_redis()
        data = await r.get(_pivot_key(entity_type, entity_id, variant))
        if data:
            return json.loads(data)
    except Exception as e:
        logger.debug(f"Cache miss (error) for pivot {entity_type}/{entity_id}: {e}")
    return None


async def set_cached_pivot(
    entity_type: str, entity_id: str, data: dict, ttl: int | None = None, variant: str = ""
) -> None:
    """Cache a pivot result."""
    try:
        r = await get_redis()
        await r.set(
            _pivot_key(entity_type, entity_id, variant), json.dumps(data, default=str), ex=ttl or _default_ttl()
        )
    except Exception as e:
        logger.debug(f"Failed to cache pivot {entity_type}/{entity_id}: {e}")


async def get_pivot_ttl(entity_type: str, entity_id: str) -> int:
    """Remaining TTL (seconds) for a cached pivot.

    Returns -2 when no cache entry exists, -1 when it exists without an expiry,
    or the remaining seconds otherwise. Used to cheaply check freshness when
    pre-warming, without fetching and decoding the (potentially large) payload.
    """
    try:
        r = await get_redis()
        return await r.ttl(_pivot_key(entity_type, entity_id, confidence_cache_variant()))
    except Exception as e:
        logger.debug(f"Failed to read pivot TTL for {entity_type}/{entity_id}: {e}")
        return -2


async def get_cached_graph(entity_type: str, entity_id: str, depth: int, variant: str = "") -> dict | None:
    """Get a cached graph result."""
    try:
        r = await get_redis()
        data = await r.get(_graph_key(entity_type, entity_id, depth, variant))
        if data:
            return json.loads(data)
    except Exception as e:
        logger.debug(f"Cache miss (error) for graph {entity_type}/{entity_id}/{depth}: {e}")
    return None


async def set_cached_graph(
    entity_type: str, entity_id: str, depth: int, data: dict, ttl: int | None = None, variant: str = ""
) -> None:
    """Cache a graph result."""
    try:
        r = await get_redis()
        await r.set(
            _graph_key(entity_type, entity_id, depth, variant),
            json.dumps(data, default=str),
            ex=ttl or _default_ttl(),
        )
    except Exception as e:
        logger.debug(f"Failed to cache graph {entity_type}/{entity_id}/{depth}: {e}")


async def invalidate_entity_cache(entity_type: str, entity_id: str) -> None:
    """Invalidate all cached results for a specific entity."""
    try:
        r = await get_redis()
        # Scan for pivot keys of any parameter variant, and graph keys at any depth
        pivot_pattern = _pivot_key(entity_type, entity_id, "*")
        graph_pattern = _graph_key(entity_type, entity_id, "*")
        keys_to_delete = [_pivot_key(entity_type, entity_id)]
        async for key in r.scan_iter(match=pivot_pattern, count=100):
            keys_to_delete.append(key)
        async for key in r.scan_iter(match=graph_pattern, count=100):
            keys_to_delete.append(key)
        if keys_to_delete:
            await r.delete(*keys_to_delete)
    except Exception as e:
        logger.debug(f"Failed to invalidate cache for {entity_type}/{entity_id}: {e}")


async def invalidate_entry_caches(db: AsyncSession, entry_id: str) -> None:
    """Invalidate caches for all entities linked to an entry."""
    import uuid

    from sqlalchemy import select

    from app.intelligence.correlation import ENTITY_CONFIG

    entry_uuid = uuid.UUID(entry_id) if isinstance(entry_id, str) else entry_id

    for entity_type, (model, junction, fk_col) in ENTITY_CONFIG.items():
        result = await db.execute(select(fk_col).where(junction.entry_id == entry_uuid))
        for (eid,) in result.all():
            await invalidate_entity_cache(entity_type, str(eid))


async def refresh_top_entities_cache(db: AsyncSession, limit: int = 100, time_budget_seconds: float = 240.0) -> int:
    """Pre-warm pivot cache for the highest-article-count entities.

    Only (re)computes entities whose pivot is not already cached — still-fresh
    entries are left untouched, since they already carry a TTL, so steady-state
    runs do almost no work instead of recomputing all ~900 entities every cycle.
    Stops once the wall-clock budget is spent so the Celery task always exits
    cleanly rather than being killed by its soft time limit; any entities not
    reached are picked up on the next scheduled run. Returns the count computed.
    """
    import time

    from sqlalchemy import select

    from app.intelligence.correlation import ENTITY_CONFIG, pivot_from_entity

    start = time.monotonic()
    refreshed = 0
    budget_exhausted = False

    for entity_type, (model, _, _) in ENTITY_CONFIG.items():
        if budget_exhausted:
            break
        if not hasattr(model, "article_count"):
            continue

        result = await db.execute(select(model.id).order_by(model.article_count.desc()).limit(limit))
        for (entity_id,) in result.all():
            if time.monotonic() - start > time_budget_seconds:
                budget_exhausted = True
                break
            # Skip entities whose pivot is still cached (ttl == -2 means absent).
            if await get_pivot_ttl(entity_type, str(entity_id)) != -2:
                continue
            pivot_data = await pivot_from_entity(db, entity_type, entity_id)
            if pivot_data:
                await set_cached_pivot(entity_type, str(entity_id), pivot_data)
                refreshed += 1

    if budget_exhausted:
        logger.info(
            "refresh_top_entities_cache hit %.0fs budget after %d refreshes",
            time_budget_seconds,
            refreshed,
        )
    return refreshed
