"""Shared filter resolution for Atlas calendar + map endpoints.

Both endpoints accept the same set of filters (date range, feed/category, entity,
region, campaign, saved search). This helper builds the candidate Entry id set
from those filters so each endpoint can group/aggregate over it differently.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, date, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppError
from app.models.campaign import CampaignEntry
from app.models.country import Country, EntryCountry
from app.models.cve import EntryCVE
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.malware_family import EntryMalware
from app.models.product import EntryProduct
from app.models.saved_search import SavedSearch
from app.models.threat_actor import EntryThreatActor
from app.models.ttp import EntryTTP
from app.models.vendor import EntryVendor

ENTITY_JUNCTION_MAP: dict[str, tuple[type, str]] = {
    "threat_actor": (EntryThreatActor, "threat_actor_id"),
    "malware": (EntryMalware, "malware_family_id"),
    "cve": (EntryCVE, "cve_id"),
    "ttp": (EntryTTP, "ttp_id"),
    "vendor": (EntryVendor, "vendor_id"),
    "product": (EntryProduct, "product_id"),
    "country": (EntryCountry, "country_id"),
}


def _to_utc_start(d: date) -> datetime:
    return datetime(d.year, d.month, d.day, tzinfo=UTC)


def _to_utc_end(d: date) -> datetime:
    # End of day, inclusive
    return datetime(d.year, d.month, d.day, 23, 59, 59, 999999, tzinfo=UTC)


async def build_atlas_entry_id_query(
    db: AsyncSession,
    *,
    from_: date,
    to: date,
    feed_id: uuid.UUID | None = None,
    category_id: uuid.UUID | None = None,
    entity_type: str | None = None,
    entity_id: uuid.UUID | None = None,
    region: str | None = None,
    campaign_id: uuid.UUID | None = None,
    saved_search_id: uuid.UUID | None = None,
):
    """Return a SELECT yielding Entry.id for entries matching the atlas filter set.

    Returns None when the filter set is provably empty (e.g. saved search with no hits).
    """
    start = _to_utc_start(from_)
    end = _to_utc_end(to)

    query = select(Entry.id).where(Entry.published_at >= start, Entry.published_at <= end)

    if feed_id is not None:
        # Specific feed view: include even when muted (matches /entries behavior).
        query = query.where(Entry.feed_id == feed_id)
    else:
        # Aggregate views exclude muted feeds, mirroring the entries-list filter
        # so a country/date count never includes entries the side panel can't show.
        muted_filter = select(Feed.id).where(Feed.is_muted == False)  # noqa: E712
        if category_id is not None:
            muted_filter = muted_filter.where(Feed.category_id == category_id)
        query = query.where(Entry.feed_id.in_(muted_filter))

    if entity_type and entity_id is not None:
        from app.intelligence.correlation import entry_scope_junction

        scope = entry_scope_junction(entity_type)
        if scope is None:
            raise AppError(
                code="bad_request",
                message=f"Unsupported entity_type: {entity_type}",
                status_code=422,
            )
        junction_cls, id_col = scope
        query = query.where(Entry.id.in_(select(junction_cls.entry_id).where(id_col == entity_id)))

    if region is not None:
        query = query.where(
            Entry.id.in_(
                select(EntryCountry.entry_id)
                .join(Country, Country.id == EntryCountry.country_id)
                .where(Country.region == region)
            )
        )

    if campaign_id is not None:
        query = query.where(
            Entry.id.in_(select(CampaignEntry.entry_id).where(CampaignEntry.campaign_id == campaign_id))
        )

    if saved_search_id is not None:
        saved = await db.get(SavedSearch, saved_search_id)
        if saved is None:
            raise AppError(code="not_found", message="Saved search not found", status_code=404)

        entry_ids = await _resolve_saved_search_ids(db, saved)
        if entry_ids is None:
            return None
        if not entry_ids:
            return None
        query = query.where(Entry.id.in_(entry_ids))

    return query


async def _resolve_saved_search_ids(db: AsyncSession, saved: SavedSearch) -> list[uuid.UUID] | None:
    """Run a saved search through Meilisearch and return matching entry UUIDs.

    Returns None when the search has no usable query (treat as empty result).
    """
    from app.search.meili_builder import execute_entry_search
    from app.search.query_parser import ParseError, parse_query
    from app.search.query_planner import build_execution_plan, resolve_deferred_filters

    query_str = (saved.query or saved.name or "").strip()
    if not query_str:
        return None

    try:
        ast = parse_query(query_str)
    except ParseError:
        return None

    plan = build_execution_plan(ast)
    await resolve_deferred_filters(db, plan)

    if not (plan.has_entry_queries or plan.meili_query.strip()):
        return None

    constraint = list(plan.db_entry_ids) if plan.db_entry_ids is not None else None
    result = await asyncio.to_thread(execute_entry_search, plan, constraint, 5000, 0)
    ids: list[uuid.UUID] = []
    for hit in result.get("hits", []):
        try:
            ids.append(uuid.UUID(hit["id"]))
        except (KeyError, ValueError):
            continue
    return ids
