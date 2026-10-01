"""Sector tools — the victim-industry entity (5 tools).

Mirrors the ``/api/sectors`` routes in app/api/intelligence.py and calls the
router functions directly (bypassing FastAPI Depends) so the tool payloads can
never drift from the API responses. Pivot / graph / timeline on a sector come
from the generic correlation tools, which accept every CORRELATABLE type.
"""

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.intelligence import _load_sector
from app.api.intelligence import get_sector_profile as _api_sector_profile
from app.api.intelligence import list_sectors as _api_list_sectors
from app.tools import _tool

_SECTOR_REF = {
    "type": "string",
    "description": "Sector UUID or canonical slug, e.g. 'healthcare' or 'financial-services'",
}


@_tool(
    name="list_sectors",
    description=(
        "List the victim-sector vocabulary (21 closed, seeded industries) with per-sector counts: linked "
        "articles, actors and malware asserted to target it, and leak-site victims in the last 90 days. "
        "Use the slug from here with get_sector / who_targets_sector / sector_victims / pivot_entity."
    ),
    input_schema={
        "properties": {
            "search": {"type": "string", "description": "Match on name, slug or alias (e.g. 'banks')"},
            "sort_by": {
                "type": "string",
                "enum": ["name", "article_count", "last_seen_at", "targeting_actor_count", "victim_count"],
                "default": "article_count",
            },
            "limit": {"type": "integer", "default": 25},
        },
    },
)
async def _list_sectors(
    db: AsyncSession,
    user_id: uuid.UUID,
    search: str | None = None,
    sort_by: str = "article_count",
    limit: int = 25,
) -> dict:
    page = await _api_list_sectors(
        search=search, sort_by=sort_by, sort_order="desc", limit=min(limit, 50), offset=0, user=None, db=db
    )
    return {
        "total": page.total,
        "sectors": [
            {
                "id": str(s.id),
                "slug": s.slug,
                "name": s.name,
                "article_count": s.article_count,
                "targeting_actor_count": s.targeting_actor_count,
                "targeting_malware_count": s.targeting_malware_count,
                "victim_count_90d": s.victim_count,
            }
            for s in page.items
        ],
    }


@_tool(
    name="get_sector",
    description=(
        "Get a sector's victimology profile: description and aliases, who targets it (reported from articles vs "
        "asserted claims), campaigns scoped to it, leak-site victim totals and top ransomware groups, the "
        "country cross-tab, the intel profiles that include it, and recent articles."
    ),
    input_schema={
        "properties": {
            "sector": _SECTOR_REF,
            "window_days": {"type": "integer", "default": 90, "description": "Window for victim/country activity"},
        },
        "required": ["sector"],
    },
)
async def _get_sector(db: AsyncSession, user_id: uuid.UUID, sector: str, window_days: int = 90) -> dict:
    profile = await _api_sector_profile(sector_ref=sector, window_days=window_days, user=None, db=db)
    # Trim the long lists for a model's context; the API carries the full ones.
    profile["reported_actors"] = profile["reported_actors"][:10]
    profile["reported_malware"] = profile["reported_malware"][:10]
    profile["asserted_actors"] = profile["asserted_actors"][:10]
    profile["asserted_malware"] = profile["asserted_malware"][:10]
    profile["victims"]["recent"] = profile["victims"]["recent"][:5]
    profile["recent_entries"] = profile["recent_entries"][:10]
    return profile


@_tool(
    name="who_targets_sector",
    description=(
        "Rank the threat actors and malware families targeting a sector. 'reported' rows are ranked by how many "
        "articles describe both the actor/family and the sector being hit; 'asserted' rows carry an explicit "
        "targets-sector claim with its source (rollup, enrichment, seed, analyst) and evidence count."
    ),
    input_schema={
        "properties": {
            "sector": _SECTOR_REF,
            "limit": {"type": "integer", "default": 15, "description": "Rows per list"},
        },
        "required": ["sector"],
    },
)
async def _who_targets_sector(db: AsyncSession, user_id: uuid.UUID, sector: str, limit: int = 15) -> dict:
    profile = await _api_sector_profile(sector_ref=sector, window_days=90, user=None, db=db)
    n = max(1, min(limit, 50))
    return {
        "sector": profile["sector"],
        "reported_actors": profile["reported_actors"][:n],
        "reported_malware": profile["reported_malware"][:n],
        "asserted_actors": profile["asserted_actors"][:n],
        "asserted_malware": profile["asserted_malware"][:n],
    }


@_tool(
    name="set_target_sector",
    description=(
        "Assert or withdraw that a threat actor or malware family targets a sector (an analyst claim on the "
        "target-sector junction; the profile's sector chips are rebuilt from it). action='add' upgrades an "
        "existing rolled-up or enriched claim to the analyst's; action='remove' withdraws the claim — the "
        "nightly rollup re-asserts it if the entity's own articles still carry the evidence."
    ),
    input_schema={
        "properties": {
            "entity_type": {"type": "string", "enum": ["threat_actor", "malware"]},
            "entity_id": {"type": "string", "description": "Actor or malware family UUID"},
            "sector": _SECTOR_REF,
            "action": {"type": "string", "enum": ["add", "remove"], "default": "add"},
        },
        "required": ["entity_type", "entity_id", "sector"],
    },
    mutating=True,
)
async def _set_target_sector(
    db: AsyncSession, user_id: uuid.UUID, entity_type: str, entity_id: str, sector: str, action: str = "add"
) -> dict:
    from app.core.exceptions import AppError
    from app.intelligence.correlation_cache import invalidate_entity_cache
    from app.services.claim_provenance import record_claim
    from app.services.sector_links import (
        add_target_sector,
        junction_for,
        list_target_sectors,
        refresh_targeted_sectors_cache,
        remove_target_sector,
    )

    try:
        model, _, _ = junction_for(entity_type)
    except ValueError as exc:
        return {"error": str(exc)}
    eid = uuid.UUID(entity_id)
    entity = (await db.execute(select(model).where(model.id == eid))).scalar_one_or_none()
    if entity is None:
        return {"error": f"{entity_type} not found"}
    try:
        sector_row = await _load_sector(db, sector)
    except AppError as exc:
        return {"error": exc.message}
    if action == "remove":
        changed = await remove_target_sector(db, entity_type, eid, sector_row.id)
    else:
        changed = await add_target_sector(db, entity_type, eid, sector_row.id, "analyst")
    labels = await refresh_targeted_sectors_cache(db, entity_type, entity)
    if changed:
        await record_claim(
            db,
            entity_type=entity_type,
            entity_id=eid,
            field="targeted_sectors",
            value=labels,
            source_kind="analyst",
            created_by=user_id,
        )
        await invalidate_entity_cache(entity_type, entity_id)
        await invalidate_entity_cache("sector", str(sector_row.id))
    return {
        "entity_type": entity_type,
        "entity_id": entity_id,
        "sector": {"id": str(sector_row.id), "slug": sector_row.slug, "name": sector_row.name},
        "action": action,
        "changed": changed,
        "target_sectors": await list_target_sectors(db, entity_type, eid),
    }


@_tool(
    name="sector_victims",
    description=(
        "Leak-site ransomware victims in a sector: totals (all time and in the window), a 12-month monthly "
        "series, the top ransomware groups posting victims in that sector, the victim-country breakdown and "
        "the most recent disclosures."
    ),
    input_schema={
        "properties": {
            "sector": _SECTOR_REF,
            "window_days": {"type": "integer", "default": 90},
            "limit": {"type": "integer", "default": 20, "description": "Recent disclosures to return"},
        },
        "required": ["sector"],
    },
)
async def _sector_victims(
    db: AsyncSession, user_id: uuid.UUID, sector: str, window_days: int = 90, limit: int = 20
) -> dict:
    profile = await _api_sector_profile(sector_ref=sector, window_days=window_days, user=None, db=db)
    victims = profile["victims"]
    return {
        "sector": profile["sector"],
        "window_days": window_days,
        "total": victims["total"],
        "in_window": victims["in_window"],
        "monthly": victims["monthly"],
        "top_groups": victims["top_groups"],
        "countries": [c for c in profile["countries"] if c["victim_count"]],
        "recent": victims["recent"][: max(1, min(limit, 20))],
    }
