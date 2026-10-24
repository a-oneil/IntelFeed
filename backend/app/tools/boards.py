"""Workbench boards — the Threats board, intel profiles, the coverage workspace,
tags and an entity's latest developments (7 tools, all read-only).

Each wraps the API route that serves the same page, called with every argument
spelled out: a route function's own defaults are FastAPI Query/Path objects, and
leaving one unset hands that object to the query instead of a value.
"""

import uuid

from fastapi.encoders import jsonable_encoder
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.coverage_workspace import get_coverage_workspace as _api_coverage_workspace
from app.api.engine import entity_whats_new as _api_whats_new
from app.api.intel_profiles import get_intel_profile as _api_get_profile
from app.api.intel_profiles import get_profile_threat_surface as _api_profile_surface
from app.api.intel_profiles import list_intel_profiles as _api_list_profiles
from app.api.tags import list_tags as _api_list_tags
from app.api.threat_board import get_threat_board as _api_threat_board
from app.core.exceptions import AppError
from app.models.user import User
from app.tools import _tool

_BOARD_WINDOWS = ["7d", "14d", "30d"]
_BOARD_FACETS = ["threats", "vulns", "all"]
_COVERAGE_WINDOWS = ["7d", "14d", "30d", "90d", "all"]
_COVERAGE_TYPES = ["threat_actor", "malware", "cve", "ttp"]


async def _user(db: AsyncSession, user_id: uuid.UUID) -> User | None:
    return await db.get(User, user_id)


async def _call(db: AsyncSession, user_id: uuid.UUID, fn, **kwargs) -> dict | list:
    user = await _user(db, user_id)
    if user is None:
        return {"error": "User not found"}
    try:
        result = await fn(user=user, db=db, **kwargs)
    except AppError as e:
        return {"error": e.message}
    return jsonable_encoder(result)


def _clamp(value: int, low: int, high: int) -> int:
    return max(low, min(high, int(value)))


@_tool(
    name="get_threat_board",
    description=(
        "The Threats board: actors/malware and exploited CVEs ranked over a recency window by how many "
        "distinct stories carried them (not raw article or outlet counts). Each row leads with its lead "
        "headline, the cached AI brief when present, source hosts, story/echo counts, the analyst's handled "
        "state, prior-rule inventory and, for CVEs, exposure lift (KEV/EPSS/weaponized) and detection "
        "posture. Rows with is_story are story threads that resolved to no entity. Use it for 'what is "
        "happening right now' and to choose what to research next."
    ),
    input_schema={
        "properties": {
            "window": {"type": "string", "enum": _BOARD_WINDOWS, "default": "14d"},
            "facet": {
                "type": "string",
                "enum": _BOARD_FACETS,
                "default": "threats",
                "description": "threats = actor/malware rows; vulns = CVE rows; all = both interleaved",
            },
            "limit": {"type": "integer", "default": 25, "description": "1-100"},
            "min_attention": {"type": "integer", "default": 3, "description": "Minimum distinct source domains"},
            "include_handled": {"type": "boolean", "default": False},
        },
        "required": [],
    },
    mutating=False,
)
async def _get_threat_board(
    db: AsyncSession,
    user_id: uuid.UUID,
    window: str = "14d",
    facet: str = "threats",
    limit: int = 25,
    min_attention: int = 3,
    include_handled: bool = False,
) -> dict:
    if window not in _BOARD_WINDOWS or facet not in _BOARD_FACETS:
        return {"error": f"window must be one of {_BOARD_WINDOWS}; facet one of {_BOARD_FACETS}"}
    return await _call(
        db,
        user_id,
        _api_threat_board,
        window=window,
        facet=facet,
        limit=_clamp(limit, 1, 100),
        min_attention=_clamp(min_attention, 1, 50),
        include_handled=bool(include_handled),
    )


@_tool(
    name="list_intel_profiles",
    description=(
        "List the instance's intel profiles (named scopes such as a customer or portfolio: the regions, "
        "verticals and technology they care about), alphabetical. Use a profile id with "
        "get_profile_threat_surface to see which actors and malware target it."
    ),
    input_schema={
        "properties": {
            "limit": {"type": "integer", "default": 50, "description": "1-200"},
            "offset": {"type": "integer", "default": 0},
        },
        "required": [],
    },
    mutating=False,
)
async def _list_intel_profiles(db: AsyncSession, user_id: uuid.UUID, limit: int = 50, offset: int = 0) -> dict:
    return await _call(db, user_id, _api_list_profiles, limit=_clamp(limit, 1, 200), offset=max(0, int(offset)))


@_tool(
    name="get_intel_profile",
    description="One intel profile with its countries (resolved names), sectors (labels) and other scope fields.",
    input_schema={
        "properties": {"profile_id": {"type": "string", "description": "Intel profile UUID"}},
        "required": ["profile_id"],
    },
    mutating=False,
)
async def _get_intel_profile(db: AsyncSession, user_id: uuid.UUID, profile_id: str) -> dict:
    try:
        pid = uuid.UUID(str(profile_id))
    except ValueError:
        return {"error": "profile_id must be a UUID"}
    return await _call(db, user_id, _api_get_profile, profile_id=pid)


@_tool(
    name="get_profile_threat_surface",
    description=(
        "The threat surface for one intel profile: actors and malware active against its regions x "
        "verticals, each with why-matched evidence (which region/sector, how many articles)."
    ),
    input_schema={
        "properties": {
            "profile_id": {"type": "string", "description": "Intel profile UUID"},
            "limit": {"type": "integer", "default": 25, "description": "Matched entities per type, 1-100"},
        },
        "required": ["profile_id"],
    },
    mutating=False,
)
async def _get_profile_threat_surface(db: AsyncSession, user_id: uuid.UUID, profile_id: str, limit: int = 25) -> dict:
    try:
        pid = uuid.UUID(str(profile_id))
    except ValueError:
        return {"error": "profile_id must be a UUID"}
    return await _call(db, user_id, _api_profile_surface, profile_id=pid, limit=_clamp(limit, 1, 100))


@_tool(
    name="get_coverage_workspace",
    description=(
        "Detection coverage workspace for one threat (actor, malware, CVE or ATT&CK technique) over a window: "
        "its recent articles and the behaviours extracted from them, each with the quote it came from, the "
        "telemetry channels it needs and whether enabled telemetry can see it. A behaviour flagged "
        "below_line has no matching telemetry: a sourcing gap, not a detection gap."
    ),
    input_schema={
        "properties": {
            "entity_type": {"type": "string", "enum": _COVERAGE_TYPES},
            "entity_key": {"type": "string", "description": "Entity UUID, CVE id or ATT&CK technique id"},
            "window": {"type": "string", "enum": _COVERAGE_WINDOWS, "default": "14d"},
        },
        "required": ["entity_type", "entity_key"],
    },
    mutating=False,
)
async def _get_coverage_workspace(
    db: AsyncSession, user_id: uuid.UUID, entity_type: str, entity_key: str, window: str = "14d"
) -> dict:
    if entity_type not in _COVERAGE_TYPES or window not in _COVERAGE_WINDOWS:
        return {"error": f"entity_type must be one of {_COVERAGE_TYPES}; window one of {_COVERAGE_WINDOWS}"}
    return await _call(
        db, user_id, _api_coverage_workspace, entity_type=entity_type, entity_key=str(entity_key), window=window
    )


@_tool(
    name="list_tags",
    description=(
        "List every tag with its entry count, by name. The tag list is shared; the counts are the caller's "
        "view (their own assignments of a personal tag, everyone's of a global one)."
    ),
    input_schema={"properties": {}, "required": []},
    mutating=False,
)
async def _list_tags(db: AsyncSession, user_id: uuid.UUID) -> dict:
    result = await _call(db, user_id, _api_list_tags)
    return result if isinstance(result, dict) else {"tags": result}


@_tool(
    name="get_entity_whats_new",
    description=(
        "Latest developments for one entity: recent novelty and severity signals (first mention, new "
        "technique, new victim sector, exploitation news...) on articles linked to it. scoped=true keeps "
        "only signals whose subject is this entity, as the profile page does."
    ),
    input_schema={
        "properties": {
            "entity_type": {"type": "string", "description": "threat_actor, malware, cve, ttp, tool, ..."},
            "entity_id": {"type": "string", "description": "Entity UUID"},
            "days": {"type": "integer", "default": 14, "description": "Look-back window, capped at 90"},
            "scoped": {"type": "boolean", "default": True},
        },
        "required": ["entity_type", "entity_id"],
    },
    mutating=False,
)
async def _get_entity_whats_new(
    db: AsyncSession, user_id: uuid.UUID, entity_type: str, entity_id: str, days: int = 14, scoped: bool = True
) -> dict:
    result = await _call(
        db,
        user_id,
        _api_whats_new,
        entity_type=str(entity_type),
        entity_id=str(entity_id),
        days=_clamp(days, 1, 90),
        scoped=bool(scoped),
    )
    return result if isinstance(result, dict) else {"developments": result}
