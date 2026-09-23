"""Landscape tools — watchlist, ransomware tracker, stack exposure, glossary (13 tools).

Mirrors app/api/watchlist.py, app/api/ransomware.py, app/api/exposure.py and
app/api/glossary.py. The read-heavy ransomware/exposure/detect endpoints are
invoked through their router functions (bypassing FastAPI Depends) so the tool
payloads can never drift from the API responses.
"""

import uuid

from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import delete as sa_delete
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.exposure import get_stack_exposure as _api_stack_exposure
from app.api.glossary import _term_response
from app.api.glossary import detect_glossary_terms as _api_detect_terms
from app.api.ransomware import get_group_victims as _api_group_victims
from app.api.ransomware import get_stats as _api_ransomware_stats
from app.api.ransomware import get_victim as _api_get_victim
from app.api.ransomware import list_disclosures as _api_list_disclosures
from app.api.watchlist import _ENTITY_NAME_SOURCES, STACK_ENTITY_TYPES, WATCHABLE_ENTITY_TYPES
from app.core.exceptions import AppError
from app.models.glossary_term import GlossaryTerm
from app.models.user import User
from app.models.user_entity_watch import UserEntityWatch
from app.schemas.glossary import DetectRequest, GlossaryTermCreate
from app.services.entity_names import resolve_entity_names
from app.tools import _tool

_WATCH_TYPES = sorted(WATCHABLE_ENTITY_TYPES)
_WATCH_MODES = ["watch", "mute", "stack"]
_DISCLOSURE_SORTS = ["recent", "group", "sector"]


async def _get_user(db: AsyncSession, user_id: uuid.UUID) -> User | None:
    return await db.get(User, user_id)


def _watch_dict(w: UserEntityWatch, entity_name: str | None) -> dict:
    return {
        "id": str(w.id),
        "entity_type": w.entity_type,
        "entity_id": str(w.entity_id),
        "mode": w.mode,
        "boost": w.boost,
        "entity_name": entity_name,
    }


# ---------------------------------------------------------------------------
# Watchlist
# ---------------------------------------------------------------------------


@_tool(
    name="list_watches",
    description=(
        "List the current user's entity watchlist rows with resolved display names. "
        "Each row has mode 'watch' (priority boost), 'mute' (suppressed), or 'stack' "
        "('I run this' — vendors/products feeding My Stack exposure scoring)."
    ),
    input_schema={
        "properties": {
            "mode": {
                "type": "string",
                "enum": _WATCH_MODES,
                "description": "Optional filter by watch mode",
            },
        },
        "required": [],
    },
    mutating=False,
)
async def _list_watches(db: AsyncSession, user_id: uuid.UUID, mode: str | None = None) -> dict:
    if mode is not None and mode not in _WATCH_MODES:
        return {"error": f"mode must be one of {_WATCH_MODES}"}
    query = select(UserEntityWatch).where(UserEntityWatch.created_by == user_id)
    if mode is not None:
        query = query.where(UserEntityWatch.mode == mode)
    rows = (await db.execute(query)).scalars().all()
    names = await resolve_entity_names(db, rows, _ENTITY_NAME_SOURCES)
    return {
        "watches": [_watch_dict(w, names.get((w.entity_type, w.entity_id))) for w in rows],
        "total": len(rows),
    }


@_tool(
    name="watch_entity",
    description=(
        "Create or update the current user's watch on an entity (upsert on entity type + id). "
        "mode 'watch' boosts the entity in priority scoring, 'mute' suppresses its entries, "
        "'stack' declares 'I run this' and is only valid for vendors and products (feeds My Stack "
        "exposure scoring). boost weights priority scoring (0-5, default 1.0)."
    ),
    input_schema={
        "properties": {
            "entity_type": {
                "type": "string",
                "enum": _WATCH_TYPES,
                "description": "Type of the entity to watch",
            },
            "entity_id": {"type": "string", "description": "UUID of the entity to watch"},
            "mode": {
                "type": "string",
                "enum": _WATCH_MODES,
                "description": "watch | mute | stack (stack: vendor/product only)",
            },
            "boost": {
                "type": "number",
                "description": "Priority-scoring weight, 0.0-5.0 (default 1.0)",
            },
        },
        "required": ["entity_type", "entity_id", "mode"],
    },
    mutating=True,
)
async def _watch_entity(
    db: AsyncSession,
    user_id: uuid.UUID,
    entity_type: str,
    entity_id: str,
    mode: str,
    boost: float = 1.0,
) -> dict:
    if entity_type not in WATCHABLE_ENTITY_TYPES:
        return {"error": f"entity_type must be one of {_WATCH_TYPES}"}
    if mode not in _WATCH_MODES:
        return {"error": f"mode must be one of {_WATCH_MODES}"}
    if mode == "stack" and entity_type not in STACK_ENTITY_TYPES:
        return {"error": f"mode=stack requires entity_type in {sorted(STACK_ENTITY_TYPES)}"}
    if not 0.0 <= boost <= 5.0:
        return {"error": "boost must be between 0.0 and 5.0"}
    try:
        eid = uuid.UUID(entity_id)
    except ValueError:
        return {"error": f"entity_id is not a valid UUID: {entity_id}"}

    # The watch table has no FK on entity_id — guard against dangling watches.
    model, name_col = _ENTITY_NAME_SOURCES[entity_type]
    name_row = (await db.execute(select(name_col).where(model.id == eid))).scalar_one_or_none()
    if name_row is None:
        return {"error": f"No {entity_type} found with id {entity_id}"}

    stmt = pg_insert(UserEntityWatch).values(
        id=uuid.uuid4(),
        created_by=user_id,
        entity_type=entity_type,
        entity_id=eid,
        mode=mode,
        boost=boost,
    )
    stmt = stmt.on_conflict_do_update(
        constraint="uq_user_entity_watch",
        set_={"mode": stmt.excluded.mode, "boost": stmt.excluded.boost},
    )
    await db.execute(stmt)
    await db.flush()
    row = (
        await db.execute(
            select(UserEntityWatch).where(
                UserEntityWatch.created_by == user_id,
                UserEntityWatch.entity_type == entity_type,
                UserEntityWatch.entity_id == eid,
            )
        )
    ).scalar_one()
    return {"status": "saved", "watch": _watch_dict(row, str(name_row))}


@_tool(
    name="unwatch_entity",
    description=(
        "Remove the current user's watch/mute/stack row on an entity. "
        "Reversible (re-add with watch_entity); no confirmation required."
    ),
    input_schema={
        "properties": {
            "entity_type": {
                "type": "string",
                "enum": _WATCH_TYPES,
                "description": "Type of the watched entity",
            },
            "entity_id": {"type": "string", "description": "UUID of the watched entity"},
        },
        "required": ["entity_type", "entity_id"],
    },
    mutating=True,
)
async def _unwatch_entity(db: AsyncSession, user_id: uuid.UUID, entity_type: str, entity_id: str) -> dict:
    try:
        eid = uuid.UUID(entity_id)
    except ValueError:
        return {"error": f"entity_id is not a valid UUID: {entity_id}"}
    result = await db.execute(
        sa_delete(UserEntityWatch).where(
            UserEntityWatch.created_by == user_id,
            UserEntityWatch.entity_type == entity_type,
            UserEntityWatch.entity_id == eid,
        )
    )
    await db.flush()
    if not result.rowcount:
        return {"error": "Watch not found"}
    return {"status": "removed", "entity_type": entity_type, "entity_id": entity_id}


# ---------------------------------------------------------------------------
# Ransomware tracker
# ---------------------------------------------------------------------------


@_tool(
    name="get_ransomware_disclosures",
    description=(
        "Reverse-chronological feed of ransomware leak-site victim disclosures (Leak Watch), with "
        "filters for group name, canonical sector slug, country (ISO code or name), posting recency, "
        "substring search, and the user's watched victims/groups. sort is 'recent', 'group', or "
        "'sector' (newest-first tiebreak). Returns a paginated list; empty when the ransomware "
        "tracker has not synced yet."
    ),
    input_schema={
        "properties": {
            "group": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Filter by ransomware group name(s)",
            },
            "sector": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Filter by canonical sector slug(s)",
            },
            "country": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Filter by country ISO code or name",
            },
            "watched_only": {
                "type": "boolean",
                "description": "Only disclosures hitting the user's watched victims/groups",
            },
            "since": {"type": "integer", "description": "Only postings newer than N days"},
            "q": {"type": "string", "description": "Substring search on victim name/domain or raw group name"},
            "sort": {
                "type": "string",
                "enum": _DISCLOSURE_SORTS,
                "description": "Sort order (default 'recent')",
            },
            "limit": {"type": "integer", "description": "Page size, 1-200 (default 50)"},
            "offset": {"type": "integer", "description": "Rows to skip for pagination"},
        },
        "required": [],
    },
    mutating=False,
)
async def _get_ransomware_disclosures(
    db: AsyncSession,
    user_id: uuid.UUID,
    group: list[str] | None = None,
    sector: list[str] | None = None,
    country: list[str] | None = None,
    watched_only: bool = False,
    since: int | None = None,
    q: str | None = None,
    sort: str = "recent",
    limit: int = 50,
    offset: int = 0,
) -> dict:
    if sort not in _DISCLOSURE_SORTS:
        return {"error": f"sort must be one of {_DISCLOSURE_SORTS}"}
    if since is not None and since < 0:
        return {"error": "since must be >= 0"}
    if not 1 <= limit <= 200:
        return {"error": "limit must be between 1 and 200"}
    if offset < 0:
        return {"error": "offset must be >= 0"}
    user = await _get_user(db, user_id)
    if user is None:
        return {"error": "User not found"}
    page = await _api_list_disclosures(
        group=group,
        sector=sector,
        country=country,
        watched_only=watched_only,
        since=since,
        q=q,
        sort=sort,
        limit=limit,
        offset=offset,
        user=user,
        db=db,
    )
    return page.model_dump(mode="json")


@_tool(
    name="get_ransomware_stats",
    description=(
        "Ransomware Landscape aggregates over a trailing window: victim totals with week-over-week "
        "change, weekly timeseries, top groups (with WoW trend), top sectors, top countries, and the "
        "user's watchlist exposure (watched groups/orgs/sectors vs new disclosures). All-zero when "
        "the ransomware tracker has not synced yet."
    ),
    input_schema={
        "properties": {
            "days": {"type": "integer", "description": "Aggregation window in days, 1-1095 (default 90)"},
        },
        "required": [],
    },
    mutating=False,
)
async def _get_ransomware_stats(db: AsyncSession, user_id: uuid.UUID, days: int = 90) -> dict:
    if not 1 <= days <= 1095:
        return {"error": "days must be between 1 and 1095"}
    user = await _get_user(db, user_id)
    if user is None:
        return {"error": "User not found"}
    stats = await _api_ransomware_stats(days=days, user=user, db=db)
    return stats.model_dump(mode="json")


@_tool(
    name="get_ransomware_victim",
    description=(
        "Fetch one ransomware victim organization by UUID: name/domain/aliases, sector, country, "
        "first/last seen, whether the user watches it, the groups that listed it, and every "
        "leak-site disclosure."
    ),
    input_schema={
        "properties": {
            "victim_id": {"type": "string", "description": "Ransomware victim UUID"},
        },
        "required": ["victim_id"],
    },
    mutating=False,
)
async def _get_ransomware_victim(db: AsyncSession, user_id: uuid.UUID, victim_id: str) -> dict:
    try:
        vid = uuid.UUID(victim_id)
    except ValueError:
        return {"error": f"victim_id is not a valid UUID: {victim_id}"}
    user = await _get_user(db, user_id)
    if user is None:
        return {"error": "User not found"}
    try:
        detail = await _api_get_victim(victim_id=vid, user=user, db=db)
    except HTTPException as exc:
        return {"error": exc.detail}
    return detail.model_dump(mode="json")


@_tool(
    name="get_ransomware_group_victims",
    description=(
        "Paginated list of victim organizations disclosed by a ransomware group (a ThreatActor), "
        "newest activity first. Returns an empty page if the actor has no tracked disclosures."
    ),
    input_schema={
        "properties": {
            "actor_id": {"type": "string", "description": "ThreatActor UUID of the ransomware group"},
            "limit": {"type": "integer", "description": "Page size, 1-200 (default 50)"},
            "offset": {"type": "integer", "description": "Rows to skip for pagination"},
        },
        "required": ["actor_id"],
    },
    mutating=False,
)
async def _get_ransomware_group_victims(
    db: AsyncSession,
    user_id: uuid.UUID,
    actor_id: str,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    try:
        aid = uuid.UUID(actor_id)
    except ValueError:
        return {"error": f"actor_id is not a valid UUID: {actor_id}"}
    if not 1 <= limit <= 200:
        return {"error": "limit must be between 1 and 200"}
    if offset < 0:
        return {"error": "offset must be >= 0"}
    user = await _get_user(db, user_id)
    if user is None:
        return {"error": "User not found"}
    page = await _api_group_victims(actor_id=aid, limit=limit, offset=offset, user=user, db=db)
    return page.model_dump(mode="json")


# ---------------------------------------------------------------------------
# Stack exposure
# ---------------------------------------------------------------------------


@_tool(
    name="get_stack_exposure",
    description=(
        "My Stack exposure board: every CVE affecting the vendors/products the user has declared "
        "as their stack (watchlist mode='stack'), ranked by exposure lift (KEV/EPSS/weaponization "
        "multipliers), each with a detection posture (defended / blind / no_rule) from the org's "
        "telemetry inventory, plus per-asset CVE tallies and the urgency x posture matrix counts. "
        "Empty if the user has no stack entities declared."
    ),
    input_schema={"properties": {}, "required": []},
    mutating=False,
)
async def _get_stack_exposure(db: AsyncSession, user_id: uuid.UUID) -> dict:
    user = await _get_user(db, user_id)
    if user is None:
        return {"error": "User not found"}
    resp = await _api_stack_exposure(user=user, db=db)
    return resp.model_dump(mode="json")


# ---------------------------------------------------------------------------
# Glossary
# ---------------------------------------------------------------------------


@_tool(
    name="list_glossary_terms",
    description=(
        "List security glossary terms alphabetically with optional filters: exact category (e.g. a "
        "NIST CSF function like 'detect'), case-insensitive name substring search, and built-in vs "
        "user-created (is_system). Each term carries maturity, descriptions, technologies, and "
        "search-term aliases."
    ),
    input_schema={
        "properties": {
            "category": {"type": "string", "description": "Filter by exact category name"},
            "search": {"type": "string", "description": "Case-insensitive substring match on term names"},
            "is_system": {
                "type": "boolean",
                "description": "true = built-in terms only, false = user-created terms only",
            },
            "limit": {"type": "integer", "description": "Maximum terms to return, 1-500 (default 100)"},
        },
        "required": [],
    },
    mutating=False,
)
async def _list_glossary_terms(
    db: AsyncSession,
    user_id: uuid.UUID,
    category: str | None = None,
    search: str | None = None,
    is_system: bool | None = None,
    limit: int = 100,
) -> dict:
    if not 1 <= limit <= 500:
        return {"error": "limit must be between 1 and 500"}
    query = select(GlossaryTerm)
    if category is not None:
        query = query.where(GlossaryTerm.category == category)
    if is_system is not None:
        query = query.where(GlossaryTerm.is_system.is_(is_system))
    if search:
        query = query.where(GlossaryTerm.name.ilike(f"%{search}%"))
    query = query.order_by(GlossaryTerm.name).limit(limit)
    terms = (await db.execute(query)).scalars().all()
    return {
        "terms": [_term_response(t).model_dump(mode="json") for t in terms],
        "total": len(terms),
    }


@_tool(
    name="create_glossary_term",
    description=(
        "Create a user glossary term. Requires name, category (free-form; NIST CSF functions govern/"
        "identify/protect/detect/respond/recover get special coloring), and description. Optional: "
        "maturity ('emerging', 'trending', or 'mature'), long_description, technologies (name + "
        "optional url), and search_terms aliases used for detection. Fails if a term with the same "
        "name already exists."
    ),
    input_schema={
        "properties": {
            "name": {"type": "string", "description": "Term name (unique)"},
            "category": {"type": "string", "description": "Category name, e.g. a NIST CSF function like 'detect'"},
            "description": {"type": "string", "description": "Short definition (max 2000 chars)"},
            "maturity": {
                "type": "string",
                "enum": ["emerging", "trending", "mature"],
                "description": "Optional maturity level",
            },
            "long_description": {"type": "string", "description": "Optional extended write-up (max 10000 chars)"},
            "technologies": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "url": {"type": "string"},
                    },
                    "required": ["name"],
                },
                "description": "Example technologies implementing the term",
            },
            "search_terms": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Alias phrases used when detecting the term in articles",
            },
        },
        "required": ["name", "category", "description"],
    },
    mutating=True,
)
async def _create_glossary_term(
    db: AsyncSession,
    user_id: uuid.UUID,
    name: str,
    category: str,
    description: str,
    maturity: str | None = None,
    long_description: str | None = None,
    technologies: list[dict] | None = None,
    search_terms: list[str] | None = None,
) -> dict:
    try:
        body = GlossaryTermCreate(
            name=name,
            category=category,
            description=description,
            maturity=maturity,
            long_description=long_description,
            technologies=technologies or [],
            search_terms=search_terms or [],
        )
    except ValidationError as exc:
        return {"error": "; ".join(f"{'.'.join(str(x) for x in e['loc'])}: {e['msg']}" for e in exc.errors())}

    existing = (await db.execute(select(GlossaryTerm).where(GlossaryTerm.name == body.name))).scalar_one_or_none()
    if existing:
        return {"error": f"Glossary term with this name already exists (id: {existing.id})"}

    term = GlossaryTerm(
        created_by=user_id,
        is_system=False,
        name=body.name,
        category=body.category,
        maturity=body.maturity,
        description=body.description,
        long_description=body.long_description,
        technologies=[t.model_dump() for t in body.technologies],
        search_terms=body.search_terms,
    )
    db.add(term)
    await db.flush()
    await db.refresh(term)
    return {"status": "created", "term": _term_response(term).model_dump(mode="json")}


@_tool(
    name="delete_glossary_term",
    description=(
        "Delete a user-created glossary term by UUID. Built-in system terms cannot be deleted. "
        "Single-row removal; no confirmation required."
    ),
    input_schema={
        "properties": {
            "term_id": {"type": "string", "description": "Glossary term UUID"},
        },
        "required": ["term_id"],
    },
    mutating=True,
)
async def _delete_glossary_term(db: AsyncSession, user_id: uuid.UUID, term_id: str) -> dict:
    try:
        tid = uuid.UUID(term_id)
    except ValueError:
        return {"error": f"term_id is not a valid UUID: {term_id}"}
    term = (await db.execute(select(GlossaryTerm).where(GlossaryTerm.id == tid))).scalar_one_or_none()
    if not term:
        return {"error": "Glossary term not found"}
    if term.is_system:
        return {"error": "Cannot delete system glossary terms"}
    name = term.name
    await db.delete(term)
    await db.flush()
    return {"status": "deleted", "term_id": term_id, "name": name}


@_tool(
    name="detect_glossary_terms",
    description=(
        "Detect which glossary terms appear in an entry's text (word-boundary matching over each "
        "term's name and search-term aliases). Returns matched terms with per-term match counts, "
        "highest first. Note: takes an entry UUID, not raw text — that is what the API supports."
    ),
    input_schema={
        "properties": {
            "entry_id": {"type": "string", "description": "Entry UUID whose text to scan"},
        },
        "required": ["entry_id"],
    },
    mutating=False,
)
async def _detect_glossary_terms(db: AsyncSession, user_id: uuid.UUID, entry_id: str) -> dict:
    try:
        eid = uuid.UUID(entry_id)
    except ValueError:
        return {"error": f"entry_id is not a valid UUID: {entry_id}"}
    user = await _get_user(db, user_id)
    if user is None:
        return {"error": "User not found"}
    try:
        matches = await _api_detect_terms(body=DetectRequest(entry_id=eid), user=user, db=db)
    except AppError as exc:
        return {"error": exc.message}
    return {
        "matches": [m.model_dump(mode="json") for m in matches],
        "total": len(matches),
    }
