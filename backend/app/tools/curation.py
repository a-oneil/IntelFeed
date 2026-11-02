"""Curation tools — entry↔entity link, relationship, extraction and hygiene curation.

Mirrors app/api/entity_links.py, false_positives.py, entity_relationships.py,
extraction.py and hygiene.py. Read tools call the router functions directly
(their user/admin params are unused in the handler bodies); mutating tools
reuse the routers' helpers and flush — the executor owns the transaction.

Review-queue decisions are exposed as one admin tool (decide_proposals, the
bulk decisions endpoint). Deliberately NOT exposed (admin plane, excluded by
design): hygiene prune / scan / AI-review actions, the per-row and bulk
apply-all endpoints, and the enrichment-gap dispatch endpoints.
"""

import uuid
from datetime import datetime
from typing import get_args

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.entity_links import LINK_CONFIGS
from app.api.extraction import _WINDOW_DAYS, AI_TYPES, Status
from app.core.exceptions import AppError
from app.intelligence.correlation import VALID_ENTITY_TYPES
from app.intelligence.relationship_matrix import ALLOWED_RELATIONSHIPS
from app.tools import _tool

_LINK_ENTITY_TYPES = sorted(LINK_CONFIGS)
_FP_ENTITY_TYPES = sorted(VALID_ENTITY_TYPES)
_REL_ENTITY_TYPES = sorted({t for a, _, b in ALLOWED_RELATIONSHIPS for t in (a, b)})
_REL_VERBS = sorted({v for _, v, _ in ALLOWED_RELATIONSHIPS})
_EXTRACTION_TYPES = sorted(AI_TYPES)
_EXTRACTION_WINDOWS = sorted(_WINDOW_DAYS)
_EXTRACTION_STATUSES = ["all", *get_args(Status)]


def _parse_uuid(value: str, label: str) -> uuid.UUID | dict:
    try:
        return uuid.UUID(value)
    except (ValueError, AttributeError, TypeError):
        return {"error": f"{label} must be a UUID, got: {value!r}"}


# ---------------------------------------------------------------------------
# Entry↔entity autolinks
# ---------------------------------------------------------------------------


@_tool(
    name="list_entity_links",
    description=(
        "List entry→entity autolinks (junction rows) unioned across all seven junction tables, newest first. "
        "Filter by entity_type, entity_id, entry_id, source provenance (auto_link, ai, ai_reconcile, "
        "auto_extracted, manual — TTP/CVE junctions record no source and are excluded when set), confidence "
        "(high, medium, low — the CVE junction has none and is excluded when set), a substring search on "
        "entity name / entry title, or a recency window in days."
    ),
    input_schema={
        "properties": {
            "entity_type": {
                "type": "string",
                "enum": _LINK_ENTITY_TYPES,
                "description": "Restrict to one junction table",
            },
            "entity_id": {"type": "string", "description": "Only links pointing at this entity UUID"},
            "entry_id": {"type": "string", "description": "Only links on this entry UUID"},
            "source": {
                "type": "string",
                "description": "Provenance filter: auto_link, ai, ai_reconcile, auto_extracted, or manual",
            },
            "confidence": {"type": "string", "description": "Link confidence filter: high, medium, or low"},
            "search": {"type": "string", "description": "Case-insensitive substring on entity name or entry title"},
            "days": {"type": "integer", "description": "Only links extracted within the last N days (1-3650)"},
            "limit": {"type": "integer", "default": 50, "description": "Max links per page (1-500)"},
            "offset": {"type": "integer", "default": 0, "description": "Pagination offset"},
        },
    },
    mutating=False,
)
async def _list_entity_links(
    db: AsyncSession,
    user_id: uuid.UUID,
    entity_type: str | None = None,
    entity_id: str | None = None,
    entry_id: str | None = None,
    source: str | None = None,
    confidence: str | None = None,
    search: str | None = None,
    days: int | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    from app.api.entity_links import list_entity_links as _route

    if entity_type and entity_type not in LINK_CONFIGS:
        return {"error": f"Unknown entity_type: {entity_type}. Valid: {_LINK_ENTITY_TYPES}"}
    ent_uuid = ety_uuid = None
    if entity_id is not None:
        ent_uuid = _parse_uuid(entity_id, "entity_id")
        if isinstance(ent_uuid, dict):
            return ent_uuid
    if entry_id is not None:
        ety_uuid = _parse_uuid(entry_id, "entry_id")
        if isinstance(ety_uuid, dict):
            return ety_uuid
    if days is not None and not 1 <= days <= 3650:
        return {"error": "days must be between 1 and 3650"}

    resp = await _route(
        entity_type=entity_type,
        entity_id=ent_uuid,
        entry_id=ety_uuid,
        source=source,
        confidence=confidence,
        search=search,
        days=days,
        limit=max(1, min(limit, 500)),
        offset=max(0, offset),
        user=None,
        db=db,
    )
    return resp.model_dump()


@_tool(
    name="get_entity_link_stats",
    description=(
        "Autolinking health signals: total entry→entity links by entity type and provenance source, the "
        "held-match (pending autolink) queue depth and how many held matches are high-confidence ready, plus "
        "the count of non-rejected entity↔entity relationships."
    ),
    input_schema={"properties": {}},
    mutating=False,
)
async def _get_entity_link_stats(db: AsyncSession, user_id: uuid.UUID) -> dict:
    from app.api.entity_links import entity_link_stats as _route

    return (await _route(user=None, db=db)).model_dump()


@_tool(
    name="unlink_entity_from_entry",
    description=(
        "Remove a single entry→entity autolink (junction row) and invalidate the entity's cached "
        "pivots/graphs. Reversible (the autolinker or an analyst can re-create it), so no confirmation is "
        "required. Does not touch the entity or the entry themselves."
    ),
    input_schema={
        "properties": {
            "entity_type": {"type": "string", "enum": _LINK_ENTITY_TYPES, "description": "Entity type of the link"},
            "entity_id": {"type": "string", "description": "UUID of the linked entity"},
            "entry_id": {"type": "string", "description": "UUID of the entry to unlink"},
        },
        "required": ["entity_type", "entity_id", "entry_id"],
    },
    mutating=True,
)
async def _unlink_entity_from_entry(
    db: AsyncSession, user_id: uuid.UUID, entity_type: str, entity_id: str, entry_id: str
) -> dict:
    from app.api.entity_links import _delete_link
    from app.schemas.entity_link import LinkRef

    if entity_type not in LINK_CONFIGS:
        return {"error": f"Unknown entity_type: {entity_type}. Valid: {_LINK_ENTITY_TYPES}"}
    ent_uuid = _parse_uuid(entity_id, "entity_id")
    if isinstance(ent_uuid, dict):
        return ent_uuid
    ety_uuid = _parse_uuid(entry_id, "entry_id")
    if isinstance(ety_uuid, dict):
        return ety_uuid

    ok = await _delete_link(db, LinkRef(entity_type=entity_type, entity_id=ent_uuid, entry_id=ety_uuid))
    if not ok:
        return {"error": "Link not found"}
    await db.flush()
    return {"status": "unlinked", "entity_type": entity_type, "entity_id": entity_id, "entry_id": entry_id}


@_tool(
    name="bulk_unlink_entities",
    description=(
        "Remove up to 500 entry→entity autolinks in one call. Each item is "
        "{entity_type, entity_id, entry_id}; items whose junction row no longer exists are skipped. "
        "Invalidates each affected entity's cached pivots/graphs. Returns the number actually deleted."
    ),
    input_schema={
        "properties": {
            "items": {
                "type": "array",
                "description": "Links to remove (max 500)",
                "items": {
                    "type": "object",
                    "properties": {
                        "entity_type": {"type": "string", "enum": _LINK_ENTITY_TYPES},
                        "entity_id": {"type": "string", "description": "Entity UUID"},
                        "entry_id": {"type": "string", "description": "Entry UUID"},
                    },
                    "required": ["entity_type", "entity_id", "entry_id"],
                },
            },
        },
        "required": ["items"],
    },
    mutating=True,
)
async def _bulk_unlink_entities(db: AsyncSession, user_id: uuid.UUID, items: list) -> dict:
    from app.api.entity_links import _delete_link
    from app.schemas.entity_link import LinkRef

    if len(items) > 500:
        return {"error": "At most 500 links per request"}
    refs: list[LinkRef] = []
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            return {"error": f"items[{i}] must be an object with entity_type, entity_id, entry_id"}
        etype = item.get("entity_type")
        if etype not in LINK_CONFIGS:
            return {"error": f"items[{i}].entity_type invalid: {etype}. Valid: {_LINK_ENTITY_TYPES}"}
        ent = _parse_uuid(str(item.get("entity_id")), f"items[{i}].entity_id")
        if isinstance(ent, dict):
            return ent
        ety = _parse_uuid(str(item.get("entry_id")), f"items[{i}].entry_id")
        if isinstance(ety, dict):
            return ety
        refs.append(LinkRef(entity_type=etype, entity_id=ent, entry_id=ety))

    deleted = 0
    for ref in refs:
        if await _delete_link(db, ref):
            deleted += 1
    await db.flush()
    return {"deleted": deleted, "requested": len(refs)}


# ---------------------------------------------------------------------------
# False positives
# ---------------------------------------------------------------------------


@_tool(
    name="report_false_positive",
    description=(
        "Report a mislinked entity (autolinker noise). Always writes a FalsePositiveRecord audit row. With "
        "source_entry_id set, unlinks the entity from that entry. scope='entry' stops there. scope='alias' "
        "also drops entity_value from the entity's aliases and unlinks every entry that matched only via it "
        "(the entity survives and keeps matching under its other names). scope='global' instead blocks the "
        "surface form from matching any entity type and rebuilds the vocabulary (existing links on other "
        "entries are not retroactively removed)."
    ),
    input_schema={
        "properties": {
            "entity_type": {"type": "string", "enum": _FP_ENTITY_TYPES, "description": "Type of the mislinked entity"},
            "entity_id": {"type": "string", "description": "UUID of the mislinked entity"},
            "entity_value": {
                "type": "string",
                "description": "The surface form that was wrongly matched (1-500 chars), e.g. 'Prometheus'",
            },
            "scope": {
                "type": "string",
                "enum": ["entry", "alias", "global"],
                "description": (
                    "'entry' = unlink from one article only; 'alias' = also drop the name from this entity "
                    "and unlink articles matched only by it; 'global' = block the name platform-wide"
                ),
            },
            "source_entry_id": {"type": "string", "description": "Entry UUID to unlink the entity from (optional)"},
            "reason": {"type": "string", "description": "Why this is a false positive (optional, for the audit row)"},
        },
        "required": ["entity_type", "entity_id", "entity_value", "scope"],
    },
    mutating=True,
)
async def _report_false_positive(
    db: AsyncSession,
    user_id: uuid.UUID,
    entity_type: str,
    entity_id: str,
    entity_value: str,
    scope: str,
    source_entry_id: str | None = None,
    reason: str | None = None,
) -> dict:
    # Same helpers the /false-positives endpoint uses — the two must not drift.
    from app.api.false_positives import _block_surface_form, _drop_alias, _unlink_from_entry
    from app.core.exceptions import AppError
    from app.intelligence.autolinker import refresh_vocabulary
    from app.models.false_positive_record import FalsePositiveRecord

    if entity_type not in VALID_ENTITY_TYPES:
        return {"error": f"entity_type must be one of {_FP_ENTITY_TYPES}"}
    if scope not in ("entry", "alias", "global"):
        return {"error": "scope must be 'entry', 'alias' or 'global'"}
    if not entity_value or not entity_value.strip() or len(entity_value) > 500:
        return {"error": "entity_value must be 1-500 characters"}
    ent_uuid = _parse_uuid(entity_id, "entity_id")
    if isinstance(ent_uuid, dict):
        return ent_uuid
    entry_uuid = None
    if source_entry_id is not None:
        entry_uuid = _parse_uuid(source_entry_id, "source_entry_id")
        if isinstance(entry_uuid, dict):
            return entry_uuid

    unlinked = False
    if entry_uuid is not None:
        unlinked = await _unlink_from_entry(db, entity_type, ent_uuid, entry_uuid)

    alias_removed = False
    links_removed = 0
    added_to_fp_list = False
    try:
        if scope == "alias":
            alias_removed, links_removed = await _drop_alias(db, entity_type, ent_uuid, entity_value)
        elif scope == "global":
            added_to_fp_list = await _block_surface_form(db, entity_value)
    except AppError as exc:
        return {"error": exc.message}

    record = FalsePositiveRecord(
        entity_type=entity_type,
        entity_id=ent_uuid,
        entity_value=entity_value,
        source_entry_id=entry_uuid,
        reason=reason,
        marked_by=user_id,
    )
    db.add(record)
    await db.flush()

    if added_to_fp_list or alias_removed:
        await refresh_vocabulary(db)

    return {
        "id": str(record.id),
        "unlinked_from_entry": unlinked,
        "added_to_autolinker_fp_list": added_to_fp_list,
        "alias_removed": alias_removed,
        "links_removed": links_removed,
    }


# ---------------------------------------------------------------------------
# Entity↔entity relationships
# ---------------------------------------------------------------------------


@_tool(
    name="list_entity_relationships",
    description=(
        "All entity↔entity relationships where the given entity is source or target, newest first, with "
        "endpoint display names resolved. Each row carries verb (relationship_type), confidence "
        "(possible/probable/confirmed), provenance source and evidence_entry_ids. Analyst-rejected edges and "
        "edges below the configured min-confidence display setting are hidden unless include_rejected is set."
    ),
    input_schema={
        "properties": {
            "entity_type": {"type": "string", "enum": _REL_ENTITY_TYPES, "description": "Pivot entity type"},
            "entity_id": {"type": "string", "description": "Pivot entity UUID"},
            "relationship_type": {
                "type": "string",
                "enum": _REL_VERBS,
                "description": "Only relationships with this verb",
            },
            "include_rejected": {
                "type": "boolean",
                "default": False,
                "description": "Include analyst-rejected relationships",
            },
        },
        "required": ["entity_type", "entity_id"],
    },
    mutating=False,
)
async def _list_entity_relationships(
    db: AsyncSession,
    user_id: uuid.UUID,
    entity_type: str,
    entity_id: str,
    relationship_type: str | None = None,
    include_rejected: bool = False,
) -> dict:
    from app.api.entity_relationships import get_entity_relationships as _route

    ent_uuid = _parse_uuid(entity_id, "entity_id")
    if isinstance(ent_uuid, dict):
        return ent_uuid
    items = await _route(
        entity_type=entity_type,
        entity_id=ent_uuid,
        relationship_type=relationship_type,
        include_rejected=include_rejected,
        user=None,
        db=db,
    )
    return {"items": [r.model_dump() for r in items], "count": len(items)}


@_tool(
    name="confirm_relationship",
    description=(
        "Trust-ladder confirm: upgrade a relationship to source='analyst_confirmed' and "
        "confidence='confirmed', then invalidate cached pivots/graphs for both endpoints. Returns the "
        "updated relationship."
    ),
    input_schema={
        "properties": {"relationship_id": {"type": "string", "description": "Relationship UUID"}},
        "required": ["relationship_id"],
    },
    mutating=True,
)
async def _confirm_relationship(db: AsyncSession, user_id: uuid.UUID, relationship_id: str) -> dict:
    from app.api.entity_relationships import confirm_entity_relationship as _route

    rel_uuid = _parse_uuid(relationship_id, "relationship_id")
    if isinstance(rel_uuid, dict):
        return rel_uuid
    try:
        return (await _route(relationship_id=rel_uuid, user=None, db=db)).model_dump()
    except AppError as e:
        return {"error": e.message}


@_tool(
    name="reject_relationship",
    description=(
        "Trust-ladder reject: mark a relationship source='analyst_rejected'. The row is kept (not deleted) so "
        "re-ingestion and the co-occurrence engine cannot resurrect or accumulate evidence on it; it is hidden "
        "from pivot/graph/list surfaces. Invalidates cached pivots/graphs for both endpoints."
    ),
    input_schema={
        "properties": {"relationship_id": {"type": "string", "description": "Relationship UUID"}},
        "required": ["relationship_id"],
    },
    mutating=True,
)
async def _reject_relationship(db: AsyncSession, user_id: uuid.UUID, relationship_id: str) -> dict:
    from app.api.entity_relationships import reject_entity_relationship as _route

    rel_uuid = _parse_uuid(relationship_id, "relationship_id")
    if isinstance(rel_uuid, dict):
        return rel_uuid
    try:
        return (await _route(relationship_id=rel_uuid, user=None, db=db)).model_dump()
    except AppError as e:
        return {"error": e.message}


@_tool(
    name="delete_relationship",
    description=(
        "Hard-delete an entity↔entity relationship and invalidate cached pivots/graphs for both endpoints. "
        "Reversible via re-create, so no confirmation is required — but prefer reject_relationship for "
        "auto-extracted edges: a deleted row can be recreated by re-ingestion, a rejected one cannot."
    ),
    input_schema={
        "properties": {"relationship_id": {"type": "string", "description": "Relationship UUID"}},
        "required": ["relationship_id"],
    },
    mutating=True,
)
async def _delete_relationship(db: AsyncSession, user_id: uuid.UUID, relationship_id: str) -> dict:
    from app.api.entity_relationships import delete_entity_relationship as _route

    rel_uuid = _parse_uuid(relationship_id, "relationship_id")
    if isinstance(rel_uuid, dict):
        return rel_uuid
    try:
        await _route(relationship_id=rel_uuid, user=None, db=db)
    except AppError as e:
        return {"error": e.message}
    return {"status": "deleted", "relationship_id": relationship_id}


# ---------------------------------------------------------------------------
# AI-extraction management
# ---------------------------------------------------------------------------


@_tool(
    name="get_extraction_stats",
    description=(
        "Aggregate stats over AI-created entities (created_via='ai_extraction' across threat actors, malware, "
        "tools, CVEs, TTPs): totals by type, needs-review / orphaned / likely-duplicate / auto-confirmed "
        "counts, and how many were created in the requested window vs the preceding one."
    ),
    input_schema={
        "properties": {
            "window": {
                "type": "string",
                "enum": _EXTRACTION_WINDOWS,
                "default": "7d",
                "description": "Creation window for the created_window / created_prev_window counters",
            },
        },
    },
    mutating=False,
)
async def _get_extraction_stats(db: AsyncSession, user_id: uuid.UUID, window: str = "7d") -> dict:
    from app.api.extraction import extraction_stats as _route

    if window not in _WINDOW_DAYS:
        return {"error": f"window must be one of {_EXTRACTION_WINDOWS}"}
    return (await _route(window=window, _=None, db=db)).model_dump()


@_tool(
    name="list_extraction_entities",
    description=(
        "List AI-created entities (created_via='ai_extraction') with a computed lifecycle status: linked "
        "(in use), review (needs analyst sign-off), orphan (zero articles), or dupe (near-duplicate sibling "
        "exists, with duplicate_of naming it). Filterable by type, status, creation window, text search and "
        "source entry; sorted and paginated. Includes provenance: created_confidence, needs_review, "
        "created_from_entry_id and the source entry title."
    ),
    input_schema={
        "properties": {
            "types": {
                "type": "string",
                "description": f"CSV of entity types to include ({', '.join(_EXTRACTION_TYPES)}); default all",
            },
            "status": {
                "type": "string",
                "enum": _EXTRACTION_STATUSES,
                "default": "all",
                "description": "Filter by computed lifecycle status",
            },
            "window": {
                "type": "string",
                "enum": _EXTRACTION_WINDOWS,
                "default": "7d",
                "description": "Only entities first seen within this window",
            },
            "q": {"type": "string", "description": "Search name / aliases / technique id"},
            "source_entry_id": {"type": "string", "description": "Only entities created from this entry UUID"},
            "sort_by": {
                "type": "string",
                "enum": ["created", "entries", "confidence", "name"],
                "default": "created",
                "description": "Sort key: created (first seen), entries (article count), confidence, or name",
            },
            "sort_order": {"type": "string", "enum": ["asc", "desc"], "default": "desc"},
            "limit": {"type": "integer", "default": 50, "description": "Max entities per page (1-200)"},
            "offset": {"type": "integer", "default": 0, "description": "Pagination offset"},
        },
    },
    mutating=False,
)
async def _list_extraction_entities(
    db: AsyncSession,
    user_id: uuid.UUID,
    types: str | None = None,
    status: str = "all",
    window: str = "7d",
    q: str | None = None,
    source_entry_id: str | None = None,
    sort_by: str = "created",
    sort_order: str = "desc",
    limit: int = 50,
    offset: int = 0,
) -> dict:
    from app.api.extraction import extraction_entities as _route

    if status not in _EXTRACTION_STATUSES:
        return {"error": f"status must be one of {_EXTRACTION_STATUSES}"}
    if window not in _WINDOW_DAYS:
        return {"error": f"window must be one of {_EXTRACTION_WINDOWS}"}
    if sort_by not in ("created", "entries", "confidence", "name"):
        return {"error": "sort_by must be created, entries, confidence, or name"}
    if sort_order not in ("asc", "desc"):
        return {"error": "sort_order must be asc or desc"}
    entry_uuid = None
    if source_entry_id is not None:
        entry_uuid = _parse_uuid(source_entry_id, "source_entry_id")
        if isinstance(entry_uuid, dict):
            return entry_uuid

    resp = await _route(
        types=types,
        status=status,
        window=window,
        q=q,
        source_entry_id=entry_uuid,
        sort_by=sort_by,
        sort_order=sort_order,
        limit=max(1, min(limit, 200)),
        offset=max(0, offset),
        _=None,
        db=db,
    )
    return resp.model_dump()


@_tool(
    name="confirm_extraction_entities",
    description=(
        "Analyst sign-off on AI-created entities: clears the needs_review flag on the given entities of one "
        "type so they no longer show in the extraction review queue. Returns how many rows were updated."
    ),
    input_schema={
        "properties": {
            "entity_type": {"type": "string", "enum": _EXTRACTION_TYPES, "description": "Type of every id given"},
            "ids": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Entity UUIDs to confirm",
            },
        },
        "required": ["entity_type", "ids"],
    },
    mutating=True,
)
async def _confirm_extraction_entities(db: AsyncSession, user_id: uuid.UUID, entity_type: str, ids: list) -> dict:
    spec = AI_TYPES.get(entity_type)
    if not spec:
        return {"error": f"entity_type must be one of {_EXTRACTION_TYPES}"}
    if not ids:
        return {"confirmed": 0}
    parsed: list[uuid.UUID] = []
    for i, raw in enumerate(ids):
        u = _parse_uuid(str(raw), f"ids[{i}]")
        if isinstance(u, dict):
            return u
        parsed.append(u)

    m = spec["model"]
    result = await db.execute(update(m).where(m.id.in_(parsed)).values(needs_review=False).returning(m.id))
    confirmed = len(result.all())
    await db.flush()
    return {"confirmed": confirmed}


# ---------------------------------------------------------------------------
# Hygiene (read-only — prune/scan actions are admin plane, not exposed)
# ---------------------------------------------------------------------------


@_tool(
    name="get_hygiene_stats",
    description=(
        "Combined entity-hygiene counters across both proposal logs: the adjudicate stage's mode and how many "
        "verdicts it has filed that nobody has applied yet, pending reclassify advisories and "
        "name/alias/vendor/id proposals, orphan entity count, last run times, and how many actions were applied "
        "in the last 24h / 7d."
    ),
    input_schema={"properties": {}},
    mutating=False,
)
async def _get_hygiene_stats(db: AsyncSession, user_id: uuid.UUID) -> dict:
    from app.api.hygiene import hygiene_stats as _route

    return (await _route(user=None, db=db)).model_dump()


@_tool(
    name="get_hygiene_feed",
    description=(
        "Chronological hygiene feed: a merge of the entity-link log and the entity-maintenance log, normalized "
        "(action, mode, applied, subject, reason, affected-entity links, origin). Filter by action code "
        "(comma-separate for several), log source, mode, origin (adjudicator = filed by the adjudicate stage, "
        "merge_review = the duplicate review, scan = the on-demand scans and analysts), pending-only, or a since "
        "timestamp. Read-only — applying or dismissing proposals happens in the Proposals queue."
    ),
    input_schema={
        "properties": {
            "action": {
                "type": "string",
                "description": "Filter by action code(s), comma-separated — e.g. 'needs_reclassification' or "
                "'ttp_malformed_id,cve_malformed_id'",
            },
            "source": {
                "type": "string",
                "enum": ["link_validator", "entity_maintenance"],
                "description": "Restrict to one log source; omit for both",
            },
            "mode": {
                "type": "string",
                "enum": ["shadow", "apply"],
                "description": "shadow = proposals only, apply = actions that actually ran",
            },
            "origin": {
                "type": "string",
                "enum": ["adjudicator", "merge_review", "scan"],
                "description": "adjudicator = rows the adjudicate stage filed; merge_review = the duplicate "
                "review; scan = the on-demand scans and analysts",
            },
            "pending": {
                "type": "boolean",
                "default": False,
                "description": "Only unapplied proposals (skips applied history)",
            },
            "since": {"type": "string", "description": "ISO timestamp; only rows created at or after it"},
            "limit": {"type": "integer", "default": 50, "description": "Rows per page (1-200)"},
            "offset": {"type": "integer", "default": 0, "description": "Rows to skip"},
        },
    },
    mutating=False,
)
async def _get_hygiene_feed(
    db: AsyncSession,
    user_id: uuid.UUID,
    action: str | None = None,
    source: str | None = None,
    mode: str | None = None,
    origin: str | None = None,
    pending: bool = False,
    since: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    from app.api.hygiene import hygiene_feed as _route

    if source is not None and source not in ("link_validator", "entity_maintenance"):
        return {"error": "source must be 'link_validator' or 'entity_maintenance'"}
    if mode is not None and mode not in ("shadow", "apply"):
        return {"error": "mode must be 'shadow' or 'apply'"}
    if origin is not None and origin not in ("adjudicator", "merge_review", "scan"):
        return {"error": "origin must be 'adjudicator', 'merge_review' or 'scan'"}
    since_dt = None
    if since is not None:
        try:
            since_dt = datetime.fromisoformat(since)
        except ValueError:
            return {"error": f"since must be an ISO timestamp, got: {since!r}"}

    resp = await _route(
        action=action,
        source=source,
        domain=None,
        mode=mode,
        origin=origin,
        pending=pending,
        orphaned=False,
        since=since_dt,
        limit=max(1, min(limit, 200)),
        offset=max(0, offset),
        user=None,
        db=db,
    )
    return resp.model_dump()


# ---------------------------------------------------------------------------
# Review queue (admin): the Engine › Review list, its rows, bulk decisions
# ---------------------------------------------------------------------------

_REVIEW_DOMAINS = ["links", "entities", "relationships"]
_REVIEW_ORIGINS = ["adjudicator", "merge_review", "scan"]


@_tool(
    name="list_review_groups",
    description=(
        "The Engine › Review queue: every pending hygiene proposal (both logs) folded one row per entity, most "
        "proposals first. Each group gives the entity, its proposal count, per-kind counts (e.g. shadow_remove, "
        "adjudication_reclassify), proposed target types, merge targets, origin, the newest row's subject and "
        "reason, matched forms and a sample entry. Read a group's rows with get_review_rows; decide them with "
        "decide_proposals. `total`/`proposals` are the queue size. Admin only."
    ),
    input_schema={
        "properties": {
            "q": {"type": "string", "description": "Entity name substring (case-insensitive)"},
            "entity_type": {"type": "string", "description": "Only groups about this entity type"},
            "action": {"type": "string", "description": "Only these action codes, comma-separated"},
            "domain": {"type": "string", "enum": _REVIEW_DOMAINS, "description": "What applying would change"},
            "origin": {"type": "string", "enum": _REVIEW_ORIGINS, "description": "Who filed the proposals"},
            "limit": {"type": "integer", "default": 50, "description": "Groups per page (1-200)"},
            "offset": {"type": "integer", "default": 0, "description": "Groups to skip"},
        },
    },
    mutating=False,
)
async def _list_review_groups(
    db: AsyncSession,
    user_id: uuid.UUID,
    q: str | None = None,
    entity_type: str | None = None,
    action: str | None = None,
    domain: str | None = None,
    origin: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    from app.api.hygiene import review_groups as _route

    try:
        resp = await _route(
            q=q,
            entity_type=entity_type,
            action=action,
            domain=domain,
            origin=origin,
            limit=max(1, min(limit, 200)),
            offset=max(0, offset),
            user=None,
            db=db,
        )
    except AppError as e:
        return {"error": e.message}
    return resp.model_dump(mode="json")


@_tool(
    name="get_review_rows",
    description=(
        "The pending proposals behind one Review group (or every pending row matching the filters), newest "
        "first. Each row has its id ('<source>:<log_id>', what decide_proposals takes), action, subject, reason, "
        "payload, and `context`: the article text around the match, so the article needn't be fetched. "
        "Admin only."
    ),
    input_schema={
        "properties": {
            "entity_type": {"type": "string", "description": "The group's entity_type"},
            "entity_id": {"type": "string", "description": "The group's entity_id"},
            "action": {"type": "string", "description": "Only these action codes, comma-separated"},
            "origin": {"type": "string", "enum": _REVIEW_ORIGINS},
            "domain": {"type": "string", "enum": _REVIEW_DOMAINS},
            "limit": {"type": "integer", "default": 200, "description": "Rows per page (1-200)"},
            "offset": {"type": "integer", "default": 0, "description": "Rows to skip"},
        },
    },
    mutating=False,
)
async def _get_review_rows(
    db: AsyncSession,
    user_id: uuid.UUID,
    entity_type: str | None = None,
    entity_id: str | None = None,
    action: str | None = None,
    origin: str | None = None,
    domain: str | None = None,
    limit: int = 200,
    offset: int = 0,
) -> dict:
    from app.api.hygiene import hygiene_feed as _route

    eid = None
    if entity_id:
        eid = _parse_uuid(entity_id, "entity_id")
        if isinstance(eid, dict):
            return eid
    try:
        resp = await _route(
            action=action,
            source=None,
            domain=domain,
            mode=None,
            pending=True,
            origin=origin,
            orphaned=False,
            since=None,
            entity_type=entity_type,
            entity_id=eid,
            context=True,
            limit=max(1, min(limit, 200)),
            offset=max(0, offset),
            user=None,
            db=db,
        )
    except AppError as e:
        return {"error": e.message}
    return resp.model_dump(mode="json")


@_tool(
    name="decide_proposals",
    description=(
        "Apply a reviewed batch of Review-queue decisions in one call (POST /admin/hygiene/decisions). Each "
        "decision is {id: '<source>:<log_id>', decision: 'apply' | 'dismiss' | 'reclassify:<entity_type>'}. "
        "apply runs the row's own applier; dismiss deletes it (a reclassify dismissal covers the entity and "
        "stops new filings); reclassify converts the entity and closes every proposal about it. Duplicates "
        "settle server-side: a row an earlier decision closed comes back 'settled'; an apply whose outcome is "
        "already reached comes back 'resolved'. Returns one result per decision plus counts. Admin only."
    ),
    input_schema={
        "properties": {
            "decisions": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string", "description": "Feed row id '<source>:<log_id>'"},
                        "decision": {"type": "string", "description": "apply | dismiss | reclassify:<entity_type>"},
                    },
                    "required": ["id", "decision"],
                },
                "description": "Up to 1000 decisions",
            },
        },
        "required": ["decisions"],
    },
    mutating=True,
)
async def _decide_proposals(db: AsyncSession, user_id: uuid.UUID, decisions: list) -> dict:
    from app.api.hygiene import ProposalDecision
    from app.api.hygiene import decide_proposals as _route
    from app.models.user import User

    user = await db.get(User, user_id)
    if user is None:
        return {"error": "user not found"}
    try:
        body = [ProposalDecision(**d) for d in decisions or []]
        resp = await _route(body=body, user=user, db=db)
    except AppError as e:
        return {"error": e.message}
    except (TypeError, ValueError) as e:
        return {"error": f"bad decisions: {e}"}
    return resp.model_dump(mode="json")
