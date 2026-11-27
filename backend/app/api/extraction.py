"""AI-extraction management API (Workbench → Engine → Extraction tab).

Surfaces every entity that AI extraction has *created* (created_via =
'ai_extraction') across the six mintable types — threat actors, malware,
tools, CVEs, TTPs, observables — with stats, filtering, and a computed
lifecycle status so an analyst can review, pivot, merge, or delete what the
pipeline produced.

Actions (merge / convert / pivot) reuse the existing entity APIs. Delete is the
exception: deleting from this table also writes the name to the analyst
do-not-recreate denylist, so it has its own endpoint here. Observables deny
differently — see ``extraction_delete``.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Literal

from fastapi import APIRouter, Body, Depends, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import delete as sql_delete
from sqlalchemy import func, literal, or_, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppError
from app.core.security import get_admin_user
from app.database import get_db
from app.intelligence.autolinker import schedule_vocabulary_refresh
from app.intelligence.correlation import ENTITY_CONFIG
from app.intelligence.correlation_cache import invalidate_entity_cache
from app.intelligence.entity_resolution import (
    ANY_ENTITY_TYPE,
    DENIABLE_TYPES,
    deniable_names,
    deny_entity_names,
    normalize_entity_name,
    sync_fp_names,
)
from app.models.cve import CVE, EntryCVE
from app.models.entity_index import EntityNameDenylist
from app.models.entity_relationship import EntityRelationship
from app.models.malware_family import MalwareFamily
from app.models.observable import STATUS_EXPIRED, EntryObservable, Observable
from app.models.threat_actor import ThreatActor
from app.models.tool import Tool
from app.models.ttp import TTP
from app.models.user import User
from app.schemas.review_evidence import EvidenceArticle
from app.services.entity_indexer import delete_entity_document

router = APIRouter()

# entity_type key -> extraction spec. `name` is the display-name column; `ac`
# marks types that carry a denormalized article_count (CVE counts live rows).
# `trgm_table` is set only for resolver-gated types that have normalized_name
# and can therefore have near-duplicate siblings.
AI_TYPES: dict[str, dict] = {
    "threat_actor": {"model": ThreatActor, "name": "name", "aliases": True, "ac": True, "trgm_table": "threat_actors"},
    "malware": {"model": MalwareFamily, "name": "name", "aliases": True, "ac": True, "trgm_table": "malware_families"},
    "tool": {"model": Tool, "name": "name", "aliases": True, "ac": True, "trgm_table": "tools"},
    "ttp": {"model": TTP, "name": "technique_name", "aliases": False, "ac": True, "second": "technique_id"},
    "cve": {"model": CVE, "name": "cve_id", "aliases": False, "ac": False},
    # Observable ledger rows created by the one-pass `iocs` array. Identity is
    # (kind, value), so `value` is the name column and `label` the second
    # searchable column (scripts are keyed by sha256 and carry a readable label).
    "observable": {"model": Observable, "name": "value", "aliases": False, "ac": True, "second": "label"},
}

# Named catalog types the delete endpoint accepts: the AI-created set above
# plus the three the review queues also surface. Observables are handled apart
# (ledger tombstones); countries are a seeded catalog, so they are deleted
# but never denylisted.
DELETABLE_TYPES = (set(AI_TYPES) | {"vendor", "product", "country"}) - {"observable"}
_NO_DENY_TYPES = {"country"}

_CONF_RANK = {"high": 3, "medium": 2, "low": 1}
_WINDOW_DAYS = {"1h": 1 / 24, "24h": 1, "7d": 7, "30d": 30, "all": None}

Status = Literal["linked", "review", "orphan", "dupe"]


class ExtractionEntity(BaseModel):
    id: uuid.UUID
    entity_type: str
    name: str
    aliases: list[str]
    article_count: int
    created_confidence: str | None
    needs_review: bool
    created_from_entry_id: uuid.UUID | None
    source_entry_title: str | None
    first_seen_at: datetime
    status: Status
    duplicate_of: str | None
    duplicate_of_id: uuid.UUID | None = None


class ExtractionListResponse(BaseModel):
    items: list[ExtractionEntity]
    total: int
    limit: int
    offset: int


class ExtractionStats(BaseModel):
    total_created: int
    created_window: int
    created_prev_window: int
    needs_review: int
    orphaned: int
    likely_duplicates: int
    auto_confirmed: int
    by_type: dict[str, int]
    # Every AI-created entity's computed status, across all time: the counts
    # of what each Review lens lists.
    by_status: dict[str, int]
    window: str


def _now() -> datetime:
    return datetime.now(UTC)


async def _duplicate_map(db: AsyncSession, types: list[str]) -> dict[str, tuple[str, str]]:
    """AI-created rows that have a near-duplicate same-type sibling → (sibling name, sibling id).

    Uses pg_trgm: the ``%`` operator hits the trigram index, similarity() ranks.
    Only threat_actor/malware/tool have normalized_name (CVE/TTP are id-keyed and
    cannot collide), so those are skipped. Pairs an analyst marked "not a
    duplicate" are left out, so the next-closest sibling (if any) shows instead.
    """
    dup: dict[str, tuple[str, str, float]] = {}
    for t in types:
        table = AI_TYPES[t].get("trgm_table")
        if not table:
            continue
        rows = (
            await db.execute(
                text(
                    f"""
                    SELECT a.id::text AS id, b.name AS dup_name, b.id::text AS dup_id,
                           similarity(a.normalized_name, b.normalized_name) AS sim
                    FROM {table} a
                    JOIN {table} b
                      ON a.id <> b.id
                     AND a.normalized_name IS NOT NULL
                     AND b.normalized_name IS NOT NULL
                     AND a.normalized_name % b.normalized_name
                    WHERE a.created_via = 'ai_extraction'
                      AND similarity(a.normalized_name, b.normalized_name) >= 0.62
                      -- same letters, different digits: Storm-3068 / Storm-3069, KillSecurity 2.0 / 3.0
                      AND NOT (
                        regexp_replace(lower(a.name), '[^a-z]', '', 'g')
                          = regexp_replace(lower(b.name), '[^a-z]', '', 'g')
                        AND regexp_replace(a.name, '[^0-9]', '', 'g') <> regexp_replace(b.name, '[^0-9]', '', 'g')
                      )
                      AND NOT EXISTS (
                        SELECT 1 FROM proposal_dismissals d
                        WHERE d.kind = 'not_duplicate' AND d.entity_type = :etype
                          AND ((d.entity_id = a.id AND d.other_key = b.id::text)
                            OR (d.entity_id = b.id AND d.other_key = a.id::text))
                      )
                    """
                ).bindparams(etype=t)
            )
        ).all()
        for rid, dup_name, dup_id, sim in rows:
            best = dup.get(rid)
            if best is None or sim > best[2]:
                dup[rid] = (dup_name, dup_id, float(sim))
    return {k: (v[0], v[1]) for k, v in dup.items()}


async def _fetch_rows(db: AsyncSession, types: list[str], window_start: datetime | None, q: str | None) -> list[dict]:
    """Load AI-created entities of the requested types into uniform dict rows."""
    rows: list[dict] = []
    for t in types:
        spec = AI_TYPES[t]
        m = spec["model"]
        # Only the columns the table shows: loading whole rows pulls in large
        # columns such as CVE.nvd_data and made this the slow half of the tab.
        cols = [
            m.id.label("id"),
            getattr(m, spec["name"]).label("name"),
            m.created_confidence.label("created_confidence"),
            m.needs_review.label("needs_review"),
            m.created_from_entry_id.label("created_from_entry_id"),
            m.first_seen_at.label("first_seen_at"),
            (m.last_seen_at if hasattr(m, "last_seen_at") else literal(None)).label("last_seen_at"),
        ]
        if spec.get("aliases"):
            cols.append(m.aliases.label("aliases"))
        elif t == "ttp":
            cols.append(m.technique_id.label("technique_id"))
        elif t == "observable":
            cols += [m.kind.label("kind"), m.label.label("label")]
        if spec["ac"]:
            cols.append(m.article_count.label("article_count"))
        else:
            # article_count: denormalized column, except CVE (count live links).
            live = select(EntryCVE.cve_id, func.count().label("n")).group_by(EntryCVE.cve_id).subquery()
            cols.append(func.coalesce(live.c.n, 0).label("article_count"))
        stmt = select(*cols)
        if not spec["ac"]:
            stmt = stmt.outerjoin(live, live.c.cve_id == m.id)
        if t == "observable":
            # Both AI write paths: the iocs array (ai_extraction) and the TTP host
            # artifacts (ttp_observable) come out of the same one-pass payload,
            # so both belong in the AI-created review table. A denied observable
            # is a tombstone, not a live row: it stays in the ledger so every
            # write path keeps refusing the value, but it is left out of this
            # table, since denying it is what this table's delete does.
            stmt = stmt.where(m.created_via.in_(("ai_extraction", "ttp_observable")), m.is_denied.is_(False))
        else:
            stmt = stmt.where(m.created_via == "ai_extraction")
        if window_start is not None:
            stmt = stmt.where(m.first_seen_at >= window_start)
        if q:
            like = f"%{q}%"
            conds = [getattr(m, spec["name"]).ilike(like)]
            if spec.get("aliases"):
                conds.append(func.array_to_string(m.aliases, ",").ilike(like))
            if spec.get("second"):
                conds.append(getattr(m, spec["second"]).ilike(like))
            stmt = stmt.where(or_(*conds))

        for o in (await db.execute(stmt)).mappings().all():
            if spec.get("aliases"):
                aliases = list(o["aliases"] or [])
            elif t == "ttp":
                aliases = [o["technique_id"]]
            elif t == "observable":
                # No alias list here — the kind (and a script's label) is the
                # qualifier that makes a bare value readable in the table.
                aliases = [x for x in (o["kind"], o["label"]) if x]
            else:
                aliases = []
            rows.append(
                {
                    "id": o["id"],
                    "entity_type": t,
                    "name": o["name"],
                    "aliases": aliases,
                    "article_count": o["article_count"] or 0,
                    "created_confidence": o["created_confidence"],
                    "needs_review": o["needs_review"],
                    "created_from_entry_id": o["created_from_entry_id"],
                    "first_seen_at": o["first_seen_at"],
                    "last_seen_at": o["last_seen_at"],
                }
            )
    return rows


def _is_orphan(row: dict) -> bool:
    """No article links, though the article it came from still exists: every
    link was removed, so either the removal or the entity is wrong. Deleting the
    source article nulls created_from_entry_id, and the entity is then kept as
    intelligence already extracted, not queued for review."""
    return row["article_count"] == 0 and row["created_from_entry_id"] is not None


def _status(row: dict, dup: dict[str, str]) -> Status:
    if str(row["id"]) in dup:
        return "dupe"
    if _is_orphan(row):
        return "orphan"
    if row["needs_review"]:
        return "review"
    return "linked"


@router.get("/stats", response_model=ExtractionStats)
async def extraction_stats(
    window: str = Query(
        "7d",
        pattern="^(1h|24h|7d|30d|all)$",
        description="Creation window for the created_window / created_prev_window counters.",
    ),
    _: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> ExtractionStats:
    """Aggregate stats over AI-created entities: review / orphan / likely-duplicate counts, how
    many were created in the requested window vs. the preceding one, and the window's count per
    type."""
    days = _WINDOW_DAYS[window]
    now = _now()
    rows = await _fetch_rows(db, list(AI_TYPES), None, None)
    dup = await _duplicate_map(db, list(AI_TYPES))

    win_start = None if days is None else now - timedelta(days=days)
    prev_start = None if days is None else now - timedelta(days=days * 2)

    by_type: dict[str, int] = defaultdict(int)
    by_status: dict[str, int] = defaultdict(int)
    created_window = created_prev = needs_review = orphaned = auto_confirmed = 0
    for r in rows:
        fs = r["first_seen_at"]
        by_status[_status(r, dup)] += 1
        if win_start is None or fs >= win_start:
            by_type[r["entity_type"]] += 1  # within the list's window, so it matches what the type lists
        if r["needs_review"]:
            needs_review += 1
        else:
            auto_confirmed += 1
        if _is_orphan(r):
            orphaned += 1
        if win_start is not None and fs >= win_start:
            created_window += 1
        elif win_start is not None and prev_start is not None and prev_start <= fs < win_start:
            created_prev += 1

    return ExtractionStats(
        total_created=len(rows),
        created_window=created_window if days is not None else len(rows),
        created_prev_window=created_prev,
        needs_review=needs_review,
        orphaned=orphaned,
        likely_duplicates=len(dup),
        auto_confirmed=auto_confirmed,
        by_type=dict(by_type),
        by_status=dict(by_status),
        window=window,
    )


@router.get("/entities", response_model=ExtractionListResponse)
async def extraction_entities(
    types: str | None = Query(None, description="CSV of entity types to include; default all"),
    status: str = Query(
        "all",
        pattern="^(all|linked|review|orphan|dupe)$",
        description="Filter by computed lifecycle status (linked, review, orphan, dupe).",
    ),
    window: str = Query(
        "7d", pattern="^(1h|24h|7d|30d|all)$", description="Only entities first seen within this window."
    ),
    q: str | None = Query(None, description="Search name / aliases"),
    source_entry_id: uuid.UUID | None = Query(None, description="Only entities created from this entry"),
    sort_by: str = Query(
        "created",
        pattern="^(created|entries|confidence|name)$",
        description="Sort key: created (first seen), entries (article count), confidence, or name.",
    ),
    sort_order: str = Query("desc", pattern="^(asc|desc)$", description="Sort direction."),
    limit: int = Query(50, ge=1, le=200, description="Maximum entities per page."),
    offset: int = Query(0, ge=0, description="Number of entities to skip for pagination."),
    _: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> ExtractionListResponse:
    """List AI-created entities with a computed lifecycle status (linked / review / orphan / dupe),
    filterable by type, status, window, and text search; sorted and paginated."""
    requested = [t.strip() for t in types.split(",")] if types else list(AI_TYPES)
    requested = [t for t in requested if t in AI_TYPES] or list(AI_TYPES)

    days = _WINDOW_DAYS[window]
    window_start = None if days is None else _now() - timedelta(days=days)

    rows = await _fetch_rows(db, requested, window_start, q)
    if source_entry_id is not None:
        rows = [r for r in rows if r["created_from_entry_id"] == source_entry_id]
    dup = await _duplicate_map(db, requested)

    for r in rows:
        r["status"] = _status(r, dup)
        sibling = dup.get(str(r["id"]))
        r["duplicate_of"], r["duplicate_of_id"] = sibling if sibling else (None, None)

    if status != "all":
        rows = [r for r in rows if r["status"] == status]

    reverse = sort_order == "desc"
    if sort_by == "created":
        rows.sort(key=lambda r: r["first_seen_at"], reverse=reverse)
    elif sort_by == "entries":
        rows.sort(key=lambda r: r["article_count"], reverse=reverse)
    elif sort_by == "confidence":
        rows.sort(key=lambda r: _CONF_RANK.get(r["created_confidence"] or "", 0), reverse=reverse)
    else:
        rows.sort(key=lambda r: (r["name"] or "").lower(), reverse=reverse)

    total = len(rows)
    page = rows[offset : offset + limit]

    # Resolve source-entry titles for the visible page only.
    entry_ids = [r["created_from_entry_id"] for r in page if r["created_from_entry_id"]]
    titles: dict[uuid.UUID, str] = {}
    if entry_ids:
        titles = dict(
            (
                await db.execute(text("SELECT id, title FROM entries WHERE id = ANY(:ids)").bindparams(ids=entry_ids))
            ).all()
        )

    items = [
        ExtractionEntity(
            id=r["id"],
            entity_type=r["entity_type"],
            name=r["name"],
            aliases=r["aliases"],
            article_count=r["article_count"],
            created_confidence=r["created_confidence"],
            needs_review=r["needs_review"],
            created_from_entry_id=r["created_from_entry_id"],
            source_entry_title=titles.get(r["created_from_entry_id"]),
            first_seen_at=r["first_seen_at"],
            status=r["status"],
            duplicate_of=r["duplicate_of"],
            duplicate_of_id=r["duplicate_of_id"],
        )
        for r in page
    ]
    return ExtractionListResponse(items=items, total=total, limit=limit, offset=offset)


class ConfirmRequest(BaseModel):
    entity_type: str
    ids: list[uuid.UUID]

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "entity_type": "threat_actor",
                "ids": ["d5b2c8f0-3e4a-4b6c-9d1e-7f8a9b0c1d2e"],
            }
        }
    )


_EVIDENCE_ARTICLES = 3


@router.get("/entities/{entity_type}/{entity_id}/evidence", response_model=list[EvidenceArticle])
async def entity_evidence(
    entity_type: str,
    entity_id: uuid.UUID,
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> list[EvidenceArticle]:
    """The articles behind an entity in the Review lenses: the one it was
    created from, then its newest links, each with the paragraph naming it."""
    from app.api.hygiene import article_evidence
    from app.models.entry import Entry

    if entity_type not in ENTITY_CONFIG:
        raise AppError(code="invalid", message=f"unknown entity type {entity_type}", status_code=400)
    model, junction, fk_col = ENTITY_CONFIG[entity_type]
    entity = await db.get(model, entity_id)
    if entity is None:
        raise AppError(code="not_found", message="Entity not found", status_code=404)
    names = [
        n
        for n in (
            getattr(entity, "name", None),
            getattr(entity, "technique_name", None),
            getattr(entity, "technique_id", None),
            getattr(entity, "cve_id", None),
            getattr(entity, "value", None),
            getattr(entity, "label", None),
            *(getattr(entity, "aliases", None) or []),
        )
        if isinstance(n, str) and n.strip()
    ]
    links = (
        (
            await db.execute(
                select(junction)
                .join(Entry, Entry.id == junction.entry_id)
                .where(fk_col == entity_id)
                .order_by(Entry.published_at.desc().nulls_last())
                .limit(_EVIDENCE_ARTICLES)
            )
        )
        .scalars()
        .all()
    )
    by_entry = {link.entry_id: link for link in links}
    created_from = getattr(entity, "created_from_entry_id", None)
    order = list(dict.fromkeys([e for e in (created_from, *by_entry) if e]))[:_EVIDENCE_ARTICLES]
    out: list[EvidenceArticle] = []
    for entry_id in order:
        link = by_entry.get(entry_id)
        needles = [*(getattr(link, "matched_names", None) or []), *names]
        indices = list(getattr(link, "paragraph_indices", None) or [])
        article = await article_evidence(db, entry_id, list(dict.fromkeys(needles)), indices)
        if article is not None:
            out.append(article)
    return out


@router.post("/confirm")
async def extraction_confirm(
    body: ConfirmRequest = Body(...),
    _: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Clear needs_review on the given AI-created entities (analyst sign-off)."""
    spec = AI_TYPES.get(body.entity_type)
    if not spec or not body.ids:
        return {"confirmed": 0}
    m = spec["model"]
    result = await db.execute(update(m).where(m.id.in_(body.ids)).values(needs_review=False).returning(m.id))
    confirmed = len(result.all())
    await db.commit()
    return {"confirmed": confirmed}


class NotDuplicateRequest(BaseModel):
    entity_type: str
    id: uuid.UUID
    other_id: uuid.UUID

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "entity_type": "malware",
                "id": "d5b2c8f0-3e4a-4b6c-9d1e-7f8a9b0c1d2e",
                "other_id": "8a1f0c3e-2b4d-4e6f-9a0b-1c2d3e4f5a6b",
            }
        }
    )


@router.post("/not-duplicate")
async def extraction_not_duplicate(
    body: NotDuplicateRequest = Body(...),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Mark two same-type entities as different things, so the pair stops being
    flagged as a likely duplicate (KillSecurity 2.0 vs 3.0)."""
    from app.services.proposal_dismissals import mark_not_duplicate

    if body.entity_type not in AI_TYPES or not AI_TYPES[body.entity_type].get("trgm_table"):
        raise AppError(code="invalid", message=f"{body.entity_type} has no duplicate detection", status_code=400)
    if body.id == body.other_id:
        raise AppError(code="invalid", message="id and other_id are the same entity", status_code=400)
    await mark_not_duplicate(db, body.entity_type, body.id, body.other_id, user.id)
    await db.commit()
    return {"ok": True}


async def _delete_observables(db: AsyncSession, ids: list[uuid.UUID], *, deny: bool) -> dict:
    """Remove ledger rows from the AI entities table.

    ``deny`` tombstones (keeps the row, flips ``is_denied``) — the ledger's own
    do-not-recreate mechanism, since a value has no name to put on the entity
    denylist. Either way the row leaves this table and the search index; both
    counts are reported as deleted because that is what the caller sees.
    """
    rows = (await db.execute(select(Observable).where(Observable.id.in_(ids)))).scalars().all()
    denied = 0
    for obs in rows:
        obs_id = obs.id
        if deny:
            obs.is_denied = True
            obs.status = STATUS_EXPIRED
            denied += 1
        else:
            await db.execute(sql_delete(EntryObservable).where(EntryObservable.observable_id == obs_id))
            await db.execute(
                sql_delete(EntityRelationship).where(
                    or_(
                        (EntityRelationship.source_type == "observable") & (EntityRelationship.source_id == obs_id),
                        (EntityRelationship.target_type == "observable") & (EntityRelationship.target_id == obs_id),
                    )
                )
            )
            await db.delete(obs)
        await db.flush()
        delete_entity_document("observable", obs_id)
        await invalidate_entity_cache("observable", str(obs_id))

    await db.commit()
    return {"deleted": len(rows), "denied": denied}


class ExtractionDeleteRequest(BaseModel):
    entity_type: str
    ids: list[uuid.UUID]
    deny: bool = True

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "entity_type": "malware",
                "ids": ["d5b2c8f0-3e4a-4b6c-9d1e-7f8a9b0c1d2e"],
                "deny": True,
            }
        }
    )


async def delete_named_entity(db: AsyncSession, entity_type: str, entity, *, deny: bool, reason: str) -> int:
    """Delete one catalog entity the way the review surfaces do: its entry
    links and relationships go with it, its pending proposals in both logs
    are cleared, its search document and cache entry are dropped, and (unless
    ``deny`` is off or the type is a seeded catalog) its names join the
    do-not-recreate list. Returns the number of denylist rows written. The
    caller commits and refreshes the autolinker vocabulary."""
    from app.services.proposal_dismissals import clear_entity_proposals

    model, junction, fk_col = ENTITY_CONFIG[entity_type]
    denied = 0
    if deny and entity_type not in _NO_DENY_TYPES:
        denied = await deny_entity_names(db, entity_type, deniable_names(entity_type, entity), reason=reason)
    entity_id = entity.id
    await db.execute(sql_delete(junction).where(fk_col == entity_id))
    await db.execute(
        sql_delete(EntityRelationship).where(
            or_(
                (EntityRelationship.source_type == entity_type) & (EntityRelationship.source_id == entity_id),
                (EntityRelationship.target_type == entity_type) & (EntityRelationship.target_id == entity_id),
            )
        )
    )
    await clear_entity_proposals(db, entity_type, entity_id)
    await db.delete(entity)
    await db.flush()
    delete_entity_document(entity_type, entity_id)
    await invalidate_entity_cache(entity_type, str(entity_id))
    return denied


@router.post("/delete")
async def extraction_delete(
    body: ExtractionDeleteRequest = Body(...),
    _: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Delete AI-created entities and (unless ``deny=false``) add their names to the
    analyst do-not-recreate denylist.

    Deleting alone doesn't stick: the next article mentioning the name mints the
    entity again. The denylist rows written here are enforced for automated
    sources regardless of the entity-creation-gate mode, so the one-pass
    extractor and the autolinker stop re-creating it.

    Observables are the exception: there is no name denylist for IOC values, so
    denying one tombstones the ledger row in place (``is_denied``) — every door
    and the export then refuse the value. ``deny=false`` hard-deletes the row
    and its sightings instead, leaving it free to be captured again.
    """
    if not body.ids:
        return {"deleted": 0, "denied": 0}
    if body.entity_type == "observable":
        return await _delete_observables(db, body.ids, deny=body.deny)
    if body.entity_type not in DELETABLE_TYPES:
        return {"deleted": 0, "denied": 0}

    model = ENTITY_CONFIG[body.entity_type][0]
    rows = (await db.execute(select(model).where(model.id.in_(body.ids)))).scalars().all()

    denied = 0
    for entity in rows:
        denied += await delete_named_entity(
            db, body.entity_type, entity, deny=body.deny, reason="Deleted from the Engine review queues"
        )

    await db.commit()

    # The vocabulary is built from live entities — queue a rebuild so the
    # autolinker stops matching what we just removed within seconds, not at the
    # next sync. Queued rather than inline: a bulk clean-up sends one request per
    # row, and each inline build takes about ten seconds of CPU on the event loop.
    if rows:
        await schedule_vocabulary_refresh(db)

    return {"deleted": len(rows), "denied": denied}


class ExtractionBulkRequest(BaseModel):
    """Act on every AI-created entity the Review › Entities table shows."""

    action: Literal["confirm", "delete", "merge", "not_duplicate"]
    status: Literal["review", "orphan", "dupe"]
    types: list[str] | None = None
    q: str | None = None
    window: Literal["1h", "24h", "7d", "30d", "all"] = "all"
    deny: bool = True

    model_config = ConfigDict(json_schema_extra={"example": {"action": "confirm", "status": "review", "window": "all"}})


class ExtractionBulkResponse(BaseModel):
    action: str
    matched: int
    done: int
    skipped: int


_BULK_CAP = 5000


@router.post("/bulk", response_model=ExtractionBulkResponse)
async def extraction_bulk(
    body: ExtractionBulkRequest = Body(...),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> ExtractionBulkResponse:
    """The Entities lens's bulk buttons, over what its filters show rather
    than a checked selection: Confirm all / Delete all on Unconfirmed, Merge
    all / Not duplicates on Duplicates, Delete all on Orphans. Each row is
    handled the way its own button would handle it; a merge folds the row
    into the sibling it most resembles."""
    from app.api.entity_merge import perform_same_type_merge
    from app.services.proposal_dismissals import mark_not_duplicate, settle_gone_entity

    requested = [t for t in (body.types or []) if t in AI_TYPES] or list(AI_TYPES)
    days = _WINDOW_DAYS[body.window]
    window_start = None if days is None else _now() - timedelta(days=days)
    rows = await _fetch_rows(db, requested, window_start, (body.q or "").strip() or None)
    dup = await _duplicate_map(db, requested)
    for r in rows:
        r["status"] = _status(r, dup)
        sibling = dup.get(str(r["id"]))
        r["duplicate_of"], r["duplicate_of_id"] = sibling if sibling else (None, None)
    rows = [r for r in rows if r["status"] == body.status]
    if body.action in ("merge", "not_duplicate"):
        rows = [r for r in rows if r["duplicate_of_id"]]
    matched = len(rows)
    rows = rows[:_BULK_CAP]
    done = skipped = 0

    if body.action == "confirm":
        by_type: dict[str, list[uuid.UUID]] = defaultdict(list)
        for r in rows:
            if r["needs_review"]:
                by_type[r["entity_type"]].append(r["id"])
            else:
                skipped += 1
        for etype, ids in by_type.items():
            m = AI_TYPES[etype]["model"]
            res = await db.execute(update(m).where(m.id.in_(ids)).values(needs_review=False).returning(m.id))
            done += len(res.all())
        await db.commit()

    elif body.action == "delete":
        obs_ids = [r["id"] for r in rows if r["entity_type"] == "observable"]
        if obs_ids:
            done += (await _delete_observables(db, obs_ids, deny=body.deny))["deleted"]
        named = 0
        for etype in requested:
            if etype == "observable" or etype not in DELETABLE_TYPES:
                continue
            ids = [r["id"] for r in rows if r["entity_type"] == etype]
            if not ids:
                continue
            model = ENTITY_CONFIG[etype][0]
            for entity in (await db.execute(select(model).where(model.id.in_(ids)))).scalars().all():
                await delete_named_entity(
                    db, etype, entity, deny=body.deny, reason="Deleted from the Engine review queues"
                )
                named += 1
        done += named
        await db.commit()
        if named:
            await schedule_vocabulary_refresh(db)

    elif body.action == "merge":
        gone: set[uuid.UUID] = set()
        for r in rows:
            target = uuid.UUID(str(r["duplicate_of_id"]))
            if r["id"] in gone or target in gone:
                skipped += 1  # its sibling was folded earlier in this run
                continue
            try:
                await perform_same_type_merge(
                    db,
                    entity_type=r["entity_type"],
                    target_id=target,
                    source_id=r["id"],
                    mode="apply",
                    reasoning=f"Merge all from Review › Entities: {r['name']} into {r['duplicate_of']}",
                )
            except AppError:  # one half of the pair is already gone; nothing was written
                skipped += 1
                continue
            # As after a single Merge: the folded entity's pending proposals close
            # (a merge proposal into it moves to the keeper).
            await settle_gone_entity(db, r["entity_type"], r["id"], successor=(r["entity_type"], target))
            gone.add(r["id"])
            done += 1
        await db.commit()

    else:  # not_duplicate
        for r in rows:
            await mark_not_duplicate(db, r["entity_type"], r["id"], uuid.UUID(str(r["duplicate_of_id"])), user.id)
            done += 1
        await db.commit()

    return ExtractionBulkResponse(action=body.action, matched=matched, done=done, skipped=skipped)


# --- Do-not-recreate list -------------------------------------------------
# The denylist the extract stage consults before minting an entity. Rows land
# here from the AI entities table's delete, the entity profile's delete popover,
# or the add box in this panel; names are mirrored into the autolinker's
# false-positive list so the vocabulary drops them too.


class DenylistEntry(BaseModel):
    id: uuid.UUID
    entity_type: str
    display_name: str
    normalized_name: str
    reason: str | None
    source: str
    created_at: datetime


class DenylistResponse(BaseModel):
    items: list[DenylistEntry]
    total: int
    limit: int
    offset: int


class DenylistAddRequest(BaseModel):
    entity_type: str
    name: str

    model_config = ConfigDict(json_schema_extra={"example": {"entity_type": "malware", "name": "Prometheus"}})


@router.get("/denylist", response_model=DenylistResponse)
async def extraction_denylist(
    q: str | None = Query(None, description="Substring match on the display name."),
    entity_type: str | None = Query(None, description="Restrict to one entity type."),
    source: str | None = Query(None, description="'do_not_recreate' (analyst-written) or 'cleanup_2026_08' (seeded)."),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    _: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> DenylistResponse:
    """Names the extract stage refuses to re-create, newest first."""
    where = [EntityNameDenylist.active.is_(True)]
    if q:
        where.append(EntityNameDenylist.display_name.ilike(f"%{q}%"))
    if entity_type:
        where.append(EntityNameDenylist.entity_type == entity_type)
    if source:
        where.append(EntityNameDenylist.source == source)

    total = await db.scalar(select(func.count()).select_from(EntityNameDenylist).where(*where)) or 0
    rows = (
        (
            await db.execute(
                select(EntityNameDenylist)
                .where(*where)
                # The 2026-08 cleanup seeded ~320 rows with one identical
                # created_at, so time alone is not a total order — without the
                # tiebreakers, LIMIT/OFFSET repeats and drops rows across pages.
                .order_by(
                    EntityNameDenylist.created_at.desc(),
                    EntityNameDenylist.display_name.asc(),
                    EntityNameDenylist.id.asc(),
                )
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return DenylistResponse(
        items=[DenylistEntry.model_validate(r, from_attributes=True) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post("/denylist", response_model=DenylistEntry, status_code=201)
async def extraction_denylist_add(
    body: DenylistAddRequest = Body(...),
    _: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> DenylistEntry:
    """Ban a name from being created (without deleting anything). ``entity_type``
    of 'any' bans it for every type rather than scoping it to one."""
    if body.entity_type not in (*DENIABLE_TYPES, ANY_ENTITY_TYPE):
        raise AppError(
            code="bad_request",
            message=f"entity_type must be one of {sorted((*DENIABLE_TYPES, ANY_ENTITY_TYPE))}",
            status_code=422,
        )
    name = body.name.strip()
    if not name:
        raise AppError(code="bad_request", message="name is required", status_code=422)

    written = await deny_entity_names(db, body.entity_type, [name], reason="Added in Engine → Extract")
    if not written:
        raise AppError(code="bad_request", message="Name normalizes to nothing", status_code=422)
    await db.commit()
    await schedule_vocabulary_refresh(db)

    row = await db.scalar(
        select(EntityNameDenylist).where(
            EntityNameDenylist.entity_type == body.entity_type,
            EntityNameDenylist.normalized_name == normalize_entity_name(name, body.entity_type).norm_exact,
        )
    )
    return DenylistEntry.model_validate(row, from_attributes=True)


@router.delete("/denylist/{row_id}", status_code=204)
async def extraction_denylist_remove(
    row_id: uuid.UUID,
    _: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Lift the ban: the extract stage may create the name again, and it stops
    being excluded from autolinker matching."""
    row = await db.get(EntityNameDenylist, row_id)
    if not row:
        raise AppError(code="not_found", message="Denylist entry not found", status_code=404)
    display_name = row.display_name
    await db.delete(row)
    await sync_fp_names(db, remove=[display_name])
    await db.commit()
    await schedule_vocabulary_refresh(db)
