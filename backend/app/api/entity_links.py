"""Autolinking admin API — entry→entity autolinks across the seven junction
tables, unified for the Settings → Engine → Autolinking tab.

The junction tables are heterogeneous: EntryTTP has ``source_text`` but no
``source``/``matched_names``; EntryCVE has neither ``source`` nor
``confidence``; the other five carry the full autolinker column set. We
normalize each into a common column shape and ``UNION ALL`` them so the tab can
page/filter/sort across every entity type at once.

Rows have a composite ``(entry_id, entity_id)`` primary key — there is no
surrogate id — so unlink keys on ``(entity_type, entity_id, entry_id)``.
"""

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from fastapi import APIRouter, Body, Depends, Path, Query
from sqlalchemy import String, Text, cast, func, null, or_, select, union_all
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import InstrumentedAttribute

from app.core.exceptions import AppError
from app.core.pagination import PaginatedResponse
from app.core.security import get_current_user, get_viewer
from app.database import get_db
from app.intelligence.autolinker import dropped_ai_off_count
from app.models.cve import CVE, EntryCVE
from app.models.cwe import CWE, EntryCWE
from app.models.entity_relationship import EntityRelationship
from app.models.entry import Entry
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.pending_autolink import PendingAutolinkMatch
from app.models.product import EntryProduct, Product
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.tool import EntryTool, Tool
from app.models.ttp import TTP, EntryTTP
from app.models.user import User
from app.models.vendor import EntryVendor, Vendor
from app.schemas.entity_link import (
    BulkUnlinkRequest,
    BulkUnlinkResponse,
    EntityLinkResponse,
    EntityLinkStats,
    LinkRef,
)

router = APIRouter()


@dataclass(frozen=True)
class LinkConfig:
    entity_type: str
    junction: type
    fk_attr: str  # junction column pointing at the entity
    entity_model: type
    name_col: InstrumentedAttribute  # the entity's display column
    has_source: bool
    has_matched: bool
    has_confidence: bool


# Ordered so the union is deterministic; keys are the API's entity_type values.
LINK_CONFIGS: dict[str, LinkConfig] = {
    "threat_actor": LinkConfig(
        "threat_actor", EntryThreatActor, "threat_actor_id", ThreatActor, ThreatActor.name, True, True, True
    ),  # noqa: E501
    "malware": LinkConfig(
        "malware", EntryMalware, "malware_family_id", MalwareFamily, MalwareFamily.name, True, True, True
    ),  # noqa: E501
    "tool": LinkConfig("tool", EntryTool, "tool_id", Tool, Tool.name, True, True, True),
    "vendor": LinkConfig("vendor", EntryVendor, "vendor_id", Vendor, Vendor.name, True, True, True),
    "product": LinkConfig("product", EntryProduct, "product_id", Product, Product.name, True, True, True),
    # TTP labels on the technique id ("T1059.001"); CVE on the cve id.
    "ttp": LinkConfig("ttp", EntryTTP, "ttp_id", TTP, TTP.technique_id, False, False, True),
    "cve": LinkConfig("cve", EntryCVE, "cve_id", CVE, CVE.cve_id, False, False, False),
    # Weakness links are autolinker-created and carry source + confidence, but
    # no matched_names: the scanner matches the id pattern, so the surface form
    # is always the id itself.
    "cwe": LinkConfig("cwe", EntryCWE, "cwe_id", CWE, CWE.cwe_id, True, False, True),
}


def _link_subquery(
    cfg: LinkConfig,
    *,
    search: str | None,
    source: str | None,
    confidence: str | None,
    since: datetime | None,
    entity_id: uuid.UUID | None,
    entry_id: uuid.UUID | None = None,
):
    """Normalized SELECT for one junction table, or None if the active filters
    can never match this table (e.g. a source filter against TTP/CVE)."""
    if source and not cfg.has_source:
        return None
    if confidence and not cfg.has_confidence:
        return None

    j = cfg.junction
    fk = getattr(j, cfg.fk_attr)

    cols = [
        cast(cfg.entity_type, String).label("entity_type"),
        fk.label("entity_id"),
        cfg.name_col.label("entity_name"),
        j.entry_id.label("entry_id"),
        Entry.title.label("entry_title"),
        (j.confidence if cfg.has_confidence else cast(null(), String)).label("confidence"),
        (j.source if cfg.has_source else cast(null(), String)).label("source"),
        (j.matched_names if cfg.has_matched else cast(null(), ARRAY(Text))).label("matched_names"),
        j.paragraph_indices.label("paragraph_indices"),
        j.extracted_at.label("extracted_at"),
    ]

    q = select(*cols).join(cfg.entity_model, fk == cfg.entity_model.id).join(Entry, j.entry_id == Entry.id)
    if entity_id is not None:
        q = q.where(fk == entity_id)
    if entry_id is not None:
        q = q.where(j.entry_id == entry_id)
    if source and cfg.has_source:
        q = q.where(j.source == source)
    if confidence and cfg.has_confidence:
        q = q.where(j.confidence == confidence)
    if since is not None:
        q = q.where(j.extracted_at >= since)
    if search:
        term = f"%{search}%"
        q = q.where(or_(cfg.name_col.ilike(term), Entry.title.ilike(term)))
    return q


@router.get("", response_model=PaginatedResponse[EntityLinkResponse])
async def list_entity_links(
    entity_type: str | None = Query(
        None, description="Restrict to one junction table (threat_actor, malware, tool, vendor, product, ttp, cve)."
    ),
    entity_id: uuid.UUID | None = Query(None, description="Only links pointing at this entity."),
    entry_id: uuid.UUID | None = Query(None, description="Only links on this feed entry."),
    source: str | None = Query(
        None,
        description="Filter by provenance (auto_link, ai, ai_reconcile, auto_extracted, manual). "
        "TTP/CVE junctions record no source and are excluded when set.",
    ),
    confidence: str | None = Query(
        None,
        description="Filter by link confidence (high, medium, low). "
        "The CVE junction has none and is excluded when set.",
    ),
    search: str | None = Query(None, description="Case-insensitive substring match on entity name or entry title."),
    days: int | None = Query(None, ge=1, le=3650, description="Only links extracted within the last N days"),
    limit: int = Query(50, ge=1, le=500, description="Maximum links per page."),
    offset: int = Query(0, ge=0, description="Number of links to skip for pagination."),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Paginated entry→entity autolinks, unioned across all junction tables and
    sorted newest-first. ``entity_type`` scopes to a single table; the remaining
    params filter within it."""
    if entity_type and entity_type not in LINK_CONFIGS:
        raise AppError(code="invalid", message=f"Unknown entity_type: {entity_type}", status_code=400)

    since = datetime.now().astimezone() - timedelta(days=days) if days else None
    configs = [LINK_CONFIGS[entity_type]] if entity_type else list(LINK_CONFIGS.values())

    subqueries = [
        sq
        for cfg in configs
        if (
            sq := _link_subquery(
                cfg,
                search=search,
                source=source,
                confidence=confidence,
                since=since,
                entity_id=entity_id,
                entry_id=entry_id,
            )
        )
        is not None  # noqa: E501
    ]
    if not subqueries:
        return PaginatedResponse(items=[], total=0, limit=limit, offset=offset, has_more=False)

    unioned = subqueries[0] if len(subqueries) == 1 else union_all(*subqueries)
    u = unioned.subquery()

    total = (await db.execute(select(func.count()).select_from(u))).scalar() or 0
    rows = (await db.execute(select(u).order_by(u.c.extracted_at.desc()).limit(limit).offset(offset))).mappings().all()

    items = [EntityLinkResponse.model_validate(dict(r)) for r in rows]
    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset, has_more=(offset + limit) < total)


@router.get("/stats", response_model=EntityLinkStats)
async def entity_link_stats(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Health signals for the Autolinking tab: totals by type and provenance,
    plus how many held matches are waiting for their article's analysis."""
    by_type: dict[str, int] = {}
    by_source: dict[str, int] = {}

    for cfg in LINK_CONFIGS.values():
        j = cfg.junction
        if cfg.has_source:
            rows = (
                await db.execute(select(func.coalesce(j.source, "unattributed"), func.count()).group_by(j.source))
            ).all()
            type_total = 0
            for src, cnt in rows:
                by_source[src] = by_source.get(src, 0) + cnt
                type_total += cnt
            by_type[cfg.entity_type] = type_total
        else:
            cnt = (await db.execute(select(func.count()).select_from(j))).scalar() or 0
            by_type[cfg.entity_type] = cnt
            by_source["unattributed"] = by_source.get("unattributed", 0) + cnt

    pending = (
        await db.execute(
            select(func.count()).select_from(PendingAutolinkMatch).where(PendingAutolinkMatch.resolution.is_(None))
        )
    ).scalar() or 0
    pending_dropped_ai_off = await dropped_ai_off_count(days=30)
    relationships_total = (
        await db.execute(
            select(func.count()).select_from(EntityRelationship).where(EntityRelationship.source != "analyst_rejected")
        )
    ).scalar() or 0

    return EntityLinkStats(
        total=sum(by_type.values()),
        by_source=by_source,
        by_type=by_type,
        pending=pending,
        pending_dropped_ai_off=pending_dropped_ai_off,
        relationships_total=relationships_total,
    )


async def _delete_link(db: AsyncSession, ref: LinkRef) -> bool:
    cfg = LINK_CONFIGS.get(ref.entity_type)
    if cfg is None:
        return False
    j = cfg.junction
    fk = getattr(j, cfg.fk_attr)
    result = await db.execute(select(j).where(j.entry_id == ref.entry_id, fk == ref.entity_id))
    row = result.scalar_one_or_none()
    if row is None:
        return False
    await db.delete(row)
    # Drop cached pivots/graphs that embedded this link as evidence.
    try:
        from app.intelligence.correlation_cache import invalidate_entity_cache

        await invalidate_entity_cache(ref.entity_type, str(ref.entity_id))
    except Exception:  # cache invalidation is best-effort
        pass
    return True


@router.delete("/{entity_type}/{entity_id}/{entry_id}", status_code=204)
async def unlink(
    entity_type: str = Path(
        ..., description="Entity type of the link (threat_actor, malware, tool, vendor, product, ttp, cve)."
    ),
    entity_id: uuid.UUID = Path(..., description="UUID of the linked entity."),
    entry_id: uuid.UUID = Path(..., description="UUID of the entry to unlink from the entity."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Remove a single entry→entity autolink."""
    if entity_type not in LINK_CONFIGS:
        raise AppError(code="invalid", message=f"Unknown entity_type: {entity_type}", status_code=400)
    ok = await _delete_link(db, LinkRef(entity_type=entity_type, entity_id=entity_id, entry_id=entry_id))
    if not ok:
        raise AppError(code="not_found", message="Link not found", status_code=404)
    await db.flush()


@router.post("/bulk-unlink", response_model=BulkUnlinkResponse)
async def bulk_unlink(
    body: BulkUnlinkRequest = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Remove up to 500 autolinks in one call."""
    if len(body.items) > 500:
        raise AppError(code="invalid", message="At most 500 links per request", status_code=400)
    deleted = 0
    for ref in body.items:
        if await _delete_link(db, ref):
            deleted += 1
    await db.flush()
    return BulkUnlinkResponse(deleted=deleted)
