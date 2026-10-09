import uuid

from fastapi import APIRouter, Body, Depends, Path, Query, Response
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppError
from app.core.pagination import PaginatedResponse
from app.core.security import get_current_user
from app.database import get_db
from app.intelligence.relationship_matrix import (
    allowed_verbs_for_pair,
    hidden_relationship_confidences,
    is_allowed_relationship,
    orient_relationship,
)
from app.models.entity_relationship import EntityRelationship
from app.models.user import User
from app.schemas.entity_relationship import (
    EntityRelationshipCreate,
    EntityRelationshipResponse,
    EntityRelationshipUpdate,
)

router = APIRouter()


async def _invalidate_rel_caches(rel: EntityRelationship) -> None:
    """Drop cached pivots/graphs for both endpoints — they embed the
    relationship's verb, confidence and provenance."""
    from app.intelligence.correlation_cache import invalidate_entity_cache

    await invalidate_entity_cache(rel.source_type, str(rel.source_id))
    await invalidate_entity_cache(rel.target_type, str(rel.target_id))


async def _enrich_names(db: AsyncSession, relationships: list[EntityRelationship]) -> list[EntityRelationshipResponse]:
    """Populate source_name and target_name on relationship responses."""
    from app.models.campaign import Campaign
    from app.models.country import Country
    from app.models.cve import CVE
    from app.models.malware_family import MalwareFamily
    from app.models.mitigation import Mitigation
    from app.models.product import Product
    from app.models.sector import Sector
    from app.models.threat_actor import ThreatActor
    from app.models.tool import Tool
    from app.models.ttp import TTP
    from app.models.vendor import Vendor

    _configs: dict[str, tuple] = {
        "ttp": (TTP, TTP.technique_name),
        "cve": (CVE, CVE.cve_id),
        "threat_actor": (ThreatActor, ThreatActor.name),
        "malware": (MalwareFamily, MalwareFamily.name),
        "campaign": (Campaign, Campaign.name),
        "country": (Country, Country.name),
        "sector": (Sector, Sector.name),
        "mitigation": (Mitigation, Mitigation.name),
        "tool": (Tool, Tool.name),
        "vendor": (Vendor, Vendor.name),
        "product": (Product, Product.name),
    }

    # Collect unique (type, id) pairs
    by_type: dict[str, list[uuid.UUID]] = {}
    for rel in relationships:
        by_type.setdefault(rel.source_type, []).append(rel.source_id)
        by_type.setdefault(rel.target_type, []).append(rel.target_id)

    name_map: dict[tuple[str, uuid.UUID], str | None] = {}
    for etype, ids in by_type.items():
        if etype not in _configs:
            continue
        model, name_col = _configs[etype]
        result = await db.execute(select(model.id, name_col).where(model.id.in_(ids)))
        for row in result.all():
            name_map[(etype, row[0])] = row[1]

    items = []
    for rel in relationships:
        resp = EntityRelationshipResponse.model_validate(rel)
        resp.source_name = name_map.get((rel.source_type, rel.source_id))
        resp.target_name = name_map.get((rel.target_type, rel.target_id))
        items.append(resp)
    return items


@router.get("", response_model=PaginatedResponse[EntityRelationshipResponse])
async def list_entity_relationships(
    entity_type: str | None = Query(
        None, description="With entity_id, only relationships where that entity is source or target."
    ),
    entity_id: uuid.UUID | None = Query(
        None, description="Entity UUID to filter by (only applied together with entity_type)."
    ),
    relationship_type: str | None = Query(
        None,
        description="Filter by verb (uses, exploits, targets, attributed_to, variant_of, "
        "communicates_with, delivers, drops, hosts, related_to).",
    ),
    evidence_entry_id: uuid.UUID | None = Query(None, description="Only relationships citing this entry as evidence."),
    include_rejected: bool = Query(False, description="Include analyst-rejected relationships (hidden by default)."),
    all_confidence: bool = Query(
        False, description="Ignore the min-confidence display setting and return every stored edge."
    ),
    limit: int = Query(50, ge=1, le=500, description="Maximum relationships per page."),
    offset: int = Query(0, ge=0, description="Number of relationships to skip for pagination."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Paginated entity↔entity relationships, newest first, with endpoint display names resolved.

    Analyst-rejected edges and edges below the configured min-confidence are hidden
    unless ``include_rejected`` / ``all_confidence`` are set.
    """
    base = select(EntityRelationship)
    count_base = select(func.count()).select_from(EntityRelationship)

    if not include_rejected:
        base = base.where(EntityRelationship.source != "analyst_rejected")
        count_base = count_base.where(EntityRelationship.source != "analyst_rejected")

    # Display surfaces respect the min-confidence setting; management views
    # (engine Links tab) pass all_confidence=true to see every stored edge.
    hidden = hidden_relationship_confidences()
    if hidden and not all_confidence:
        base = base.where(EntityRelationship.confidence.notin_(hidden))
        count_base = count_base.where(EntityRelationship.confidence.notin_(hidden))

    if entity_type and entity_id:
        condition = or_(
            (EntityRelationship.source_type == entity_type) & (EntityRelationship.source_id == entity_id),
            (EntityRelationship.target_type == entity_type) & (EntityRelationship.target_id == entity_id),
        )
        base = base.where(condition)
        count_base = count_base.where(condition)

    if relationship_type:
        base = base.where(EntityRelationship.relationship_type == relationship_type)
        count_base = count_base.where(EntityRelationship.relationship_type == relationship_type)

    if evidence_entry_id is not None:
        condition = EntityRelationship.evidence_entry_ids.any(evidence_entry_id)
        base = base.where(condition)
        count_base = count_base.where(condition)

    total = (await db.execute(count_base)).scalar() or 0

    query = base.order_by(EntityRelationship.created_at.desc()).limit(limit).offset(offset)
    result = await db.execute(query)
    relationships = result.scalars().all()

    items = await _enrich_names(db, list(relationships))
    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset, has_more=(offset + limit) < total)


@router.post("/signals/{entity_type}")
async def relationship_signals(
    entity_type: str = Path(..., description="Entity type of every id in the request body."),
    ids: list[str] = Body(
        ...,
        embed=True,
        description="Entity IDs (max 1000)",
        examples=[["d5b2c8f0-3e4a-4b6c-9d1e-7f8a9b0c1d2e", "3f9d2a1b-8c7e-4f6a-b5d4-0e1c2a3b4d5f"]],
    ),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Batched relationship signals for table columns.

    POST because the table sends every loaded row's id — as a GET query string
    this overflowed gunicorn's 4094-byte request line (414) after a few pages.

    Per entity id: the count of (non-rejected) typed relationships and the top
    3 by confidence + evidence volume, with verb / direction / counterpart.
    """
    try:
        id_list = [uuid.UUID(x) for x in ids if x.strip()][:1000]
    except ValueError:
        raise AppError(code="invalid", message="ids must be UUIDs", status_code=400)
    if not id_list:
        return {}
    id_set = set(id_list)

    signals_query = select(EntityRelationship).where(
        EntityRelationship.source != "analyst_rejected",
        or_(
            (EntityRelationship.source_type == entity_type) & (EntityRelationship.source_id.in_(id_list)),
            (EntityRelationship.target_type == entity_type) & (EntityRelationship.target_id.in_(id_list)),
        ),
    )
    hidden = hidden_relationship_confidences()
    if hidden:
        signals_query = signals_query.where(EntityRelationship.confidence.notin_(hidden))
    result = await db.execute(signals_query)
    rels = list(result.scalars().all())
    enriched = await _enrich_names(db, rels)

    conf_rank = {"confirmed": 2, "probable": 1, "possible": 0}
    per_entity: dict[str, list[tuple[EntityRelationship, EntityRelationshipResponse, bool]]] = {}
    for rel, resp in zip(rels, enriched):
        if rel.source_type == entity_type and rel.source_id in id_set:
            per_entity.setdefault(str(rel.source_id), []).append((rel, resp, True))
        if rel.target_type == entity_type and rel.target_id in id_set:
            per_entity.setdefault(str(rel.target_id), []).append((rel, resp, False))

    out: dict[str, dict] = {}
    for eid, entries in per_entity.items():
        entries.sort(
            key=lambda t: (conf_rank.get(t[0].confidence, 0), len(t[0].evidence_entry_ids or [])),
            reverse=True,
        )
        out[eid] = {
            "count": len(entries),
            "top": [
                {
                    "verb": rel.relationship_type,
                    "direction": "outbound" if is_src else "inbound",
                    "other_type": rel.target_type if is_src else rel.source_type,
                    "other_label": resp.target_name if is_src else resp.source_name,
                    "confidence": rel.confidence,
                }
                for rel, resp, is_src in entries[:3]
            ],
        }
    return out


@router.get("/by-entity/{entity_type}/{entity_id}", response_model=list[EntityRelationshipResponse])
async def get_entity_relationships(
    entity_type: str = Path(..., description="Entity type of the pivot entity."),
    entity_id: uuid.UUID = Path(..., description="UUID of the pivot entity."),
    relationship_type: str | None = Query(None, description="Filter by verb (e.g. uses, targets, attributed_to)."),
    include_rejected: bool = Query(False, description="Include analyst-rejected relationships (hidden by default)."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get all relationships for a specific entity (as source or target)."""
    condition = or_(
        (EntityRelationship.source_type == entity_type) & (EntityRelationship.source_id == entity_id),
        (EntityRelationship.target_type == entity_type) & (EntityRelationship.target_id == entity_id),
    )
    query = select(EntityRelationship).where(condition)
    if not include_rejected:
        query = query.where(EntityRelationship.source != "analyst_rejected")
    hidden = hidden_relationship_confidences()
    if hidden:
        query = query.where(EntityRelationship.confidence.notin_(hidden))
    if relationship_type:
        query = query.where(EntityRelationship.relationship_type == relationship_type)
    query = query.order_by(EntityRelationship.created_at.desc())
    result = await db.execute(query)
    return await _enrich_names(db, list(result.scalars().all()))


@router.post("", response_model=EntityRelationshipResponse, status_code=201)
async def create_entity_relationship(
    body: EntityRelationshipCreate,
    response: Response,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create an analyst relationship between two entities.

    The (source, verb, target) triple is validated against the semantic allowlist and
    stored in its canonical orientation. Re-creating an existing triple merges evidence
    into the stored row and returns 200 instead of 201.
    """
    # Enforce the semantic matrix; a reversed triple is stored in its allowed
    # orientation so mirrored duplicates can't exist.
    oriented = orient_relationship(body.source_type, body.relationship_type, body.target_type)
    if oriented is None:
        verbs = allowed_verbs_for_pair(body.source_type, body.target_type) or allowed_verbs_for_pair(
            body.target_type, body.source_type
        )
        raise AppError(
            code="invalid_relationship",
            message=f"'{body.source_type} {body.relationship_type} {body.target_type}' is not a tracked combination",
            details={"allowed_verbs_for_pair": verbs},
            status_code=400,
        )
    src_type, tgt_type = oriented[0], oriented[2]
    src_id, tgt_id = body.source_id, body.target_id
    if src_type != body.source_type:
        src_id, tgt_id = tgt_id, src_id

    # Upsert on the (source, target, type) unique constraint: re-creating an
    # existing relationship merges evidence instead of erroring, and explicitly
    # re-creating a rejected one resurrects it (that's a deliberate analyst act).
    existing = (
        await db.execute(
            select(EntityRelationship).where(
                EntityRelationship.source_type == src_type,
                EntityRelationship.source_id == src_id,
                EntityRelationship.target_type == tgt_type,
                EntityRelationship.target_id == tgt_id,
                EntityRelationship.relationship_type == body.relationship_type,
            )
        )
    ).scalar_one_or_none()

    if existing is not None:
        merged = list(existing.evidence_entry_ids or [])
        merged += [e for e in body.evidence_entry_ids if e not in merged]
        existing.evidence_entry_ids = merged
        existing.confidence = body.confidence
        if body.description is not None:
            existing.description = body.description
        existing.source = "analyst_created"
        db.add(existing)
        await db.flush()
        await db.refresh(existing)
        await _invalidate_rel_caches(existing)
        response.status_code = 200
        return EntityRelationshipResponse.model_validate(existing)

    rel = EntityRelationship(
        source_type=src_type,
        source_id=src_id,
        target_type=tgt_type,
        target_id=tgt_id,
        relationship_type=body.relationship_type,
        confidence=body.confidence,
        source="analyst_created",
        description=body.description,
        evidence_entry_ids=body.evidence_entry_ids,
        created_by=user.id,
    )
    db.add(rel)
    await db.flush()
    await db.refresh(rel)
    await _invalidate_rel_caches(rel)
    return EntityRelationshipResponse.model_validate(rel)


@router.put("/{relationship_id}", response_model=EntityRelationshipResponse)
async def update_entity_relationship(
    relationship_id: uuid.UUID = Path(..., description="UUID of the relationship to update."),
    body: EntityRelationshipUpdate = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update the verb, confidence, description, or evidence entries of a relationship.

    A new verb must still be an allowed combination for the relationship's endpoint types.
    """
    result = await db.execute(select(EntityRelationship).where(EntityRelationship.id == relationship_id))
    rel = result.scalar_one_or_none()
    if not rel:
        raise AppError(code="not_found", message="Relationship not found", status_code=404)

    if body.relationship_type is not None and not is_allowed_relationship(
        rel.source_type, body.relationship_type, rel.target_type
    ):
        raise AppError(
            code="invalid_relationship",
            message=f"'{rel.source_type} {body.relationship_type} {rel.target_type}' is not a tracked combination",
            details={"allowed_verbs_for_pair": allowed_verbs_for_pair(rel.source_type, rel.target_type)},
            status_code=400,
        )

    for field in ["relationship_type", "confidence", "description", "evidence_entry_ids"]:
        value = getattr(body, field, None)
        if value is not None:
            setattr(rel, field, value)

    db.add(rel)
    await db.flush()
    await db.refresh(rel)
    await _invalidate_rel_caches(rel)
    return EntityRelationshipResponse.model_validate(rel)


@router.post("/{relationship_id}/confirm", response_model=EntityRelationshipResponse)
async def confirm_entity_relationship(
    relationship_id: uuid.UUID = Path(..., description="UUID of the relationship to confirm."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Upgrade an auto-extracted relationship to analyst_confirmed."""
    result = await db.execute(select(EntityRelationship).where(EntityRelationship.id == relationship_id))
    rel = result.scalar_one_or_none()
    if not rel:
        raise AppError(code="not_found", message="Relationship not found", status_code=404)
    rel.source = "analyst_confirmed"
    rel.confidence = "confirmed"
    db.add(rel)
    await db.flush()
    await db.refresh(rel)
    await _invalidate_rel_caches(rel)
    return EntityRelationshipResponse.model_validate(rel)


@router.post("/{relationship_id}/reject", response_model=EntityRelationshipResponse)
async def reject_entity_relationship(
    relationship_id: uuid.UUID = Path(..., description="UUID of the relationship to reject."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Mark a relationship as analyst-rejected.

    Rejected relationships are hidden from pivot/graph/list surfaces and the
    co-occurrence engine will not resurrect or accumulate evidence on them.
    The row is kept (not deleted) precisely so re-ingestion can't recreate it.
    """
    result = await db.execute(select(EntityRelationship).where(EntityRelationship.id == relationship_id))
    rel = result.scalar_one_or_none()
    if not rel:
        raise AppError(code="not_found", message="Relationship not found", status_code=404)
    rel.source = "analyst_rejected"
    db.add(rel)
    await db.flush()
    await db.refresh(rel)
    await _invalidate_rel_caches(rel)
    return EntityRelationshipResponse.model_validate(rel)


@router.delete("/{relationship_id}", status_code=204)
async def delete_entity_relationship(
    relationship_id: uuid.UUID = Path(..., description="UUID of the relationship to delete."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Hard-delete a relationship and invalidate cached graphs for both endpoints.

    Prefer the reject action for auto-extracted edges — a deleted row can be recreated
    by re-ingestion, while a rejected one cannot.
    """
    result = await db.execute(select(EntityRelationship).where(EntityRelationship.id == relationship_id))
    rel = result.scalar_one_or_none()
    if not rel:
        raise AppError(code="not_found", message="Relationship not found", status_code=404)
    await _invalidate_rel_caches(rel)
    await db.delete(rel)
    await db.flush()
