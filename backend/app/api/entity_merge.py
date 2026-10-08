"""Merge endpoints for duplicate threat actors / malware families.

These are the primitive operations the autonomous entity_merge_maintenance
worker calls (via the IntelFeed skill in claude-code) when it decides two
entities are the same. Also usable by humans from the workbench.

A merge does three things atomically:
  1. Move all junction rows (entry_threat_actors, threat_actor_target_countries
     for actors; entry_malware for malware) from source → target. Existing
     (entry_id, target_id) rows survive — source rows on the same entry are
     just dropped.
  2. Union source.aliases (plus source.name) into target.aliases (deduped,
     case-insensitive).
  3. Optionally update target.description / target.aliases if the caller
     supplied new values, then delete the source row.

A maintenance-log row is written for every merge (mode = 'shadow' | 'apply'),
giving the operator full audit + revert capability.
"""

from __future__ import annotations

import uuid
from typing import Literal

from fastapi import APIRouter, Body, Depends, Path, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app import entity_types
from app.core.exceptions import AppError
from app.core.security import get_admin_user, get_current_user
from app.database import get_db
from app.models.country_junction import ThreatActorTargetCountry
from app.models.entity_maintenance import EntityMaintenanceLog, EntityReclassifyTombstone
from app.models.entity_relationship import EntityRelationship
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.product import EntryProduct, Product
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.tool import EntryTool, Tool
from app.models.user import User
from app.models.vendor import EntryVendor, Vendor
from app.services.entity_backlink import dispatch_backlink_for_added_aliases, dispatch_entity_backlink
from app.services.entity_indexer import delete_entity_document

router = APIRouter()


# Registry of every entity type that participates in autonomous merge +
# reclassification. Keep aligned with the prompt in
# backend/app/ai/prompts/defaults.py (entity_merge_maintenance).
#
# Each entry maps: entity_type → (model, junction_model, FK attribute on the junction
# pointing at the entity, table name for raw SQL cluster discovery).
ENTITY_TYPE_REGISTRY: dict[str, dict] = {
    "threat_actor": {
        "model": ThreatActor,
        "junction_model": EntryThreatActor,
        "junction_fk": "threat_actor_id",
        "table": "threat_actors",
    },
    "malware": {
        "model": MalwareFamily,
        "junction_model": EntryMalware,
        "junction_fk": "malware_family_id",
        "table": "malware_families",
    },
    "vendor": {
        "model": Vendor,
        "junction_model": EntryVendor,
        "junction_fk": "vendor_id",
        "table": "vendors",
    },
    "product": {
        "model": Product,
        "junction_model": EntryProduct,
        "junction_fk": "product_id",
        "table": "products",
    },
    "tool": {
        "model": Tool,
        "junction_model": EntryTool,
        "junction_fk": "tool_id",
        "table": "tools",
    },
}


# Retired spellings are folded centrally — see app/entity_types.py.
canonical_entity_type = entity_types.normalize_entity_type


def _get_type_spec(entity_type: str) -> dict:
    spec = ENTITY_TYPE_REGISTRY.get(canonical_entity_type(entity_type))
    if not spec:
        raise AppError(
            code="invalid",
            message=f"unsupported entity_type: {entity_type}",
            status_code=400,
        )
    return spec


# ----------------------------------------------------------------- schemas


class MergeRequest(BaseModel):
    source_id: uuid.UUID = Field(description="Entity to be merged away (deleted at the end).")
    mode: Literal["shadow", "apply"] = Field(
        default="apply",
        description="In 'shadow' mode, log what would happen but make no changes.",
    )
    new_description: str | None = Field(
        default=None,
        description="Replace target description with this. None = leave existing.",
    )
    extra_aliases: list[str] = Field(
        default_factory=list,
        description="Additional aliases to add to target on top of source.name + source.aliases.",
    )
    reasoning: str | None = Field(
        default=None,
        max_length=2000,
        description="Why this merge — recorded in the maintenance log.",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "source_id": "3f9d2a1b-8c7e-4f6a-b5d4-0e1c2a3b4d5f",
                "mode": "apply",
                "extra_aliases": ["Cozy Bear"],
                "reasoning": "Same actor: shared aliases and overlapping infrastructure reporting.",
            }
        }
    )


class MergeResponse(BaseModel):
    action: str  # 'merge'
    mode: str
    target_id: uuid.UUID
    source_id: uuid.UUID
    moved_entry_links: int
    moved_country_links: int
    merged_alias_count: int
    log_id: uuid.UUID
    applied: bool


# --------------------------------------------------------------- helpers


def _dedupe_aliases(values: list[str], exclude: str = "") -> list[str]:
    """Deduplicate aliases case-insensitively, preserving first-seen casing.

    `exclude` (typically the canonical entity name) is dropped so merge/reclassify
    don't fold a source.name that equals target.name (case-different) into the
    target's aliases — the UI hides self-aliases and they look like phantom
    aliases in the DB.
    """
    excl_key = exclude.strip().lower()
    seen: dict[str, str] = {}
    for v in values:
        if not v:
            continue
        key = v.strip().lower()
        if not key or key in seen or key == excl_key:
            continue
        seen[key] = v.strip()
    return list(seen.values())


_CONFIDENCE_ORDER = {"possible": 0, "probable": 1, "confirmed": 2}


async def _repoint_entity_relationships(
    db: AsyncSession,
    old_type: str,
    old_id: uuid.UUID,
    new_type: str,
    new_id: uuid.UUID,
) -> int:
    """Repoint EntityRelationship rows from (old_type, old_id) to (new_type, new_id).

    Used by merge (same type, new id) and reclassify (new type, possibly new id)
    so relationship evidence and confidence survive instead of dangling on a
    deleted entity. Rows whose repointed identity collides with an existing row
    merge their evidence into it (keeping the stronger confidence) and are
    deleted; self-relationships are dropped.
    """
    result = await db.execute(
        select(EntityRelationship).where(
            or_(
                (EntityRelationship.source_type == old_type) & (EntityRelationship.source_id == old_id),
                (EntityRelationship.target_type == old_type) & (EntityRelationship.target_id == old_id),
            )
        )
    )
    rows = list(result.scalars().all())
    touched = 0
    for rel in rows:
        s_type, s_id = rel.source_type, rel.source_id
        t_type, t_id = rel.target_type, rel.target_id
        if s_type == old_type and s_id == old_id:
            s_type, s_id = new_type, new_id
        if t_type == old_type and t_id == old_id:
            t_type, t_id = new_type, new_id

        # Merging an entity into one it was related to would create a self-edge.
        if s_type == t_type and s_id == t_id:
            await db.delete(rel)
            touched += 1
            continue

        existing = (
            await db.execute(
                select(EntityRelationship).where(
                    EntityRelationship.source_type == s_type,
                    EntityRelationship.source_id == s_id,
                    EntityRelationship.target_type == t_type,
                    EntityRelationship.target_id == t_id,
                    EntityRelationship.relationship_type == rel.relationship_type,
                    EntityRelationship.id != rel.id,
                )
            )
        ).scalar_one_or_none()

        if existing is not None:
            merged = list(existing.evidence_entry_ids or [])
            merged += [e for e in (rel.evidence_entry_ids or []) if e not in merged]
            existing.evidence_entry_ids = merged
            # A coincidental adjudication verdict survives the merge — folding
            # in a duplicate must not silently undo the AI's demotion.
            if existing.adjudication_verdict != "coincidental" and _CONFIDENCE_ORDER.get(
                rel.confidence, 0
            ) > _CONFIDENCE_ORDER.get(existing.confidence, 0):
                existing.confidence = rel.confidence
            await db.delete(rel)
        else:
            rel.source_type, rel.source_id = s_type, s_id
            rel.target_type, rel.target_id = t_type, t_id
        touched += 1

    if touched:
        await db.flush()
    return touched


async def _move_target_sectors(db: AsyncSession, entity_type: str, source_id: uuid.UUID, target) -> int:
    """Re-point the source's target-sector claims at the survivor.

    A sector both already carry keeps the stronger source and the higher
    evidence count; the duplicate row is dropped. The survivor's cache column is
    rebuilt afterwards so its chips reflect the union.
    """
    from app.services.sector_links import (
        SOURCE_PRECEDENCE,
        junction_for,
        refresh_targeted_sectors_cache,
    )

    _, junction, fk_attr = junction_for(entity_type)
    fk = getattr(junction, fk_attr)
    existing = {
        row.sector_id: row for row in (await db.execute(select(junction).where(fk == target.id))).scalars().all()
    }
    moved = 0
    for row in (await db.execute(select(junction).where(fk == source_id))).scalars().all():
        kept = existing.get(row.sector_id)
        if kept is None:
            setattr(row, fk_attr, target.id)
            moved += 1
            continue
        if SOURCE_PRECEDENCE[row.source] > SOURCE_PRECEDENCE[kept.source]:
            kept.source = row.source
        kept.article_count = max(kept.article_count or 0, row.article_count or 0)
        await db.delete(row)
    await db.flush()
    await refresh_targeted_sectors_cache(db, entity_type, target)
    return moved


def _snapshot_actor(actor: ThreatActor) -> dict:
    return {
        "id": str(actor.id),
        "name": actor.name,
        "aliases": list(actor.aliases or []),
        "description": actor.description,
        "article_count": actor.article_count,
        "mitre_id": actor.mitre_id,
        "country": actor.country,
        "motivation": actor.motivation,
    }


def _snapshot_malware(m: MalwareFamily) -> dict:
    return {
        "id": str(m.id),
        "name": m.name,
        "aliases": list(m.aliases or []),
        "description": m.description,
        "article_count": m.article_count,
        "malware_type": m.malware_type,
    }


# ---------------------------------------------------------- actor merge


async def perform_actor_merge(
    db: AsyncSession,
    target_id: uuid.UUID,
    body: MergeRequest,
) -> MergeResponse:
    """Same as the route handler, but callable from a tool / worker context.

    Raises AppError on validation problems. Caller owns the transaction
    (we only flush — commit is the caller's responsibility).
    """
    if body.source_id == target_id:
        raise AppError(code="invalid", message="source and target must differ", status_code=400)

    target = (await db.execute(select(ThreatActor).where(ThreatActor.id == target_id))).scalar_one_or_none()
    source = (await db.execute(select(ThreatActor).where(ThreatActor.id == body.source_id))).scalar_one_or_none()
    if not target:
        raise AppError(code="not_found", message="target actor not found", status_code=404)
    if not source:
        raise AppError(code="not_found", message="source actor not found", status_code=404)

    before = {"target": _snapshot_actor(target), "source": _snapshot_actor(source)}

    merged_aliases = _dedupe_aliases(
        list(target.aliases or []) + list(source.aliases or []) + [source.name] + list(body.extra_aliases),
        exclude=target.name,
    )
    after = {
        "target_id": str(target_id),
        "merged_aliases": merged_aliases,
        "new_description": body.new_description if body.new_description is not None else target.description,
        "dropped_source_id": str(body.source_id),
    }

    log_row = EntityMaintenanceLog(
        entity_type="threat_actor",
        entity_id=target_id,
        action="merge",
        mode=body.mode,
        before=before,
        after=after,
        reasoning=(body.reasoning or "")[:2000] or None,
        applied=(body.mode == "apply"),
    )
    db.add(log_row)

    if body.mode != "apply":
        await db.flush()
        return MergeResponse(
            action="merge",
            mode="shadow",
            target_id=target_id,
            source_id=body.source_id,
            moved_entry_links=0,
            moved_country_links=0,
            merged_alias_count=len(merged_aliases),
            log_id=log_row.id,
            applied=False,
        )

    # --- Apply mode: actually mutate.
    # entry_threat_actors: move source rows to target, skipping (entry_id, target_id) collisions.
    existing_pairs = await db.execute(
        select(EntryThreatActor.entry_id).where(EntryThreatActor.threat_actor_id == target_id)
    )
    existing_entries = {row for row in existing_pairs.scalars().all()}
    src_rows = await db.execute(select(EntryThreatActor).where(EntryThreatActor.threat_actor_id == body.source_id))
    moved_entries = 0
    dropped_entries = 0
    for j in src_rows.scalars().all():
        if j.entry_id in existing_entries:
            await db.delete(j)
            dropped_entries += 1
        else:
            j.threat_actor_id = target_id
            moved_entries += 1
    await db.flush()

    # threat_actor_target_countries: same pattern.
    existing_country_q = await db.execute(
        select(ThreatActorTargetCountry.country_id).where(ThreatActorTargetCountry.threat_actor_id == target_id)
    )
    existing_countries = {row for row in existing_country_q.scalars().all()}
    src_country_q = await db.execute(
        select(ThreatActorTargetCountry).where(ThreatActorTargetCountry.threat_actor_id == body.source_id)
    )
    moved_countries = 0
    for j in src_country_q.scalars().all():
        if j.country_id in existing_countries:
            await db.delete(j)
        else:
            j.threat_actor_id = target_id
            moved_countries += 1
    await db.flush()
    await _move_target_sectors(db, "threat_actor", body.source_id, target)

    # Aliases + description + article_count
    original_aliases = list(target.aliases or [])
    target.aliases = merged_aliases
    if body.new_description is not None:
        target.description = body.new_description
    target.article_count = (target.article_count or 0) + (source.article_count or 0) - dropped_entries

    # Repoint relationship evidence to the survivor, then delete source
    await _repoint_entity_relationships(db, "threat_actor", body.source_id, "threat_actor", target_id)
    await db.delete(source)
    await db.flush()
    delete_entity_document("threat_actor", body.source_id)

    # Absorbed names widen the target's match surface — retro-scan existing entries
    dispatch_backlink_for_added_aliases("threat_actor", target_id, original_aliases, merged_aliases)

    return MergeResponse(
        action="merge",
        mode="apply",
        target_id=target_id,
        source_id=body.source_id,
        moved_entry_links=moved_entries,
        moved_country_links=moved_countries,
        merged_alias_count=len(merged_aliases),
        log_id=log_row.id,
        applied=True,
    )


@router.post("/threat-actors/{target_id}/merge", response_model=MergeResponse)
async def merge_threat_actors(
    target_id: uuid.UUID = Path(..., description="UUID of the surviving (target) threat actor."),
    body: MergeRequest = Body(...),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Merge one threat actor into another: move entry and target-country links to the target,
    union aliases (including the source name), log the merge, then delete the source.
    Shadow mode records what would happen without changing data."""
    return await perform_actor_merge(db, target_id, body)


# -------------------------------------------------------- malware merge


async def perform_malware_merge(
    db: AsyncSession,
    target_id: uuid.UUID,
    body: MergeRequest,
) -> MergeResponse:
    if body.source_id == target_id:
        raise AppError(code="invalid", message="source and target must differ", status_code=400)

    target = (await db.execute(select(MalwareFamily).where(MalwareFamily.id == target_id))).scalar_one_or_none()
    source = (await db.execute(select(MalwareFamily).where(MalwareFamily.id == body.source_id))).scalar_one_or_none()
    if not target:
        raise AppError(code="not_found", message="target malware not found", status_code=404)
    if not source:
        raise AppError(code="not_found", message="source malware not found", status_code=404)

    before = {"target": _snapshot_malware(target), "source": _snapshot_malware(source)}
    merged_aliases = _dedupe_aliases(
        list(target.aliases or []) + list(source.aliases or []) + [source.name] + list(body.extra_aliases),
        exclude=target.name,
    )
    after = {
        "target_id": str(target_id),
        "merged_aliases": merged_aliases,
        "new_description": body.new_description if body.new_description is not None else target.description,
        "dropped_source_id": str(body.source_id),
    }

    log_row = EntityMaintenanceLog(
        entity_type="malware",
        entity_id=target_id,
        action="merge",
        mode=body.mode,
        before=before,
        after=after,
        reasoning=(body.reasoning or "")[:2000] or None,
        applied=(body.mode == "apply"),
    )
    db.add(log_row)

    if body.mode != "apply":
        await db.flush()
        return MergeResponse(
            action="merge",
            mode="shadow",
            target_id=target_id,
            source_id=body.source_id,
            moved_entry_links=0,
            moved_country_links=0,
            merged_alias_count=len(merged_aliases),
            log_id=log_row.id,
            applied=False,
        )

    # Move entry_malware rows.
    existing_pairs = await db.execute(select(EntryMalware.entry_id).where(EntryMalware.malware_family_id == target_id))
    existing_entries = {row for row in existing_pairs.scalars().all()}
    src_rows = await db.execute(select(EntryMalware).where(EntryMalware.malware_family_id == body.source_id))
    moved = 0
    dropped = 0
    for j in src_rows.scalars().all():
        if j.entry_id in existing_entries:
            await db.delete(j)
            dropped += 1
        else:
            j.malware_family_id = target_id
            moved += 1
    await db.flush()

    original_aliases = list(target.aliases or [])
    target.aliases = merged_aliases
    if body.new_description is not None:
        target.description = body.new_description
    target.article_count = (target.article_count or 0) + (source.article_count or 0) - dropped

    await _move_target_sectors(db, "malware", body.source_id, target)
    await _repoint_entity_relationships(db, "malware", body.source_id, "malware", target_id)
    await db.delete(source)
    await db.flush()
    delete_entity_document("malware", body.source_id)

    # Absorbed names widen the target's match surface — retro-scan existing entries
    dispatch_backlink_for_added_aliases("malware", target_id, original_aliases, merged_aliases)

    return MergeResponse(
        action="merge",
        mode="apply",
        target_id=target_id,
        source_id=body.source_id,
        moved_entry_links=moved,
        moved_country_links=0,
        merged_alias_count=len(merged_aliases),
        log_id=log_row.id,
        applied=True,
    )


@router.post("/malware/{target_id}/merge", response_model=MergeResponse)
async def merge_malware(
    target_id: uuid.UUID = Path(..., description="UUID of the surviving (target) malware family."),
    body: MergeRequest = Body(...),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Merge one malware family into another: move entry links to the target, union aliases
    (including the source name), log the merge, then delete the source. Shadow mode records
    what would happen without changing data."""
    return await perform_malware_merge(db, target_id, body)


# ----------------------------------------- generic same-type merge


async def perform_same_type_merge(
    db: AsyncSession,
    entity_type: str,
    target_id: uuid.UUID,
    source_id: uuid.UUID,
    mode: str = "apply",
    new_description: str | None = None,
    extra_aliases: list[str] | None = None,
    reasoning: str | None = None,
) -> MergeResponse:
    """Generic same-type merge for any registered entity_type.

    The threat_actor and malware code paths above keep their dedicated
    helpers because the actor merge also moves threat_actor_target_countries
    rows. For vendor / product / tool — which only have one junction
    table each — this generic implementation is the merge primitive.
    """
    spec = _get_type_spec(entity_type)
    model = spec["model"]
    junction = spec["junction_model"]
    fk_attr = spec["junction_fk"]

    if source_id == target_id:
        raise AppError(code="invalid", message="source and target must differ", status_code=400)

    target = (await db.execute(select(model).where(model.id == target_id))).scalar_one_or_none()
    source = (await db.execute(select(model).where(model.id == source_id))).scalar_one_or_none()
    if not target:
        raise AppError(code="not_found", message=f"target {entity_type} not found", status_code=404)
    if not source:
        raise AppError(code="not_found", message=f"source {entity_type} not found", status_code=404)

    before = {"target": _snapshot_generic(target), "source": _snapshot_generic(source)}
    merged_aliases = _dedupe_aliases(
        list(target.aliases or []) + list(source.aliases or []) + [source.name] + list(extra_aliases or []),
        exclude=target.name,
    )
    after = {
        "target_id": str(target_id),
        "merged_aliases": merged_aliases,
        "new_description": new_description if new_description is not None else target.description,
        "dropped_source_id": str(source_id),
    }

    log_row = EntityMaintenanceLog(
        entity_type=entity_type,
        entity_id=target_id,
        action="merge",
        mode=mode,
        before=before,
        after=after,
        reasoning=(reasoning or "")[:2000] or None,
        applied=(mode == "apply"),
    )
    db.add(log_row)

    if mode != "apply":
        await db.flush()
        return MergeResponse(
            action="merge",
            mode="shadow",
            target_id=target_id,
            source_id=source_id,
            moved_entry_links=0,
            moved_country_links=0,
            merged_alias_count=len(merged_aliases),
            log_id=log_row.id,
            applied=False,
        )

    existing_pairs = await db.execute(select(junction.entry_id).where(getattr(junction, fk_attr) == target_id))
    existing_entries = {row for row in existing_pairs.scalars().all()}
    src_rows = await db.execute(select(junction).where(getattr(junction, fk_attr) == source_id))
    moved = 0
    dropped = 0
    for j in src_rows.scalars().all():
        if j.entry_id in existing_entries:
            await db.delete(j)
            dropped += 1
        else:
            setattr(j, fk_attr, target_id)
            moved += 1
    await db.flush()

    original_aliases = list(target.aliases or [])
    target.aliases = merged_aliases
    if new_description is not None:
        target.description = new_description
    target.article_count = (target.article_count or 0) + (source.article_count or 0) - dropped

    await _repoint_entity_relationships(db, entity_type, source_id, entity_type, target_id)
    await db.delete(source)
    await db.flush()
    delete_entity_document(entity_type, source_id)

    # Absorbed names widen the target's match surface — retro-scan existing entries
    dispatch_backlink_for_added_aliases(entity_type, target_id, original_aliases, merged_aliases)

    return MergeResponse(
        action="merge",
        mode="apply",
        target_id=target_id,
        source_id=source_id,
        moved_entry_links=moved,
        moved_country_links=0,
        merged_alias_count=len(merged_aliases),
        log_id=log_row.id,
        applied=True,
    )


@router.post("/vendors/{target_id}/merge", response_model=MergeResponse)
async def merge_vendors(
    target_id: uuid.UUID = Path(..., description="UUID of the surviving (target) vendor."),
    body: MergeRequest = Body(...),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Merge one vendor into another: move entry links to the target, union aliases (including
    the source name), log the merge, then delete the source. Shadow mode records what would
    happen without changing data."""
    return await perform_same_type_merge(
        db,
        entity_type="vendor",
        target_id=target_id,
        source_id=body.source_id,
        mode=body.mode,
        new_description=body.new_description,
        extra_aliases=body.extra_aliases,
        reasoning=body.reasoning,
    )


@router.post("/products/{target_id}/merge", response_model=MergeResponse)
async def merge_products(
    target_id: uuid.UUID = Path(..., description="UUID of the surviving (target) product."),
    body: MergeRequest = Body(...),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Merge one product into another: move entry links to the target, union aliases (including
    the source name), log the merge, then delete the source. Shadow mode records what would
    happen without changing data."""
    return await perform_same_type_merge(
        db,
        entity_type="product",
        target_id=target_id,
        source_id=body.source_id,
        mode=body.mode,
        new_description=body.new_description,
        extra_aliases=body.extra_aliases,
        reasoning=body.reasoning,
    )


@router.post("/tools/{target_id}/merge", response_model=MergeResponse)
# Legacy path (pre-rename) — kept for one release so deployed CLI prompts don't 404.
@router.post("/offensive-tools/{target_id}/merge", response_model=MergeResponse, include_in_schema=False)
async def merge_tools(
    target_id: uuid.UUID = Path(..., description="UUID of the surviving (target) tool."),
    body: MergeRequest = Body(...),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Merge one tool into another: move entry links to the target, union aliases (including
    the source name), log the merge, then delete the source. Shadow mode records what would
    happen without changing data."""
    return await perform_same_type_merge(
        db,
        entity_type="tool",
        target_id=target_id,
        source_id=body.source_id,
        mode=body.mode,
        new_description=body.new_description,
        extra_aliases=body.extra_aliases,
        reasoning=body.reasoning,
    )


# -------------------------------------------------- cross-type reclassify


class ReclassifyRequest(BaseModel):
    source_type: str = Field(description="Current entity type (e.g. malware).")
    source_id: uuid.UUID = Field(description="Entity being moved out of source_type.")
    target_type: str = Field(description="Destination entity type (e.g. tool).")
    target_id: uuid.UUID | None = Field(
        default=None,
        description=(
            "Existing target entity to merge into. If omitted, a new entity is "
            "created in target_type using name/aliases/description from source."
        ),
    )
    mode: Literal["shadow", "apply"] = Field(default="apply")
    new_description: str | None = None
    extra_aliases: list[str] = Field(default_factory=list)
    reasoning: str | None = Field(default=None, max_length=2000)

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "source_type": "malware",
                "source_id": "3f9d2a1b-8c7e-4f6a-b5d4-0e1c2a3b4d5f",
                "target_type": "tool",
                "mode": "apply",
                "reasoning": "Mimikatz is a credential-theft tool, not a malware family.",
            }
        }
    )


class ReclassifyResponse(BaseModel):
    action: str  # 'reclassify'
    mode: str
    source_type: str
    source_id: uuid.UUID
    target_type: str
    target_id: uuid.UUID
    target_created: bool  # True if we made a new entity in target_type
    moved_entry_links: int
    merged_alias_count: int
    log_id: uuid.UUID
    applied: bool


async def _write_reclassify_tombstones(
    db: AsyncSession,
    source_type: str,
    names: list[str],
    target_type: str,
    target_id: uuid.UUID,
) -> None:
    """Record that ``names`` were folded out of ``source_type`` into the survivor.

    One upserted row per normalized name/alias. Automated creation paths consult
    these (see ``entity_dedup.find_reclassify_tombstone``) so the daily feed sync
    and per-article AI extraction don't resurrect the folded entity. A re-fold of
    the same (source_type, name) updates the target and reactivates the row.
    """
    seen: set[str] = set()
    for raw in names:
        norm = (raw or "").strip().lower()
        if not norm or norm in seen:
            continue
        seen.add(norm)
        await db.execute(
            pg_insert(EntityReclassifyTombstone)
            .values(
                normalized_name=norm,
                source_type=source_type,
                target_type=target_type,
                target_id=target_id,
                active=True,
            )
            .on_conflict_do_update(
                constraint="uq_reclassify_tombstone_src_name",
                set_={"target_type": target_type, "target_id": target_id, "active": True},
            )
        )


def _snapshot_generic(entity) -> dict:
    """Lowest-common-denominator snapshot used for any entity in the registry."""
    return {
        "id": str(entity.id),
        "name": entity.name,
        "aliases": list(entity.aliases or []),
        "description": getattr(entity, "description", None),
        "article_count": getattr(entity, "article_count", None),
    }


async def perform_reclassify(
    db: AsyncSession,
    body: ReclassifyRequest,
) -> ReclassifyResponse:
    """Move an entity from one type to another, optionally merging into an existing
    target entity. Caller owns the transaction (we flush, not commit).

    Type-specific fields (motivation, malware_type, vendor_id, tool_type, etc.)
    are NOT carried across — they don't have equivalents in other types. Only
    the common fields (name, aliases, description, article_count, first_seen_at,
    last_seen_at) survive. Operator can fix specific fields after via
    update_entity_profile.
    """
    # Accept the legacy tools slug from saved prompts / in-flight AI output;
    # everything downstream (tombstones, logs, repoints) writes the canonical one.
    body.source_type = canonical_entity_type(body.source_type)
    body.target_type = canonical_entity_type(body.target_type)
    if body.source_type == body.target_type:
        raise AppError(
            code="invalid",
            message="reclassify is for cross-type moves — use merge endpoints for same-type",
            status_code=400,
        )
    src_spec = _get_type_spec(body.source_type)
    tgt_spec = _get_type_spec(body.target_type)

    src_model = src_spec["model"]
    tgt_model = tgt_spec["model"]
    src_junction = src_spec["junction_model"]
    tgt_junction = tgt_spec["junction_model"]
    src_fk_attr = src_spec["junction_fk"]
    tgt_fk_attr = tgt_spec["junction_fk"]

    source = (await db.execute(select(src_model).where(src_model.id == body.source_id))).scalar_one_or_none()
    if not source:
        raise AppError(code="not_found", message="source entity not found", status_code=404)

    target = None
    target_created = False
    if body.target_id is not None:
        target = (await db.execute(select(tgt_model).where(tgt_model.id == body.target_id))).scalar_one_or_none()
        if not target:
            raise AppError(code="not_found", message="target entity not found", status_code=404)
    else:
        # Make a new entity in the target table by copying common fields.
        # Reject if the name already exists in target table — the caller should
        # have supplied that existing entity as target_id.
        name_conflict = (
            await db.execute(select(tgt_model.id).where(tgt_model.name == source.name))
        ).scalar_one_or_none()
        if name_conflict:
            raise AppError(
                code="invalid",
                message=(
                    f"entity name {source.name!r} already exists in {body.target_type} "
                    f"(id={name_conflict}); pass target_id to merge into it instead of creating a duplicate"
                ),
                status_code=409,
            )

    merged_aliases = _dedupe_aliases(
        list((target.aliases if target else []) or [])
        + list(source.aliases or [])
        + ([source.name] if target else [])  # only fold source.name in when merging into an existing target
        + list(body.extra_aliases),
        exclude=target.name if target else source.name,
    )

    before = {
        "source_type": body.source_type,
        "source": _snapshot_generic(source),
        "target_type": body.target_type,
        "target": _snapshot_generic(target) if target else None,
    }
    after_summary = {
        "target_type": body.target_type,
        "target_id_known": str(body.target_id) if body.target_id else None,
        "target_created": target is None,
        "merged_aliases": merged_aliases,
        "new_description": body.new_description
        if body.new_description is not None
        else (target.description if target else source.description),
        "dropped_source_id": str(body.source_id),
        "fields_dropped_on_reclassify": (
            "type-specific (motivation, malware_type, vendor_id, tool_type, etc.) — "
            "set via update_entity_profile if needed"
        ),
    }

    log_row = EntityMaintenanceLog(
        entity_type=body.target_type,  # survivor's type — search/filter will land you here
        entity_id=body.target_id,  # may be None if creating; we backfill after flush
        action="reclassify",
        mode=body.mode,
        before=before,
        after=after_summary,
        reasoning=(body.reasoning or "")[:2000] or None,
        applied=(body.mode == "apply"),
    )
    db.add(log_row)

    if body.mode != "apply":
        await db.flush()
        # In shadow mode we don't actually move anything; report the planned target id (or None for new).
        synthetic_target = body.target_id or uuid.uuid4()
        return ReclassifyResponse(
            action="reclassify",
            mode="shadow",
            source_type=body.source_type,
            source_id=body.source_id,
            target_type=body.target_type,
            target_id=synthetic_target,
            target_created=target is None,
            moved_entry_links=0,
            merged_alias_count=len(merged_aliases),
            log_id=log_row.id,
            applied=False,
        )

    # --- APPLY MODE ---
    # 1. Create or update the target entity.
    if target is None:
        target = tgt_model(
            name=source.name,
            aliases=merged_aliases,
            description=body.new_description if body.new_description is not None else source.description,
            article_count=source.article_count or 0,
            first_seen_at=source.first_seen_at,
            last_seen_at=source.last_seen_at,
        )
        db.add(target)
        await db.flush()  # populate target.id
        target_created = True
        original_aliases: list[str] = []
    else:
        original_aliases = list(target.aliases or [])
        target.aliases = merged_aliases
        if body.new_description is not None:
            target.description = body.new_description

    target_id_resolved = target.id

    # 2. Move every junction row entry by entry: pull source junctions, insert
    # equivalent target junctions, handling existing (entry, target) collisions.
    existing_pairs_q = await db.execute(
        select(getattr(tgt_junction, "entry_id")).where(getattr(tgt_junction, tgt_fk_attr) == target_id_resolved)
    )
    existing_entries = {row for row in existing_pairs_q.scalars().all()}

    src_rows = await db.execute(select(src_junction).where(getattr(src_junction, src_fk_attr) == body.source_id))
    moved = 0
    dropped = 0
    for j in src_rows.scalars().all():
        if j.entry_id in existing_entries:
            # Target already linked to this entry — drop the source row, keep the target.
            await db.delete(j)
            dropped += 1
            continue
        # Build the destination junction row with the columns it expects. All five
        # junction tables share the same shape (entry_id + entity_fk + metadata).
        new_junction_kwargs = {
            "entry_id": j.entry_id,
            tgt_fk_attr: target_id_resolved,
            "confidence": getattr(j, "confidence", None),
            "source": getattr(j, "source", None),
            "matched_names": list(getattr(j, "matched_names", None) or []) or None,
            "paragraph_indices": list(getattr(j, "paragraph_indices", None) or []) or None,
        }
        if getattr(j, "extracted_at", None) is not None:
            new_junction_kwargs["extracted_at"] = j.extracted_at
        db.add(tgt_junction(**new_junction_kwargs))
        await db.delete(j)
        moved += 1
    await db.flush()

    # 3. article_count on the target reflects the new total minus duplicates we collapsed.
    target.article_count = (target.article_count or 0) + (source.article_count or 0) - dropped

    # 3b. Tombstone the source name + aliases so automated creation paths (AI
    # extraction, external feed sync) don't recreate this folded entity.
    await _write_reclassify_tombstones(
        db,
        body.source_type,
        [source.name, *(source.aliases or [])],
        body.target_type,
        target_id_resolved,
    )

    # 4. Repoint relationships to the survivor, then delete the source entity
    # (cascade handles its remaining junctions / FKs).
    await _repoint_entity_relationships(db, body.source_type, body.source_id, body.target_type, target_id_resolved)
    await db.delete(source)
    await db.flush()
    delete_entity_document(body.source_type, body.source_id)

    # 5. Update the log row to point at the resolved target_id (was None for create-new).
    if log_row.entity_id is None:
        log_row.entity_id = target_id_resolved
        db.add(log_row)
        await db.flush()

    # A brand-new target has never been scanned; an existing one just absorbed the
    # source's names. Either way, retro-scan existing entries for the new surface.
    if target_created:
        dispatch_entity_backlink(body.target_type, target_id_resolved)
    else:
        dispatch_backlink_for_added_aliases(body.target_type, target_id_resolved, original_aliases, merged_aliases)

    return ReclassifyResponse(
        action="reclassify",
        mode="apply",
        source_type=body.source_type,
        source_id=body.source_id,
        target_type=body.target_type,
        target_id=target_id_resolved,
        target_created=target_created,
        moved_entry_links=moved,
        merged_alias_count=len(merged_aliases),
        log_id=log_row.id,
        applied=True,
    )


@router.post("/entity-maintenance/reclassify", response_model=ReclassifyResponse)
async def reclassify_entity(
    body: ReclassifyRequest,
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Move an entity to a different type (e.g. malware → tool), merging into an existing
    target entity or creating a new one. Moves entry links, writes reclassify tombstones so
    automated pipelines don't recreate the source, logs the action, then deletes the source.
    Shadow mode records the plan without changing data."""
    return await perform_reclassify(db, body)


# --------------------------------------------- maintenance log listing


class MergePairView(BaseModel):
    target_id: uuid.UUID
    source_id: uuid.UUID
    target_name: str | None = None
    source_name: str | None = None
    reasoning: str | None = None
    new_description: str | None = None
    extra_aliases: list[str] | None = None


class ReclassifyPairView(BaseModel):
    source_type: str
    source_id: uuid.UUID
    target_type: str
    target_id: uuid.UUID | None = None
    source_name: str | None = None
    target_name: str | None = None  # null when target_id is null (new entity will be created)
    reasoning: str | None = None
    new_description: str | None = None


class ClusterMember(BaseModel):
    """Per-member tag for cluster_members so the UI knows the type of each id."""

    entity_type: str
    entity_id: uuid.UUID
    name: str | None = None


class MaintenanceLogRow(BaseModel):
    id: uuid.UUID
    created_at: str
    entity_type: str
    entity_id: uuid.UUID | None
    action: str
    mode: str
    applied: bool
    reasoning: str | None
    before: dict | None
    after: dict | None
    ai_result_id: uuid.UUID | None
    # Enriched server-side for merge_cluster_summary rows so the UI can show
    # entity names without doing a second lookup per row.
    merges_view: list[MergePairView] | None = None
    reclassifies_view: list[ReclassifyPairView] | None = None
    cluster_names: list[str] | None = None  # human-readable names for before.cluster_ids (legacy single-type)
    cluster_members: list[ClusterMember] | None = None  # typed members for cross-type clusters
    subject: str | None = None  # short label for the row ("Clop ransomware (5 → 1)" etc.)

    model_config = {"from_attributes": True}


@router.delete("/entity-maintenance/log/{log_id}", status_code=204)
async def delete_maintenance_log(
    log_id: uuid.UUID = Path(..., description="UUID of the maintenance-log row to delete."),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Hard-delete a maintenance log row.

    Used to dismiss stale shadow proposals (e.g. the source entity was merged
    manually since the proposal was generated). Applied rows can also be
    deleted — the underlying merge has already happened and isn't reversed.
    """
    row = (await db.execute(select(EntityMaintenanceLog).where(EntityMaintenanceLog.id == log_id))).scalar_one_or_none()
    if not row:
        raise AppError(code="not_found", message="log row not found", status_code=404)
    await db.delete(row)
    await db.flush()


@router.get("/entity-maintenance/log", response_model=list[MaintenanceLogRow])
async def list_maintenance_log(
    entity_type: str | None = Query(None, description="Filter by entity_type (threat_actor / malware)."),
    action: str | None = Query(None, description="Filter by action (e.g. merge, reclassify, merge_cluster_summary)."),
    mode: str | None = Query(None, description="'shadow' | 'apply' to filter by execution mode."),
    applied: bool | None = Query(
        None, description="Filter by applied state: true = executed rows, false = shadow proposals."
    ),
    hide_applied_summaries: bool = Query(
        True,
        description=(
            "When true (default), hide merge_cluster_summary rows that have already been applied — "
            "the per-pair merge rows created by the apply are the canonical record. "
            "Set false to see the full audit trail including original cluster proposals."
        ),
    ),
    limit: int = Query(100, ge=1, le=500, description="Maximum log rows per page."),
    offset: int = Query(0, ge=0, description="Number of log rows to skip for pagination."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Entity-maintenance audit log (merges, reclassifies, cluster proposals), newest first,
    with entity names resolved and per-row merge / reclassify detail views attached."""
    from sqlalchemy import and_, not_

    q = select(EntityMaintenanceLog).order_by(EntityMaintenanceLog.created_at.desc())
    if entity_type:
        q = q.where(EntityMaintenanceLog.entity_type == entity_type)
    if action:
        q = q.where(EntityMaintenanceLog.action == action)
    if mode:
        q = q.where(EntityMaintenanceLog.mode == mode)
    if applied is not None:
        q = q.where(EntityMaintenanceLog.applied == applied)
    # Default-hide applied cluster summaries — the per-pair merge rows already
    # cover them with proper names. Skip this filter when the caller is
    # explicitly asking to see applied rows or for cluster_summary specifically.
    if hide_applied_summaries and applied is None and action != "merge_cluster_summary":
        q = q.where(
            not_(
                and_(
                    EntityMaintenanceLog.action == "merge_cluster_summary",
                    EntityMaintenanceLog.applied.is_(True),
                )
            )
        )
    q = q.limit(limit).offset(offset)
    rows = (await db.execute(q)).scalars().all()

    # ----- Gather every (entity_type, uuid) referenced by these rows so we
    # can do one bulk lookup per type and avoid N round-trips. The new
    # cluster_members representation in `before` is typed; older rows used
    # `cluster_ids` (untyped — inferred from row.entity_type).
    pending: dict[str, set[uuid.UUID]] = {t: set() for t in ENTITY_TYPE_REGISTRY}

    def _add(etype: str | None, raw_id) -> None:
        if not etype or etype not in pending or not raw_id:
            return
        try:
            pending[etype].add(uuid.UUID(str(raw_id)))
        except (ValueError, TypeError):
            pass

    for r in rows:
        # entity_id (survivor) is the row's entity_type
        _add(r.entity_type, r.entity_id)
        before = r.before or {}
        after = r.after or {}
        # New: typed cluster_members [{entity_type, entity_id}]
        members = before.get("cluster_members")
        if isinstance(members, list):
            for m in members:
                if isinstance(m, dict):
                    _add(m.get("entity_type"), m.get("entity_id"))
        # Legacy: untyped cluster_ids — assume row.entity_type for all
        legacy_ids = before.get("cluster_ids")
        if isinstance(legacy_ids, list):
            for cid in legacy_ids:
                _add(r.entity_type, cid)
        # merges (same-type, scoped to row.entity_type)
        merges = after.get("merges")
        if isinstance(merges, list):
            for m in merges:
                if isinstance(m, dict):
                    _add(r.entity_type, m.get("target_id"))
                    _add(r.entity_type, m.get("source_id"))
        # reclassifies (per-entry source_type + target_type)
        reclassifies = after.get("reclassifies")
        if isinstance(reclassifies, list):
            for r2 in reclassifies:
                if isinstance(r2, dict):
                    _add(r2.get("source_type"), r2.get("source_id"))
                    _add(r2.get("target_type"), r2.get("target_id"))
        # merge_cluster_summary "before.target" / "after.target_id" / single merge
        _add(r.entity_type, after.get("target_id"))
        _add(r.entity_type, after.get("dropped_source_id"))

    # ----- One SELECT per entity type for present ids. Keyed by (etype, id) so
    # cross-type id collisions (extremely unlikely with v4 UUIDs but
    # conceptually possible) don't shadow each other.
    name_lookup: dict[tuple[str, uuid.UUID], str] = {}
    for etype, ids in pending.items():
        if not ids:
            continue
        model = ENTITY_TYPE_REGISTRY[etype]["model"]
        rows_q = await db.execute(select(model.id, model.name).where(model.id.in_(ids)))
        for eid, ename in rows_q.all():
            name_lookup[(etype, eid)] = ename

    # Backfill names for entities that have already been merged/deleted:
    # historical per-pair merge log rows snapshot the source's name in their
    # `before.source.name`, so we can recover the dropped name from there.
    # Same trick for reclassify rows: `before.source.name`.
    missing_ids: set[str] = set()
    for r in rows:
        for etype, ids in pending.items():
            for eid in ids:
                if (etype, eid) not in name_lookup:
                    missing_ids.add(str(eid))
    if missing_ids:
        # Pull every per-pair merge / reclassify log whose dropped/source id matches.
        hist_q = await db.execute(
            select(EntityMaintenanceLog).where(EntityMaintenanceLog.action.in_(["merge", "reclassify"]))
        )
        for hist in hist_q.scalars().all():
            before = hist.before or {}
            after = hist.after or {}
            src_block = before.get("source") if isinstance(before.get("source"), dict) else None
            tgt_block = before.get("target") if isinstance(before.get("target"), dict) else None

            # action='merge' — both source and target are row.entity_type.
            if hist.action == "merge":
                dropped = after.get("dropped_source_id")
                if dropped and str(dropped) in missing_ids and isinstance(src_block, dict) and src_block.get("name"):
                    try:
                        eid = uuid.UUID(str(dropped))
                        name_lookup.setdefault((hist.entity_type, eid), src_block["name"])
                    except (ValueError, TypeError):
                        pass
                tgt_id_in_after = after.get("target_id")
                if (
                    tgt_id_in_after
                    and str(tgt_id_in_after) in missing_ids
                    and isinstance(tgt_block, dict)
                    and tgt_block.get("name")
                ):
                    try:
                        eid = uuid.UUID(str(tgt_id_in_after))
                        name_lookup.setdefault((hist.entity_type, eid), tgt_block["name"])
                    except (ValueError, TypeError):
                        pass
            # action='reclassify' — types live in `before.source_type` / `before.target_type`.
            elif hist.action == "reclassify":
                st = before.get("source_type")
                tt = before.get("target_type")
                if st and isinstance(src_block, dict) and src_block.get("id") and src_block.get("name"):
                    try:
                        sid = uuid.UUID(str(src_block["id"]))
                        if str(sid) in missing_ids:
                            name_lookup.setdefault((st, sid), src_block["name"])
                    except (ValueError, TypeError):
                        pass
                if tt and isinstance(tgt_block, dict) and tgt_block.get("id") and tgt_block.get("name"):
                    try:
                        tid = uuid.UUID(str(tgt_block["id"]))
                        if str(tid) in missing_ids:
                            name_lookup.setdefault((tt, tid), tgt_block["name"])
                    except (ValueError, TypeError):
                        pass

    def _name(etype: str | None, raw_id) -> str | None:
        if not etype or not raw_id:
            return None
        try:
            eid = raw_id if isinstance(raw_id, uuid.UUID) else uuid.UUID(str(raw_id))
        except (ValueError, TypeError):
            return None
        return name_lookup.get((etype, eid))

    def _build_subject(row: EntityMaintenanceLog) -> str | None:
        after = row.after or {}
        before = row.before or {}
        if row.action == "merge_cluster_summary":
            target_names: list[str] = []
            merges = after.get("merges")
            if isinstance(merges, list):
                seen: set[str] = set()
                for m in merges:
                    if not isinstance(m, dict):
                        continue
                    n = _name(row.entity_type, m.get("target_id"))
                    if n and n not in seen:
                        seen.add(n)
                        target_names.append(n)
            reclassifies = after.get("reclassifies")
            reclass_count = len(reclassifies) if isinstance(reclassifies, list) else 0
            # Count cluster size — prefer typed members
            members = before.get("cluster_members")
            if isinstance(members, list) and members:
                cluster_size = len(members)
            else:
                legacy_ids = before.get("cluster_ids")
                cluster_size = len(legacy_ids) if isinstance(legacy_ids, list) else 0
            parts: list[str] = []
            if target_names:
                canonical = ", ".join(target_names[:2])
                if len(target_names) > 2:
                    canonical += f" + {len(target_names) - 2} more"
                parts.append(canonical)
                if cluster_size:
                    parts[-1] = f"{canonical} ({cluster_size} → {len(target_names)})"
            elif cluster_size:
                parts.append(f"cluster of {cluster_size}")
            if reclass_count:
                parts.append(f"+{reclass_count} reclassif{'y' if reclass_count == 1 else 'ies'}")
            return " ".join(parts) or None
        if row.action == "merge":
            target = _name(row.entity_type, after.get("target_id"))
            dropped = _name(row.entity_type, after.get("dropped_source_id"))
            if target and dropped:
                return f"{dropped} → {target}"
            return target or dropped
        if row.action == "reclassify":
            src_block = before.get("source") if isinstance(before.get("source"), dict) else {}
            tgt_block = before.get("target") if isinstance(before.get("target"), dict) else {}
            src_type = before.get("source_type") or ""
            tgt_type = before.get("target_type") or ""
            src_name = src_block.get("name") if isinstance(src_block, dict) else None
            tgt_name = (tgt_block.get("name") if isinstance(tgt_block, dict) else None) or _name(
                tgt_type, row.entity_id
            )
            if src_name and tgt_name:
                return f"{src_name} ({src_type}) → {tgt_name} ({tgt_type})"
            if src_name:
                return f"{src_name} ({src_type}) → {tgt_type}"
            return None
        if row.action in {"update_description", "update_aliases"} and row.entity_id:
            return _name(row.entity_type, row.entity_id)
        if row.action == "no_op":
            members = before.get("cluster_members")
            if isinstance(members, list) and members:
                names = [_name(m.get("entity_type"), m.get("entity_id")) for m in members if isinstance(m, dict)]
                names = [n for n in names if n]
                if names:
                    return ", ".join(names[:3]) + (" …" if len(names) > 3 else "")
            legacy_ids = before.get("cluster_ids")
            if isinstance(legacy_ids, list) and legacy_ids:
                names = [_name(row.entity_type, c) for c in legacy_ids]
                names = [n for n in names if n]
                if names:
                    return ", ".join(names[:3]) + (" …" if len(names) > 3 else "")
        return None

    def _build_merges_view(row: EntityMaintenanceLog) -> list[MergePairView] | None:
        merges = (row.after or {}).get("merges") if row.after else None
        if not isinstance(merges, list):
            return None
        out: list[MergePairView] = []
        for m in merges:
            if not isinstance(m, dict):
                continue
            try:
                tid = uuid.UUID(str(m.get("target_id")))
                sid = uuid.UUID(str(m.get("source_id")))
            except (ValueError, TypeError):
                continue
            extra = m.get("extra_aliases")
            # Prefer the name snapshotted at proposal time — the source entity
            # gets deleted on merge, so a live DB lookup returns nothing for
            # applied rows. Fall back to live lookup for legacy rows that
            # predate the snapshot field.
            out.append(
                MergePairView(
                    target_id=tid,
                    source_id=sid,
                    target_name=m.get("target_name") or _name(row.entity_type, tid),
                    source_name=m.get("source_name") or _name(row.entity_type, sid),
                    reasoning=m.get("reasoning"),
                    new_description=m.get("new_description"),
                    extra_aliases=list(extra) if isinstance(extra, list) else None,
                )
            )
        return out or None

    def _build_reclassifies_view(row: EntityMaintenanceLog) -> list[ReclassifyPairView] | None:
        reclassifies = (row.after or {}).get("reclassifies") if row.after else None
        if not isinstance(reclassifies, list):
            return None
        out: list[ReclassifyPairView] = []
        for r2 in reclassifies:
            if not isinstance(r2, dict):
                continue
            st = r2.get("source_type")
            tt = r2.get("target_type")
            try:
                sid = uuid.UUID(str(r2.get("source_id")))
            except (ValueError, TypeError):
                continue
            try:
                tid = uuid.UUID(str(r2.get("target_id"))) if r2.get("target_id") else None
            except (ValueError, TypeError):
                tid = None
            if not st or not tt:
                continue
            out.append(
                ReclassifyPairView(
                    source_type=st,
                    source_id=sid,
                    target_type=tt,
                    target_id=tid,
                    source_name=r2.get("source_name") or _name(st, sid),
                    target_name=r2.get("target_name") or (_name(tt, tid) if tid else None),
                    reasoning=r2.get("reasoning"),
                    new_description=r2.get("new_description"),
                )
            )
        return out or None

    def _build_cluster_views(row: EntityMaintenanceLog) -> tuple[list[str] | None, list[ClusterMember] | None]:
        """Return (legacy_cluster_names, typed_cluster_members) — first non-None is shown."""
        before = row.before or {}
        members = before.get("cluster_members")
        if isinstance(members, list) and members:
            typed: list[ClusterMember] = []
            for m in members:
                if not isinstance(m, dict):
                    continue
                etype = m.get("entity_type")
                raw_id = m.get("entity_id")
                if not etype or not raw_id:
                    continue
                try:
                    eid = uuid.UUID(str(raw_id))
                except (ValueError, TypeError):
                    continue
                # Prefer snapshot, fall back to live DB lookup.
                typed.append(
                    ClusterMember(
                        entity_type=etype,
                        entity_id=eid,
                        name=m.get("name") or _name(etype, eid),
                    )
                )
            return None, typed or None
        legacy_ids = before.get("cluster_ids")
        if isinstance(legacy_ids, list) and legacy_ids:
            names = [_name(row.entity_type, c) for c in legacy_ids]
            names = [n for n in names if n]
            return names or None, None
        return None, None

    out_rows: list[MaintenanceLogRow] = []
    for r in rows:
        cluster_names, cluster_members = _build_cluster_views(r)
        out_rows.append(
            MaintenanceLogRow(
                id=r.id,
                created_at=r.created_at.isoformat(),
                entity_type=r.entity_type,
                entity_id=r.entity_id,
                action=r.action,
                mode=r.mode,
                applied=r.applied,
                reasoning=r.reasoning,
                before=r.before,
                after=r.after,
                ai_result_id=r.ai_result_id,
                merges_view=_build_merges_view(r),
                reclassifies_view=_build_reclassifies_view(r),
                cluster_names=cluster_names,
                cluster_members=cluster_members,
                subject=_build_subject(r),
            )
        )
    return out_rows
