"""Unified workbench hygiene API.

Powers the "Entity Hygiene" surface in Settings → Workbench. Aggregates the
existing entity-maintenance / link-validation systems and adds:

  - GET  /api/admin/hygiene/feed            — chronological merge of
         entity_link_validation_log + entity_maintenance_log, normalized
  - GET  /api/admin/hygiene/stats           — combined counters across both
  - GET  /api/admin/hygiene/orphans         — entities with article_count == 0
  - POST /api/admin/hygiene/orphans/prune   — prune (one or all) orphans
  - GET  /api/admin/hygiene/enrichment-gaps — per-type missing-field counts
  - POST /api/admin/hygiene/apply-reclassify-advisories
                                            — promote needs_reclassification
                                              rows into real reclassify ops
  - GET  /api/entities/{type}/{id}/cascade-preview
                                            — blast radius before delete

All write endpoints require admin. The cascade-preview endpoint is read-only
and uses get_current_user.
"""

from __future__ import annotations

import re
import uuid
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from fastapi import APIRouter, Body, Depends, Path, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import and_, delete, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.entity_merge import (
    ENTITY_TYPE_REGISTRY,
    ReclassifyRequest,
    perform_reclassify,
    perform_same_type_merge,
)
from app.core.exceptions import AppError
from app.core.security import get_admin_user, get_current_user
from app.database import get_db
from app.models.ai_result import AIResult
from app.models.ai_task import AITask
from app.models.campaign import CampaignEntity
from app.models.country import Country, EntryCountry
from app.models.cve import CVE, EntryCVE
from app.models.detection_rule import DetectionRule
from app.models.entity_link_validation_log import EntityLinkValidationLog
from app.models.entity_maintenance import EntityMaintenanceLog
from app.models.entity_note import EntityNote
from app.models.entity_relationship import EntityRelationship
from app.models.entry import Entry
from app.models.entry_sector import EntrySector
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.observable import EntryObservable, Observable
from app.models.product import EntryProduct, Product
from app.models.sector import Sector
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.tool import EntryTool, Tool
from app.models.ttp import TTP, EntryTTP
from app.models.user import User
from app.models.vendor import EntryVendor, Vendor
from app.services.entry_adjudication import (
    ACTION_ASSESSMENT,
    ACTION_EDGE_DEMOTE,
    ACTION_IOC_DROP,
    ACTION_MERGE,
    ACTION_RECLASSIFY,
    ACTION_UNLINK,
    ACTION_VETO,
    ADJUDICATION_ACTIONS,
    LEGACY_MAINT_ACTIONS,
    legacy_row_is_orphaned,
)
from app.services.entry_adjudication import TASK_NAME as ADJUDICATION_TASK_NAME

router = APIRouter()


# ---------------------------------------------------------------------------
# Cascade preview
# ---------------------------------------------------------------------------

# Per-entity-type model + junction(s) + relationship type-name used in
# entity_relationships.source_type / target_type. Keep ordered by readability
# of the preview output.
CASCADE_SPECS: dict[str, dict[str, Any]] = {
    "threat_actor": {
        "model": ThreatActor,
        "junction": EntryThreatActor,
        "junction_fk": "threat_actor_id",
        "rel_type": "threat_actor",
    },
    "malware": {
        "model": MalwareFamily,
        "junction": EntryMalware,
        "junction_fk": "malware_family_id",
        "rel_type": "malware",
    },
    "vendor": {
        "model": Vendor,
        "junction": EntryVendor,
        "junction_fk": "vendor_id",
        "rel_type": "vendor",
    },
    "product": {
        "model": Product,
        "junction": EntryProduct,
        "junction_fk": "product_id",
        "rel_type": "product",
    },
    "tool": {
        "model": Tool,
        "junction": EntryTool,
        "junction_fk": "tool_id",
        "rel_type": "tool",
    },
    "cve": {
        "model": CVE,
        "junction": EntryCVE,
        "junction_fk": "cve_id",
        "rel_type": "cve",
    },
    "ttp": {
        "model": TTP,
        "junction": EntryTTP,
        "junction_fk": "ttp_id",
        "rel_type": "ttp",
    },
    "country": {
        "model": Country,
        "junction": EntryCountry,
        "junction_fk": "country_id",
        "rel_type": "country",
    },
    "sector": {
        "model": Sector,
        "junction": EntrySector,
        "junction_fk": "sector_id",
        "rel_type": "sector",
    },
    # The ledger row's identity is its value, not a name — the preview reads
    # `name_attr` so the header says which observable is about to go.
    "observable": {
        "model": Observable,
        "junction": EntryObservable,
        "junction_fk": "observable_id",
        "rel_type": "observable",
        "name_attr": "value",
    },
}


class CascadePreview(BaseModel):
    entity_type: str
    entity_id: uuid.UUID
    entity_name: str
    entry_links: int  # junction rows
    campaign_links: int
    detection_rules: int  # rules whose source_actors/source_ttps/source_cves reference this
    relationships: int
    notes: int


@router.get("/entities/{entity_type}/{entity_id}/cascade-preview", response_model=CascadePreview)
async def cascade_preview(
    entity_type: str = Path(..., description="Entity type slug (retired spellings are canonicalized)"),
    entity_id: uuid.UUID = Path(..., description="Entity UUID"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> CascadePreview:
    """Blast radius before deleting an entity: counts of entry links, campaign links,
    detection rules, relationships and notes that reference it.
    """
    from app.api.entity_merge import canonical_entity_type

    entity_type = canonical_entity_type(entity_type)
    spec = CASCADE_SPECS.get(entity_type)
    if not spec:
        raise AppError(code="invalid", message=f"unsupported entity_type: {entity_type}", status_code=400)

    model = spec["model"]
    junction = spec["junction"]
    fk_attr = spec["junction_fk"]
    rel_type = spec["rel_type"]

    entity = (await db.execute(select(model).where(model.id == entity_id))).scalar_one_or_none()
    if not entity:
        raise AppError(code="not_found", message=f"{entity_type} not found", status_code=404)

    entry_links = (
        await db.execute(select(func.count()).select_from(junction).where(getattr(junction, fk_attr) == entity_id))
    ).scalar_one()

    campaign_links = (
        await db.execute(
            select(func.count())
            .select_from(CampaignEntity)
            .where(
                CampaignEntity.entity_type == rel_type,
                CampaignEntity.entity_id == entity_id,
            )
        )
    ).scalar_one()

    # detection_rules: rules referencing this entity via the relevant ARRAY column.
    detection_rules = 0
    if entity_type == "threat_actor":
        detection_rules = (
            await db.execute(
                select(func.count()).select_from(DetectionRule).where(DetectionRule.source_actors.any(entity_id))
            )
        ).scalar_one()
    # source_ttps / source_cves are JSONB lists of IDs; skip without a JSON containment
    # query — TTP / CVE deletes are rare and cascade-preview is best-effort for those.

    relationships = (
        await db.execute(
            select(func.count())
            .select_from(EntityRelationship)
            .where(
                or_(
                    and_(
                        EntityRelationship.source_type == rel_type,
                        EntityRelationship.source_id == entity_id,
                    ),
                    and_(
                        EntityRelationship.target_type == rel_type,
                        EntityRelationship.target_id == entity_id,
                    ),
                )
            )
        )
    ).scalar_one()

    note_type = entity_type
    notes = (
        await db.execute(
            select(func.count())
            .select_from(EntityNote)
            .where(
                EntityNote.entity_type == note_type,
                EntityNote.entity_id == entity_id,
            )
        )
    ).scalar_one()

    return CascadePreview(
        entity_type=entity_type,
        entity_id=entity_id,
        entity_name=getattr(entity, spec.get("name_attr", "name"), "") or "",
        entry_links=int(entry_links),
        campaign_links=int(campaign_links),
        detection_rules=int(detection_rules),
        relationships=int(relationships),
        notes=int(notes),
    )


# ---------------------------------------------------------------------------
# Orphan entities
# ---------------------------------------------------------------------------

ORPHAN_SCANNABLE_TYPES = ["threat_actor", "malware", "vendor", "product", "tool"]


class OrphanRow(BaseModel):
    entity_type: str
    entity_id: uuid.UUID
    name: str
    article_count: int
    first_seen_at: datetime | None
    last_seen_at: datetime | None


class OrphanListResponse(BaseModel):
    total: int
    items: list[OrphanRow]
    by_type: dict[str, int]


@router.get("/admin/hygiene/orphans", response_model=OrphanListResponse)
async def list_orphans(
    entity_type: str | None = Query(None, description="Restrict the scan to one entity type; default scans all"),
    limit: int = Query(200, ge=1, le=2000, description="Max orphan rows to return"),
    offset: int = Query(0, ge=0, description="Rows to skip for pagination"),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> OrphanListResponse:
    """Entities whose article_count is 0 AND have no junction rows.

    The double check guards against stale article_count values (which can lag
    after bulk operations). An entity only shows up here if it is truly
    unreferenced.
    """
    types_to_scan = [entity_type] if entity_type else ORPHAN_SCANNABLE_TYPES
    by_type: dict[str, int] = {}
    rows: list[OrphanRow] = []

    for etype in types_to_scan:
        spec = ENTITY_TYPE_REGISTRY.get(etype)
        if not spec:
            continue
        model = spec["model"]
        junction = spec["junction_model"]
        fk_attr = spec["junction_fk"]

        # Count from junction subquery to verify orphan status (article_count can be stale).
        link_count_subq = (
            select(func.count()).select_from(junction).where(getattr(junction, fk_attr) == model.id).scalar_subquery()
        )
        q = (
            select(
                model.id,
                model.name,
                getattr(model, "article_count"),
                getattr(model, "first_seen_at", None),
                getattr(model, "last_seen_at", None),
            )
            .where(link_count_subq == 0)
            .order_by(model.name)
        )
        type_rows = (await db.execute(q)).all()
        by_type[etype] = len(type_rows)
        for r in type_rows:
            rows.append(
                OrphanRow(
                    entity_type=etype,
                    entity_id=r[0],
                    name=r[1] or "(unnamed)",
                    article_count=int(r[2] or 0),
                    first_seen_at=r[3],
                    last_seen_at=r[4],
                )
            )

    total = len(rows)
    rows.sort(key=lambda x: (x.entity_type, (x.name or "").lower()))
    sliced = rows[offset : offset + limit]
    return OrphanListResponse(total=total, items=sliced, by_type=by_type)


class PruneOrphansRequest(BaseModel):
    targets: list[dict] | None = Field(
        default=None,
        description=(
            "Specific orphans to prune as [{entity_type, entity_id}]. "
            "If null, prune ALL orphans of `entity_type` (or all scannable types)."
        ),
    )
    entity_type: str | None = Field(
        default=None,
        description="When `targets` is null, restrict the all-orphan prune to this type.",
    )
    mode: Literal["shadow", "apply"] = Field(default="apply")
    max_prune: int = Field(
        default=500,
        ge=1,
        le=5000,
        description="Cap on how many orphans to delete in one batch (safety net).",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "targets": [{"entity_type": "malware", "entity_id": "d5b2f1e8-3c4a-4b6d-9e2f-7a8b9c0d1e2f"}],
                "mode": "apply",
                "max_prune": 500,
            }
        }
    )


class PruneOrphansResponse(BaseModel):
    mode: str
    pruned: int
    skipped: int  # entities that weren't actually orphans at delete-time
    by_type: dict[str, int]
    log_ids: list[uuid.UUID]


@router.post("/admin/hygiene/orphans/prune", response_model=PruneOrphansResponse)
async def prune_orphans(
    body: PruneOrphansRequest = Body(default_factory=PruneOrphansRequest),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> PruneOrphansResponse:
    """Delete orphan entities (article_count == 0 AND no junction rows).

    Each prune writes an EntityMaintenanceLog row with action='orphan_prune'
    so the unified feed reflects what happened. Shadow mode logs would-prune
    rows without deleting.
    """
    # Build the list of (entity_type, entity_id) to consider.
    candidates: list[tuple[str, uuid.UUID]] = []
    if body.targets:
        for t in body.targets:
            etype = t.get("entity_type")
            raw_id = t.get("entity_id")
            if not etype or not raw_id:
                continue
            try:
                candidates.append((etype, uuid.UUID(str(raw_id))))
            except (ValueError, TypeError):
                continue
    else:
        types_to_scan = [body.entity_type] if body.entity_type else ORPHAN_SCANNABLE_TYPES
        for etype in types_to_scan:
            spec = ENTITY_TYPE_REGISTRY.get(etype)
            if not spec:
                continue
            model = spec["model"]
            junction = spec["junction_model"]
            fk_attr = spec["junction_fk"]
            link_count_subq = (
                select(func.count())
                .select_from(junction)
                .where(getattr(junction, fk_attr) == model.id)
                .scalar_subquery()
            )
            ids = (await db.execute(select(model.id).where(link_count_subq == 0))).scalars().all()
            candidates.extend((etype, eid) for eid in ids)

    candidates = candidates[: body.max_prune]

    pruned = 0
    skipped = 0
    by_type: dict[str, int] = defaultdict(int)
    log_ids: list[uuid.UUID] = []

    for etype, eid in candidates:
        spec = ENTITY_TYPE_REGISTRY.get(etype)
        if not spec:
            skipped += 1
            continue
        model = spec["model"]
        junction = spec["junction_model"]
        fk_attr = spec["junction_fk"]

        entity = (await db.execute(select(model).where(model.id == eid))).scalar_one_or_none()
        if not entity:
            skipped += 1
            continue

        # Re-verify orphan status at delete-time.
        link_count = (
            await db.execute(select(func.count()).select_from(junction).where(getattr(junction, fk_attr) == eid))
        ).scalar_one()
        if link_count > 0:
            skipped += 1
            continue

        snapshot = {
            "id": str(entity.id),
            "name": getattr(entity, "name", None),
            "aliases": list(getattr(entity, "aliases", None) or []),
            "article_count": getattr(entity, "article_count", 0),
            "first_seen_at": (
                getattr(entity, "first_seen_at", None).isoformat() if getattr(entity, "first_seen_at", None) else None
            ),
            "last_seen_at": (
                getattr(entity, "last_seen_at", None).isoformat() if getattr(entity, "last_seen_at", None) else None
            ),
        }

        log_row = EntityMaintenanceLog(
            entity_type=etype,
            entity_id=eid,
            action="orphan_prune",
            mode=body.mode,
            before={"entity": snapshot},
            after={"deleted": body.mode == "apply"},
            reasoning="Orphan sweep: article_count == 0 and no junction rows present.",
            applied=(body.mode == "apply"),
        )
        db.add(log_row)
        await db.flush()
        log_ids.append(log_row.id)

        if body.mode == "apply":
            await db.delete(entity)
            await db.flush()
            pruned += 1
            by_type[etype] += 1

    return PruneOrphansResponse(
        mode=body.mode,
        pruned=pruned,
        skipped=skipped,
        by_type=dict(by_type),
        log_ids=log_ids,
    )


# ---------------------------------------------------------------------------
# Bulk-apply reclassify advisories
# ---------------------------------------------------------------------------


class ApplyAdvisoriesRequest(BaseModel):
    limit: int = Field(default=100, ge=1, le=2000)
    entity_type: str | None = Field(
        default=None,
        description="Restrict to advisories whose source is this entity_type.",
    )
    mode: Literal["shadow", "apply"] = Field(default="apply")

    model_config = ConfigDict(
        json_schema_extra={"example": {"limit": 100, "entity_type": "threat_actor", "mode": "apply"}}
    )


class ApplyAdvisoriesResponse(BaseModel):
    mode: str
    advisories_considered: int
    distinct_sources: int
    applied: int
    skipped: int  # source entity already gone or invalid suggested_type
    failed: int
    cleared_advisory_rows: int
    errors: list[dict]


@router.post("/admin/hygiene/apply-reclassify-advisories", response_model=ApplyAdvisoriesResponse)
async def apply_reclassify_advisories(
    body: ApplyAdvisoriesRequest = Body(default_factory=ApplyAdvisoriesRequest),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> ApplyAdvisoriesResponse:
    """Promote needs_reclassification advisories into real reclassify ops.

    Multiple advisories for the same (entity_type, entity_id, suggested_type)
    tuple are deduped into a single reclassify operation. The reclassify
    endpoint handles target-entity discovery by name (or creates a new one).
    """
    q = (
        select(EntityLinkValidationLog)
        .where(
            EntityLinkValidationLog.action == "needs_reclassification",
            EntityLinkValidationLog.suggested_entity_type.is_not(None),
        )
        .order_by(EntityLinkValidationLog.created_at.desc())
        .limit(body.limit)
    )
    if body.entity_type:
        q = q.where(EntityLinkValidationLog.entity_type == body.entity_type)
    advisories = (await db.execute(q)).scalars().all()
    return await _apply_advisory_rows(db, list(advisories), body.mode)


async def _apply_advisory_rows(
    db: AsyncSession,
    advisories: list[EntityLinkValidationLog],
    mode: str,
) -> ApplyAdvisoriesResponse:
    """Core of advisory promotion: dedupe the advisories and run one reclassify per tuple."""
    # Dedupe by (source_type, source_id, suggested_type) — keep the latest reasoning.
    grouped: dict[tuple[str, uuid.UUID, str], list[EntityLinkValidationLog]] = defaultdict(list)
    for a in advisories:
        if a.entity_type == a.suggested_entity_type:
            continue
        if a.entity_type not in ENTITY_TYPE_REGISTRY or a.suggested_entity_type not in ENTITY_TYPE_REGISTRY:
            continue
        grouped[(a.entity_type, a.entity_id, a.suggested_entity_type)].append(a)

    applied = 0
    skipped = 0
    failed = 0
    cleared = 0
    errors: list[dict] = []

    for (src_type, src_id, tgt_type), rows in grouped.items():
        # Confirm source still exists.
        src_spec = ENTITY_TYPE_REGISTRY[src_type]
        src_model = src_spec["model"]
        src_entity = (await db.execute(select(src_model).where(src_model.id == src_id))).scalar_one_or_none()
        if not src_entity:
            # Already gone — clear the now-stale advisories.
            for r in rows:
                await db.delete(r)
                cleared += 1
            skipped += 1
            continue

        # Find an existing target with the same name in tgt_type.
        tgt_model = ENTITY_TYPE_REGISTRY[tgt_type]["model"]
        existing_target_id = (
            await db.execute(select(tgt_model.id).where(func.lower(tgt_model.name) == func.lower(src_entity.name)))
        ).scalar_one_or_none()

        latest_reason = rows[0].reason or ""

        req = ReclassifyRequest(
            source_type=src_type,
            source_id=src_id,
            target_type=tgt_type,
            target_id=existing_target_id,
            mode=mode,
            reasoning=(
                f"Bulk apply of {len(rows)} link-validator advisor{'y' if len(rows) == 1 else 'ies'}: " + latest_reason
            )[:2000],
        )
        try:
            await perform_reclassify(db, req)
            if mode == "apply":
                for r in rows:
                    await db.delete(r)
                    cleared += 1
                applied += 1
            else:
                # shadow — leave advisories in place
                applied += 1
        except AppError as e:
            failed += 1
            errors.append(
                {
                    "source_type": src_type,
                    "source_id": str(src_id),
                    "target_type": tgt_type,
                    "error": e.message,
                }
            )
        except Exception as e:  # pragma: no cover  (defense-in-depth)
            failed += 1
            errors.append(
                {
                    "source_type": src_type,
                    "source_id": str(src_id),
                    "target_type": tgt_type,
                    "error": str(e)[:300],
                }
            )

    await db.flush()
    return ApplyAdvisoriesResponse(
        mode=mode,
        advisories_considered=len(advisories),
        distinct_sources=len(grouped),
        applied=applied,
        skipped=skipped,
        failed=failed,
        cleared_advisory_rows=cleared,
        errors=errors[:50],
    )


# ---------------------------------------------------------------------------
# Enrichment gaps — which profile fields are empty, per entity type
# ---------------------------------------------------------------------------


class GapBucket(BaseModel):
    entity_type: str
    field: str
    missing: int
    sample: list[dict]  # [{id, name, article_count}]


class EnrichmentGapsResponse(BaseModel):
    buckets: list[GapBucket]


@router.get("/admin/hygiene/enrichment-gaps", response_model=EnrichmentGapsResponse)
async def enrichment_gaps(
    sample_size: int = Query(
        5, ge=0, le=50, description="Sample entities per gap bucket (top by article_count); 0 to skip samples"
    ),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> EnrichmentGapsResponse:
    """Per-(entity_type, field) counts of unfilled enrichment.

    Cheap aggregate queries; the `sample` lists pull the top-N by
    article_count so the UI can show "what's most impactful to fix first."
    """
    buckets: list[GapBucket] = []

    async def _bucket(etype: str, field_label: str, model, condition, *, order_col=None):
        count = (await db.execute(select(func.count()).select_from(model).where(condition))).scalar_one()
        sample: list[dict] = []
        if sample_size > 0 and int(count) > 0:
            order_expr = order_col if order_col is not None else getattr(model, "article_count", model.id).desc()
            # CVE has no `name` column — fall back to cve_id for display.
            name_col = getattr(model, "name", None) or getattr(model, "cve_id", None) or model.id
            count_col = getattr(model, "article_count", None)
            sample_rows = (
                await db.execute(
                    select(model.id, name_col, count_col).where(condition).order_by(order_expr).limit(sample_size)
                    if count_col is not None
                    else select(model.id, name_col).where(condition).order_by(order_expr).limit(sample_size)
                )
            ).all()
            sample = [
                {
                    "id": str(r[0]),
                    "name": r[1],
                    "article_count": int(r[2] or 0) if (len(r) > 2 and r[2] is not None) else None,
                }
                for r in sample_rows
            ]
        buckets.append(GapBucket(entity_type=etype, field=field_label, missing=int(count), sample=sample))

    ta_order = ThreatActor.article_count.desc()
    await _bucket("threat_actor", "mitre_id", ThreatActor, ThreatActor.mitre_id.is_(None), order_col=ta_order)
    await _bucket(
        "threat_actor",
        "country",
        ThreatActor,
        ThreatActor.origin_country_id.is_(None),
        order_col=ta_order,
    )
    await _bucket(
        "threat_actor",
        "motivation",
        ThreatActor,
        ThreatActor.motivation.is_(None),
        order_col=ta_order,
    )
    await _bucket(
        "threat_actor",
        "description",
        ThreatActor,
        or_(ThreatActor.description.is_(None), func.length(ThreatActor.description) < 80),
        order_col=ThreatActor.article_count.desc(),
    )
    await _bucket(
        "malware",
        "malware_type",
        MalwareFamily,
        MalwareFamily.malware_type.is_(None),
        order_col=MalwareFamily.article_count.desc(),
    )
    await _bucket(
        "malware",
        "description",
        MalwareFamily,
        or_(MalwareFamily.description.is_(None), func.length(MalwareFamily.description) < 80),
        order_col=MalwareFamily.article_count.desc(),
    )
    await _bucket(
        "product",
        "vendor_id",
        Product,
        Product.vendor_id.is_(None),
        order_col=Product.article_count.desc(),
    )
    await _bucket(
        "cve",
        "cvss",
        CVE,
        CVE.cvss_score.is_(None),
        order_col=CVE.id.desc(),
    )

    return EnrichmentGapsResponse(buckets=buckets)


# ---------------------------------------------------------------------------
# Bulk gap enrichment
# ---------------------------------------------------------------------------

# (entity_type, field) → (model, missing-field condition, order, name_attr).
# `name_attr` is the column that becomes the human-readable name passed to the
# AI researcher. Every tuple here is fair game for Claude + WebFetch — the
# worker has a matching field-guidance entry in `_GAP_FIELD_GUIDANCE`.
_ENRICH_GAP_SPECS: dict[tuple[str, str], dict[str, Any]] = {
    ("threat_actor", "mitre_id"): {
        "model": ThreatActor,
        "condition": lambda: ThreatActor.mitre_id.is_(None),
        "order": lambda: ThreatActor.article_count.desc(),
        "name_attr": "name",
    },
    ("threat_actor", "country"): {
        "model": ThreatActor,
        "condition": lambda: ThreatActor.origin_country_id.is_(None),
        "order": lambda: ThreatActor.article_count.desc(),
        "name_attr": "name",
    },
    ("threat_actor", "motivation"): {
        "model": ThreatActor,
        "condition": lambda: ThreatActor.motivation.is_(None),
        "order": lambda: ThreatActor.article_count.desc(),
        "name_attr": "name",
    },
    ("threat_actor", "description"): {
        "model": ThreatActor,
        "condition": lambda: or_(ThreatActor.description.is_(None), func.length(ThreatActor.description) < 80),
        "order": lambda: ThreatActor.article_count.desc(),
        "name_attr": "name",
    },
    ("malware", "malware_type"): {
        "model": MalwareFamily,
        "condition": lambda: MalwareFamily.malware_type.is_(None),
        "order": lambda: MalwareFamily.article_count.desc(),
        "name_attr": "name",
    },
    ("malware", "description"): {
        "model": MalwareFamily,
        "condition": lambda: or_(MalwareFamily.description.is_(None), func.length(MalwareFamily.description) < 80),
        "order": lambda: MalwareFamily.article_count.desc(),
        "name_attr": "name",
    },
    ("product", "vendor_id"): {
        "model": Product,
        "condition": lambda: Product.vendor_id.is_(None),
        "order": lambda: Product.article_count.desc(),
        "name_attr": "name",
    },
    ("cve", "cvss"): {
        "model": CVE,
        "condition": lambda: CVE.cvss_score.is_(None),
        "order": lambda: CVE.id.desc(),
        "name_attr": "cve_id",
    },
}


class EnrichGapRequest(BaseModel):
    entity_type: str
    field: str
    limit: int = Field(default=10, ge=1, le=50)

    model_config = ConfigDict(
        json_schema_extra={"example": {"entity_type": "threat_actor", "field": "country", "limit": 10}}
    )


class EnrichGapResponse(BaseModel):
    entity_type: str
    field: str
    enqueued: int
    total_missing: int
    supported: bool
    async_mode: bool = True
    batch_size: int = 0
    message: str | None = None


@router.post("/admin/hygiene/enrichment-gaps/enrich", response_model=EnrichGapResponse)
async def enrich_gap(
    body: EnrichGapRequest,
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> EnrichGapResponse:
    """Dispatch Claude Code with WebFetch to research and fill the requested
    field for the top-N entities missing it.

    Runs as a single batch (capped at body.limit, ≤50 by the request schema)
    on the `ai` queue. The worker writes high-confidence values
    directly into the entity column and records source URLs in the
    enrichment_results audit table (source_type='ai_research').
    """
    spec = _ENRICH_GAP_SPECS.get((body.entity_type, body.field))
    if not spec:
        return EnrichGapResponse(
            entity_type=body.entity_type,
            field=body.field,
            enqueued=0,
            total_missing=0,
            supported=False,
            async_mode=True,
            batch_size=0,
            message=f"AI enrichment isn't wired up for {body.entity_type} · {body.field}.",
        )

    model = spec["model"]
    condition = spec["condition"]()
    order = spec["order"]()
    name_attr = spec["name_attr"]

    total = (await db.execute(select(func.count()).select_from(model).where(condition))).scalar_one()

    rows = (
        await db.execute(select(model.id, getattr(model, name_attr)).where(condition).order_by(order).limit(body.limit))
    ).all()

    batch = [{"id": str(r[0]), "name": r[1]} for r in rows if r[1]]
    if not batch:
        return EnrichGapResponse(
            entity_type=body.entity_type,
            field=body.field,
            enqueued=0,
            total_missing=int(total),
            supported=True,
            async_mode=True,
            batch_size=0,
            message="Nothing to enrich.",
        )

    from app.workers.entity_maintenance_tasks import ai_enrich_gap_batch

    try:
        ai_enrich_gap_batch.apply_async(
            args=[body.entity_type, body.field, batch],
            queue="ai",
        )
    except Exception as e:  # pragma: no cover  (broker hiccup; best-effort)
        return EnrichGapResponse(
            entity_type=body.entity_type,
            field=body.field,
            enqueued=0,
            total_missing=int(total),
            supported=True,
            async_mode=True,
            batch_size=0,
            message=f"Failed to dispatch AI task: {e}",
        )

    return EnrichGapResponse(
        entity_type=body.entity_type,
        field=body.field,
        enqueued=len(batch),
        total_missing=int(total),
        supported=True,
        async_mode=True,
        batch_size=len(batch),
    )


# ---------------------------------------------------------------------------
# Unified feed
# ---------------------------------------------------------------------------


class FeedLink(BaseModel):
    """A clickable affected-entity link surfaced on a feed row.

    The frontend uses `kind` to decide where to deep-link:
      entity   → /workbench/{slug}/{id}  (slug from entity_type)
      entry    → /?entry={id}
      external → href = entity_id verbatim (used for AI source URLs)
    """

    kind: str  # "entity" | "entry" | "external"
    entity_type: str | None = None  # only set when kind == "entity"
    entity_id: str | None = None  # uuid for entity/entry, full URL for external
    label: str
    role: str | None = None  # e.g. "source" | "target" | "member"


class FeedRow(BaseModel):
    """Normalized row from either log source. The unified hygiene feed."""

    id: str  # "{source}:{row_id}" — globally unique across both tables
    source: str  # 'link_validator' | 'entity_maintenance'
    action: str  # raw action label from the underlying row
    when: datetime
    mode: str | None  # 'shadow' | 'apply' | None
    applied: bool | None
    entity_type: str | None
    entity_id: uuid.UUID | None
    entity_name: str | None
    subject: str | None  # short, human-readable label for the row
    reason: str | None
    payload: dict  # the underlying log row's structured fields, kept verbatim
    actions: list[str]  # frontend hints: e.g. ["restore"], ["apply"], ["dismiss"]
    links: list[FeedLink] = []  # affected entities/entries to deep-link from the row
    # Who proposed it: "adjudicator" (the post-analysis adjudicate stage, with
    # the article in hand) or "legacy" (the retired nightly jobs / scans).
    origin: str | None = None


class FeedResponse(BaseModel):
    rows: list[FeedRow]
    has_more: bool
    next_offset: int


_LINK_VALIDATOR_ACTIONS = {"shadow_remove", "removed", "restored", "needs_reclassification"}
_MAINTENANCE_ACTIONS = {
    "merge",
    "reclassify",
    "no_op",
    "update_description",
    "update_aliases",
    "orphan_prune",
    "normalize_name",
    "ai_enrich_filled",
    "ai_enrich_unknown",
    "alias_collision",
    "vendor_autolink",
    "ttp_malformed_id",
    "cve_malformed_id",
    "cve_withdrawn",
    *ADJUDICATION_ACTIONS,
}
# Maintenance actions whose action code persists from proposal through apply
# (only the `applied` boolean flips). Filtering by these in the UI means
# "show me the unapplied proposals" — applied rows must be excluded.
_MAINTENANCE_PROPOSAL_ACTIONS = {
    "normalize_name",
    "alias_collision",
    "vendor_autolink",
    "ttp_malformed_id",
    "cve_malformed_id",
    "cve_withdrawn",
    *ADJUDICATION_ACTIONS,
}
# Maintenance actions whose code is used for BOTH a shadow preview and the
# real apply. UI labels them in past tense ("Merged", "Reclassified",
# "Orphan pruned"), so the filter should only show rows that actually ran.
_MAINTENANCE_APPLIED_ACTIONS = {
    "merge",
    "reclassify",
    "orphan_prune",
}


def _parse_action_list(action: str | None) -> set[str]:
    """An action filter is a single code or a comma-separated list of codes
    (the UI's grouped chips, e.g. all three id-fix actions as one filter)."""
    if not action:
        return set()
    return {a.strip() for a in action.split(",") if a.strip()}


def _row_actions_link(row: EntityLinkValidationLog) -> list[str]:
    if row.action == "removed":
        return ["restore"]
    if row.action == "needs_reclassification":
        return ["apply_reclassify", "dismiss"]
    if row.action == "shadow_remove":
        return ["promote_to_remove", "dismiss"]
    return []


def _row_actions_maint(row: EntityMaintenanceLog) -> list[str]:
    if row.action == "orphan_prune" and row.mode == "shadow":
        return ["apply", "dismiss"]
    if row.action == "normalize_name" and not row.applied:
        return ["apply", "dismiss"]
    if row.action in ("alias_collision", "vendor_autolink") and not row.applied:
        return ["apply", "dismiss"]
    if row.action in ("ttp_malformed_id", "cve_malformed_id") and not row.applied:
        # Apply is only meaningful when we computed a `proposed_id`; otherwise
        # the row is informational and the only useful action is dismiss.
        after = row.after or {}
        if after.get("proposed_id"):
            return ["apply", "dismiss"]
        return ["dismiss"]
    if row.action == "cve_withdrawn" and not row.applied:
        return ["apply", "dismiss"]
    if row.action in ADJUDICATION_ACTIONS:
        if row.action == ACTION_ASSESSMENT:
            return ["dismiss"] if not row.applied else []
        if not row.applied:
            return ["apply", "dismiss"]
        # A merge or a reclassify is undone from the merge engine's tombstone,
        # not from this row.
        if row.action in (ACTION_MERGE, ACTION_RECLASSIFY) or (row.after or {}).get("restored"):
            return []
        return ["restore"]
    return []


def _link_subject(row: EntityLinkValidationLog) -> str:
    name = row.entity_name_snapshot or "(unnamed)"
    parts: list[str] = [f"{name} ({row.entity_type})"]
    if row.action == "needs_reclassification" and row.suggested_entity_type:
        parts.append(f"→ {row.suggested_entity_type}")
    return " ".join(parts)


def _maint_subject(row: EntityMaintenanceLog) -> str:
    after = row.after or {}
    before = row.before or {}
    if row.action == "reclassify":
        src = (before.get("source") or {}).get("name") if isinstance(before.get("source"), dict) else None
        st = before.get("source_type") or ""
        tt = before.get("target_type") or row.entity_type
        if src:
            return f"{src} ({st}) → {tt}"
        return f"{row.entity_type} reclassify"
    if row.action == "merge":
        tgt = (before.get("target") or {}).get("name") if isinstance(before.get("target"), dict) else None
        src = (before.get("source") or {}).get("name") if isinstance(before.get("source"), dict) else None
        if tgt and src:
            return f"{src} → {tgt}"
        return tgt or src or row.entity_type
    if row.action == "orphan_prune":
        nm = (before.get("entity") or {}).get("name") if isinstance(before.get("entity"), dict) else None
        return f"{nm or '(unknown)'} ({row.entity_type})"
    if row.action in ADJUDICATION_ACTIONS:
        return _adjudication_subject(row)
    if row.action == "normalize_name":
        current = (before.get("entity") or {}).get("name") if isinstance(before.get("entity"), dict) else None
        proposed = after.get("proposed_name")
        kind = after.get("kind") or "rename"
        suffix = "merge" if kind == "merge_into_canonical" else "rename"
        if current and proposed:
            return f"{current} → {proposed} ({suffix})"
        return f"{current or proposed or row.entity_type} ({suffix})"
    if row.action == "alias_collision":
        ent = before.get("entity") or {}
        ent_name = ent.get("name") if isinstance(ent, dict) else None
        bad = after.get("bad_alias")
        kind = after.get("kind")
        if kind == "matches_other_entity":
            other = after.get("matches_entity_name") or "another entity"
            return f"{ent_name or '(unknown)'} · trim alias '{bad}' (clashes with {other})"
        if kind == "alias_equals_canonical":
            return f"{ent_name or '(unknown)'} · trim duplicate alias '{bad}'"
        if kind == "case_duplicate":
            return f"{ent_name or '(unknown)'} · trim case-only alias '{bad}'"
        return f"{ent_name or row.entity_type} · trim alias '{bad}'"
    if row.action == "vendor_autolink":
        prod = (before.get("entity") or {}).get("name") if isinstance(before.get("entity"), dict) else None
        vendor = after.get("proposed_vendor_name") or "?"
        return f"{prod or 'product'} → vendor {vendor}"
    if row.action == "ttp_malformed_id":
        ent = before.get("entity") or {}
        current = after.get("current_id") or ent.get("technique_id") or "?"
        proposed = after.get("proposed_id")
        if proposed:
            return f"{current} → {proposed}"
        return f"{current} (malformed, no canonical form)"
    if row.action == "cve_malformed_id":
        ent = before.get("entity") or {}
        current = after.get("current_id") or ent.get("cve_id") or "?"
        proposed = after.get("proposed_id")
        if proposed:
            return f"{current} → {proposed}"
        return f"{current} (malformed CVE id)"
    if row.action == "cve_withdrawn":
        ent = before.get("entity") or {}
        cve = ent.get("cve_id") or "?"
        status = after.get("vuln_status") or "withdrawn"
        return f"{cve} · {status} (NVD)"
    if row.action in ("ai_enrich_filled", "ai_enrich_unknown"):
        ent_name = (before.get("entity") or {}).get("name") if isinstance(before.get("entity"), dict) else None
        field = after.get("field") or "?"
        if row.action == "ai_enrich_filled":
            preview = (after.get("value") or "").strip().replace("\n", " ")
            if len(preview) > 80:
                preview = preview[:77] + "…"
            if ent_name and preview:
                return f"{ent_name} · {field} ← {preview}"
            if ent_name:
                return f"{ent_name} · {field} filled"
            return f"{row.entity_type} {field} filled"
        # unknown
        return f"{ent_name or row.entity_type} · {field} (AI: no reliable source)"
    return f"{row.entity_type} {row.action}"


def _adjudication_subject(row: EntityMaintenanceLog) -> str:
    """Plain-English subject for the adjudicate stage's proposal rows."""
    before = row.before or {}
    after = row.after or {}
    ent = before.get("entity") if isinstance(before.get("entity"), dict) else {}
    name = ent.get("name") or after.get("value") or "(unknown)"
    if row.action == ACTION_VETO:
        return f"Veto: {name} ({row.entity_type}) should not exist"
    if row.action == ACTION_MERGE:
        return f"Merge: {name} → {after.get('merge_into') or '?'} ({after.get('target_type') or row.entity_type})"
    if row.action == ACTION_RECLASSIFY:
        return f"Reclassify: {name or row.entity_type} → {after.get('suggested_type') or '?'}"
    if row.action == ACTION_UNLINK:
        return f"Unlink: {name or row.entity_type} from this article"
    if row.action == ACTION_EDGE_DEMOTE:
        return f"Demote: {before.get('claim') or 'relationship'}"
    if row.action == ACTION_IOC_DROP:
        where = "staged candidate" if before.get("staged") else "captured sighting"
        return f"Drop: {after.get('value') or '?'} ({after.get('kind') or 'observable'}, {where})"
    if row.action == ACTION_ASSESSMENT:
        return f"Assessment {after.get('verdict') or '?'}"
    return row.action


def _maint_links(row: EntityMaintenanceLog) -> list[FeedLink]:
    """Surface every affected entity on a maintenance row as a deep-link chip.

    The cluster-summary rows pack their member entities into
    `before.cluster_members`, plus per-pair source/target names inside
    `after.merges` and `after.reclassifies`. Per-pair merge/reclassify rows
    keep the source/target snapshots in `before.{source,target}`.
    """
    out: list[FeedLink] = []
    before = row.before or {}
    after = row.after or {}

    def _add(etype: str | None, eid, name: str | None, role: str | None = None) -> None:
        if not etype or not eid or not name:
            return
        out.append(
            FeedLink(
                kind="entity",
                entity_type=etype,
                entity_id=str(eid),
                label=name,
                role=role,
            )
        )

    if row.action in ADJUDICATION_ACTIONS:
        ent = before.get("entity") if isinstance(before.get("entity"), dict) else None
        if ent and row.entity_id and row.action in (ACTION_VETO, ACTION_MERGE, ACTION_UNLINK, ACTION_RECLASSIFY):
            _add(row.entity_type, row.entity_id, ent.get("name"), role="subject")
        if row.action == ACTION_MERGE and after.get("target_id"):
            _add(
                after.get("target_type") or row.entity_type,
                after.get("target_id"),
                after.get("merge_into"),
                role="target",
            )
        if before.get("entry_id"):
            out.append(FeedLink(kind="entry", entity_id=str(before["entry_id"]), label="source entry"))
        return out
    if row.action in ("merge", "reclassify"):
        src = before.get("source") if isinstance(before.get("source"), dict) else None
        tgt = before.get("target") if isinstance(before.get("target"), dict) else None
        src_type = before.get("source_type") or row.entity_type
        tgt_type = before.get("target_type") or row.entity_type
        if src:
            _add(src_type, src.get("id"), src.get("name"), role="source")
        if tgt:
            _add(tgt_type, tgt.get("id"), tgt.get("name"), role="target")
        elif row.entity_id and src and src.get("name"):
            # Reclassify with no pre-existing target — the new entity is row.entity_id
            # in target_type, name == source.name.
            _add(tgt_type, row.entity_id, src.get("name"), role="target")
    elif row.action == "orphan_prune":
        ent = before.get("entity") if isinstance(before.get("entity"), dict) else None
        if ent:
            _add(row.entity_type, ent.get("id"), ent.get("name"))
    elif row.action == "normalize_name":
        ent = before.get("entity") if isinstance(before.get("entity"), dict) else None
        if ent:
            _add(row.entity_type, ent.get("id"), ent.get("name"), role="source")
        merge_target = after.get("merge_target_id")
        if merge_target and after.get("proposed_name"):
            _add(row.entity_type, merge_target, after.get("proposed_name"), role="target")
    elif row.action in ("update_description", "update_aliases"):
        if row.entity_id:
            # Try to recover a name from the before-snapshot; otherwise fall back
            # to a generic label so the chip is still clickable.
            name = (before.get("target") or {}).get("name") if isinstance(before.get("target"), dict) else None
            _add(row.entity_type, row.entity_id, name or row.entity_type)
    elif row.action in ("ai_enrich_filled", "ai_enrich_unknown"):
        ent = before.get("entity") if isinstance(before.get("entity"), dict) else None
        if ent:
            _add(row.entity_type, ent.get("id"), ent.get("name"))
        # Surface the cited source URLs as external chips so the analyst can
        # click straight through to KELA / Mandiant / ATT&CK / etc. Label is
        # the bare hostname so the row stays compact.
        from urllib.parse import urlparse

        for url in (after.get("source_urls") or [])[:3]:
            if not isinstance(url, str) or not url:
                continue
            try:
                host = urlparse(url).hostname or url
            except ValueError:
                host = url
            out.append(
                FeedLink(
                    kind="external",
                    entity_type=None,
                    entity_id=url,
                    label=host,
                    role="source",
                )
            )
    elif row.action == "alias_collision":
        ent = before.get("entity") if isinstance(before.get("entity"), dict) else None
        if ent:
            _add(row.entity_type, ent.get("id"), ent.get("name"), role="subject")
        # Surface the would-be-merged sibling so the analyst can pivot to it.
        match_id = after.get("matches_entity_id")
        match_name = after.get("matches_entity_name")
        if match_id and match_name:
            _add(row.entity_type, match_id, match_name, role="missed_merge")
    elif row.action == "vendor_autolink":
        ent = before.get("entity") if isinstance(before.get("entity"), dict) else None
        if ent:
            _add("product", ent.get("id"), ent.get("name"), role="product")
        v_id = after.get("proposed_vendor_id")
        v_name = after.get("proposed_vendor_name")
        if v_id and v_name:
            _add("vendor", v_id, v_name, role="vendor")
    elif row.action in ("ttp_malformed_id", "cve_malformed_id", "cve_withdrawn"):
        ent = before.get("entity") if isinstance(before.get("entity"), dict) else None
        if ent:
            label = ent.get("name") or ent.get("technique_id") or ent.get("cve_id") or "(unknown)"
            # ttps / cves don't have entity profile routes in the workbench, so
            # the chip won't get a deep link — surfaced just for visibility.
            _add(row.entity_type, ent.get("id"), label, role="subject")
    return out


@router.get("/admin/hygiene/feed", response_model=FeedResponse)
async def hygiene_feed(
    action: str | None = Query(
        None,
        description="Filter by action. Accepts any action from either log source; "
        "comma-separate to match several (e.g. 'ttp_malformed_id,cve_malformed_id').",
    ),
    source: str | None = Query(None, description="'link_validator' | 'entity_maintenance' | null (all)."),
    mode: str | None = Query(None, description="'shadow' | 'apply' — applies to entity_maintenance rows."),
    pending: bool = Query(
        False,
        description="Only unapplied proposals (skips applied history). Required for the review queue, "
        "since applied resolution logs otherwise flood the newest page.",
    ),
    origin: str | None = Query(
        None,
        description="'adjudicator' = rows the post-analysis adjudicate stage filed; "
        "'legacy' = everything else (nightly jobs, scans, analysts).",
    ),
    orphaned: bool = Query(
        False,
        description="Only pending proposals the retired jobs left that no entry can carry to the adjudicate "
        "stage: link proposals whose entry is gone, and merge-engine / stale-sweep proposals about an entity "
        "that no longer exists or has no creating entry. They are listed for manual disposition, never "
        "auto-dismissed.",
    ),
    since: datetime | None = Query(None, description="Only rows created at or after this timestamp"),
    limit: int = Query(50, ge=1, le=200, description="Rows per page"),
    offset: int = Query(0, ge=0, description="Rows to skip for pagination"),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> FeedResponse:
    """Chronological merge of both maintenance log tables, normalized to FeedRow.

    Implementation: pulls limit+offset+1 from each table independently, merges
    in Python by created_at desc, slices to the requested window. For the
    expected log volumes (thousands, not millions) this is fine; if the tables
    grow, switch to a UNION ALL SQL query.
    """
    fetch_cap = limit + offset + 1

    # When an action filter is set, skip the table it doesn't belong to entirely.
    # The previous elif-chain failed to exclude one side when the action was
    # valid on the OTHER side, leaking unfiltered rows through. Compute
    # eligibility up-front so the queries are obviously scoped.
    actions = _parse_action_list(action)
    link_actions = actions & _LINK_VALIDATOR_ACTIONS
    maint_actions = actions & _MAINTENANCE_ACTIONS
    link_eligible = source in (None, "link_validator") and (not actions or bool(link_actions))
    maint_eligible = source in (None, "entity_maintenance") and (not actions or bool(maint_actions))

    adjudicator_results = select(AIResult.id).where(
        AIResult.task_id == select(AITask.id).where(AITask.name == ADJUDICATION_TASK_NAME).scalar_subquery()
    )

    link_rows: list[EntityLinkValidationLog] = []
    if link_eligible:
        q = select(EntityLinkValidationLog)
        if orphaned:
            # A pending legacy proposal whose entry is gone: the backfill can
            # never reach it. (The entry FK cascades, so this is rare and
            # means a row written without an entry.)
            q = q.where(
                EntityLinkValidationLog.action.in_(["shadow_remove", "needs_reclassification"]),
                or_(
                    EntityLinkValidationLog.ai_result_id.is_(None),
                    ~EntityLinkValidationLog.ai_result_id.in_(adjudicator_results),
                ),
                ~EntityLinkValidationLog.entry_id.in_(select(Entry.id)),
            )
        if origin == "adjudicator":
            q = q.where(EntityLinkValidationLog.ai_result_id.in_(adjudicator_results))
        elif origin == "legacy":
            q = q.where(
                or_(
                    EntityLinkValidationLog.ai_result_id.is_(None),
                    ~EntityLinkValidationLog.ai_result_id.in_(adjudicator_results),
                )
            )
        if pending:
            q = q.where(EntityLinkValidationLog.action.in_(["shadow_remove", "needs_reclassification"]))
        if link_actions:
            q = q.where(EntityLinkValidationLog.action.in_(sorted(link_actions)))
        # link_validator has no `mode` column — map mode filter to action subsets:
        # proposed → shadow_remove + needs_reclassification (no junction mutation)
        # applied  → removed + restored (junction actually mutated)
        if mode == "shadow":
            q = q.where(EntityLinkValidationLog.action.in_(["shadow_remove", "needs_reclassification"]))
        elif mode == "apply":
            q = q.where(EntityLinkValidationLog.action.in_(["removed", "restored"]))
        if since:
            q = q.where(EntityLinkValidationLog.created_at >= since)
        q = q.order_by(EntityLinkValidationLog.created_at.desc()).limit(fetch_cap)
        link_rows = list((await db.execute(q)).scalars().all())

    maint_rows: list[EntityMaintenanceLog] = []
    if maint_eligible:
        q = select(EntityMaintenanceLog)
        if origin == "adjudicator":
            q = q.where(EntityMaintenanceLog.action.in_(sorted(ADJUDICATION_ACTIONS)))
        elif origin == "legacy":
            q = q.where(EntityMaintenanceLog.action.notin_(sorted(ADJUDICATION_ACTIONS)))
        if orphaned:
            q = q.where(
                EntityMaintenanceLog.action.in_(list(LEGACY_MAINT_ACTIONS)),
                EntityMaintenanceLog.applied.is_(False),
            )
            fetch_cap = max(fetch_cap, 500)  # narrowed again in Python below
        if pending:
            q = q.where(
                EntityMaintenanceLog.applied.is_(False),
                EntityMaintenanceLog.action.in_(sorted(_MAINTENANCE_PROPOSAL_ACTIONS | {"orphan_prune"})),
            )
        if maint_actions:
            q = q.where(EntityMaintenanceLog.action.in_(sorted(maint_actions)))
            # Proposal-only actions reuse the same code post-apply (only the
            # `applied` flag flips). The UI labels them "· proposed", so scope
            # to unapplied rows.
            if maint_actions <= _MAINTENANCE_PROPOSAL_ACTIONS:
                q = q.where(EntityMaintenanceLog.applied.is_(False))
            # Outcome filters ("Merged", "Reclassified", "Orphan pruned") use
            # the same action code as their shadow previews. Scope to rows
            # that actually ran.
            elif maint_actions <= _MAINTENANCE_APPLIED_ACTIONS:
                q = q.where(EntityMaintenanceLog.applied.is_(True))
        # mode filter for entity_maintenance: proposed = shadow + not-yet-applied,
        # applied = anything where applied=True regardless of mode column.
        if mode == "shadow":
            q = q.where(
                EntityMaintenanceLog.mode == "shadow",
                EntityMaintenanceLog.applied.is_(False),
            )
        elif mode == "apply":
            q = q.where(EntityMaintenanceLog.applied.is_(True))
        if since:
            q = q.where(EntityMaintenanceLog.created_at >= since)
        q = q.order_by(EntityMaintenanceLog.created_at.desc()).limit(fetch_cap)
        maint_rows = list((await db.execute(q)).scalars().all())
        if orphaned:
            # "No entry can carry it" is a per-entity question (the entity is
            # gone, or nothing records which entry created it), so it is
            # answered here rather than in the query.
            keep: list[EntityMaintenanceLog] = []
            for r in maint_rows:
                if await legacy_row_is_orphaned(db, r):
                    keep.append(r)
            maint_rows = keep

    # Which link rows came from the adjudicate stage (maintenance rows carry
    # it in their action code).
    adjudicator_ids: set[uuid.UUID] = set()
    result_ids = {r.ai_result_id for r in link_rows if r.ai_result_id}
    if result_ids:
        adjudicator_ids = set(
            (
                await db.execute(
                    select(AIResult.id)
                    .join(AITask, AITask.id == AIResult.task_id)
                    .where(AIResult.id.in_(result_ids), AITask.name == ADJUDICATION_TASK_NAME)
                )
            )
            .scalars()
            .all()
        )

    # Normalize and merge.
    feed: list[FeedRow] = []
    for r in link_rows:
        # Synthesize a mode tag so the row visually matches maintenance rows:
        # actions that mutated junctions = applied, advisories = proposed.
        link_mode = "apply" if r.action in ("removed", "restored") else "shadow"
        links: list[FeedLink] = []
        if r.entity_name_snapshot and r.entity_id:
            links.append(
                FeedLink(
                    kind="entity",
                    entity_type=r.entity_type,
                    entity_id=str(r.entity_id),
                    label=r.entity_name_snapshot,
                    role="subject",
                )
            )
        if r.entry_id:
            links.append(FeedLink(kind="entry", entity_id=str(r.entry_id), label="source entry"))
        feed.append(
            FeedRow(
                id=f"link_validator:{r.id}",
                source="link_validator",
                action=r.action,
                when=r.created_at,
                mode=link_mode,
                applied=r.action in ("removed", "restored"),
                entity_type=r.entity_type,
                entity_id=r.entity_id,
                entity_name=r.entity_name_snapshot,
                subject=_link_subject(r),
                reason=r.reason,
                payload={
                    "log_id": str(r.id),
                    "entry_id": str(r.entry_id),
                    "original_source": r.original_source,
                    "original_confidence": r.original_confidence,
                    "original_matched_names": list(r.original_matched_names or []),
                    "original_paragraph_indices": list(r.original_paragraph_indices or []),
                    "suggested_entity_type": r.suggested_entity_type,
                    "ai_result_id": str(r.ai_result_id) if r.ai_result_id else None,
                },
                actions=_row_actions_link(r),
                links=links,
                origin="adjudicator" if r.ai_result_id in adjudicator_ids else "legacy",
            )
        )
    for r in maint_rows:
        feed.append(
            FeedRow(
                id=f"entity_maintenance:{r.id}",
                source="entity_maintenance",
                action=r.action,
                when=r.created_at,
                mode=r.mode,
                applied=bool(r.applied),
                entity_type=r.entity_type,
                entity_id=r.entity_id,
                entity_name=None,
                subject=_maint_subject(r),
                reason=r.reasoning,
                payload={
                    "log_id": str(r.id),
                    "before": r.before,
                    "after": r.after,
                    "ai_result_id": str(r.ai_result_id) if r.ai_result_id else None,
                },
                actions=_row_actions_maint(r),
                links=_maint_links(r),
                origin="adjudicator" if r.action in ADJUDICATION_ACTIONS else "legacy",
            )
        )

    feed.sort(key=lambda f: f.when, reverse=True)
    sliced = feed[offset : offset + limit]
    has_more = len(feed) > offset + limit
    return FeedResponse(
        rows=sliced,
        has_more=has_more,
        next_offset=offset + len(sliced),
    )


# ---------------------------------------------------------------------------
# Combined stats
# ---------------------------------------------------------------------------


class HygieneStats(BaseModel):
    # Adjudicate stage (post-analysis review) — the cleanup path
    adjudication_mode: str  # off | shadow | apply
    adjudication_pending: int  # unapplied verdicts it filed, across both logs
    adjudication_breaker_until: datetime | None = None  # rolling breaker has paused dispatch until then
    pending_advisories: int  # needs_reclassification rows
    name_normalization_proposed: int  # unapplied normalize_name rows
    applied_24h: int  # actions applied across both logs in last 24h
    applied_7d: int
    orphan_count: int
    last_maintenance_run_at: datetime | None
    # Deterministic hygiene scans — each tracks unapplied proposals
    alias_collisions_proposed: int
    vendor_autolinks_proposed: int
    ttp_cve_issues_proposed: int


@router.get("/admin/hygiene/stats", response_model=HygieneStats)
async def hygiene_stats(
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> HygieneStats:
    """Combined hygiene counters across both proposal logs: the adjudicate
    stage's mode and pending verdicts, pending proposals per scan type,
    orphans and recent apply activity."""
    from app.services.entry_adjudication import breaker_paused_until
    from app.services.system_settings import get_setting

    adjudication_mode = str(await get_setting("adjudication_mode", db) or "off").lower()
    adjudication_breaker_until = await breaker_paused_until()
    adjudicator_results = select(AIResult.id).where(
        AIResult.task_id == select(AITask.id).where(AITask.name == ADJUDICATION_TASK_NAME).scalar_subquery()
    )
    adjudication_pending = (
        await db.execute(
            select(func.count())
            .select_from(EntityLinkValidationLog)
            .where(
                EntityLinkValidationLog.action.in_(["shadow_remove", "needs_reclassification"]),
                EntityLinkValidationLog.ai_result_id.in_(adjudicator_results),
            )
        )
    ).scalar_one() + (
        await db.execute(
            select(func.count())
            .select_from(EntityMaintenanceLog)
            .where(
                EntityMaintenanceLog.action.in_(sorted(ADJUDICATION_ACTIONS)),
                EntityMaintenanceLog.applied.is_(False),
            )
        )
    ).scalar_one()

    # pending_advisories drives the "Apply all proposed reclassifies (N)" bulk button.
    pending_advisories = (
        await db.execute(
            select(func.count())
            .select_from(EntityLinkValidationLog)
            .where(EntityLinkValidationLog.action == "needs_reclassification")
        )
    ).scalar_one()

    name_normalization_proposed = (
        await db.execute(
            select(func.count())
            .select_from(EntityMaintenanceLog)
            .where(
                EntityMaintenanceLog.action == "normalize_name",
                EntityMaintenanceLog.applied.is_(False),
            )
        )
    ).scalar_one()

    now = datetime.now(UTC)
    cutoff_24h = now - timedelta(hours=24)
    cutoff_7d = now - timedelta(days=7)

    # "Applied" = link_validator removed/restored + entity_maintenance applied=true
    applied_24h_link = (
        await db.execute(
            select(func.count())
            .select_from(EntityLinkValidationLog)
            .where(
                EntityLinkValidationLog.action.in_(["removed", "restored"]),
                EntityLinkValidationLog.created_at >= cutoff_24h,
            )
        )
    ).scalar_one()
    applied_24h_maint = (
        await db.execute(
            select(func.count())
            .select_from(EntityMaintenanceLog)
            .where(
                EntityMaintenanceLog.applied.is_(True),
                EntityMaintenanceLog.created_at >= cutoff_24h,
            )
        )
    ).scalar_one()

    applied_7d_link = (
        await db.execute(
            select(func.count())
            .select_from(EntityLinkValidationLog)
            .where(
                EntityLinkValidationLog.action.in_(["removed", "restored"]),
                EntityLinkValidationLog.created_at >= cutoff_7d,
            )
        )
    ).scalar_one()
    applied_7d_maint = (
        await db.execute(
            select(func.count())
            .select_from(EntityMaintenanceLog)
            .where(
                EntityMaintenanceLog.applied.is_(True),
                EntityMaintenanceLog.created_at >= cutoff_7d,
            )
        )
    ).scalar_one()

    last_maintenance = (await db.execute(select(func.max(EntityMaintenanceLog.created_at)))).scalar_one()

    # Orphan count: sum across scannable types.
    orphan_count = 0
    for etype in ORPHAN_SCANNABLE_TYPES:
        spec = ENTITY_TYPE_REGISTRY.get(etype)
        if not spec:
            continue
        model = spec["model"]
        junction = spec["junction_model"]
        fk_attr = spec["junction_fk"]
        link_count_subq = (
            select(func.count()).select_from(junction).where(getattr(junction, fk_attr) == model.id).scalar_subquery()
        )
        c = (await db.execute(select(func.count()).select_from(model).where(link_count_subq == 0))).scalar_one()
        orphan_count += int(c)

    alias_collisions_proposed = (
        await db.execute(
            select(func.count())
            .select_from(EntityMaintenanceLog)
            .where(
                EntityMaintenanceLog.action == "alias_collision",
                EntityMaintenanceLog.applied.is_(False),
            )
        )
    ).scalar_one()
    vendor_autolinks_proposed = (
        await db.execute(
            select(func.count())
            .select_from(EntityMaintenanceLog)
            .where(
                EntityMaintenanceLog.action == "vendor_autolink",
                EntityMaintenanceLog.applied.is_(False),
            )
        )
    ).scalar_one()
    ttp_cve_issues_proposed = (
        await db.execute(
            select(func.count())
            .select_from(EntityMaintenanceLog)
            .where(
                EntityMaintenanceLog.action.in_(["ttp_malformed_id", "cve_malformed_id", "cve_withdrawn"]),
                EntityMaintenanceLog.applied.is_(False),
            )
        )
    ).scalar_one()

    return HygieneStats(
        adjudication_mode=adjudication_mode,
        adjudication_breaker_until=adjudication_breaker_until,
        adjudication_pending=int(adjudication_pending),
        pending_advisories=int(pending_advisories),
        name_normalization_proposed=int(name_normalization_proposed),
        applied_24h=int(applied_24h_link) + int(applied_24h_maint),
        applied_7d=int(applied_7d_link) + int(applied_7d_maint),
        orphan_count=orphan_count,
        last_maintenance_run_at=last_maintenance,
        alias_collisions_proposed=int(alias_collisions_proposed),
        vendor_autolinks_proposed=int(vendor_autolinks_proposed),
        ttp_cve_issues_proposed=int(ttp_cve_issues_proposed),
    )


# ---------------------------------------------------------------------------
# Deterministic name normalization
# ---------------------------------------------------------------------------

NAME_NORMALIZATION_TYPES = ["threat_actor", "malware", "vendor", "product", "tool"]


class NameNormalizationRunRequest(BaseModel):
    entity_type: str | None = Field(
        default=None,
        description="Restrict scan to a single entity_type. Default scans all five.",
    )

    model_config = ConfigDict(json_schema_extra={"example": {"entity_type": "malware"}})


class NameNormalizationRunResponse(BaseModel):
    mode: str
    scanned: int
    proposed: int  # always 0 here — proposals come in asynchronously
    by_type: dict[str, int]
    by_kind: dict[str, int]
    # Async dispatch metadata so the UI can show real progress information
    # instead of falsely claiming "proposed 0 fixes" right after dispatch.
    dispatched_batches: int
    batch_size: int
    async_mode: bool = True


@router.post("/admin/hygiene/run-name-normalization", response_model=NameNormalizationRunResponse)
async def run_name_normalization(
    body: NameNormalizationRunRequest = Body(default_factory=NameNormalizationRunRequest),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> NameNormalizationRunResponse:
    """Kick off the AI-driven per-entity name correctness check.

    Enqueues a Celery task that batches all entities (or just the requested
    `entity_type`) and dispatches per-batch jobs to the ai queue.
    Each batch asks Claude to judge every name in it cosmetically — casing,
    spelling, formatting per industry convention — and any rename decision
    becomes a `normalize_name` proposal in the hygiene feed.

    This is rename-only; alias collisions / true duplicates belong to the
    merge engine, not here. Returns immediately with the dispatch counts;
    proposals trickle in as the worker processes batches.
    """
    from app.workers.entity_maintenance_tasks import kickoff_name_normalization_ai

    types_to_scan = [body.entity_type] if body.entity_type else NAME_NORMALIZATION_TYPES

    # Count how many entities we're about to scan so the caller knows what
    # was enqueued. The kickoff task itself recomputes the same set.
    total_scanned = 0
    by_type: dict[str, int] = {}
    for etype in types_to_scan:
        spec = ENTITY_TYPE_REGISTRY.get(etype)
        if not spec:
            continue
        model = spec["model"]
        c = (await db.execute(select(func.count()).select_from(model))).scalar_one()
        by_type[etype] = int(c)
        total_scanned += int(c)

    kickoff_name_normalization_ai.apply_async(
        args=[body.entity_type] if body.entity_type else [],
    )

    # Mirror the batching the worker uses so the UI can show how many AI calls
    # will fire. Kept in sync with `_NAME_NORMALIZATION_BATCH_SIZE` in
    # backend/app/workers/entity_maintenance_tasks.py.
    BATCH_SIZE = 30
    dispatched_batches = (total_scanned + BATCH_SIZE - 1) // BATCH_SIZE

    return NameNormalizationRunResponse(
        mode="shadow",
        scanned=total_scanned,
        proposed=0,
        by_type=by_type,
        by_kind={"dispatched": total_scanned},
        dispatched_batches=dispatched_batches,
        batch_size=BATCH_SIZE,
        async_mode=True,
    )


class ApplyNormalizeNameResponse(BaseModel):
    log_id: uuid.UUID
    applied: bool
    skipped: bool
    kind: str | None
    entity_id: uuid.UUID | None
    merge_target_id: uuid.UUID | None
    new_name: str | None


@router.post(
    "/admin/hygiene/normalize-name/{log_id}/apply",
    response_model=ApplyNormalizeNameResponse,
)
async def apply_normalize_name(
    log_id: uuid.UUID = Path(..., description="EntityMaintenanceLog row UUID of the normalize_name proposal"),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> ApplyNormalizeNameResponse:
    """Apply a single `normalize_name` proposal — merge or rename, depending
    on the row's `after.kind`. Idempotent: if the source entity is already
    gone, marks the proposal applied and returns skipped=true.
    """
    row = (await db.execute(select(EntityMaintenanceLog).where(EntityMaintenanceLog.id == log_id))).scalar_one_or_none()
    if not row:
        raise AppError(code="not_found", message="log row not found", status_code=404)
    if row.action != "normalize_name":
        raise AppError(
            code="invalid",
            message=f"can only apply normalize_name rows (got {row.action})",
            status_code=400,
        )
    if row.applied:
        raise AppError(code="invalid", message="already applied", status_code=400)

    after = row.after or {}
    kind = after.get("kind")
    proposed_name = after.get("proposed_name")
    merge_target_raw = after.get("merge_target_id")
    merge_target_id: uuid.UUID | None = None
    if merge_target_raw:
        try:
            merge_target_id = uuid.UUID(str(merge_target_raw))
        except (ValueError, TypeError):
            raise AppError(code="invalid", message="bad merge_target_id in proposal", status_code=400) from None

    spec = ENTITY_TYPE_REGISTRY.get(row.entity_type)
    if not spec:
        raise AppError(
            code="invalid",
            message=f"unsupported entity_type for normalize: {row.entity_type}",
            status_code=400,
        )
    model = spec["model"]
    entity = None
    if row.entity_id is not None:
        entity = (await db.execute(select(model).where(model.id == row.entity_id))).scalar_one_or_none()

    # Source is gone — mark applied and return skipped.
    if entity is None:
        row.applied = True
        db.add(row)
        await db.flush()
        return ApplyNormalizeNameResponse(
            log_id=row.id,
            applied=True,
            skipped=True,
            kind=kind,
            entity_id=row.entity_id,
            merge_target_id=merge_target_id,
            new_name=proposed_name,
        )

    if kind == "merge_into_canonical":
        if merge_target_id is None:
            raise AppError(code="invalid", message="merge proposal missing merge_target_id", status_code=400)
        # If canonical target is gone, the merge is moot — mark applied.
        target_exists = (await db.execute(select(model.id).where(model.id == merge_target_id))).scalar_one_or_none()
        if target_exists is None:
            row.applied = True
            db.add(row)
            await db.flush()
            return ApplyNormalizeNameResponse(
                log_id=row.id,
                applied=True,
                skipped=True,
                kind=kind,
                entity_id=row.entity_id,
                merge_target_id=merge_target_id,
                new_name=proposed_name,
            )
        await perform_same_type_merge(
            db,
            entity_type=row.entity_type,
            target_id=merge_target_id,
            source_id=entity.id,
            mode="apply",
            reasoning=(f"Promoted from name-normalization proposal {row.id}: {(row.reasoning or '')[:1500]}"),
        )
    elif kind == "rename":
        if not proposed_name or not proposed_name.strip():
            raise AppError(code="invalid", message="rename proposal has empty proposed_name", status_code=400)
        before_name = entity.name
        entity.name = proposed_name
        await db.flush()
        applied_row = EntityMaintenanceLog(
            entity_type=row.entity_type,
            entity_id=entity.id,
            action="normalize_name",
            mode="apply",
            before={"entity": {"id": str(entity.id), "name": before_name, "aliases": list(entity.aliases or [])}},
            after={
                "kind": "rename",
                "proposed_name": proposed_name,
                "merge_target_id": None,
                "previous_name": before_name,
                "promoted_from": str(row.id),
            },
            reasoning=(row.reasoning or "")[:2000] or None,
            applied=True,
        )
        db.add(applied_row)
    else:
        raise AppError(code="invalid", message=f"unknown normalize_name kind: {kind!r}", status_code=400)

    row.applied = True
    db.add(row)
    await db.flush()

    return ApplyNormalizeNameResponse(
        log_id=row.id,
        applied=True,
        skipped=False,
        kind=kind,
        entity_id=row.entity_id,
        merge_target_id=merge_target_id,
        new_name=proposed_name,
    )


# ---------------------------------------------------------------------------
# Deterministic alias hygiene scan
# ---------------------------------------------------------------------------
#
# Catches the duplicates the merge engine doesn't bother with: an alias that
# is identical to (or only differs from) the canonical name, or matches the
# canonical name of a sibling entity (likely missed merge).
#
# Pure SQL — no AI. Idempotent: re-running collapses to the same proposal
# rows because we DELETE existing unapplied alias_collision rows before each
# scan, then re-emit.

ALIAS_SCAN_TYPES = ["threat_actor", "malware", "vendor", "product", "tool"]


class AliasScanResponse(BaseModel):
    scanned_entities: int
    proposed: int
    by_kind: dict[str, int]
    by_type: dict[str, int]


@router.post("/admin/hygiene/scan-alias-hygiene", response_model=AliasScanResponse)
async def scan_alias_hygiene(
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> AliasScanResponse:
    """Sweep merge-registry entities for alias duplicates.

    Three categories — all fixed by trimming the alias:

      case_duplicate        alias.lower() == name.lower() AND alias != name
      alias_equals_canonical alias == name (exact dupe)
      matches_other_entity   alias.lower() matches some other entity's
                             canonical name in the same table → likely
                             missed merge

    We clear prior unapplied proposals first so reruns don't compound. The
    fix is a simple alias trim; the missed-merge case still gets a trim
    (merge engine will catch the real merge on its next pass).
    """
    # Wipe stale unapplied proposals so each scan returns the current state.
    await db.execute(
        EntityMaintenanceLog.__table__.delete().where(
            EntityMaintenanceLog.action == "alias_collision",
            EntityMaintenanceLog.applied.is_(False),
        )
    )

    by_kind: dict[str, int] = defaultdict(int)
    by_type: dict[str, int] = defaultdict(int)
    total_scanned = 0
    total_proposed = 0

    for etype in ALIAS_SCAN_TYPES:
        spec = ENTITY_TYPE_REGISTRY.get(etype)
        if not spec:
            continue
        model = spec["model"]
        rows = (await db.execute(select(model.id, model.name, model.aliases))).all()
        # Lowercase name index for the "matches other canonical" check.
        name_by_lower: dict[str, tuple[uuid.UUID, str]] = {}
        for rid, rname, _ in rows:
            if rname:
                name_by_lower[rname.lower()] = (rid, rname)

        for rid, rname, raliases in rows:
            total_scanned += 1
            if not rname or not raliases:
                continue
            seen_alias_lower: set[str] = set()
            for alias in raliases:
                if not isinstance(alias, str):
                    continue
                a = alias.strip()
                if not a:
                    continue
                al = a.lower()
                if al in seen_alias_lower:
                    continue
                seen_alias_lower.add(al)

                kind: str | None = None
                matches_other: tuple[uuid.UUID, str] | None = None
                if a == rname:
                    kind = "alias_equals_canonical"
                elif al == rname.lower():
                    kind = "case_duplicate"
                else:
                    sibling = name_by_lower.get(al)
                    if sibling and sibling[0] != rid:
                        kind = "matches_other_entity"
                        matches_other = sibling
                if not kind:
                    continue

                after_payload: dict[str, Any] = {
                    "bad_alias": a,
                    "kind": kind,
                }
                if matches_other:
                    after_payload["matches_entity_id"] = str(matches_other[0])
                    after_payload["matches_entity_name"] = matches_other[1]
                reasoning = {
                    "alias_equals_canonical": (f"Alias '{a}' is identical to canonical name '{rname}'."),
                    "case_duplicate": (f"Alias '{a}' differs from canonical '{rname}' only in casing."),
                    "matches_other_entity": (
                        f"Alias '{a}' matches canonical name of another {etype} "
                        f"({matches_other[1] if matches_other else '?'}) — likely missed merge."
                    ),
                }[kind]

                db.add(
                    EntityMaintenanceLog(
                        entity_type=etype,
                        entity_id=rid,
                        action="alias_collision",
                        mode="shadow",
                        before={"entity": {"id": str(rid), "name": rname, "aliases": list(raliases or [])}},
                        after=after_payload,
                        reasoning=reasoning[:2000],
                        applied=False,
                    )
                )
                by_kind[kind] += 1
                by_type[etype] += 1
                total_proposed += 1

    await db.flush()
    return AliasScanResponse(
        scanned_entities=total_scanned,
        proposed=total_proposed,
        by_kind=dict(by_kind),
        by_type=dict(by_type),
    )


class ApplyAliasCollisionResponse(BaseModel):
    log_id: uuid.UUID
    applied: bool
    skipped: bool
    entity_id: uuid.UUID | None
    removed_alias: str | None


@router.post(
    "/admin/hygiene/alias-collision/{log_id}/apply",
    response_model=ApplyAliasCollisionResponse,
)
async def apply_alias_collision(
    log_id: uuid.UUID = Path(..., description="EntityMaintenanceLog row UUID of the alias_collision proposal"),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> ApplyAliasCollisionResponse:
    """Trim the offending alias from the source entity.

    Idempotent: if the entity is gone or the alias has already been removed,
    we mark the proposal applied and return skipped=true.
    """
    row = (await db.execute(select(EntityMaintenanceLog).where(EntityMaintenanceLog.id == log_id))).scalar_one_or_none()
    if not row:
        raise AppError(code="not_found", message="proposal not found", status_code=404)
    if row.action != "alias_collision":
        raise AppError(
            code="invalid",
            message=f"can only apply alias_collision rows (got {row.action})",
            status_code=400,
        )
    if row.applied:
        raise AppError(code="invalid", message="already applied", status_code=400)

    bad_alias = (row.after or {}).get("bad_alias")
    if not bad_alias:
        raise AppError(code="invalid", message="missing bad_alias in proposal", status_code=400)

    spec = ENTITY_TYPE_REGISTRY.get(row.entity_type)
    if not spec:
        raise AppError(
            code="invalid",
            message=f"unsupported entity_type: {row.entity_type}",
            status_code=400,
        )
    model = spec["model"]
    entity = (await db.execute(select(model).where(model.id == row.entity_id))).scalar_one_or_none()
    if entity is None:
        row.applied = True
        db.add(row)
        await db.flush()
        return ApplyAliasCollisionResponse(
            log_id=row.id,
            applied=True,
            skipped=True,
            entity_id=row.entity_id,
            removed_alias=bad_alias,
        )

    current = list(entity.aliases or [])
    new_aliases = [a for a in current if a != bad_alias]
    if len(new_aliases) == len(current):
        # Already gone.
        row.applied = True
        db.add(row)
        await db.flush()
        return ApplyAliasCollisionResponse(
            log_id=row.id,
            applied=True,
            skipped=True,
            entity_id=entity.id,
            removed_alias=bad_alias,
        )
    entity.aliases = new_aliases
    row.applied = True
    db.add(row)
    db.add(
        EntityMaintenanceLog(
            entity_type=row.entity_type,
            entity_id=entity.id,
            action="alias_collision",
            mode="apply",
            before={"entity": {"id": str(entity.id), "name": entity.name, "aliases": current}},
            after={
                "bad_alias": bad_alias,
                "kind": (row.after or {}).get("kind"),
                "aliases_after": new_aliases,
                "promoted_from": str(row.id),
            },
            reasoning=f"Promoted from alias_collision proposal {row.id}.",
            applied=True,
        )
    )
    await db.flush()
    return ApplyAliasCollisionResponse(
        log_id=row.id,
        applied=True,
        skipped=False,
        entity_id=entity.id,
        removed_alias=bad_alias,
    )


# ---------------------------------------------------------------------------
# Deterministic vendor↔product auto-link
# ---------------------------------------------------------------------------
#
# Products with vendor_id IS NULL whose name starts with a known vendor name
# (or one of its aliases) followed by a space. Catches the obvious wins
# without bothering Claude — "Cisco IOS", "Microsoft Exchange", "Palo Alto
# Networks Cortex" etc.


class VendorAutolinkScanResponse(BaseModel):
    products_scanned: int
    proposed: int
    by_match_kind: dict[str, int]


@router.post("/admin/hygiene/scan-vendor-autolink", response_model=VendorAutolinkScanResponse)
async def scan_vendor_autolink(
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> VendorAutolinkScanResponse:
    """Propose vendor parents for unparented products via deterministic prefix
    match. Multiple matches → prefer the longest vendor name (most specific:
    'Palo Alto Networks' beats 'Palo Alto').
    """
    await db.execute(
        EntityMaintenanceLog.__table__.delete().where(
            EntityMaintenanceLog.action == "vendor_autolink",
            EntityMaintenanceLog.applied.is_(False),
        )
    )

    # Build a sorted list of (lowercased_token, vendor_id, vendor_name, kind)
    # for every vendor name + alias. Sort longest-first so longest match wins
    # when multiple prefixes match the same product.
    vendor_rows = (await db.execute(select(Vendor.id, Vendor.name, Vendor.aliases))).all()
    tokens: list[tuple[str, uuid.UUID, str, str]] = []
    for vid, vname, valiases in vendor_rows:
        if vname:
            tokens.append((vname.lower(), vid, vname, "name"))
        for alias in valiases or []:
            if isinstance(alias, str) and alias.strip():
                tokens.append((alias.strip().lower(), vid, vname, "alias"))
    tokens.sort(key=lambda t: -len(t[0]))

    by_match_kind: dict[str, int] = defaultdict(int)
    proposed = 0

    products_q = (await db.execute(select(Product.id, Product.name).where(Product.vendor_id.is_(None)))).all()
    for pid, pname in products_q:
        if not pname or len(pname) < 3:
            continue
        pl = pname.lower()
        match: tuple[str, uuid.UUID, str, str] | None = None
        for token in tokens:
            tok = token[0]
            # Require a separator after the prefix so "Microsoft" doesn't
            # falsely claim "Microsoftia" (unlikely but cheap to guard).
            if pl.startswith(tok + " "):
                match = token
                break
        if not match:
            continue
        _, vid, vname, kind = match
        db.add(
            EntityMaintenanceLog(
                entity_type="product",
                entity_id=pid,
                action="vendor_autolink",
                mode="shadow",
                before={"entity": {"id": str(pid), "name": pname}},
                after={
                    "proposed_vendor_id": str(vid),
                    "proposed_vendor_name": vname,
                    "match_kind": kind,
                },
                reasoning=(
                    f"Product name '{pname}' starts with vendor {'alias' if kind == 'alias' else 'name'} '{vname}'."
                )[:2000],
                applied=False,
            )
        )
        by_match_kind[kind] += 1
        proposed += 1

    await db.flush()
    return VendorAutolinkScanResponse(
        products_scanned=len(products_q),
        proposed=proposed,
        by_match_kind=dict(by_match_kind),
    )


class ApplyVendorAutolinkResponse(BaseModel):
    log_id: uuid.UUID
    applied: bool
    skipped: bool
    product_id: uuid.UUID | None
    vendor_id: uuid.UUID | None


@router.post(
    "/admin/hygiene/vendor-autolink/{log_id}/apply",
    response_model=ApplyVendorAutolinkResponse,
)
async def apply_vendor_autolink(
    log_id: uuid.UUID = Path(..., description="EntityMaintenanceLog row UUID of the vendor_autolink proposal"),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> ApplyVendorAutolinkResponse:
    """Set product.vendor_id to the proposed vendor.

    Idempotent: if the product is gone, the vendor is gone, or vendor_id is
    already set, we mark applied and return skipped=true.
    """
    row = (await db.execute(select(EntityMaintenanceLog).where(EntityMaintenanceLog.id == log_id))).scalar_one_or_none()
    if not row:
        raise AppError(code="not_found", message="proposal not found", status_code=404)
    if row.action != "vendor_autolink":
        raise AppError(
            code="invalid",
            message=f"can only apply vendor_autolink rows (got {row.action})",
            status_code=400,
        )
    if row.applied:
        raise AppError(code="invalid", message="already applied", status_code=400)

    after = row.after or {}
    raw_vid = after.get("proposed_vendor_id")
    if not raw_vid:
        raise AppError(code="invalid", message="proposal missing proposed_vendor_id", status_code=400)
    try:
        proposed_vid = uuid.UUID(str(raw_vid))
    except (ValueError, TypeError):
        raise AppError(code="invalid", message="bad proposed_vendor_id", status_code=400) from None

    product = (await db.execute(select(Product).where(Product.id == row.entity_id))).scalar_one_or_none()
    if product is None:
        row.applied = True
        db.add(row)
        await db.flush()
        return ApplyVendorAutolinkResponse(
            log_id=row.id,
            applied=True,
            skipped=True,
            product_id=row.entity_id,
            vendor_id=proposed_vid,
        )

    vendor = (await db.execute(select(Vendor.id).where(Vendor.id == proposed_vid))).scalar_one_or_none()
    if vendor is None:
        row.applied = True
        db.add(row)
        await db.flush()
        return ApplyVendorAutolinkResponse(
            log_id=row.id,
            applied=True,
            skipped=True,
            product_id=product.id,
            vendor_id=None,
        )

    if product.vendor_id == proposed_vid:
        row.applied = True
        db.add(row)
        await db.flush()
        return ApplyVendorAutolinkResponse(
            log_id=row.id,
            applied=True,
            skipped=True,
            product_id=product.id,
            vendor_id=proposed_vid,
        )
    if product.vendor_id is not None and product.vendor_id != proposed_vid:
        # Race: someone set vendor_id manually (or via another autolink) between
        # scan + apply. Refuse to clobber — the operator should rescan.
        raise AppError(
            code="conflict",
            message=(
                "Product was assigned to a different vendor after the proposal "
                "was generated. Dismiss this row and rescan."
            ),
            status_code=409,
        )

    product.vendor_id = proposed_vid
    row.applied = True
    db.add(row)
    db.add(
        EntityMaintenanceLog(
            entity_type="product",
            entity_id=product.id,
            action="vendor_autolink",
            mode="apply",
            before={
                "entity": {
                    "id": str(product.id),
                    "name": product.name,
                    "vendor_id": None,
                }
            },
            after={
                "proposed_vendor_id": str(proposed_vid),
                "proposed_vendor_name": after.get("proposed_vendor_name"),
                "match_kind": after.get("match_kind"),
                "promoted_from": str(row.id),
            },
            reasoning=f"Promoted from vendor_autolink proposal {row.id}.",
            applied=True,
        )
    )
    await db.flush()
    return ApplyVendorAutolinkResponse(
        log_id=row.id,
        applied=True,
        skipped=False,
        product_id=product.id,
        vendor_id=proposed_vid,
    )


# ---------------------------------------------------------------------------
# Deterministic TTP / CVE id hygiene
# ---------------------------------------------------------------------------
#
# Catches malformed identifiers and withdrawn CVEs without contacting the
# upstream sources at scan time — we lean on cached NVD payloads for CVE
# status and on a simple regex for ID shape.

# Canonical MITRE technique id: T + 4-digit main + optional .3-digit sub.
# ".000" is not a real sub-technique (it's a zero-padded parent), so it's malformed.
_TTP_ID_RE = re.compile(r"^T(\d{4})(?:\.(?!000)(\d{3}))?$")
# Canonical CVE id: CVE-YYYY-N{4,}.
_CVE_ID_RE = re.compile(r"^CVE-(\d{4})-(\d{4,})$")
# NVD vulnStatus values that mean the CVE was withdrawn or never published.
_CVE_WITHDRAWN_STATUSES = {"rejected", "reject", "rejected by cna", "withdrawn"}


def _canonicalize_technique_id(raw: str | None) -> str | None:
    """Best-effort canonicalization. Returns the canonical form if it can be
    derived deterministically, otherwise None (so the operator decides).
    """
    if not raw:
        return None
    s = raw.strip().upper().replace(" ", "")
    if not s.startswith("T"):
        return None
    rest = s[1:]
    main, _, sub = rest.partition(".")
    if not main.isdigit():
        return None
    main_int = int(main)
    if not (1 <= main_int <= 9999):
        return None
    if sub == "":
        return f"T{main_int:04d}"
    if not sub.isdigit():
        return None
    sub_int = int(sub)
    if sub_int == 0:
        # ".000" (or ".0") is a zero-padded parent reference, not a sub-technique.
        return f"T{main_int:04d}"
    if not (1 <= sub_int <= 999):
        return None
    return f"T{main_int:04d}.{sub_int:03d}"


def _canonicalize_cve_id(raw: str | None) -> str | None:
    if not raw:
        return None
    s = raw.strip().upper().replace(" ", "")
    # Common malformations: lowercase prefix, missing prefix, extra dashes.
    if s.startswith("CVE"):
        # Accept "CVE2024-1234", "CVE 2024 1234" already normalized.
        if not s.startswith("CVE-"):
            s = "CVE-" + s[3:]
    elif re.match(r"^\d{4}-\d+$", s):
        s = "CVE-" + s
    m = re.match(r"^CVE-(\d{4})-(\d+)$", s)
    if not m:
        return None
    year = int(m.group(1))
    if not (1999 <= year <= 2100):
        return None
    seq = m.group(2)
    if len(seq) < 4:
        seq = seq.zfill(4)
    return f"CVE-{year:04d}-{seq}"


class IdHygieneScanResponse(BaseModel):
    ttps_scanned: int
    cves_scanned: int
    ttp_malformed: int
    cve_malformed: int
    cve_withdrawn: int


@router.post("/admin/hygiene/scan-id-hygiene", response_model=IdHygieneScanResponse)
async def scan_id_hygiene(
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> IdHygieneScanResponse:
    """Scan TTPs and CVEs for malformed identifiers + withdrawn CVEs.

    Pushes every filter into SQL — at ~38K CVEs with multi-KB nvd_data blobs,
    pulling everything into Python overflows the proxy timeout (~60s). We
    only ever materialize the small set of bad rows.

    Clears prior unapplied proposals first so reruns reflect current state.
    """
    await db.execute(
        EntityMaintenanceLog.__table__.delete().where(
            EntityMaintenanceLog.action.in_(["ttp_malformed_id", "cve_malformed_id", "cve_withdrawn"]),
            EntityMaintenanceLog.applied.is_(False),
        )
    )

    # ── TTPs ──
    ttps_scanned = int((await db.execute(select(func.count()).select_from(TTP))).scalar_one())
    # Pull only the bad ones. The canonical-form regex lives in `_TTP_ID_RE`
    # (`^T\d{4}(\.(?!000)\d{3})?$` — ".000" is a zero-padded parent, so it's
    # malformed). Postgres regex is anchored by default with `~` and its ARE
    # flavor supports the `(?!...)` lookahead.
    malformed_ttp_rows = (
        await db.execute(
            select(TTP.id, TTP.technique_id, TTP.technique_name).where(
                or_(
                    TTP.technique_id.is_(None),
                    ~TTP.technique_id.op("~")(r"^T\d{4}(\.(?!000)\d{3})?$"),
                )
            )
        )
    ).all()
    # Build the canonical-id set from the GOOD rows so we know which fixes
    # would collide. Pull only the id column to keep this cheap.
    canonical_ttps: set[str] = set(
        (await db.execute(select(TTP.technique_id).where(TTP.technique_id.op("~")(r"^T\d{4}(\.(?!000)\d{3})?$"))))
        .scalars()
        .all()
    )
    ttp_malformed = 0
    for tid, raw_id, tname in malformed_ttp_rows:
        proposed = _canonicalize_technique_id(raw_id)
        if proposed and proposed in canonical_ttps:
            proposed = None
        kind = "subtechnique_short_digits" if "." in (raw_id or "") else "malformed_main"
        db.add(
            EntityMaintenanceLog(
                entity_type="ttp",
                entity_id=tid,
                action="ttp_malformed_id",
                mode="shadow",
                before={"entity": {"id": str(tid), "technique_id": raw_id, "name": tname}},
                after={
                    "current_id": raw_id,
                    "proposed_id": proposed,
                    "kind": kind,
                },
                reasoning=(
                    f"Technique id '{raw_id}' doesn't match T{{4}}[.{{3}}] form."
                    + (f" Canonical: {proposed}." if proposed else " No safe canonical form.")
                )[:2000],
                applied=False,
            )
        )
        ttp_malformed += 1

    # ── CVEs ──
    cves_scanned = int((await db.execute(select(func.count()).select_from(CVE))).scalar_one())

    # Malformed CVE ids — same SQL-side regex pattern. Cheap to filter at the DB.
    malformed_cve_rows = (
        await db.execute(
            select(CVE.id, CVE.cve_id).where(
                or_(
                    CVE.cve_id.is_(None),
                    ~CVE.cve_id.op("~")(r"^CVE-\d{4}-\d{4,}$"),
                )
            )
        )
    ).all()
    canonical_cves: set[str] = set(
        (await db.execute(select(CVE.cve_id).where(CVE.cve_id.op("~")(r"^CVE-\d{4}-\d{4,}$")))).scalars().all()
    )
    cve_malformed = 0
    for cid, raw_cve in malformed_cve_rows:
        proposed = _canonicalize_cve_id(raw_cve)
        if proposed and proposed in canonical_cves:
            proposed = None
        db.add(
            EntityMaintenanceLog(
                entity_type="cve",
                entity_id=cid,
                action="cve_malformed_id",
                mode="shadow",
                before={"entity": {"id": str(cid), "cve_id": raw_cve}},
                after={
                    "current_id": raw_cve,
                    "proposed_id": proposed,
                },
                reasoning=(
                    f"CVE id '{raw_cve}' doesn't match CVE-YYYY-NNNN+ form."
                    + (f" Canonical: {proposed}." if proposed else " No safe canonical form.")
                )[:2000],
                applied=False,
            )
        )
        cve_malformed += 1

    # Withdrawn / rejected CVEs — extract the status via jsonb_extract_path_text
    # so we never pull the full payload. We check both the flattened shape
    # (vulnStatus at top of cve_data, current writer behavior) and the wrapped
    # shape (vulnerabilities[0].cve.vulnStatus, legacy storage).
    # Using the function form (not `->>` / `#>>` operators) avoids the
    # asyncpg/SQLAlchemy bind-type mismatch where the path string would be
    # sent as varchar but `#>>` requires text[].
    direct_status = func.jsonb_extract_path_text(CVE.nvd_data, "vulnStatus")
    wrapped_status = func.jsonb_extract_path_text(CVE.nvd_data, "vulnerabilities", "0", "cve", "vulnStatus")
    withdrawn_rows = (
        await db.execute(
            select(CVE.id, CVE.cve_id, direct_status, wrapped_status).where(
                or_(
                    func.lower(direct_status).in_(list(_CVE_WITHDRAWN_STATUSES)),
                    func.lower(wrapped_status).in_(list(_CVE_WITHDRAWN_STATUSES)),
                )
            )
        )
    ).all()
    cve_withdrawn = 0
    for cid, raw_cve, d_status, w_status in withdrawn_rows:
        status = d_status or w_status
        db.add(
            EntityMaintenanceLog(
                entity_type="cve",
                entity_id=cid,
                action="cve_withdrawn",
                mode="shadow",
                before={"entity": {"id": str(cid), "cve_id": raw_cve}},
                after={
                    "vuln_status": status,
                    "reason": "NVD vulnStatus marks this CVE as withdrawn or rejected.",
                },
                reasoning=(f"Cached NVD payload reports vulnStatus={status!r}.")[:2000],
                applied=False,
            )
        )
        cve_withdrawn += 1

    await db.flush()
    return IdHygieneScanResponse(
        ttps_scanned=ttps_scanned,
        cves_scanned=cves_scanned,
        ttp_malformed=ttp_malformed,
        cve_malformed=cve_malformed,
        cve_withdrawn=cve_withdrawn,
    )


def _extract_nvd_vuln_status(nvd_data: Any) -> str | None:
    """Pull the vulnStatus out of a cached NVD payload, tolerating either the
    raw API shape ({vulnerabilities:[{cve:{vulnStatus:...}}]}) or a flattened
    {vulnStatus:...} shape we've stored before.
    """
    if not isinstance(nvd_data, dict) or not nvd_data:
        return None
    direct = nvd_data.get("vulnStatus")
    if isinstance(direct, str):
        return direct
    vulns = nvd_data.get("vulnerabilities")
    if isinstance(vulns, list) and vulns:
        first = vulns[0]
        if isinstance(first, dict):
            cve_obj = first.get("cve")
            if isinstance(cve_obj, dict):
                status = cve_obj.get("vulnStatus")
                if isinstance(status, str):
                    return status
    return None


class ApplyIdHygieneResponse(BaseModel):
    log_id: uuid.UUID
    applied: bool
    skipped: bool
    action_taken: str | None  # "renamed" | "deleted" | "skipped"
    entity_id: uuid.UUID | None
    new_id: str | None


@router.post(
    "/admin/hygiene/id-hygiene/{log_id}/apply",
    response_model=ApplyIdHygieneResponse,
)
async def apply_id_hygiene(
    log_id: uuid.UUID = Path(..., description="EntityMaintenanceLog row UUID of the TTP/CVE id-hygiene proposal"),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> ApplyIdHygieneResponse:
    """Apply a single TTP/CVE id-hygiene proposal.

    For ttp_malformed_id / cve_malformed_id: rename the entity's id column
    to the proposed canonical form. Refuses if a colliding row appeared
    after the scan (caller should rescan).

    For cve_withdrawn: delete the CVE entity. Cascade drops entry_cves.
    """
    row = (await db.execute(select(EntityMaintenanceLog).where(EntityMaintenanceLog.id == log_id))).scalar_one_or_none()
    if not row:
        raise AppError(code="not_found", message="proposal not found", status_code=404)
    if row.action not in ("ttp_malformed_id", "cve_malformed_id", "cve_withdrawn"):
        raise AppError(
            code="invalid",
            message=f"can only apply id-hygiene rows (got {row.action})",
            status_code=400,
        )
    if row.applied:
        raise AppError(code="invalid", message="already applied", status_code=400)

    after = row.after or {}

    if row.action == "ttp_malformed_id":
        proposed = after.get("proposed_id")
        if not proposed:
            raise AppError(
                code="invalid",
                message="no canonical form available; dismiss and edit manually",
                status_code=400,
            )
        ttp = (await db.execute(select(TTP).where(TTP.id == row.entity_id))).scalar_one_or_none()
        if ttp is None:
            row.applied = True
            db.add(row)
            await db.flush()
            return ApplyIdHygieneResponse(
                log_id=row.id,
                applied=True,
                skipped=True,
                action_taken="skipped",
                entity_id=row.entity_id,
                new_id=proposed,
            )
        collision = (
            await db.execute(select(TTP.id).where(TTP.technique_id == proposed, TTP.id != ttp.id))
        ).scalar_one_or_none()
        if collision is not None:
            raise AppError(
                code="conflict",
                message=f"another TTP already uses {proposed} — merge required",
                status_code=409,
            )
        before_id = ttp.technique_id
        ttp.technique_id = proposed
        row.applied = True
        db.add(row)
        db.add(
            EntityMaintenanceLog(
                entity_type="ttp",
                entity_id=ttp.id,
                action="ttp_malformed_id",
                mode="apply",
                before={"entity": {"id": str(ttp.id), "technique_id": before_id}},
                after={"current_id": before_id, "new_id": proposed, "promoted_from": str(row.id)},
                reasoning=f"Promoted from ttp_malformed_id proposal {row.id}.",
                applied=True,
            )
        )
        await db.flush()
        return ApplyIdHygieneResponse(
            log_id=row.id,
            applied=True,
            skipped=False,
            action_taken="renamed",
            entity_id=ttp.id,
            new_id=proposed,
        )

    if row.action == "cve_malformed_id":
        proposed = after.get("proposed_id")
        if not proposed:
            raise AppError(
                code="invalid",
                message="no canonical form available; dismiss and edit manually",
                status_code=400,
            )
        cve = (await db.execute(select(CVE).where(CVE.id == row.entity_id))).scalar_one_or_none()
        if cve is None:
            row.applied = True
            db.add(row)
            await db.flush()
            return ApplyIdHygieneResponse(
                log_id=row.id,
                applied=True,
                skipped=True,
                action_taken="skipped",
                entity_id=row.entity_id,
                new_id=proposed,
            )
        collision = (
            await db.execute(select(CVE.id).where(CVE.cve_id == proposed, CVE.id != cve.id))
        ).scalar_one_or_none()
        if collision is not None:
            raise AppError(
                code="conflict",
                message=f"another CVE already uses {proposed} — merge required",
                status_code=409,
            )
        before_id = cve.cve_id
        cve.cve_id = proposed
        row.applied = True
        db.add(row)
        db.add(
            EntityMaintenanceLog(
                entity_type="cve",
                entity_id=cve.id,
                action="cve_malformed_id",
                mode="apply",
                before={"entity": {"id": str(cve.id), "cve_id": before_id}},
                after={"current_id": before_id, "new_id": proposed, "promoted_from": str(row.id)},
                reasoning=f"Promoted from cve_malformed_id proposal {row.id}.",
                applied=True,
            )
        )
        await db.flush()
        return ApplyIdHygieneResponse(
            log_id=row.id,
            applied=True,
            skipped=False,
            action_taken="renamed",
            entity_id=cve.id,
            new_id=proposed,
        )

    # row.action == "cve_withdrawn"
    cve = (await db.execute(select(CVE).where(CVE.id == row.entity_id))).scalar_one_or_none()
    if cve is None:
        row.applied = True
        db.add(row)
        await db.flush()
        return ApplyIdHygieneResponse(
            log_id=row.id,
            applied=True,
            skipped=True,
            action_taken="skipped",
            entity_id=row.entity_id,
            new_id=None,
        )
    snapshot = {
        "id": str(cve.id),
        "cve_id": cve.cve_id,
        "vuln_status": after.get("vuln_status"),
    }
    await db.delete(cve)
    row.applied = True
    db.add(row)
    db.add(
        EntityMaintenanceLog(
            entity_type="cve",
            entity_id=None,
            action="cve_withdrawn",
            mode="apply",
            before={"entity": snapshot},
            after={"deleted": True, "promoted_from": str(row.id)},
            reasoning=f"Promoted from cve_withdrawn proposal {row.id}; entity removed.",
            applied=True,
        )
    )
    await db.flush()
    return ApplyIdHygieneResponse(
        log_id=row.id,
        applied=True,
        skipped=False,
        action_taken="deleted",
        entity_id=None,
        new_id=None,
    )


# ---------------------------------------------------------------------------
# Dismiss a single feed row (delete advisory / shadow proposal)
# ---------------------------------------------------------------------------


class AdjudicationRowResult(BaseModel):
    log_id: uuid.UUID
    applied: bool = False
    restored: bool = False
    reason: str | None = None
    detail: dict = Field(default_factory=dict)


async def _adjudication_row(db: AsyncSession, log_id: uuid.UUID) -> EntityMaintenanceLog:
    row = (await db.execute(select(EntityMaintenanceLog).where(EntityMaintenanceLog.id == log_id))).scalar_one_or_none()
    if row is None or row.action not in ADJUDICATION_ACTIONS:
        raise AppError(code="not_found", message="adjudication proposal not found", status_code=404)
    return row


@router.post("/admin/hygiene/adjudication/{log_id}/apply", response_model=AdjudicationRowResult)
async def apply_adjudication_proposal(
    log_id: uuid.UUID = Path(..., description="entity_maintenance_log row id of an adjudication_* proposal"),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> AdjudicationRowResult:
    """Apply one proposal the adjudicate stage filed in shadow mode: unlink,
    veto (delete when nothing else holds the entity), merge, demote, drop.
    Same code path apply mode uses at ingest; the row becomes the undo record."""
    from app.services.entry_adjudication import apply_adjudication_row

    row = await _adjudication_row(db, log_id)
    outcome = await apply_adjudication_row(db, row)
    await db.flush()
    return AdjudicationRowResult(
        log_id=row.id,
        applied=bool(outcome.get("applied")),
        reason=outcome.get("reason"),
        detail={k: v for k, v in outcome.items() if k not in ("applied", "reason")},
    )


@router.post("/admin/hygiene/adjudication/{log_id}/restore", response_model=AdjudicationRowResult)
async def restore_adjudication_proposal(
    log_id: uuid.UUID = Path(..., description="entity_maintenance_log row id of an applied adjudication_* change"),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> AdjudicationRowResult:
    """Undo an applied adjudication change from its snapshots: re-link, re-create
    a vetoed entity, restore an edge's confidence, put an observable back."""
    from app.services.entry_adjudication import restore_adjudication_row

    row = await _adjudication_row(db, log_id)
    outcome = await restore_adjudication_row(db, row)
    await db.flush()
    return AdjudicationRowResult(
        log_id=row.id,
        restored=bool(outcome.get("restored")),
        reason=outcome.get("reason"),
        detail={k: v for k, v in outcome.items() if k not in ("restored", "reason")},
    )


class LinkLogResult(BaseModel):
    log_id: uuid.UUID
    restored: bool = False
    applied: bool = False
    already_removed: bool = False
    message: str | None = None


@router.post("/admin/hygiene/link-log/{log_id}/restore", response_model=LinkLogResult)
async def restore_removed_link(
    log_id: uuid.UUID = Path(..., description="entity_link_validation_log row id of a 'removed' action to undo"),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> LinkLogResult:
    """Re-create a junction row from a `removed` log row's snapshot (and the
    entity's article_count). The undo for a link the adjudicate stage removed."""
    from app.intelligence.link_validation_apply import restore_from_log

    ok, message = await restore_from_log(db, log_id)
    if not ok:
        raise AppError(code="restore_failed", message=message, status_code=400)
    await db.flush()
    return LinkLogResult(log_id=log_id, restored=True, message=message)


@router.post("/admin/hygiene/link-log/{log_id}/apply-removal", response_model=LinkLogResult)
async def apply_proposed_link_removal(
    log_id: uuid.UUID = Path(..., description="entity_link_validation_log row id of a 'shadow_remove' proposal"),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> LinkLogResult:
    """Promote a `shadow_remove` proposal into the actual junction deletion.
    Writes a `removed` row (the proposal stays as history) and decrements the
    entity's article_count. Idempotent when the junction is already gone."""
    row = (
        await db.execute(select(EntityLinkValidationLog).where(EntityLinkValidationLog.id == log_id))
    ).scalar_one_or_none()
    if not row:
        raise AppError(code="not_found", message="proposal not found", status_code=404)
    already_removed = await _apply_link_removal_row(db, row)
    return LinkLogResult(log_id=log_id, applied=True, already_removed=already_removed)


async def _apply_link_removal_row(db: AsyncSession, row: EntityLinkValidationLog) -> bool:
    """Promote one shadow_remove row into the junction deletion (+ `removed`
    audit row). Returns True when the junction was already gone."""
    from sqlalchemy import update as sql_update

    from app.intelligence.link_validation_apply import ENTITY_TYPES

    if row.action != "shadow_remove":
        raise AppError(code="invalid", message=f"can only apply shadow_remove rows (got {row.action})", status_code=400)
    spec = ENTITY_TYPES.get(row.entity_type)
    if not spec:
        raise AppError(code="invalid", message=f"unsupported entity_type: {row.entity_type}", status_code=400)
    jmodel, emodel, fk_attr = spec
    junction = (
        await db.execute(
            select(jmodel).where(jmodel.entry_id == row.entry_id, getattr(jmodel, fk_attr) == row.entity_id)
        )
    ).scalar_one_or_none()
    if junction is None:
        db.add(
            EntityLinkValidationLog(
                entry_id=row.entry_id,
                entity_type=row.entity_type,
                entity_id=row.entity_id,
                entity_name_snapshot=row.entity_name_snapshot,
                action="removed",
                reason="Promoted from proposal; junction was already absent.",
                ai_result_id=row.ai_result_id,
            )
        )
        await db.flush()
        return True
    db.add(
        EntityLinkValidationLog(
            entry_id=row.entry_id,
            entity_type=row.entity_type,
            entity_id=row.entity_id,
            entity_name_snapshot=row.entity_name_snapshot,
            action="removed",
            reason=f"Promoted from proposal {row.id}: " + (row.reason or "")[:400],
            original_source=junction.source,
            original_confidence=junction.confidence,
            original_matched_names=list(junction.matched_names or []),
            original_paragraph_indices=list(junction.paragraph_indices or []),
            original_extracted_at=junction.extracted_at,
            ai_result_id=row.ai_result_id,
        )
    )
    await db.delete(junction)
    await db.execute(
        sql_update(emodel)
        .where(emodel.id == row.entity_id)
        .values(article_count=func.greatest(emodel.article_count - 1, 0))
    )
    await db.flush()
    return False


@router.delete("/admin/hygiene/feed/{source}/{row_id}", status_code=204)
async def dismiss_feed_row(
    source: str = Path(..., description="Log table the row lives in: link_validator or entity_maintenance"),
    row_id: uuid.UUID = Path(..., description="Log row UUID"),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Hard-delete a single hygiene row. Used to clear stale advisories /
    shadow proposals that the operator decides aren't worth applying.
    """
    if source == "link_validator":
        row = (
            await db.execute(select(EntityLinkValidationLog).where(EntityLinkValidationLog.id == row_id))
        ).scalar_one_or_none()
        if not row:
            raise AppError(code="not_found", message="advisory not found", status_code=404)
        await db.delete(row)
    elif source == "entity_maintenance":
        row = (
            await db.execute(select(EntityMaintenanceLog).where(EntityMaintenanceLog.id == row_id))
        ).scalar_one_or_none()
        if not row:
            raise AppError(code="not_found", message="log row not found", status_code=404)
        await db.delete(row)
    else:
        raise AppError(code="invalid", message=f"unknown source: {source}", status_code=400)
    await db.flush()


class DismissProposalsRequest(BaseModel):
    action: str | None = Field(
        default=None,
        description="Dismiss only these proposal types (single code or comma-separated list); "
        "null clears every pending type.",
    )
    source: str | None = Field(default=None, description="'link_validator' | 'entity_maintenance' | null (both).")
    origin: str | None = Field(
        default=None,
        description="'adjudicator' = only proposals the adjudicate stage filed; 'legacy' = everything else; "
        "omit for both",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {"action": "needs_reclassification", "source": "link_validator", "origin": "legacy"}
        }
    )


class DismissProposalsResponse(BaseModel):
    dismissed: int


class ApplyAdjudicationAllRequest(BaseModel):
    """Scope for the bulk Apply of the adjudicate stage's pending proposals."""

    action: str | None = Field(
        default=None,
        description="Only this proposal kind (an adjudication_* action code or shadow_remove); omit for all",
    )
    limit: int = Field(default=200, ge=1, le=1000, description="Maximum proposals to apply in one call")


class ApplyAdjudicationAllResponse(BaseModel):
    applied: int
    skipped: int
    errors: list[dict] = Field(default_factory=list)


@router.post("/admin/hygiene/dismiss-proposals", response_model=DismissProposalsResponse)
async def dismiss_proposals(
    body: DismissProposalsRequest,
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> DismissProposalsResponse:
    """Bulk-discard PENDING proposals without applying them — the "clear" that
    the per-row Dismiss and "Apply + clear rejected" never offered on their own.

    Only ever deletes proposals that haven't run: link-validator advisories
    (shadow_remove / needs_reclassification) and unapplied entity-maintenance
    rows. Applied history is never touched. Scope with action / source / origin,
    or pass an empty body to clear the whole pending queue.
    """
    dismissed = 0
    adjudicator_results = select(AIResult.id).where(
        AIResult.task_id == select(AITask.id).where(AITask.name == ADJUDICATION_TASK_NAME).scalar_subquery()
    )

    # Only actions that surface a per-row Dismiss can be bulk-dismissed — mirrors
    # _row_actions_maint so bulk clears exactly what the UI lets you clear one by
    # one (never no_op / ai_enrich_* / applied-history rows).
    dismissable_maint = _MAINTENANCE_PROPOSAL_ACTIONS | {"orphan_prune"}

    actions = _parse_action_list(body.action)
    link_actions = actions & {"shadow_remove", "needs_reclassification"}
    maint_actions = actions & dismissable_maint
    link_eligible = body.source in (None, "link_validator") and (not actions or bool(link_actions))
    maint_eligible = body.source in (None, "entity_maintenance") and (not actions or bool(maint_actions))

    if link_eligible:
        q = delete(EntityLinkValidationLog).where(
            EntityLinkValidationLog.action.in_(["shadow_remove", "needs_reclassification"])
        )
        if link_actions:
            q = q.where(EntityLinkValidationLog.action.in_(sorted(link_actions)))
        if body.origin == "adjudicator":
            q = q.where(EntityLinkValidationLog.ai_result_id.in_(adjudicator_results))
        elif body.origin == "legacy":
            q = q.where(
                or_(
                    EntityLinkValidationLog.ai_result_id.is_(None),
                    ~EntityLinkValidationLog.ai_result_id.in_(adjudicator_results),
                )
            )
        dismissed += (await db.execute(q)).rowcount or 0

    if maint_eligible:
        # Unapplied proposal rows only; applied history and informational logs stay.
        q = delete(EntityMaintenanceLog).where(
            EntityMaintenanceLog.applied.is_(False),
            EntityMaintenanceLog.action.in_(sorted(dismissable_maint)),
        )
        if maint_actions:
            q = q.where(EntityMaintenanceLog.action.in_(sorted(maint_actions)))
        if body.origin == "adjudicator":
            q = q.where(EntityMaintenanceLog.action.in_(sorted(ADJUDICATION_ACTIONS)))
        elif body.origin == "legacy":
            q = q.where(EntityMaintenanceLog.action.notin_(sorted(ADJUDICATION_ACTIONS)))
        dismissed += (await db.execute(q)).rowcount or 0

    await db.flush()
    return DismissProposalsResponse(dismissed=dismissed)


@router.post("/admin/hygiene/adjudication/apply-all", response_model=ApplyAdjudicationAllResponse)
async def apply_adjudication_all(
    body: ApplyAdjudicationAllRequest = Body(default_factory=ApplyAdjudicationAllRequest),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> ApplyAdjudicationAllResponse:
    """Apply every pending proposal the adjudicate stage filed, oldest first:
    the entity-maintenance rows (unlink, reclassify, veto, merge, demote,
    drop) through the same code the per-row Apply uses, and its link-removal
    proposals through the link log's apply-removal. Assessment flags are
    informational and skipped. Each row is its own savepoint, so one failure
    is reported and the rest still apply."""
    from app.services.entry_adjudication import apply_adjudication_row

    adjudicator_results = select(AIResult.id).where(
        AIResult.task_id == select(AITask.id).where(AITask.name == ADJUDICATION_TASK_NAME).scalar_subquery()
    )
    applied = skipped = 0
    errors: list[dict] = []
    budget = body.limit

    maint_actions = sorted(ADJUDICATION_ACTIONS - {ACTION_ASSESSMENT})
    if body.action and body.action != "shadow_remove":
        if body.action not in ADJUDICATION_ACTIONS or body.action == ACTION_ASSESSMENT:
            raise AppError(
                code="invalid", message=f"not an applyable adjudication action: {body.action}", status_code=400
            )
        maint_actions = [body.action]
    if body.action in (None, *maint_actions):
        rows = (
            (
                await db.execute(
                    select(EntityMaintenanceLog)
                    .where(EntityMaintenanceLog.action.in_(maint_actions), EntityMaintenanceLog.applied.is_(False))
                    .order_by(EntityMaintenanceLog.created_at.asc())
                    .limit(budget)
                )
            )
            .scalars()
            .all()
        )
        for row in rows:
            try:
                async with db.begin_nested():
                    outcome = await apply_adjudication_row(db, row)
            except Exception as exc:  # one bad row must not sink the batch
                errors.append({"log_id": str(row.id), "action": row.action, "error": str(exc)[:300]})
                continue
            if outcome.get("applied"):
                applied += 1
            else:
                skipped += 1
        budget -= len(rows)

    if budget > 0 and body.action in (None, "shadow_remove"):
        link_rows = (
            (
                await db.execute(
                    select(EntityLinkValidationLog)
                    .where(
                        EntityLinkValidationLog.action == "shadow_remove",
                        EntityLinkValidationLog.ai_result_id.in_(adjudicator_results),
                    )
                    .order_by(EntityLinkValidationLog.created_at.asc())
                    .limit(budget)
                )
            )
            .scalars()
            .all()
        )
        for row in link_rows:
            try:
                async with db.begin_nested():
                    await _apply_link_removal_row(db, row)
            except Exception as exc:
                errors.append({"log_id": str(row.id), "action": row.action, "error": str(exc)[:300]})
                continue
            applied += 1

    await db.flush()
    return ApplyAdjudicationAllResponse(applied=applied, skipped=skipped, errors=errors)
