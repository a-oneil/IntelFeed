"""Unified workbench hygiene API.

Powers the "Entity Hygiene" surface in Settings → Workbench. Aggregates the
existing entity-maintenance / link-validation systems and adds:

  - GET  /api/admin/hygiene/feed            — chronological merge of
         entity_link_validation_log + entity_maintenance_log, normalized
  - GET  /api/admin/hygiene/stats           — combined counters across both
  - GET  /api/admin/hygiene/orphans         — entities with article_count == 0
  - POST /api/admin/hygiene/orphans/prune   — prune (one or all) orphans
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
from sqlalchemy import and_, case, delete, false, func, literal, or_, select, text
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
from app.services.enrichment_gaps import ENRICH_GAP_SPECS
from app.services.entity_merge_review import ACTION_DISTINCT
from app.services.entity_merge_review import ORIGIN as MERGE_REVIEW_ORIGIN
from app.services.entry_adjudication import (
    ACTION_ASSESSMENT,
    ACTION_EDGE_DEMOTE,
    ACTION_IOC_DROP,
    ACTION_MERGE,
    ACTION_RECLASSIFY,
    ACTION_RESTORED,
    ACTION_UNLINK,
    ACTION_VETO,
    ADJUDICATION_ACTIONS,
    ADJUDICATION_PROPOSAL_ACTIONS,
    LEGACY_MAINT_ACTIONS,
    legacy_row_is_orphaned,
)
from app.services.entry_adjudication import TASK_NAME as ADJUDICATION_TASK_NAME
from app.services.proposal_apply import (
    DOMAINS,
    adjudication_scope,
    apply_adjudication_batch,
    apply_link_removal_row,
    count_adjudication_pending,
    count_advisories_pending,
    link_log_actions_for_domain,
    maint_actions_for_domain,
    new_progress,
    proposal_domain,
    read_progress,
    settle_adjudication_outcome,
    write_progress,
)
from app.services.proposal_dismissals import (
    clear_entity_proposals,
    clear_reclassify_proposals,
    dismiss_reclassify,
    entity_alive_clause,
    mark_not_duplicate,
    settle_gone_entity,
)

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
            await settle_gone_entity(db, etype, eid, gone=True)
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
            # Already gone (possibly reclassified by an earlier group in this
            # batch) — clear the now-stale advisories.
            cleared += await clear_reclassify_proposals(db, src_type, src_id)
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
            resp = await perform_reclassify(db, req)
            if mode == "apply":
                # Every proposal about the entity, not just these rows: the
                # other suggested types and the other log are moot now.
                cleared += await clear_reclassify_proposals(db, src_type, src_id)
                cleared += await settle_gone_entity(db, src_type, src_id, successor=(tgt_type, resp.target_id))
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
# Bulk gap enrichment
# ---------------------------------------------------------------------------


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
    """Dispatch Claude Code with web search to research and fill the requested
    field for the top-N entities missing it.

    Runs as a single batch (capped at body.limit, ≤50 by the request schema)
    on the `ai` queue. The worker writes high-confidence values
    directly into the entity column and records source URLs in the
    enrichment_results audit table (source_type='ai_research').
    """
    spec = ENRICH_GAP_SPECS.get((body.entity_type, body.field))
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
    # the article in hand), "merge_review" (the catalogue-wide duplicate
    # review, two profiles side by side) or "scan" (the on-demand scans and
    # analysts).
    origin: str | None = None
    # What applying it changes: links | entities | relationships (the Review
    # tab's Domain facet; both logs feed that one queue; observables are entities).
    domain: str = "entities"
    # The article text around the match (the paragraph the link came from, or
    # the first mention), so a reviewer needn't open the article. At most
    # FEED_CONTEXT_MAX characters; None when the row has no article or no match.
    context: str | None = None


class FeedResponse(BaseModel):
    rows: list[FeedRow]
    has_more: bool
    next_offset: int


ORIGIN_ADJUDICATOR = "adjudicator"
ORIGIN_MERGE_REVIEW = "merge_review"
ORIGIN_SCAN = "scan"
# after.kind on the adjudicator's alias_collision rows (its alias trims).
ADJUDICATOR_ALIAS_KIND = "adjudicator"
PROPOSAL_ORIGINS = (ORIGIN_ADJUDICATOR, ORIGIN_MERGE_REVIEW, ORIGIN_SCAN)
_ORIGIN_HELP = (
    "'adjudicator' = rows the post-analysis adjudicate stage filed with the article in hand; "
    "'merge_review' = the catalogue-wide duplicate review; 'scan' = everything else "
    "(on-demand scans, analysts). Omit for all."
)


def _check_origin(origin: str | None) -> str | None:
    if origin is not None and origin not in PROPOSAL_ORIGINS:
        raise AppError(code="invalid", message=f"unknown origin: {origin}", status_code=400)
    return origin


def _maint_origin(action: str, after: dict | None) -> str:
    """Who filed a maintenance-log row. The duplicate review reuses the
    adjudicator's merge action, so its rows are told apart by ``after.origin``."""
    if (after or {}).get("origin") == MERGE_REVIEW_ORIGIN:
        return ORIGIN_MERGE_REVIEW
    # The adjudicator files its alias trims as alias_collision rows, told apart by after.kind.
    if action in ADJUDICATION_ACTIONS or (after or {}).get("kind") == ADJUDICATOR_ALIAS_KIND:
        return ORIGIN_ADJUDICATOR
    return ORIGIN_SCAN


def _maint_origin_clause(origin: str):
    """The origin facet as a maintenance-log predicate."""
    review = EntityMaintenanceLog.after["origin"].astext == MERGE_REVIEW_ORIGIN
    if origin == ORIGIN_MERGE_REVIEW:
        return review
    not_review = EntityMaintenanceLog.after["origin"].astext.is_distinct_from(MERGE_REVIEW_ORIGIN)
    adjudicator = or_(
        EntityMaintenanceLog.action.in_(sorted(ADJUDICATION_ACTIONS)),
        func.coalesce(EntityMaintenanceLog.after["kind"].astext == ADJUDICATOR_ALIAS_KIND, False),
    )
    return and_(adjudicator, not_review) if origin == ORIGIN_ADJUDICATOR else and_(~adjudicator, not_review)


def _link_origin_clause(origin: str, adjudicator_results):
    """The origin facet as a link-log predicate. The duplicate review never
    writes the link log, so that facet matches nothing there."""
    if origin == ORIGIN_MERGE_REVIEW:
        return false()
    filed_by_stage = EntityLinkValidationLog.ai_result_id.in_(adjudicator_results)
    if origin == ORIGIN_ADJUDICATOR:
        return filed_by_stage
    return or_(EntityLinkValidationLog.ai_result_id.is_(None), ~filed_by_stage)


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
    ACTION_DISTINCT,
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
    # Not ACTION_RESTORED: an analyst's undo is history, not a fresh verdict.
    *ADJUDICATION_PROPOSAL_ACTIONS,
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
        if row.action == ACTION_RESTORED:
            return []  # the undo already ran; this row is the audit line
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
    if row.action == ACTION_DISTINCT:
        pair = before.get("pair") if isinstance(before.get("pair"), dict) else {}
        a = (pair.get("a") or {}).get("name") or "?"
        b = after.get("other_name") or (pair.get("b") or {}).get("name") or "?"
        if after.get("verdict") == "unsure":
            return f"Unsure: {a} vs {b} · duplicate review"
        return f"Not duplicates: {a} ≠ {b} · duplicate review"
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
        who = " · duplicate review" if after.get("origin") == MERGE_REVIEW_ORIGIN else ""
        return f"Merge: {name} → {after.get('merge_into') or '?'} ({after.get('target_type') or row.entity_type}){who}"
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
    if row.action == ACTION_RESTORED:
        undid = (before.get("undid") or "").removeprefix("adjudication_") or "change"
        return f"Restored: {name or row.entity_type} ({undid} undone by an analyst)"
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
    if row.action == ACTION_DISTINCT:
        pair = before.get("pair") if isinstance(before.get("pair"), dict) else {}
        for side, role in (("a", "a"), ("b", "b")):
            ent = pair.get(side) if isinstance(pair.get(side), dict) else None
            if ent:
                _add(row.entity_type, ent.get("id"), ent.get("name"), role=role)
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


FEED_CONTEXT_MAX = 320  # characters of article text per feed row
_CONTEXT_WINDOW = 160


def _claim_needles(claim: str) -> list[str]:
    """The entity names in an edge claim: "FIN7 uses AsyncRAT" → FIN7, AsyncRAT
    (runs of words that aren't a lowercase verb)."""
    out: list[str] = []
    cur: list[str] = []
    for tok in claim.split():
        if tok.isalpha() and tok.islower():
            if cur:
                out.append(" ".join(cur))
                cur = []
        else:
            cur.append(tok)
    if cur:
        out.append(" ".join(cur))
    return out


def _context_target(row: FeedRow) -> tuple[uuid.UUID, list[str], list[int]] | None:
    """(entry id, names to find, paragraph indices) for a feed row's snippet."""
    p = row.payload or {}
    needles: list[str] = []
    indices: list[int] = []
    if row.source == "link_validator":
        raw_entry = p.get("entry_id")
        needles += [n for n in p.get("original_matched_names") or [] if isinstance(n, str)]
        indices += [i for i in p.get("original_paragraph_indices") or [] if isinstance(i, int)]
        if row.entity_name:
            needles.append(row.entity_name)
    else:
        before = p.get("before") if isinstance(p.get("before"), dict) else {}
        after = p.get("after") if isinstance(p.get("after"), dict) else {}
        raw_entry = before.get("entry_id")
        junction = before.get("junction") if isinstance(before.get("junction"), dict) else {}
        needles += [n for n in junction.get("matched_names") or [] if isinstance(n, str)]
        indices += [i for i in junction.get("paragraph_indices") or [] if isinstance(i, int)]
        ent = before.get("entity") if isinstance(before.get("entity"), dict) else {}
        for v in (ent.get("name"), after.get("value")):
            if isinstance(v, str):
                needles.append(v)
        if isinstance(before.get("claim"), str):
            needles += _claim_needles(before["claim"])
    needles = [n.strip() for n in needles if n and n.strip()]
    if not raw_entry or not needles:
        return None
    try:
        return uuid.UUID(str(raw_entry)), list(dict.fromkeys(needles)), indices
    except ValueError:
        return None


def _snippet_around(texts: list[str], needles: list[str]) -> str | None:
    """The text around the first needle found, searching ``texts`` in order."""
    for chunk in texts:
        lowered = chunk.lower()
        pos = next((p for p in (lowered.find(n.lower()) for n in needles) if p != -1), -1)
        if pos == -1:
            continue
        start = max(0, pos - _CONTEXT_WINDOW // 2)
        piece = " ".join(chunk[start : pos + _CONTEXT_WINDOW].split())
        if start > 0:
            piece = "…" + piece
        if pos + _CONTEXT_WINDOW < len(chunk):
            piece += "…"
        return piece[:FEED_CONTEXT_MAX]
    return None


async def _attach_context(db: AsyncSession, rows: list[FeedRow]) -> None:
    """Fill each row's ``context`` from its article: the linked paragraph when
    the row records one, else the first mention anywhere in the article."""
    from app.intelligence.autolinker import split_into_paragraphs

    targets = {r.id: t for r in rows if (t := _context_target(r)) is not None}
    if not targets:
        return
    entry_ids = {t[0] for t in targets.values()}
    entries = {
        eid: (title, summary, text)
        for eid, title, summary, text in (
            await db.execute(
                select(Entry.id, Entry.title, Entry.summary, Entry.content_text).where(Entry.id.in_(entry_ids))
            )
        ).all()
    }
    paragraphs: dict[uuid.UUID, dict[int, str]] = {}
    for r in rows:
        t = targets.get(r.id)
        if t is None or t[0] not in entries:
            continue
        entry_id, needles, indices = t
        if entry_id not in paragraphs:
            title, summary, text = entries[entry_id]
            paragraphs[entry_id] = dict(split_into_paragraphs(title or "", summary or "", text or ""))
        pmap = paragraphs[entry_id]
        texts = [pmap[i] for i in indices if i in pmap] + list(pmap.values())
        r.context = _snippet_around(texts, needles)


@router.get("/admin/hygiene/feed", response_model=FeedResponse)
async def hygiene_feed(
    action: str | None = Query(
        None,
        description="Filter by action. Accepts any action from either log source; "
        "comma-separate to match several (e.g. 'ttp_malformed_id,cve_malformed_id').",
    ),
    source: str | None = Query(None, description="'link_validator' | 'entity_maintenance' | null (all)."),
    domain: str | None = Query(
        None,
        description="What applying the proposal changes: 'links' | 'entities' | 'relationships'; null for every "
        "domain. Spans both logs (a link-log reclassify advisory is 'entities'; observables are entities).",
    ),
    mode: str | None = Query(None, description="'shadow' | 'apply' — applies to entity_maintenance rows."),
    pending: bool = Query(
        False,
        description="Only unapplied proposals (skips applied history). Required for the review queue, "
        "since applied resolution logs otherwise flood the newest page.",
    ),
    origin: str | None = Query(None, description=_ORIGIN_HELP),
    orphaned: bool = Query(
        False,
        description="Only pending proposals the retired jobs left that no entry can carry to the adjudicate "
        "stage: link proposals whose entry is gone, and merge-engine / stale-sweep proposals about an entity "
        "that no longer exists or has no creating entry. They are listed for manual disposition, never "
        "auto-dismissed.",
    ),
    since: datetime | None = Query(None, description="Only rows created at or after this timestamp"),
    entity_type: str | None = Query(None, description="Only rows about entities of this type (with entity_id)"),
    entity_id: uuid.UUID | None = Query(None, description="Only rows about this entity (the Review tab's expand)"),
    context: bool = Query(
        False,
        description="Add each row's article snippet around the match (`context`). Reads every row's article, "
        "so ask for it only on small pages (one entity's rows)",
    ),
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
    if not isinstance(domain, str):
        domain = None  # called directly (the curation tool), not through FastAPI
    if not isinstance(entity_type, str):
        entity_type = None
    if not isinstance(entity_id, uuid.UUID):
        entity_id = None
    if not isinstance(origin, str):
        origin = None
    if not isinstance(orphaned, bool):
        orphaned = False
    if not isinstance(context, bool):
        context = True
    if not isinstance(pending, bool):
        pending = False
    if domain is not None and domain not in DOMAINS:
        raise AppError(code="invalid", message=f"unknown domain: {domain}", status_code=400)
    _check_origin(origin)
    actions = _parse_action_list(action)
    link_actions = actions & _LINK_VALIDATOR_ACTIONS
    maint_actions = actions & _MAINTENANCE_ACTIONS
    # The domain facet is a second action filter, per log.
    domain_link_actions = link_log_actions_for_domain(domain)
    domain_maint_actions = maint_actions_for_domain(domain)
    link_eligible = (
        source in (None, "link_validator")
        and (not actions or bool(link_actions))
        and (domain_link_actions is None or bool(domain_link_actions))
    )
    maint_eligible = (
        source in (None, "entity_maintenance")
        and (not actions or bool(maint_actions))
        and (domain_maint_actions is None or bool(domain_maint_actions))
    )

    adjudicator_results = select(AIResult.id).where(
        AIResult.task_id == select(AITask.id).where(AITask.name == ADJUDICATION_TASK_NAME).scalar_subquery()
    )

    link_rows: list[EntityLinkValidationLog] = []
    if link_eligible:
        q = select(EntityLinkValidationLog)
        if domain_link_actions is not None:
            q = q.where(EntityLinkValidationLog.action.in_(sorted(domain_link_actions)))
        if orphaned:
            # A pending scan proposal whose entry is gone: the backfill can
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
        if origin:
            q = q.where(_link_origin_clause(origin, adjudicator_results))
        if pending:
            q = q.where(EntityLinkValidationLog.action.in_(["shadow_remove", "needs_reclassification"]))
            if not orphaned:
                # The Review list drops proposals about a gone entity; so does its count.
                q = q.where(entity_alive_clause(EntityLinkValidationLog))
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
        if entity_type:
            q = q.where(EntityLinkValidationLog.entity_type == entity_type)
        if entity_id:
            q = q.where(EntityLinkValidationLog.entity_id == entity_id)
        q = q.order_by(EntityLinkValidationLog.created_at.desc()).limit(fetch_cap)
        link_rows = list((await db.execute(q)).scalars().all())

    maint_rows: list[EntityMaintenanceLog] = []
    if maint_eligible:
        q = select(EntityMaintenanceLog)
        if domain_maint_actions is not None:
            q = q.where(EntityMaintenanceLog.action.in_(sorted(domain_maint_actions)))
        if origin:
            q = q.where(_maint_origin_clause(origin))
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
            if not orphaned:
                q = q.where(entity_alive_clause(EntityMaintenanceLog))
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
        if entity_type:
            q = q.where(EntityMaintenanceLog.entity_type == entity_type)
        if entity_id:
            q = q.where(EntityMaintenanceLog.entity_id == entity_id)
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
                origin=ORIGIN_ADJUDICATOR if r.ai_result_id in adjudicator_ids else ORIGIN_SCAN,
                domain=proposal_domain("link_validator", r.action),
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
                origin=_maint_origin(r.action, r.after),
                domain=proposal_domain("entity_maintenance", r.action),
            )
        )

    feed.sort(key=lambda f: f.when, reverse=True)
    sliced = feed[offset : offset + limit]
    has_more = len(feed) > offset + limit
    if context:
        await _attach_context(db, sliced)
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
    pending_advisories: int  # entities with a pending reclassify proposal (either log)
    pending_unlink_entities: int = 0  # entities with a pending remove-link proposal (either log)
    name_normalization_proposed: int  # unapplied normalize_name rows
    applied_24h: int  # actions applied across both logs in last 24h
    applied_7d: int
    orphan_count: int
    last_maintenance_run_at: datetime | None
    # Deterministic hygiene scans — each tracks unapplied proposals
    alias_collisions_proposed: int
    vendor_autolinks_proposed: int
    ttp_cve_issues_proposed: int
    # Every pending proposal across both logs, and the same split by what
    # applying it changes (the Review tab's badge and Domain facet counts).
    pending_total: int = 0
    pending_by_domain: dict[str, int] = Field(default_factory=dict)


async def _pending_by_domain(db: AsyncSession) -> dict[str, int]:
    """Unapplied proposals per Review domain, both logs."""
    link_counts = (
        await db.execute(
            select(EntityLinkValidationLog.action, func.count())
            .where(
                EntityLinkValidationLog.action.in_(["shadow_remove", "needs_reclassification"]),
                entity_alive_clause(EntityLinkValidationLog),
            )
            .group_by(EntityLinkValidationLog.action)
        )
    ).all()
    maint_counts = (
        await db.execute(
            select(EntityMaintenanceLog.action, func.count())
            .where(
                EntityMaintenanceLog.applied.is_(False),
                EntityMaintenanceLog.action.in_(sorted(_MAINTENANCE_PROPOSAL_ACTIONS | {"orphan_prune"})),
                entity_alive_clause(EntityMaintenanceLog),
            )
            .group_by(EntityMaintenanceLog.action)
        )
    ).all()
    out = {d: 0 for d in DOMAINS}
    for action, n in link_counts:
        out[proposal_domain("link_validator", action)] += int(n)
    for action, n in maint_counts:
        out[proposal_domain("entity_maintenance", action)] += int(n)
    return out


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
                entity_alive_clause(EntityLinkValidationLog),
            )
        )
    ).scalar_one() + (
        await db.execute(
            select(func.count())
            .select_from(EntityMaintenanceLog)
            .where(
                EntityMaintenanceLog.action.in_(sorted(ADJUDICATION_PROPOSAL_ACTIONS)),
                EntityMaintenanceLog.applied.is_(False),
                entity_alive_clause(EntityMaintenanceLog),
            )
        )
    ).scalar_one()

    # Entities with a pending reclassify proposal in either log (the console's
    # "reclassify proposals" chip). One per entity, not one per article.
    pending_advisories = len(await _reclassify_group_rows(db))
    pending_unlink_entities = len({(r[0], r[1]) for r in (await db.execute(text(_UNLINK_GROUPS_SQL))).all()})

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
                entity_alive_clause(EntityMaintenanceLog),
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

    pending_by_domain = await _pending_by_domain(db)
    return HygieneStats(
        adjudication_mode=adjudication_mode,
        adjudication_breaker_until=adjudication_breaker_until,
        adjudication_pending=int(adjudication_pending),
        pending_advisories=int(pending_advisories),
        pending_unlink_entities=pending_unlink_entities,
        name_normalization_proposed=int(name_normalization_proposed),
        applied_24h=int(applied_24h_link) + int(applied_24h_maint),
        applied_7d=int(applied_7d_link) + int(applied_7d_maint),
        orphan_count=orphan_count,
        last_maintenance_run_at=last_maintenance,
        alias_collisions_proposed=int(alias_collisions_proposed),
        vendor_autolinks_proposed=int(vendor_autolinks_proposed),
        ttp_cve_issues_proposed=int(ttp_cve_issues_proposed),
        pending_total=sum(pending_by_domain.values()),
        pending_by_domain=pending_by_domain,
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
        source_id = entity.id
        await perform_same_type_merge(
            db,
            entity_type=row.entity_type,
            target_id=merge_target_id,
            source_id=source_id,
            mode="apply",
            reasoning=(f"Promoted from name-normalization proposal {row.id}: {(row.reasoning or '')[:1500]}"),
        )
        row.applied = True
        await settle_gone_entity(db, row.entity_type, source_id, successor=(row.entity_type, merge_target_id))
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
    # Unlink what only that alias matched and recount, like an alias edit on the profile;
    # otherwise the wrong links (and the inflated count) outlive the alias.
    unlinked = 0
    cascade = CASCADE_SPECS.get(row.entity_type)
    if cascade is not None:
        from app.api.entity_profiles import _unlink_entries_for_removed_aliases

        junction = cascade["junction"]
        unlinked = await _unlink_entries_for_removed_aliases(
            db, current, new_aliases, junction, getattr(junction, cascade["junction_fk"]), entity.id, entity=entity
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
                "unlinked_entries": unlinked,
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
    # A vendor named exactly like a product is a product filed twice ("Windows",
    # "Docker Engine"); it is no product's parent.
    product_names = {(n or "").lower() for n in (await db.execute(select(Product.name))).scalars().all() if n}
    tokens: list[tuple[str, uuid.UUID, str, str]] = []
    for vid, vname, valiases in vendor_rows:
        if vname and vname.lower() in product_names:
            continue
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


async def _all_canonical_cves(db: AsyncSession) -> list[tuple[uuid.UUID, str]]:
    """Every CVE whose id has the canonical shape."""
    return list((await db.execute(select(CVE.id, CVE.cve_id).where(CVE.cve_id.op("~")(r"^CVE-\d{4}-\d{4,}$")))).all())


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
    canonical_rows = await _all_canonical_cves(db)  # one read serves both checks
    canonical_cves: set[str] = {raw for _cid, raw in canonical_rows}
    # Right shape, impossible id: an over-long sequence (a CVSS score glued on,
    # "CVE-2024-123459.8"), or a zero-padded one past four digits. No safe
    # canonical form, so the row is the analyst's to dismiss or delete.
    from app.intelligence.cve import is_plausible_cve_id

    implausible_cve_rows = [(cid, raw) for cid, raw in canonical_rows if not is_plausible_cve_id(raw)]
    cve_malformed = 0
    for cid, raw_cve in [*malformed_cve_rows, *implausible_cve_rows]:
        proposed = _canonicalize_cve_id(raw_cve)
        if proposed and (proposed in canonical_cves or not is_plausible_cve_id(proposed)):
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
                    (
                        f"CVE id '{raw_cve}' can't be a real id (sequence too long or zero-padded)."
                        if raw_cve and _CVE_ID_RE.match(raw_cve)
                        else f"CVE id '{raw_cve}' doesn't match CVE-YYYY-NNNN+ form."
                    )
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
    await settle_gone_entity(db, "cve", cve.id, gone=True)
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
    # Apply found its outcome already reached (the entry, edge or entity is
    # gone, or an analyst rejected the edge): the proposal is closed.
    resolved: bool = False
    reason: str | None = None
    detail: dict = Field(default_factory=dict)


async def _adjudication_row(db: AsyncSession, log_id: uuid.UUID) -> EntityMaintenanceLog:
    row = (await db.execute(select(EntityMaintenanceLog).where(EntityMaintenanceLog.id == log_id))).scalar_one_or_none()
    if row is None or row.action not in ADJUDICATION_PROPOSAL_ACTIONS:
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
    Same code path apply mode uses at ingest; the row becomes the undo record.
    When the outcome is already reached (entry, edge or entity gone; edge
    rejected by an analyst) the proposal is closed and `resolved` is true.
    An entity the apply removes has its other pending proposals closed."""
    from app.services.entry_adjudication import apply_adjudication_row

    row = await _adjudication_row(db, log_id)
    outcome = await apply_adjudication_row(db, row)
    status = await settle_adjudication_outcome(db, row, outcome)
    await db.flush()
    return AdjudicationRowResult(
        log_id=log_id,
        applied=status == "applied",
        resolved=status == "resolved",
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


# The per-row promoter moved to the service so the bulk worker can share it.
_apply_link_removal_row = apply_link_removal_row


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
        if row.action == "needs_reclassification":
            # The decision is about the entity: drop every article's copy.
            await dismiss_reclassify(db, row.entity_type, row.entity_id, user.id)
        else:
            await db.delete(row)
    elif source == "entity_maintenance":
        row = (
            await db.execute(select(EntityMaintenanceLog).where(EntityMaintenanceLog.id == row_id))
        ).scalar_one_or_none()
        if not row:
            raise AppError(code="not_found", message="log row not found", status_code=404)
        if row.action == ACTION_RECLASSIFY and row.entity_id and not row.applied:
            await dismiss_reclassify(db, row.entity_type, row.entity_id, user.id)
        else:
            await _remember_merge_dismissal(db, row, user.id)
            await db.delete(row)
    else:
        raise AppError(code="invalid", message=f"unknown source: {source}", status_code=400)
    await db.flush()


async def _remember_merge_dismissal(db: AsyncSession, row: EntityMaintenanceLog, user_id: uuid.UUID | None) -> None:
    """Dismissing a duplicate review's Merge proposal says the pair is two
    things: record it so neither the review nor the Dupes lens brings it back."""
    after = row.after or {}
    if row.action != ACTION_MERGE or row.applied or after.get("origin") != MERGE_REVIEW_ORIGIN:
        return
    if not row.entity_id or not after.get("target_id"):
        return
    try:
        other = uuid.UUID(str(after["target_id"]))
    except ValueError:
        return
    await mark_not_duplicate(db, row.entity_type, row.entity_id, other, user_id)


class DismissProposalsRequest(BaseModel):
    action: str | None = Field(
        default=None,
        description="Dismiss only these proposal types (single code or comma-separated list); "
        "null clears every pending type.",
    )
    source: str | None = Field(default=None, description="'link_validator' | 'entity_maintenance' | null (both).")
    origin: str | None = Field(default=None, description=_ORIGIN_HELP)
    domain: str | None = Field(
        default=None, description="'links' | 'entities' | 'relationships'; omit for every domain"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {"action": "needs_reclassification", "source": "link_validator", "origin": "scan"}
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

    if body.domain is not None and body.domain not in DOMAINS:
        raise AppError(code="invalid", message=f"unknown domain: {body.domain}", status_code=400)
    _check_origin(body.origin)
    actions = _parse_action_list(body.action)
    link_actions = actions & {"shadow_remove", "needs_reclassification"}
    maint_actions = actions & dismissable_maint
    domain_link_actions = link_log_actions_for_domain(body.domain)
    domain_maint_actions = maint_actions_for_domain(body.domain)
    link_eligible = (
        body.source in (None, "link_validator")
        and (not actions or bool(link_actions))
        and (domain_link_actions is None or bool(domain_link_actions))
    )
    maint_eligible = (
        body.source in (None, "entity_maintenance")
        and (not actions or bool(maint_actions))
        and (domain_maint_actions is None or bool(domain_maint_actions))
    )

    if link_eligible:
        q = delete(EntityLinkValidationLog).where(
            EntityLinkValidationLog.action.in_(["shadow_remove", "needs_reclassification"])
        )
        if domain_link_actions is not None:
            q = q.where(EntityLinkValidationLog.action.in_(sorted(domain_link_actions)))
        if link_actions:
            q = q.where(EntityLinkValidationLog.action.in_(sorted(link_actions)))
        if body.origin:
            q = q.where(_link_origin_clause(body.origin, adjudicator_results))
        dismissed += (await db.execute(q)).rowcount or 0

    if maint_eligible:
        # Unapplied proposal rows only; applied history and informational logs stay.
        q = delete(EntityMaintenanceLog).where(
            EntityMaintenanceLog.applied.is_(False),
            EntityMaintenanceLog.action.in_(sorted(dismissable_maint)),
        )
        if domain_maint_actions is not None:
            q = q.where(EntityMaintenanceLog.action.in_(sorted(domain_maint_actions)))
        if maint_actions:
            q = q.where(EntityMaintenanceLog.action.in_(sorted(maint_actions)))
        if body.origin:
            q = q.where(_maint_origin_clause(body.origin))
        dismissed += (await db.execute(q)).rowcount or 0

    await db.flush()
    return DismissProposalsResponse(dismissed=dismissed)


@router.post("/admin/hygiene/adjudication/apply-all", response_model=ApplyAdjudicationAllResponse)
async def apply_adjudication_all(
    body: ApplyAdjudicationAllRequest = Body(default_factory=ApplyAdjudicationAllRequest),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> ApplyAdjudicationAllResponse:
    """Apply up to `limit` pending proposals the adjudicate stage filed,
    oldest first, inside this request: the entity-maintenance rows (unlink,
    reclassify, veto, merge, demote, drop) through the same code the per-row
    Apply uses, and its link-removal proposals through the link log's
    apply-removal. Assessment flags are informational and skipped. Each row
    is its own savepoint, so one failure is reported and the rest still
    apply. For a whole backlog use `POST /admin/hygiene/bulk-apply`, which
    runs in the background and reports progress."""
    out = await apply_adjudication_batch(db, action=body.action, limit=body.limit)
    return ApplyAdjudicationAllResponse(applied=out["applied"], skipped=out["skipped"], errors=out["errors"])


class BulkApplyRequest(BaseModel):
    """Scope for a background "Apply all" over one proposals queue."""

    kind: Literal["adjudication", "advisories", "all"] = Field(
        description=(
            "adjudication: the adjudicate stage's pending proposals (both logs). "
            "advisories: the link validator's needs_reclassification advisories. "
            "all: both, the adjudicator's first (the Review tab's one button)"
        )
    )
    action: str | None = Field(
        default=None,
        description="adjudication_* action codes, shadow_remove and/or needs_reclassification, comma-separated; "
        "omit for all",
    )
    domain: str | None = Field(
        default=None, description="'links' | 'entities' | 'relationships'; omit for every domain"
    )
    entity_type: str | None = Field(default=None, description="advisories only: limit to one source entity type")
    mode: Literal["shadow", "apply"] = Field(default="apply", description="advisories only")
    limit: int | None = Field(default=None, ge=1, le=100_000, description="Stop after this many rows; omit to drain")

    model_config = ConfigDict(json_schema_extra={"example": {"kind": "adjudication", "action": "shadow_remove"}})


class BulkApplyProgress(BaseModel):
    """Where a background Apply all stands. Polled until `status` is done or error."""

    job_id: str
    kind: str
    scope: dict[str, Any] = Field(default_factory=dict)
    status: Literal["queued", "running", "done", "error"]
    total: int = Field(description="Rows in scope when the job was queued; the loop may find fewer or more")
    processed: int
    applied: int
    skipped: int
    errors: list[dict] = Field(default_factory=list, description="First few row errors")
    error_count: int = 0
    started_at: str | None = None
    finished_at: str | None = None
    duration_ms: int | None = None
    message: str | None = None


@router.post("/admin/hygiene/bulk-apply", response_model=BulkApplyProgress, status_code=202)
async def start_bulk_apply(
    body: BulkApplyRequest,
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> BulkApplyProgress:
    """Queue a background Apply all over one proposals queue and return its
    progress record. The worker drains the queue in batches of 50 through
    the same appliers the per-row buttons use, committing per batch; poll
    `GET /admin/hygiene/bulk-apply/{job_id}` for progress. Rows that fail are
    reported and left in place."""
    from app.workers.proposal_apply_tasks import bulk_apply_proposals

    if body.domain is not None and body.domain not in DOMAINS:
        raise AppError(code="invalid", message=f"unknown domain: {body.domain}", status_code=400)
    total = 0
    scope: dict[str, Any] = {"action": body.action, "domain": body.domain}
    if body.kind in ("adjudication", "all"):
        adjudication_scope(body.action, body.domain)  # validates the action codes
        total += await count_adjudication_pending(db, body.action, body.domain)
    if body.kind == "advisories" or (
        body.kind == "all"
        and body.domain in (None, "entities")
        and (not body.action or "needs_reclassification" in body.action)
    ):
        total += await count_advisories_pending(db, body.entity_type)
        scope.update({"entity_type": body.entity_type, "mode": body.mode})

    job_id = uuid.uuid4().hex
    progress = new_progress(job_id, kind=body.kind, scope=scope, total=total)
    await write_progress(progress)
    bulk_apply_proposals.apply_async(
        kwargs={
            "job_id": job_id,
            "kind": body.kind,
            "action": body.action,
            "entity_type": body.entity_type,
            "mode": body.mode,
            "limit": body.limit,
            "domain": body.domain,
        }
    )
    return BulkApplyProgress(**progress)


@router.get("/admin/hygiene/bulk-apply/{job_id}", response_model=BulkApplyProgress)
async def get_bulk_apply(
    job_id: str = Path(..., description="Job id returned by POST /admin/hygiene/bulk-apply"),
    user: User = Depends(get_admin_user),
) -> BulkApplyProgress:
    """Progress of a background Apply all. Records expire two hours after the job finishes."""
    progress = await read_progress(job_id)
    if progress is None:
        raise AppError(code="not_found", message="No such bulk apply job (or it expired)", status_code=404)
    return BulkApplyProgress(**progress)


# ---------------------------------------------------------------------------
# Reclassify proposals grouped by entity
# ---------------------------------------------------------------------------
#
# A reclassify proposal is filed once per article that mentions the entity, so
# "Linux Kernel: tool → product" can be hundreds of rows across both logs. The
# decision is about the entity: these endpoints show one row per entity and
# apply / dismiss every proposal about it at once.


class ReclassifySuggestion(BaseModel):
    type: str
    count: int


class ReclassifyGroup(BaseModel):
    entity_type: str
    entity_id: uuid.UUID
    name: str
    exists: bool  # False → the entity is gone; applying just clears the rows
    suggestions: list[ReclassifySuggestion]  # most-proposed first
    proposals: int
    latest_at: datetime
    reason: str | None
    sample_entry_id: uuid.UUID | None


class ReclassifyGroupsResponse(BaseModel):
    groups: list[ReclassifyGroup]
    total: int


async def _reclassify_group_rows(db: AsyncSession) -> dict[tuple[str, uuid.UUID], dict]:
    """Every pending reclassify proposal in both logs, folded per entity."""
    groups: dict[tuple[str, uuid.UUID], dict] = {}
    rows = (
        await db.execute(
            text(
                """
                SELECT entity_type, entity_id, suggested_entity_type, count(*), max(created_at),
                       max(entity_name_snapshot)
                FROM entity_link_validation_log
                WHERE action = 'needs_reclassification'
                  AND suggested_entity_type IS NOT NULL
                  AND suggested_entity_type <> entity_type
                GROUP BY 1, 2, 3
                UNION ALL
                SELECT entity_type, entity_id, after->>'suggested_type', count(*), max(created_at),
                       max(before->'entity'->>'name')
                FROM entity_maintenance_log
                WHERE action = 'adjudication_reclassify' AND applied = false
                  AND entity_id IS NOT NULL
                  AND after->>'suggested_type' IS NOT NULL
                  AND after->>'suggested_type' <> entity_type
                GROUP BY 1, 2, 3
                """
            )
        )
    ).all()
    for etype, eid, sug, n, latest, name in rows:
        g = groups.setdefault(
            (etype, eid),
            {
                "entity_type": etype,
                "entity_id": eid,
                "name": name,
                "suggestions": defaultdict(int),
                "latest_at": latest,
            },
        )
        g["suggestions"][sug] += n
        g["name"] = g["name"] or name
        if latest > g["latest_at"]:
            g["latest_at"] = latest
    return groups


@router.get("/admin/hygiene/reclassify-groups", response_model=ReclassifyGroupsResponse)
async def reclassify_groups(
    q: str | None = Query(None, description="Filter by entity name (substring, case-insensitive)."),
    entity_type: str | None = Query(None, description="Only proposals about entities of this type."),
    limit: int = Query(50, ge=1, le=200, description="Groups per page."),
    offset: int = Query(0, ge=0, description="Groups to skip."),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> ReclassifyGroupsResponse:
    """Pending reclassify proposals from both logs, one row per entity, most-proposed first."""
    groups = list((await _reclassify_group_rows(db)).values())

    # Live names (and whether the entity still exists), per type.
    by_type: dict[str, list[uuid.UUID]] = defaultdict(list)
    for g in groups:
        by_type[g["entity_type"]].append(g["entity_id"])
    live: dict[tuple[str, uuid.UUID], str] = {}
    for etype, ids in by_type.items():
        spec = ENTITY_TYPE_REGISTRY.get(etype)
        if spec is None:
            continue
        model = spec["model"]
        for eid, name in (await db.execute(select(model.id, model.name).where(model.id.in_(ids)))).all():
            live[(etype, eid)] = name
    for g in groups:
        key = (g["entity_type"], g["entity_id"])
        g["exists"] = key in live
        g["name"] = live.get(key) or g["name"] or "(unnamed)"
        g["proposals"] = sum(g["suggestions"].values())

    # A deleted entity has nothing left to reclassify: drop its proposals here
    # rather than list a row whose only action is "clear". Unregistered types
    # can't be looked up, so they're never assumed gone.
    for g in groups:
        if not g["exists"] and g["entity_type"] in ENTITY_TYPE_REGISTRY:
            await clear_reclassify_proposals(db, g["entity_type"], g["entity_id"])
    groups = [g for g in groups if g["exists"] or g["entity_type"] not in ENTITY_TYPE_REGISTRY]

    if entity_type:
        groups = [g for g in groups if g["entity_type"] == entity_type]
    if q:
        needle = q.strip().lower()
        groups = [g for g in groups if needle in g["name"].lower()]
    groups.sort(key=lambda g: (-g["proposals"], g["name"].lower()))
    total = len(groups)
    page = groups[offset : offset + limit]

    # The latest reason and an example article, for the visible page only.
    detail: dict[tuple[str, uuid.UUID], tuple[str | None, uuid.UUID | None, datetime]] = {}
    if page:
        ids = [g["entity_id"] for g in page]
        rows = (
            await db.execute(
                text(
                    """
                    SELECT entity_type, entity_id, reason, entry_id, created_at
                    FROM entity_link_validation_log
                    WHERE action = 'needs_reclassification' AND entity_id = ANY(:ids)
                    UNION ALL
                    SELECT entity_type, entity_id, coalesce(after->>'reason', reasoning),
                           (before->>'entry_id')::uuid, created_at
                    FROM entity_maintenance_log
                    WHERE action = 'adjudication_reclassify' AND applied = false AND entity_id = ANY(:ids)
                    """
                ).bindparams(ids=ids)
            )
        ).all()
        for etype, eid, reason, entry_id, created in rows:
            prev = detail.get((etype, eid))
            if prev is None or created > prev[2]:
                detail[(etype, eid)] = (reason, entry_id, created)

    out = []
    for g in page:
        reason, entry_id, _ = detail.get((g["entity_type"], g["entity_id"]), (None, None, None))
        out.append(
            ReclassifyGroup(
                entity_type=g["entity_type"],
                entity_id=g["entity_id"],
                name=g["name"],
                exists=g["exists"],
                suggestions=[
                    ReclassifySuggestion(type=t, count=n)
                    for t, n in sorted(g["suggestions"].items(), key=lambda kv: -kv[1])
                ],
                proposals=g["proposals"],
                latest_at=g["latest_at"],
                reason=reason,
                sample_entry_id=entry_id,
            )
        )
    return ReclassifyGroupsResponse(groups=out, total=total)


class ReclassifyGroupItem(BaseModel):
    entity_type: str
    entity_id: uuid.UUID
    target_type: str | None = Field(default=None, description="Apply only: the type to convert the entity to.")


class ReclassifyGroupsActionRequest(BaseModel):
    items: list[ReclassifyGroupItem] = Field(..., max_length=200)

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "items": [
                    {
                        "entity_type": "tool",
                        "entity_id": "d5b2c8f0-3e4a-4b6c-9d1e-7f8a9b0c1d2e",
                        "target_type": "product",
                    }
                ]
            }
        }
    )


class ReclassifyGroupsActionResponse(BaseModel):
    entities: int  # entities handled
    cleared_rows: int  # proposal rows removed from both logs
    failed: int
    errors: list[dict]


def _reclassify_successor(target_type: str, outcome: dict | None) -> tuple[str, uuid.UUID] | None:
    """The entity a reclassify moved into, from ``_reclassify_entity``'s outcome."""
    raw = ((outcome or {}).get("response") or {}).get("target_id")
    try:
        return (target_type, uuid.UUID(str(raw))) if raw else None
    except ValueError:
        return None


@router.post("/admin/hygiene/reclassify-groups/apply", response_model=ReclassifyGroupsActionResponse)
async def apply_reclassify_groups(
    body: ReclassifyGroupsActionRequest = Body(...),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> ReclassifyGroupsActionResponse:
    """Convert each entity to its target type, then clear every reclassify proposal
    about it (any suggested type, both logs). An entity that's already gone just
    has its proposals cleared."""
    from app.services.entry_adjudication import _reclassify_entity

    entities = cleared = failed = 0
    errors: list[dict] = []
    for it in body.items:
        if not it.target_type:
            failed += 1
            errors.append({"entity_id": str(it.entity_id), "error": "target_type is required"})
            continue
        try:
            async with db.begin_nested():
                outcome = await _reclassify_entity(db, it.entity_type, it.entity_id, it.target_type, "")
                if not outcome.get("applied") and outcome.get("reason") != "entity gone":
                    raise AppError(code="invalid", message=str(outcome.get("reason")), status_code=400)
                cleared += await clear_reclassify_proposals(db, it.entity_type, it.entity_id)
                cleared += await settle_gone_entity(
                    db, it.entity_type, it.entity_id, successor=_reclassify_successor(it.target_type, outcome)
                )
            entities += 1
        except AppError as e:
            failed += 1
            errors.append({"entity_id": str(it.entity_id), "error": e.message})
        except Exception as e:  # pragma: no cover  (defense-in-depth)
            failed += 1
            errors.append({"entity_id": str(it.entity_id), "error": str(e)[:300]})
    await db.flush()
    return ReclassifyGroupsActionResponse(entities=entities, cleared_rows=cleared, failed=failed, errors=errors[:50])


@router.post("/admin/hygiene/reclassify-groups/dismiss", response_model=ReclassifyGroupsActionResponse)
async def dismiss_reclassify_groups(
    body: ReclassifyGroupsActionRequest = Body(...),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> ReclassifyGroupsActionResponse:
    """Clear every reclassify proposal about each entity and stop new ones from
    being filed for it."""
    cleared = 0
    for it in body.items:
        cleared += await dismiss_reclassify(db, it.entity_type, it.entity_id, user.id)
    await db.flush()
    return ReclassifyGroupsActionResponse(entities=len(body.items), cleared_rows=cleared, failed=0, errors=[])


# ---------------------------------------------------------------------------
# Remove-link proposals grouped by entity
# ---------------------------------------------------------------------------
#
# The adjudicate stage judges each article's links on their own, so one entity
# the autolinker over-matches ("Linux", "python3") collects a remove-link
# proposal per article in one of two logs: the link log's shadow_remove for the
# linkable types, the maintenance log's adjudication_unlink for the rest. These
# endpoints show one row per entity and settle its proposals together.

UNLINK_APPLY_BATCH = 400  # rows per apply call; the client repeats while `remaining`


class UnlinkGroup(BaseModel):
    entity_type: str
    entity_id: uuid.UUID
    name: str
    exists: bool
    proposals: int  # articles the review wants this entity unlinked from
    linked: int | None  # articles it is linked to now, where the type keeps a count
    matched_names: list[str]  # the surface forms the proposals were about, most common first
    reason: str | None
    latest_at: datetime


class UnlinkGroupsResponse(BaseModel):
    groups: list[UnlinkGroup]
    total: int
    proposals: int


class UnlinkRow(BaseModel):
    id: str  # "{source}:{uuid}", the feed's id shape
    entry_id: uuid.UUID | None
    entry_title: str | None
    reason: str | None
    matched_names: list[str]
    created_at: datetime


_UNLINK_GROUPS_SQL = """
SELECT entity_type, entity_id, count(*), max(created_at), max(entity_name_snapshot)
FROM entity_link_validation_log WHERE action = 'shadow_remove'
GROUP BY 1, 2
UNION ALL
SELECT entity_type, entity_id, count(*), max(created_at), NULL
FROM entity_maintenance_log
WHERE action = 'adjudication_unlink' AND applied = false AND entity_id IS NOT NULL
GROUP BY 1, 2
"""

# One row per proposal for the given entities, newest first, with the forms it
# matched on. :ids is a uuid[]; maintenance rows keep the junction snapshot in
# before->'junction'.
_UNLINK_ROWS_SQL = """
SELECT 'link_validator' AS source, l.id, l.entity_type, l.entity_id, l.entry_id, l.reason,
       coalesce(l.original_matched_names, ARRAY[]::text[]) AS forms, l.created_at
FROM entity_link_validation_log l
WHERE l.action = 'shadow_remove' AND l.entity_id = ANY(:ids)
UNION ALL
SELECT 'entity_maintenance', m.id, m.entity_type, m.entity_id, (m.before->>'entry_id')::uuid,
       coalesce(m.after->>'reason', m.reasoning),
       coalesce(ARRAY(SELECT jsonb_array_elements_text(m.before->'junction'->'matched_names')), ARRAY[]::text[]),
       m.created_at
FROM entity_maintenance_log m
WHERE m.action = 'adjudication_unlink' AND m.applied = false AND m.entity_id = ANY(:ids)
ORDER BY 8 DESC
"""


async def _entity_labels(
    db: AsyncSession, by_type: dict[str, list[uuid.UUID]]
) -> dict[tuple[str, uuid.UUID], tuple[str, int | None]]:
    """Live (display name, article_count) per entity, for any entity type."""
    from app.services.entry_adjudication import _model_for

    out: dict[tuple[str, uuid.UUID], tuple[str, int | None]] = {}
    for etype, ids in by_type.items():
        model = _model_for(etype)
        if model is None:
            continue
        name_col = next(getattr(model, a) for a in ("name", "cve_id", "technique_id", "value") if hasattr(model, a))
        count_col = model.article_count if hasattr(model, "article_count") else literal(None)
        for eid, name, n in (await db.execute(select(model.id, name_col, count_col).where(model.id.in_(ids)))).all():
            out[(etype, eid)] = (str(name), n)
    return out


@router.get("/admin/hygiene/unlink-groups", response_model=UnlinkGroupsResponse)
async def unlink_groups(
    q: str | None = Query(None, description="Filter by entity name (substring, case-insensitive)."),
    entity_type: str | None = Query(None, description="Only proposals about entities of this type."),
    limit: int = Query(50, ge=1, le=200, description="Groups per page."),
    offset: int = Query(0, ge=0, description="Groups to skip."),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> UnlinkGroupsResponse:
    """Pending remove-link proposals from both logs, one row per entity, most-proposed first."""
    groups: dict[tuple[str, uuid.UUID], dict] = {}
    for etype, eid, n, latest, snap in (await db.execute(text(_UNLINK_GROUPS_SQL))).all():
        g = groups.setdefault((etype, eid), {"proposals": 0, "latest_at": latest, "snap": snap})
        g["proposals"] += n
        g["latest_at"] = max(g["latest_at"], latest)
        g["snap"] = g["snap"] or snap
    all_proposals = sum(g["proposals"] for g in groups.values())

    by_type: dict[str, list[uuid.UUID]] = defaultdict(list)
    for etype, eid in groups:
        by_type[etype].append(eid)
    labels = await _entity_labels(db, by_type)

    # A deleted entity has no links left to remove: drop its proposals here
    # rather than list a row whose only action is "clear". Types with no model
    # can't be looked up, so they're never assumed gone.
    from app.services.entry_adjudication import _model_for

    gone = [k for k in groups if k not in labels and _model_for(k[0]) is not None]
    for etype, eid in gone:
        for model, action in ((EntityLinkValidationLog, "shadow_remove"), (EntityMaintenanceLog, ACTION_UNLINK)):
            stmt = delete(model).where(model.action == action, model.entity_type == etype, model.entity_id == eid)
            if model is EntityMaintenanceLog:
                stmt = stmt.where(model.applied.is_(False))
            await db.execute(stmt)
        all_proposals -= groups.pop((etype, eid))["proposals"]

    items = []
    for (etype, eid), g in groups.items():
        name, linked = labels.get((etype, eid), (g["snap"] or "(deleted)", None))
        items.append(
            {"entity_type": etype, "entity_id": eid, "name": name, "linked": linked, "exists": (etype, eid) in labels}
            | g
        )
    if entity_type:
        items = [g for g in items if g["entity_type"] == entity_type]
    if q:
        needle = q.strip().lower()
        items = [g for g in items if needle in g["name"].lower()]
    items.sort(key=lambda g: (-g["proposals"], g["name"].lower()))
    total = len(items)
    page = items[offset : offset + limit]

    # Matched forms and the latest reason, for the visible page only.
    forms: dict[tuple[str, uuid.UUID], dict[str, int]] = defaultdict(lambda: defaultdict(int))
    reasons: dict[tuple[str, uuid.UUID], str | None] = {}
    if page:
        rows = (await db.execute(text(_UNLINK_ROWS_SQL).bindparams(ids=[g["entity_id"] for g in page]))).all()
        for _src, _id, etype, eid, _entry, reason, row_forms, _at in rows:
            key = (etype, eid)
            reasons.setdefault(key, reason)  # newest first
            for f in row_forms or []:
                forms[key][f] += 1

    return UnlinkGroupsResponse(
        groups=[
            UnlinkGroup(
                entity_type=g["entity_type"],
                entity_id=g["entity_id"],
                name=g["name"],
                exists=g["exists"],
                proposals=g["proposals"],
                linked=g["linked"],
                matched_names=[
                    f for f, _ in sorted(forms[(g["entity_type"], g["entity_id"])].items(), key=lambda kv: -kv[1])
                ][:4],
                reason=reasons.get((g["entity_type"], g["entity_id"])),
                latest_at=g["latest_at"],
            )
            for g in page
        ],
        total=total,
        proposals=all_proposals,
    )


@router.get("/admin/hygiene/unlink-groups/rows", response_model=list[UnlinkRow])
async def unlink_group_rows(
    entity_type: str = Query(..., description="Entity type of the group."),
    entity_id: uuid.UUID = Query(..., description="Entity id of the group."),
    limit: int = Query(200, ge=1, le=1000, description="Most rows to return, newest first."),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> list[UnlinkRow]:
    """The articles behind one entity's remove-link proposals, newest first."""
    rows = [
        r for r in (await db.execute(text(_UNLINK_ROWS_SQL).bindparams(ids=[entity_id]))).all() if r[2] == entity_type
    ][:limit]
    entry_ids = [r[4] for r in rows if r[4]]
    titles = (
        dict((await db.execute(select(Entry.id, Entry.title).where(Entry.id.in_(entry_ids)))).all())
        if entry_ids
        else {}
    )
    return [
        UnlinkRow(
            id=f"{src}:{rid}",
            entry_id=entry_id,
            entry_title=titles.get(entry_id),
            reason=reason,
            matched_names=list(row_forms or []),
            created_at=at,
        )
        for src, rid, _t, _e, entry_id, reason, row_forms, at in rows
    ]


class UnlinkGroupsActionRequest(BaseModel):
    items: list[ReclassifyGroupItem] = Field(
        default_factory=list, max_length=200, description="Whole groups: every proposal about each entity."
    )
    row_ids: list[str] = Field(
        default_factory=list, max_length=1000, description="Or single proposals, as '{source}:{uuid}' feed ids."
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {"items": [{"entity_type": "tool", "entity_id": "d5b2c8f0-3e4a-4b6c-9d1e-7f8a9b0c1d2e"}]}
        }
    )


class UnlinkGroupsActionResponse(BaseModel):
    done: int  # proposals applied (links removed) or cleared (links kept)
    failed: int
    remaining: int  # apply only: proposals still pending in the requested groups — call again
    errors: list[dict]


async def _unlink_targets(
    db: AsyncSession, body: UnlinkGroupsActionRequest, cap: int | None
) -> tuple[list[EntityLinkValidationLog], list[EntityMaintenanceLog], int]:
    """The proposal rows an unlink-group action covers, capped; plus how many exist in all."""
    link_ids: list[uuid.UUID] = []
    maint_ids: list[uuid.UUID] = []
    for rid in body.row_ids:
        src, _, raw = rid.partition(":")
        try:
            (link_ids if src == "link_validator" else maint_ids).append(uuid.UUID(raw))
        except ValueError:
            raise AppError(code="invalid", message=f"bad row id: {rid}", status_code=400) from None
    link_q = select(EntityLinkValidationLog).where(EntityLinkValidationLog.action == "shadow_remove")
    maint_q = select(EntityMaintenanceLog).where(
        EntityMaintenanceLog.action == ACTION_UNLINK, EntityMaintenanceLog.applied.is_(False)
    )
    if body.items:
        link_q = link_q.where(
            or_(
                *(
                    and_(
                        EntityLinkValidationLog.entity_type == it.entity_type,
                        EntityLinkValidationLog.entity_id == it.entity_id,
                    )
                    for it in body.items
                )
            )
        )
        maint_q = maint_q.where(
            or_(
                *(
                    and_(
                        EntityMaintenanceLog.entity_type == it.entity_type,
                        EntityMaintenanceLog.entity_id == it.entity_id,
                    )
                    for it in body.items
                )
            )
        )
    elif body.row_ids:
        link_q = link_q.where(EntityLinkValidationLog.id.in_(link_ids))
        maint_q = maint_q.where(EntityMaintenanceLog.id.in_(maint_ids))
    else:
        raise AppError(code="invalid", message="Pass items or row_ids", status_code=400)
    total = (await db.execute(select(func.count()).select_from(link_q.subquery()))).scalar_one() + (
        await db.execute(select(func.count()).select_from(maint_q.subquery()))
    ).scalar_one()
    if cap is not None:
        link_q = link_q.limit(cap)
        maint_q = maint_q.limit(cap)
    return list((await db.execute(link_q)).scalars().all()), list((await db.execute(maint_q)).scalars().all()), total


@router.post("/admin/hygiene/unlink-groups/apply", response_model=UnlinkGroupsActionResponse)
async def apply_unlink_groups(
    body: UnlinkGroupsActionRequest = Body(...),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> UnlinkGroupsActionResponse:
    """Remove the links the proposals name — every article for each entity, or the
    picked rows. Works in batches of a few hundred; `remaining` says to call again.
    Every removal stays restorable from History."""
    from app.services.entry_adjudication import apply_adjudication_row

    link_rows, maint_rows, total = await _unlink_targets(db, body, UNLINK_APPLY_BATCH)
    link_rows = link_rows[:UNLINK_APPLY_BATCH]
    maint_rows = maint_rows[: max(0, UNLINK_APPLY_BATCH - len(link_rows))]
    done = failed = 0
    errors: list[dict] = []
    for row in [*link_rows, *maint_rows]:
        try:
            async with db.begin_nested():
                if isinstance(row, EntityLinkValidationLog):
                    await apply_link_removal_row(db, row)
                else:
                    outcome = await apply_adjudication_row(db, row)
                    if not outcome.get("applied"):
                        # Entry or entity gone: nothing to unlink, the proposal is moot.
                        await db.delete(row)
            done += 1
        except Exception as e:
            failed += 1
            errors.append({"id": str(row.id), "error": str(getattr(e, "message", e))[:300]})
    await db.flush()
    return UnlinkGroupsActionResponse(
        done=done, failed=failed, remaining=max(0, total - done - failed), errors=errors[:50]
    )


@router.post("/admin/hygiene/unlink-groups/keep", response_model=UnlinkGroupsActionResponse)
async def keep_unlink_groups(
    body: UnlinkGroupsActionRequest = Body(...),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> UnlinkGroupsActionResponse:
    """Keep the links: clear the remove-link proposals for each entity (or the
    picked rows) without touching a junction."""
    link_rows, maint_rows, _ = await _unlink_targets(db, body, None)
    for row in [*link_rows, *maint_rows]:
        await db.delete(row)
    await db.flush()
    return UnlinkGroupsActionResponse(done=len(link_rows) + len(maint_rows), failed=0, remaining=0, errors=[])


# ---------------------------------------------------------------------------
# The Review tab's one queue: every pending proposal, one row per entity
# ---------------------------------------------------------------------------
#
# The flat feed and the per-entity Remove-links / Reclassify queues showed the
# same rows two ways. This is the one view: pending proposals from both logs
# folded per entity (an entity the autolinker over-matches collects one
# remove-link proposal per article; a mis-filed one a reclassify per article),
# with per-kind counts so the row says what the reviewer wants done. Rows
# about something other than a catalogue entity (an edge, an article's
# assessment) stand alone.

_LINK_PENDING_ACTIONS = ("shadow_remove", "needs_reclassification")


class ReviewGroupKind(BaseModel):
    action: str
    count: int


class ReviewGroupTarget(BaseModel):
    type: str
    count: int


class ReviewGroupMerge(BaseModel):
    target_type: str
    target_id: str
    name: str | None
    count: int


class ReviewGroup(BaseModel):
    key: str  # "{entity_type}:{entity_id}" or "row:{source}:{id}" for a row with no entity
    entity_type: str
    entity_id: uuid.UUID | None
    name: str
    exists: bool
    linked: int | None  # articles it is linked to now, where the type keeps a count
    proposals: int
    kinds: list[ReviewGroupKind]  # per action code, most common first
    reclassify_to: list[ReviewGroupTarget]  # proposed target types, most proposed first
    merge_into: list[ReviewGroupMerge]
    domains: list[str]
    origin: str  # adjudicator | merge_review | scan | mixed
    subject: str | None  # the newest row's plain-English line
    reason: str | None
    links: list[FeedLink]
    latest_at: datetime
    sample_entry_id: uuid.UUID | None
    matched_names: list[str]
    row_ids: list[str]  # the row(s) behind a group with no entity (feed id shape)


class ReviewGroupsResponse(BaseModel):
    groups: list[ReviewGroup]
    total: int
    proposals: int


def _group_key(etype: str, eid: uuid.UUID | None, source: str, rid: uuid.UUID | None) -> str:
    return f"{etype}:{eid}" if eid else f"row:{source}:{rid}"


@router.get("/admin/hygiene/review-groups", response_model=ReviewGroupsResponse)
async def review_groups(
    q: str | None = Query(None, description="Filter by entity name (substring, case-insensitive)."),
    entity_type: str | None = Query(None, description="Only proposals about entities of this type."),
    action: str | None = Query(None, description="Only these action codes (comma-separated), either log."),
    domain: str | None = Query(None, description="'links' | 'entities' | 'relationships'; omit for all."),
    origin: str | None = Query(None, description=_ORIGIN_HELP),
    limit: int = Query(50, ge=1, le=200, description="Groups per page."),
    offset: int = Query(0, ge=0, description="Groups to skip."),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> ReviewGroupsResponse:
    """Every pending proposal in both logs, one row per entity, most-proposed first.

    Three passes, so the cost is one row per *entity*, never per proposal:
    the logs are grouped in SQL; live names settle the order and the page;
    then only the page's rows are read for their kinds, targets and forms.
    """
    if domain is not None and domain not in DOMAINS:
        raise AppError(code="invalid", message=f"unknown domain: {domain}", status_code=400)
    _check_origin(origin)
    actions = _parse_action_list(action)
    link_actions = (actions & _LINK_VALIDATOR_ACTIONS) if actions else set(_LINK_PENDING_ACTIONS)
    maint_actions = (actions & _MAINTENANCE_ACTIONS) if actions else (_MAINTENANCE_PROPOSAL_ACTIONS | {"orphan_prune"})
    domain_link_actions = link_log_actions_for_domain(domain)
    domain_maint_actions = maint_actions_for_domain(domain)
    link_actions &= set(_LINK_PENDING_ACTIONS)
    maint_actions &= _MAINTENANCE_PROPOSAL_ACTIONS | {"orphan_prune"}
    if domain_link_actions is not None:
        link_actions &= set(domain_link_actions)
    if domain_maint_actions is not None:
        maint_actions &= set(domain_maint_actions)
    if origin == ORIGIN_MERGE_REVIEW:
        link_actions = set()  # the duplicate review writes only the maintenance log
    adjudicator_results = select(AIResult.id).where(
        AIResult.task_id == select(AITask.id).where(AITask.name == ADJUDICATION_TASK_NAME).scalar_subquery()
    )
    link_adjudicated = func.coalesce(EntityLinkValidationLog.ai_result_id.in_(adjudicator_results), False)
    maint_origin = case(
        (EntityMaintenanceLog.after["origin"].astext == MERGE_REVIEW_ORIGIN, ORIGIN_MERGE_REVIEW),
        (EntityMaintenanceLog.action.in_(sorted(ADJUDICATION_ACTIONS)), ORIGIN_ADJUDICATOR),
        (EntityMaintenanceLog.after["kind"].astext == ADJUDICATOR_ALIAS_KIND, ORIGIN_ADJUDICATOR),
        else_=ORIGIN_SCAN,
    )
    # A maintenance row with no entity is its own group.
    maint_row_key = case((EntityMaintenanceLog.entity_id.is_(None), EntityMaintenanceLog.id))

    # Pass 1 — one row per group from each log: count, newest, a snapshot
    # name, the origins and the action codes (for the Domain facet).
    groups: dict[str, dict] = {}

    def _bucket(key: str, etype: str, eid: uuid.UUID | None) -> dict:
        return groups.setdefault(
            key,
            {
                "key": key,
                "entity_type": etype,
                "entity_id": eid,
                "snap": None,
                "proposals": 0,
                "latest_at": None,
                "domains": set(),
                "origins": set(),
                "row_ids": [],
            },
        )

    def _fold(g: dict, n: int, latest: datetime, snap, acts, origins, source: str, rid) -> None:
        g["proposals"] += int(n)
        g["snap"] = g["snap"] or snap
        if g["latest_at"] is None or latest > g["latest_at"]:
            g["latest_at"] = latest
        g["domains"].update(proposal_domain(source, a) for a in acts or [] if a)
        g["origins"].update(o for o in origins or [] if o)
        if g["entity_id"] is None and rid is not None:
            g["row_ids"].append(f"{source}:{rid}")

    if link_actions:
        lq = (
            select(
                EntityLinkValidationLog.entity_type,
                EntityLinkValidationLog.entity_id,
                func.count(),
                func.max(EntityLinkValidationLog.created_at),
                func.max(EntityLinkValidationLog.entity_name_snapshot),
                func.array_agg(EntityLinkValidationLog.action.distinct()),
                func.array_agg(case((link_adjudicated, ORIGIN_ADJUDICATOR), else_=ORIGIN_SCAN).distinct()),
            )
            .where(EntityLinkValidationLog.action.in_(sorted(link_actions)))
            .where(entity_alive_clause(EntityLinkValidationLog))
            .group_by(EntityLinkValidationLog.entity_type, EntityLinkValidationLog.entity_id)
        )
        if entity_type:
            lq = lq.where(EntityLinkValidationLog.entity_type == entity_type)
        if origin:
            lq = lq.where(_link_origin_clause(origin, adjudicator_results))
        for etype, eid, n, latest, snap, acts, origins in (await db.execute(lq)).all():
            _fold(
                _bucket(_group_key(etype, eid, "link_validator", None), etype, eid),
                n,
                latest,
                snap,
                acts,
                origins,
                "link_validator",
                None,
            )

    if maint_actions:
        mq = (
            select(
                EntityMaintenanceLog.entity_type,
                EntityMaintenanceLog.entity_id,
                maint_row_key,
                func.count(),
                func.max(EntityMaintenanceLog.created_at),
                func.max(EntityMaintenanceLog.before["entity"]["name"].astext),
                func.array_agg(EntityMaintenanceLog.action.distinct()),
                func.array_agg(maint_origin.distinct()),
            )
            .where(EntityMaintenanceLog.applied.is_(False), EntityMaintenanceLog.action.in_(sorted(maint_actions)))
            .where(entity_alive_clause(EntityMaintenanceLog))
            .group_by(EntityMaintenanceLog.entity_type, EntityMaintenanceLog.entity_id, maint_row_key)
        )
        if entity_type:
            mq = mq.where(EntityMaintenanceLog.entity_type == entity_type)
        if origin:
            mq = mq.where(_maint_origin_clause(origin))
        for etype, eid, rid, n, latest, snap, acts, origins in (await db.execute(mq)).all():
            g = _bucket(_group_key(etype, eid, "entity_maintenance", rid), etype, eid)
            _fold(g, n, latest, snap, acts, origins, "entity_maintenance", rid)

    # Pass 2 — live names, order, page. A deleted entity has nothing left to
    # fix: pass 1 already left its rows out (entity_alive_clause, which the
    # pending feed and the counts share), deletes, merges and reclassifies
    # close them, and the nightly prune drops any left
    # (purge_gone_entity_proposals). Pseudo types (relationship, entry) have
    # no model and are never assumed gone.
    by_type: dict[str, list[uuid.UUID]] = defaultdict(list)
    for g in groups.values():
        if g["entity_id"] is not None:
            by_type[g["entity_type"]].append(g["entity_id"])
    labels = await _entity_labels(db, by_type)
    from app.services.entry_adjudication import _model_for

    items: list[dict] = []
    for g in groups.values():
        eid = g["entity_id"]
        if eid is None:
            g["exists"], g["name"], g["linked"] = True, g["snap"] or "", None
        else:
            live = labels.get((g["entity_type"], eid))
            if live is None and _model_for(g["entity_type"]) is not None:
                continue
            g["exists"] = True
            g["name"] = (live[0] if live else None) or g["snap"] or "(unnamed)"
            g["linked"] = live[1] if live else None
        items.append(g)
    if q:
        needle = q.strip().lower()
        items = [g for g in items if needle in (g["name"] or "").lower()]
    items.sort(key=lambda g: (-g["proposals"], -(g["latest_at"].timestamp()), (g["name"] or "").lower()))
    total = len(items)
    all_proposals = sum(g["proposals"] for g in items)
    page = items[offset : offset + limit]

    # Pass 3 — the page's own rows: per-kind counts, proposed types and merge
    # targets, the forms matched, and the newest row for subject / links.
    detail: dict[str, dict] = {
        g["key"]: {
            "kinds": defaultdict(int),
            "reclassify_to": defaultdict(int),
            "merge_into": {},
            "forms": defaultdict(int),
            "latest": None,  # (source, id)
            "latest_at": None,
            "sample_entry_id": None,
        }
        for g in page
    }
    page_ids = [g["entity_id"] for g in page if g["entity_id"] is not None]
    page_rows: dict[str, list[uuid.UUID]] = {"link_validator": [], "entity_maintenance": []}
    for g in page:
        for rid in g["row_ids"]:
            src, _, raw = rid.partition(":")
            page_rows.setdefault(src, []).append(uuid.UUID(raw))

    def _touch(d: dict, source: str, rid: uuid.UUID, when: datetime, entry_id) -> None:
        if d["latest_at"] is None or when > d["latest_at"]:
            d["latest_at"] = when
            d["latest"] = (source, rid)
            if entry_id:
                d["sample_entry_id"] = entry_id
        elif d["sample_entry_id"] is None and entry_id:
            d["sample_entry_id"] = entry_id

    def _scope(col_entity, col_id, rows: list[uuid.UUID]):
        parts = []
        if page_ids:
            parts.append(col_entity.in_(page_ids))
        if rows:
            parts.append(col_id.in_(rows))
        return or_(*parts) if parts else None

    scope = _scope(EntityLinkValidationLog.entity_id, EntityLinkValidationLog.id, page_rows["link_validator"])
    if link_actions and scope is not None:
        lq = select(
            EntityLinkValidationLog.id,
            EntityLinkValidationLog.entity_type,
            EntityLinkValidationLog.entity_id,
            EntityLinkValidationLog.action,
            EntityLinkValidationLog.created_at,
            EntityLinkValidationLog.suggested_entity_type,
            EntityLinkValidationLog.entry_id,
            EntityLinkValidationLog.original_matched_names,
        ).where(EntityLinkValidationLog.action.in_(sorted(link_actions)), scope)
        if origin:
            lq = lq.where(_link_origin_clause(origin, adjudicator_results))
        for rid, etype, eid, act, when, sug, entry_id, forms in (await db.execute(lq)).all():
            d = detail.get(_group_key(etype, eid, "link_validator", rid))
            if d is None:
                continue
            d["kinds"][act] += 1
            if act == "needs_reclassification" and sug and sug != etype:
                d["reclassify_to"][sug] += 1
            for f in forms or []:
                d["forms"][f] += 1
            _touch(d, "link_validator", rid, when, entry_id)

    scope = _scope(EntityMaintenanceLog.entity_id, EntityMaintenanceLog.id, page_rows["entity_maintenance"])
    if maint_actions and scope is not None:
        mq = select(
            EntityMaintenanceLog.id,
            EntityMaintenanceLog.entity_type,
            EntityMaintenanceLog.entity_id,
            EntityMaintenanceLog.action,
            EntityMaintenanceLog.created_at,
            EntityMaintenanceLog.before,
            EntityMaintenanceLog.after,
        ).where(
            EntityMaintenanceLog.applied.is_(False),
            EntityMaintenanceLog.action.in_(sorted(maint_actions)),
            scope,
        )
        if origin:
            mq = mq.where(_maint_origin_clause(origin))
        for rid, etype, eid, act, when, before, after in (await db.execute(mq)).all():
            d = detail.get(_group_key(etype, eid, "entity_maintenance", rid))
            if d is None:
                continue
            before = before or {}
            after = after or {}
            d["kinds"][act] += 1
            if act == ACTION_RECLASSIFY and after.get("suggested_type") and after["suggested_type"] != etype:
                d["reclassify_to"][after["suggested_type"]] += 1
            if act == ACTION_MERGE and after.get("target_id"):
                tkey = str(after["target_id"])
                m = d["merge_into"].setdefault(
                    tkey,
                    {
                        "target_type": after.get("target_type") or etype,
                        "target_id": tkey,
                        "name": after.get("merge_into"),
                        "count": 0,
                    },
                )
                m["count"] += 1
            junction = before.get("junction") if isinstance(before.get("junction"), dict) else {}
            for f in junction.get("matched_names") or []:
                d["forms"][f] += 1
            entry_id = None
            if before.get("entry_id"):
                try:
                    entry_id = uuid.UUID(str(before["entry_id"]))
                except ValueError:
                    entry_id = None
            _touch(d, "entity_maintenance", rid, when, entry_id)

    # The newest row of each visible group, for its subject / reason / links.
    link_ids = [d["latest"][1] for d in detail.values() if d["latest"] and d["latest"][0] == "link_validator"]
    maint_ids = [d["latest"][1] for d in detail.values() if d["latest"] and d["latest"][0] == "entity_maintenance"]
    latest_rows: dict[tuple[str, uuid.UUID], tuple[str | None, str | None, list[FeedLink]]] = {}
    if link_ids:
        for r in (
            await db.execute(select(EntityLinkValidationLog).where(EntityLinkValidationLog.id.in_(link_ids)))
        ).scalars():
            links: list[FeedLink] = []
            if r.entry_id:
                links.append(FeedLink(kind="entry", entity_id=str(r.entry_id), label="source entry"))
            latest_rows[("link_validator", r.id)] = (_link_subject(r), r.reason, links)
    if maint_ids:
        for r in (
            await db.execute(select(EntityMaintenanceLog).where(EntityMaintenanceLog.id.in_(maint_ids)))
        ).scalars():
            latest_rows[("entity_maintenance", r.id)] = (_maint_subject(r), r.reasoning, _maint_links(r))

    out: list[ReviewGroup] = []
    for g in page:
        d = detail[g["key"]]
        subject, reason, links = latest_rows.get(d["latest"], (None, None, []))
        if g["entity_id"] is None and not g["name"]:
            g["name"] = subject or g["entity_type"]
        origins = g["origins"]
        out.append(
            ReviewGroup(
                key=g["key"],
                entity_type=g["entity_type"],
                entity_id=g["entity_id"],
                name=g["name"],
                exists=g["exists"],
                linked=g["linked"],
                proposals=g["proposals"],
                kinds=[
                    ReviewGroupKind(action=a, count=n)
                    for a, n in sorted(d["kinds"].items(), key=lambda kv: (-kv[1], kv[0]))
                ],
                reclassify_to=[
                    ReviewGroupTarget(type=t, count=n)
                    for t, n in sorted(d["reclassify_to"].items(), key=lambda kv: (-kv[1], kv[0]))
                ],
                merge_into=[ReviewGroupMerge(**m) for m in sorted(d["merge_into"].values(), key=lambda m: -m["count"])],
                domains=sorted(g["domains"]),
                origin=next(iter(origins)) if len(origins) == 1 else "mixed",
                subject=subject,
                reason=reason,
                links=links,
                latest_at=g["latest_at"],
                sample_entry_id=d["sample_entry_id"],
                matched_names=[f for f, _ in sorted(d["forms"].items(), key=lambda kv: -kv[1])][:4],
                row_ids=g["row_ids"],
            )
        )
    return ReviewGroupsResponse(groups=out, total=total, proposals=all_proposals)


class ReviewGroupRef(BaseModel):
    entity_type: str
    entity_id: uuid.UUID | None = None
    row_ids: list[str] = Field(default_factory=list, description="Feed row ids, for a group with no entity")


class ReviewGroupsActionRequest(BaseModel):
    items: list[ReviewGroupRef] = Field(..., min_length=1, max_length=500)


class ReviewGroupsActionResponse(BaseModel):
    entities: int
    cleared_rows: int


@router.post("/admin/hygiene/review-groups/dismiss", response_model=ReviewGroupsActionResponse)
async def dismiss_review_groups(
    body: ReviewGroupsActionRequest = Body(...),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> ReviewGroupsActionResponse:
    """Settle an entity's row the "leave it alone" way: keep its links, keep
    its type (and stop proposing a change), remember a duplicate review's pair
    as two things, and drop every other pending proposal about it. A group
    with no entity dismisses its own rows."""
    entities = cleared = 0
    for it in body.items:
        if it.entity_id is not None:
            if await _has_pending_reclassify(db, it.entity_type, it.entity_id):
                cleared += await dismiss_reclassify(db, it.entity_type, it.entity_id, user.id)
            merges = (
                await db.execute(
                    select(EntityMaintenanceLog).where(
                        EntityMaintenanceLog.action == ACTION_MERGE,
                        EntityMaintenanceLog.applied.is_(False),
                        EntityMaintenanceLog.entity_type == it.entity_type,
                        EntityMaintenanceLog.entity_id == it.entity_id,
                    )
                )
            ).scalars()
            for row in merges:
                await _remember_merge_dismissal(db, row, user.id)
            cleared += await clear_entity_proposals(db, it.entity_type, it.entity_id)
            entities += 1
            continue
        for rid in it.row_ids:
            src, _, raw = rid.partition(":")
            try:
                row_id = uuid.UUID(raw)
            except ValueError:
                raise AppError(code="invalid", message=f"bad row id: {rid}", status_code=400) from None
            model = EntityLinkValidationLog if src == "link_validator" else EntityMaintenanceLog
            row = await db.get(model, row_id)
            if row is None:
                continue
            if model is EntityMaintenanceLog and row.applied:
                continue
            await db.delete(row)
            cleared += 1
    await db.flush()
    return ReviewGroupsActionResponse(entities=entities, cleared_rows=cleared)


async def _has_pending_reclassify(db: AsyncSession, entity_type: str, entity_id: uuid.UUID) -> bool:
    link = (
        await db.execute(
            select(EntityLinkValidationLog.id)
            .where(
                EntityLinkValidationLog.action == "needs_reclassification",
                EntityLinkValidationLog.entity_type == entity_type,
                EntityLinkValidationLog.entity_id == entity_id,
            )
            .limit(1)
        )
    ).first()
    if link:
        return True
    return (
        await db.execute(
            select(EntityMaintenanceLog.id)
            .where(
                EntityMaintenanceLog.action == ACTION_RECLASSIFY,
                EntityMaintenanceLog.applied.is_(False),
                EntityMaintenanceLog.entity_type == entity_type,
                EntityMaintenanceLog.entity_id == entity_id,
            )
            .limit(1)
        )
    ).first() is not None


# ---------------------------------------------------------------------------
# Bulk decisions: one call for a reviewed batch
# ---------------------------------------------------------------------------
#
# A triage pass decides hundreds of rows at once: apply this, dismiss that,
# "this entity is really a product". The per-row endpoints made the client
# pick the right one per action, order reclassifies before their copies, and
# treat a 404 on a copy as success. This endpoint takes the decisions as they
# are and settles duplicates itself.

DECISIONS_MAX = 1000
_DECISION_STATUSES = ("applied", "dismissed", "reclassified", "resolved", "settled", "skipped", "gone", "error")


class ProposalDecision(BaseModel):
    id: str = Field(..., description="Feed row id: '{source}:{log_id}' (source = link_validator | entity_maintenance)")
    decision: str = Field(..., description="'apply', 'dismiss' or 'reclassify:<entity_type>' (the entity, every copy)")


class ProposalDecisionResult(BaseModel):
    id: str
    decision: str
    status: Literal["applied", "dismissed", "reclassified", "resolved", "settled", "skipped", "gone", "error"] = Field(
        description="applied / dismissed / reclassified: done. resolved: the outcome was already reached, the "
        "proposal is closed. settled: an earlier decision in this call already closed it (one reclassify or "
        "dismiss settles every copy). skipped: nothing to do (already applied, informational). gone: no such "
        "proposal. error: see reason."
    )
    reason: str | None = None
    detail: dict = Field(default_factory=dict)


class ProposalDecisionsResponse(BaseModel):
    results: list[ProposalDecisionResult]
    counts: dict[str, int]


class _Parsed(BaseModel):
    index: int
    id: str
    decision: str
    source: str
    log_id: uuid.UUID
    verb: str  # apply | dismiss | reclassify
    target_type: str | None = None


def _parse_decision(i: int, d: ProposalDecision) -> _Parsed | ProposalDecisionResult:
    from app.services.entry_adjudication import RECLASSIFY_TYPES

    src, _, raw = d.id.partition(":")
    dec = d.decision.strip()

    def bad(reason: str) -> ProposalDecisionResult:
        return ProposalDecisionResult(id=d.id, decision=dec, status="error", reason=reason)

    if src not in ("link_validator", "entity_maintenance"):
        return bad("id must be 'link_validator:<uuid>' or 'entity_maintenance:<uuid>'")
    try:
        log_id = uuid.UUID(raw)
    except ValueError:
        return bad("id has no valid uuid")
    verb, _, target = dec.partition(":")
    if verb in ("apply", "dismiss") and not target:
        return _Parsed(index=i, id=d.id, decision=dec, source=src, log_id=log_id, verb=verb)
    if verb == "reclassify" and target in RECLASSIFY_TYPES:
        return _Parsed(index=i, id=d.id, decision=dec, source=src, log_id=log_id, verb=verb, target_type=target)
    if verb == "reclassify":
        return bad(f"reclassify target must be one of {sorted(RECLASSIFY_TYPES)}")
    return bad("decision must be 'apply', 'dismiss' or 'reclassify:<entity_type>'")


async def _load_log_row(db: AsyncSession, source: str, log_id: uuid.UUID):
    model = EntityLinkValidationLog if source == "link_validator" else EntityMaintenanceLog
    return (await db.execute(select(model).where(model.id == log_id))).scalar_one_or_none()


async def _decide_reclassify(
    db: AsyncSession, entity_type: str, entity_id: uuid.UUID, target_type: str, reason: str
) -> tuple[str, str | None, dict]:
    """Reclassify the entity and close every proposal about it."""
    from app.services.entry_adjudication import _reclassify_entity

    outcome = await _reclassify_entity(db, entity_type, entity_id, target_type, reason)
    if not outcome.get("applied"):
        if outcome.get("reason") == "entity gone":
            cleared = await settle_gone_entity(db, entity_type, entity_id)
            return "resolved", "entity gone", {"cleared": cleared}
        raise AppError(code="invalid", message=str(outcome.get("reason")), status_code=400)
    cleared = await clear_reclassify_proposals(db, entity_type, entity_id)
    cleared += await settle_gone_entity(
        db, entity_type, entity_id, successor=_reclassify_successor(target_type, outcome)
    )
    detail = {
        "target_type": target_type,
        "merged_into_existing": bool(outcome.get("merged_into_existing")),
        "cleared": cleared,
    }
    return "reclassified", None, detail


async def _decide_apply_maint(db: AsyncSession, row: EntityMaintenanceLog, user: User) -> tuple[str, str | None, dict]:
    """Apply one maintenance-log proposal through the appliers the per-row buttons use."""
    from app.services.entry_adjudication import apply_adjudication_row

    if row.action in ADJUDICATION_PROPOSAL_ACTIONS:
        outcome = await apply_adjudication_row(db, row)
        status = await settle_adjudication_outcome(db, row, outcome)
        detail = {k: v for k, v in outcome.items() if k not in ("applied", "reason")}
        return status, outcome.get("reason"), detail
    route = {
        "alias_collision": apply_alias_collision,
        "vendor_autolink": apply_vendor_autolink,
        "normalize_name": apply_normalize_name,
        "ttp_malformed_id": apply_id_hygiene,
        "cve_malformed_id": apply_id_hygiene,
        "cve_withdrawn": apply_id_hygiene,
    }.get(row.action)
    if route is not None:
        resp = await route(log_id=row.id, user=user, db=db)
        detail = resp.model_dump(mode="json")
        return ("resolved" if detail.get("skipped") else "applied"), None, detail
    if row.action == "orphan_prune" and row.entity_id:
        resp = await prune_orphans(
            body=PruneOrphansRequest(
                targets=[{"entity_type": row.entity_type, "entity_id": str(row.entity_id)}], mode="apply"
            ),
            user=user,
            db=db,
        )
        if resp.pruned:
            return "applied", None, {"pruned": resp.pruned}
        return "skipped", "no longer an orphan (or already gone)", {}
    raise AppError(code="invalid", message=f"no apply path for {row.action}", status_code=400)


async def _decide_one(
    db: AsyncSession, p: _Parsed, user: User, reclassified: dict[tuple[str, uuid.UUID], str]
) -> tuple[str, str | None, dict]:
    row = await _load_log_row(db, p.source, p.log_id)
    if row is None:
        return "gone", "no such proposal", {}
    is_link = p.source == "link_validator"
    pending = row.action in _LINK_PENDING_ACTIONS if is_link else not row.applied
    if not pending:
        return "skipped", "not pending (already applied)", {}
    key = (row.entity_type, row.entity_id)
    link_reclassify = is_link and row.action == "needs_reclassification"
    maint_reclassify = not is_link and row.action == ACTION_RECLASSIFY

    if p.verb == "reclassify" or (p.verb == "apply" and link_reclassify):
        target = p.target_type or row.suggested_entity_type
        if row.entity_id is None or not target:
            raise AppError(code="invalid", message="row has no entity or no proposed type", status_code=400)
        if key in reclassified:
            if reclassified[key] == target:
                return "settled", "already reclassified in this call", {}
            raise AppError(code="conflict", message=f"already reclassified to {reclassified[key]}", status_code=409)
        out = await _decide_reclassify(db, row.entity_type, row.entity_id, target, row.reason if is_link else "")
        reclassified[key] = target
        return out

    if p.verb == "dismiss":
        if (link_reclassify or maint_reclassify) and row.entity_id:
            # The decision is about the entity: every article's copy goes, and it isn't re-proposed.
            n = await dismiss_reclassify(db, row.entity_type, row.entity_id, user.id)
            return "dismissed", None, {"cleared": n}
        if not is_link:
            await _remember_merge_dismissal(db, row, user.id)
        await db.delete(row)
        return "dismissed", None, {"cleared": 1}

    # apply
    if is_link:
        already = await apply_link_removal_row(db, row)
        return "applied", None, {"already_removed": already}
    status, reason, detail = await _decide_apply_maint(db, row, user)
    if maint_reclassify and status == "applied":
        reclassified[key] = (row.after or {}).get("suggested_type") or ""
    return status, reason, detail


@router.post("/admin/hygiene/decisions", response_model=ProposalDecisionsResponse)
async def decide_proposals(
    body: list[ProposalDecision] = Body(
        ...,
        description=f"Decisions, at most {DECISIONS_MAX}: [{{id: '<source>:<log_id>', decision}}]",
        examples=[
            [
                {"id": "link_validator:3f9d2a1b-8c7e-4f6a-b5d4-0e1c2a3b4d5f", "decision": "apply"},
                {"id": "entity_maintenance:d5b2c8f0-3e4a-4b6c-9d1e-7f8a9b0c1d2e", "decision": "reclassify:tool"},
            ]
        ],
    ),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> ProposalDecisionsResponse:
    """Apply a reviewed batch of decisions on pending proposals, one result per row.

    `apply` runs the row's own applier (link removal, adjudication apply,
    alias trim, vendor link, rename, id fix, orphan prune). `dismiss` deletes
    the proposal; a reclassify dismissal covers the entity and stops new
    filings. `reclassify:<type>` converts the entity (into the same-named
    entity of that type when one exists) and closes every proposal about it.

    Duplicates settle server-side: reclassifies run first, and a row an
    earlier decision already closed comes back `settled`, not as an error.
    An apply whose outcome is already reached closes the proposal
    (`resolved`). Each row is its own savepoint, so one failure doesn't stop
    the rest."""
    if not body:
        raise AppError(code="invalid", message="no decisions", status_code=400)
    if len(body) > DECISIONS_MAX:
        raise AppError(code="invalid", message=f"at most {DECISIONS_MAX} decisions per call", status_code=400)

    results: list[ProposalDecisionResult | None] = [None] * len(body)
    parsed: list[_Parsed] = []
    for i, d in enumerate(body):
        p = _parse_decision(i, d)
        if isinstance(p, ProposalDecisionResult):
            results[i] = p
        else:
            parsed.append(p)

    # Which rows exist now, so a row closed by an earlier decision reads as settled.
    present: set[str] = set()
    for source, model in (("link_validator", EntityLinkValidationLog), ("entity_maintenance", EntityMaintenanceLog)):
        ids = [p.log_id for p in parsed if p.source == source]
        if ids:
            found = (await db.execute(select(model.id).where(model.id.in_(ids)))).scalars()
            present |= {f"{source}:{rid}" for rid in found}

    reclassified: dict[tuple[str, uuid.UUID], str] = {}
    done: set[str] = set()
    for p in sorted(parsed, key=lambda p: (p.verb != "reclassify", p.index)):
        canon = f"{p.source}:{p.log_id}"
        try:
            async with db.begin_nested():
                status, reason, detail = await _decide_one(db, p, user, reclassified)
            if status == "gone" and canon in present:
                status, reason = "settled", "closed by an earlier decision in this call"
            if status == "gone" and canon in done:
                status, reason = "settled", "duplicate of an earlier decision in this call"
        except AppError as e:
            status, reason, detail = "error", e.message, {}
        except Exception as e:  # one bad row must not sink the batch
            status, reason, detail = "error", str(e)[:300], {}
        done.add(canon)
        results[p.index] = ProposalDecisionResult(
            id=p.id, decision=p.decision, status=status, reason=reason, detail=detail
        )
    await db.flush()

    final = [r for r in results if r is not None]
    counts = {s: 0 for s in _DECISION_STATUSES}
    for r in final:
        counts[r.status] += 1
    return ProposalDecisionsResponse(results=final, counts={k: v for k, v in counts.items() if v})


# ---------------------------------------------------------------------------
# Duplicate review on demand
# ---------------------------------------------------------------------------


class ScanDuplicatesResponse(BaseModel):
    dispatched: bool
    already_running: bool = Field(False, description="A run is in progress on the AI worker; nothing was started")


async def _merge_review_running() -> bool:
    """Whether the duplicate review holds its one-run-at-a-time lock."""
    import redis.asyncio as aioredis

    from app.config import settings as app_settings
    from app.services.entity_merge_review import LOCK_KEY

    try:
        r = aioredis.from_url(app_settings.redis_url)
        try:
            return bool(await r.exists(LOCK_KEY))
        finally:
            await r.aclose()
    except Exception:
        return False


@router.post("/admin/hygiene/scan-duplicates", response_model=ScanDuplicatesResponse)
async def scan_duplicates(user: User = Depends(get_admin_user)) -> ScanDuplicatesResponse:
    """Run the daily duplicate review now (the `review-duplicate-entities` job):
    the most likely duplicate pairs of actors, malware and tools go to the model
    on the AI worker, and each 'same' verdict lands here as a Merge proposal.
    Dispatches the job; the candidate search runs on the AI worker."""
    from app.config import settings as app_settings
    from app.workers.entity_maintenance_tasks import review_duplicate_entities

    if max(0, int(app_settings.get("merge_review_batch_size"))) == 0:
        raise AppError(code="disabled", message="Duplicate review is off: set Pairs Per Run above 0", status_code=400)
    if await _merge_review_running():
        return ScanDuplicatesResponse(dispatched=False, already_running=True)
    review_duplicate_entities.apply_async(queue="ai")
    return ScanDuplicatesResponse(dispatched=True)
