import uuid
from collections import Counter, defaultdict
from datetime import UTC, datetime

from fastapi import APIRouter, Body, Depends, Path, Query, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppError
from app.core.pagination import PaginatedResponse
from app.core.security import get_current_user
from app.database import get_db
from app.models.campaign import Campaign, CampaignEntity, CampaignEntry, CampaignSavedSearch, CampaignSource
from app.models.cve import CVE, EntryCVE
from app.models.entry import Entry
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.ransomware import RansomwareVictim
from app.models.saved_search import SavedSearch
from app.models.story_thread import StoryThread, StoryThreadEntry
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.ttp import TTP, EntryTTP
from app.models.user import User
from app.schemas.campaign import (
    CampaignCreate,
    CampaignEntityAdd,
    CampaignEntityResponse,
    CampaignEntriesAdd,
    CampaignEntriesAddResult,
    CampaignEntryAdd,
    CampaignResponse,
    CampaignSavedSearchAdd,
    CampaignSavedSearchResponse,
    CampaignSavedSearchSyncResult,
    CampaignSavedSearchUpdate,
    CampaignSourceAdd,
    CampaignSourceResponse,
    CampaignSourceUpdate,
    CampaignSuggestion,
    CampaignTimelineEntry,
    CampaignUpdate,
)

router = APIRouter()


def _build_campaign_response(
    campaign: Campaign,
    entry_count: int = 0,
    entity_count: int = 0,
    last_activity_at: datetime | None = None,
    first_activity_at: datetime | None = None,
) -> CampaignResponse:
    return CampaignResponse(
        id=campaign.id,
        created_by=campaign.created_by,
        name=campaign.name,
        description=campaign.description,
        status=campaign.status,
        tlp_marking=campaign.tlp_marking,
        start_date=campaign.start_date,
        end_date=campaign.end_date,
        tags=campaign.tags,
        created_at=campaign.created_at,
        updated_at=campaign.updated_at,
        entry_count=entry_count,
        entity_count=entity_count,
        last_activity_at=last_activity_at,
        first_activity_at=first_activity_at,
    )


async def _campaign_response(campaign: Campaign, db: AsyncSession) -> CampaignResponse:
    """Single-campaign helper (used by create/update endpoints)."""
    entry_count = (
        await db.execute(
            select(func.count()).select_from(CampaignEntry).where(CampaignEntry.campaign_id == campaign.id)
        )
    ).scalar() or 0
    entity_count = (
        await db.execute(
            select(func.count()).select_from(CampaignEntity).where(CampaignEntity.campaign_id == campaign.id)
        )
    ).scalar() or 0
    span = (
        await db.execute(
            select(func.min(Entry.published_at), func.max(Entry.published_at))
            .join(CampaignEntry, CampaignEntry.entry_id == Entry.id)
            .where(CampaignEntry.campaign_id == campaign.id)
        )
    ).first()
    first_activity_at, last_activity_at = (span[0], span[1]) if span else (None, None)
    return _build_campaign_response(campaign, entry_count, entity_count, last_activity_at, first_activity_at)


@router.get("", response_model=PaginatedResponse[CampaignResponse])
async def list_campaigns(
    status: str | None = Query(None, description="Filter by campaign status (active, monitoring, closed, historical)."),
    limit: int = Query(50, ge=1, le=500, description="Maximum number of campaigns to return."),
    offset: int = Query(0, ge=0, description="Number of campaigns to skip for pagination."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List campaigns ordered by most recently updated, with per-campaign entry and entity counts."""
    base = select(Campaign)
    count_base = select(func.count()).select_from(Campaign)

    if status:
        base = base.where(Campaign.status == status)
        count_base = count_base.where(Campaign.status == status)

    total = (await db.execute(count_base)).scalar() or 0

    query = base.order_by(Campaign.updated_at.desc()).limit(limit).offset(offset)
    result = await db.execute(query)
    campaigns = result.scalars().all()

    if not campaigns:
        return PaginatedResponse(items=[], total=total, limit=limit, offset=offset, has_more=False)

    # Batch-fetch entry and entity counts to avoid N+1
    campaign_ids = [c.id for c in campaigns]

    entry_counts_q = (
        select(CampaignEntry.campaign_id, func.count())
        .where(CampaignEntry.campaign_id.in_(campaign_ids))
        .group_by(CampaignEntry.campaign_id)
    )
    entity_counts_q = (
        select(CampaignEntity.campaign_id, func.count())
        .where(CampaignEntity.campaign_id.in_(campaign_ids))
        .group_by(CampaignEntity.campaign_id)
    )
    # The span of each campaign's coverage: the newest article is what marks a
    # gone-quiet campaign, and the oldest is what the Started column falls back
    # to when nobody declared a start_date (nothing sets one, so the column was
    # empty on every row).
    span_q = (
        select(CampaignEntry.campaign_id, func.min(Entry.published_at), func.max(Entry.published_at))
        .join(Entry, Entry.id == CampaignEntry.entry_id)
        .where(CampaignEntry.campaign_id.in_(campaign_ids))
        .group_by(CampaignEntry.campaign_id)
    )
    entry_counts = dict((await db.execute(entry_counts_q)).all())
    entity_counts = dict((await db.execute(entity_counts_q)).all())
    spans = {row[0]: (row[1], row[2]) for row in (await db.execute(span_q)).all()}

    items = [
        _build_campaign_response(
            c,
            entry_counts.get(c.id, 0),
            entity_counts.get(c.id, 0),
            spans.get(c.id, (None, None))[1],
            spans.get(c.id, (None, None))[0],
        )
        for c in campaigns
    ]
    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset, has_more=(offset + limit) < total)


@router.post("", response_model=CampaignResponse, status_code=201)
async def create_campaign(
    body: CampaignCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a campaign. Optionally seeds it with entries (entry_ids) and a primary pivot entity
    (e.g. from auto-detect suggestions)."""
    campaign = Campaign(
        created_by=user.id,
        name=body.name,
        description=body.description,
        status=body.status,
        tlp_marking=body.tlp_marking,
        start_date=body.start_date,
        end_date=body.end_date,
        tags=body.tags,
    )
    db.add(campaign)
    await db.flush()

    # Seed entries if provided (e.g. from auto-detect)
    if body.entry_ids:
        for eid in body.entry_ids:
            db.add(
                CampaignEntry(
                    campaign_id=campaign.id,
                    entry_id=eid,
                    added_by=user.id,
                )
            )

    # Seed pivot entity if provided (e.g. from auto-detect)
    if body.pivot_entity:
        pe = body.pivot_entity
        entity_type = pe.get("type")
        entity_id = pe.get("id")
        if entity_type and entity_id:
            import uuid as _uuid

            db.add(
                CampaignEntity(
                    campaign_id=campaign.id,
                    entity_type=entity_type,
                    entity_id=_uuid.UUID(entity_id) if isinstance(entity_id, str) else entity_id,
                    role="primary",
                    added_by=user.id,
                )
            )

    await db.flush()
    await db.refresh(campaign)
    return await _campaign_response(campaign, db)


@router.get("/by-entity/{entity_type}/{entity_id}")
async def get_campaigns_for_entity(
    entity_type: str = Path(..., description="Entity type slug (threat_actor, malware, cve, ttp, …)."),
    entity_id: uuid.UUID = Path(..., description="Entity UUID."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Campaigns this entity belongs to — powers the profile's Snapshot row."""
    result = await db.execute(
        select(Campaign.id, Campaign.name, Campaign.status, CampaignEntity.role)
        .join(CampaignEntity, CampaignEntity.campaign_id == Campaign.id)
        .where(CampaignEntity.entity_type == entity_type, CampaignEntity.entity_id == entity_id)
        .order_by(Campaign.updated_at.desc())
    )
    return [{"id": str(row.id), "name": row.name, "status": row.status, "role": row.role} for row in result.all()]


@router.get("/by-entry/{entry_id}")
async def get_campaigns_for_entry(
    entry_id: uuid.UUID = Path(..., description="Entry UUID."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return campaign IDs that contain a given entry."""
    result = await db.execute(select(CampaignEntry.campaign_id).where(CampaignEntry.entry_id == entry_id))
    campaign_ids = [str(row[0]) for row in result.all()]
    return campaign_ids


@router.get("/{campaign_id}", response_model=CampaignResponse)
async def get_campaign(
    campaign_id: uuid.UUID = Path(..., description="Campaign UUID."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get a single campaign with its entry and entity counts."""
    campaign = await db.get(Campaign, campaign_id)
    if not campaign:
        raise AppError(code="not_found", message="Campaign not found", status_code=404)
    return await _campaign_response(campaign, db)


@router.put("/{campaign_id}", response_model=CampaignResponse)
@router.patch("/{campaign_id}", response_model=CampaignResponse)
async def update_campaign(
    campaign_id: uuid.UUID = Path(..., description="Campaign UUID."),
    body: CampaignUpdate = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update campaign fields. Only non-null fields in the body are applied (PUT and PATCH behave identically)."""
    campaign = await db.get(Campaign, campaign_id)
    if not campaign:
        raise AppError(code="not_found", message="Campaign not found", status_code=404)

    for field in ["name", "description", "status", "tlp_marking", "start_date", "end_date", "tags"]:
        value = getattr(body, field, None)
        if value is not None:
            setattr(campaign, field, value)

    db.add(campaign)
    await db.flush()
    await db.refresh(campaign)
    return await _campaign_response(campaign, db)


@router.delete("/{campaign_id}", status_code=204)
async def delete_campaign(
    campaign_id: uuid.UUID = Path(..., description="Campaign UUID."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete a campaign and its entry/entity/saved-search links. Linked entries/entities are not deleted."""
    campaign = await db.get(Campaign, campaign_id)
    if not campaign:
        raise AppError(code="not_found", message="Campaign not found", status_code=404)
    await db.delete(campaign)
    await db.flush()


@router.post("/{campaign_id}/entries", status_code=201)
async def add_campaign_entry(
    campaign_id: uuid.UUID = Path(..., description="Campaign UUID."),
    body: CampaignEntryAdd = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Add an entry to a campaign, with optional analyst notes. Returns 409 if the entry is already in the campaign."""
    campaign = await db.get(Campaign, campaign_id)
    if not campaign:
        raise AppError(code="not_found", message="Campaign not found", status_code=404)

    existing = await db.get(CampaignEntry, (campaign_id, body.entry_id))
    if existing:
        raise AppError(code="conflict", message="Entry already in campaign", status_code=409)

    entry = CampaignEntry(
        campaign_id=campaign_id,
        entry_id=body.entry_id,
        added_by=user.id,
        notes=body.notes,
    )
    db.add(entry)
    await db.flush()
    return {"status": "added"}


@router.delete("/{campaign_id}/entries/{entry_id}", status_code=204)
async def remove_campaign_entry(
    campaign_id: uuid.UUID = Path(..., description="Campaign UUID."),
    entry_id: uuid.UUID = Path(..., description="Entry UUID."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Remove an entry from a campaign. The entry itself is not deleted."""
    result = await db.execute(
        select(CampaignEntry).where(
            CampaignEntry.campaign_id == campaign_id,
            CampaignEntry.entry_id == entry_id,
        )
    )
    ce = result.scalar_one_or_none()
    if not ce:
        raise AppError(code="not_found", message="Campaign entry not found", status_code=404)
    await db.delete(ce)
    await db.flush()


@router.post("/{campaign_id}/entities", status_code=201)
async def add_campaign_entity(
    campaign_id: uuid.UUID = Path(..., description="Campaign UUID."),
    body: CampaignEntityAdd = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Explicitly link an intelligence entity (ttp, cve, threat_actor, or malware) to a campaign with a role."""
    campaign = await db.get(Campaign, campaign_id)
    if not campaign:
        raise AppError(code="not_found", message="Campaign not found", status_code=404)

    entity = CampaignEntity(
        campaign_id=campaign_id,
        entity_type=body.entity_type,
        entity_id=body.entity_id,
        role=body.role,
        added_by=user.id,
    )
    db.add(entity)
    await db.flush()
    return {"status": "added"}


@router.delete("/{campaign_id}/entities/{entity_id}", status_code=204)
async def remove_campaign_entity(
    campaign_id: uuid.UUID = Path(..., description="Campaign UUID."),
    entity_id: uuid.UUID = Path(
        ..., description="Campaign-entity link UUID (CampaignEntity.id, not the entity's own id)."
    ),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Remove an explicitly linked entity from a campaign. The entity itself is not deleted."""
    result = await db.execute(
        select(CampaignEntity).where(
            CampaignEntity.campaign_id == campaign_id,
            CampaignEntity.id == entity_id,
        )
    )
    ce = result.scalar_one_or_none()
    if not ce:
        raise AppError(code="not_found", message="Campaign entity not found", status_code=404)
    await db.delete(ce)
    await db.flush()


@router.get("/{campaign_id}/entities", response_model=list[CampaignEntityResponse])
async def list_campaign_entities(
    campaign_id: uuid.UUID = Path(..., description="Campaign UUID."),
    entity_type: str | None = Query(
        default=None,
        pattern=r"^(ttp|cve|threat_actor|malware)$",
        description="Filter to a single entity type (ttp, cve, threat_actor, malware).",
    ),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all entities explicitly linked to a campaign with resolved names."""
    campaign = await db.get(Campaign, campaign_id)
    if not campaign:
        raise AppError(code="not_found", message="Campaign not found", status_code=404)

    query = select(CampaignEntity).where(CampaignEntity.campaign_id == campaign_id)
    if entity_type:
        query = query.where(CampaignEntity.entity_type == entity_type)
    query = query.order_by(CampaignEntity.added_at.desc())

    result = await db.execute(query)
    entities = result.scalars().all()

    if not entities:
        return []

    # Group entity IDs by type for batch fetching
    entity_model_map = {
        "threat_actor": ThreatActor,
        "malware": MalwareFamily,
        "cve": CVE,
        "ttp": TTP,
        "ransomware_victim": RansomwareVictim,
    }

    ids_by_type: dict[str, list[uuid.UUID]] = {}
    for ent in entities:
        ids_by_type.setdefault(ent.entity_type, []).append(ent.entity_id)

    # Batch-fetch all referenced entities
    resolved: dict[uuid.UUID, object] = {}
    for etype, ids in ids_by_type.items():
        model_cls = entity_model_map.get(etype)
        if model_cls:
            rows = await db.execute(select(model_cls).where(model_cls.id.in_(ids)))
            for obj in rows.scalars().all():
                resolved[obj.id] = obj

    # Build responses with resolved names
    responses = []
    for ent in entities:
        obj = resolved.get(ent.entity_id)
        if obj is None:
            entity_name = str(ent.entity_id)
        elif ent.entity_type == "ttp":
            prefix = f"{obj.technique_id}: " if getattr(obj, "technique_id", None) else ""
            entity_name = f"{prefix}{obj.technique_name}"
        elif ent.entity_type == "cve":
            entity_name = obj.cve_id
        else:
            entity_name = getattr(obj, "name", str(ent.entity_id))

        responses.append(
            CampaignEntityResponse(
                id=ent.id,
                campaign_id=ent.campaign_id,
                entity_type=ent.entity_type,
                entity_id=ent.entity_id,
                entity_name=entity_name,
                role=ent.role,
                added_at=ent.added_at,
            )
        )

    return responses


# --- Extension Endpoints ---


@router.get("/{campaign_id}/timeline", response_model=list[CampaignTimelineEntry])
async def get_campaign_timeline(
    campaign_id: uuid.UUID = Path(..., description="Campaign UUID."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get campaign entries sorted chronologically for timeline display.

    Each row carries its story thread when the sweeper has folded it into one,
    so the timeline can render waves of coverage rather than a flat article
    list. Entries the sweeper never threaded (pre-embeddings articles, hand-added
    advisories, anything that clustered with nothing) come back unthreaded and
    stand on their own.
    """
    campaign = await db.get(Campaign, campaign_id)
    if not campaign:
        raise AppError(code="not_found", message="Campaign not found", status_code=404)

    result = await db.execute(
        select(
            Entry.id,
            Entry.title,
            Entry.url,
            Entry.published_at,
            CampaignEntry.notes,
            StoryThread.id.label("thread_id"),
            StoryThread.slug.label("thread_slug"),
            StoryThread.title.label("thread_title"),
            StoryThreadEntry.role.label("thread_role"),
        )
        .join(CampaignEntry, CampaignEntry.entry_id == Entry.id)
        .outerjoin(StoryThreadEntry, StoryThreadEntry.entry_id == Entry.id)
        .outerjoin(StoryThread, StoryThread.id == StoryThreadEntry.thread_id)
        .where(CampaignEntry.campaign_id == campaign_id)
        .order_by(Entry.published_at.desc().nullslast())
    )

    return [
        CampaignTimelineEntry(
            entry_id=row.id,
            title=row.title,
            url=row.url,
            published_at=row.published_at,
            notes=row.notes,
            thread_id=row.thread_id,
            thread_slug=row.thread_slug,
            thread_title=row.thread_title,
            thread_role=row.thread_role,
        )
        for row in result.all()
    ]


@router.get("/{campaign_id}/attack-layer")
async def get_campaign_attack_layer(
    campaign_id: uuid.UUID = Path(..., description="Campaign UUID."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate ATT&CK Navigator JSON for campaign TTPs."""
    from app.intelligence.ttp import generate_navigator_layer

    campaign = await db.get(Campaign, campaign_id)
    if not campaign:
        raise AppError(code="not_found", message="Campaign not found", status_code=404)

    # Get all TTPs from campaign entries
    result = await db.execute(
        select(TTP.technique_id, TTP.technique_name, TTP.tactic, EntryTTP.confidence)
        .join(EntryTTP, EntryTTP.ttp_id == TTP.id)
        .join(CampaignEntry, CampaignEntry.entry_id == EntryTTP.entry_id)
        .where(CampaignEntry.campaign_id == campaign_id)
        .distinct()
    )

    # The same technique can appear across multiple entries with different
    # confidence values — dedupe by technique_id, keeping the highest confidence.
    confidence_rank = {"low": 0, "medium": 1, "high": 2}
    by_technique: dict[str, dict] = {}
    for row in result.all():
        candidate = {
            "technique_id": row.technique_id,
            "technique_name": row.technique_name,
            "tactic": row.tactic,
            "confidence": row.confidence,
        }
        existing = by_technique.get(row.technique_id)
        if existing is None or (
            confidence_rank.get(row.confidence or "medium", 1)
            > confidence_rank.get(existing["confidence"] or "medium", 1)
        ):
            by_technique[row.technique_id] = candidate

    ttps = list(by_technique.values())

    return generate_navigator_layer(ttps, title=campaign.name)


@router.get("/{campaign_id}/detection-gaps")
async def get_campaign_detection_gaps(
    campaign_id: uuid.UUID = Path(..., description="Campaign UUID."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Telemetry-aware detection coverage for the campaign's techniques.

    A technique is only "covered" when a non-draft rule references it AND that
    rule's required data sources are satisfiable by the enabled telemetry
    inventory. Rules blocked by missing telemetry land in "library_only".
    """
    from app.services.detection_coverage import (
        STATUS_COVERED,
        STATUS_LIBRARY_ONLY,
        classify_techniques,
    )

    campaign = await db.get(Campaign, campaign_id)
    if not campaign:
        raise AppError(code="not_found", message="Campaign not found", status_code=404)

    # Get all TTPs from campaign entries
    result = await db.execute(
        select(TTP.id, TTP.technique_id, TTP.technique_name, TTP.tactic)
        .join(EntryTTP, EntryTTP.ttp_id == TTP.id)
        .join(CampaignEntry, CampaignEntry.entry_id == EntryTTP.entry_id)
        .where(CampaignEntry.campaign_id == campaign_id)
        .distinct()
    )
    campaign_ttps = result.all()

    classification = await classify_techniques(db, [row.technique_id for row in campaign_ttps])

    gaps = []
    library_only = []
    covered = []
    for ttp_row in campaign_ttps:
        info = classification.get(ttp_row.technique_id) or {}
        entry = {
            "ttp_id": str(ttp_row.id),
            "technique_id": ttp_row.technique_id,
            "technique_name": ttp_row.technique_name,
            "tactic": ttp_row.tactic,
            "rule_count": info.get("rule_count", 0),
        }
        status = info.get("status")
        if status == STATUS_COVERED:
            entry["rules"] = info["rules"]
            covered.append(entry)
        elif status == STATUS_LIBRARY_ONLY:
            entry["rules"] = info["rules"]
            entry["missing_data_sources"] = info["missing_data_sources"]
            library_only.append(entry)
        else:
            gaps.append(entry)

    total = len(campaign_ttps)
    return {
        "total_ttps": total,
        "covered_count": len(covered),
        "library_only_count": len(library_only),
        "no_rule_count": len(gaps),
        "gap_count": len(gaps),
        "coverage_percentage": round(len(covered) / total * 100, 1) if total > 0 else 0,
        "gaps": gaps,
        "library_only": library_only,
        "covered": covered,
    }


@router.get("/{campaign_id}/export")
async def export_campaign(
    campaign_id: uuid.UUID = Path(..., description="Campaign UUID."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Export complete campaign intel package as a JSON bundle.

    Includes: campaign metadata, entries, IOCs, TTPs, CVEs, actors, malware,
    detection rules, and ATT&CK layer.
    """
    from app.models.cve import CVE
    from app.models.detection_rule import DetectionRule

    campaign = await db.get(Campaign, campaign_id)
    if not campaign:
        raise AppError(code="not_found", message="Campaign not found", status_code=404)

    # Campaign entries
    entry_result = await db.execute(
        select(Entry.id, Entry.title, Entry.url, Entry.published_at, CampaignEntry.notes)
        .join(CampaignEntry, CampaignEntry.entry_id == Entry.id)
        .where(CampaignEntry.campaign_id == campaign_id)
        .order_by(Entry.published_at.asc().nullslast())
    )
    entries = [
        {
            "id": str(r.id),
            "title": r.title,
            "url": r.url,
            "published_at": r.published_at.isoformat() if r.published_at else None,
            "notes": r.notes,
        }
        for r in entry_result.all()
    ]
    entry_ids = [uuid.UUID(e["id"]) for e in entries]

    # TTPs
    ttp_result = await db.execute(
        select(TTP).join(EntryTTP, EntryTTP.ttp_id == TTP.id).where(EntryTTP.entry_id.in_(entry_ids)).distinct()
    )
    ttps = [
        {"id": str(t.id), "technique_id": t.technique_id, "technique_name": t.technique_name, "tactic": t.tactic}
        for t in ttp_result.scalars().all()
    ]

    # CVEs
    from app.models.cve import EntryCVE as EntryCVEModel

    cve_result = await db.execute(
        select(CVE)
        .join(EntryCVEModel, EntryCVEModel.cve_id == CVE.id)
        .where(EntryCVEModel.entry_id.in_(entry_ids))
        .distinct()
    )
    cves = [
        {
            "id": str(c.id),
            "cve_id": c.cve_id,
            "cvss_score": float(c.cvss_score) if c.cvss_score else None,
            "severity": c.severity,
            "epss_score": c.epss_score,
        }
        for c in cve_result.scalars().all()
    ]

    # Threat actors
    from app.models.threat_actor import ThreatActor as TAModel

    actor_result = await db.execute(
        select(TAModel)
        .join(EntryThreatActor, EntryThreatActor.threat_actor_id == TAModel.id)
        .where(EntryThreatActor.entry_id.in_(entry_ids))
        .distinct()
    )
    actors = [
        {"id": str(a.id), "name": a.name, "aliases": a.aliases, "country": a.country}
        for a in actor_result.scalars().all()
    ]

    # Malware
    from app.models.malware_family import MalwareFamily as MWModel

    mw_result = await db.execute(
        select(MWModel)
        .join(EntryMalware, EntryMalware.malware_family_id == MWModel.id)
        .where(EntryMalware.entry_id.in_(entry_ids))
        .distinct()
    )
    malware_list = [
        {"id": str(m.id), "name": m.name, "aliases": m.aliases, "malware_type": m.malware_type}
        for m in mw_result.scalars().all()
    ]

    # Detection rules linked to campaign
    rule_result = await db.execute(select(DetectionRule).where(DetectionRule.source_campaigns.any(campaign_id)))
    rules = [
        {
            "id": str(r.id),
            "name": r.title,
            "rule_type": r.rule_type,
            "rule_content": r.rule_content,
            "is_draft": r.is_draft,
        }
        for r in rule_result.scalars().all()
    ]

    return {
        "campaign": {
            "id": str(campaign.id),
            "name": campaign.name,
            "description": campaign.description,
            "status": campaign.status,
            "tlp_marking": campaign.tlp_marking,
            "start_date": campaign.start_date.isoformat() if campaign.start_date else None,
            "end_date": campaign.end_date.isoformat() if campaign.end_date else None,
            "tags": campaign.tags,
        },
        "entries": entries,
        "ttps": ttps,
        "cves": cves,
        "threat_actors": actors,
        "malware": malware_list,
        "detection_rules": rules,
        "stats": {
            "entry_count": len(entries),
            "ttp_count": len(ttps),
            "cve_count": len(cves),
            "actor_count": len(actors),
            "malware_count": len(malware_list),
            "rule_count": len(rules),
        },
    }


@router.get("/{campaign_id}/suggest", response_model=list[CampaignSuggestion])
async def suggest_campaign_entries(
    campaign_id: uuid.UUID = Path(..., description="Campaign UUID."),
    min_overlap: int = Query(3, ge=1, le=10, description="Minimum shared entities an entry needs to be suggested."),
    limit: int = Query(20, ge=1, le=500, description="Maximum number of suggestions to return."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Suggest entries to add: the rest of stories the campaign already holds, then entity matches.

    Two reasons an entry is offered. ``same_story`` — the campaign already holds
    part of the story this article belongs to, which is the surest match there
    is and needs no entity overlap at all (the tenth article about a breach may
    name nothing extractable the first nine did not). ``shared_entities`` — the
    older heuristic, for coverage that never clustered into a story.
    """
    campaign = await db.get(Campaign, campaign_id)
    if not campaign:
        raise AppError(code="not_found", message="Campaign not found", status_code=404)

    campaign_entry_result = await db.execute(
        select(CampaignEntry.entry_id).where(CampaignEntry.campaign_id == campaign_id)
    )
    campaign_entry_ids = {row[0] for row in campaign_entry_result.all()}

    if not campaign_entry_ids:
        return []

    # --- The rest of the stories the campaign is already part of ---
    held_threads = (
        (
            await db.execute(
                select(StoryThreadEntry.thread_id).where(StoryThreadEntry.entry_id.in_(campaign_entry_ids)).distinct()
            )
        )
        .scalars()
        .all()
    )

    same_story: dict[uuid.UUID, uuid.UUID] = {}
    if held_threads:
        missing = await db.execute(
            select(StoryThreadEntry.entry_id, StoryThreadEntry.thread_id).where(
                StoryThreadEntry.thread_id.in_(held_threads),
                StoryThreadEntry.entry_id.notin_(campaign_entry_ids),
            )
        )
        same_story = {entry_id: thread_id for entry_id, thread_id in missing.all()}

    # --- Entries sharing entities with the campaign ---
    campaign_entities: set[tuple[str, uuid.UUID]] = set()
    junctions = {
        "ttp": (EntryTTP, EntryTTP.ttp_id),
        "cve": (EntryCVE, EntryCVE.cve_id),
        "threat_actor": (EntryThreatActor, EntryThreatActor.threat_actor_id),
        "malware": (EntryMalware, EntryMalware.malware_family_id),
    }

    for entity_type, (table, id_col) in junctions.items():
        result = await db.execute(select(id_col).where(table.entry_id.in_(campaign_entry_ids)).distinct())
        for row in result.all():
            campaign_entities.add((entity_type, row[0]))

    candidate_counts: Counter[uuid.UUID] = Counter()
    candidate_overlaps: dict[uuid.UUID, list[dict]] = defaultdict(list)

    for entity_type, entity_id in campaign_entities:
        table, id_col = junctions[entity_type]
        result = await db.execute(select(table.entry_id).where(id_col == entity_id))
        for row in result.all():
            eid = row[0]
            if eid not in campaign_entry_ids:
                candidate_counts[eid] += 1
                candidate_overlaps[eid].append({"type": entity_type, "label": str(entity_id)})

    # Same-story entries are offered whatever their overlap: the story is the
    # evidence. Everything else still has to clear min_overlap.
    qualifying: list[uuid.UUID] = list(same_story)
    qualifying += [
        eid for eid, count in candidate_counts.most_common() if count >= min_overlap and eid not in same_story
    ]
    if not qualifying:
        return []

    # --- Annotate with the story each suggestion belongs to ---
    thread_rows = await db.execute(
        select(
            StoryThreadEntry.entry_id,
            StoryThreadEntry.role,
            StoryThread.id,
            StoryThread.slug,
            StoryThread.title,
            StoryThread.entry_count,
        )
        .join(StoryThread, StoryThread.id == StoryThreadEntry.thread_id)
        .where(StoryThreadEntry.entry_id.in_(qualifying))
    )
    threads = {row.entry_id: row for row in thread_rows.all()}

    # How much of each story the campaign already holds — the "you have 2 of 9" half.
    held_counts: dict[uuid.UUID, int] = {}
    if held_threads:
        held_rows = await db.execute(
            select(StoryThreadEntry.thread_id, func.count())
            .where(
                StoryThreadEntry.thread_id.in_(held_threads),
                StoryThreadEntry.entry_id.in_(campaign_entry_ids),
            )
            .group_by(StoryThreadEntry.thread_id)
        )
        held_counts = dict(held_rows.all())

    entries = {e.id: e for e in (await db.execute(select(Entry).where(Entry.id.in_(qualifying)))).scalars().all()}

    suggestions = []
    for eid in qualifying:
        entry = entries.get(eid)
        if not entry:
            continue
        thread = threads.get(eid)
        suggestions.append(
            CampaignSuggestion(
                entry_id=entry.id,
                title=entry.title,
                url=entry.url,
                published_at=entry.published_at,
                overlap_count=candidate_counts.get(eid, 0),
                overlapping_entities=candidate_overlaps.get(eid, [])[:5],
                reason="same_story" if eid in same_story else "shared_entities",
                thread_id=thread.id if thread else None,
                thread_slug=thread.slug if thread else None,
                thread_title=thread.title if thread else None,
                thread_role=thread.role if thread else None,
                thread_article_count=thread.entry_count if thread else None,
                thread_in_campaign=held_counts.get(thread.id, 0) if thread else None,
            )
        )

    # Surest first: the rest of a story you already track, then the heaviest
    # entity matches.
    suggestions.sort(key=lambda s: (s.reason != "same_story", -s.overlap_count))
    return suggestions[:limit]


@router.post("/{campaign_id}/entries/bulk", response_model=CampaignEntriesAddResult, status_code=201)
async def add_campaign_entries(
    campaign_id: uuid.UUID = Path(..., description="Campaign UUID."),
    body: CampaignEntriesAdd = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Add several entries at once — adding a whole story is one action, not nine.

    Entries already in the campaign are skipped rather than conflicting, so
    re-adding a story that grew since you last looked does the right thing.
    """
    campaign = await db.get(Campaign, campaign_id)
    if not campaign:
        raise AppError(code="not_found", message="Campaign not found", status_code=404)

    wanted = set(body.entry_ids)
    if not wanted:
        return CampaignEntriesAddResult(added=0, skipped=0)

    existing = set(
        (
            await db.execute(
                select(CampaignEntry.entry_id).where(
                    CampaignEntry.campaign_id == campaign_id, CampaignEntry.entry_id.in_(wanted)
                )
            )
        )
        .scalars()
        .all()
    )
    # An id that matches no entry would violate the foreign key and take the
    # whole batch down with it.
    real = set((await db.execute(select(Entry.id).where(Entry.id.in_(wanted - existing)))).scalars().all())

    for entry_id in real:
        db.add(
            CampaignEntry(
                campaign_id=campaign_id,
                entry_id=entry_id,
                added_by=user.id,
                notes=body.notes,
            )
        )
    await db.flush()
    return CampaignEntriesAddResult(added=len(real), skipped=len(wanted) - len(real))


# --- Campaign Saved Searches ---


@router.get("/{campaign_id}/saved-searches", response_model=list[CampaignSavedSearchResponse])
async def list_campaign_saved_searches(
    campaign_id: uuid.UUID = Path(..., description="Campaign UUID."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List saved searches linked to a campaign."""
    campaign = await db.get(Campaign, campaign_id)
    if not campaign:
        raise AppError(code="not_found", message="Campaign not found", status_code=404)

    result = await db.execute(
        select(CampaignSavedSearch, SavedSearch.name, SavedSearch.query)
        .join(SavedSearch, SavedSearch.id == CampaignSavedSearch.saved_search_id)
        .where(CampaignSavedSearch.campaign_id == campaign_id)
        .order_by(CampaignSavedSearch.created_at.desc())
    )

    return [
        CampaignSavedSearchResponse(
            id=css.id,
            campaign_id=css.campaign_id,
            saved_search_id=css.saved_search_id,
            saved_search_name=name,
            saved_search_query=query,
            auto_sync=css.auto_sync,
            last_synced_at=css.last_synced_at,
            entries_added=css.entries_added,
            created_at=css.created_at,
        )
        for css, name, query in result.all()
    ]


@router.post("/{campaign_id}/saved-searches", response_model=CampaignSavedSearchResponse, status_code=201)
async def add_campaign_saved_search(
    campaign_id: uuid.UUID = Path(..., description="Campaign UUID."),
    body: CampaignSavedSearchAdd = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Link a saved search to a campaign. Optionally syncs matching entries immediately."""
    campaign = await db.get(Campaign, campaign_id)
    if not campaign:
        raise AppError(code="not_found", message="Campaign not found", status_code=404)

    saved_search = await db.execute(select(SavedSearch).where(SavedSearch.id == body.saved_search_id))
    ss = saved_search.scalar_one_or_none()
    if not ss:
        raise AppError(code="not_found", message="Saved search not found", status_code=404)

    # Check for duplicate
    existing = await db.execute(
        select(CampaignSavedSearch).where(
            CampaignSavedSearch.campaign_id == campaign_id,
            CampaignSavedSearch.saved_search_id == body.saved_search_id,
        )
    )
    if existing.scalar_one_or_none():
        raise AppError(code="conflict", message="Saved search already linked to this campaign", status_code=409)

    css = CampaignSavedSearch(
        campaign_id=campaign_id,
        saved_search_id=body.saved_search_id,
        auto_sync=body.auto_sync,
        added_by=user.id,
    )
    db.add(css)
    await db.flush()
    await db.refresh(css)

    return CampaignSavedSearchResponse(
        id=css.id,
        campaign_id=css.campaign_id,
        saved_search_id=css.saved_search_id,
        saved_search_name=ss.name,
        saved_search_query=ss.query,
        auto_sync=css.auto_sync,
        last_synced_at=css.last_synced_at,
        entries_added=css.entries_added,
        created_at=css.created_at,
    )


@router.patch("/{campaign_id}/saved-searches/{css_id}", response_model=CampaignSavedSearchResponse)
async def update_campaign_saved_search(
    campaign_id: uuid.UUID = Path(..., description="Campaign UUID."),
    css_id: uuid.UUID = Path(..., description="Campaign saved-search link UUID."),
    body: CampaignSavedSearchUpdate = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update a campaign saved search link (e.g. toggle auto_sync)."""
    result = await db.execute(
        select(CampaignSavedSearch).where(
            CampaignSavedSearch.id == css_id,
            CampaignSavedSearch.campaign_id == campaign_id,
        )
    )
    css = result.scalar_one_or_none()
    if not css:
        raise AppError(code="not_found", message="Campaign saved search not found", status_code=404)

    css.auto_sync = body.auto_sync
    db.add(css)
    await db.flush()
    await db.refresh(css)

    ss = await db.get(SavedSearch, css.saved_search_id)
    return CampaignSavedSearchResponse(
        id=css.id,
        campaign_id=css.campaign_id,
        saved_search_id=css.saved_search_id,
        saved_search_name=ss.name if ss else "",
        saved_search_query=ss.query if ss else None,
        auto_sync=css.auto_sync,
        last_synced_at=css.last_synced_at,
        entries_added=css.entries_added,
        created_at=css.created_at,
    )


@router.delete("/{campaign_id}/saved-searches/{css_id}", status_code=204)
async def remove_campaign_saved_search(
    campaign_id: uuid.UUID = Path(..., description="Campaign UUID."),
    css_id: uuid.UUID = Path(..., description="Campaign saved-search link UUID."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Unlink a saved search from a campaign. Does not remove entries already added."""
    result = await db.execute(
        select(CampaignSavedSearch).where(
            CampaignSavedSearch.id == css_id,
            CampaignSavedSearch.campaign_id == campaign_id,
        )
    )
    css = result.scalar_one_or_none()
    if not css:
        raise AppError(code="not_found", message="Campaign saved search not found", status_code=404)
    await db.delete(css)
    await db.flush()


@router.post("/{campaign_id}/saved-searches/{css_id}/sync", response_model=CampaignSavedSearchSyncResult)
async def sync_campaign_saved_search(
    campaign_id: uuid.UUID = Path(..., description="Campaign UUID."),
    css_id: uuid.UUID = Path(..., description="Campaign saved-search link UUID."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Execute the saved search and add any new matching entries to the campaign."""
    import asyncio
    from datetime import datetime

    from app.search.meili_builder import execute_entry_search
    from app.search.query_parser import ParseError, parse_query
    from app.search.query_planner import build_execution_plan, resolve_deferred_filters

    result = await db.execute(
        select(CampaignSavedSearch).where(
            CampaignSavedSearch.id == css_id,
            CampaignSavedSearch.campaign_id == campaign_id,
        )
    )
    css = result.scalar_one_or_none()
    if not css:
        raise AppError(code="not_found", message="Campaign saved search not found", status_code=404)

    ss = await db.get(SavedSearch, css.saved_search_id)
    if not ss:
        raise AppError(code="not_found", message="Saved search not found", status_code=404)

    query_str = ss.query or ss.name or ""
    if not query_str.strip():
        raise AppError(code="bad_request", message="Saved search has no query", status_code=400)

    try:
        ast = parse_query(query_str)
    except ParseError:
        raise AppError(code="bad_request", message="Failed to parse saved search query", status_code=400)

    plan = build_execution_plan(ast)
    # `feed:`, `category:` and the rest are answered from Postgres; without this
    # they were silently dropped from a campaign sync.
    await resolve_deferred_filters(db, plan)

    # Fetch up to 1000 matching entry IDs
    constraint = list(plan.db_entry_ids) if plan.db_entry_ids is not None else None
    search_result = await asyncio.to_thread(execute_entry_search, plan, constraint, 1000, 0)
    hit_ids = [hit["id"] for hit in search_result.get("hits", []) if "id" in hit]

    if not hit_ids:
        css.last_synced_at = datetime.now(UTC)
        db.add(css)
        await db.flush()
        return CampaignSavedSearchSyncResult(
            saved_search_id=css.saved_search_id,
            new_entries_added=0,
            total_entries=search_result.get("estimatedTotalHits", 0),
        )

    # Get entry IDs already in campaign
    existing_result = await db.execute(select(CampaignEntry.entry_id).where(CampaignEntry.campaign_id == campaign_id))
    existing_ids = {str(row[0]) for row in existing_result.all()}

    # Add new entries
    new_count = 0
    for eid_str in hit_ids:
        if eid_str not in existing_ids:
            try:
                entry_uuid = uuid.UUID(eid_str)
            except ValueError:
                continue
            db.add(
                CampaignEntry(
                    campaign_id=campaign_id,
                    entry_id=entry_uuid,
                    added_by=user.id,
                    notes=f"Auto-added from saved search: {ss.name}",
                )
            )
            new_count += 1

    css.last_synced_at = datetime.now(UTC)
    css.entries_added = css.entries_added + new_count
    db.add(css)
    await db.flush()

    return CampaignSavedSearchSyncResult(
        saved_search_id=css.saved_search_id,
        new_entries_added=new_count,
        total_entries=search_result.get("estimatedTotalHits", 0),
    )


# A campaign is something you track for months; a single burst of coverage is
# just today's news. A thread-backed candidate has to show duration — either the
# entity carried more than one story, or one story kept moving for a week — or
# be a genuinely large single story (``min_entries`` doubled).
THREAD_SUSTAINED_DAYS = 7

# A key entity named in one member out of twenty is incidental to that story,
# not its subject.
THREAD_KEY_ENTITY_MIN = 2


async def _thread_campaign_candidates(
    db: AsyncSession,
    cutoff: datetime,
    min_entries: int,
    existing_entities: set[tuple[str, uuid.UUID]],
) -> list[dict]:
    """Campaign candidates seeded from story threads.

    Counting "this actor appeared in 3 entries in 30 days" cannot tell a story
    that ran for a fortnight from three unrelated mentions. Threads already know
    which articles are the same story, so an entity carrying several of them —
    or one that kept moving — is the candidate worth offering.
    """
    from sqlalchemy import text as _text

    threads = (
        (
            await db.execute(
                _text(
                    """
                SELECT id, slug, title, entry_count, source_count,
                       first_seen, last_seen, key_entities
                FROM story_threads
                WHERE last_seen >= :cutoff AND entry_count >= 2
                """
                ),
                {"cutoff": cutoff},
            )
        )
        .mappings()
        .all()
    )
    if not threads:
        return []

    # entity -> the threads it carries
    carried: dict[tuple[str, uuid.UUID], list[dict]] = defaultdict(list)
    for thread in threads:
        for entity in thread["key_entities"] or []:
            if entity.get("entity_type") not in ("threat_actor", "malware"):
                continue
            if (entity.get("count") or 0) < THREAD_KEY_ENTITY_MIN:
                continue
            try:
                entity_uuid = uuid.UUID(str(entity["entity_id"]))
            except (ValueError, KeyError, TypeError):
                continue
            key = (entity["entity_type"], entity_uuid)
            if key in existing_entities:
                continue
            carried[key].append(dict(thread))

    if not carried:
        return []

    # Member articles for every thread in play, in one pass.
    thread_ids = list({t["id"] for threads_ in carried.values() for t in threads_})
    members: dict[uuid.UUID, list[uuid.UUID]] = defaultdict(list)
    member_rows = await db.execute(
        _text(
            """
            SELECT ste.thread_id, ste.entry_id
            FROM story_thread_entries ste
            WHERE ste.thread_id = ANY(:ids)
            """
        ),
        {"ids": thread_ids},
    )
    for thread_id, entry_id in member_rows.all():
        members[thread_id].append(entry_id)

    candidates: list[dict] = []
    for (entity_type, entity_id), entity_threads in carried.items():
        entry_ids: set[uuid.UUID] = set()
        for thread in entity_threads:
            entry_ids.update(members.get(thread["id"], []))
        if len(entry_ids) < min_entries:
            continue

        seen = [t["first_seen"] for t in entity_threads if t["first_seen"]]
        last = [t["last_seen"] for t in entity_threads if t["last_seen"]]
        span_days = int(((max(last) - min(seen)).days) if seen and last else 0)
        sustained = len(entity_threads) >= 2 or span_days >= THREAD_SUSTAINED_DAYS or len(entry_ids) >= min_entries * 2
        if not sustained:
            continue

        model = ThreatActor if entity_type == "threat_actor" else MalwareFamily
        entity = await db.get(model, entity_id)
        if not entity:
            continue

        sample_result = await db.execute(
            select(Entry.id, Entry.title, Entry.published_at)
            .where(Entry.id.in_(entry_ids))
            .order_by(Entry.published_at.desc().nullslast())
            .limit(5)
        )
        suffix = "Activity" if entity_type == "threat_actor" else "Campaign"
        candidates.append(
            {
                "suggested_name": f"{entity.name} {suffix}",
                "pivot_entity": {"type": entity_type, "id": str(entity_id), "name": entity.name},
                "entry_count": len(entry_ids),
                "entry_ids": [str(e) for e in entry_ids],
                "sample_entries": [
                    {
                        "id": str(r.id),
                        "title": r.title,
                        "published_at": r.published_at.isoformat() if r.published_at else None,
                    }
                    for r in sample_result.all()
                ],
                "evidence": "story_threads",
                "thread_count": len(entity_threads),
                "span_days": span_days,
                "source_count": max((t["source_count"] or 0) for t in entity_threads),
                "threads": sorted(
                    (
                        {
                            "slug": t["slug"],
                            "title": t["title"],
                            "entry_count": t["entry_count"],
                            "first_seen": t["first_seen"].isoformat() if t["first_seen"] else None,
                            "last_seen": t["last_seen"].isoformat() if t["last_seen"] else None,
                        }
                        for t in entity_threads
                    ),
                    key=lambda t: t["last_seen"] or "",
                    reverse=True,
                ),
            }
        )

    candidates.sort(key=lambda c: (c["thread_count"], c["span_days"], c["entry_count"]), reverse=True)
    return candidates


@router.post("/auto-detect")
async def auto_detect_campaigns(
    min_entries: int = Query(
        3, ge=2, le=20, description="Minimum number of recent entries an entity needs to become a candidate."
    ),
    days: int = Query(30, ge=7, le=365, description="Look-back window in days for recent entries."),
    limit: int = Query(20, ge=1, le=100, description="Maximum number of campaign suggestions to return."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Suggest potential campaigns from story threads and entity clusters.

    Two passes, ranked so the better-evidenced one leads. First, threat actors
    and malware families that carry story threads — several distinct stories, or
    one that kept moving for a week — since a thread already knows which
    articles are the same story. Second, the older volume heuristic: entities
    appearing across ``min_entries`` entries in the window, which still catches
    coverage that never clustered. Suggestions for similar entity names are
    merged, thread-backed evidence winning the pivot.
    """
    import re
    from datetime import datetime, timedelta

    cutoff = datetime.now(UTC) - timedelta(days=days)

    # Fetch more candidates internally to have enough after dedup/merge
    internal_limit = limit * 3

    # Find threat actors appearing in multiple recent entries
    actor_result = await db.execute(
        select(
            EntryThreatActor.threat_actor_id,
            func.count(EntryThreatActor.entry_id.distinct()).label("entry_count"),
        )
        .join(Entry, Entry.id == EntryThreatActor.entry_id)
        .where(Entry.published_at >= cutoff)
        .group_by(EntryThreatActor.threat_actor_id)
        .having(func.count(EntryThreatActor.entry_id.distinct()) >= min_entries)
        .order_by(func.count(EntryThreatActor.entry_id.distinct()).desc())
        .limit(internal_limit)
    )

    # Find malware families appearing in multiple recent entries
    malware_result = await db.execute(
        select(
            EntryMalware.malware_family_id,
            func.count(EntryMalware.entry_id.distinct()).label("entry_count"),
        )
        .join(Entry, Entry.id == EntryMalware.entry_id)
        .where(Entry.published_at >= cutoff)
        .group_by(EntryMalware.malware_family_id)
        .having(func.count(EntryMalware.entry_id.distinct()) >= min_entries)
        .order_by(func.count(EntryMalware.entry_id.distinct()).desc())
        .limit(internal_limit)
    )

    # Get existing campaign entity IDs to avoid suggesting already-tracked entities
    existing_entities = set()
    existing_result = await db.execute(select(CampaignEntity.entity_type, CampaignEntity.entity_id))
    for row in existing_result.all():
        existing_entities.add((row[0], row[1]))

    # Story threads first: they already know which articles are one story, so an
    # entity carrying several of them is a better campaign candidate than one
    # that merely got mentioned N times. The entity-count pass below still runs,
    # for entities whose coverage never clustered (and for anything predating
    # embeddings), and merges underneath.
    suggestions = await _thread_campaign_candidates(db, cutoff, min_entries, existing_entities)

    from app.models.malware_family import MalwareFamily as MalwareFamilyModel
    from app.models.threat_actor import ThreatActor as ThreatActorModel

    for actor_id, entry_count in actor_result.all():
        if ("threat_actor", actor_id) in existing_entities:
            continue
        actor = await db.get(ThreatActorModel, actor_id)
        if not actor:
            continue
        # Get all entry IDs for this entity
        all_entry_result = await db.execute(
            select(Entry.id)
            .join(EntryThreatActor, EntryThreatActor.entry_id == Entry.id)
            .where(EntryThreatActor.threat_actor_id == actor_id, Entry.published_at >= cutoff)
        )
        all_entry_ids = [str(r[0]) for r in all_entry_result.all()]
        # Get sample entry titles
        entry_result = await db.execute(
            select(Entry.id, Entry.title, Entry.published_at)
            .join(EntryThreatActor, EntryThreatActor.entry_id == Entry.id)
            .where(EntryThreatActor.threat_actor_id == actor_id, Entry.published_at >= cutoff)
            .order_by(Entry.published_at.desc())
            .limit(5)
        )
        sample_entries = [
            {"id": str(r.id), "title": r.title, "published_at": r.published_at.isoformat() if r.published_at else None}
            for r in entry_result.all()
        ]
        suggestions.append(
            {
                "suggested_name": f"{actor.name} Activity",
                "pivot_entity": {"type": "threat_actor", "id": str(actor_id), "name": actor.name},
                "entry_count": entry_count,
                "entry_ids": all_entry_ids,
                "sample_entries": sample_entries,
                "evidence": "entity_volume",
                "thread_count": 0,
                "span_days": 0,
            }
        )

    for malware_id, entry_count in malware_result.all():
        if ("malware", malware_id) in existing_entities:
            continue
        malware = await db.get(MalwareFamilyModel, malware_id)
        if not malware:
            continue
        # Get all entry IDs for this entity
        all_entry_result = await db.execute(
            select(Entry.id)
            .join(EntryMalware, EntryMalware.entry_id == Entry.id)
            .where(EntryMalware.malware_family_id == malware_id, Entry.published_at >= cutoff)
        )
        all_entry_ids = [str(r[0]) for r in all_entry_result.all()]
        entry_result = await db.execute(
            select(Entry.id, Entry.title, Entry.published_at)
            .join(EntryMalware, EntryMalware.entry_id == Entry.id)
            .where(EntryMalware.malware_family_id == malware_id, Entry.published_at >= cutoff)
            .order_by(Entry.published_at.desc())
            .limit(5)
        )
        sample_entries = [
            {"id": str(r.id), "title": r.title, "published_at": r.published_at.isoformat() if r.published_at else None}
            for r in entry_result.all()
        ]
        suggestions.append(
            {
                "suggested_name": f"{malware.name} Campaign",
                "pivot_entity": {"type": "malware", "id": str(malware_id), "name": malware.name},
                "entry_count": entry_count,
                "entry_ids": all_entry_ids,
                "sample_entries": sample_entries,
                "evidence": "entity_volume",
                "thread_count": 0,
                "span_days": 0,
            }
        )

    # --- Deduplicate suggestions with similar entity names ---
    # Normalize name: lowercase, strip non-alphanumeric, collapse whitespace
    def _normalize_name(name: str) -> str:
        return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9\s]", "", name.lower())).strip()

    # Group suggestions by normalized entity name
    # Thread-backed evidence outranks raw volume for the same entity, however
    # many entries the volume pass happened to sweep up.
    def _rank(s: dict) -> tuple[int, int]:
        return (1 if s.get("evidence") == "story_threads" else 0, s["entry_count"])

    merged: dict[str, dict] = {}
    for s in suggestions:
        key = _normalize_name(s["pivot_entity"]["name"])
        if key not in merged:
            merged[key] = {**s, "_rank": _rank(s), "_wider": set(s["entry_ids"])}
            continue

        existing = merged[key]
        # Every entry either pass found, so the candidate can report how much
        # wider the entity's coverage runs than the story it seeds from.
        existing["_wider"].update(s["entry_ids"])

        if _rank(s) > existing["_rank"]:
            # A better-evidenced candidate replaces the seed outright rather than
            # absorbing the loser's entries. Seeding a campaign with every entry
            # that merely mentions Qilin is the noise the thread pass exists to
            # avoid; those entries are what /suggest offers once the campaign has
            # a shape to compare them against.
            existing.update(
                {
                    "pivot_entity": s["pivot_entity"],
                    "suggested_name": s["suggested_name"],
                    "sample_entries": s["sample_entries"],
                    "entry_ids": list(s["entry_ids"]),
                    "entry_count": len(set(s["entry_ids"])),
                    "evidence": s.get("evidence", "entity_volume"),
                    "thread_count": s.get("thread_count", 0),
                    "span_days": s.get("span_days", 0),
                    "threads": s.get("threads", []),
                    "_rank": _rank(s),
                }
            )
        elif _rank(s) == existing["_rank"]:
            # Same evidence, two spellings of one entity — union as before.
            existing_ids = set(existing["entry_ids"])
            existing_ids.update(s["entry_ids"])
            existing["entry_ids"] = list(existing_ids)
            existing["entry_count"] = len(existing_ids)

    # Clean up internal field and sort thread-backed candidates first
    deduped = []
    for s in merged.values():
        s.pop("_rank", None)
        s["wider_entry_count"] = len(s.pop("_wider", set()))
        deduped.append(s)

    deduped.sort(
        key=lambda s: (s.get("thread_count", 0), s.get("span_days", 0), s["entry_count"]),
        reverse=True,
    )
    return deduped[:limit]


# --- Campaign Sources (entity / story intake) ---


@router.get("/{campaign_id}/sources", response_model=list[CampaignSourceResponse])
async def list_campaign_sources(
    campaign_id: uuid.UUID = Path(..., description="Campaign UUID."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """What feeds this campaign besides a saved search: entities and stories it follows."""
    campaign = await db.get(Campaign, campaign_id)
    if not campaign:
        raise AppError(code="not_found", message="Campaign not found", status_code=404)

    rows = (
        (
            await db.execute(
                select(CampaignSource)
                .where(CampaignSource.campaign_id == campaign_id)
                .order_by(CampaignSource.created_at)
            )
        )
        .scalars()
        .all()
    )
    return [CampaignSourceResponse.model_validate(r, from_attributes=True) for r in rows]


@router.get("/{campaign_id}/sources/suggested")
async def suggest_campaign_sources(
    campaign_id: uuid.UUID = Path(..., description="Campaign UUID."),
    limit: int = Query(8, ge=1, le=50, description="Maximum suggestions to return."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Sources this campaign could follow, drawn from what it already holds."""
    from app.services.campaign_sources import suggested_sources

    campaign = await db.get(Campaign, campaign_id)
    if not campaign:
        raise AppError(code="not_found", message="Campaign not found", status_code=404)
    return await suggested_sources(db, campaign_id, limit=limit)


@router.post("/{campaign_id}/sources", response_model=CampaignSourceResponse, status_code=201)
async def add_campaign_source(
    campaign_id: uuid.UUID = Path(..., description="Campaign UUID."),
    body: CampaignSourceAdd = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Follow an entity or a story. Syncs once immediately so the effect is visible."""
    from app.services.campaign_sources import SOURCE_KINDS, resolve_source_label, sync_source

    campaign = await db.get(Campaign, campaign_id)
    if not campaign:
        raise AppError(code="not_found", message="Campaign not found", status_code=404)
    if body.kind not in SOURCE_KINDS:
        raise AppError(
            code="bad_request",
            message=f"kind must be one of {', '.join(SOURCE_KINDS)}",
            status_code=422,
        )

    existing = (
        await db.execute(
            select(CampaignSource).where(
                CampaignSource.campaign_id == campaign_id,
                CampaignSource.kind == body.kind,
                CampaignSource.entity_type == body.entity_type,
                CampaignSource.ref_id == body.ref_id,
            )
        )
    ).scalar_one_or_none()
    if existing:
        raise AppError(code="conflict", message="Already followed by this campaign", status_code=409)

    label = await resolve_source_label(db, body.kind, body.entity_type, body.ref_id)
    source = CampaignSource(
        campaign_id=campaign_id,
        kind=body.kind,
        entity_type=body.entity_type,
        ref_id=body.ref_id,
        label=label,
        auto_sync=body.auto_sync,
        added_by=user.id,
    )
    db.add(source)
    await db.flush()

    # Sync on link: following something that already has articles should show
    # them now, not on the next sweep.
    await sync_source(db, source, user.id)
    return CampaignSourceResponse.model_validate(source, from_attributes=True)


@router.patch("/{campaign_id}/sources/{source_id}", response_model=CampaignSourceResponse)
async def update_campaign_source(
    campaign_id: uuid.UUID = Path(..., description="Campaign UUID."),
    source_id: uuid.UUID = Path(..., description="Source UUID."),
    body: CampaignSourceUpdate = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Pause or resume a source. Pausing keeps the row and its history."""
    source = await db.get(CampaignSource, source_id)
    if not source or source.campaign_id != campaign_id:
        raise AppError(code="not_found", message="Source not found", status_code=404)
    if body.auto_sync is not None:
        source.auto_sync = body.auto_sync
    await db.flush()
    return CampaignSourceResponse.model_validate(source, from_attributes=True)


@router.post("/{campaign_id}/sources/{source_id}/sync")
async def sync_campaign_source(
    campaign_id: uuid.UUID = Path(..., description="Campaign UUID."),
    source_id: uuid.UUID = Path(..., description="Source UUID."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Run one source now, whether or not it auto-syncs."""
    from app.services.campaign_sources import sync_source

    source = await db.get(CampaignSource, source_id)
    if not source or source.campaign_id != campaign_id:
        raise AppError(code="not_found", message="Source not found", status_code=404)
    added = await sync_source(db, source, user.id)
    return {"entries_added": added, "total_entries_added": source.entries_added}


@router.delete("/{campaign_id}/sources/{source_id}", status_code=204)
async def remove_campaign_source(
    campaign_id: uuid.UUID = Path(..., description="Campaign UUID."),
    source_id: uuid.UUID = Path(..., description="Source UUID."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Stop following. Articles already pulled in stay — they were added, not borrowed."""
    source = await db.get(CampaignSource, source_id)
    if not source or source.campaign_id != campaign_id:
        raise AppError(code="not_found", message="Source not found", status_code=404)
    await db.delete(source)
    return None


# --- Campaign Statistics ---


@router.get("/{campaign_id}/stats")
async def get_campaign_stats(
    campaign_id: uuid.UUID = Path(..., description="Campaign UUID."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get aggregated statistics for a campaign."""
    from app.models.feed import Feed

    campaign = await db.get(Campaign, campaign_id)
    if not campaign:
        raise AppError(code="not_found", message="Campaign not found", status_code=404)

    # Get campaign entry IDs and basic info (feed_type + file content type are
    # needed to keep machine records out of the top-sources stats)
    entry_result = await db.execute(
        select(
            Entry.id,
            Entry.feed_id,
            Entry.published_at,
            Feed.feed_type,
            Entry.metadata_["content_type"].astext.label("file_content_type"),
        )
        .join(CampaignEntry, CampaignEntry.entry_id == Entry.id)
        .join(Feed, Feed.id == Entry.feed_id)
        .where(CampaignEntry.campaign_id == campaign_id)
    )
    entry_rows = entry_result.all()
    entry_ids = [r.id for r in entry_rows]
    entry_count = len(entry_ids)

    # Explicitly linked entities (CampaignEntity) — counted in the distinct total
    explicit_result = await db.execute(
        select(CampaignEntity.entity_type, CampaignEntity.entity_id).where(CampaignEntity.campaign_id == campaign_id)
    )
    explicit_by_type: dict[str, set[uuid.UUID]] = {}
    for etype, eid in explicit_result.all():
        explicit_by_type.setdefault(etype, set()).add(eid)

    if not entry_ids:
        return {
            "entry_count": 0,
            "entity_counts": {"ttp": 0, "cve": 0, "threat_actor": 0, "malware": 0},
            "total_entity_count": sum(len(ids) for ids in explicit_by_type.values()),
            "detection_coverage_pct": 0,
            "date_range": {"earliest_entry": None, "latest_entry": None},
            "top_sources": [],
            "entries_over_time": [],
            "entries_over_time_bucket": "month",
        }

    # Entity counts (distinct entities referenced by campaign entries)
    entity_counts = {}
    total_entity_count = 0
    for label, table, id_col_name in [
        ("ttp", EntryTTP, "ttp_id"),
        ("cve", EntryCVE, "cve_id"),
        ("threat_actor", EntryThreatActor, "threat_actor_id"),
        ("malware", EntryMalware, "malware_family_id"),
    ]:
        id_col = getattr(table, id_col_name)
        id_result = await db.execute(select(id_col.distinct()).where(table.entry_id.in_(entry_ids)))
        entity_ids = {row[0] for row in id_result.all()}
        entity_counts[label] = len(entity_ids)
        # Union with explicitly linked entities of the same type for the true total
        total_entity_count += len(entity_ids | explicit_by_type.pop(label, set()))
    # Explicitly linked entities of any other type
    total_entity_count += sum(len(ids) for ids in explicit_by_type.values())

    # Detection coverage (telemetry-aware: covered = satisfiable rule exists)
    from app.services.detection_coverage import classify_techniques, summarize

    ttp_result = await db.execute(
        select(TTP.id, TTP.technique_id)
        .join(EntryTTP, EntryTTP.ttp_id == TTP.id)
        .where(EntryTTP.entry_id.in_(entry_ids))
        .distinct()
    )
    campaign_ttps = ttp_result.all()
    coverage_summary = summarize(await classify_techniques(db, [row.technique_id for row in campaign_ttps]))
    detection_coverage_pct = coverage_summary["coverage_percentage"]

    # Date range
    dates = [r.published_at for r in entry_rows if r.published_at]
    date_range = {
        "earliest_entry": min(dates).isoformat() if dates else None,
        "latest_entry": max(dates).isoformat() if dates else None,
    }

    # Top sources (feeds) — exclude machine records (imported rule files, NVD
    # vuln records) so rule-repo feeds don't dominate the campaign's sources
    from app.services.content_classification import is_reporting_content

    feed_counter: Counter = Counter()
    for r in entry_rows:
        if not is_reporting_content(r.feed_type, {"content_type": r.file_content_type}):
            continue
        feed_counter[r.feed_id] += 1
    top_feed_ids = feed_counter.most_common(5)
    top_sources = []
    for feed_id, count in top_feed_ids:
        feed = await db.get(Feed, feed_id)
        top_sources.append(
            {
                "feed_name": feed.title if feed else "Unknown",
                "entry_count": count,
            }
        )

    # Entries over time — contiguous histogram buckets across the campaign date
    # range (daily/weekly/monthly depending on span), zero-filled so sparse data
    # doesn't collapse into a couple of giant bars.
    from datetime import date as date_cls
    from datetime import timedelta

    entries_over_time: list[dict] = []
    bucket = "month"
    if dates:
        earliest, latest = min(dates), max(dates)
        span_days = (latest - earliest).days
        if span_days <= 31:
            bucket = "day"
        elif span_days <= 182:
            bucket = "week"

        def _bucket_start(dt) -> date_cls:
            d = dt.date()
            if bucket == "day":
                return d
            if bucket == "week":
                return d - timedelta(days=d.weekday())
            return d.replace(day=1)

        def _next_bucket(d: date_cls) -> date_cls:
            if bucket == "day":
                return d + timedelta(days=1)
            if bucket == "week":
                return d + timedelta(days=7)
            return (d + timedelta(days=32)).replace(day=1)

        bucket_counter: Counter = Counter(_bucket_start(d) for d in dates)
        cursor = _bucket_start(earliest)
        end = _bucket_start(latest)
        while cursor <= end:
            entries_over_time.append(
                {
                    "date": cursor.isoformat(),
                    "count": bucket_counter.get(cursor, 0),
                }
            )
            cursor = _next_bucket(cursor)

    return {
        "entry_count": entry_count,
        "entity_counts": entity_counts,
        "total_entity_count": total_entity_count,
        "detection_coverage_pct": detection_coverage_pct,
        "date_range": date_range,
        "top_sources": top_sources,
        "entries_over_time": entries_over_time,
        "entries_over_time_bucket": bucket,
    }


# --- Campaign Sectors ---


@router.get("/{campaign_id}/sectors")
async def list_campaign_sectors(
    campaign_id: uuid.UUID = Path(..., description="Campaign UUID."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """The victim verticals an analyst scoped this campaign to."""
    from app.models.sector import CampaignSector, Sector

    campaign = await db.get(Campaign, campaign_id)
    if not campaign:
        raise AppError(code="not_found", message="Campaign not found", status_code=404)
    result = await db.execute(
        select(CampaignSector, Sector.slug, Sector.name)
        .join(Sector, Sector.id == CampaignSector.sector_id)
        .where(CampaignSector.campaign_id == campaign_id)
        .order_by(Sector.name)
    )
    return [
        {
            "sector_id": str(cs.sector_id),
            "slug": slug,
            "name": name,
            "added_at": cs.added_at.isoformat() if cs.added_at else None,
        }
        for cs, slug, name in result.all()
    ]


@router.get("/{campaign_id}/sectors/suggested")
async def suggest_campaign_sectors(
    campaign_id: uuid.UUID = Path(..., description="Campaign UUID."),
    limit: int = Query(8, ge=1, le=21, description="Maximum number of suggested sectors to return."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Sectors the campaign's own articles describe as targeted, ranked by how many say so,
    excluding the ones already linked."""
    from app.models.entry_sector import EntrySector
    from app.models.sector import CampaignSector, Sector

    campaign = await db.get(Campaign, campaign_id)
    if not campaign:
        raise AppError(code="not_found", message="Campaign not found", status_code=404)
    linked = {
        row
        for row in (
            await db.execute(select(CampaignSector.sector_id).where(CampaignSector.campaign_id == campaign_id))
        ).scalars()
    }
    n = func.count(func.distinct(EntrySector.entry_id)).label("n")
    result = await db.execute(
        select(Sector.id, Sector.slug, Sector.name, n)
        .join(EntrySector, EntrySector.sector_id == Sector.id)
        .where(EntrySector.entry_id.in_(select(CampaignEntry.entry_id).where(CampaignEntry.campaign_id == campaign_id)))
        .group_by(Sector.id, Sector.slug, Sector.name)
        .order_by(n.desc(), Sector.name)
    )
    return [
        {"sector_id": str(sid), "slug": slug, "name": name, "entry_count": count}
        for sid, slug, name, count in result.all()
        if sid not in linked
    ][:limit]


@router.post("/{campaign_id}/sectors", status_code=201)
async def add_campaign_sector(
    campaign_id: uuid.UUID = Path(..., description="Campaign UUID."),
    body: dict = Body(
        ...,
        description="JSON object with sector (UUID, canonical slug or display name).",
        json_schema_extra={"example": {"sector": "healthcare"}},
    ),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Scope a campaign to a victim vertical."""
    from app.api.intelligence import _load_sector
    from app.models.sector import CampaignSector

    campaign = await db.get(Campaign, campaign_id)
    if not campaign:
        raise AppError(code="not_found", message="Campaign not found", status_code=404)
    ref = body.get("sector") or body.get("sector_id")
    if not ref:
        raise AppError(code="bad_request", message="sector is required", status_code=400)
    sector = await _load_sector(db, str(ref))
    existing = await db.execute(
        select(CampaignSector).where(CampaignSector.campaign_id == campaign_id, CampaignSector.sector_id == sector.id)
    )
    if existing.scalar_one_or_none():
        raise AppError(code="conflict", message="Sector already linked to this campaign", status_code=409)
    db.add(CampaignSector(campaign_id=campaign_id, sector_id=sector.id))
    await db.flush()
    return {"sector_id": str(sector.id), "slug": sector.slug, "name": sector.name}


@router.delete("/{campaign_id}/sectors/{sector_ref}", status_code=204)
async def remove_campaign_sector(
    campaign_id: uuid.UUID = Path(..., description="Campaign UUID."),
    sector_ref: str = Path(..., description="Sector UUID, slug or name."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Unlink a sector from a campaign."""
    from app.api.intelligence import _load_sector
    from app.models.sector import CampaignSector

    sector = await _load_sector(db, sector_ref)
    result = await db.execute(
        select(CampaignSector).where(CampaignSector.campaign_id == campaign_id, CampaignSector.sector_id == sector.id)
    )
    cs = result.scalar_one_or_none()
    if not cs:
        raise AppError(code="not_found", message="Campaign sector link not found", status_code=404)
    await db.delete(cs)
    await db.flush()
    return Response(status_code=204)


# --- Campaign Countries ---


@router.get("/{campaign_id}/countries")
async def list_campaign_countries(
    campaign_id: uuid.UUID = Path(..., description="Campaign UUID."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List countries linked to a campaign with their roles."""
    from app.models.country import Country
    from app.models.country_junction import CampaignCountry

    campaign = await db.get(Campaign, campaign_id)
    if not campaign:
        raise AppError(code="not_found", message="Campaign not found", status_code=404)

    result = await db.execute(
        select(CampaignCountry, Country.name, Country.iso_code)
        .join(Country, Country.id == CampaignCountry.country_id)
        .where(CampaignCountry.campaign_id == campaign_id)
        .order_by(CampaignCountry.role, Country.name)
    )

    return [
        {
            "country_id": str(cc.country_id),
            "country_name": name,
            "country_code": iso_code,
            "role": cc.role,
            "added_at": cc.added_at.isoformat() if cc.added_at else None,
        }
        for cc, name, iso_code in result.all()
    ]


@router.get("/{campaign_id}/countries/suggested")
async def suggest_campaign_countries(
    campaign_id: uuid.UUID = Path(..., description="Campaign UUID."),
    limit: int = Query(8, ge=1, le=20, description="Maximum number of suggested countries to return."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Suggest countries for a campaign from its linked entries' country entities.

    Aggregates the country entities referenced by campaign entries, excludes
    countries already linked to the campaign, and returns the top matches with
    a suggested role derived from how the country appears in the entries.
    """
    from app.models.country import Country, EntryCountry
    from app.models.country_junction import CampaignCountry

    campaign = await db.get(Campaign, campaign_id)
    if not campaign:
        raise AppError(code="not_found", message="Campaign not found", status_code=404)

    entry_result = await db.execute(select(CampaignEntry.entry_id).where(CampaignEntry.campaign_id == campaign_id))
    entry_ids = [row[0] for row in entry_result.all()]
    if not entry_ids:
        return []

    linked_result = await db.execute(
        select(CampaignCountry.country_id).where(CampaignCountry.campaign_id == campaign_id)
    )
    linked_ids = {row[0] for row in linked_result.all()}

    result = await db.execute(
        select(
            EntryCountry.country_id,
            Country.name,
            Country.iso_code,
            EntryCountry.role,
            func.count(EntryCountry.entry_id.distinct()).label("entry_count"),
        )
        .join(Country, Country.id == EntryCountry.country_id)
        .where(EntryCountry.entry_id.in_(entry_ids))
        .group_by(EntryCountry.country_id, Country.name, Country.iso_code, EntryCountry.role)
    )

    aggregated: dict[uuid.UUID, dict] = {}
    role_counts: dict[uuid.UUID, Counter] = {}
    for country_id, name, iso_code, role, count in result.all():
        if country_id in linked_ids:
            continue
        item = aggregated.setdefault(
            country_id,
            {
                "country_id": str(country_id),
                "country_name": name,
                "country_code": iso_code,
                "entry_count": 0,
            },
        )
        item["entry_count"] += count
        if role:
            role_counts.setdefault(country_id, Counter())[role] += count

    suggestions = []
    for country_id, item in aggregated.items():
        counts = role_counts.get(country_id, Counter())
        # Map entry-level roles (origin/target/infrastructure/mentioned) to a
        # campaign role; default to target when signal is ambiguous.
        item["suggested_role"] = "origin" if counts.get("origin", 0) > counts.get("target", 0) else "target"
        suggestions.append(item)

    suggestions.sort(key=lambda s: (-s["entry_count"], s["country_name"]))
    return suggestions[:limit]


@router.post("/{campaign_id}/countries", status_code=201)
async def add_campaign_country(
    campaign_id: uuid.UUID = Path(..., description="Campaign UUID."),
    body: dict = Body(
        ...,
        description="JSON object with country_id (UUID, required) and role ('origin' or 'target', default 'target').",
        json_schema_extra={"example": {"country_id": "d5b2f1c8-3a4e-4b6d-9c2f-8e7a1b3c5d4e", "role": "origin"}},
    ),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Link a country to a campaign with a role (origin or target)."""
    from app.models.country import Country
    from app.models.country_junction import CampaignCountry

    campaign = await db.get(Campaign, campaign_id)
    if not campaign:
        raise AppError(code="not_found", message="Campaign not found", status_code=404)

    country_id = uuid.UUID(body["country_id"])
    role = body.get("role", "target")
    if role not in ("origin", "target"):
        raise AppError(code="bad_request", message="Role must be 'origin' or 'target'", status_code=400)

    country = await db.get(Country, country_id)
    if not country:
        raise AppError(code="not_found", message="Country not found", status_code=404)

    # Check for duplicate
    existing = await db.execute(
        select(CampaignCountry).where(
            CampaignCountry.campaign_id == campaign_id,
            CampaignCountry.country_id == country_id,
        )
    )
    if existing.scalar_one_or_none():
        raise AppError(code="conflict", message="Country already linked to this campaign", status_code=409)

    cc = CampaignCountry(campaign_id=campaign_id, country_id=country_id, role=role)
    db.add(cc)
    await db.flush()

    return {"country_id": str(country_id), "country_name": country.name, "country_code": country.iso_code, "role": role}


@router.delete("/{campaign_id}/countries/{country_id}", status_code=204)
async def remove_campaign_country(
    campaign_id: uuid.UUID = Path(..., description="Campaign UUID."),
    country_id: uuid.UUID = Path(..., description="Country UUID."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Unlink a country from a campaign."""
    from app.models.country_junction import CampaignCountry

    result = await db.execute(
        select(CampaignCountry).where(
            CampaignCountry.campaign_id == campaign_id,
            CampaignCountry.country_id == country_id,
        )
    )
    cc = result.scalar_one_or_none()
    if not cc:
        raise AppError(code="not_found", message="Campaign country link not found", status_code=404)
    await db.delete(cc)
    await db.flush()
