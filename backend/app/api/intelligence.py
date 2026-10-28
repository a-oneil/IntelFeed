"""Intelligence extraction API routes — TTPs, CVEs, threat actors, malware, detection rules."""

import asyncio
import logging
import re
import uuid
from datetime import UTC, datetime, timedelta

import anyio
import sqlalchemy as sa
from fastapi import APIRouter, Body, Depends, File, Path, Query, Response, UploadFile
from pydantic import BaseModel, ConfigDict
from sqlalchemy import case, cast, delete, func, or_, select, tuple_, type_coerce
from sqlalchemy import false as sa_false
from sqlalchemy import text as sa_text
from sqlalchemy import update as sa_update
from sqlalchemy.dialects.postgresql import ARRAY as PG_ARRAY
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app import entity_types
from app.ai.caller import Caller
from app.core.exceptions import AppError
from app.core.pagination import PaginatedResponse
from app.core.public_access import viewer_is_anonymous
from app.core.security import get_admin_user, get_current_user, get_entry_viewer, get_viewer
from app.database import get_db
from app.enrichment.capec import capec_names
from app.intelligence.cve import extract_and_store_cves
from app.intelligence.detection import (
    ENTITY_RULE_TYPES,
    generate_detection_rules,
    generate_entity_detection_rules,
)
from app.intelligence.enrichment import extract_countries, extract_malware, extract_sectors, extract_threat_actors
from app.intelligence.mitigation import extract_mitigations, store_mitigations
from app.intelligence.tool import extract_tools
from app.intelligence.ttp import extract_ttps, generate_navigator_layer, store_ttps
from app.models.ai_result import AIResult
from app.models.ai_task import AITask
from app.models.campaign import Campaign
from app.models.country import Country, EntryCountry
from app.models.country_junction import CampaignCountry, ThreatActorTargetCountry
from app.models.cve import CVE, EntryCVE
from app.models.cve_affected import CVEAffected
from app.models.cwe import CWE, CVEWeakness, EntryCWE
from app.models.detection_rule import DetectionRule
from app.models.detection_rule_version import DetectionRuleVersion
from app.models.entry import Entry
from app.models.entry_sector import EntrySector
from app.models.feed import Feed
from app.models.intel_profile import IntelProfile
from app.models.intelligence_requirement import IntelligenceRequirement, RequirementMatch
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.mitigation import EntryMitigation, Mitigation, TTPMitigation
from app.models.note import Note
from app.models.observable import ALL_KINDS, EntryObservable, Observable
from app.models.product import EntryProduct, Product
from app.models.ransomware import RansomwareVictim, VictimDisclosure
from app.models.rule_coverage import RuleCoverage
from app.models.sector import CampaignSector, MalwareTargetSector, Sector, ThreatActorTargetSector
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.tool import EntryTool, Tool
from app.models.ttp import TTP, EntryTTP
from app.models.user import User
from app.models.vendor import EntryVendor, Vendor
from app.schemas.intelligence import (
    AffectedByProduct,
    AffectedCVECounts,
    AffectedCVEItem,
    AffectedCVEsResponse,
    AffectedProductRef,
    BulkExtractRequest,
    BulkRuleDeleteRequest,
    BulkRuleUpdateRequest,
    BulkTranslateRequest,
    CAPECRef,
    CountryResponse,
    CVEAffectedEntityRow,
    CVEResponse,
    CVEWeaknessRow,
    CWEAffectedVendorRow,
    CWEFamilyRef,
    CWEFamilyResponse,
    CWEResponse,
    CWEVendorRow,
    DetectionRuleCreate,
    DetectionRuleGenerateRequest,
    DetectionRuleListItem,
    DetectionRuleResponse,
    DetectionRuleUpdate,
    DetectionRuleValidateRequest,
    DetectionRuleVersionResponse,
    EntryCountryResponse,
    EntrySectorResponse,
    ExtractionResponse,
    MalwareFamilyResponse,
    MitigationResponse,
    ObservableCandidateRow,
    ObservableDismissRequest,
    ObservableEntryPayload,
    ObservableNeverCaptureRequest,
    ObservablePromoteRequest,
    ObservableResponse,
    ObservableUpdateRequest,
    ProductResponse,
    RuleChatRequest,
    RuleConvertRequest,
    SectorResponse,
    ThreatActorResponse,
    ToolResponse,
    TTPFamilyRef,
    TTPRelatedTechniquesResponse,
    TTPResponse,
    VendorResponse,
)
from app.services import meilisearch_client
from app.services.entity_indexer import delete_entity_document, index_rule

logger = logging.getLogger(__name__)
router = APIRouter()


def _entry_to_dict(entry: Entry) -> dict:
    return {
        "title": entry.title,
        "content_text": entry.content_text or "",
        "content_html": entry.content_html,
        "summary": entry.summary,
        "author": entry.author,
        "url": entry.url,
        "published_at": str(entry.published_at) if entry.published_at else "",
        "feed_title": "",
    }


# --- TTP Routes ---


@router.post("/entries/{entry_id}/extract-ttps", response_model=ExtractionResponse[TTPResponse])
async def extract_entry_ttps(
    entry_id: uuid.UUID = Path(..., description="UUID of the entry to extract from"),
    use_ai: bool = Query(True, description="Also run AI-based extraction; false uses regex/pattern matching only"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Extract MITRE ATT&CK techniques from the entry's content and store them as entry-TTP links.

    Returns the stored TTPs with an extraction status (success / ai_not_configured / provider_error / parse_error).
    """
    entry = await _get_entry(db, entry_id)
    entry_data = _entry_to_dict(entry)
    ttp_results, status, error_msg = await extract_ttps(db, user.id, entry_id, entry_data, use_ai=use_ai)
    stored_with_flags = await store_ttps(db, entry_id, ttp_results)
    await db.commit()
    items = [_ttp_to_response(t) for t, _ in stored_with_flags]
    return ExtractionResponse(items=items, status=status, error_message=error_msg)


@router.get("/entries/{entry_id}/ttps", response_model=list[TTPResponse])
async def get_entry_ttps(
    entry_id: uuid.UUID = Path(..., description="UUID of the entry"),
    user: User = Depends(get_entry_viewer),
    db: AsyncSession = Depends(get_db),
):
    """List the MITRE ATT&CK techniques linked to an entry, with per-entry confidence and matched source text."""
    result = await db.execute(
        select(TTP, EntryTTP.confidence, EntryTTP.source_text)
        .join(EntryTTP, EntryTTP.ttp_id == TTP.id)
        .where(EntryTTP.entry_id == entry_id)
        .order_by(TTP.tactic, TTP.technique_id)
    )
    items = []
    for ttp, confidence, source_text in result.all():
        resp = _ttp_to_response(ttp)
        resp.confidence = confidence
        resp.source_text = source_text
        items.append(resp)
    return items


@router.get("/entries/{entry_id}/kill-chain")
async def get_entry_kill_chain(
    entry_id: uuid.UUID = Path(..., description="UUID of the entry"),
    user: User = Depends(get_entry_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Entry TTPs ordered as an attack chain (kill-chain phases) — plan item 3.9.4.

    Derived from each technique's hydrated ATT&CK tactic(s); no extra extraction.
    """
    from app.intelligence.kill_chain import order_by_kill_chain

    result = await db.execute(
        select(TTP, EntryTTP.confidence).join(EntryTTP, EntryTTP.ttp_id == TTP.id).where(EntryTTP.entry_id == entry_id)
    )
    ttps = [
        {
            "technique_id": t.technique_id,
            "technique_name": t.technique_name,
            "tactic": t.tactic,
            "tactics": list(getattr(t, "tactics", None) or ([t.tactic] if t.tactic else [])),
            "confidence": c,
        }
        for t, c in result.all()
    ]
    return {"phases": order_by_kill_chain(ttps)}


@router.get("/entries/{entry_id}/ttps/navigator")
async def get_navigator_layer(
    entry_id: uuid.UUID = Path(..., description="UUID of the entry"),
    user: User = Depends(get_entry_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Build a MITRE ATT&CK Navigator layer JSON from the entry's linked techniques, titled after the entry."""
    entry = await _get_entry(db, entry_id)
    result = await db.execute(
        select(TTP, EntryTTP.confidence, EntryTTP.source_text)
        .join(EntryTTP, EntryTTP.ttp_id == TTP.id)
        .where(EntryTTP.entry_id == entry_id)
    )
    ttps = [
        {
            "technique_id": t.technique_id,
            "technique_name": t.technique_name,
            "tactic": t.tactic,
            "confidence": c,
            "source_text": s,
        }
        for t, c, s in result.all()
    ]
    return generate_navigator_layer(ttps, title=entry.title)


def _linked_count_subquery(model, entity_type: str):
    """Correlated count of an entity's non-rejected typed relationships.

    Used to ORDER BY the workbench "Linked" column. Mirrors the count logic in
    the /entity-relationships/signals endpoint so the ordering agrees with the
    displayed counts.
    """
    from app.models.entity_relationship import EntityRelationship

    return (
        select(func.count())
        .select_from(EntityRelationship)
        .where(
            EntityRelationship.source != "analyst_rejected",
            or_(
                (EntityRelationship.source_type == entity_type) & (EntityRelationship.source_id == model.id),
                (EntityRelationship.target_type == entity_type) & (EntityRelationship.target_id == model.id),
            ),
        )
        .correlate(model)
        .scalar_subquery()
    )


@router.get("/ttps", response_model=PaginatedResponse[TTPResponse])
async def list_ttps(
    search: str | None = Query(None, description="Case-insensitive substring match on technique ID or name"),
    tactic: str | None = Query(None, description="Exact ATT&CK tactic filter (e.g. 'initial-access')"),
    sort_by: str = Query(
        "article_count",
        pattern="^(technique_id|technique_name|tactic|article_count|first_seen_at|last_seen_at|linked_count)$",
        description="Sort column; linked_count sorts by non-rejected entity-relationship count",
    ),
    sort_order: str = Query("desc", pattern="^(asc|desc)$", description="Sort direction"),
    limit: int = Query(50, ge=1, le=500, description="Page size"),
    offset: int = Query(0, ge=0, description="Number of rows to skip"),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Paginated catalog of known MITRE ATT&CK techniques with search, tactic filter, and sorting."""
    query = select(TTP)
    count_q = select(func.count()).select_from(TTP)
    if search:
        pattern = f"%{search}%"
        search_filter = or_(
            TTP.technique_id.ilike(pattern),
            TTP.technique_name.ilike(pattern),
        )
        query = query.where(search_filter)
        count_q = count_q.where(search_filter)
    if tactic:
        query = query.where(TTP.tactic == tactic)
        count_q = count_q.where(TTP.tactic == tactic)

    total = (await db.execute(count_q)).scalar() or 0
    if sort_by == "linked_count":
        sort_expr = _linked_count_subquery(TTP, "ttp")
    else:
        col = getattr(TTP, sort_by)
        sort_expr = func.lower(col) if sort_by == "technique_name" else col
    order = sort_expr.asc() if sort_order == "asc" else sort_expr.desc()
    result = await db.execute(query.order_by(order).limit(limit).offset(offset))
    items = [_ttp_to_response(t) for t in result.scalars().all()]
    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset, has_more=(offset + limit) < total)


@router.get("/ttps/by-technique/{technique_id}", response_model=TTPResponse)
async def get_ttp_by_technique_id(
    technique_id: str = Path(..., description="ATT&CK technique ID, e.g. T1566.001 (case-insensitive)"),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Look up a single TTP by its MITRE ATT&CK technique ID. Returns 404 if the technique is not in the catalog."""
    result = await db.execute(select(TTP).where(TTP.technique_id == technique_id.upper()))
    ttp = result.scalar_one_or_none()
    if not ttp:
        raise AppError(code="not_found", message=f"TTP {technique_id} not found", status_code=404)
    return _ttp_to_response(ttp)


@router.get("/ttps/{ttp_id}/mitigations", response_model=list[MitigationResponse])
async def get_ttp_mitigations(
    ttp_id: uuid.UUID = Path(..., description="UUID of the TTP"),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Get mitigations linked to a TTP via the ttp_mitigations junction table."""
    result = await db.execute(
        select(Mitigation)
        .join(TTPMitigation, TTPMitigation.mitigation_id == Mitigation.id)
        .where(TTPMitigation.ttp_id == ttp_id)
        .order_by(Mitigation.mitre_id)
    )
    return [_mitigation_to_response(m) for m in result.scalars()]


@router.get("/ttps/{ttp_id}/related-techniques", response_model=TTPRelatedTechniquesResponse)
async def get_ttp_related_techniques(
    ttp_id: uuid.UUID = Path(..., description="UUID of the TTP"),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Parent technique, sub-techniques, and (for revoked entries) the replacement."""
    result = await db.execute(select(TTP).where(TTP.id == ttp_id))
    ttp = result.scalar_one_or_none()
    if not ttp:
        raise AppError(code="not_found", message="TTP not found", status_code=404)

    def _ref(t: TTP) -> TTPFamilyRef:
        return TTPFamilyRef(
            id=t.id,
            technique_id=t.technique_id,
            technique_name=t.technique_name,
            is_deprecated=t.is_deprecated or False,
        )

    parent = None
    if ttp.parent_technique_id:
        parent_row = await db.execute(select(TTP).where(TTP.technique_id == ttp.parent_technique_id))
        parent_ttp = parent_row.scalar_one_or_none()
        if parent_ttp:
            parent = _ref(parent_ttp)

    subs_result = await db.execute(
        select(TTP)
        .where(TTP.parent_technique_id == ttp.technique_id, TTP.is_deprecated.is_(False))
        .order_by(TTP.technique_id)
    )
    subtechniques = [_ref(t) for t in subs_result.scalars().all()]

    replacement = None
    if ttp.superseded_by:
        repl_row = await db.execute(select(TTP).where(TTP.technique_id == ttp.superseded_by))
        repl_ttp = repl_row.scalar_one_or_none()
        if repl_ttp:
            replacement = _ref(repl_ttp)

    return TTPRelatedTechniquesResponse(parent=parent, subtechniques=subtechniques, replacement=replacement)


# --- CVE Routes ---


@router.post("/entries/{entry_id}/extract-cves", response_model=list[CVEResponse])
async def extract_entry_cves(
    entry_id: uuid.UUID = Path(..., description="UUID of the entry to extract from"),
    enrich: bool = Query(True, description="Enrich newly found CVEs with NVD data (CVSS, severity, description)"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Extract CVE identifiers from the entry's title and content, store the entry-CVE links, and return the CVEs."""
    entry = await _get_entry(db, entry_id)
    # Include title — many advisories (e.g. Cisco, NVD) put CVE IDs only in the title
    text = entry.content_text or ""
    if entry.title:
        text = entry.title + "\n" + text
    stored = await extract_and_store_cves(db, entry_id, text, enrich=enrich)
    await db.commit()
    return [_cve_to_response(c) for c in stored]


@router.get("/entries/{entry_id}/cves", response_model=list[CVEResponse])
async def get_entry_cves(
    entry_id: uuid.UUID = Path(..., description="UUID of the entry"),
    user: User = Depends(get_entry_viewer),
    db: AsyncSession = Depends(get_db),
):
    """List the CVEs linked to an entry, ordered by CVSS score descending."""
    article_count_sq = (
        select(func.count(EntryCVE.entry_id))
        .where(EntryCVE.cve_id == CVE.id)
        .correlate(CVE)
        .scalar_subquery()
        .label("article_count")
    )
    result = await db.execute(
        select(CVE, article_count_sq)
        .join(EntryCVE, EntryCVE.cve_id == CVE.id)
        .where(EntryCVE.entry_id == entry_id)
        .order_by(CVE.cvss_score.desc().nullslast())
    )
    return [_cve_to_response(c, article_count=ac) for c, ac in result.all()]


@router.get("/cves", response_model=PaginatedResponse[CVEResponse])
async def list_cves(
    search: str | None = Query(None, description="Case-insensitive substring match on CVE ID or description"),
    severity: str | None = Query(None, description="Exact severity filter (LOW/MEDIUM/HIGH/CRITICAL, any case)"),
    kev_only: bool = Query(False, description="Only CVEs in the CISA Known Exploited Vulnerabilities catalog"),
    sort_by: str = Query(
        "first_seen_at",
        pattern="^(cve_id|severity|cvss_score|exploit_availability|article_count|first_seen_at|updated_at|epss_score|is_kev|risk_tier|linked_count)$",
        description="Sort column; risk_tier uses tier rank with EPSS as tiebreaker",
    ),
    sort_order: str = Query("desc", pattern="^(asc|desc)$", description="Sort direction"),
    limit: int = Query(50, ge=1, le=500, description="Page size"),
    offset: int = Query(0, ge=0, description="Number of rows to skip"),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Paginated CVE list with search, severity and KEV filters, and sorting including EPSS/risk-tier columns."""
    # Compute article_count via subquery since CVE model doesn't store it
    article_count_sq = (
        select(func.count(EntryCVE.entry_id))
        .where(EntryCVE.cve_id == CVE.id)
        .correlate(CVE)
        .scalar_subquery()
        .label("article_count")
    )

    query = select(CVE, article_count_sq)
    count_q = select(func.count()).select_from(CVE)
    if search:
        pattern = f"%{search}%"
        search_filter = or_(
            CVE.cve_id.ilike(pattern),
            CVE.description.ilike(pattern),
        )
        query = query.where(search_filter)
        count_q = count_q.where(search_filter)
    if severity:
        query = query.where(CVE.severity == severity.upper())
        count_q = count_q.where(CVE.severity == severity.upper())
    if kev_only:
        query = query.where(CVE.is_kev.is_(True))
        count_q = count_q.where(CVE.is_kev.is_(True))

    total = (await db.execute(count_q)).scalar() or 0

    if sort_by == "article_count":
        order = [article_count_sq.asc() if sort_order == "asc" else article_count_sq.desc()]
    elif sort_by == "linked_count":
        lc = _linked_count_subquery(CVE, "cve")
        order = [lc.asc() if sort_order == "asc" else lc.desc()]
    elif sort_by == "risk_tier":
        from app.intelligence.cve import risk_tier_rank_expr

        rank = risk_tier_rank_expr()
        # Tier rank, then EPSS as the intra-tier tiebreaker
        if sort_order == "asc":
            order = [rank.asc(), CVE.epss_score.asc().nullsfirst()]
        else:
            order = [rank.desc(), CVE.epss_score.desc().nullslast()]
    else:
        col = getattr(CVE, sort_by)
        order = [col.asc().nullsfirst() if sort_order == "asc" else col.desc().nullslast()]

    result = await db.execute(query.order_by(*order).limit(limit).offset(offset))
    items = [_cve_to_response(cve, article_count=ac) for cve, ac in result.all()]
    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset, has_more=(offset + limit) < total)


@router.get("/cves/trending", response_model=list[CVEResponse])
async def trending_cves(
    limit: int = Query(10, ge=1, le=500, description="Maximum number of CVEs to return"),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Most-mentioned CVEs ranked by the number of entries linking to them."""
    # Most mentioned CVEs (by entry count)
    result = await db.execute(
        select(CVE, func.count(EntryCVE.entry_id).label("cnt"))
        .join(EntryCVE, EntryCVE.cve_id == CVE.id)
        .group_by(CVE.id)
        .order_by(func.count(EntryCVE.entry_id).desc())
        .limit(limit)
    )
    return [_cve_to_response(cve, article_count=cnt) for cve, cnt in result.all()]


@router.get("/cves/{cve_id}", response_model=CVEResponse)
async def get_cve(
    cve_id: str = Path(..., description="CVE UUID or CVE identifier string (e.g. CVE-2024-3400)"),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Get a single CVE by internal UUID or by CVE identifier string, including its linked-article count."""
    # Accept both UUID and CVE ID string (e.g. "CVE-2024-1234")
    try:
        uid = uuid.UUID(cve_id)
        result = await db.execute(select(CVE).where(CVE.id == uid))
    except ValueError:
        result = await db.execute(select(CVE).where(CVE.cve_id == cve_id))
    cve = result.scalar_one_or_none()
    if not cve:
        raise AppError(code="not_found", message="CVE not found", status_code=404)
    # Compute article count
    ac = await db.scalar(select(func.count(EntryCVE.entry_id)).where(EntryCVE.cve_id == cve.id))
    return _cve_to_response(cve, article_count=ac or 0)


# --- Threat Actor Routes ---


@router.get("/entries/{entry_id}/threat-actors", response_model=list[ThreatActorResponse])
async def get_entry_threat_actors(
    entry_id: uuid.UUID = Path(..., description="UUID of the entry"),
    user: User = Depends(get_entry_viewer),
    db: AsyncSession = Depends(get_db),
):
    """List the threat actors linked to an entry, including the surface forms matched in the text."""
    result = await db.execute(
        select(ThreatActor, EntryThreatActor.matched_names)
        .join(EntryThreatActor, EntryThreatActor.threat_actor_id == ThreatActor.id)
        .where(EntryThreatActor.entry_id == entry_id)
        .order_by(ThreatActor.name)
    )
    items = []
    for actor, matched_names in result.all():
        resp = ThreatActorResponse.model_validate(actor)
        resp.matched_names = matched_names
        items.append(resp)
    return items


@router.post("/entries/{entry_id}/extract-threat-actors", response_model=ExtractionResponse[ThreatActorResponse])
async def extract_entry_threat_actors(
    entry_id: uuid.UUID = Path(..., description="UUID of the entry to extract from"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Run AI threat-actor extraction on the entry and store the resulting entry-actor links.

    Returns the actors with an extraction status (success / ai_not_configured / provider_error / parse_error).
    """
    entry = await _get_entry(db, entry_id)
    entry_data = _entry_to_dict(entry)
    actors_with_flags, status, error_msg = await extract_threat_actors(db, user.id, entry_id, entry_data)
    await db.commit()
    items = [actor for actor, _ in actors_with_flags]
    return ExtractionResponse(items=items, status=status, error_message=error_msg)


@router.get("/threat-actors", response_model=PaginatedResponse[ThreatActorResponse])
async def list_threat_actors(
    search: str | None = Query(None, description="Case-insensitive match on actor name or whole-word alias"),
    sort_by: str = Query(
        "article_count",
        pattern="^(name|country|motivation|article_count|last_seen_at|linked_count)$",
        description="Sort column; linked_count sorts by non-rejected entity-relationship count",
    ),
    sort_order: str = Query("desc", pattern="^(asc|desc)$", description="Sort direction"),
    limit: int = Query(50, ge=1, le=500, description="Page size"),
    offset: int = Query(0, ge=0, description="Number of rows to skip"),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Paginated threat-actor list with name/alias search and sorting."""
    query = select(ThreatActor)
    count_q = select(func.count()).select_from(ThreatActor)
    if search:
        pattern = f"%{search}%"
        alias_pattern = rf"\y{re.escape(search)}\y"
        search_filter = or_(
            ThreatActor.name.ilike(pattern),
            func.array_to_string(ThreatActor.aliases, " ").op("~*")(alias_pattern),
        )
        query = query.where(search_filter)
        count_q = count_q.where(search_filter)
    total = (await db.execute(count_q)).scalar() or 0
    if sort_by == "linked_count":
        sort_expr = _linked_count_subquery(ThreatActor, "threat_actor")
    else:
        col = getattr(ThreatActor, sort_by)
        sort_expr = func.lower(col) if sort_by == "name" else col
    order = sort_expr.asc() if sort_order == "asc" else sort_expr.desc()
    result = await db.execute(query.order_by(order).limit(limit).offset(offset))
    items = result.scalars().all()
    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset, has_more=(offset + limit) < total)


@router.get("/threat-actors/{actor_id}", response_model=ThreatActorResponse)
async def get_threat_actor(
    actor_id: uuid.UUID = Path(..., description="UUID of the threat actor"),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Get a single threat actor by UUID."""
    result = await db.execute(select(ThreatActor).where(ThreatActor.id == actor_id))
    actor = result.scalar_one_or_none()
    if not actor:
        raise AppError(code="not_found", message="Threat actor not found", status_code=404)
    return actor


# --- Malware Routes ---


@router.get("/entries/{entry_id}/malware", response_model=list[MalwareFamilyResponse])
async def get_entry_malware(
    entry_id: uuid.UUID = Path(..., description="UUID of the entry"),
    user: User = Depends(get_entry_viewer),
    db: AsyncSession = Depends(get_db),
):
    """List the malware families linked to an entry, including the surface forms matched in the text."""
    result = await db.execute(
        select(MalwareFamily, EntryMalware.matched_names)
        .join(EntryMalware, EntryMalware.malware_family_id == MalwareFamily.id)
        .where(EntryMalware.entry_id == entry_id)
        .order_by(MalwareFamily.name)
    )
    items = []
    for malware, matched_names in result.all():
        resp = MalwareFamilyResponse.model_validate(malware)
        resp.matched_names = matched_names
        items.append(resp)
    return items


@router.post("/entries/{entry_id}/extract-malware", response_model=ExtractionResponse[MalwareFamilyResponse])
async def extract_entry_malware(
    entry_id: uuid.UUID = Path(..., description="UUID of the entry to extract from"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Run AI malware-family extraction on the entry and store the resulting entry-malware links.

    Returns the malware families with an extraction status (success / ai_not_configured / provider_error /
    parse_error).
    """
    entry = await _get_entry(db, entry_id)
    entry_data = _entry_to_dict(entry)
    malware_with_flags, status, error_msg = await extract_malware(db, user.id, entry_id, entry_data)
    await db.commit()
    items = [m for m, _ in malware_with_flags]
    return ExtractionResponse(items=items, status=status, error_message=error_msg)


@router.get("/malware", response_model=PaginatedResponse[MalwareFamilyResponse])
async def list_malware(
    search: str | None = Query(None, description="Case-insensitive match on family name or whole-word alias"),
    malware_type: str | None = Query(None, description="Exact malware type filter (e.g. 'ransomware')"),
    sort_by: str = Query(
        "article_count",
        pattern="^(name|malware_type|article_count|last_seen_at|linked_count)$",
        description="Sort column; linked_count sorts by non-rejected entity-relationship count",
    ),
    sort_order: str = Query("desc", pattern="^(asc|desc)$", description="Sort direction"),
    limit: int = Query(50, ge=1, le=500, description="Page size"),
    offset: int = Query(0, ge=0, description="Number of rows to skip"),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Paginated malware-family list with name/alias search, type filter, and sorting."""
    query = select(MalwareFamily)
    count_q = select(func.count()).select_from(MalwareFamily)
    if search:
        pattern = f"%{search}%"
        alias_pattern = rf"\y{re.escape(search)}\y"
        search_filter = or_(
            MalwareFamily.name.ilike(pattern),
            func.array_to_string(MalwareFamily.aliases, " ").op("~*")(alias_pattern),
        )
        query = query.where(search_filter)
        count_q = count_q.where(search_filter)
    if malware_type:
        query = query.where(MalwareFamily.malware_type == malware_type)
        count_q = count_q.where(MalwareFamily.malware_type == malware_type)

    total = (await db.execute(count_q)).scalar() or 0
    if sort_by == "linked_count":
        sort_expr = _linked_count_subquery(MalwareFamily, "malware")
    else:
        col = getattr(MalwareFamily, sort_by)
        sort_expr = func.lower(col) if sort_by == "name" else col
    order = sort_expr.asc() if sort_order == "asc" else sort_expr.desc()
    result = await db.execute(query.order_by(order).limit(limit).offset(offset))
    items = result.scalars().all()
    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset, has_more=(offset + limit) < total)


@router.get("/malware/{malware_id}", response_model=MalwareFamilyResponse)
async def get_malware(
    malware_id: uuid.UUID = Path(..., description="UUID of the malware family"),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Get a single malware family by UUID."""
    result = await db.execute(select(MalwareFamily).where(MalwareFamily.id == malware_id))
    malware = result.scalar_one_or_none()
    if not malware:
        raise AppError(code="not_found", message="Malware family not found", status_code=404)
    return malware


# --- Country Routes ---


@router.get("/entries/{entry_id}/countries", response_model=list[EntryCountryResponse])
async def get_entry_countries(
    entry_id: uuid.UUID = Path(..., description="UUID of the entry"),
    user: User = Depends(get_entry_viewer),
    db: AsyncSession = Depends(get_db),
):
    """List the countries linked to an entry with junction metadata (role, confidence, source, matched names)."""
    result = await db.execute(
        select(Country, EntryCountry.role, EntryCountry.confidence, EntryCountry.source, EntryCountry.matched_names)
        .join(EntryCountry, EntryCountry.country_id == Country.id)
        .where(EntryCountry.entry_id == entry_id)
        .order_by(Country.name)
    )
    items = []
    for country, role, confidence, source, matched_names in result.all():
        items.append(
            EntryCountryResponse(
                id=country.id,
                name=country.name,
                iso_code=country.iso_code,
                aliases=country.aliases or [],
                region=country.region,
                description=country.description,
                first_seen_at=country.first_seen_at,
                last_seen_at=country.last_seen_at,
                article_count=country.article_count,
                role=role,
                confidence=confidence,
                source=source,
                matched_names=matched_names,
                wikipedia_url=country.wikipedia_url,
                wikipedia_image_url=country.wikipedia_image_url,
            )
        )
    return items


@router.post("/entries/{entry_id}/extract-countries", response_model=ExtractionResponse[CountryResponse])
async def extract_entry_countries(
    entry_id: uuid.UUID = Path(..., description="UUID of the entry to extract from"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Run AI country extraction on the entry and store the resulting entry-country links.

    Returns the countries with an extraction status (success / ai_not_configured / provider_error / parse_error).
    """
    entry = await _get_entry(db, entry_id)
    entry_data = _entry_to_dict(entry)
    countries_with_flags, status, error_msg = await extract_countries(db, user.id, entry_id, entry_data)
    await db.commit()
    items = [country for country, _ in countries_with_flags]
    return ExtractionResponse(items=items, status=status, error_message=error_msg)


# --- Sector Routes ---


@router.get("/entries/{entry_id}/sectors", response_model=list[EntrySectorResponse])
async def get_entry_sectors(
    entry_id: uuid.UUID = Path(..., description="UUID of the entry"),
    user: User = Depends(get_entry_viewer),
    db: AsyncSession = Depends(get_db),
):
    """List the victim sectors an entry describes as targeted, with the sector entity id for linking."""
    result = await db.execute(
        select(EntrySector, Sector.name)
        .join(Sector, Sector.id == EntrySector.sector_id)
        .where(EntrySector.entry_id == entry_id)
        .order_by(Sector.name)
    )
    return [
        EntrySectorResponse(
            id=row.sector_id,
            slug=row.sector,
            name=name,
            sector=row.sector,
            label=name,
            confidence=row.confidence,
            source=row.source,
        )
        for row, name in result.all()
    ]


@router.get("/entries/{entry_id}/article-metadata")
async def get_entry_article_metadata(
    entry_id: uuid.UUID = Path(..., description="UUID of the entry"),
    user: User = Depends(get_entry_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Report type, victim orgs, timeline anchors, and patch availability — plan items 3.9.6–3.9.9.

    Returns the AI-extracted metadata stored on ``entry.metadata_["article_intel"]``,
    or null if none has been extracted.
    """
    entry = await _get_entry(db, entry_id)
    if user.is_anonymous:
        return None  # AI output, which visitors don't get
    return (entry.metadata_ or {}).get("article_intel")


@router.post("/entries/{entry_id}/extract-sectors", response_model=ExtractionResponse[EntrySectorResponse])
async def extract_entry_sectors(
    entry_id: uuid.UUID = Path(..., description="UUID of the entry to extract from"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Run AI sector extraction on the entry and store the resulting entry-sector rows.

    Returns the sectors with an extraction status (success / ai_not_configured / provider_error / parse_error).
    """
    entry = await _get_entry(db, entry_id)
    entry_data = _entry_to_dict(entry)
    items, status, error_msg = await extract_sectors(db, user.id, entry_id, entry_data)
    await db.commit()
    return ExtractionResponse(items=items, status=status, error_message=error_msg)


@router.get("/countries", response_model=PaginatedResponse[CountryResponse])
async def list_countries(
    search: str | None = Query(None, description="Case-insensitive match on country name or whole-word alias"),
    region: str | None = Query(None, description="Exact region filter (e.g. 'Eastern Europe')"),
    sort_by: str = Query(
        "article_count",
        pattern="^(name|region|iso_code|article_count|last_seen_at|linked_count)$",
        description="Sort column; linked_count sorts by non-rejected entity-relationship count",
    ),
    sort_order: str = Query("desc", pattern="^(asc|desc)$", description="Sort direction"),
    limit: int = Query(50, ge=1, le=500, description="Page size"),
    offset: int = Query(0, ge=0, description="Number of rows to skip"),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Paginated country list with search, region filter, sorting, and per-country targeting-actor counts."""
    query = select(Country)
    count_q = select(func.count()).select_from(Country)
    if search:
        pattern = f"%{search}%"
        alias_pattern = rf"\y{re.escape(search)}\y"
        search_filter = or_(
            Country.name.ilike(pattern),
            func.array_to_string(Country.aliases, " ").op("~*")(alias_pattern),
        )
        query = query.where(search_filter)
        count_q = count_q.where(search_filter)
    if region:
        query = query.where(Country.region == region)
        count_q = count_q.where(Country.region == region)

    total = (await db.execute(count_q)).scalar() or 0
    if sort_by == "linked_count":
        sort_expr = _linked_count_subquery(Country, "country")
    else:
        col = getattr(Country, sort_by)
        sort_expr = func.lower(col) if sort_by == "name" else col
    order = sort_expr.asc() if sort_order == "asc" else sort_expr.desc()
    result = await db.execute(query.order_by(order).limit(limit).offset(offset))
    items = result.scalars().all()

    # Batch targeting-actor counts for the workbench "Targeted by" column
    if items:
        from app.models.country_junction import ThreatActorTargetCountry

        counts_q = await db.execute(
            select(ThreatActorTargetCountry.country_id, func.count())
            .where(ThreatActorTargetCountry.country_id.in_([c.id for c in items]))
            .group_by(ThreatActorTargetCountry.country_id)
        )
        count_map = dict(counts_q.all())
        for c in items:
            c.targeting_actor_count = count_map.get(c.id, 0)

    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset, has_more=(offset + limit) < total)


@router.get("/countries/{country_id}", response_model=CountryResponse)
async def get_country(
    country_id: uuid.UUID = Path(..., description="UUID of the country"),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Get a single country by UUID."""
    result = await db.execute(select(Country).where(Country.id == country_id))
    country = result.scalar_one_or_none()
    if not country:
        raise AppError(code="not_found", message="Country not found", status_code=404)
    return country


@router.get("/countries/{country_id}/profile")
async def get_country_profile(
    country_id: uuid.UUID = Path(..., description="UUID of the country"),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Get a rich country threat profile with associated actors, campaigns, entries, and stats."""
    # Fetch country
    result = await db.execute(select(Country).where(Country.id == country_id))
    country = result.scalar_one_or_none()
    if not country:
        raise AppError(code="not_found", message="Country not found", status_code=404)

    # Threat actors originating from this country
    origin_actors_q = await db.execute(
        select(ThreatActor)
        .where(ThreatActor.origin_country_id == country_id)
        .order_by(ThreatActor.last_seen_at.desc())
        .limit(50)
    )
    origin_actors = [
        {
            "id": str(a.id),
            "name": a.name,
            "aliases": a.aliases or [],
            "motivation": a.motivation,
            "last_seen_at": a.last_seen_at.isoformat() if a.last_seen_at else None,
            "article_count": a.article_count,
        }
        for a in origin_actors_q.scalars().all()
    ]

    # Threat actors targeting this country
    targeting_actors_q = await db.execute(
        select(ThreatActor)
        .join(ThreatActorTargetCountry, ThreatActorTargetCountry.threat_actor_id == ThreatActor.id)
        .where(ThreatActorTargetCountry.country_id == country_id)
        .order_by(ThreatActor.last_seen_at.desc())
        .limit(50)
    )
    targeting_actors = [
        {
            "id": str(a.id),
            "name": a.name,
            "aliases": a.aliases or [],
            "motivation": a.motivation,
            "last_seen_at": a.last_seen_at.isoformat() if a.last_seen_at else None,
            "article_count": a.article_count,
        }
        for a in targeting_actors_q.scalars().all()
    ]

    # Campaigns linked to this country
    campaigns_q = await db.execute(
        select(Campaign, CampaignCountry.role)
        .join(CampaignCountry, CampaignCountry.campaign_id == Campaign.id)
        .where(CampaignCountry.country_id == country_id)
        .order_by(Campaign.updated_at.desc())
        .limit(50)
    )
    campaigns = [
        {
            "id": str(c.id),
            "name": c.name,
            "status": c.status,
            "role": role,
            "start_date": c.start_date.isoformat() if c.start_date else None,
        }
        for c, role in campaigns_q.all()
    ]

    # Recent entries mentioning this country with role breakdown
    entries_q = await db.execute(
        select(Entry.id, Entry.title, Entry.published_at, EntryCountry.role)
        .join(EntryCountry, EntryCountry.entry_id == Entry.id)
        .where(EntryCountry.country_id == country_id)
        .order_by(Entry.published_at.desc())
        .limit(25)
    )
    recent_entries = [
        {"id": str(eid), "title": title, "published_at": pub.isoformat() if pub else None, "role": role}
        for eid, title, pub, role in entries_q.all()
    ]

    # Role breakdown stats
    role_stats_q = await db.execute(
        select(EntryCountry.role, func.count()).where(EntryCountry.country_id == country_id).group_by(EntryCountry.role)
    )
    role_breakdown = {role or "unknown": count for role, count in role_stats_q.all()}

    # Related countries (co-occur in same entries)
    related_q = await db.execute(
        select(Country.id, Country.name, Country.iso_code, func.count().label("shared_entries"))
        .join(EntryCountry, EntryCountry.country_id == Country.id)
        .where(
            EntryCountry.entry_id.in_(select(EntryCountry.entry_id).where(EntryCountry.country_id == country_id)),
            Country.id != country_id,
        )
        .group_by(Country.id, Country.name, Country.iso_code)
        .order_by(func.count().desc())
        .limit(10)
    )
    related_countries = [
        {"id": str(cid), "name": name, "iso_code": iso, "shared_entries": cnt}
        for cid, name, iso, cnt in related_q.all()
    ]

    return {
        "country": {
            "id": str(country.id),
            "name": country.name,
            "iso_code": country.iso_code,
            "aliases": country.aliases or [],
            "region": country.region,
            "description": country.description,
            "article_count": country.article_count,
            "first_seen_at": country.first_seen_at.isoformat() if country.first_seen_at else None,
            "last_seen_at": country.last_seen_at.isoformat() if country.last_seen_at else None,
        },
        "origin_actors": origin_actors,
        "targeting_actors": targeting_actors,
        "campaigns": campaigns,
        "recent_entries": recent_entries,
        "role_breakdown": role_breakdown,
        "related_countries": related_countries,
    }


@router.get("/regions")
async def list_regions(
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """List all regions with country counts and threat activity stats."""
    result = await db.execute(
        select(
            Country.region,
            func.count(Country.id).label("country_count"),
            func.sum(Country.article_count).label("total_articles"),
        )
        .where(Country.region.is_not(None))
        .group_by(Country.region)
        .order_by(func.sum(Country.article_count).desc())
    )
    regions = [
        {"region": region, "country_count": cnt, "total_articles": int(articles or 0)}
        for region, cnt, articles in result.all()
    ]
    return {"regions": regions}


# --- Sector entity routes ---


async def _load_sector(db: AsyncSession, sector_ref: str) -> Sector:
    """A sector is addressable by UUID, by its canonical slug (``healthcare``), by
    its exact display name (``Financial Services`` — so a profile chip can link by
    the label it shows) or by one of its aliases (``banks``)."""
    try:
        cond = Sector.id == uuid.UUID(sector_ref)
    except ValueError:
        ref = sector_ref.strip().lower()
        cond = or_(Sector.slug == ref, func.lower(Sector.name) == ref, Sector.aliases.any(ref))
    sector = (await db.execute(select(Sector).where(cond))).scalar_one_or_none()
    if not sector:
        raise AppError(code="not_found", message="Sector not found", status_code=404)
    return sector


_SECTOR_VICTIM_WINDOW_DAYS = 90


async def _attach_sector_counts(db: AsyncSession, sectors: list[Sector]) -> None:
    """Batch the per-sector counts the workbench columns show.

    ``victim_count`` is leak-site disclosures in the last 90 days — the recent
    ground truth, not the all-time pile the ransomware page already sums.
    """
    if not sectors:
        return
    ids = [s.id for s in sectors]
    slugs = [s.slug for s in sectors]
    actor_counts = dict(
        (
            await db.execute(
                select(ThreatActorTargetSector.sector_id, func.count())
                .where(ThreatActorTargetSector.sector_id.in_(ids))
                .group_by(ThreatActorTargetSector.sector_id)
            )
        ).all()
    )
    malware_counts = dict(
        (
            await db.execute(
                select(MalwareTargetSector.sector_id, func.count())
                .where(MalwareTargetSector.sector_id.in_(ids))
                .group_by(MalwareTargetSector.sector_id)
            )
        ).all()
    )
    since = datetime.now(UTC) - timedelta(days=_SECTOR_VICTIM_WINDOW_DAYS)
    victim_counts = dict(
        (
            await db.execute(
                select(VictimDisclosure.sector, func.count())
                .where(VictimDisclosure.sector.in_(slugs), VictimDisclosure.posted_at >= since)
                .group_by(VictimDisclosure.sector)
            )
        ).all()
    )
    for s in sectors:
        s.targeting_actor_count = actor_counts.get(s.id, 0)
        s.targeting_malware_count = malware_counts.get(s.id, 0)
        s.victim_count = victim_counts.get(s.slug, 0)


@router.get("/sectors", response_model=PaginatedResponse[SectorResponse])
async def list_sectors(
    search: str | None = Query(None, description="Case-insensitive match on sector name, slug or whole-word alias"),
    sort_by: str = Query(
        "article_count",
        pattern="^(name|article_count|last_seen_at|linked_count|targeting_actor_count|victim_count)$",
        description=(
            "Sort column; linked_count sorts by non-rejected entity-relationship count, "
            "targeting_actor_count by asserted actor claims, victim_count by leak-site victims in the last 90 days"
        ),
    ),
    sort_order: str = Query("desc", pattern="^(asc|desc)$", description="Sort direction"),
    limit: int = Query(50, ge=1, le=500, description="Page size"),
    offset: int = Query(0, ge=0, description="Number of rows to skip"),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Paginated list of the victim-sector vocabulary with per-sector targeting and victim counts."""
    query = select(Sector)
    count_q = select(func.count()).select_from(Sector)
    if search:
        pattern = f"%{search}%"
        alias_pattern = rf"\y{re.escape(search)}\y"
        search_filter = or_(
            Sector.name.ilike(pattern),
            Sector.slug.ilike(pattern),
            func.array_to_string(Sector.aliases, " ").op("~*")(alias_pattern),
        )
        query = query.where(search_filter)
        count_q = count_q.where(search_filter)

    total = (await db.execute(count_q)).scalar() or 0
    if sort_by == "linked_count":
        sort_expr = _linked_count_subquery(Sector, "sector")
    elif sort_by == "targeting_actor_count":
        sort_expr = (
            select(func.count())
            .select_from(ThreatActorTargetSector)
            .where(ThreatActorTargetSector.sector_id == Sector.id)
            .correlate(Sector)
            .scalar_subquery()
        )
    elif sort_by == "victim_count":
        since = datetime.now(UTC) - timedelta(days=_SECTOR_VICTIM_WINDOW_DAYS)
        sort_expr = (
            select(func.count())
            .select_from(VictimDisclosure)
            .where(VictimDisclosure.sector == Sector.slug, VictimDisclosure.posted_at >= since)
            .correlate(Sector)
            .scalar_subquery()
        )
    else:
        col = getattr(Sector, sort_by)
        sort_expr = func.lower(col) if sort_by == "name" else col
    order = sort_expr.asc() if sort_order == "asc" else sort_expr.desc()
    result = await db.execute(query.order_by(order, Sector.slug.asc()).limit(limit).offset(offset))
    items = list(result.scalars().all())
    await _attach_sector_counts(db, items)
    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset, has_more=(offset + limit) < total)


@router.get("/sectors/{sector_ref}", response_model=SectorResponse)
async def get_sector(
    sector_ref: str = Path(..., description="Sector UUID or canonical slug (e.g. healthcare)"),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Get a single sector by UUID or slug, with its targeting and 90-day victim counts."""
    sector = await _load_sector(db, sector_ref)
    await _attach_sector_counts(db, [sector])
    return sector


@router.get("/sectors/{sector_ref}/profile")
async def get_sector_profile(
    sector_ref: str = Path(..., description="Sector UUID or canonical slug (e.g. healthcare)"),
    window_days: int = Query(90, ge=7, le=730, description="Window for victim and country activity"),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """The sector's victimology: who targets it (reported vs asserted), leak-site victims,
    the country cross-tab, campaigns, the intel profiles that scope it, and recent articles.

    *Reported* actors/malware co-occur with the sector on articles the AI judged
    to describe it as targeted (counted by distinct article). *Asserted* ones
    carry a targets-sector claim row, with the door that wrote it.
    """
    sector = await _load_sector(db, sector_ref)
    now = datetime.now(UTC)
    since = now - timedelta(days=window_days)
    sector_entries = select(EntrySector.entry_id).where(EntrySector.sector_id == sector.id)

    async def _reported(entity_cls, junction_cls, fk):
        n = func.count(func.distinct(junction_cls.entry_id))
        rows = await db.execute(
            select(entity_cls.id, entity_cls.name, n.label("n"))
            .join(entity_cls, entity_cls.id == fk)
            .where(junction_cls.entry_id.in_(sector_entries))
            .group_by(entity_cls.id, entity_cls.name)
            .order_by(n.desc(), entity_cls.name.asc())
            .limit(25)
        )
        return [{"id": str(eid), "name": name, "article_count": cnt} for eid, name, cnt in rows.all()]

    async def _asserted(entity_cls, junction_cls, fk):
        rows = await db.execute(
            select(entity_cls.id, entity_cls.name, junction_cls.source, junction_cls.article_count)
            .join(entity_cls, entity_cls.id == fk)
            .where(junction_cls.sector_id == sector.id)
            .order_by(junction_cls.article_count.desc(), entity_cls.name.asc())
            .limit(50)
        )
        return [
            {"id": str(eid), "name": name, "source": source, "article_count": cnt}
            for eid, name, source, cnt in rows.all()
        ]

    reported_actors = await _reported(ThreatActor, EntryThreatActor, EntryThreatActor.threat_actor_id)
    reported_malware = await _reported(MalwareFamily, EntryMalware, EntryMalware.malware_family_id)
    asserted_actors = await _asserted(ThreatActor, ThreatActorTargetSector, ThreatActorTargetSector.threat_actor_id)
    asserted_malware = await _asserted(MalwareFamily, MalwareTargetSector, MalwareTargetSector.malware_family_id)

    campaigns_q = await db.execute(
        select(Campaign)
        .join(CampaignSector, CampaignSector.campaign_id == Campaign.id)
        .where(CampaignSector.sector_id == sector.id)
        .order_by(Campaign.updated_at.desc())
        .limit(50)
    )
    campaigns = [
        {
            "id": str(c.id),
            "name": c.name,
            "status": c.status,
            "start_date": c.start_date.isoformat() if c.start_date else None,
        }
        for c in campaigns_q.scalars().all()
    ]

    # --- leak-site victims: the richest victimology signal in the platform ---
    victims_all = (
        await db.execute(
            select(func.count()).select_from(VictimDisclosure).where(VictimDisclosure.sector == sector.slug)
        )
    ).scalar() or 0
    victims_window = (
        await db.execute(
            select(func.count())
            .select_from(VictimDisclosure)
            .where(VictimDisclosure.sector == sector.slug, VictimDisclosure.posted_at >= since)
        )
    ).scalar() or 0
    month = func.date_trunc("month", VictimDisclosure.posted_at)
    monthly_q = await db.execute(
        select(month.label("m"), func.count())
        .where(VictimDisclosure.sector == sector.slug, VictimDisclosure.posted_at >= now - timedelta(days=365))
        .group_by(month)
        .order_by(month)
    )
    victims_monthly = [{"month": m.date().isoformat(), "count": n} for m, n in monthly_q.all()]
    groups_q = await db.execute(
        select(VictimDisclosure.group_name_raw, func.count())
        .where(
            VictimDisclosure.sector == sector.slug,
            VictimDisclosure.posted_at >= since,
            VictimDisclosure.group_name_raw.is_not(None),
        )
        .group_by(VictimDisclosure.group_name_raw)
        .order_by(func.count().desc())
        .limit(10)
    )
    top_groups = [{"group": g, "victims": n} for g, n in groups_q.all()]
    recent_q = await db.execute(
        select(VictimDisclosure, RansomwareVictim.name, Country.name, Country.iso_code)
        .join(RansomwareVictim, RansomwareVictim.id == VictimDisclosure.victim_id)
        .outerjoin(Country, Country.id == VictimDisclosure.country_id)
        .where(VictimDisclosure.sector == sector.slug)
        .order_by(VictimDisclosure.posted_at.desc())
        .limit(20)
    )
    recent_victims = [
        {
            "id": str(d.id),
            "victim_id": str(d.victim_id),
            "victim_name": vname,
            "group": d.group_name_raw,
            "country": cname,
            "country_code": ciso,
            "posted_at": d.posted_at.isoformat() if d.posted_at else None,
        }
        for d, vname, cname, ciso in recent_q.all()
    ]

    # --- sector × country: articles that name a victim country, plus leak-site victims ---
    countries: dict[uuid.UUID, dict] = {}
    article_countries_q = await db.execute(
        select(Country.id, Country.name, Country.iso_code, func.count(func.distinct(EntryCountry.entry_id)))
        .join(EntryCountry, EntryCountry.country_id == Country.id)
        .join(Entry, Entry.id == EntryCountry.entry_id)
        .where(
            EntryCountry.entry_id.in_(sector_entries),
            Entry.published_at >= since,
            or_(EntryCountry.role.is_(None), EntryCountry.role.not_in(["origin", "infrastructure"])),
        )
        .group_by(Country.id, Country.name, Country.iso_code)
    )
    for cid, cname, ciso, n in article_countries_q.all():
        countries[cid] = {"id": str(cid), "name": cname, "iso_code": ciso, "article_count": n, "victim_count": 0}
    victim_countries_q = await db.execute(
        select(Country.id, Country.name, Country.iso_code, func.count())
        .join(VictimDisclosure, VictimDisclosure.country_id == Country.id)
        .where(VictimDisclosure.sector == sector.slug, VictimDisclosure.posted_at >= since)
        .group_by(Country.id, Country.name, Country.iso_code)
    )
    for cid, cname, ciso, n in victim_countries_q.all():
        row = countries.setdefault(
            cid, {"id": str(cid), "name": cname, "iso_code": ciso, "article_count": 0, "victim_count": 0}
        )
        row["victim_count"] = n
    country_rows = sorted(countries.values(), key=lambda r: -(r["article_count"] + r["victim_count"]))[:15]

    profiles_q = await db.execute(
        select(IntelProfile.id, IntelProfile.name)
        .where(IntelProfile.sectors.any(sector.slug))
        .order_by(IntelProfile.name)
    )
    intel_profiles = [{"id": str(pid), "name": pname} for pid, pname in profiles_q.all()]

    entries_q = await db.execute(
        select(Entry.id, Entry.title, Entry.published_at, EntrySector.confidence)
        .join(EntrySector, EntrySector.entry_id == Entry.id)
        .where(EntrySector.sector_id == sector.id)
        .order_by(Entry.published_at.desc())
        .limit(25)
    )
    recent_entries = [
        {"id": str(eid), "title": title, "published_at": pub.isoformat() if pub else None, "confidence": conf}
        for eid, title, pub, conf in entries_q.all()
    ]
    entry_month = func.date_trunc("month", Entry.published_at)
    entry_monthly_q = await db.execute(
        select(entry_month.label("m"), func.count(func.distinct(Entry.id)))
        .join(EntrySector, EntrySector.entry_id == Entry.id)
        .where(EntrySector.sector_id == sector.id, Entry.published_at >= now - timedelta(days=365))
        .group_by(entry_month)
        .order_by(entry_month)
    )
    articles_monthly = [{"month": m.date().isoformat(), "count": n} for m, n in entry_monthly_q.all()]

    return {
        "sector": {
            "id": str(sector.id),
            "slug": sector.slug,
            "name": sector.name,
            "aliases": sector.aliases or [],
            "description": sector.description,
            "article_count": sector.article_count,
            "first_seen_at": sector.first_seen_at.isoformat() if sector.first_seen_at else None,
            "last_seen_at": sector.last_seen_at.isoformat() if sector.last_seen_at else None,
        },
        "window_days": window_days,
        "reported_actors": reported_actors,
        "reported_malware": reported_malware,
        "asserted_actors": asserted_actors,
        "asserted_malware": asserted_malware,
        "campaigns": campaigns,
        "victims": {
            "total": victims_all,
            "in_window": victims_window,
            "monthly": victims_monthly,
            "top_groups": top_groups,
            "recent": recent_victims,
        },
        "countries": country_rows,
        "intel_profiles": intel_profiles,
        "recent_entries": recent_entries,
        "articles_monthly": articles_monthly,
    }


# --- Unlink Entity from Entry ---


async def _invalidate_after_unlink(
    entity_type: str, entity_id: uuid.UUID, entry_id: uuid.UUID, db: AsyncSession
) -> None:
    """Invalidate Redis pivot/graph caches after unlinking an entity from an entry."""
    from app.intelligence.correlation_cache import invalidate_entity_cache, invalidate_entry_caches

    await invalidate_entity_cache(entity_type, str(entity_id))
    # Also invalidate caches for other entities on this entry whose graphs changed
    await invalidate_entry_caches(db, str(entry_id))


class LinkEntityRequest(BaseModel):
    entity_type: str  # ttp, cve, threat_actor, malware, country, sector, mitigation, tool, vendor, product
    entity_id: uuid.UUID
    selected_text: str | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "entity_type": "threat_actor",
                "entity_id": "d5b2f1a0-3c4e-4b6d-9a8f-1e2d3c4b5a69",
                "selected_text": "Cozy Bear",
            }
        }
    )


@router.post("/entries/{entry_id}/link-entity", status_code=201)
async def link_entity_to_entry(
    entry_id: uuid.UUID = Path(..., description="UUID of the entry to link the entity to"),
    body: LinkEntityRequest = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Link an existing entity to an entry via its junction table."""
    # Verify entry exists
    entry = await db.get(Entry, entry_id)
    if not entry:
        raise AppError(code="not_found", message="Entry not found", status_code=404)

    # Map entity_type to (junction model, FK column name, entity model)
    junction_map = {
        "ttp": (EntryTTP, "ttp_id", TTP),
        "cve": (EntryCVE, "cve_id", CVE),
        "threat_actor": (EntryThreatActor, "threat_actor_id", ThreatActor),
        "malware": (EntryMalware, "malware_family_id", MalwareFamily),
        "country": (EntryCountry, "country_id", Country),
        "mitigation": (EntryMitigation, "mitigation_id", Mitigation),
        "tool": (EntryTool, "tool_id", Tool),
        "vendor": (EntryVendor, "vendor_id", Vendor),
        "product": (EntryProduct, "product_id", Product),
        "sector": (EntrySector, "sector_id", Sector),
    }

    if body.entity_type not in junction_map:
        raise AppError(
            code="invalid_entity_type",
            message=f"Invalid entity type: {body.entity_type}. Must be one of: {', '.join(junction_map.keys())}",
            status_code=400,
        )

    junction_model, fk_col, entity_model = junction_map[body.entity_type]

    # Verify entity exists
    entity = await db.get(entity_model, body.entity_id)
    if not entity:
        raise AppError(code="not_found", message=f"{body.entity_type} not found", status_code=404)

    # Check if link already exists
    existing = await db.execute(
        select(junction_model).where(
            junction_model.entry_id == entry_id,
            getattr(junction_model, fk_col) == body.entity_id,
        )
    )
    if existing.scalar_one_or_none():
        raise AppError(code="already_linked", message="Entity is already linked to this entry", status_code=409)

    # Create the junction record
    kwargs = {fk_col: body.entity_id}
    if hasattr(junction_model, "source"):
        kwargs["source"] = "manual"
    if body.entity_type == "sector":
        # The slug is the junction's natural key; an analyst link is a targeting judgment.
        kwargs["sector"] = entity.slug
        kwargs["role"] = "target"
    # Store the highlighted text as a matched name so the frontend underlines it.
    # Without this the highlighter falls back to entity name + aliases and misses
    # arbitrary surface forms the user selected.
    selected = (body.selected_text or "").strip()
    if selected and hasattr(junction_model, "matched_names"):
        kwargs["matched_names"] = [selected]
    link = junction_model(entry_id=entry_id, **kwargs)
    db.add(link)
    await db.commit()

    # Invalidate caches
    from app.intelligence.correlation_cache import invalidate_entity_cache, invalidate_entry_caches

    await invalidate_entity_cache(body.entity_type, str(body.entity_id))
    await invalidate_entry_caches(db, str(entry_id))

    return {"status": "linked", "entity_type": body.entity_type, "entity_id": str(body.entity_id)}


@router.delete("/entries/{entry_id}/ttps/{ttp_id}", status_code=204)
async def unlink_entry_ttp(
    entry_id: uuid.UUID = Path(..., description="UUID of the entry"),
    ttp_id: uuid.UUID = Path(..., description="UUID of the TTP to unlink"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Remove the entry-TTP association (the TTP itself is kept) and invalidate correlation caches."""
    result = await db.execute(delete(EntryTTP).where(EntryTTP.entry_id == entry_id, EntryTTP.ttp_id == ttp_id))
    if result.rowcount == 0:
        raise AppError(code="not_found", message="Association not found", status_code=404)
    await db.commit()
    await _invalidate_after_unlink("ttp", ttp_id, entry_id, db)
    return Response(status_code=204)


@router.delete("/entries/{entry_id}/cves/{cve_id}", status_code=204)
async def unlink_entry_cve(
    entry_id: uuid.UUID = Path(..., description="UUID of the entry"),
    cve_id: uuid.UUID = Path(..., description="UUID of the CVE to unlink"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Remove the entry-CVE association (the CVE itself is kept) and invalidate correlation caches."""
    result = await db.execute(delete(EntryCVE).where(EntryCVE.entry_id == entry_id, EntryCVE.cve_id == cve_id))
    if result.rowcount == 0:
        raise AppError(code="not_found", message="Association not found", status_code=404)
    await db.commit()
    await _invalidate_after_unlink("cve", cve_id, entry_id, db)
    return Response(status_code=204)


@router.delete("/entries/{entry_id}/threat-actors/{actor_id}", status_code=204)
async def unlink_entry_threat_actor(
    entry_id: uuid.UUID = Path(..., description="UUID of the entry"),
    actor_id: uuid.UUID = Path(..., description="UUID of the threat actor to unlink"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Remove the entry-actor association (the actor itself is kept) and invalidate correlation caches."""
    result = await db.execute(
        delete(EntryThreatActor).where(
            EntryThreatActor.entry_id == entry_id,
            EntryThreatActor.threat_actor_id == actor_id,
        )
    )
    if result.rowcount == 0:
        raise AppError(code="not_found", message="Association not found", status_code=404)
    await db.commit()
    await _invalidate_after_unlink("threat_actor", actor_id, entry_id, db)
    return Response(status_code=204)


@router.delete("/entries/{entry_id}/malware/{malware_id}", status_code=204)
async def unlink_entry_malware(
    entry_id: uuid.UUID = Path(..., description="UUID of the entry"),
    malware_id: uuid.UUID = Path(..., description="UUID of the malware family to unlink"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Remove the entry-malware association (the family itself is kept) and invalidate correlation caches."""
    result = await db.execute(
        delete(EntryMalware).where(
            EntryMalware.entry_id == entry_id,
            EntryMalware.malware_family_id == malware_id,
        )
    )
    if result.rowcount == 0:
        raise AppError(code="not_found", message="Association not found", status_code=404)
    await db.commit()
    await _invalidate_after_unlink("malware", malware_id, entry_id, db)
    return Response(status_code=204)


@router.delete("/entries/{entry_id}/countries/{country_id}", status_code=204)
async def unlink_entry_country(
    entry_id: uuid.UUID = Path(..., description="UUID of the entry"),
    country_id: uuid.UUID = Path(..., description="UUID of the country to unlink"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Remove the entry-country association (the country itself is kept) and invalidate correlation caches."""
    result = await db.execute(
        delete(EntryCountry).where(
            EntryCountry.entry_id == entry_id,
            EntryCountry.country_id == country_id,
        )
    )
    if result.rowcount == 0:
        raise AppError(code="not_found", message="Association not found", status_code=404)
    await db.commit()
    await _invalidate_after_unlink("country", country_id, entry_id, db)
    return Response(status_code=204)


@router.delete("/entries/{entry_id}/sectors/{sector_id}", status_code=204)
async def unlink_entry_sector(
    entry_id: uuid.UUID = Path(..., description="UUID of the entry"),
    sector_id: uuid.UUID = Path(..., description="UUID of the sector to unlink"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Remove the entry-sector association (the sector itself is kept) and invalidate correlation caches."""
    result = await db.execute(
        delete(EntrySector).where(EntrySector.entry_id == entry_id, EntrySector.sector_id == sector_id)
    )
    if result.rowcount == 0:
        raise AppError(code="not_found", message="Association not found", status_code=404)
    await db.execute(
        sa_update(Sector)
        .where(Sector.id == sector_id, Sector.article_count > 0)
        .values(article_count=Sector.article_count - 1)
    )
    await db.commit()
    await _invalidate_after_unlink("sector", sector_id, entry_id, db)
    return Response(status_code=204)


@router.delete("/entries/{entry_id}/mitigations/{mitigation_id}", status_code=204)
async def unlink_entry_mitigation(
    entry_id: uuid.UUID = Path(..., description="UUID of the entry"),
    mitigation_id: uuid.UUID = Path(..., description="UUID of the mitigation to unlink"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Remove the entry-mitigation association (the mitigation itself is kept) and invalidate correlation caches."""
    result = await db.execute(
        delete(EntryMitigation).where(
            EntryMitigation.entry_id == entry_id,
            EntryMitigation.mitigation_id == mitigation_id,
        )
    )
    if result.rowcount == 0:
        raise AppError(code="not_found", message="Association not found", status_code=404)
    await db.commit()
    await _invalidate_after_unlink("mitigation", mitigation_id, entry_id, db)
    return Response(status_code=204)


@router.delete("/entries/{entry_id}/cwes/{cwe_id}", status_code=204)
async def unlink_entry_cwe(
    entry_id: uuid.UUID = Path(..., description="UUID of the entry"),
    cwe_id: uuid.UUID = Path(..., description="UUID of the weakness to unlink"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Remove the entry-weakness association (the catalog row is kept) and invalidate correlation caches."""
    result = await db.execute(delete(EntryCWE).where(EntryCWE.entry_id == entry_id, EntryCWE.cwe_id == cwe_id))
    if result.rowcount == 0:
        raise AppError(code="not_found", message="Association not found", status_code=404)
    await db.commit()
    await _invalidate_after_unlink("cwe", cwe_id, entry_id, db)
    return Response(status_code=204)


@router.delete("/entries/{entry_id}/tools/{tool_id}", status_code=204)
async def unlink_entry_tool(
    entry_id: uuid.UUID = Path(..., description="UUID of the entry"),
    tool_id: uuid.UUID = Path(..., description="UUID of the tool to unlink"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Remove the entry-tool association (the tool itself is kept) and invalidate correlation caches."""
    result = await db.execute(
        delete(EntryTool).where(
            EntryTool.entry_id == entry_id,
            EntryTool.tool_id == tool_id,
        )
    )
    if result.rowcount == 0:
        raise AppError(code="not_found", message="Association not found", status_code=404)
    await db.commit()
    await _invalidate_after_unlink("tool", tool_id, entry_id, db)
    return Response(status_code=204)


@router.delete("/entries/{entry_id}/vendors/{vendor_id}", status_code=204)
async def unlink_entry_vendor(
    entry_id: uuid.UUID = Path(..., description="UUID of the entry"),
    vendor_id: uuid.UUID = Path(..., description="UUID of the vendor to unlink"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Remove the entry-vendor association (the vendor itself is kept) and invalidate correlation caches."""
    result = await db.execute(
        delete(EntryVendor).where(
            EntryVendor.entry_id == entry_id,
            EntryVendor.vendor_id == vendor_id,
        )
    )
    if result.rowcount == 0:
        raise AppError(code="not_found", message="Association not found", status_code=404)
    await db.commit()
    await _invalidate_after_unlink("vendor", vendor_id, entry_id, db)
    return Response(status_code=204)


@router.delete("/entries/{entry_id}/products/{product_id}", status_code=204)
async def unlink_entry_product(
    entry_id: uuid.UUID = Path(..., description="UUID of the entry"),
    product_id: uuid.UUID = Path(..., description="UUID of the product to unlink"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Remove the entry-product association (the product itself is kept) and invalidate correlation caches."""
    result = await db.execute(
        delete(EntryProduct).where(
            EntryProduct.entry_id == entry_id,
            EntryProduct.product_id == product_id,
        )
    )
    if result.rowcount == 0:
        raise AppError(code="not_found", message="Association not found", status_code=404)
    await db.commit()
    await _invalidate_after_unlink("product", product_id, entry_id, db)
    return Response(status_code=204)


# --- Detection Rules Routes ---


@router.post("/entries/{entry_id}/generate-rules", response_model=list[DetectionRuleResponse])
async def generate_entry_rules(
    entry_id: uuid.UUID = Path(..., description="UUID of the source entry"),
    body: DetectionRuleGenerateRequest = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate detection rules from the entry's content via AI, in the requested rule formats.

    Uses the entry's already-linked TTPs as context and persists the generated rules as drafts.
    """
    entry = await _get_entry(db, entry_id)
    entry_data = _entry_to_dict(entry)

    # Get existing TTPs for this entry
    ttp_result = await db.execute(select(TTP).join(EntryTTP).where(EntryTTP.entry_id == entry_id))
    ttps = [
        {"technique_id": t.technique_id, "technique_name": t.technique_name, "tactic": t.tactic}
        for t in ttp_result.scalars().all()
    ]

    rules = await generate_detection_rules(db, user.id, entry_id, entry_data, ttps, body.rule_types)
    await db.commit()

    # Re-query with entry relationship eagerly loaded to avoid MissingGreenlet
    # when Pydantic serializes entry_title/entry_url properties
    if rules:
        rule_ids = [r.id for r in rules]
        result = await db.execute(
            select(DetectionRule).options(selectinload(DetectionRule.entry)).where(DetectionRule.id.in_(rule_ids))
        )
        rules = list(result.scalars().all())

    return rules


@router.post(
    "/intelligence/entities/{entity_type}/{entity_id}/generate-rules",
    response_model=list[DetectionRuleResponse],
)
async def generate_entity_rules(
    entity_type: str = Path(..., description="Entity type: threat_actor, malware, cve, or ttp"),
    entity_id: uuid.UUID = Path(..., description="UUID of the entity"),
    body: DetectionRuleGenerateRequest = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate detection rules for an entity (threat_actor / malware / cve / ttp).

    Entity-scoped wrapper over the entry AI flow: the entity's facts plus its
    most recent linked articles form the generation context. Used by the
    profile Detection tab's "Generate rule" CTA.
    """
    if entity_type not in ENTITY_RULE_TYPES:
        raise AppError(
            code="bad_request",
            message=f"Rule generation is not supported for entity type '{entity_type}'",
            status_code=400,
        )

    rules = await generate_entity_detection_rules(db, user.id, entity_type, entity_id, body.rule_types)
    if rules is None:
        raise AppError(code="not_found", message="Entity not found", status_code=404)
    await db.commit()

    # Re-query with entry relationship eagerly loaded to avoid MissingGreenlet
    # when Pydantic serializes entry_title/entry_url properties
    if rules:
        rule_ids = [r.id for r in rules]
        result = await db.execute(
            select(DetectionRule).options(selectinload(DetectionRule.entry)).where(DetectionRule.id.in_(rule_ids))
        )
        rules = list(result.scalars().all())

    return rules


@router.get("/detection-rules", response_model=PaginatedResponse[DetectionRuleListItem])
async def list_detection_rules(
    rule_type: str | None = Query(None, description="Filter by rule language (e.g. sigma, splunk_spl, yara)"),
    entry_id: uuid.UUID | None = Query(None, description="Only rules attached to this entry"),
    is_draft: bool | None = Query(None, description="Filter by draft status"),
    search: str | None = Query(
        None, max_length=200, description="Substring match on title/description/tags/tactics, relevance-ranked"
    ),
    severity: str | None = Query(None, description="Exact severity filter"),
    source_repo: str | None = Query(None, description="Only rules imported from this upstream GitHub repo"),
    tactic: str | None = Query(None, description="Only rules mapped to this MITRE ATT&CK tactic"),
    product: str | None = Query(None, description="Only rules whose source_products include this product"),
    technique: str | None = Query(
        None, max_length=20, description="Only rules whose source_ttps include this ATT&CK technique id"
    ),
    cve: str | None = Query(None, max_length=30, description="Only rules whose source_cves include this CVE id"),
    authored_local: bool | None = Query(
        None, description="True: only locally authored rules (no upstream repo); false: only imported rules"
    ),
    created_after: datetime | None = Query(None, description="Only rules created at or after this timestamp"),
    sort_by: str = Query(
        "created_at",
        pattern="^(title|rule_type|severity|is_draft|created_at|updated_at|upstream_updated_at)$",
        description="Sort column",
    ),
    sort_order: str = Query("desc", pattern="^(asc|desc)$", description="Sort direction"),
    limit: int = Query(50, ge=1, le=500, description="Page size"),
    offset: int = Query(0, ge=0, description="Number of rows to skip"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Paginated detection-rule library list (lightweight rows without rule content).

    Supports filtering by type, draft status, severity, provenance, tactic, and product; each row is
    annotated with telemetry feasibility against the enabled Telemetry Sources inventory.
    """
    query = select(DetectionRule).options(selectinload(DetectionRule.entry))
    count_q = select(func.count()).select_from(DetectionRule)
    if rule_type:
        query = query.where(DetectionRule.rule_type == rule_type)
        count_q = count_q.where(DetectionRule.rule_type == rule_type)
    if entry_id:
        query = query.where(DetectionRule.entry_id == entry_id)
        count_q = count_q.where(DetectionRule.entry_id == entry_id)
    if is_draft is not None:
        query = query.where(DetectionRule.is_draft == is_draft)
        count_q = count_q.where(DetectionRule.is_draft == is_draft)
    if severity:
        query = query.where(DetectionRule.severity == severity)
        count_q = count_q.where(DetectionRule.severity == severity)
    if source_repo:
        repo_filter = DetectionRule.metadata_["repo"].astext == source_repo
        query = query.where(repo_filter)
        count_q = count_q.where(repo_filter)
    if tactic:
        query = query.where(DetectionRule.mitre_tactics.any(tactic))
        count_q = count_q.where(DetectionRule.mitre_tactics.any(tactic))
    if product:
        product_filter = DetectionRule.source_products.contains([product])
        query = query.where(product_filter)
        count_q = count_q.where(product_filter)
    if technique:
        # type_coerce, not cast(json.dumps(...)): the JSONB bind serializes its
        # value itself — a pre-dumped string double-encodes and matches nothing.
        technique_filter = DetectionRule.source_ttps.op("@>")(type_coerce([technique], JSONB))
        query = query.where(technique_filter)
        count_q = count_q.where(technique_filter)
    if cve:
        cve_filter = DetectionRule.source_cves.op("@>")(type_coerce([cve], JSONB))
        query = query.where(cve_filter)
        count_q = count_q.where(cve_filter)
    if authored_local is not None:
        # authored_local == no upstream repo recorded in metadata
        repo_present = DetectionRule.metadata_["repo"].astext.isnot(None)
        local_filter = ~repo_present if authored_local else repo_present
        query = query.where(local_filter)
        count_q = count_q.where(local_filter)
    if created_after:
        query = query.where(DetectionRule.created_at >= created_after)
        count_q = count_q.where(DetectionRule.created_at >= created_after)
    if search:
        term = f"%{search}%"
        search_filter = or_(
            DetectionRule.title.ilike(term),
            DetectionRule.description.ilike(term),
            DetectionRule.tags.any(search),
            DetectionRule.mitre_tactics.any(search),
            func.array_to_string(DetectionRule.tags, " ").ilike(term),
            func.array_to_string(DetectionRule.mitre_tactics, " ").ilike(term),
        )
        query = query.where(search_filter)
        count_q = count_q.where(search_filter)

        # Relevance ranking: title > tags/tactics > description
        relevance = case(
            (DetectionRule.title.ilike(term), 1),
            (func.array_to_string(DetectionRule.tags, " ").ilike(term), 2),
            (func.array_to_string(DetectionRule.mitre_tactics, " ").ilike(term), 2),
            else_=3,
        )

    total = (await db.execute(count_q)).scalar() or 0
    col = getattr(DetectionRule, sort_by)
    sort_expr = func.lower(col) if sort_by == "title" else col
    order = sort_expr.asc() if sort_order == "asc" else sort_expr.desc()
    order = order.nullslast()  # keep unmapped (e.g. null upstream_updated_at) rows out of the way
    if search:
        result = await db.execute(query.order_by(relevance, order).limit(limit).offset(offset))
    else:
        result = await db.execute(query.order_by(order).limit(limit).offset(offset))
    items = list(result.scalars().all())

    # Attach per-rule telemetry feasibility vs the enabled Telemetry Sources inventory.
    from app.services.detection_coverage import get_available_telemetry, rule_telemetry_coverage

    available = await get_available_telemetry(db)
    for r in items:
        r.telemetry = rule_telemetry_coverage(r, available)

    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset, has_more=(offset + limit) < total)


def _meili_quote(value: str) -> str:
    """Quote a Meilisearch filter literal. Backslashes first, then quotes."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _telemetry_clause(mode: str, available) -> str | None:
    """Meilisearch clause for "runnable on the telemetry we collect".

    Feasibility is deliberately not indexed — ticking a telemetry source would
    then need a rule reindex to take effect, and a stale verdict is invisible.
    Instead the index carries each rule's raw required tokens and the verdict is
    computed here, once per request, over the few hundred distinct tokens in the
    vocabulary (match_data_source is memoized on token + profile).

    Returns None when nothing can match — an empty inventory has no covered
    rules, a fully satisfied one has no gaps — which the caller turns into an
    empty result rather than an unfiltered one.
    """
    from app.services.detection_coverage import match_data_source

    collected: list[str] = []
    absent: list[str] = []
    for value in meilisearch_client.rule_facet_values("telemetry_tokens"):
        (collected if match_data_source(value, available) else absent).append(value)

    def _in(values: list[str]) -> str:
        return "telemetry_tokens IN [" + ", ".join(_meili_quote(v) for v in values) + "]"

    if mode == "covered":
        # `IN [collected]` also carries "declares a need at all": a rule with no
        # discernible telemetry need is not evidence that we could run it.
        if not collected:
            return None
        return f"{_in(collected)} AND NOT {_in(absent)}" if absent else _in(collected)
    if not absent:
        return None
    return _in(absent)


@router.get("/detection-rules/search")
async def search_detection_rules(
    q: str = Query("", max_length=200, description="Full-text query; empty matches all"),
    scope: str = Query(
        "both",
        pattern="^(metadata|content|both)$",
        description="Which attributes `q` searches: rule metadata, the rule body, or both",
    ),
    rule_type: list[str] | None = Query(None, description="Rule languages to include (repeatable, ORed)"),
    severity: list[str] | None = Query(None, description="Severities to include (repeatable, ORed)"),
    is_draft: bool | None = Query(None, description="Filter by draft status"),
    source_repo: list[str] | None = Query(None, description="Upstream GitHub repos to include (repeatable, ORed)"),
    source_author: list[str] | None = Query(None, description="Upstream authors to include (repeatable, ORed)"),
    license: list[str] | None = Query(None, description="Upstream licenses to include (repeatable, ORed)"),
    tactic: list[str] | None = Query(None, description="MITRE ATT&CK tactics to include (repeatable, ORed)"),
    product: list[str] | None = Query(None, description="Products linked via the source entry (repeatable, ORed)"),
    vendor: list[str] | None = Query(None, description="Vendors linked via the source entry (repeatable, ORed)"),
    tool: list[str] | None = Query(None, description="Tools linked via the source entry (repeatable, ORed)"),
    data_source: list[str] | None = Query(
        None, description="Values of the rule's declared `data_sources` column (repeatable, ORed)"
    ),
    telemetry_token: list[str] | None = Query(
        None,
        description=(
            "Required telemetry, across every rule format — the rail's Telemetry group (repeatable, ORed). "
            "Wider than `data_source`: falls back to the Sigma log_source triple and the per-format defaults."
        ),
    ),
    tag: list[str] | None = Query(None, description="Tags to include (repeatable, ORed)"),
    actor: list[str] | None = Query(None, description="Threat actors linked via the source entry (repeatable, ORed)"),
    malware: list[str] | None = Query(None, description="Malware linked via the source entry (repeatable, ORed)"),
    technique: list[str] | None = Query(None, description="ATT&CK technique IDs, e.g. T1055 (repeatable, ORed)"),
    authored_local: bool | None = Query(
        None, description="True: only locally authored rules (no upstream repo); false: only imported rules"
    ),
    telemetry: str | None = Query(
        None,
        pattern="^(covered|missing)$",
        description=(
            "Filter by feasibility against the enabled telemetry inventory. "
            "'covered': every source the rule needs is collected. "
            "'missing': the rule needs at least one source that is not."
        ),
    ),
    created_after: datetime | None = Query(None, description="Only rules created at or after this timestamp"),
    sort_by: str = Query(
        "created_at",
        pattern="^(relevance|title|rule_type|severity|is_draft|created_at|updated_at|upstream_updated_at)$",
        description="Sort column; 'relevance' defers to Meilisearch ranking",
    ),
    sort_order: str = Query("desc", pattern="^(asc|desc)$", description="Sort direction"),
    limit: int = Query(100, ge=1, le=500, description="Page size"),
    offset: int = Query(0, ge=0, description="Number of hits to skip"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """The rule library's list and its facet counts, in one Meilisearch round trip.

    Unlike GET /detection-rules (Postgres, ILIKE substring matching), this ranks
    by relevance with typo tolerance and returns a facet distribution scoped to
    the active filters — so the library rail narrows as you click, the way the
    entry search rail does.

    Rows are hydrated from Postgres by id in Meilisearch's order: the index
    carries only what is searched, filtered, or sorted on, while derived fields
    (telemetry coverage against the live inventory, linked entry counts) stay
    computed off the authoritative row.

    Declared before /detection-rules/{rule_id} so the static path isn't parsed as a UUID.
    """

    # Keyed by facet attribute so each count can exclude its own clause; see
    # search_rules for why conjunctive counts break a multi-value rail.
    def _any_of(attr: str, values: list[str] | None) -> None:
        """OR the values within one facet; facets are ANDed with each other.

        Ticking two rule formats should widen the result set, not empty it, so a
        group's own values are a disjunction.
        """
        if not values:
            return
        clause = " OR ".join(f"{attr} = {_meili_quote(v)}" for v in values)
        facet_filters[attr] = f"({clause})" if len(values) > 1 else clause

    facet_filters: dict[str, str] = {}
    _any_of("rule_type", rule_type)
    _any_of("severity", severity)
    _any_of("source_repo", source_repo)
    _any_of("source_author", source_author)
    _any_of("license", license)
    _any_of("mitre_tactics", tactic)
    _any_of("products", product)
    _any_of("vendors", vendor)
    _any_of("tools", tool)
    _any_of("data_sources", data_source)
    _any_of("telemetry_tokens", telemetry_token)
    _any_of("tags", tag)
    _any_of("actors", actor)
    _any_of("malware", malware)
    _any_of("techniques", technique)

    # No facet group of their own — the rail exposes these as saved views, so
    # they narrow every count including their own.
    global_filters: list[str] = []
    if is_draft is not None:
        global_filters.append(f"is_draft = {str(is_draft).lower()}")
    if authored_local is not None:
        global_filters.append(f"authored_local = {str(authored_local).lower()}")
    if created_after:
        global_filters.append(f"created_at >= {int(created_after.timestamp())}")

    from app.services.detection_coverage import get_available_telemetry, rule_telemetry_coverage

    # Read once: the same profile decides the filter and each row's coverage ring.
    available = await get_available_telemetry(db)
    if telemetry:
        clause = _telemetry_clause(telemetry, available)
        if clause is None:
            return {"items": [], "total": 0, "limit": limit, "offset": offset, "has_more": False, "facets": {}}
        global_filters.append(clause)

    # An empty query has no relevance signal to rank by, so fall back to the
    # default column sort rather than handing Meilisearch an arbitrary order.
    sort = (
        None
        if sort_by == "relevance" and q.strip()
        else [f"{'created_at' if sort_by == 'relevance' else sort_by}:{sort_order}"]
    )

    try:
        result = meilisearch_client.search_rules(
            query=q,
            facet_filters=facet_filters,
            global_filters=global_filters,
            sort=sort,
            limit=limit,
            offset=offset,
            scope=scope,
        )
    except Exception as e:
        logger.warning("Rule search failed: %s", e)
        raise AppError(
            code="rule_search_unavailable",
            message="Rule search is temporarily unavailable.",
            status_code=503,
        ) from e

    ids = [uuid.UUID(h["id"]) for h in result.get("hits", [])]
    items: list[DetectionRule] = []
    if ids:
        rows = await db.execute(
            select(DetectionRule).options(selectinload(DetectionRule.entry)).where(DetectionRule.id.in_(ids))
        )
        by_id = {r.id: r for r in rows.scalars().all()}
        # Meilisearch decides the order; a doc whose row has since been deleted
        # is skipped rather than surfacing as a hole.
        items = [by_id[i] for i in ids if i in by_id]

    for r in items:
        r.telemetry = rule_telemetry_coverage(r, available)

    total = result.get("totalHits", 0)
    facets = {
        name: [{"value": v, "count": c} for v, c in sorted(dist.items(), key=lambda kv: -kv[1])]
        for name, dist in (result.get("facetDistribution") or {}).items()
    }
    return {
        "items": [DetectionRuleListItem.model_validate(r) for r in items],
        "total": total,
        "limit": limit,
        "offset": offset,
        "has_more": (offset + limit) < total,
        "facets": facets,
    }


@router.get("/detection-rules/telemetry-vocabulary")
async def get_rule_telemetry_vocabulary(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """The rail's Telemetry values, split by whether the inventory answers them.

    Lets the library tick "everything we collect" in one click: the match is
    tiered and fuzzy (a ticked product name, a canonical behaviour id, or a
    category with a ticked source), so the client cannot derive this list by
    comparing strings against the telemetry inventory itself.

    Declared before /detection-rules/{rule_id} so the static path isn't parsed
    as a UUID.
    """
    from app.services.detection_coverage import get_available_telemetry, match_data_source

    available = await get_available_telemetry(db)
    collected: list[str] = []
    missing: list[str] = []
    for value in meilisearch_client.rule_facet_values("telemetry_tokens"):
        (collected if match_data_source(value, available) else missing).append(value)
    return {"collected": sorted(collected), "missing": sorted(missing)}


@router.get("/detection-rules/facets")
async def get_detection_rule_facets(
    limit_per_facet: int = Query(25, ge=1, le=100, description="Maximum distinct values returned per facet"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Distribution counts for the library's faceted rail: type, source repo, ATT&CK tactic, product."""

    async def _grouped(column):
        rows = await db.execute(
            select(column.label("value"), func.count().label("count"))
            .where(column.isnot(None))
            .group_by(column)
            .order_by(func.count().desc())
            .limit(limit_per_facet)
        )
        return [{"value": v, "count": c} for v, c in rows.all() if v not in (None, "")]

    async def _grouped_unnest(set_returning_fn):
        # Expand the array/JSONB column to one row per element in a subquery
        # (set-returning function in the SELECT list, implicitly lateral to
        # detection_rules), then group the elements.
        sub = select(set_returning_fn.label("value")).select_from(DetectionRule).subquery()
        rows = await db.execute(
            select(sub.c.value, func.count().label("count"))
            .group_by(sub.c.value)
            .order_by(func.count().desc())
            .limit(limit_per_facet)
        )
        return [{"value": v, "count": c} for v, c in rows.all() if v not in (None, "")]

    rule_types = await _grouped(DetectionRule.rule_type)
    repos = await _grouped(DetectionRule.metadata_["repo"].astext)
    tactics = await _grouped_unnest(func.unnest(DetectionRule.mitre_tactics))
    products = await _grouped_unnest(func.jsonb_array_elements_text(DetectionRule.source_products))

    return {"rule_types": rule_types, "repos": repos, "tactics": tactics, "products": products}


#: Coverage confidences that count as evidence a rule is *about* an entity.
#: `low` is a `story:` tag membership or a body-text mention — inventory worth
#: opening, but never enough to clear a gap on its own.
STRONG_COVERAGE_CONFIDENCES = ("high", "medium")


@router.get("/detection-rules/coverage-board")
async def get_coverage_board(
    window: str = Query("7d", pattern="^(24h|7d|30d)$", description="Recency window for trending entries"),
    type: str = Query("cve", pattern="^(cve|technique|actor)$", description="Entity type to rank"),
    limit: int = Query(15, ge=1, le=50, description="Maximum entities returned"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """The intel→rules bridge: entities trending in recent entries, with how many
    library rules cover each. A gap is *no strongly-resolved rule*, not no rule
    at all — `rule_count` is the full inventory, `rule_count_strong` drops the
    low-confidence rows the gap flag must not be cleared by.

    Declared before /detection-rules/{rule_id} so the static path isn't parsed as a UUID.
    """
    from datetime import timedelta

    hours = {"24h": 24, "7d": 168, "30d": 720}[window]
    since = datetime.now(UTC) - timedelta(hours=hours)

    # Each branch ranks its entity type by recent entry volume, then normalizes to
    # (entity uuid, label, sublabel, rule_coverage key, entry count).
    if type == "cve":
        rows = (
            await db.execute(
                select(CVE.id, CVE.cve_id, func.count(func.distinct(Entry.id)).label("ec"))
                .join(EntryCVE, EntryCVE.cve_id == CVE.id)
                .join(Entry, Entry.id == EntryCVE.entry_id)
                .where(Entry.published_at > since)
                .group_by(CVE.id, CVE.cve_id)
                .order_by(func.count(func.distinct(Entry.id)).desc())
                .limit(limit)
            )
        ).all()
        item_type, coverage_type = "cve", entity_types.CVE
        ranked = [(str(r[0]), r[1], None, r[1], r[2]) for r in rows]
    elif type == "technique":
        rows = (
            await db.execute(
                select(TTP.id, TTP.technique_id, TTP.technique_name, func.count(func.distinct(Entry.id)).label("ec"))
                .join(EntryTTP, EntryTTP.ttp_id == TTP.id)
                .join(Entry, Entry.id == EntryTTP.entry_id)
                .where(Entry.published_at > since)
                .group_by(TTP.id, TTP.technique_id, TTP.technique_name)
                .order_by(func.count(func.distinct(Entry.id)).desc())
                .limit(limit)
            )
        ).all()
        item_type, coverage_type = "technique", entity_types.TTP
        ranked = [(str(r[0]), r[1], r[2], r[1], r[3]) for r in rows]
    else:  # actor
        rows = (
            await db.execute(
                select(ThreatActor.id, ThreatActor.name, func.count(func.distinct(Entry.id)).label("ec"))
                .join(EntryThreatActor, EntryThreatActor.threat_actor_id == ThreatActor.id)
                .join(Entry, Entry.id == EntryThreatActor.entry_id)
                .where(Entry.published_at > since)
                .group_by(ThreatActor.id, ThreatActor.name)
                .order_by(func.count(func.distinct(Entry.id)).desc())
                .limit(limit)
            )
        ).all()
        item_type, coverage_type = "threat_actor", entity_types.THREAT_ACTOR
        ranked = [(str(r[0]), r[1], None, str(r[0]), r[2]) for r in rows]

    # One aggregate over the materialised resolution, instead of a COUNT per row.
    # `source_actors` is written by nothing, so the actor branch counted zero
    # forever until rule_coverage started resolving names out of rule text.
    #
    # Two counts, because they answer different questions. `rule_count` is the
    # whole inventory — every resolved rule, weak evidence included. The strong
    # count drops `low`, which is a story:-tag membership or a body-text mention:
    # real inventory, but not a rule that is *about* this entity. On the dev
    # library 33 actors, 56 CVEs and 86 malware families resolve only through
    # low-confidence rows, and counting those as coverage cleared their gap flag
    # on evidence no analyst would accept. Same split, same threshold, as
    # `prior_rules` / `prior_rules_strong` on the threat board.
    counts: dict[str, int] = {}
    strong_counts: dict[str, int] = {}
    keys = [key for _, _, _, key, _ in ranked]
    if keys:
        for entity_key, total, strong in (
            await db.execute(
                select(
                    RuleCoverage.entity_key,
                    func.count(func.distinct(RuleCoverage.rule_id)),
                    func.count(func.distinct(RuleCoverage.rule_id)).filter(
                        RuleCoverage.confidence.in_(STRONG_COVERAGE_CONFIDENCES)
                    ),
                )
                .where(RuleCoverage.entity_type == coverage_type, RuleCoverage.entity_key.in_(keys))
                .group_by(RuleCoverage.entity_key)
            )
        ).all():
            counts[entity_key] = total
            strong_counts[entity_key] = strong

    items = [
        {
            "type": item_type,
            "id": row_id if item_type == "threat_actor" else label,
            "entity_id": row_id,
            "label": label,
            "sublabel": sublabel,
            "entry_count": entry_count,
            "rule_count": counts.get(key, 0),
            "rule_count_strong": strong_counts.get(key, 0),
            # The gap decision reads the strong count only. A row with weak-only
            # inventory is not a gap to write from scratch and not a rule set to
            # extend — it is a diff, and `rule_count` still surfaces it.
            "is_gap": strong_counts.get(key, 0) == 0,
        }
        for row_id, label, sublabel, key, entry_count in ranked
    ]

    return {"window": window, "type": type, "items": items, "total": len(items)}


@router.get("/detection-rules/export")
async def export_detection_rules(
    rule_ids: str | None = Query(None, description="Comma-separated rule UUIDs; omit to export all rules"),
    format: str = Query(
        "yaml", pattern=r"^(yaml|zip)$", description="yaml: single '---'-joined file; zip: one file per rule"
    ),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Export detection rules as YAML or ZIP."""
    import io
    import zipfile

    from fastapi.responses import StreamingResponse

    query = select(DetectionRule)
    if rule_ids:
        ids = [uuid.UUID(rid.strip()) for rid in rule_ids.split(",") if rid.strip()]
        query = query.where(DetectionRule.id.in_(ids))

    result = await db.execute(query.order_by(DetectionRule.created_at.desc()))
    rules = result.scalars().all()

    if not rules:
        raise AppError(code="not_found", message="No rules found to export", status_code=404)

    ext_map = {
        "sigma": ".yml",
        "splunk_spl": ".spl",
        "kql": ".kql",
        "elastic_ql": ".eql",
        "crowdstrike_ql": ".cql",
        "snort_suricata": ".rules",
        "yara": ".yar",
    }

    if format == "yaml":
        content = "\n---\n".join(r.rule_content for r in rules)
        return Response(
            content=content,
            media_type="text/yaml",
            headers={"Content-Disposition": "attachment; filename=detection-rules.yml"},
        )
    else:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for rule in rules:
                ext = ext_map.get(rule.rule_type, ".txt")
                safe_title = "".join(c if c.isalnum() or c in "-_ " else "" for c in rule.title)[:80]
                filename = f"{safe_title}{ext}"
                zf.writestr(filename, rule.rule_content)
        buf.seek(0)
        return StreamingResponse(
            buf,
            media_type="application/zip",
            headers={"Content-Disposition": "attachment; filename=detection-rules.zip"},
        )


@router.get("/detection-rules/needing-review")
async def get_rules_needing_review(
    limit: int = Query(20, ge=1, le=500, description="Maximum rules returned"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Find rules that may need review because new intelligence has arrived for their techniques."""
    # Get all non-draft rules with source_ttps for this user
    rules_result = await db.execute(
        select(DetectionRule)
        .where(
            DetectionRule.is_draft == False,  # noqa: E712
        )
        .order_by(DetectionRule.updated_at.desc())
    )
    rules = rules_result.scalars().all()

    needing_review = []
    for rule in rules:
        if not rule.source_ttps:
            continue

        # Extract technique IDs from source_ttps
        technique_ids = []
        for ttp in rule.source_ttps:
            if isinstance(ttp, str):
                technique_ids.append(ttp)
            elif isinstance(ttp, dict) and "technique_id" in ttp:
                technique_ids.append(ttp["technique_id"])

        if not technique_ids:
            continue

        # Find TTPs matching these technique IDs
        ttps_result = await db.execute(select(TTP).where(TTP.technique_id.in_(technique_ids)))
        ttp_ids = [t.id for t in ttps_result.scalars().all()]

        if not ttp_ids:
            continue

        # Find entries linked to these TTPs that are newer than the rule's last update
        new_entries_result = await db.execute(
            select(func.count(Entry.id))
            .join(EntryTTP, EntryTTP.entry_id == Entry.id)
            .where(
                EntryTTP.ttp_id.in_(ttp_ids),
                Entry.published_at > rule.updated_at,
            )
        )
        new_count = new_entries_result.scalar() or 0

        if new_count > 0:
            needing_review.append(
                {
                    "rule_id": str(rule.id),
                    "rule_title": rule.title,
                    "rule_type": rule.rule_type,
                    "updated_at": str(rule.updated_at),
                    "techniques": technique_ids,
                    "new_article_count": new_count,
                }
            )

        if len(needing_review) >= limit:
            break

    return {"items": needing_review, "total": len(needing_review)}


@router.get("/detection-rules/{rule_id}", response_model=DetectionRuleResponse)
async def get_detection_rule(
    rule_id: uuid.UUID = Path(..., description="UUID of the detection rule"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get a single detection rule with full content and telemetry feasibility annotation."""
    result = await db.execute(select(DetectionRule).where(DetectionRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise AppError(code="not_found", message="Detection rule not found", status_code=404)

    from app.services.detection_coverage import get_available_telemetry, rule_telemetry_coverage

    rule.telemetry = rule_telemetry_coverage(rule, await get_available_telemetry(db))
    return rule


async def _resolve_coverage(db: AsyncSession, rule: DetectionRule) -> None:
    """Materialise this rule's entity coverage now, inside the caller's transaction.

    Without this the resolver only runs on the nightly backstop, so a rule
    authored from an article is invisible to the board and to every
    `rule_coverage` join for up to a day — exactly the window in which someone
    would go looking for it.

    Never fatal: coverage is derived data, and losing a save because the
    autolinker vocabulary could not be built would be a much worse trade.
    """
    from app.services.rule_coverage import resolve_rule

    try:
        await resolve_rule(db, rule)
    except Exception:
        logger.exception("rule_coverage resolve failed for rule %s", rule.id)


@router.put("/detection-rules/{rule_id}", response_model=DetectionRuleResponse)
async def update_detection_rule(
    rule_id: uuid.UUID = Path(..., description="UUID of the detection rule"),
    body: DetectionRuleUpdate = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Partially update a detection rule; only fields present in the body are changed.

    Changing rule_content automatically snapshots the previous content as a new version, and content or
    type changes trigger metadata re-extraction.
    """
    result = await db.execute(select(DetectionRule).where(DetectionRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise AppError(code="not_found", message="Detection rule not found", status_code=404)

    # Track changes before mutations for metadata re-extraction
    content_changed = body.rule_content is not None and body.rule_content != rule.rule_content
    type_changed = body.rule_type is not None and body.rule_type != rule.rule_type

    # Auto-create version when rule_content changes
    if content_changed:
        # Get current max version number
        ver_result = await db.execute(
            select(func.coalesce(func.max(DetectionRuleVersion.version_number), 0)).where(
                DetectionRuleVersion.rule_id == rule_id
            )
        )
        max_ver = ver_result.scalar() or 0
        version = DetectionRuleVersion(
            rule_id=rule_id,
            version_number=max_ver + 1,
            rule_content=rule.rule_content,
            rule_type=rule.rule_type,
            change_description=body.change_description,
            changed_by=user.id,
        )
        db.add(version)
        rule.rule_content = body.rule_content

    if body.title is not None:
        rule.title = body.title
    if body.description is not None:
        rule.description = body.description
    if body.rule_type is not None:
        rule.rule_type = body.rule_type
    if body.severity is not None:
        rule.severity = body.severity
    if body.tags is not None:
        rule.tags = body.tags
    if body.is_draft is not None:
        rule.is_draft = body.is_draft
    if body.log_sources is not None:
        rule.log_sources = body.log_sources
    if body.mitre_tactics is not None:
        rule.mitre_tactics = body.mitre_tactics
    if body.data_sources is not None:
        rule.data_sources = body.data_sources
    if body.notes is not None:
        rule.notes = body.notes
    if body.source_ttps is not None:
        rule.source_ttps = body.source_ttps
    if body.source_cves is not None:
        rule.source_cves = body.source_cves
    if body.source_entries is not None:
        rule.source_entries = body.source_entries
    if body.source_actors is not None:
        rule.source_actors = body.source_actors
    if body.source_campaigns is not None:
        rule.source_campaigns = body.source_campaigns

    # Re-extract metadata when rule_content or rule_type changes
    if content_changed or type_changed or body.metadata is not None:
        from app.intelligence.rule_metadata import extract_and_apply

        if body.metadata is not None:
            rule.metadata_ = body.metadata
        explicit_fields = {k for k, v in body.model_dump(exclude_unset=True).items() if v is not None}
        extract_and_apply(rule, explicit_fields)

    db.add(rule)
    await db.flush()
    # Only the fields the resolver reads are worth a re-resolve; flipping
    # is_draft or editing notes cannot change which entities a rule covers.
    if (
        content_changed
        or type_changed
        or any(
            getattr(body, field) is not None
            for field in ("title", "tags", "source_ttps", "source_cves", "source_actors", "metadata")
        )
    ):
        await _resolve_coverage(db, rule)
    await db.refresh(rule)
    await index_rule(db, rule)
    return rule


@router.delete("/detection-rules/{rule_id}", status_code=204)
async def delete_detection_rule(
    rule_id: uuid.UUID = Path(..., description="UUID of the detection rule"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete a detection rule (its version history is removed with it)."""
    result = await db.execute(select(DetectionRule).where(DetectionRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise AppError(code="not_found", message="Detection rule not found", status_code=404)
    await db.delete(rule)
    await db.flush()
    delete_entity_document("rule", rule_id)


@router.post("/detection-rules", response_model=DetectionRuleResponse, status_code=201)
async def create_detection_rule(
    body: DetectionRuleCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a detection rule; metadata is auto-extracted from the rule content to fill fields not set explicitly."""
    rule = DetectionRule(
        entry_id=body.entry_id,
        created_by=user.id,
        rule_type=body.rule_type,
        title=body.title,
        description=body.description,
        rule_content=body.rule_content,
        severity=body.severity,
        tags=body.tags,
        source_ttps=body.source_ttps,
        # Accepted by DetectionRuleCreate since it was written but never
        # assigned, so a rule authored against an advisory resolved to zero CVEs.
        source_cves=body.source_cves,
        is_draft=body.is_draft,
        log_sources=body.log_sources,
        mitre_tactics=body.mitre_tactics,
        data_sources=body.data_sources,
        notes=body.notes,
        source_entries=body.source_entries,
        source_actors=body.source_actors,
        source_campaigns=body.source_campaigns,
        metadata_=body.metadata,
    )

    # Auto-extract metadata from rule content and fill empty fields
    from app.intelligence.rule_metadata import extract_and_apply

    explicit_fields = {k for k, v in body.model_dump(exclude_unset=True).items() if v is not None}
    extract_and_apply(rule, explicit_fields)

    db.add(rule)
    await db.flush()
    await _resolve_coverage(db, rule)
    await db.refresh(rule, attribute_names=["entry"])
    await index_rule(db, rule)
    return rule


@router.post("/entries/{entry_id}/extract-detection-rules", response_model=list[DetectionRuleResponse])
async def extract_entry_detection_rules(
    entry_id: uuid.UUID = Path(..., description="UUID of the entry to scan for embedded rules"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Extract detection rules (SIGMA, YARA, Elastic EQL/ES|QL/TOML, KQL, Snort/Suricata, Splunk) from entry content."""
    from app.intelligence.rule_extraction import extract_rules_from_content, store_extracted_rules

    entry = await _get_entry(db, entry_id)
    # Prefer raw_content from metadata (github_repo entries store file content there)
    text = (entry.metadata_ or {}).get("raw_content") or entry.content_text or ""
    if not (entry.metadata_ or {}).get("raw_content") and entry.title:
        text = entry.title + "\n" + text

    extracted = extract_rules_from_content(
        text, source_url=entry.url, html=entry.content_html, article_title=entry.title
    )
    if not extracted:
        return []

    stored = await store_extracted_rules(db, entry_id, user.id, extracted)
    await db.commit()

    # Re-query with entry relationship to avoid MissingGreenlet on serialization
    if stored:
        rule_ids = [r.id for r in stored]
        result = await db.execute(
            select(DetectionRule).options(selectinload(DetectionRule.entry)).where(DetectionRule.id.in_(rule_ids))
        )
        stored = list(result.scalars().all())

    return stored


@router.post("/detection-rules/validate")
async def validate_detection_rule(
    body: DetectionRuleValidateRequest,
    user: User = Depends(get_current_user),
):
    """Validate detection rule syntax without saving."""
    from app.intelligence.rule_validation import validate_rule

    result = validate_rule(body.rule_type, body.rule_content)
    return {
        "valid": result.valid,
        "errors": [
            {"line": e.line, "column": e.column, "severity": e.severity, "message": e.message} for e in result.errors
        ],
        "suggestions": result.suggestions,
    }


@router.post("/detection-rules/extract-metadata")
async def extract_detection_rule_metadata(
    body: DetectionRuleValidateRequest,
    user: User = Depends(get_current_user),
):
    """Extract metadata from rule content without saving."""
    from app.intelligence.rule_metadata import extract_rule_metadata, map_metadata_to_fields

    metadata = extract_rule_metadata(body.rule_type, body.rule_content)
    mapped_fields = map_metadata_to_fields(metadata) if metadata else {}
    return {"metadata": metadata, "mapped_fields": mapped_fields}


# --- AI Rule Conversion & Chat ---

RULE_TYPE_LABELS = {
    "sigma": "SIGMA",
    "splunk_spl": "Splunk SPL",
    "kql": "KQL",
    "elastic_ql": "Elastic QL",
    "crowdstrike_ql": "CrowdStrike QL",
    "snort_suricata": "Snort/Suricata",
    "yara": "YARA",
    "nuclei": "Nuclei",
    "panther": "Panther",
}


@router.post("/detection-rules/{rule_id}/convert")
async def convert_detection_rule(
    rule_id: uuid.UUID = Path(..., description="UUID of the source detection rule"),
    body: RuleConvertRequest = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Convert a detection rule to a different rule language using AI."""

    rule = (await db.execute(select(DetectionRule).where(DetectionRule.id == rule_id))).scalar_one_or_none()
    if not rule:
        raise AppError(code="not_found", message="Detection rule not found", status_code=404)

    if rule.rule_type == body.target_type:
        raise AppError(code="same_type", message="Source and target rule types are the same", status_code=400)

    from app.ai.caller import Caller
    from app.ai.engine import _get_provider_instance, record_direct_result, resolve_assignment

    resolved = await resolve_assignment(db, Caller.user(user.id), "detection_rules")
    if resolved is None:
        raise AppError(
            code="no_ai_assignment",
            message="No AI provider assigned for detection rules. Configure one in Settings > AI.",
            status_code=400,
        )

    task, provider_model = resolved.task, resolved.provider
    provider = _get_provider_instance(provider_model, extra_config=resolved.config)

    source_label = RULE_TYPE_LABELS.get(rule.rule_type, rule.rule_type)
    target_label = RULE_TYPE_LABELS.get(body.target_type, body.target_type)

    prompt = f"""Convert the following {source_label} detection rule to {target_label} format.

SOURCE RULE ({source_label}):
```
{rule.rule_content}
```

RULE CONTEXT:
- Title: {rule.title}
- Description: {rule.description or "N/A"}
- Severity: {rule.severity or "N/A"}
- MITRE Tactics: {", ".join(rule.mitre_tactics) if rule.mitre_tactics else "N/A"}
- Data Sources: {", ".join(rule.data_sources) if rule.data_sources else "N/A"}

CONVERSION INSTRUCTIONS:
1. Produce a complete, syntactically valid {target_label} rule — not pseudocode
2. Map field names correctly between formats
   (e.g., SIGMA 'Image' → Splunk 'process_name' → Elastic 'process.executable')
3. Translate log source references to the target platform's conventions
4. Preserve the detection logic, severity, and MITRE ATT&CK mappings
5. If certain features cannot be directly translated, add a comment explaining the limitation
6. Include appropriate metadata/headers for the target format

Return ONLY the converted rule content — no explanation, no markdown fences, just the raw rule text."""

    config = resolved.config
    # Bound the provider call below the gunicorn worker timeout (180s) and
    # nginx's proxy_read_timeout. Unbounded, a slow claude_code CLI call plus
    # its automatic retry outlasts the worker and the request dies as a 502
    # instead of a readable error. Passing an explicit per-call timeout also
    # forces the CLI provider to a single attempt.
    ledger = dict(
        caller=Caller.user(user.id),
        task=task,
        provider_model=provider_model,
        model_name=resolved.model_name,
        prompt_used=prompt,
        target_type="detection_rule",
        target_id=rule.id,
        key_owner_id=resolved.key_owner_id,
    )
    try:
        response = await provider.complete(
            prompt=prompt,
            system="You are an expert detection engineer. Convert detection rules between formats with perfect syntax.",
            temperature=config.get("temperature", 0.1),
            max_tokens=config.get("max_tokens", 4096),
            model=resolved.model_name,
            timeout_seconds=float(config.get("timeout_seconds", 150)),
        )
    except Exception as e:
        # Commit before raising: the session dependency rolls back on any
        # exception, and a failed call still has to count as a request.
        await record_direct_result(db, response=None, error=str(e), **ledger)
        await db.commit()
        raise AppError(code="ai_error", message=f"AI provider error: {e}", status_code=502)

    converted_content = response.content.strip()
    # Strip markdown fences if the model added them despite instructions
    if converted_content.startswith("```"):
        lines = converted_content.split("\n")
        lines = lines[1:]  # remove opening fence
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        converted_content = "\n".join(lines)

    cost = (await record_direct_result(db, response=response, content=converted_content, **ledger)).cost_estimate

    sibling = await _upsert_conversion_sibling(
        db,
        parent=rule,
        target_type=body.target_type,
        target_label=target_label,
        content=converted_content,
        user=user,
        provenance={
            "converted_from": str(rule.id),
            "source_type": rule.rule_type,
            "converted_at": datetime.now(UTC).isoformat(),
            "model": response.model,
            "tokens_used": response.tokens_input + response.tokens_output,
            "cost": float(cost),
        },
    )

    return {
        "converted_content": converted_content,
        "source_type": rule.rule_type,
        "target_type": body.target_type,
        "model": response.model,
        "tokens_input": response.tokens_input,
        "tokens_output": response.tokens_output,
        "tokens_used": response.tokens_input + response.tokens_output,
        "cost": float(cost),
        # The conversion is now a rule of its own. Callers that only wanted the
        # text still get it above; these two say where it landed.
        "rule_id": str(sibling.id),
        "title": sibling.title,
    }


async def _upsert_conversion_sibling(
    db: AsyncSession,
    *,
    parent: DetectionRule,
    target_type: str,
    target_label: str,
    content: str,
    user: User,
    provenance: dict,
) -> DetectionRule:
    """Store a conversion as a real rule row hanging off its parent.

    It used to be a JSON blob in `metadata.rule_conversions`: absent from
    /detection-rules/search, absent from detection_rule_versions, not exportable
    on its own, and deleted with the parent. A KQL translation of a Sigma rule is
    a rule — the thing you hand to whoever runs Sentinel — so it gets a row.

    One sibling per (parent, target format). Re-converting rewrites that row and
    snapshots the previous body as a version, rather than accumulating a pile of
    near-identical rules every time someone re-runs the model.

    The parent's entity mappings (techniques, CVEs, actors, entries) are copied
    across: the translation detects the same thing, and without them the sibling
    would resolve to nothing and read as an unattributed orphan on the board.
    `data_sources` and `log_sources` are deliberately *not* copied — those are
    format-specific and get re-extracted from the converted body below.
    """
    sibling = (
        (
            await db.execute(
                select(DetectionRule).where(
                    DetectionRule.derived_from == parent.id,
                    DetectionRule.rule_type == target_type,
                )
            )
        )
        .scalars()
        .first()
    )

    if sibling is None:
        sibling = DetectionRule(
            entry_id=parent.entry_id,
            created_by=user.id,
            derived_from=parent.id,
            rule_type=target_type,
            title=f"{parent.title} ({target_label})",
            description=parent.description,
            rule_content=content,
            severity=parent.severity,
            tags=list(parent.tags or []),
            source_ttps=list(parent.source_ttps or []),
            source_cves=list(parent.source_cves or []),
            # A machine translation is a draft until a human reads it.
            is_draft=True,
            mitre_tactics=list(parent.mitre_tactics or []),
            source_entries=list(parent.source_entries or []),
            source_actors=list(parent.source_actors or []),
            source_campaigns=list(parent.source_campaigns or []),
            references=list(parent.references or []),
            license=parent.license,
            metadata_={"conversion": provenance},
        )
        db.add(sibling)
    elif sibling.rule_content != content:
        max_ver = (
            await db.execute(
                select(func.coalesce(func.max(DetectionRuleVersion.version_number), 0)).where(
                    DetectionRuleVersion.rule_id == sibling.id
                )
            )
        ).scalar() or 0
        db.add(
            DetectionRuleVersion(
                rule_id=sibling.id,
                version_number=max_ver + 1,
                rule_content=sibling.rule_content,
                rule_type=sibling.rule_type,
                change_description=f"Re-converted from {RULE_TYPE_LABELS.get(parent.rule_type, parent.rule_type)}",
                changed_by=user.id,
            )
        )
        sibling.rule_content = content
        sibling.metadata_ = {**(sibling.metadata_ or {}), "conversion": provenance}
    else:
        sibling.metadata_ = {**(sibling.metadata_ or {}), "conversion": provenance}

    # Fill log_sources / data_sources from the converted body, never overwriting
    # what was copied from the parent.
    from app.intelligence.rule_metadata import extract_and_apply

    extract_and_apply(sibling, {"title", "description", "severity", "tags", "mitre_tactics"})
    # extract_and_apply rebuilds metadata_ from the extractor and only preserves
    # the two keys it knows about, so the conversion provenance goes back on.
    sibling.metadata_ = {**(sibling.metadata_ or {}), "conversion": provenance}

    await db.flush()
    await _resolve_coverage(db, sibling)
    await db.refresh(sibling, attribute_names=["entry"])
    await index_rule(db, sibling)
    return sibling


@router.post("/detection-rules/{rule_id}/extend", response_model=DetectionRuleResponse, status_code=201)
async def extend_rule(
    rule_id: uuid.UUID = Path(..., description="UUID of the upstream rule to extend"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a draft child of a rule for extension.

    Today extending means Save-a-copy and hand-editing, with no record of what
    changed or why. The child hangs off `derived_from` so the bench can show the
    upstream read-only beside your edit, upstream commits can badge the child,
    and the lineage survives export. Same format, same mappings, draft until a
    human ships it. A new child per call — unlike conversions, two analysts
    extending the same upstream are doing two different jobs.
    """
    parent = await db.get(DetectionRule, rule_id)
    if parent is None:
        raise AppError(code="not_found", message="Detection rule not found", status_code=404)

    child = DetectionRule(
        entry_id=parent.entry_id,
        created_by=user.id,
        derived_from=parent.id,
        rule_type=parent.rule_type,
        title=f"{parent.title} (extended)",
        description=parent.description,
        rule_content=parent.rule_content,
        severity=parent.severity,
        tags=list(parent.tags or []),
        source_ttps=list(parent.source_ttps or []),
        source_cves=list(parent.source_cves or []),
        is_draft=True,
        mitre_tactics=list(parent.mitre_tactics or []),
        source_entries=list(parent.source_entries or []),
        source_actors=list(parent.source_actors or []),
        source_campaigns=list(parent.source_campaigns or []),
        references=list(parent.references or []),
        license=parent.license,
        data_sources=list(parent.data_sources or []),
        log_sources=dict(parent.log_sources or {}) if isinstance(parent.log_sources, dict) else parent.log_sources,
        metadata_={
            **{k: v for k, v in (parent.metadata_ or {}).items() if k in ("repo", "owner", "file_path")},
            "extended_from": str(parent.id),
        },
        notes=f"Extended from: {parent.title}",
    )
    db.add(child)
    await db.flush()
    await _resolve_coverage(db, child)
    await db.commit()
    # Load the entry relationship before Pydantic touches it (async lazy-load
    # inside serialization is a MissingGreenlet).
    await db.refresh(child, attribute_names=["entry"])
    await index_rule(db, child)
    return child


@router.get("/detection-rules/{rule_id}/conversions", response_model=list[DetectionRuleResponse])
async def list_rule_conversions(
    rule_id: uuid.UUID = Path(..., description="UUID of the source detection rule"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Sibling rules converted from this one, one per target format."""
    rows = (
        (
            await db.execute(
                select(DetectionRule)
                .options(selectinload(DetectionRule.entry))
                .where(DetectionRule.derived_from == rule_id)
                .order_by(DetectionRule.rule_type)
            )
        )
        .scalars()
        .all()
    )
    return list(rows)


@router.post("/detection-rules/chat")
async def chat_rule_assistant(
    body: RuleChatRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Streaming AI chat for detection rule development assistance."""
    from sse_starlette.sse import EventSourceResponse

    from app.ai.caller import Caller
    from app.ai.engine import _get_provider_instance, record_direct_result, resolve_assignment

    resolved = await resolve_assignment(db, Caller.user(user.id), "detection_rules")
    if resolved is None:
        raise AppError(
            code="no_ai_assignment",
            message="No AI provider assigned for detection rules. Configure one in Settings > AI.",
            status_code=400,
        )

    task, provider_model = resolved.task, resolved.provider
    provider = _get_provider_instance(provider_model, extra_config=resolved.config)

    rule_type_label = RULE_TYPE_LABELS.get(body.rule_type, body.rule_type)

    system_prompt = f"""\
You are a senior detection engineer assisting with {rule_type_label} rule development in IntelFeed.

CURRENT RULE CONTEXT:
- Format: {rule_type_label}
- Title: {body.title or "(untitled)"}
- Severity: {body.severity or "not set"}
- MITRE Tactics: {", ".join(body.mitre_tactics) if body.mitre_tactics else "none mapped"}
- Data Sources: {", ".join(body.data_sources) if body.data_sources else "none configured"}

CURRENT RULE CONTENT:
```
{body.rule_content or "(empty — new rule)"}
```

GUIDELINES:
- Be a pair-programming partner — suggest, explain trade-offs, refine
- Always produce syntactically valid {rule_type_label} when providing rule code
- When suggesting rule changes, output the complete updated rule in a code block so the analyst can apply it directly
- Flag false positive risks proactively
- Suggest test cases when relevant (Atomic Red Team, manual simulation)
- Maintain ATT&CK accuracy — use correct technique/sub-technique IDs
- Consider detection evasion — how might an adversary bypass this rule?
- Note log source requirements — what telemetry must be enabled?
- Keep responses focused and actionable — detection engineers are busy"""

    # Build conversation messages
    messages = []
    for msg in body.history[-20:]:  # Keep last 20 messages for context
        if msg.get("role") in ("user", "assistant") and msg.get("content"):
            messages.append({"role": msg["role"], "content": msg["content"]})
    messages.append({"role": "user", "content": body.message})

    config = resolved.config

    async def _ledger(prompt: str, answer: str, error: str | None) -> None:
        # A streamed reply reports usage only when the provider sends it on
        # the stream (see AIProvider.last_stream_usage); otherwise the row
        # counts a request at zero tokens. Accounting must never break the
        # stream.
        try:
            streamed = getattr(provider, "last_stream_usage", None)
            response = None
            if streamed and error is None:
                from app.ai.providers.base import AIResponse

                response = AIResponse(
                    content=answer,
                    raw_response={},
                    tokens_input=int(streamed.get("tokens_input") or 0),
                    tokens_output=int(streamed.get("tokens_output") or 0),
                    model=resolved.model_name,
                    latency_ms=0,
                    cost_usd=streamed.get("cost_usd"),
                )
            await record_direct_result(
                db,
                caller=Caller.user(user.id),
                task=task,
                provider_model=provider_model,
                model_name=resolved.model_name,
                prompt_used=prompt,
                response=response,
                content=answer,
                error=error,
                target_type="rule_chat",
                key_owner_id=resolved.key_owner_id,
            )
            await db.commit()
        except Exception as e:
            logger.warning("rule chat failed to record ai_result: %s", e)
            await db.rollback()

    async def generate():
        import json as _json

        conversation_text = ""
        answer_parts: list[str] = []
        ledgered = False
        try:
            # Build the full prompt from conversation
            for msg in messages[:-1]:
                role_label = "Analyst" if msg["role"] == "user" else "Assistant"
                conversation_text += f"\n{role_label}: {msg['content']}\n"
            conversation_text += f"\nAnalyst: {messages[-1]['content']}\n\nAssistant:"

            async for chunk in provider.stream_complete(
                prompt=conversation_text,
                system=system_prompt,
                temperature=config.get("temperature", 0.3),
                max_tokens=config.get("max_tokens", 4096),
                model=resolved.model_name,
            ):
                answer_parts.append(chunk)
                yield {"event": "chunk", "data": _json.dumps({"text": chunk})}
            await _ledger(conversation_text, "".join(answer_parts), None)
            ledgered = True
            yield {"event": "done", "data": _json.dumps({"status": "complete"})}
        except Exception as e:
            await _ledger(conversation_text, "".join(answer_parts), str(e))
            ledgered = True
            yield {"event": "error", "data": _json.dumps({"error": str(e)})}
        finally:
            # The client went away mid-stream. sse-starlette cancels this task,
            # so the write has to be shielded or it is cancelled at its first
            # await. The prompt reached the provider either way, so even a call
            # abandoned before its first token is spend: a disconnect-and-retry
            # loop must not be free.
            if not ledgered:
                with anyio.CancelScope(shield=True):
                    await _ledger(conversation_text, "".join(answer_parts), "client disconnected")

    return EventSourceResponse(generate())


# --- Detection Rule Versioning ---


@router.get(
    "/detection-rules/{rule_id}/versions",
    response_model=list[DetectionRuleVersionResponse],
)
async def list_rule_versions(
    rule_id: uuid.UUID = Path(..., description="UUID of the detection rule"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List a rule's saved versions, newest first."""
    # Verify rule exists
    rule_result = await db.execute(select(DetectionRule.id).where(DetectionRule.id == rule_id))
    if not rule_result.scalar_one_or_none():
        raise AppError(code="not_found", message="Detection rule not found", status_code=404)

    result = await db.execute(
        select(DetectionRuleVersion)
        .where(DetectionRuleVersion.rule_id == rule_id)
        .order_by(DetectionRuleVersion.version_number.desc())
    )
    return result.scalars().all()


@router.get(
    "/detection-rules/{rule_id}/versions/{version_id}",
    response_model=DetectionRuleVersionResponse,
)
async def get_rule_version(
    rule_id: uuid.UUID = Path(..., description="UUID of the detection rule"),
    version_id: uuid.UUID = Path(..., description="UUID of the version record"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get a single saved version of a detection rule."""
    rule_result = await db.execute(select(DetectionRule.id).where(DetectionRule.id == rule_id))
    if not rule_result.scalar_one_or_none():
        raise AppError(code="not_found", message="Detection rule not found", status_code=404)

    result = await db.execute(
        select(DetectionRuleVersion).where(
            DetectionRuleVersion.id == version_id,
            DetectionRuleVersion.rule_id == rule_id,
        )
    )
    version = result.scalar_one_or_none()
    if not version:
        raise AppError(code="not_found", message="Version not found", status_code=404)
    return version


@router.get("/detection-rules/{rule_id}/diff")
async def diff_rule_versions(
    rule_id: uuid.UUID = Path(..., description="UUID of the detection rule"),
    v1: int = Query(..., description="First version number"),
    v2: int | None = Query(None, description="Second version number (omit to compare against current)"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Diff between two rule versions, or a version and the current content."""
    import difflib

    rule_result = await db.execute(select(DetectionRule).where(DetectionRule.id == rule_id))
    rule = rule_result.scalar_one_or_none()
    if not rule:
        raise AppError(code="not_found", message="Detection rule not found", status_code=404)

    # Fetch version v1
    v1_result = await db.execute(
        select(DetectionRuleVersion).where(
            DetectionRuleVersion.rule_id == rule_id,
            DetectionRuleVersion.version_number == v1,
        )
    )
    version1 = v1_result.scalar_one_or_none()
    if not version1:
        raise AppError(code="not_found", message=f"Version {v1} not found", status_code=404)

    if v2 is not None:
        v2_result = await db.execute(
            select(DetectionRuleVersion).where(
                DetectionRuleVersion.rule_id == rule_id,
                DetectionRuleVersion.version_number == v2,
            )
        )
        version2 = v2_result.scalar_one_or_none()
        if not version2:
            raise AppError(code="not_found", message=f"Version {v2} not found", status_code=404)
        right_content = version2.rule_content
        right_label = f"Version {v2}"
    else:
        right_content = rule.rule_content
        right_label = "Current"

    left_lines = version1.rule_content.splitlines(keepends=True)
    right_lines = right_content.splitlines(keepends=True)

    diff = list(
        difflib.unified_diff(
            left_lines,
            right_lines,
            fromfile=f"Version {v1}",
            tofile=right_label,
        )
    )

    return {
        "rule_id": str(rule_id),
        "from_version": v1,
        "to_version": v2 if v2 is not None else "current",
        "diff": "".join(diff),
        "has_changes": len(diff) > 0,
    }


@router.post(
    "/detection-rules/{rule_id}/versions/{version_id}/rollback",
    response_model=DetectionRuleResponse,
)
async def rollback_rule_version(
    rule_id: uuid.UUID = Path(..., description="UUID of the detection rule"),
    version_id: uuid.UUID = Path(..., description="UUID of the version to restore"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Restore a rule's content (and type) from a saved version, snapshotting the current content first."""
    result = await db.execute(select(DetectionRule).where(DetectionRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise AppError(code="not_found", message="Detection rule not found", status_code=404)

    ver_result = await db.execute(
        select(DetectionRuleVersion).where(
            DetectionRuleVersion.id == version_id,
            DetectionRuleVersion.rule_id == rule_id,
        )
    )
    target_version = ver_result.scalar_one_or_none()
    if not target_version:
        raise AppError(code="not_found", message="Version not found", status_code=404)

    # Snapshot current content as a new version before rollback
    max_ver_result = await db.execute(
        select(func.coalesce(func.max(DetectionRuleVersion.version_number), 0)).where(
            DetectionRuleVersion.rule_id == rule_id
        )
    )
    max_ver = max_ver_result.scalar() or 0
    snapshot = DetectionRuleVersion(
        rule_id=rule_id,
        version_number=max_ver + 1,
        rule_content=rule.rule_content,
        rule_type=rule.rule_type,
        change_description=f"Snapshot before rollback to v{target_version.version_number}",
        changed_by=user.id,
    )
    db.add(snapshot)

    # Restore target version content
    rule.rule_content = target_version.rule_content
    if target_version.rule_type:
        rule.rule_type = target_version.rule_type
    db.add(rule)
    await db.flush()
    await db.refresh(rule)
    return rule


@router.patch("/detection-rules/{rule_id}/status", response_model=DetectionRuleResponse)
async def toggle_rule_status(
    rule_id: uuid.UUID = Path(..., description="UUID of the detection rule"),
    body: dict = Body(..., json_schema_extra={"example": {"is_draft": False}}),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Set a rule's draft/published status. Body must contain the boolean field is_draft."""
    result = await db.execute(select(DetectionRule).where(DetectionRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise AppError(code="not_found", message="Detection rule not found", status_code=404)

    if "is_draft" not in body:
        raise AppError(code="validation_error", message="is_draft field required", status_code=422)

    rule.is_draft = body["is_draft"]
    db.add(rule)
    await db.flush()
    await db.refresh(rule)
    return rule


@router.get("/detection-rules/{rule_id}/provenance")
async def get_rule_provenance(
    rule_id: uuid.UUID = Path(..., description="UUID of the detection rule"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get the full intelligence provenance chain for a detection rule."""
    result = await db.execute(select(DetectionRule).where(DetectionRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise AppError(code="not_found", message="Detection rule not found", status_code=404)

    # Collect all linked entry IDs
    linked_entry_ids = list(rule.source_entries or [])
    if rule.entry_id and rule.entry_id not in linked_entry_ids:
        linked_entry_ids.append(rule.entry_id)

    # Fetch linked entries
    entries_data = []
    if linked_entry_ids:
        entries_result = await db.execute(select(Entry).where(Entry.id.in_(linked_entry_ids)))
        entries_data = [
            {
                "id": str(e.id),
                "title": e.title,
                "url": e.url,
                "published_at": str(e.published_at) if e.published_at else None,
            }
            for e in entries_result.scalars().all()
        ]

    # Fetch TTPs from linked entries
    ttps_data = []
    if linked_entry_ids:
        ttps_result = await db.execute(
            select(TTP)
            .join(EntryTTP, EntryTTP.ttp_id == TTP.id)
            .where(EntryTTP.entry_id.in_(linked_entry_ids))
            .distinct()
        )
        ttps_data = [
            {"id": str(t.id), "technique_id": t.technique_id, "technique_name": t.technique_name, "tactic": t.tactic}
            for t in ttps_result.scalars().all()
        ]

    # Fetch threat actors from linked entries or source_actors
    actors_data = []
    actor_ids = list(rule.source_actors or [])
    if linked_entry_ids:
        actors_result = await db.execute(
            select(ThreatActor)
            .join(EntryThreatActor, EntryThreatActor.threat_actor_id == ThreatActor.id)
            .where(EntryThreatActor.entry_id.in_(linked_entry_ids))
            .distinct()
        )
        for a in actors_result.scalars().all():
            actors_data.append({"id": str(a.id), "name": a.name, "aliases": a.aliases or []})
            if a.id not in actor_ids:
                actor_ids.append(a.id)
    # Also fetch directly linked actors
    if actor_ids:
        direct_actors = await db.execute(select(ThreatActor).where(ThreatActor.id.in_(actor_ids)))
        for a in direct_actors.scalars().all():
            if not any(d["id"] == str(a.id) for d in actors_data):
                actors_data.append({"id": str(a.id), "name": a.name, "aliases": a.aliases or []})

    # Fetch malware from linked entries
    malware_data = []
    if linked_entry_ids:
        malware_result = await db.execute(
            select(MalwareFamily)
            .join(EntryMalware, EntryMalware.malware_family_id == MalwareFamily.id)
            .where(EntryMalware.entry_id.in_(linked_entry_ids))
            .distinct()
        )
        malware_data = [
            {"id": str(m.id), "name": m.name, "malware_type": m.malware_type} for m in malware_result.scalars().all()
        ]

    return {
        "rule": {
            "id": str(rule.id),
            "title": rule.title,
            "rule_type": rule.rule_type,
            "created_at": str(rule.created_at),
            "source_repo": rule.source_repo,
            "source_author": rule.source_author,
            "license": rule.license,
            "references": rule.references or [],
            "upstream_updated_at": str(rule.upstream_updated_at) if rule.upstream_updated_at else None,
        },
        "entries": entries_data,
        "ttps": ttps_data,
        "threat_actors": actors_data,
        "malware": malware_data,
    }


def _rule_cve_strings(source_cves) -> list[str]:
    """Normalize a rule's source_cves (list of str or dicts) to CVE-ID strings."""
    out: list[str] = []
    for c in source_cves or []:
        if isinstance(c, str):
            out.append(c.strip().upper())
        elif isinstance(c, dict):
            cid = c.get("cve_id") or c.get("id") or c.get("cve")
            if cid:
                out.append(str(cid).strip().upper())
    return [c for c in out if c.startswith("CVE-")]


def _rule_technique_strings(source_ttps) -> list[str]:
    """Normalize a rule's source_ttps (list of str or dicts) to technique-ID strings."""
    out: list[str] = []
    for t in source_ttps or []:
        if isinstance(t, str):
            out.append(t.strip().upper())
        elif isinstance(t, dict):
            tid = t.get("technique_id") or t.get("id")
            if tid:
                out.append(str(tid).strip().upper())
    return [t for t in out if t.startswith("T")]


@router.get("/detection-rules/{rule_id}/fresh-intel")
async def get_rule_fresh_intel(
    rule_id: uuid.UUID = Path(..., description="UUID of the detection rule"),
    limit: int = Query(10, ge=1, le=50, description="Maximum entries returned"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Entries on this rule's CVEs/techniques that arrived AFTER the rule was last edited.

    Surfaces the decay signal at the point of reading/editing a borrowed rule.
    """
    result = await db.execute(select(DetectionRule).where(DetectionRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise AppError(code="not_found", message="Detection rule not found", status_code=404)

    since = rule.updated_at
    found: dict[uuid.UUID, dict] = {}

    tech_ids = _rule_technique_strings(rule.source_ttps)
    if tech_ids:
        ttp_uuids = [r[0] for r in (await db.execute(select(TTP.id).where(TTP.technique_id.in_(tech_ids)))).all()]
        if ttp_uuids:
            rows = await db.execute(
                select(Entry)
                .join(EntryTTP, EntryTTP.entry_id == Entry.id)
                .where(EntryTTP.ttp_id.in_(ttp_uuids), Entry.published_at > since)
                .order_by(Entry.published_at.desc())
                .limit(limit)
            )
            for e in rows.scalars().all():
                found[e.id] = {
                    "id": str(e.id),
                    "title": e.title,
                    "url": e.url,
                    "published_at": str(e.published_at) if e.published_at else None,
                    "matched_on": "technique",
                }

    cve_ids = _rule_cve_strings(rule.source_cves)
    if cve_ids:
        cve_uuids = [r[0] for r in (await db.execute(select(CVE.id).where(CVE.cve_id.in_(cve_ids)))).all()]
        if cve_uuids:
            rows = await db.execute(
                select(Entry)
                .join(EntryCVE, EntryCVE.entry_id == Entry.id)
                .where(EntryCVE.cve_id.in_(cve_uuids), Entry.published_at > since)
                .order_by(Entry.published_at.desc())
                .limit(limit)
            )
            for e in rows.scalars().all():
                if e.id not in found:
                    found[e.id] = {
                        "id": str(e.id),
                        "title": e.title,
                        "url": e.url,
                        "published_at": str(e.published_at) if e.published_at else None,
                        "matched_on": "cve",
                    }

    items = sorted(found.values(), key=lambda x: x["published_at"] or "", reverse=True)[:limit]
    return {"items": items, "total": len(items), "since": str(since)}


@router.get("/detection-rules/{rule_id}/related")
async def get_related_rules(
    rule_id: uuid.UUID = Path(..., description="UUID of the detection rule"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Rules related by shared CVE, shared technique, alternate format, or near-duplicate content."""
    import difflib

    result = await db.execute(select(DetectionRule).where(DetectionRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise AppError(code="not_found", message="Detection rule not found", status_code=404)

    my_cves = _rule_cve_strings(rule.source_cves)
    my_techs = _rule_technique_strings(rule.source_ttps)

    cand: dict[uuid.UUID, DetectionRule] = {}
    reasons: dict[uuid.UUID, set[str]] = {}

    async def _collect(condition, reason: str, cap: int = 25):
        rows = await db.execute(select(DetectionRule).where(DetectionRule.id != rule.id, condition).limit(cap))
        for r in rows.scalars().all():
            cand[r.id] = r
            reasons.setdefault(r.id, set()).add(reason)

    if my_cves:
        await _collect(or_(*[DetectionRule.source_cves.contains([c]) for c in my_cves]), "same_cve")
    if my_techs:
        await _collect(or_(*[DetectionRule.source_ttps.contains([t]) for t in my_techs]), "same_technique")

    buckets: dict[str, list] = {"near_duplicate": [], "other_format": [], "same_cve": [], "same_technique": []}
    for rid, r in cand.items():
        summary = {
            "id": str(r.id),
            "title": r.title,
            "rule_type": r.rule_type,
            "severity": r.severity,
            "source_repo": r.source_repo,
        }
        ratio = difflib.SequenceMatcher(None, rule.rule_content or "", r.rule_content or "").quick_ratio()
        if ratio >= 0.8:
            buckets["near_duplicate"].append({**summary, "similarity": round(ratio, 2)})
        elif r.rule_type != rule.rule_type:
            buckets["other_format"].append(summary)
        elif "same_cve" in reasons[rid]:
            buckets["same_cve"].append(summary)
        else:
            buckets["same_technique"].append(summary)

    buckets["near_duplicate"].sort(key=lambda x: x["similarity"], reverse=True)
    return buckets


@router.get("/detection-rules/{rule_id}/commits")
async def get_rule_commit_timeline(
    rule_id: uuid.UUID = Path(..., description="UUID of the detection rule"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get the commit history timeline for a detection rule imported from a GitHub repo."""
    result = await db.execute(select(DetectionRule).where(DetectionRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise AppError(code="not_found", message="Detection rule not found", status_code=404)

    meta = rule.metadata_ or {}
    commit_history = meta.get("commit_history", [])
    owner = meta.get("owner", "")
    repo = meta.get("repo", "")
    file_path = meta.get("file_path", "")

    # Build GitHub URLs for each commit
    commits = []
    for commit in commit_history:
        sha = commit.get("sha", "")
        commits.append(
            {
                "sha": sha,
                "short_sha": sha[:8] if sha else "",
                "author": commit.get("author", "unknown"),
                "message": commit.get("message", ""),
                "date": commit.get("date"),
                "change_type": commit.get("change_type", "modified"),
                "url": f"https://github.com/{owner}/{repo}/commit/{sha}" if sha and owner and repo else None,
                "file_url": f"https://github.com/{owner}/{repo}/blob/{sha}/{file_path}"
                if sha and owner and repo and file_path
                else None,
            }
        )

    return {
        "rule_id": str(rule.id),
        "owner": owner,
        "repo": repo,
        "file_path": file_path,
        "commits": commits,
    }


# --- Bulk Detection Rule Operations ---


@router.post("/detection-rules/bulk-update")
async def bulk_update_detection_rules(
    body: BulkRuleUpdateRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Bulk-update detection rules: set draft status and/or add and remove tags. Returns the updated count."""
    result = await db.execute(
        select(DetectionRule).where(
            DetectionRule.id.in_(body.rule_ids),
        )
    )
    rules = result.scalars().all()
    updated = 0
    for rule in rules:
        if body.is_draft is not None:
            rule.is_draft = body.is_draft
        if body.tags_add:
            existing = set(rule.tags or [])
            existing.update(body.tags_add)
            rule.tags = list(existing)
        if body.tags_remove:
            rule.tags = [t for t in (rule.tags or []) if t not in body.tags_remove]
        db.add(rule)
        updated += 1
    await db.flush()
    for rule in rules:
        await index_rule(db, rule)
    return {"updated": updated}


@router.post("/detection-rules/bulk-delete")
async def bulk_delete_detection_rules(
    body: BulkRuleDeleteRequest,
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Bulk-delete detection rules by ID. Returns the deleted count. Admin only."""
    result = await db.execute(
        select(DetectionRule).where(
            DetectionRule.id.in_(body.rule_ids),
        )
    )
    rules = result.scalars().all()
    deleted_ids = [r.id for r in rules]
    deleted = 0
    for rule in rules:
        await db.delete(rule)
        deleted += 1
    await db.flush()
    for rule_id in deleted_ids:
        delete_entity_document("rule", rule_id)
    return {"deleted": deleted}


# SIGMA import limits. A rule is a few KB; these leave two orders of magnitude
# of headroom and stop a small archive that inflates to gigabytes from taking
# the api container (and every request it serves) down with it.
_SIGMA_IMPORT_MAX_UPLOAD = 20 * 1024 * 1024
_SIGMA_IMPORT_MAX_MEMBERS = 5000
_SIGMA_IMPORT_MAX_MEMBER_BYTES = 1024 * 1024
_SIGMA_IMPORT_MAX_TOTAL_BYTES = 64 * 1024 * 1024


@router.post("/detection-rules/import")
async def import_detection_rules(
    file: UploadFile = File(..., description="A .yml/.yaml SIGMA rule or a .zip archive of SIGMA YAML files"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Import SIGMA rules from a YAML file or ZIP archive."""
    import io
    import zipfile

    import yaml

    from app.intelligence.rule_validation import validate_rule

    contents = await file.read(_SIGMA_IMPORT_MAX_UPLOAD + 1)
    if len(contents) > _SIGMA_IMPORT_MAX_UPLOAD:
        raise AppError(code="validation_error", message="File is larger than 20 MB", status_code=413)
    filename = file.filename or ""
    imported = 0
    skipped = 0
    errors: list[dict] = []

    async def _import_sigma_yaml(name: str, yaml_bytes: bytes) -> None:
        nonlocal imported, skipped, errors
        try:
            doc = yaml.safe_load(yaml_bytes)
            if not isinstance(doc, dict):
                errors.append({"file": name, "error": "Not a valid YAML document"})
                return

            title = doc.get("title", name.replace(".yml", "").replace(".yaml", ""))
            rule_content = yaml_bytes.decode("utf-8", errors="replace")

            validation = validate_rule("sigma", rule_content)
            if not validation.valid:
                err_msgs = "; ".join(e.message for e in validation.errors[:3])
                errors.append({"file": name, "error": f"Validation failed: {err_msgs}"})
                return

            rule = DetectionRule(
                created_by=user.id,
                rule_type="sigma",
                title=title[:500],
                description=doc.get("description"),
                rule_content=rule_content,
                severity=doc.get("level"),
                tags=doc.get("tags", []),
                is_draft=True,
                mitre_tactics=[],
                data_sources=[],
            )
            # Extract MITRE tactics from tags
            for tag in doc.get("tags", []):
                if isinstance(tag, str) and tag.startswith("attack.") and not tag[7:].startswith("t"):
                    rule.mitre_tactics.append(tag[7:])

            db.add(rule)
            imported += 1
        except yaml.YAMLError as e:
            errors.append({"file": name, "error": f"YAML parse error: {e}"})
        except Exception as e:
            errors.append({"file": name, "error": str(e)})

    if filename.endswith(".zip"):
        try:
            zf = zipfile.ZipFile(io.BytesIO(contents))
            members = zf.infolist()
            # file_size is the header's claim, and zipfile never inflates a
            # member past it (a lie fails the CRC instead), so checking the
            # headers bounds what the reads below can allocate.
            yaml_members = [m for m in members if m.filename.endswith((".yml", ".yaml"))]
            if (
                len(members) > _SIGMA_IMPORT_MAX_MEMBERS
                or any(m.file_size > _SIGMA_IMPORT_MAX_MEMBER_BYTES for m in yaml_members)
                or sum(m.file_size for m in yaml_members) > _SIGMA_IMPORT_MAX_TOTAL_BYTES
            ):
                raise AppError(
                    code="validation_error",
                    message=(
                        f"Archive too large: at most {_SIGMA_IMPORT_MAX_MEMBERS} files, "
                        f"1 MB per rule and 64 MB uncompressed in total"
                    ),
                    status_code=413,
                )
            skipped += len(members) - len(yaml_members)
            for member in yaml_members:
                await _import_sigma_yaml(member.filename, zf.read(member))
        except zipfile.BadZipFile:
            raise AppError(code="validation_error", message="Invalid ZIP file", status_code=422)
    elif filename.endswith((".yml", ".yaml")):
        await _import_sigma_yaml(filename, contents)
    else:
        raise AppError(
            code="validation_error",
            message="Unsupported file type. Use .yml, .yaml, or .zip",
            status_code=422,
        )

    await db.flush()
    return {"imported": imported, "skipped": skipped, "errors": errors}


# --- AI Cost / Batch Routes ---


@router.get("/ai/cost-summary")
async def get_cost_summary(
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Aggregate AI usage over the last 30 days: total estimated cost, request count, and input/output tokens."""
    from datetime import timedelta

    from app.models.ai_result import AIResult

    thirty_days_ago = func.now() - timedelta(days=30)

    result = await db.execute(
        select(
            func.coalesce(func.sum(AIResult.cost_estimate), 0),
            func.count(AIResult.id),
            func.coalesce(func.sum(AIResult.tokens_input), 0),
            func.coalesce(func.sum(AIResult.tokens_output), 0),
        ).where(AIResult.created_at >= thirty_days_ago)
    )
    row = result.first()

    return {
        "total_cost_30d": float(row[0]),
        "total_requests_30d": row[1],
        "total_tokens_30d": {"input": row[2], "output": row[3]},
    }


class RunTextTaskRequest(BaseModel):
    task_name: str
    text: str

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "task_name": "article_summary",
                "text": "APT29 used spearphishing attachments (T1566.001) to deliver a new LockBit variant...",
            }
        }
    )


@router.post("/ai/run-text")
async def run_task_on_text(
    body: RunTextTaskRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Run an AI task on arbitrary text (e.g. a text selection from an article)."""
    from app.ai.engine import run_task

    if not body.text.strip():
        raise AppError(code="bad_request", message="Text is required", status_code=400)

    parsed = await run_task(
        db=db,
        user_id=user.id,
        caller=Caller.user(user.id),
        task_name=body.task_name,
        variables={"text": body.text},
    )
    if parsed is None:
        raise AppError(
            code="not_configured",
            message=f"AI task '{body.task_name}' is not configured or has no provider assigned.",
            status_code=422,
        )
    await db.commit()
    return {"task_name": body.task_name, "result": parsed}


class RunEntryTaskRequest(BaseModel):
    task_name: str
    force: bool = False
    focus: str | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "task_name": "threat_assessment",
                "force": False,
                "focus": "impact on healthcare organizations",
            }
        }
    )


class BulkSummarizeRequest(BaseModel):
    entry_ids: list[uuid.UUID]

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "entry_ids": [
                    "d5b2f1a0-3c4e-4b6d-9a8f-1e2d3c4b5a69",
                    "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
                ]
            }
        }
    )


@router.post("/entries/bulk-summarize")
async def bulk_summarize_entries(
    body: BulkSummarizeRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Summarize multiple entries together using the intelligence_briefing AI task."""
    from app.ai.engine import run_task

    if not body.entry_ids:
        raise AppError(code="bad_request", message="No entry IDs provided", status_code=400)
    if len(body.entry_ids) > 100:
        raise AppError(code="bad_request", message="Maximum 100 entries", status_code=400)

    # Fetch all entries
    result = await db.execute(select(Entry).where(Entry.id.in_(body.entry_ids)))
    entries = result.scalars().all()
    if not entries:
        raise AppError(code="not_found", message="No entries found", status_code=404)

    # Build entries list for the intelligence_briefing prompt
    entries_data = []
    for entry in entries:
        entries_data.append(
            {
                "title": entry.title,
                "content_text": (entry.content_text or entry.summary or "")[:3000],
                "feed_title": "",
                "published_at": str(entry.published_at) if entry.published_at else "",
            }
        )

    variables = {
        "entries": entries_data,
        "entry_count": len(entries_data),
    }

    parsed = await run_task(
        db=db,
        user_id=user.id,
        caller=Caller.user(user.id),
        task_name="intelligence_briefing",
        variables=variables,
        force=True,
    )
    if parsed is None:
        raise AppError(
            code="not_configured",
            message="AI task 'intelligence_briefing' is not configured. Assign a provider and model in Settings > AI.",
            status_code=422,
        )

    return {
        "summary": parsed.get("summary", ""),
        "entry_count": len(entries_data),
    }


@router.post("/entries/{entry_id}/run-ai-task")
async def run_task_on_entry(
    entry_id: uuid.UUID = Path(..., description="UUID of the entry the task runs against"),
    body: RunEntryTaskRequest = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Run any AI task on a specific entry (e.g. article_summary, threat_assessment)."""
    from app.ai.engine import run_task
    from app.intelligence.telemetry_context import get_telemetry_for_prompt

    entry = await _get_entry(db, entry_id)
    entry_data = _entry_to_dict(entry)

    variables: dict = {"entry": entry_data}

    # Optional steering: focusable prompts render `{% if focus %}` when provided.
    if body.focus and body.focus.strip():
        variables["focus"] = body.focus.strip()

    # Inject telemetry sources for tasks that benefit from environment context
    TELEMETRY_AWARE_TASKS = {
        "threat_assessment",
        "detection_rules",
        "ttp_mapping",
        "tool_extraction",
        "mitigation_extraction",
        "detection_engineering_summary",
    }
    if body.task_name in TELEMETRY_AWARE_TASKS:
        variables["telemetry_sources"] = await get_telemetry_for_prompt(db, user.id)

    # detection_rules: delegate to generate_detection_rules which injects
    # TTPs/CVEs and creates actual DetectionRule records.
    if body.task_name == "detection_rules":
        from app.intelligence.detection import generate_detection_rules

        ttp_result = await db.execute(select(TTP).join(EntryTTP).where(EntryTTP.entry_id == entry_id))
        ttps = [
            {"technique_id": t.technique_id, "technique_name": t.technique_name, "tactic": t.tactic}
            for t in ttp_result.scalars().all()
        ]

        rule_types = ["sigma", "splunk_spl"]
        rules = await generate_detection_rules(db, user.id, entry_id, entry_data, ttps, rule_types)
        await db.commit()

        # Build a result summary for the AI Analysis panel
        rules_summary = []
        for r in rules:
            rules_summary.append(
                {
                    "title": r.title,
                    "rule_type": r.rule_type,
                    "severity": r.severity,
                    "id": str(r.id),
                }
            )

        parsed = {
            "_extraction_status": "success",
            "rules_created": len(rules),
            "rules": rules_summary,
        }

        # Fetch cost metadata from the latest AI result
        latest = (
            await db.execute(
                select(AIResult)
                .where(
                    AIResult.entry_id == entry_id,
                    AIResult.is_current == True,  # noqa: E712
                    AIResult.task_id.in_(select(AITask.id).where(AITask.name == body.task_name)),
                )
                .order_by(AIResult.created_at.desc())
                .limit(1)
            )
        ).scalar_one_or_none()

        return {
            "task_name": body.task_name,
            "entry_id": str(entry_id),
            "result": parsed,
            "model_name": latest.model_name if latest else None,
            "cost_estimate": str(latest.cost_estimate) if latest and latest.cost_estimate else None,
        }

    parsed = await run_task(
        db=db,
        user_id=user.id,
        caller=Caller.user(user.id),
        task_name=body.task_name,
        variables=variables,
        entry_id=entry_id,
        target_type="entry",
        target_id=entry_id,
        # A focus is a steering re-run — bypass the dedup cache so the focused
        # result replaces any prior unfocused one.
        force=body.force or "focus" in variables,
    )
    if parsed is None:
        raise AppError(
            code="not_configured",
            message=f"AI task '{body.task_name}' is not configured. Assign a provider and model in Settings > AI.",
            status_code=422,
        )

    # Fetch the freshly-saved AIResult to include model/cost metadata
    latest = (
        await db.execute(
            select(AIResult)
            .where(
                AIResult.target_type == "entry",
                AIResult.target_id == entry_id,
                AIResult.is_current == True,  # noqa: E712
                AIResult.task_id.in_(select(AITask.id).where(AITask.name == body.task_name)),
            )
            .order_by(AIResult.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()

    return {
        "task_name": body.task_name,
        "entry_id": str(entry_id),
        "result": parsed,
        "model_name": latest.model_name if latest else None,
        "cost_estimate": str(latest.cost_estimate) if latest and latest.cost_estimate else None,
    }


# --- Bulk Extraction Routes ---


@router.post("/intelligence/bulk-extract")
async def bulk_extract(
    body: BulkExtractRequest,
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Dispatch bulk intelligence extraction as a background Celery task. Admin only."""
    entry_ids = body.entry_ids
    if not entry_ids:
        entry_ids = await _resolve_bulk_entry_ids(db, body, user)

    from app.workers.intel_feed_tasks import bulk_extract_intelligence

    task = bulk_extract_intelligence.delay(
        entry_ids=[str(eid) for eid in entry_ids[: body.limit]],
        extract_types=body.extract_types,
        user_id=str(user.id),
        use_ai=body.use_ai,
    )
    return {"task_id": task.id, "entry_count": min(len(entry_ids), body.limit)}


@router.post("/intelligence/bulk-translate")
async def bulk_translate(
    body: BulkTranslateRequest,
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Queue translation for many entries (by feed/category/tag/explicit ids). Admin only."""
    from app.config import settings as env_settings
    from app.workers.translation_tasks import translate_entry_task

    entry_ids = body.entry_ids
    if not entry_ids:
        entry_ids = await _resolve_bulk_entry_ids(db, body, user)
    entry_ids = entry_ids[: body.limit]

    target_lang = (body.target_language or env_settings.get("translation_default_target") or "en").lower()

    for eid in entry_ids:
        translate_entry_task.delay(str(eid), target_lang)

    return {"entry_count": len(entry_ids), "target_language": target_lang}


async def _resolve_bulk_entry_ids(
    db: AsyncSession, body: BulkExtractRequest | BulkTranslateRequest, user: User
) -> list[uuid.UUID]:
    """Resolve entry IDs from feed_id, category_id, or tag (as the caller sees it)."""
    from app.models.tag import EntryTag, Tag
    from app.services.entry_tags import visible_to

    q = select(Entry.id).order_by(Entry.published_at.desc()).limit(body.limit)
    if body.feed_id:
        q = q.where(Entry.feed_id == body.feed_id)
    elif body.category_id:
        # Get all feed IDs in this category
        feed_ids_q = select(Feed.id).where(Feed.category_id == body.category_id)
        q = q.where(Entry.feed_id.in_(feed_ids_q))
    elif body.tag:
        # The caller's view of the tag: their own assignments, or the shared
        # ones of a global tag. A subquery rather than a join so an entry is
        # processed once however many rows it has.
        q = q.where(
            Entry.id.in_(
                select(EntryTag.entry_id)
                .join(Tag, Tag.id == EntryTag.tag_id)
                .where(Tag.name == body.tag, visible_to(user.id))
            )
        )
    result = await db.execute(q)
    return [row[0] for row in result.all()]


# --- Auto-Linker Routes ---


@router.post("/entries/{entry_id}/autolink")
async def autolink_entry(
    entry_id: uuid.UUID = Path(..., description="UUID of the entry to scan"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Run the entity auto-linker on a single entry."""
    from app.intelligence.autolinker import autolink_entry as _autolink_entry

    entry = await _get_entry(db, entry_id)
    stored = await _autolink_entry(
        db=db,
        entry_id=entry.id,
        content_text=entry.content_text or "",
        title=entry.title or "",
        summary=entry.summary or "",
    )
    await db.commit()
    return {"linked": len(stored), "matches": stored}


@router.get("/proximity-settings")
async def get_proximity_settings(
    user: User = Depends(get_current_user),
):
    """Return current proximity scoring parameters for frontend display."""
    from app.config import settings as env_settings

    return {
        "proximity_default_score": float(env_settings.get("proximity_default_score") or 0.3),
        "proximity_decay_rate": float(env_settings.get("proximity_decay_rate") or 1.0),
        "proximity_strong_threshold": float(env_settings.get("proximity_strong_threshold") or 0.7),
        "proximity_moderate_threshold": float(env_settings.get("proximity_moderate_threshold") or 0.3),
    }


@router.post("/autolink/rescan")
async def autolink_rescan(
    days: int = Query(7, ge=1, le=90, description="How many days of recent entries to re-scan"),
    backfill_proximity: bool = Query(
        False, description="Instead of a re-scan, backfill paragraph_indices on existing junction records"
    ),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Trigger a batch re-scan of recent entries with the auto-linker. Admin only.

    Set backfill_proximity=true to run a lightweight backfill that adds
    paragraph_indices to existing junction records (preserves metadata).
    """
    if backfill_proximity:
        from app.workers.intel_feed_tasks import backfill_paragraph_indices_task

        task = backfill_paragraph_indices_task.delay()
        return {"status": "queued", "mode": "backfill_proximity", "task_id": task.id}

    from app.workers.intel_feed_tasks import rescan_recent_entries

    rescan_recent_entries.delay(days=days)
    return {"status": "queued", "days": days}


@router.post("/autolink/revalidate")
async def autolink_revalidate(
    user: User = Depends(get_admin_user),
):
    """Remove stale auto-link records that no longer pass the current matching rules. Admin only.

    Re-scans every entry with existing auto-links and deletes any junction records
    whose entity is not found under the updated vocabulary / false-positive rules.
    article_count is corrected for each removed link.  Runs asynchronously via Celery.
    """
    from app.workers.intel_feed_tasks import revalidate_autolinks

    task = revalidate_autolinks.delay()
    return {"status": "queued", "task_id": task.id}


class ScanTextRequest(BaseModel):
    text: str

    model_config = ConfigDict(
        json_schema_extra={
            "example": {"text": "APT29 deployed LockBit via CVE-2024-3400 using spearphishing (T1566.001)."}
        }
    )


@router.post("/autolink/scan")
async def autolink_scan(
    payload: ScanTextRequest,
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Scan caller-supplied text for known intelligence entities.

    Mirrors the entry auto-linker but operates on arbitrary text (e.g. an entity
    profile description) instead of a stored entry. Returns matched entities with
    their surface forms so the frontend can highlight + link them inline, exactly
    like the daily AI summary. CVE/TTP matches found by regex are resolved against
    the DB so only entities that actually have a profile are returned.
    """
    from app.intelligence.autolinker import _ensure_vocabulary, scan_text

    text = (payload.text or "").strip()
    if not text:
        return {"matches": []}

    await _ensure_vocabulary(db)
    # Off the event loop: scan_text is pure CPU (Aho-Corasick over ~20k surface
    # forms) with nothing to await, so running it inline froze every other
    # request multiplexed on this gunicorn worker until it finished. A single
    # slow scan was dragging unrelated requests on the same page past the
    # frontend's 15s timeout.
    raw = await asyncio.to_thread(scan_text, text)
    if not raw:
        return {"matches": []}

    out: list[dict] = []
    for m in raw:
        etype = m["entity_type"]
        eid = m.get("entity_id")
        if etype == "cve" and not eid:
            found = (await db.execute(select(CVE.id).where(CVE.cve_id == m["lookup_key"]))).scalar_one_or_none()
            if not found:
                continue
            eid = str(found)
        elif etype == "ttp" and not eid:
            found = (await db.execute(select(TTP.id).where(TTP.technique_id == m["lookup_key"]))).scalar_one_or_none()
            if not found:
                continue
            eid = str(found)
        if not eid:
            continue
        out.append(
            {
                "entity_type": etype,
                "entity_id": eid,
                "canonical_name": m["canonical_name"],
                "surface_forms": m.get("surface_forms") or [m["surface_form"]],
            }
        )
    if user.is_anonymous and out:
        # The vocabulary holds every entity: a visitor's scan must not name
        # (or confirm the existence of) one they can't see.
        from app.services.public_view import entities_shown

        shown = await entities_shown(db, {(m["entity_type"], uuid.UUID(m["entity_id"])) for m in out})
        out = [m for m in out if (m["entity_type"], uuid.UUID(m["entity_id"])) in shown]

    # Attach each match's full entity payload (the same response shape the
    # entry-entity endpoints return) so popovers over scanned text — entity
    # profile assessments, notes — show the same descriptions, facts and links
    # as the reader instead of a bare name card.
    ids_by_type: dict[str, list[uuid.UUID]] = {}
    for m in out:
        ids_by_type.setdefault(m["entity_type"], []).append(uuid.UUID(m["entity_id"]))

    validated = {
        entity_types.THREAT_ACTOR: (ThreatActor, ThreatActorResponse),
        entity_types.MALWARE: (MalwareFamily, MalwareFamilyResponse),
        entity_types.VENDOR: (Vendor, VendorResponse),
        entity_types.TOOL: (Tool, ToolResponse),
        # EntryCountryResponse rather than CountryResponse: it carries the
        # wikipedia fields the popover renders; its entry-level fields default null.
        entity_types.COUNTRY: (Country, EntryCountryResponse),
        entity_types.CWE: (CWE, CWEResponse),
    }
    payloads: dict[tuple[str, str], dict] = {}
    for etype, ids in ids_by_type.items():
        if etype == entity_types.CVE:
            # article_count lives on the junction for CVEs, not the model.
            counts = dict(
                (
                    await db.execute(
                        select(EntryCVE.cve_id, func.count()).where(EntryCVE.cve_id.in_(ids)).group_by(EntryCVE.cve_id)
                    )
                ).all()
            )
            for row in (await db.execute(select(CVE).where(CVE.id.in_(ids)))).scalars():
                payloads[(etype, str(row.id))] = _cve_to_response(row, counts.get(row.id, 0)).model_dump(mode="json")
        elif etype == entity_types.TTP:
            for row in (await db.execute(select(TTP).where(TTP.id.in_(ids)))).scalars():
                payloads[(etype, str(row.id))] = _ttp_to_response(row).model_dump(mode="json")
        elif etype == entity_types.MITIGATION:
            for row in (await db.execute(select(Mitigation).where(Mitigation.id.in_(ids)))).scalars():
                payloads[(etype, str(row.id))] = _mitigation_to_response(row).model_dump(mode="json")
        elif etype == entity_types.PRODUCT:
            rows = await db.execute(select(Product).where(Product.id.in_(ids)).options(selectinload(Product.vendor)))
            for row in rows.scalars():
                payloads[(etype, str(row.id))] = _product_to_response(row).model_dump(mode="json")
        elif etype in validated:
            model_cls, schema_cls = validated[etype]
            for row in (await db.execute(select(model_cls).where(model_cls.id.in_(ids)))).scalars():
                payloads[(etype, str(row.id))] = schema_cls.model_validate(row).model_dump(mode="json")

    for m in out:
        m["entity"] = payloads.get((m["entity_type"], m["entity_id"]))
    return {"matches": out}


@router.get("/autolink/status")
async def autolink_status(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get auto-linker vocabulary status."""
    from app.intelligence.autolinker import _vocab_version, _vocabulary

    vocab_size = _vocabulary.entry_count if _vocabulary and _vocabulary.built else 0
    return {
        "vocabulary_loaded": _vocabulary is not None and _vocabulary.built,
        "vocabulary_size": vocab_size,
        "vocabulary_version": _vocab_version,
    }


# --- Entry Intel Badges ---


@router.post("/entries/intel-counts")
async def batch_entry_intel_counts(
    entry_ids: list[uuid.UUID] = Body(
        ...,
        description="1-100 entry UUIDs",
        json_schema_extra={"example": ["d5b2f1a0-3c4e-4b6d-9a8f-1e2d3c4b5a69", "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"]},
    ),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Return entity counts for a batch of entries (for inline badges)."""
    if not entry_ids or len(entry_ids) > 100:
        raise AppError(
            code="bad_request",
            message="Provide 1-100 entry IDs",
            status_code=400,
        )

    # TTP counts per entry
    ttp_q = await db.execute(
        select(EntryTTP.entry_id, func.count()).where(EntryTTP.entry_id.in_(entry_ids)).group_by(EntryTTP.entry_id)
    )
    ttp_counts = dict(ttp_q.all())

    # CVE counts per entry
    cve_q = await db.execute(
        select(EntryCVE.entry_id, func.count()).where(EntryCVE.entry_id.in_(entry_ids)).group_by(EntryCVE.entry_id)
    )
    cve_counts = dict(cve_q.all())

    # Detection rule counts per entry (check both entry_id FK and source_entries array)
    rule_q = await db.execute(
        select(DetectionRule.entry_id, func.count())
        .where(DetectionRule.entry_id.in_(entry_ids))
        .group_by(DetectionRule.entry_id)
    )
    rule_counts = dict(rule_q.all())

    # Also count rules where entry appears in source_entries but not as entry_id
    # This catches rules whose entry_id was reassigned to a newer entry
    missing_ids = [eid for eid in entry_ids if eid not in rule_counts]
    if missing_ids:
        eid_col = func.unnest(DetectionRule.source_entries).label("eid")
        subq = (
            select(eid_col, DetectionRule.id)
            .where(DetectionRule.source_entries.overlap(cast(missing_ids, PG_ARRAY(PG_UUID(as_uuid=True)))))
            .subquery()
        )
        source_q = await db.execute(
            select(subq.c.eid, func.count(func.distinct(subq.c.id)))
            .where(subq.c.eid.in_(missing_ids))
            .group_by(subq.c.eid)
        )
        for eid, count in source_q.all():
            rule_counts[eid] = count

    # Note counts per entry
    note_q = await db.execute(
        select(Note.entry_id, func.count()).where(Note.entry_id.in_(entry_ids)).group_by(Note.entry_id)
    )
    note_counts = dict(note_q.all())

    # AI result counts per entry
    ai_q = await db.execute(
        select(AIResult.entry_id, func.count()).where(AIResult.entry_id.in_(entry_ids)).group_by(AIResult.entry_id)
    )
    ai_counts = dict(ai_q.all())

    # Named threat actors / malware per entry — the "who / what" headline. We
    # surface the names (not just a count) so the card can name its subject.
    actor_q = await db.execute(
        select(EntryThreatActor.entry_id, ThreatActor.name)
        .join(ThreatActor, ThreatActor.id == EntryThreatActor.threat_actor_id)
        .where(EntryThreatActor.entry_id.in_(entry_ids))
        .order_by(ThreatActor.name)
    )
    actor_names: dict[uuid.UUID, list[str]] = {}
    for eid, name in actor_q.all():
        actor_names.setdefault(eid, []).append(name)

    malware_q = await db.execute(
        select(EntryMalware.entry_id, MalwareFamily.name)
        .join(MalwareFamily, MalwareFamily.id == EntryMalware.malware_family_id)
        .where(EntryMalware.entry_id.in_(entry_ids))
        .order_by(MalwareFamily.name)
    )
    malware_names: dict[uuid.UUID, list[str]] = {}
    for eid, name in malware_q.all():
        malware_names.setdefault(eid, []).append(name)

    # Worst CVE severity per entry (by CVSS) — lets the CVE badge convey how bad
    sev_q = await db.execute(
        select(EntryCVE.entry_id, func.max(CVE.cvss_score))
        .join(CVE, CVE.id == EntryCVE.cve_id)
        .where(EntryCVE.entry_id.in_(entry_ids))
        .group_by(EntryCVE.entry_id)
    )
    cve_severity: dict[uuid.UUID, str] = {}
    for eid, score in sev_q.all():
        if score is None:
            continue
        s = float(score)
        cve_severity[eid] = "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low"

    # High-risk CVEs per entry (KEV / high EPSS / Metasploit) — boosts the
    # detection-opportunity badge so exploited-in-the-wild gaps rank first
    from app.intelligence.cve import risk_tier_rank_expr

    high_risk_q = await db.execute(
        select(EntryCVE.entry_id, func.bool_or(CVE.is_kev))
        .join(CVE, CVE.id == EntryCVE.cve_id)
        .where(
            EntryCVE.entry_id.in_(entry_ids),
            risk_tier_rank_expr() >= 2,
        )
        .group_by(EntryCVE.entry_id)
    )
    high_risk_cves = {row[0]: bool(row[1]) for row in high_risk_q.all()}

    # PIR (requirement) matches per entry — return requirement titles & priority
    pir_q = await db.execute(
        select(
            RequirementMatch.entry_id,
            IntelligenceRequirement.id,
            IntelligenceRequirement.title,
            IntelligenceRequirement.priority,
            IntelligenceRequirement.category,
            RequirementMatch.match_type,
            RequirementMatch.matched_on,
            RequirementMatch.relevance,
        )
        .join(IntelligenceRequirement, RequirementMatch.requirement_id == IntelligenceRequirement.id)
        .where(
            RequirementMatch.entry_id.in_(entry_ids),
            IntelligenceRequirement.status == "active",
        )
    )
    pir_matches: dict[uuid.UUID, list[dict]] = {}
    for row in pir_q.all():
        pir_matches.setdefault(row[0], []).append(
            {
                "id": str(row[1]),
                "title": row[2],
                "priority": row[3],
                "category": row[4],
                "match_type": row[5],
                "matched_on": row[6],
                "relevance": row[7],
            }
        )

    # Telemetry-aware opportunity tier per entry, from its techniques:
    # actionable_gap (no rule exists), telemetry_gap (library rules blocked by
    # missing telemetry), or None (everything satisfiable — no opportunity).
    from app.services.detection_coverage import entry_opportunity_tiers

    tech_q = await db.execute(
        select(EntryTTP.entry_id, TTP.technique_id)
        .join(TTP, TTP.id == EntryTTP.ttp_id)
        .where(EntryTTP.entry_id.in_(entry_ids))
    )
    entry_techniques: dict[uuid.UUID, set[str]] = {}
    for eid, technique_id in tech_q.all():
        entry_techniques.setdefault(eid, set()).add(technique_id)
    opportunity_tiers = await entry_opportunity_tiers(db, entry_techniques)

    results = {}
    for eid in entry_ids:
        ttps = ttp_counts.get(eid, 0)
        cves = cve_counts.get(eid, 0)
        rules = rule_counts.get(eid, 0)
        notes = note_counts.get(eid, 0)
        ai_results = ai_counts.get(eid, 0)
        pirs = pir_matches.get(eid, [])
        total = ttps + cves + rules
        if total == 0 and notes == 0 and ai_results == 0 and not pirs:
            continue
        has_gap = (ttps > 0 or cves > 0) and rules == 0
        if rules > 0:
            # Entry already has its own rules — no opportunity badge
            opportunity = None
        elif eid in entry_techniques:
            opportunity = opportunity_tiers.get(eid)
        else:
            # No techniques to classify: CVE-only intel with no rules is
            # still an actionable gap (legacy binary behavior)
            opportunity = "actionable_gap" if cves > 0 else None
        actors = actor_names.get(eid, [])
        malware = malware_names.get(eid, [])
        results[str(eid)] = {
            "ttps": ttps,
            "cves": cves,
            "rules": rules,
            "notes": notes,
            "ai_results": ai_results,
            "total": total,
            "has_detection_gap": has_gap,
            # Tiered, telemetry-aware refinement of has_detection_gap
            "detection_opportunity": opportunity,
            # KEV/high-EPSS CVE present — elevates the opportunity badge
            "has_high_risk_cve": eid in high_risk_cves,
            "has_kev_cve": high_risk_cves.get(eid, False),
            "high_value": total >= 5,
            "pir_matches": pirs,
            # Named subject: actors take precedence over malware on the card
            "actors": actors[:3],
            "actor_count": len(actors),
            "malware": malware[:3],
            "malware_count": len(malware),
            "cve_max_severity": cve_severity.get(eid),
        }

    return results


# --- Detection Coverage (telemetry-aware) ---


@router.post("/intelligence/detection-coverage")
async def classify_detection_coverage(
    technique_ids: list[str] = Body(
        ...,
        description="Up to 500 ATT&CK technique IDs",
        json_schema_extra={"example": ["T1566.001", "T1059.001", "T1027"]},
    ),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Classify techniques as covered / library_only / no_rule.

    Covered means a non-draft rule references the technique AND its required
    data sources are satisfiable by the enabled telemetry inventory. Used by
    entity profiles to roll up genuine detection coverage.
    """
    from app.services.detection_coverage import classify_techniques, summarize

    if len(technique_ids) > 500:
        raise AppError(
            code="bad_request",
            message="Provide at most 500 technique IDs",
            status_code=400,
        )

    classification = await classify_techniques(db, technique_ids)
    return {
        "summary": summarize(classification),
        "techniques": classification,
    }


# --- Workbench Settings: Reset & Rescan ---


@router.post("/intelligence/reset-correlation")
async def reset_correlation(
    user: User = Depends(get_admin_user),
):
    """Reset the correlation engine: unlink all entities from entries and clear relationships. Admin only."""
    from app.workers.intel_feed_tasks import reset_correlation_engine

    task = reset_correlation_engine.delay()
    return {"status": "queued", "task_id": task.id}


@router.post("/intelligence/rescan-all-extraction")
async def rescan_all_extraction(
    user: User = Depends(get_admin_user),
):
    """Re-run regex-based TTP/CVE/mitigation extraction on all entries. Admin only."""
    from app.workers.intel_feed_tasks import rescan_all_feeds_extraction

    task = rescan_all_feeds_extraction.delay()
    return {"status": "queued", "task_id": task.id}


@router.delete("/intelligence/detection-rules")
async def delete_all_detection_rules(
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete all detection rules and their version history. Admin only."""
    rule_result = await db.execute(delete(DetectionRule))
    await db.commit()
    return {
        "status": "deleted",
        "rules_deleted": rule_result.rowcount,
    }


# --- Helpers ---


async def _get_entry(db: AsyncSession, entry_id: uuid.UUID) -> Entry:
    result = await db.execute(select(Entry).where(Entry.id == entry_id))
    entry = result.scalar_one_or_none()
    if not entry:
        raise AppError(code="not_found", message="Entry not found", status_code=404)
    return entry


@router.post("/sync/mitre-attack")
async def trigger_mitre_sync(
    user: User = Depends(get_admin_user),
):
    """Trigger an immediate MITRE ATT&CK sync to populate/update all TTPs. Admin only."""
    from app.workers.enrichment_tasks import run_mitre_attack_sync

    run_mitre_attack_sync.delay()
    return {"status": "dispatched", "message": "MITRE ATT&CK sync started"}


@router.post("/sync/cve-backfill")
async def trigger_cve_backfill(
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Enrich existing CVEs that are missing NVD data (description, CVSS, etc.). Admin only."""
    result = await db.execute(select(func.count()).select_from(CVE).where(CVE.description.is_(None)))
    count = result.scalar() or 0
    if count == 0:
        return {"status": "skipped", "message": "All CVEs already have NVD data"}

    from app.workers.enrichment_tasks import run_cve_nvd_backfill

    run_cve_nvd_backfill.delay()
    return {"status": "dispatched", "message": f"NVD backfill started for {count} CVEs"}


def _ttp_to_response(ttp: TTP) -> TTPResponse:
    return TTPResponse(
        id=ttp.id,
        technique_id=ttp.technique_id,
        technique_name=ttp.technique_name,
        tactic=ttp.tactic,
        tactics=ttp.tactics or [],
        description=ttp.description,
        platforms=ttp.platforms or [],
        data_sources=ttp.data_sources or [],
        mitre_url=ttp.mitre_url,
        detection=ttp.detection,
        is_subtechnique=ttp.is_subtechnique or False,
        parent_technique_id=ttp.parent_technique_id,
        is_deprecated=ttp.is_deprecated or False,
        superseded_by=ttp.superseded_by,
        matrix_domain=ttp.matrix_domain,
        nist_controls=ttp.nist_controls or [],
        cis_controls=ttp.cis_controls or [],
        first_seen_at=ttp.first_seen_at,
        last_seen_at=ttp.last_seen_at,
        article_count=ttp.article_count,
    )


def _cve_to_response(cve: CVE, article_count: int | None = None) -> CVEResponse:
    from app.intelligence.cve import calculate_cve_priority, risk_tier_for

    return CVEResponse(
        id=cve.id,
        cve_id=cve.cve_id,
        cvss_score=cve.cvss_score,
        severity=cve.severity,
        description=cve.description,
        affected_products=cve.affected_products,
        exploit_status=cve.exploit_status,
        exploit_sources=cve.exploit_sources,
        references_=cve.references_ or [],
        nvd_data=cve.nvd_data,
        timeline=cve.timeline,
        first_seen_at=cve.first_seen_at,
        updated_at=cve.updated_at,
        article_count=article_count or 0,
        epss_score=cve.epss_score,
        epss_percentile=cve.epss_percentile,
        epss_updated_at=cve.epss_updated_at,
        epss_previous_score=cve.epss_previous_score,
        epss_changed_at=cve.epss_changed_at,
        exploit_availability=cve.exploit_availability,
        exploit_status_source=cve.exploit_status_source,
        github_poc_count=cve.github_poc_count,
        github_poc_urls=cve.github_poc_urls or [],
        metasploit_module=cve.metasploit_module,
        is_kev=bool(cve.is_kev),
        kev_date_added=cve.kev_date_added,
        kev_due_date=cve.kev_due_date,
        priority=calculate_cve_priority(
            cve.cvss_score,
            cve.epss_score,
            cve.exploit_status,
            is_kev=bool(cve.is_kev),
        ),
        risk_tier=risk_tier_for(cve),
    )


# =============================================================================
# --- Mitigation Routes ---
# =============================================================================


def _mitigation_to_response(m: Mitigation, entry_link: EntryMitigation | None = None) -> MitigationResponse:
    return MitigationResponse(
        id=m.id,
        mitre_id=m.mitre_id,
        name=m.name,
        description=m.description,
        mitre_url=m.mitre_url,
        cis_controls=m.cis_controls or [],
        nist_controls=m.nist_controls or [],
        article_count=m.article_count,
        first_seen_at=m.first_seen_at,
        last_seen_at=m.last_seen_at,
        wikipedia_url=m.wikipedia_url,
        wikipedia_image_url=m.wikipedia_image_url,
        confidence=entry_link.confidence if entry_link else None,
        source=entry_link.source if entry_link else None,
    )


@router.post("/entries/{entry_id}/extract-mitigations", response_model=ExtractionResponse[MitigationResponse])
async def extract_entry_mitigations(
    entry_id: uuid.UUID = Path(..., description="UUID of the entry to extract from"),
    use_ai: bool = Query(True, description="Also run AI-based extraction; false uses regex/pattern matching only"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Extract MITRE mitigations from the entry's content and store them as entry-mitigation links.

    Returns the stored mitigations with an extraction status (success / ai_not_configured / provider_error /
    parse_error).
    """
    entry = await _get_entry(db, entry_id)
    entry_data = _entry_to_dict(entry)
    items, status, error = await extract_mitigations(db, user.id, entry_id, entry_data, use_ai=use_ai)
    stored = await store_mitigations(db, entry_id, items)
    await db.commit()
    return ExtractionResponse(
        items=[_mitigation_to_response(m) for m, _ in stored],
        status=status,
        error_message=error,
    )


@router.get("/entries/{entry_id}/mitigations", response_model=list[MitigationResponse])
async def get_entry_mitigations(
    entry_id: uuid.UUID = Path(..., description="UUID of the entry"),
    user: User = Depends(get_entry_viewer),
    db: AsyncSession = Depends(get_db),
):
    """List the mitigations linked to an entry, with per-entry confidence and source."""
    await _get_entry(db, entry_id)
    result = await db.execute(
        select(Mitigation, EntryMitigation)
        .join(EntryMitigation, EntryMitigation.mitigation_id == Mitigation.id)
        .where(EntryMitigation.entry_id == entry_id)
        .order_by(Mitigation.name)
    )
    return [_mitigation_to_response(m, link) for m, link in result.all()]


@router.get("/entries/{entry_id}/cwes", response_model=list[CWEResponse])
async def get_entry_cwes(
    entry_id: uuid.UUID = Path(..., description="UUID of the entry"),
    user: User = Depends(get_entry_viewer),
    db: AsyncSession = Depends(get_db),
):
    """List the weaknesses linked to an entry, with per-entry confidence and source."""
    await _get_entry(db, entry_id)
    result = await db.execute(
        select(CWE, EntryCWE)
        .join(EntryCWE, EntryCWE.cwe_id == CWE.id)
        .where(EntryCWE.entry_id == entry_id)
        .order_by(CWE.cwe_id)
    )
    return [_cwe_to_response(c, entry_link=link) for c, link in result.all()]


# ---------------------------------------------------------------------------
# Observables — the IOC ledger
# ---------------------------------------------------------------------------


def _observable_expiry(obs: Observable) -> tuple[int | None, datetime | None]:
    """(half_life_days, projected expiry date) — None for kinds that never decay
    and for pinned/denied rows."""
    import math

    from app.intelligence.observables import _EXPIRED_BELOW
    from app.models.observable import DECAY_HALF_LIFE_DAYS

    half_life = DECAY_HALF_LIFE_DAYS.get(obs.kind)
    if half_life is None:
        return None, None
    if obs.confidence_pinned or obs.is_denied or not obs.base_confidence:
        return half_life, None
    if obs.base_confidence <= _EXPIRED_BELOW:
        return half_life, obs.last_seen_at
    days_to_expiry = half_life * math.log2(obs.base_confidence / _EXPIRED_BELOW)
    return half_life, obs.last_seen_at + timedelta(days=days_to_expiry)


def _observable_to_response(obs: Observable, entry_link: EntryObservable | None = None) -> ObservableResponse:
    half_life, expires_at = _observable_expiry(obs)
    return ObservableResponse(
        decay_half_life_days=half_life,
        expires_at=expires_at,
        id=obs.id,
        kind=obs.kind,
        value=obs.value,
        label=obs.label,
        content=obs.content,
        language=obs.language,
        role=obs.role,
        status=obs.status,
        description=obs.description,
        evidence=obs.evidence,
        base_confidence=obs.base_confidence,
        current_confidence=obs.current_confidence,
        confidence_pinned=obs.confidence_pinned,
        is_denied=obs.is_denied,
        infra_tag=obs.infra_tag,
        needs_review=obs.needs_review,
        created_via=obs.created_via,
        sighting_count=obs.sighting_count or 0,
        report_count=obs.report_count or 0,
        feed_source_count=obs.feed_source_count or 0,
        reputation=obs.reputation,
        asn=obs.asn,
        asn_org=obs.asn_org,
        geo_country=obs.geo_country,
        registered_at=obs.registered_at,
        popularity_rank=obs.popularity_rank,
        noise_class=obs.noise_class,
        first_seen_at=obs.first_seen_at,
        last_seen_at=obs.last_seen_at,
        link_source=entry_link.source if entry_link else None,
        link_confidence=entry_link.confidence if entry_link else None,
        surface_form=entry_link.surface_form if entry_link else None,
        was_defanged=entry_link.was_defanged if entry_link else None,
    )


@router.get("/entities/{entity_type}/{entity_id}/infrastructure")
async def get_entity_infrastructure_view(
    entity_type: str = Path(..., description="threat_actor, malware, campaign or tool"),
    entity_id: uuid.UUID = Path(..., description="Entity UUID"),
    format: str = Query("json", pattern="^(json|csv)$", description="json, or csv for a flat export"),
    limit: int = Query(200, ge=1, le=1000),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """The observables behind an actor, family, campaign or tool, in two tiers.

    **Claimed** rows are attribution edges onto the ledger (uses /
    communicates_with / controls), each born from an evidence sentence or an
    analyst — the graph's edges, with their trust tier. **Reported alongside**
    rows are observables a reporting door sighted in articles that link the
    entity: read-time co-occurrence that never becomes a relationship, with
    indicator-list files and newsletters excluded.
    """
    import csv
    import io

    from app.intelligence.infrastructure import (
        INFRASTRUCTURE_ENTITY_TYPES,
        get_entity_infrastructure,
        infrastructure_csv_rows,
    )

    if entity_type not in INFRASTRUCTURE_ENTITY_TYPES:
        raise AppError(
            code="invalid_entity_type",
            message=f"entity_type must be one of {sorted(INFRASTRUCTURE_ENTITY_TYPES)}",
            status_code=422,
        )
    payload = await get_entity_infrastructure(db, entity_type, entity_id, limit=limit)
    if format == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        for row in infrastructure_csv_rows(payload):
            # Spreadsheet formula-injection guard, same as sightings.csv.
            writer.writerow([("'" + c) if c[:1] in "=+-@\t" else c for c in row])
        return Response(
            content=buf.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{entity_type}-{entity_id}-infrastructure.csv"'},
        )
    return payload


@router.get("/observables/{observable_id}/backlinks")
async def get_observable_backlinks_view(
    observable_id: uuid.UUID = Path(..., description="Observable UUID"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Who claims this observable (attribution edges) and which actors,
    families, campaigns and tools its reporting articles name."""
    from app.intelligence.infrastructure import get_observable_backlinks

    exists = (await db.execute(select(Observable.id).where(Observable.id == observable_id))).scalar_one_or_none()
    if exists is None:
        raise AppError(code="not_found", message="Observable not found", status_code=404)
    return await get_observable_backlinks(db, observable_id)


@router.get("/observables", response_model=PaginatedResponse[ObservableResponse])
async def list_observables(
    search: str | None = Query(None, description="Case-insensitive substring match on value or label"),
    kind: str | None = Query(
        None, description="Filter to one kind or a comma-separated group (ipv4,ipv6 — the browser's segments)"
    ),
    role: str | None = Query(None, description="Filter to one network role (c2, phishing, ...)"),
    status: str | None = Query(None, pattern="^(active|aging|expired)$", description="Lifecycle state filter"),
    created_via: str | None = Query(None, description="Capture door filter (ai_extraction, ioc_list, ...)"),
    infra_tag: str | None = Query(
        None,
        description="Dual-use infrastructure filter: a tag (vpn, proxy, tor, rmm, kvm, scanner, phish_sim), "
        "'any' for all tagged rows, or 'none' for true indicators only",
    ),
    min_confidence: float | None = Query(None, ge=0, le=1, description="Minimum current confidence"),
    linked_entity: str | None = Query(
        None,
        pattern=r"^(threat_actor|malware|campaign|tool):[0-9a-fA-F-]{36}$",
        description=(
            "`<type>:<uuid>` — only the observables behind that actor/family/campaign/tool "
            "(claimed attribution edges plus values reported alongside it); the profile's "
            "'Open in observables browser' pivot"
        ),
    ),
    include_denied: bool = Query(False, description="Include analyst-denied values (hidden by default)"),
    sort_by: str = Query(
        "last_seen_at",
        pattern="^(value|kind|current_confidence|sighting_count|first_seen_at|last_seen_at|linked_count|report_count|feed_source_count)$",
        description="Sort column; linked_count sorts by non-rejected entity-relationship count (attribution claims)",
    ),
    sort_order: str = Query("desc", pattern="^(asc|desc)$", description="Sort direction"),
    limit: int = Query(50, ge=1, le=500, description="Page size"),
    offset: int = Query(0, ge=0, description="Number of rows to skip"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Paginated observable ledger with kind/role/lifecycle filters."""
    base_q = select(Observable)
    if not include_denied:
        base_q = base_q.where(Observable.is_denied.is_(False))
    if search:
        pattern = f"%{search}%"
        base_q = base_q.where(or_(Observable.value.ilike(pattern), Observable.label.ilike(pattern)))
    if kind:
        kinds = [k.strip() for k in kind.split(",") if k.strip()]
        base_q = base_q.where(Observable.kind.in_(kinds) if len(kinds) > 1 else Observable.kind == kinds[0])
    if role:
        base_q = base_q.where(Observable.role == role)
    if status:
        base_q = base_q.where(Observable.status == status)
    if created_via:
        base_q = base_q.where(Observable.created_via == created_via)
    if infra_tag:
        if infra_tag == "none":
            base_q = base_q.where(Observable.infra_tag.is_(None))
        elif infra_tag == "any":
            base_q = base_q.where(Observable.infra_tag.is_not(None))
        else:
            base_q = base_q.where(Observable.infra_tag == infra_tag)
    if min_confidence is not None:
        base_q = base_q.where(Observable.current_confidence >= min_confidence)
    if linked_entity:
        from app.intelligence.infrastructure import infrastructure_observable_ids

        l_type, l_id = linked_entity.split(":", 1)
        ids = await infrastructure_observable_ids(db, l_type, uuid.UUID(l_id))
        base_q = base_q.where(Observable.id.in_(ids)) if ids else base_q.where(sa_false())

    total = (await db.execute(select(func.count()).select_from(base_q.subquery()))).scalar_one()
    # linked_count = the shared workbench "Linked" column (attribution claims).
    sort_col = (
        _linked_count_subquery(Observable, "observable") if sort_by == "linked_count" else getattr(Observable, sort_by)
    )
    order = sort_col.asc() if sort_order == "asc" else sort_col.desc()
    result = await db.execute(base_q.order_by(order, Observable.id.asc()).limit(limit).offset(offset))
    items = [_observable_to_response(o) for o in result.scalars().all()]
    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset, has_more=(offset + limit) < total)


@router.get("/observables/rollup")
async def observables_rollup(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Counts by kind and lifecycle state for the browser's segmented filter."""
    by_kind = (
        await db.execute(
            select(Observable.kind, func.count()).where(Observable.is_denied.is_(False)).group_by(Observable.kind)
        )
    ).all()
    by_status = (
        await db.execute(
            select(Observable.status, func.count()).where(Observable.is_denied.is_(False)).group_by(Observable.status)
        )
    ).all()
    return {
        "total": sum(c for _, c in by_kind),
        "by_kind": {k: c for k, c in by_kind},
        "by_status": {s: c for s, c in by_status},
    }


@router.get("/observables/candidates", response_model=list[ObservableCandidateRow])
async def list_observable_candidates(
    limit: int = Query(100, ge=1, le=500, description="Max aggregated candidate rows"),
    entry_window: int = Query(
        400, ge=10, le=2000, description="How many recent candidate-bearing entries to aggregate"
    ),
    kind: str | None = Query(None, description="Filter to one kind"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """The central review queue: regex nominations no judgment door confirmed.

    Aggregated by (kind, value) across recent entries — a value nominated in
    many articles is the one worth a look. Values already in the ledger
    (confirmed or denied) are excluded.
    """
    rows = (
        await db.execute(
            select(Entry.id, Entry.title, Entry.published_at, Entry.observable_candidates)
            .where(func.jsonb_array_length(Entry.observable_candidates) > 0)
            .order_by(Entry.published_at.desc().nulls_last())
            .limit(entry_window)
        )
    ).all()

    from app.intelligence.observables import validate_kind_value

    agg: dict[tuple[str, str], dict] = {}
    rejected: dict[tuple[str, str], bool] = {}
    for entry_id, title, published_at, candidates in rows:
        for c in candidates or []:
            c_kind, c_value = c.get("kind"), c.get("value")
            if not c_kind or not c_value or (kind and c_kind != kind):
                continue
            key = (c_kind, c_value)
            # Nominations staged under older, looser rules: a value today's
            # validators reject could never be promoted, so it never shows.
            if key not in agg:
                if key not in rejected:
                    rejected[key] = c_kind not in ALL_KINDS or validate_kind_value(c_kind, c_value) is None
                if rejected[key]:
                    continue
            row = agg.get(key)
            if row is None:
                agg[key] = {
                    "kind": c_kind,
                    "value": c_value,
                    "entry_count": 1,
                    "was_defanged": bool(c.get("was_defanged")),
                    "sample_surface": c.get("surface_form"),
                    # Entries are scanned newest-first, so the first hit is the latest.
                    "latest_entry_id": entry_id,
                    "latest_entry_title": title,
                    "latest_seen_at": published_at,
                }
            else:
                row["entry_count"] += 1
                row["was_defanged"] = row["was_defanged"] or bool(c.get("was_defanged"))

    if not agg:
        return []
    known = (
        await db.execute(
            select(Observable.kind, Observable.value).where(
                tuple_(Observable.kind, Observable.value).in_(list(agg.keys()))
            )
        )
    ).all()
    for pair in known:
        agg.pop((pair.kind, pair.value), None)

    ranked = sorted(agg.values(), key=lambda r: (-r["entry_count"], -int(r["was_defanged"])))
    return [ObservableCandidateRow(**r) for r in ranked[:limit]]


@router.post("/observables/never-capture", response_model=ObservableResponse)
async def never_capture_observable(
    payload: ObservableNeverCaptureRequest,
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Tombstone a value: dismiss it from the candidates queue forever.

    Creates (or reuses) the ledger row and marks it denied, so the observables
    stage, every door, and the export all refuse it from now on.
    """
    from app.intelligence.observables import normalize_value
    from app.models.observable import ALL_KINDS

    if payload.kind not in ALL_KINDS:
        raise AppError(code="invalid_kind", message=f"kind must be one of {sorted(ALL_KINDS)}", status_code=422)
    canonical = normalize_value(payload.kind, payload.value)
    if not canonical:
        raise AppError(code="invalid_observable", message="Empty value", status_code=422)
    existing = (
        await db.execute(select(Observable).where(Observable.kind == payload.kind, Observable.value == canonical))
    ).scalar_one_or_none()
    if existing is None:
        existing = Observable(
            kind=payload.kind,
            value=canonical,
            created_via="manual",
            base_confidence=0.0,
            current_confidence=0.0,
        )
        db.add(existing)
        await db.flush()
    existing.is_denied = True
    existing.status = "expired"
    await db.commit()
    from app.services.entity_indexer import delete_entity_document

    delete_entity_document("observable", existing.id)
    await db.refresh(existing)
    return _observable_to_response(existing)


@router.get("/observables/{observable_id}", response_model=ObservableResponse)
async def get_observable(
    observable_id: uuid.UUID = Path(..., description="UUID of the observable"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Observable).where(Observable.id == observable_id))
    obs = result.scalar_one_or_none()
    if not obs:
        raise AppError(code="not_found", message="Observable not found", status_code=404)
    return _observable_to_response(obs)


@router.get("/observables/{observable_id}/sightings.csv")
async def export_observable_sightings(
    observable_id: uuid.UUID = Path(..., description="UUID of the observable"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """The row's history as CSV: every sighting with its source and article."""
    import csv as csv_mod
    import io

    obs = (await db.execute(select(Observable).where(Observable.id == observable_id))).scalar_one_or_none()
    if not obs:
        raise AppError(code="not_found", message="Observable not found", status_code=404)
    rows = (
        await db.execute(
            select(Entry.title, Entry.published_at, EntryObservable)
            .join(EntryObservable, EntryObservable.entry_id == Entry.id)
            .where(EntryObservable.observable_id == observable_id)
            .order_by(Entry.published_at.desc().nulls_last())
        )
    ).all()
    buf = io.StringIO()
    writer = csv_mod.writer(buf)
    writer.writerow(["kind", "value", "entry_title", "published_at", "source", "surface_form", "confidence"])
    for title, published_at, link in rows:

        def _safe(v: str) -> str:
            return "'" + v if v[:1] in "=+-@\t" else v

        writer.writerow(
            [
                obs.kind,
                _safe(obs.value),
                _safe(title or ""),
                published_at.isoformat() if published_at else "",
                link.source or "",
                _safe(link.surface_form or ""),
                link.confidence or "",
            ]
        )
    return Response(buf.getvalue(), media_type="text/csv")


@router.patch("/observables/{observable_id}", response_model=ObservableResponse)
async def update_observable(
    payload: ObservableUpdateRequest,
    observable_id: uuid.UUID = Path(..., description="UUID of the observable"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Edit the analyst-owned fields: label, role, description, confidence pin."""
    result = await db.execute(select(Observable).where(Observable.id == observable_id))
    obs = result.scalar_one_or_none()
    if not obs:
        raise AppError(code="not_found", message="Observable not found", status_code=404)
    if payload.label is not None:
        obs.label = payload.label.strip() or None
    if payload.role is not None:
        from app.models.observable import ROLES

        if payload.role and payload.role not in ROLES:
            raise AppError(code="invalid_role", message=f"role must be one of {sorted(ROLES)}", status_code=422)
        obs.role = payload.role or None
    if payload.description is not None:
        obs.description = payload.description.strip() or None
    if payload.confidence_pinned is not None:
        obs.confidence_pinned = payload.confidence_pinned
        if payload.confidence_pinned:
            obs.current_confidence = obs.base_confidence
            obs.status = "active"
    if payload.is_denied is not None:
        # Un-denying resurrects a tombstone — admin judgment only.
        if user.role != "admin":
            raise AppError(code="forbidden", message="Only admins can change the never-capture flag", status_code=403)
        obs.is_denied = payload.is_denied
        if not payload.is_denied:
            obs.status = "active"
    await db.commit()
    await db.refresh(obs)
    return _observable_to_response(obs)


@router.post("/observables/{observable_id}/deny", response_model=ObservableResponse)
async def deny_observable(
    observable_id: uuid.UUID = Path(..., description="UUID of the observable"),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Never capture or export this value again. Sightings are kept as history."""
    result = await db.execute(select(Observable).where(Observable.id == observable_id))
    obs = result.scalar_one_or_none()
    if not obs:
        raise AppError(code="not_found", message="Observable not found", status_code=404)
    obs.is_denied = True
    obs.status = "expired"
    await db.commit()
    from app.services.entity_indexer import delete_entity_document

    delete_entity_document("observable", observable_id)
    await db.refresh(obs)
    return _observable_to_response(obs)


@router.delete("/observables/{observable_id}", status_code=204)
async def delete_observable(
    observable_id: uuid.UUID = Path(..., description="UUID of the observable"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete the ledger row outright, with its sightings and relationships.

    The other rung is ``/deny`` — that keeps the row as a tombstone so the
    capture doors refuse the value forever. A plain delete leaves no memory of
    the value, so a future door may capture it again; delete is for rows that
    should never have existed, deny is for values that must stay out.
    """
    from app.models.campaign import CampaignEntity
    from app.models.entity_relationship import EntityRelationship

    result = await db.execute(select(Observable).where(Observable.id == observable_id))
    obs = result.scalar_one_or_none()
    if not obs:
        raise AppError(code="not_found", message="Observable not found", status_code=404)

    await db.execute(delete(EntryObservable).where(EntryObservable.observable_id == observable_id))
    await db.execute(
        delete(EntityRelationship).where(
            or_(
                (EntityRelationship.source_type == "observable") & (EntityRelationship.source_id == observable_id),
                (EntityRelationship.target_type == "observable") & (EntityRelationship.target_id == observable_id),
            )
        )
    )
    await db.execute(
        delete(CampaignEntity).where(
            CampaignEntity.entity_type == "observable", CampaignEntity.entity_id == observable_id
        )
    )
    await db.delete(obs)
    await db.commit()

    from app.intelligence.correlation_cache import invalidate_entity_cache
    from app.services.entity_indexer import delete_entity_document

    delete_entity_document("observable", observable_id)
    await invalidate_entity_cache("observable", str(observable_id))
    return Response(status_code=204)


@router.get("/entries/{entry_id}/observables", response_model=ObservableEntryPayload)
async def get_entry_observables(
    entry_id: uuid.UUID = Path(..., description="UUID of the entry"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """An entry's confirmed observables plus its unpromoted Tier-0 candidates."""
    entry = await _get_entry(db, entry_id)
    result = await db.execute(
        select(Observable, EntryObservable)
        .join(EntryObservable, EntryObservable.observable_id == Observable.id)
        .where(EntryObservable.entry_id == entry_id)
        .order_by(Observable.current_confidence.desc(), Observable.kind, Observable.value)
        # An ioc_list entry can carry thousands of sightings; the reader panel
        # and highlighter need the strongest few hundred, not a megabyte.
        .limit(300)
    )
    items = [_observable_to_response(o, entry_link=link) for o, link in result.all()]
    confirmed = {(i.kind, i.value) for i in items}
    candidates = [c for c in (entry.observable_candidates or []) if (c.get("kind"), c.get("value")) not in confirmed]
    return ObservableEntryPayload(items=items, candidates=candidates)


@router.post("/entries/{entry_id}/observables/promote", response_model=ObservableResponse)
async def promote_observable_candidate(
    payload: ObservablePromoteRequest,
    entry_id: uuid.UUID = Path(..., description="UUID of the entry the value was seen in"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """The analyst door: turn a candidate (or any value) into a ledger row."""
    from app.intelligence.observables import get_or_create_observable, record_sighting, validate_kind_value
    from app.models.observable import ALL_KINDS

    entry = await _get_entry(db, entry_id)
    if payload.kind not in ALL_KINDS:
        raise AppError(code="invalid_kind", message=f"kind must be one of {sorted(ALL_KINDS)}", status_code=422)
    canonical = validate_kind_value(payload.kind, payload.value)
    if canonical is None:
        raise AppError(
            code="invalid_observable",
            message=f"'{payload.value}' is not a valid {payload.kind} value",
            status_code=422,
        )
    # A staged candidate (an AI shadow nomination) already carries a judgment;
    # the analyst's click confirms it rather than discarding it.
    staged = next(
        (
            c
            for c in (entry.observable_candidates or [])
            if isinstance(c, dict) and c.get("kind") == payload.kind and c.get("value") == canonical
        ),
        {},
    )
    obs = await get_or_create_observable(
        db,
        payload.kind,
        canonical,
        via="manual",
        entry_id=entry_id,
        role=payload.role or staged.get("role"),
        evidence=payload.evidence or staged.get("evidence"),
        label=payload.label,
        was_defanged=bool(staged.get("was_defanged")),
    )
    if obs is None:
        raise AppError(code="observable_denied", message="This value is on the never-capture list", status_code=409)
    await record_sighting(
        db,
        entry_id,
        obs,
        source="manual",
        confidence=staged.get("confidence"),
        surface_form=payload.surface_form or staged.get("surface_form") or payload.value,
        was_defanged=bool(staged.get("was_defanged")),
    )
    await db.commit()
    await db.refresh(obs)
    from app.services.entity_indexer import index_single_entity
    from app.workers.automation_tasks import dispatch_observable_capture_automations

    try:
        await index_single_entity("observable", obs)
    except Exception:
        logger.warning("Observable search indexing failed for %s", obs.id, exc_info=True)
    # The analyst door is a capture too: on_observable_captured rules see it.
    dispatch_observable_capture_automations(entry_id, countdown=0)
    return _observable_to_response(obs)


@router.post("/entries/{entry_id}/observables/dismiss", status_code=204)
async def dismiss_observable_candidate(
    payload: ObservableDismissRequest,
    entry_id: uuid.UUID = Path(..., description="UUID of the entry carrying the candidate"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Drop one candidate from this entry's nomination list.

    Entry-local and available to every analyst — the value can nominate again
    in other articles. Never-capture (admin) is the global tombstone rung.
    """
    entry = await _get_entry(db, entry_id)
    before = list(entry.observable_candidates or [])
    remaining = [c for c in before if not (c.get("kind") == payload.kind and c.get("value") == payload.value)]
    if len(remaining) == len(before):
        raise AppError(code="not_found", message="Candidate not found on this entry", status_code=404)
    entry.observable_candidates = remaining
    await db.commit()
    return Response(status_code=204)


@router.delete("/entries/{entry_id}/observables/{observable_id}", status_code=204)
async def unlink_entry_observable(
    entry_id: uuid.UUID = Path(..., description="UUID of the entry"),
    observable_id: uuid.UUID = Path(..., description="UUID of the observable to unlink"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Remove one sighting (the ledger row is kept) and refresh its counters."""
    from app.intelligence.observables import recount_observable

    result = await db.execute(
        delete(EntryObservable).where(
            EntryObservable.entry_id == entry_id, EntryObservable.observable_id == observable_id
        )
    )
    if not result.rowcount:
        raise AppError(code="not_found", message="No such sighting", status_code=404)
    await recount_observable(db, observable_id)
    await db.commit()
    await _invalidate_after_unlink("observable", observable_id, entry_id, db)
    return Response(status_code=204)


@router.get("/mitigations", response_model=PaginatedResponse[MitigationResponse])
async def list_mitigations(
    search: str | None = Query(None, description="Case-insensitive substring match on name or MITRE ID"),
    sort_by: str = Query(
        "article_count",
        pattern="^(name|mitre_id|article_count|linked_count)$",
        description="Sort column; linked_count sorts by non-rejected entity-relationship count",
    ),
    sort_order: str = Query("desc", pattern="^(asc|desc)$", description="Sort direction"),
    limit: int = Query(50, ge=1, le=500, description="Page size"),
    offset: int = Query(0, ge=0, description="Number of rows to skip"),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Paginated mitigation list with search and sorting."""
    base_q = select(Mitigation)
    if search:
        base_q = base_q.where((Mitigation.name.ilike(f"%{search}%")) | (Mitigation.mitre_id.ilike(f"%{search}%")))
    total_result = await db.execute(select(func.count()).select_from(base_q.subquery()))
    total = total_result.scalar_one()
    if sort_by == "linked_count":
        sort_expr = _linked_count_subquery(Mitigation, "mitigation")
    else:
        col = getattr(Mitigation, sort_by)
        sort_expr = func.lower(col) if sort_by == "name" else col
    order = sort_expr.asc() if sort_order == "asc" else sort_expr.desc()
    result = await db.execute(base_q.order_by(order).offset(offset).limit(limit))
    items = [_mitigation_to_response(m) for m in result.scalars()]
    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset, has_more=(offset + limit) < total)


@router.get("/mitigations/{mitigation_id}", response_model=MitigationResponse)
async def get_mitigation(
    mitigation_id: uuid.UUID = Path(..., description="UUID of the mitigation"),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Get a single mitigation by UUID."""
    result = await db.execute(select(Mitigation).where(Mitigation.id == mitigation_id))
    m = result.scalar_one_or_none()
    if not m:
        raise AppError(code="not_found", message="Mitigation not found", status_code=404)
    return _mitigation_to_response(m)


# =============================================================================
# --- CWE (Weakness) Routes ---
# =============================================================================


def _cwe_to_response(
    c: CWE,
    *,
    cve_count: int = 0,
    kev_count: int = 0,
    cve_count_rolled: int | None = None,
    kev_count_rolled: int | None = None,
    top_vendor: tuple[str, int] | None = None,
    entry_link: EntryCWE | None = None,
) -> CWEResponse:
    return CWEResponse(
        id=c.id,
        cwe_id=c.cwe_id,
        name=c.name,
        kind=c.kind,
        abstraction=c.abstraction,
        status=c.status,
        mapping_usage=c.mapping_usage,
        description=c.description,
        extended_description=c.extended_description,
        parent_cwe_id=c.parent_cwe_id,
        likelihood_of_exploit=c.likelihood_of_exploit,
        alternate_terms=c.alternate_terms or [],
        capec_ids=c.capec_ids or [],
        consequences=c.consequences or [],
        mitigations=c.mitigations or [],
        detection_methods=c.detection_methods or [],
        cwe_url=c.cwe_url,
        is_deprecated=c.is_deprecated,
        superseded_by=c.superseded_by,
        article_count=c.article_count or 0,
        first_seen_at=c.first_seen_at,
        last_seen_at=c.last_seen_at,
        wikipedia_url=c.wikipedia_url,
        wikipedia_image_url=c.wikipedia_image_url,
        cve_count=cve_count,
        kev_count=kev_count,
        cve_count_rolled=cve_count_rolled,
        kev_count_rolled=kev_count_rolled,
        top_vendor=top_vendor[0] if top_vendor else None,
        top_vendor_count=top_vendor[1] if top_vendor else None,
        confidence=entry_link.confidence if entry_link else None,
        source=entry_link.source if entry_link else None,
    )


#: Recursive ancestor walk over parent_cwe_id, used to roll descendant CVE counts
#: up the abstraction ladder. NVD tags a CVE at whatever level the analyst chose,
#: so a Class or Pillar's *direct* count is close to meaningless — CWE-664 has 2
#: direct links and ~24k rolled up. The depth guard is belt-and-braces: view 1000
#: is a tree, but a malformed catalog refresh must not hang the API.
_MAX_LADDER_DEPTH = 12


async def _cwe_rolled_counts(db: AsyncSession) -> dict[uuid.UUID, tuple[int, int]]:
    """cwe pk -> (cve_count_rolled, kev_count_rolled), self included.

    Counts DISTINCT CVEs, not links: a CVE tagged with both CWE-416 and CWE-787
    sits under CWE-664 twice, and summing per-node counts would report 23,910
    where the subtree actually holds 21,651 — a headline that disagrees with the
    list underneath it. One query for the whole catalog (~1,400 rows) rather
    than a correlated subquery per result row.
    """
    sql = sa_text(
        """
        WITH RECURSIVE anc AS (
            SELECT w.id AS node, w.id AS ancestor, w.parent_cwe_id AS next_id, 0 AS depth
            FROM cwes w
            UNION ALL
            SELECT a.node, p.id, p.parent_cwe_id, a.depth + 1
            FROM anc a
            JOIN cwes p ON p.cwe_id = a.next_id
            WHERE a.next_id IS NOT NULL AND a.depth < :max_depth
        )
        SELECT anc.ancestor,
               count(DISTINCT cw.cve_id)::bigint,
               count(DISTINCT cw.cve_id) FILTER (WHERE c.is_kev)::bigint
        FROM anc
        JOIN cve_weaknesses cw ON cw.cwe_id = anc.node
        JOIN cves c ON c.id = cw.cve_id
        GROUP BY 1
        """
    )
    rows = (await db.execute(sql, {"max_depth": _MAX_LADDER_DEPTH})).all()
    return {row[0]: (int(row[1] or 0), int(row[2] or 0)) for row in rows}


async def _cwe_top_vendors(db: AsyncSession, cwe_pks: list[uuid.UUID]) -> dict[uuid.UUID, tuple[str, int]]:
    """cwe pk -> (vendor name, CVE count) for the vendor shipping the most of it.

    One DISTINCT ON over the page's ids rather than a correlated subquery per
    row. Absent for most weaknesses: cve_affected resolves ~25k of the corpus's
    CPE pairs, so a weakness whose CVEs never resolved has no vendor to name.
    """
    if not cwe_pks:
        return {}
    sql = sa_text(
        """
        SELECT DISTINCT ON (cw.cwe_id) cw.cwe_id, v.name, count(DISTINCT cw.cve_id) AS n
        FROM cve_weaknesses cw
        JOIN cve_affected ca ON ca.cve_id = cw.cve_id
        JOIN vendors v ON v.id = ca.vendor_id
        WHERE cw.cwe_id = ANY(:ids)
        GROUP BY cw.cwe_id, v.name
        ORDER BY cw.cwe_id, count(DISTINCT cw.cve_id) DESC, v.name
        """
    )
    rows = (await db.execute(sql, {"ids": cwe_pks})).all()
    return {row[0]: (row[1], int(row[2])) for row in rows}


def _cwe_direct_count_subq(kev_only: bool = False):
    """Correlated count of a weakness's own CVE links (not rolled up)."""
    q = select(func.count()).select_from(CVEWeakness).where(CVEWeakness.cwe_id_fk == CWE.id)
    if kev_only:
        q = q.join(CVE, CVE.id == CVEWeakness.cve_id).where(CVE.is_kev.is_(True))
    return q.correlate(CWE).scalar_subquery()


@router.get("/cwes", response_model=PaginatedResponse[CWEResponse])
async def list_cwes(
    search: str | None = Query(None, description="Case-insensitive substring match on CWE id, name or alternate terms"),
    abstraction: str | None = Query(None, description="Filter by ladder level: Pillar, Class, Base, Variant, Compound"),
    kind: str | None = Query(None, pattern="^(weakness|category)$", description="Filter by catalog kind"),
    mapping_usage: str | None = Query(
        None, description="Filter by MITRE mapping guidance: Allowed, Allowed-with-Review, Discouraged, Prohibited"
    ),
    observed_only: bool = Query(False, description="Only weaknesses with at least one CVE or article in this corpus"),
    include_deprecated: bool = Query(True, description="Include entries MITRE has retired"),
    sort_by: str = Query(
        "cve_count",
        pattern="^(cwe_id|name|abstraction|article_count|cve_count|kev_count|cve_count_rolled|kev_count_rolled|linked_count)$",
        description="Sort column; cve_count_rolled sorts by the whole subtree",
    ),
    sort_order: str = Query("desc", pattern="^(asc|desc)$", description="Sort direction"),
    limit: int = Query(50, ge=1, le=500, description="Page size"),
    offset: int = Query(0, ge=0, description="Number of rows to skip"),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Paginated weakness catalog with corpus counts, search, filters and sorting."""
    cve_count = _cwe_direct_count_subq().label("cve_count")
    kev_count = _cwe_direct_count_subq(kev_only=True).label("kev_count")

    base_q = select(CWE, cve_count, kev_count)
    if search:
        pattern = f"%{search}%"
        base_q = base_q.where(
            or_(
                CWE.cwe_id.ilike(pattern),
                CWE.name.ilike(pattern),
                func.array_to_string(CWE.alternate_terms, " ").ilike(pattern),
            )
        )
    if abstraction:
        base_q = base_q.where(CWE.abstraction == abstraction)
    if kind:
        base_q = base_q.where(CWE.kind == kind)
    if mapping_usage:
        base_q = base_q.where(CWE.mapping_usage == mapping_usage)
    if not include_deprecated:
        base_q = base_q.where(CWE.is_deprecated.is_(False))
    if observed_only:
        base_q = base_q.where(or_(cve_count > 0, CWE.article_count > 0))

    total = (await db.execute(select(func.count()).select_from(base_q.subquery()))).scalar_one()

    # One catalog-wide CTE (~1,400 rows) rather than a correlated subquery per
    # row, so it is cheap enough to run on every page — the rolled counts are
    # displayed columns, not just a sort key. Sorting by them orders in Python
    # over the filtered set, which is bounded by the catalog, not the corpus.
    rolled = await _cwe_rolled_counts(db)

    if sort_by in ("cve_count_rolled", "kev_count_rolled"):
        idx = 0 if sort_by == "cve_count_rolled" else 1
        rows = (await db.execute(base_q)).all()
        rows.sort(key=lambda r: rolled.get(r[0].id, (0, 0))[idx], reverse=(sort_order == "desc"))
        page = rows[offset : offset + limit]
    else:
        if sort_by == "linked_count":
            sort_expr = _linked_count_subquery(CWE, entity_types.CWE)
        elif sort_by == "cve_count":
            sort_expr = cve_count
        elif sort_by == "kev_count":
            sort_expr = kev_count
        else:
            col = getattr(CWE, sort_by)
            sort_expr = func.lower(col) if sort_by == "name" else col
        order = sort_expr.asc() if sort_order == "asc" else sort_expr.desc()
        # cwe_id is text ("CWE-9" < "CWE-10" lexically), so the numeric suffix is
        # the tiebreaker that makes paging stable and id sorting read correctly.
        numeric_id = cast(func.regexp_replace(CWE.cwe_id, r"\D", "", "g"), sa.BigInteger)
        if sort_by == "cwe_id":
            order = numeric_id.asc() if sort_order == "asc" else numeric_id.desc()
        page = (await db.execute(base_q.order_by(order, numeric_id.asc()).offset(offset).limit(limit))).all()

    top_vendors = await _cwe_top_vendors(db, [c.id for c, _, _ in page])
    items = [
        _cwe_to_response(
            c,
            cve_count=n,
            kev_count=k,
            cve_count_rolled=rolled.get(c.id, (None, None))[0],
            kev_count_rolled=rolled.get(c.id, (None, None))[1],
            top_vendor=top_vendors.get(c.id),
        )
        for c, n, k in page
    ]
    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset, has_more=(offset + limit) < total)


@router.get("/cwes/rollup", response_model=list[CWEResponse])
async def cwe_rollup(
    abstraction: str = Query("Pillar", description="Ladder level to roll up to: Pillar, Class, Base, Variant"),
    limit: int = Query(25, ge=1, le=200, description="Maximum rows"),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Every CVE in the corpus folded up to the given abstraction level.

    This is the view a flat `nvd_data` string cannot produce: NVD tags CVEs
    wherever the assigning analyst chose on the ladder, so counting the raw ids
    puts a Variant and a Pillar side by side as if they were peers.
    """
    rolled = await _cwe_rolled_counts(db)
    rows = (
        await db.execute(
            select(CWE, _cwe_direct_count_subq(), _cwe_direct_count_subq(kev_only=True)).where(
                CWE.abstraction == abstraction
            )
        )
    ).all()
    ordered = sorted(rows, key=lambda r: rolled.get(r[0].id, (0, 0))[0], reverse=True)[:limit]
    top_vendors = await _cwe_top_vendors(db, [c.id for c, _, _ in ordered])
    return [
        _cwe_to_response(
            c,
            cve_count=n,
            kev_count=k,
            cve_count_rolled=rolled.get(c.id, (0, 0))[0],
            kev_count_rolled=rolled.get(c.id, (0, 0))[1],
            top_vendor=top_vendors.get(c.id),
        )
        for c, n, k in ordered
    ]


async def _load_cwe(db: AsyncSession, cwe_id: str) -> CWE:
    """Resolve a CWE by UUID or by its catalog id ("CWE-416", or bare "416")."""
    try:
        uid = uuid.UUID(cwe_id)
        cwe = (await db.execute(select(CWE).where(CWE.id == uid))).scalar_one_or_none()
    except ValueError:
        key = cwe_id if cwe_id.upper().startswith("CWE-") else f"CWE-{cwe_id}"
        cwe = (await db.execute(select(CWE).where(func.upper(CWE.cwe_id) == key.upper()))).scalar_one_or_none()
    if not cwe:
        raise AppError(code="not_found", message="Weakness not found", status_code=404)
    return cwe


@router.get("/cwes/{cwe_id}", response_model=CWEResponse)
async def get_cwe(
    cwe_id: str = Path(..., description="CWE UUID or catalog id (e.g. CWE-416)"),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Get a single weakness by UUID or catalog id, with direct and rolled CVE counts."""
    cwe = await _load_cwe(db, cwe_id)
    counts = (
        await db.execute(
            select(
                func.count(CVEWeakness.id),
                func.count(CVEWeakness.id).filter(CVE.is_kev.is_(True)),
            )
            .select_from(CVEWeakness)
            .join(CVE, CVE.id == CVEWeakness.cve_id)
            .where(CVEWeakness.cwe_id_fk == cwe.id)
        )
    ).one()
    rolled = await _cwe_rolled_counts(db)
    response = _cwe_to_response(
        cwe,
        cve_count=int(counts[0] or 0),
        kev_count=int(counts[1] or 0),
        cve_count_rolled=rolled.get(cwe.id, (0, 0))[0],
        kev_count_rolled=rolled.get(cwe.id, (0, 0))[1],
    )
    response.capec_patterns = [CAPECRef(**p) for p in await capec_names(db, cwe.capec_ids or [])]
    return response


@router.get("/cwes/{cwe_id}/family", response_model=CWEFamilyResponse)
async def get_cwe_family(
    cwe_id: str = Path(..., description="CWE UUID or catalog id (e.g. CWE-416)"),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Where a weakness sits on the ladder: lineage to the pillar, children, siblings.

    The direct analogue of /ttps/{id}/related-techniques, and it feeds the same
    shape of Overview panel.
    """
    cwe = await _load_cwe(db, cwe_id)
    rolled = await _cwe_rolled_counts(db)

    def ref(row: CWE) -> CWEFamilyRef:
        return CWEFamilyRef(
            id=row.id,
            cwe_id=row.cwe_id,
            name=row.name,
            abstraction=row.abstraction,
            cve_count=rolled.get(row.id, (0, 0))[0],
        )

    by_id = {row.cwe_id: row for row in (await db.execute(select(CWE))).scalars()}

    lineage: list[CWEFamilyRef] = []
    cursor = cwe.parent_cwe_id
    seen: set[str] = set()
    while cursor and cursor not in seen and len(lineage) < _MAX_LADDER_DEPTH:
        seen.add(cursor)
        parent_row = by_id.get(cursor)
        if parent_row is None:
            break
        lineage.append(ref(parent_row))
        cursor = parent_row.parent_cwe_id
    lineage.reverse()  # root-first

    children = [ref(r) for r in by_id.values() if r.parent_cwe_id == cwe.cwe_id]
    children.sort(key=lambda r: -r.cve_count)

    siblings = (
        [ref(r) for r in by_id.values() if r.parent_cwe_id == cwe.parent_cwe_id and r.cwe_id != cwe.cwe_id]
        if cwe.parent_cwe_id
        else []
    )
    siblings.sort(key=lambda r: -r.cve_count)

    replacement_row = by_id.get(cwe.superseded_by) if cwe.superseded_by else None
    return CWEFamilyResponse(
        lineage=lineage,
        parent=lineage[-1] if lineage else None,
        children=children,
        siblings=siblings,
        replacement=ref(replacement_row) if replacement_row else None,
    )


@router.get("/cwes/{cwe_id}/vendors", response_model=list[CWEAffectedVendorRow])
async def get_cwe_vendors(
    cwe_id: str = Path(..., description="CWE UUID or catalog id (e.g. CWE-416)"),
    limit: int = Query(8, ge=1, le=50, description="Maximum rows"),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Vendors shipping the most CVEs with this weakness — who keeps writing this bug.

    Derived through cve_affected, so it covers the CVEs whose NVD CPE strings
    resolved to a vendor entity: accurate where present, incomplete overall.
    """
    cwe = await _load_cwe(db, cwe_id)
    rows = (
        await db.execute(
            select(
                Vendor.id,
                Vendor.name,
                func.count(func.distinct(CVEWeakness.cve_id)).label("n"),
                func.count(func.distinct(case((CVE.is_kev.is_(True), CVEWeakness.cve_id)))).label("kev"),
            )
            .select_from(CVEWeakness)
            .join(CVE, CVE.id == CVEWeakness.cve_id)
            .join(CVEAffected, CVEAffected.cve_id == CVEWeakness.cve_id)
            .join(Vendor, Vendor.id == CVEAffected.vendor_id)
            .where(CVEWeakness.cwe_id_fk == cwe.id)
            .group_by(Vendor.id, Vendor.name)
            .order_by(func.count(func.distinct(CVEWeakness.cve_id)).desc())
            .limit(limit)
        )
    ).all()
    return [
        CWEAffectedVendorRow(vendor_id=vid, name=name, cve_count=int(n), kev_count=int(kev or 0))
        for vid, name, n, kev in rows
    ]


@router.get("/cves/{cve_id}/weaknesses", response_model=list[CVEWeaknessRow])
async def get_cve_weaknesses(
    cve_id: str = Path(..., description="CVE UUID or CVE identifier string (e.g. CVE-2024-3400)"),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Every NVD weakness assignment on a CVE — feeds the profile's Weaknesses panel.

    Unresolved refs (`NVD-CWE-noinfo`, `NVD-CWE-Other`) are returned rather than
    filtered: "NVD declined to classify this" is a real answer, and hiding it
    would make an unclassified CVE look identical to one with no data.
    """
    try:
        uid = uuid.UUID(cve_id)
        cve = (await db.execute(select(CVE).where(CVE.id == uid))).scalar_one_or_none()
    except ValueError:
        cve = (await db.execute(select(CVE).where(CVE.cve_id == cve_id))).scalar_one_or_none()
    if not cve:
        raise AppError(code="not_found", message="CVE not found", status_code=404)

    rows = (
        await db.execute(
            select(CVEWeakness, CWE)
            .outerjoin(CWE, CWE.id == CVEWeakness.cwe_id_fk)
            .where(CVEWeakness.cve_id == cve.id)
            .order_by(CVEWeakness.is_primary.desc(), CVEWeakness.cwe_ref)
        )
    ).all()

    by_id = {row.cwe_id: row for row in (await db.execute(select(CWE))).scalars()} if rows else {}

    def pillar_of(row: CWE | None) -> CWE | None:
        cursor, seen, depth = row, set(), 0
        while cursor and cursor.parent_cwe_id and depth < _MAX_LADDER_DEPTH:
            if cursor.parent_cwe_id in seen:
                break
            seen.add(cursor.parent_cwe_id)
            nxt = by_id.get(cursor.parent_cwe_id)
            if nxt is None:
                break
            cursor, depth = nxt, depth + 1
        return cursor

    out: list[CVEWeaknessRow] = []
    for link, cwe in rows:
        pillar = pillar_of(cwe) if cwe else None
        out.append(
            CVEWeaknessRow(
                cwe_ref=link.cwe_ref,
                cwe_id=cwe.id if cwe else None,
                name=cwe.name if cwe else None,
                description=cwe.description if cwe else None,
                abstraction=cwe.abstraction if cwe else None,
                kind=cwe.kind if cwe else None,
                mapping_usage=cwe.mapping_usage if cwe else None,
                is_primary=link.is_primary,
                assigner=link.assigner,
                pillar_cwe_id=pillar.cwe_id if pillar and pillar.id != (cwe.id if cwe else None) else None,
                pillar_name=pillar.name if pillar and pillar.id != (cwe.id if cwe else None) else None,
            )
        )
    return out


async def _entity_weakness_profile(db: AsyncSession, join_col, entity_id: uuid.UUID, limit: int) -> list[CWEVendorRow]:
    """Weakness mix for a vendor or product, derived through cve_affected.

    Deliberately derived rather than materialised: the join is two hops and both
    are indexed, and a stored table would be a third thing to drift out of sync
    with NVD.
    """
    rows = (
        await db.execute(
            select(CWE.cwe_id, CWE.name, CWE.abstraction, func.count(func.distinct(CVEWeakness.cve_id)).label("n"))
            .select_from(CVEAffected)
            .join(CVEWeakness, CVEWeakness.cve_id == CVEAffected.cve_id)
            .join(CWE, CWE.id == CVEWeakness.cwe_id_fk)
            .where(join_col == entity_id)
            .group_by(CWE.cwe_id, CWE.name, CWE.abstraction)
            .order_by(func.count(func.distinct(CVEWeakness.cve_id)).desc())
            .limit(limit)
        )
    ).all()
    total = (
        await db.execute(select(func.count(func.distinct(CVEAffected.cve_id))).where(join_col == entity_id))
    ).scalar_one() or 0
    return [
        CWEVendorRow(
            cwe_id=cwe_id,
            name=name,
            abstraction=abstraction,
            cve_count=int(n),
            share=round(n / total, 4) if total else 0.0,
        )
        for cwe_id, name, abstraction, n in rows
    ]


@router.get("/vendors/{vendor_id}/weaknesses", response_model=list[CWEVendorRow])
async def get_vendor_weaknesses(
    vendor_id: uuid.UUID = Path(..., description="UUID of the vendor"),
    limit: int = Query(10, ge=1, le=50, description="Maximum rows"),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """A vendor's weakness mix — what this vendor keeps getting wrong.

    Covers the CVEs whose NVD CPE strings resolved to this vendor, so it is
    accurate where present and incomplete overall, the same caveat the
    Vulnerabilities tab already carries.
    """
    return await _entity_weakness_profile(db, CVEAffected.vendor_id, vendor_id, limit)


@router.get("/products/{product_id}/weaknesses", response_model=list[CWEVendorRow])
async def get_product_weaknesses(
    product_id: uuid.UUID = Path(..., description="UUID of the product"),
    limit: int = Query(10, ge=1, le=50, description="Maximum rows"),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """A product's weakness mix, derived the same way as the vendor view."""
    return await _entity_weakness_profile(db, CVEAffected.product_id, product_id, limit)


# =============================================================================
# --- Offensive Tool Routes ---
# =============================================================================


def _tool_to_response(t: Tool, entry_link: EntryTool | None = None) -> ToolResponse:
    return ToolResponse(
        id=t.id,
        name=t.name,
        aliases=t.aliases or [],
        description=t.description,
        tool_type=t.tool_type,
        platforms=t.platforms or [],
        malpedia_url=t.malpedia_url,
        github_url=t.github_url,
        detection_artifacts=t.detection_artifacts or {},
        article_count=t.article_count,
        first_seen_at=t.first_seen_at,
        last_seen_at=t.last_seen_at,
        wikipedia_url=t.wikipedia_url,
        wikipedia_image_url=t.wikipedia_image_url,
        confidence=entry_link.confidence if entry_link else None,
        matched_names=entry_link.matched_names if entry_link else None,
    )


@router.post("/entries/{entry_id}/extract-tools", response_model=ExtractionResponse[ToolResponse])
async def extract_entry_tools(
    entry_id: uuid.UUID = Path(..., description="UUID of the entry to extract from"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Run AI tool extraction on the entry and store the resulting entry-tool links.

    Returns the tools with an extraction status (success / ai_not_configured / provider_error / parse_error).
    """
    entry = await _get_entry(db, entry_id)
    entry_data = _entry_to_dict(entry)
    stored, status, error = await extract_tools(db, user.id, entry_id, entry_data)
    await db.commit()
    return ExtractionResponse(
        items=[_tool_to_response(t) for t, _ in stored],
        status=status,
        error_message=error,
    )


@router.get("/entries/{entry_id}/tools", response_model=list[ToolResponse])
async def get_entry_tools(
    entry_id: uuid.UUID = Path(..., description="UUID of the entry"),
    user: User = Depends(get_entry_viewer),
    db: AsyncSession = Depends(get_db),
):
    """List the tools linked to an entry, with per-entry confidence and matched names."""
    await _get_entry(db, entry_id)
    result = await db.execute(
        select(Tool, EntryTool)
        .join(EntryTool, EntryTool.tool_id == Tool.id)
        .where(EntryTool.entry_id == entry_id)
        .order_by(Tool.name)
    )
    return [_tool_to_response(t, link) for t, link in result.all()]


@router.get("/tools", response_model=PaginatedResponse[ToolResponse])
async def list_tools(
    search: str | None = Query(None, description="Case-insensitive match on tool name or whole-word alias"),
    tool_type: str | None = Query(None, description="Exact tool type filter (e.g. 'c2', 'credential_theft')"),
    sort_by: str = Query(
        "name",
        pattern="^(name|tool_type|article_count|first_seen_at|last_seen_at|linked_count)$",
        description="Sort column; linked_count sorts by non-rejected entity-relationship count",
    ),
    sort_order: str = Query("asc", pattern="^(asc|desc)$", description="Sort direction"),
    limit: int = Query(50, ge=1, le=500, description="Page size"),
    offset: int = Query(0, ge=0, description="Number of rows to skip"),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Paginated tool list with name/alias search, type filter, and sorting."""
    base_q = select(Tool)
    if search:
        pattern = f"%{search}%"
        alias_pattern = rf"\y{re.escape(search)}\y"
        base_q = base_q.where(
            or_(
                Tool.name.ilike(pattern),
                func.array_to_string(Tool.aliases, " ").op("~*")(alias_pattern),
            )
        )
    if tool_type:
        base_q = base_q.where(Tool.tool_type == tool_type)
    total_result = await db.execute(select(func.count()).select_from(base_q.subquery()))
    total = total_result.scalar_one()
    if sort_by == "linked_count":
        sort_expr = _linked_count_subquery(Tool, "tool")
    else:
        col = getattr(Tool, sort_by)
        sort_expr = func.lower(col) if sort_by == "name" else col
    order = sort_expr.asc() if sort_order == "asc" else sort_expr.desc()
    result = await db.execute(base_q.order_by(order).offset(offset).limit(limit))
    items = [_tool_to_response(t) for t in result.scalars()]
    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset, has_more=(offset + limit) < total)


# The :uuid converter keeps non-UUID paths (e.g. /api/tools/tools, served by the
# tools router) from being captured by this route.
@router.get("/tools/{tool_id:uuid}", response_model=ToolResponse)
async def get_tool(
    tool_id: uuid.UUID = Path(..., description="UUID of the tool"),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Get a single tool by UUID."""
    result = await db.execute(select(Tool).where(Tool.id == tool_id))
    t = result.scalar_one_or_none()
    if not t:
        raise AppError(code="not_found", message="Tool not found", status_code=404)
    return _tool_to_response(t)


# --- Vendors ---


def _vendor_to_response(v: Vendor, entry_link: EntryVendor | None = None) -> VendorResponse:
    return VendorResponse(
        id=v.id,
        name=v.name,
        aliases=v.aliases or [],
        description=v.description,
        website=v.website,
        vendor_type=v.vendor_type,
        article_count=v.article_count,
        first_seen_at=v.first_seen_at,
        last_seen_at=v.last_seen_at,
        wikipedia_url=v.wikipedia_url,
        wikipedia_image_url=v.wikipedia_image_url,
        confidence=entry_link.confidence if entry_link else None,
        source=entry_link.source if entry_link else None,
        matched_names=entry_link.matched_names if entry_link else None,
    )


@router.get("/entries/{entry_id}/vendors", response_model=list[VendorResponse])
async def get_entry_vendors(
    entry_id: uuid.UUID = Path(..., description="UUID of the entry"),
    user: User = Depends(get_entry_viewer),
    db: AsyncSession = Depends(get_db),
):
    """List the vendors linked to an entry, with per-entry confidence, source, and matched names."""
    await _get_entry(db, entry_id)
    result = await db.execute(
        select(Vendor, EntryVendor)
        .join(EntryVendor, EntryVendor.vendor_id == Vendor.id)
        .where(EntryVendor.entry_id == entry_id)
        .order_by(Vendor.name)
    )
    return [_vendor_to_response(v, link) for v, link in result.all()]


@router.get("/vendors", response_model=PaginatedResponse[VendorResponse])
async def list_vendors(
    search: str | None = Query(None, description="Case-insensitive match on vendor name or whole-word alias"),
    vendor_type: str | None = Query(None, description="Exact vendor type filter"),
    sort_by: str = Query(
        "name",
        pattern="^(name|vendor_type|article_count|first_seen_at|last_seen_at|linked_count)$",
        description="Sort column; linked_count sorts by non-rejected entity-relationship count",
    ),
    sort_order: str = Query("asc", pattern="^(asc|desc)$", description="Sort direction"),
    limit: int = Query(50, ge=1, le=500, description="Page size"),
    offset: int = Query(0, ge=0, description="Number of rows to skip"),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Paginated vendor list with name/alias search, type filter, and sorting."""
    base_q = select(Vendor)
    if search:
        pattern = f"%{search}%"
        alias_pattern = rf"\y{re.escape(search)}\y"
        base_q = base_q.where(
            or_(
                Vendor.name.ilike(pattern),
                func.array_to_string(Vendor.aliases, " ").op("~*")(alias_pattern),
            )
        )
    if vendor_type:
        base_q = base_q.where(Vendor.vendor_type == vendor_type)
    total_result = await db.execute(select(func.count()).select_from(base_q.subquery()))
    total = total_result.scalar_one()
    if sort_by == "linked_count":
        sort_expr = _linked_count_subquery(Vendor, "vendor")
    else:
        col = getattr(Vendor, sort_by)
        sort_expr = func.lower(col) if sort_by == "name" else col
    order = sort_expr.asc() if sort_order == "asc" else sort_expr.desc()
    result = await db.execute(base_q.order_by(order).offset(offset).limit(limit))
    items = [_vendor_to_response(v) for v in result.scalars()]
    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset, has_more=(offset + limit) < total)


@router.get("/vendors/{vendor_id}", response_model=VendorResponse)
async def get_vendor(
    vendor_id: uuid.UUID = Path(..., description="UUID of the vendor"),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Get a single vendor by UUID."""
    result = await db.execute(select(Vendor).where(Vendor.id == vendor_id))
    v = result.scalar_one_or_none()
    if not v:
        raise AppError(code="not_found", message="Vendor not found", status_code=404)
    return _vendor_to_response(v)


@router.get("/vendors/{vendor_id}/products", response_model=list[ProductResponse])
async def get_vendor_products(
    vendor_id: uuid.UUID = Path(..., description="UUID of the vendor"),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """List all products belonging to a vendor, sorted by name."""
    from sqlalchemy.orm import selectinload

    result = await db.execute(
        select(Product)
        .options(selectinload(Product.vendor))
        .where(Product.vendor_id == vendor_id)
        .order_by(func.lower(Product.name))
    )
    return [_product_to_response(p) for p in result.scalars()]


# --- Products ---


def _product_to_response(p: Product, entry_link: EntryProduct | None = None) -> ProductResponse:
    vendor_name = p.vendor.name if p.vendor_id and hasattr(p, "vendor") and p.vendor else None
    # A visitor's vendor load goes through the visitor filter: a vendor they
    # can't see comes back empty, and its id must not stand in for it.
    vendor_id = p.vendor_id if vendor_name is not None or not viewer_is_anonymous() else None
    return ProductResponse(
        id=p.id,
        vendor_id=vendor_id,
        vendor_name=vendor_name,
        name=p.name,
        aliases=p.aliases or [],
        description=p.description,
        product_type=p.product_type,
        website=p.website,
        support_status=p.support_status,
        next_eol=p.next_eol,
        article_count=p.article_count,
        first_seen_at=p.first_seen_at,
        last_seen_at=p.last_seen_at,
        wikipedia_url=p.wikipedia_url,
        wikipedia_image_url=p.wikipedia_image_url,
        confidence=entry_link.confidence if entry_link else None,
        source=entry_link.source if entry_link else None,
        matched_names=entry_link.matched_names if entry_link else None,
    )


@router.get("/entries/{entry_id}/products", response_model=list[ProductResponse])
async def get_entry_products(
    entry_id: uuid.UUID = Path(..., description="UUID of the entry"),
    user: User = Depends(get_entry_viewer),
    db: AsyncSession = Depends(get_db),
):
    """List the products linked to an entry, with per-entry confidence, source, and matched names."""
    await _get_entry(db, entry_id)
    result = await db.execute(
        select(Product, EntryProduct)
        .join(EntryProduct, EntryProduct.product_id == Product.id)
        .where(EntryProduct.entry_id == entry_id)
        .options(selectinload(Product.vendor))
        .order_by(Product.name)
    )
    return [_product_to_response(p, link) for p, link in result.all()]


@router.get("/products", response_model=PaginatedResponse[ProductResponse])
async def list_products(
    search: str | None = Query(None, description="Case-insensitive match on product name or whole-word alias"),
    product_type: str | None = Query(None, description="Exact product type filter"),
    vendor_id: uuid.UUID | None = Query(None, description="Only products belonging to this vendor"),
    sort_by: str = Query(
        "name",
        pattern="^(name|product_type|article_count|first_seen_at|last_seen_at|linked_count)$",
        description="Sort column; linked_count sorts by non-rejected entity-relationship count",
    ),
    sort_order: str = Query("asc", pattern="^(asc|desc)$", description="Sort direction"),
    limit: int = Query(50, ge=1, le=500, description="Page size"),
    offset: int = Query(0, ge=0, description="Number of rows to skip"),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Paginated product list with name/alias search, type and vendor filters, and sorting."""
    from sqlalchemy.orm import selectinload

    base_q = select(Product).options(selectinload(Product.vendor))
    if search:
        pattern = f"%{search}%"
        alias_pattern = rf"\y{re.escape(search)}\y"
        base_q = base_q.where(
            or_(
                Product.name.ilike(pattern),
                func.array_to_string(Product.aliases, " ").op("~*")(alias_pattern),
            )
        )
    if product_type:
        base_q = base_q.where(Product.product_type == product_type)
    if vendor_id:
        base_q = base_q.where(Product.vendor_id == vendor_id)
    total_result = await db.execute(select(func.count()).select_from(base_q.subquery()))
    total = total_result.scalar_one()
    if sort_by == "linked_count":
        sort_expr = _linked_count_subquery(Product, "product")
    else:
        col = getattr(Product, sort_by)
        sort_expr = func.lower(col) if sort_by == "name" else col
    order = sort_expr.asc() if sort_order == "asc" else sort_expr.desc()
    result = await db.execute(base_q.order_by(order).offset(offset).limit(limit))
    items = [_product_to_response(p) for p in result.scalars()]
    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset, has_more=(offset + limit) < total)


@router.get("/products/{product_id}", response_model=ProductResponse)
async def get_product(
    product_id: uuid.UUID = Path(..., description="UUID of the product"),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Get a single product by UUID, including its vendor name."""
    from sqlalchemy.orm import selectinload

    result = await db.execute(select(Product).options(selectinload(Product.vendor)).where(Product.id == product_id))
    p = result.scalar_one_or_none()
    if not p:
        raise AppError(code="not_found", message="Product not found", status_code=404)
    return _product_to_response(p)


# --- Affected CVEs (authoritative NVD CPE links via cve_affected) ---

_EXPLOITED_STATUSES = ("weaponized", "active_exploitation")


def _affected_published_expr():
    """Published timestamp for sorting: NVD published date, else first_seen."""
    return func.coalesce(
        CVE.nvd_data.op("->>")("published"),
        func.to_char(CVE.first_seen_at, 'YYYY-MM-DD"T"HH24:MI:SS'),
    )


def _affected_cve_filters(query, severity: str | None, kev: bool, exploited: bool):
    if severity:
        wanted = [s.strip().upper() for s in severity.split(",") if s.strip()]
        if wanted:
            query = query.where(func.upper(func.coalesce(CVE.severity, "")).in_(wanted))
    if kev:
        query = query.where(CVE.is_kev.is_(True))
    if exploited:
        query = query.where(CVE.exploit_availability.in_(_EXPLOITED_STATUSES))
    return query


def _affected_cve_sort(query, sort: str):
    if sort == "epss":
        return query.order_by(CVE.epss_score.desc().nulls_last(), CVE.cve_id.desc())
    if sort == "recent":
        return query.order_by(_affected_published_expr().desc(), CVE.cve_id.desc())
    return query.order_by(CVE.cvss_score.desc().nulls_last(), CVE.cve_id.desc())


def _affected_item(cve: CVE, *, products: list[AffectedProductRef], vendor_level: bool) -> AffectedCVEItem:
    published = (cve.nvd_data or {}).get("published") or (cve.first_seen_at.isoformat() if cve.first_seen_at else None)
    return AffectedCVEItem(
        id=cve.id,
        cve_id=cve.cve_id,
        severity=cve.severity,
        cvss_score=cve.cvss_score,
        epss_score=cve.epss_score,
        is_kev=bool(cve.is_kev),
        exploited=cve.exploit_availability in _EXPLOITED_STATUSES,
        description=cve.description,
        published_at=published,
        vendor_level=vendor_level,
        products=products,
    )


async def _affected_cve_counts(db: AsyncSession, cve_ids_subq) -> AffectedCVECounts:
    sev_expr = func.upper(func.coalesce(CVE.severity, "UNKNOWN"))
    severity_rows = (
        await db.execute(select(sev_expr, func.count()).where(CVE.id.in_(cve_ids_subq)).group_by(sev_expr))
    ).all()
    flags = (
        await db.execute(
            select(
                func.count().filter(CVE.is_kev.is_(True)),
                func.count().filter(CVE.exploit_availability.in_(_EXPLOITED_STATUSES)),
            ).where(CVE.id.in_(cve_ids_subq))
        )
    ).one()
    return AffectedCVECounts(
        severity={sev: cnt for sev, cnt in severity_rows},
        kev=flags[0] or 0,
        exploited=flags[1] or 0,
    )


@router.get("/products/{product_id}/affected-cves", response_model=AffectedCVEsResponse)
async def get_product_affected_cves(
    product_id: uuid.UUID = Path(..., description="UUID of the product"),
    severity: str | None = Query(None, description="Comma-separated severities"),
    kev: bool = Query(False, description="Only CVEs in the CISA KEV catalog"),
    exploited: bool = Query(False, description="Only CVEs with weaponized or actively exploited status"),
    sort: str = Query("cvss", pattern="^(cvss|epss|recent)$", description="Sort by CVSS, EPSS, or published date"),
    limit: int = Query(50, ge=1, le=200, description="Page size"),
    offset: int = Query(0, ge=0, description="Number of rows to skip"),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """CVEs affecting a product per authoritative NVD CPE links, with version ranges and severity/KEV counts."""
    product = (await db.execute(select(Product).where(Product.id == product_id))).scalar_one_or_none()
    if not product:
        raise AppError(code="not_found", message="Product not found", status_code=404)

    cve_ids_subq = select(CVEAffected.cve_id).where(CVEAffected.product_id == product_id).distinct()
    base = _affected_cve_filters(select(CVE).where(CVE.id.in_(cve_ids_subq)), severity, kev, exploited)
    total = (await db.execute(select(func.count()).select_from(base.subquery()))).scalar_one()
    page = (await db.execute(_affected_cve_sort(base, sort).offset(offset).limit(limit))).scalars().all()

    link_rows = (
        await db.execute(
            select(CVEAffected).where(
                CVEAffected.product_id == product_id,
                CVEAffected.cve_id.in_([c.id for c in page] or [uuid.UUID(int=0)]),
            )
        )
    ).scalars()
    versions: dict[uuid.UUID, CVEAffected] = {row.cve_id: row for row in link_rows}

    items = []
    for cve in page:
        link = versions.get(cve.id)
        ref = AffectedProductRef(
            id=product.id,
            name=product.name,
            cpe_product=link.cpe_product if link else "",
            version_start=link.version_start if link else None,
            version_end=link.version_end if link else None,
        )
        items.append(_affected_item(cve, products=[ref], vendor_level=False))

    counts = await _affected_cve_counts(db, cve_ids_subq)
    return AffectedCVEsResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
        has_more=(offset + limit) < total,
        counts=counts,
    )


@router.get("/cwes/{cwe_id}/affected-cves", response_model=AffectedCVEsResponse)
async def get_cwe_affected_cves(
    cwe_id: str = Path(..., description="CWE UUID or catalog id (e.g. CWE-416)"),
    include_descendants: bool = Query(
        True,
        description=(
            "Include CVEs tagged with any weakness below this one on the abstraction ladder. "
            "On by default so the list matches the profile's headline count — NVD tags a CVE "
            "wherever the assigning analyst chose, so a Class's direct list is near-empty."
        ),
    ),
    severity: str | None = Query(None, description="Comma-separated severities"),
    kev: bool = Query(False, description="Only CVEs in the CISA KEV catalog"),
    exploited: bool = Query(False, description="Only CVEs with weaponized or actively exploited status"),
    sort: str = Query("cvss", pattern="^(cvss|epss|recent)$", description="Sort by CVSS, EPSS, or published date"),
    limit: int = Query(50, ge=1, le=200, description="Page size"),
    offset: int = Query(0, ge=0, description="Number of rows to skip"),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """CVEs carrying this weakness per the NVD weakness block, with severity/KEV counts.

    The CWE analogue of /vendors/{id}/affected-cves, reusing the same filters,
    sort, counts and response shape — `matched_cwe` says which descendant
    actually matched when the subtree is included.
    """
    cwe = await _load_cwe(db, cwe_id)

    if include_descendants:
        subtree = sa_text(
            """
            WITH RECURSIVE descendants AS (
                SELECT id, cwe_id FROM cwes WHERE id = :root
                UNION ALL
                SELECT c.id, c.cwe_id
                FROM cwes c JOIN descendants d ON c.parent_cwe_id = d.cwe_id
            )
            SELECT id FROM descendants
            """
        )
        cwe_pks = [row[0] for row in (await db.execute(subtree, {"root": cwe.id})).all()]
    else:
        cwe_pks = [cwe.id]

    cve_ids_subq = select(CVEWeakness.cve_id).where(CVEWeakness.cwe_id_fk.in_(cwe_pks)).distinct()
    base = _affected_cve_filters(select(CVE).where(CVE.id.in_(cve_ids_subq)), severity, kev, exploited)
    total = (await db.execute(select(func.count()).select_from(base.subquery()))).scalar_one()
    page = (await db.execute(_affected_cve_sort(base, sort).offset(offset).limit(limit))).scalars().all()
    page_ids = [c.id for c in page] or [uuid.UUID(int=0)]

    # Which weakness each row actually matched. Primary wins when a CVE carries
    # several from this subtree, which is the one the analyst would name.
    matched_rows = (
        await db.execute(
            select(CVEWeakness.cve_id, CWE.cwe_id, CWE.name)
            .join(CWE, CWE.id == CVEWeakness.cwe_id_fk)
            .where(CVEWeakness.cwe_id_fk.in_(cwe_pks), CVEWeakness.cve_id.in_(page_ids))
            .order_by(CVEWeakness.cve_id, CVEWeakness.is_primary.desc())
        )
    ).all()
    matched: dict[uuid.UUID, tuple[str, str]] = {}
    for cve_pk, ref, name in matched_rows:
        matched.setdefault(cve_pk, (ref, name))

    # Affected products for context, same as the vendor list shows.
    product_rows = (
        await db.execute(
            select(CVEAffected.cve_id, CVEAffected.product_id, Product.name, CVEAffected.cpe_product)
            .outerjoin(Product, Product.id == CVEAffected.product_id)
            .where(CVEAffected.cve_id.in_(page_ids), CVEAffected.product_id.isnot(None))
        )
    ).all()
    by_cve: dict[uuid.UUID, list[AffectedProductRef]] = {}
    for cve_pk, product_id, product_name, cpe_product in product_rows:
        refs = by_cve.setdefault(cve_pk, [])
        if len(refs) < 4 and not any(r.id == product_id for r in refs):
            refs.append(
                AffectedProductRef(
                    id=product_id,
                    name=product_name,
                    cpe_product=cpe_product,
                    version_start=None,
                    version_end=None,
                )
            )

    items = []
    for cve in page:
        hit = matched.get(cve.id)
        item = _affected_item(cve, products=by_cve.get(cve.id, []), vendor_level=False)
        if hit:
            item.matched_cwe, item.matched_cwe_name = hit
        items.append(item)

    counts = await _affected_cve_counts(db, cve_ids_subq)
    return AffectedCVEsResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
        has_more=(offset + limit) < total,
        counts=counts,
        subtree_size=len(cwe_pks),
    )


@router.get("/vendors/{vendor_id}/affected-cves", response_model=AffectedCVEsResponse)
async def get_vendor_affected_cves(
    vendor_id: uuid.UUID = Path(..., description="UUID of the vendor"),
    severity: str | None = Query(None, description="Comma-separated severities"),
    kev: bool = Query(False, description="Only CVEs in the CISA KEV catalog"),
    exploited: bool = Query(False, description="Only CVEs with weaponized or actively exploited status"),
    product_id: uuid.UUID | None = Query(None, description="Restrict to one of this vendor's products"),
    vendor_level: bool = Query(False, description="Only CVEs with no resolved product under this vendor"),
    sort: str = Query("cvss", pattern="^(cvss|epss|recent)$", description="Sort by CVSS, EPSS, or published date"),
    limit: int = Query(50, ge=1, le=200, description="Page size"),
    offset: int = Query(0, ge=0, description="Number of rows to skip"),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Vendor rollup: CVEs affecting the vendor directly plus any of its products."""
    vendor = (await db.execute(select(Vendor).where(Vendor.id == vendor_id))).scalar_one_or_none()
    if not vendor:
        raise AppError(code="not_found", message="Vendor not found", status_code=404)

    vendor_products = select(Product.id).where(Product.vendor_id == vendor_id).scalar_subquery()
    rollup_pred = or_(CVEAffected.vendor_id == vendor_id, CVEAffected.product_id.in_(vendor_products))
    cve_ids_subq = select(CVEAffected.cve_id).where(rollup_pred).distinct()
    badge_ids_subq = select(CVEAffected.cve_id).where(CVEAffected.product_id.in_(vendor_products)).distinct()

    base = select(CVE).where(CVE.id.in_(cve_ids_subq))
    if product_id is not None:
        base = base.where(CVE.id.in_(select(CVEAffected.cve_id).where(CVEAffected.product_id == product_id).distinct()))
    if vendor_level:
        base = base.where(CVE.id.notin_(badge_ids_subq))
    base = _affected_cve_filters(base, severity, kev, exploited)
    total = (await db.execute(select(func.count()).select_from(base.subquery()))).scalar_one()
    page = (await db.execute(_affected_cve_sort(base, sort).offset(offset).limit(limit))).scalars().all()

    page_ids = [c.id for c in page] or [uuid.UUID(int=0)]
    badge_rows = (
        await db.execute(
            select(CVEAffected, Product.name)
            .join(Product, Product.id == CVEAffected.product_id)
            .where(CVEAffected.cve_id.in_(page_ids), CVEAffected.product_id.in_(vendor_products))
        )
    ).all()
    products_by_cve: dict[uuid.UUID, list[AffectedProductRef]] = {}
    for link, product_name in badge_rows:
        products_by_cve.setdefault(link.cve_id, []).append(
            AffectedProductRef(
                id=link.product_id,
                name=product_name,
                cpe_product=link.cpe_product,
                version_start=link.version_start,
                version_end=link.version_end,
            )
        )

    items = [
        _affected_item(cve, products=products_by_cve.get(cve.id, []), vendor_level=cve.id not in products_by_cve)
        for cve in page
    ]

    counts = await _affected_cve_counts(db, cve_ids_subq)
    by_product_rows = (
        await db.execute(
            select(Product.id, Product.name, func.count(func.distinct(CVEAffected.cve_id)))
            .join(CVEAffected, CVEAffected.product_id == Product.id)
            .where(Product.vendor_id == vendor_id)
            .group_by(Product.id, Product.name)
            .order_by(func.count(func.distinct(CVEAffected.cve_id)).desc())
        )
    ).all()
    total_distinct = (await db.execute(select(func.count()).select_from(cve_ids_subq.subquery()))).scalar_one()
    badge_distinct = (await db.execute(select(func.count()).select_from(badge_ids_subq.subquery()))).scalar_one()

    return AffectedCVEsResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
        has_more=(offset + limit) < total,
        counts=counts,
        by_product=[AffectedByProduct(id=pid, name=name, count=cnt) for pid, name, cnt in by_product_rows],
        vendor_level_count=max(total_distinct - badge_distinct, 0),
    )


@router.get("/cves/{cve_id}/affected", response_model=list[CVEAffectedEntityRow])
async def get_cve_affected(
    cve_id: str = Path(..., description="CVE UUID or CVE identifier string (e.g. CVE-2024-3400)"),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Parsed CPE pairs for a CVE with entity resolution — feeds the profile's Affected panel."""
    try:
        uid = uuid.UUID(cve_id)
        cve = (await db.execute(select(CVE).where(CVE.id == uid))).scalar_one_or_none()
    except ValueError:
        cve = (await db.execute(select(CVE).where(CVE.cve_id == cve_id))).scalar_one_or_none()
    if not cve:
        raise AppError(code="not_found", message="CVE not found", status_code=404)

    rows = (
        await db.execute(
            select(CVEAffected, Vendor.name, Product.name)
            .outerjoin(Vendor, Vendor.id == CVEAffected.vendor_id)
            .outerjoin(Product, Product.id == CVEAffected.product_id)
            .where(CVEAffected.cve_id == cve.id)
            .order_by(CVEAffected.cpe_vendor, CVEAffected.cpe_product)
        )
    ).all()
    return [
        CVEAffectedEntityRow(
            cpe_vendor=link.cpe_vendor,
            cpe_product=link.cpe_product,
            vendor_id=link.vendor_id,
            vendor_name=vendor_name,
            product_id=link.product_id,
            product_name=product_name,
            version_start=link.version_start,
            version_end=link.version_end,
        )
        for link, vendor_name, product_name in rows
    ]


class ResolveEntityNamesRequest(BaseModel):
    ttps: list[uuid.UUID] = []
    cves: list[uuid.UUID] = []
    actors: list[uuid.UUID] = []
    malware: list[uuid.UUID] = []
    countries: list[uuid.UUID] = []

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "actors": ["d5b2f1a0-3c4e-4b6d-9a8f-1e2d3c4b5a69"],
                "cves": ["a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"],
            }
        }
    )


@router.post("/intelligence/resolve-names")
async def resolve_entity_names(
    body: ResolveEntityNamesRequest,
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Resolve entity UUIDs to {id, name} for display in reports."""
    result: dict[str, list[dict]] = {}

    if body.ttps:
        rows = await db.execute(select(TTP.id, TTP.technique_name, TTP.technique_id).where(TTP.id.in_(body.ttps)))
        result["ttps"] = [
            {"id": str(r.id), "name": f"{r.technique_id} {r.technique_name}" if r.technique_id else r.technique_name}
            for r in rows.all()
        ]

    if body.cves:
        rows = await db.execute(select(CVE.id, CVE.cve_id, CVE.description).where(CVE.id.in_(body.cves)))
        result["cves"] = [{"id": str(r.id), "name": r.cve_id} for r in rows.all()]

    if body.actors:
        rows = await db.execute(select(ThreatActor.id, ThreatActor.name).where(ThreatActor.id.in_(body.actors)))
        result["actors"] = [{"id": str(r.id), "name": r.name} for r in rows.all()]

    if body.malware:
        rows = await db.execute(select(MalwareFamily.id, MalwareFamily.name).where(MalwareFamily.id.in_(body.malware)))
        result["malware"] = [{"id": str(r.id), "name": r.name} for r in rows.all()]

    if body.countries:
        rows = await db.execute(select(Country.id, Country.name).where(Country.id.in_(body.countries)))
        result["countries"] = [{"id": str(r.id), "name": r.name} for r in rows.all()]

    return result
