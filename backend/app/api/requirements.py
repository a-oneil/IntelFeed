"""Intelligence Requirements (PIR) API routes."""

import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Body, Depends, Path, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.exceptions import AppError
from app.core.pagination import PaginatedResponse
from app.core.security import get_current_user
from app.database import get_db
from app.models.cve import CVE, EntryCVE
from app.models.entry import Entry
from app.models.intel_report import IntelReport
from app.models.intelligence_requirement import IntelligenceRequirement, RequirementMatch
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.ttp import TTP, EntryTTP
from app.models.user import User
from app.schemas.intelligence_requirement import (
    RequirementCoverageBrief,
    RequirementCoverageSummary,
    RequirementCreate,
    RequirementFulfillRequest,
    RequirementManualMatchRequest,
    RequirementMatchResponse,
    RequirementResponse,
    RequirementUpdate,
)

router = APIRouter()


def _serialize_linked_entities(linked: dict | None) -> dict:
    """Normalize linked_entities to JSON-safe {key: [{"id": str, "name": str}]}."""
    if not linked:
        return {}
    return {
        key: [
            {
                "id": str(ref["id"] if isinstance(ref, dict) else ref.id),
                "name": ref["name"] if isinstance(ref, dict) else ref.name,
            }
            for ref in refs
        ]
        for key, refs in linked.items()
    }


@router.get("", response_model=PaginatedResponse[RequirementResponse])
async def list_requirements(
    status: str | None = Query(None, description="Filter by status (active, fulfilled, expired, draft)."),
    priority: str | None = Query(None, description="Filter by priority (critical, high, medium, low)."),
    category: str | None = Query(None, description="Filter by category (strategic, operational, tactical, technical)."),
    limit: int = Query(50, ge=1, le=500, description="Maximum number of requirements to return."),
    offset: int = Query(0, ge=0, description="Number of requirements to skip for pagination."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List intelligence requirements (PIRs) ordered by most recently updated."""
    query = select(IntelligenceRequirement)
    count_q = select(func.count()).select_from(IntelligenceRequirement)

    if status:
        query = query.where(IntelligenceRequirement.status == status)
        count_q = count_q.where(IntelligenceRequirement.status == status)
    if priority:
        query = query.where(IntelligenceRequirement.priority == priority)
        count_q = count_q.where(IntelligenceRequirement.priority == priority)
    if category:
        query = query.where(IntelligenceRequirement.category == category)
        count_q = count_q.where(IntelligenceRequirement.category == category)

    total = (await db.execute(count_q)).scalar() or 0
    result = await db.execute(query.order_by(IntelligenceRequirement.updated_at.desc()).limit(limit).offset(offset))
    items = [RequirementResponse.model_validate(r) for r in result.scalars().all()]
    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset, has_more=(offset + limit) < total)


@router.get("/coverage", response_model=RequirementCoverageSummary)
async def get_coverage_summary(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Coverage summary: counts by status, priority, category, and staleness."""
    result = await db.execute(select(IntelligenceRequirement))
    reqs = result.scalars().all()

    by_status = {"active": 0, "fulfilled": 0, "expired": 0, "draft": 0}
    by_priority = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    by_category = {"strategic": 0, "operational": 0, "tactical": 0, "technical": 0}
    with_recent_matches = 0
    stale = 0
    needs_review: list[RequirementCoverageBrief] = []
    now = datetime.now(UTC)
    stale_threshold = now - timedelta(days=30)
    review_threshold = now - timedelta(days=90)

    def _brief(req: IntelligenceRequirement) -> RequirementCoverageBrief:
        return RequirementCoverageBrief(
            id=req.id,
            title=req.title,
            priority=req.priority,
            status=req.status,
            match_count=req.match_count,
            last_matched_at=req.last_matched_at,
            linked_feeds=len(req.linked_feed_ids) if req.linked_feed_ids else 0,
        )

    for req in reqs:
        by_status[req.status] = by_status.get(req.status, 0) + 1
        by_priority[req.priority] = by_priority.get(req.priority, 0) + 1
        by_category[req.category] = by_category.get(req.category, 0) + 1
        if req.last_matched_at and req.last_matched_at > stale_threshold:
            with_recent_matches += 1
        if req.status == "active":
            # Stale: no new matches in 30 days, or past its expiry date
            no_recent_matches = not req.last_matched_at or req.last_matched_at <= stale_threshold
            past_expiry = req.expires_at is not None and req.expires_at < now
            if no_recent_matches or past_expiry:
                stale += 1
            # Review reminder: not touched in 90 days
            if req.updated_at and req.updated_at <= review_threshold:
                needs_review.append(_brief(req))

    requirements = [_brief(req) for req in reqs]

    return RequirementCoverageSummary(
        total_requirements=len(reqs),
        active=by_status.get("active", 0),
        fulfilled=by_status.get("fulfilled", 0),
        expired=by_status.get("expired", 0),
        draft=by_status.get("draft", 0),
        by_priority=by_priority,
        by_category=by_category,
        with_recent_matches=with_recent_matches,
        stale=stale,
        needs_review=needs_review,
        requirements=requirements,
    )


@router.post("", response_model=RequirementResponse, status_code=201)
async def create_requirement(
    body: RequirementCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create an intelligence requirement with keywords, linked feeds, and linked entities used for entry matching."""
    requirement = IntelligenceRequirement(
        created_by=user.id,
        title=body.title,
        description=body.description,
        priority=body.priority,
        status=body.status,
        category=body.category,
        keywords=body.keywords,
        linked_feed_ids=body.linked_feed_ids,
        linked_entities=_serialize_linked_entities(body.linked_entities),
        min_relevance=body.min_relevance,
        auto_match=body.auto_match,
        expires_at=body.expires_at,
    )
    db.add(requirement)
    await db.flush()
    await db.refresh(requirement)
    return RequirementResponse.model_validate(requirement)


@router.get("/{requirement_id}", response_model=RequirementResponse)
async def get_requirement(
    requirement_id: uuid.UUID = Path(..., description="Intelligence requirement UUID."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get a single intelligence requirement."""
    requirement = await db.get(IntelligenceRequirement, requirement_id)
    if not requirement:
        raise AppError(code="not_found", message="Requirement not found", status_code=404)
    return RequirementResponse.model_validate(requirement)


@router.patch("/{requirement_id}", response_model=RequirementResponse)
async def update_requirement(
    requirement_id: uuid.UUID = Path(..., description="Intelligence requirement UUID."),
    body: RequirementUpdate = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Partially update a requirement. Removing keywords or linked entities also deletes their existing matches
    and decrements the match count."""
    requirement = await db.get(IntelligenceRequirement, requirement_id)
    if not requirement:
        raise AppError(code="not_found", message="Requirement not found", status_code=404)

    update_data = body.model_dump(exclude_unset=True)

    # If keywords are being updated, remove matches for removed keywords
    if "keywords" in update_data:
        old_keywords = set(k.lower() for k in (requirement.keywords or []))
        new_keywords = set(k.lower() for k in (update_data["keywords"] or []))
        removed_keywords = old_keywords - new_keywords

        if removed_keywords:
            # Find and delete matches that were matched on removed keywords
            stale_matches = await db.execute(
                select(RequirementMatch).where(
                    RequirementMatch.requirement_id == requirement_id,
                    RequirementMatch.match_type == "keyword",
                    func.lower(RequirementMatch.matched_on).in_(removed_keywords),
                )
            )
            deleted_count = 0
            for match in stale_matches.scalars().all():
                await db.delete(match)
                deleted_count += 1

            if deleted_count > 0:
                requirement.match_count = max(0, requirement.match_count - deleted_count)

    # If linked entities are being updated, remove matches for removed entities
    if "linked_entities" in update_data:
        update_data["linked_entities"] = _serialize_linked_entities(update_data["linked_entities"])
        old_names = {
            ref["name"].lower()
            for refs in (requirement.linked_entities or {}).values()
            for ref in refs
            if ref.get("name")
        }
        new_names = {ref["name"].lower() for refs in update_data["linked_entities"].values() for ref in refs}
        removed_names = old_names - new_names

        if removed_names:
            stale_entity_matches = await db.execute(
                select(RequirementMatch).where(
                    RequirementMatch.requirement_id == requirement_id,
                    RequirementMatch.match_type == "entity",
                    func.lower(RequirementMatch.matched_on).in_(removed_names),
                )
            )
            deleted_count = 0
            for match in stale_entity_matches.scalars().all():
                await db.delete(match)
                deleted_count += 1

            if deleted_count > 0:
                requirement.match_count = max(0, requirement.match_count - deleted_count)

    for field, value in update_data.items():
        setattr(requirement, field, value)

    db.add(requirement)
    await db.flush()
    await db.refresh(requirement)
    return RequirementResponse.model_validate(requirement)


@router.delete("/{requirement_id}", status_code=204)
async def delete_requirement(
    requirement_id: uuid.UUID = Path(..., description="Intelligence requirement UUID."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete a requirement and its entry matches."""
    result = await db.execute(
        select(IntelligenceRequirement)
        .where(IntelligenceRequirement.id == requirement_id)
        .options(selectinload(IntelligenceRequirement.matches))
    )
    requirement = result.scalar_one_or_none()
    if not requirement:
        raise AppError(code="not_found", message="Requirement not found", status_code=404)
    await db.delete(requirement)
    await db.flush()


@router.get("/{requirement_id}/matches", response_model=PaginatedResponse[RequirementMatchResponse])
async def get_requirement_matches(
    requirement_id: uuid.UUID = Path(..., description="Intelligence requirement UUID."),
    limit: int = Query(50, ge=1, le=500, description="Maximum number of matches to return."),
    offset: int = Query(0, ge=0, description="Number of matches to skip for pagination."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List entries matched to a requirement (keyword, entity, and manual matches), newest first."""
    requirement = await db.get(IntelligenceRequirement, requirement_id)
    if not requirement:
        raise AppError(code="not_found", message="Requirement not found", status_code=404)

    count_q = (
        select(func.count()).select_from(RequirementMatch).where(RequirementMatch.requirement_id == requirement_id)
    )
    total = (await db.execute(count_q)).scalar() or 0

    result = await db.execute(
        select(RequirementMatch, Entry.title, Entry.url, Entry.published_at)
        .join(Entry, Entry.id == RequirementMatch.entry_id, isouter=True)
        .where(RequirementMatch.requirement_id == requirement_id)
        .order_by(RequirementMatch.matched_at.desc())
        .limit(limit)
        .offset(offset)
    )

    items = []
    for match, entry_title, entry_url, entry_published_at in result.all():
        items.append(
            RequirementMatchResponse(
                requirement_id=match.requirement_id,
                entry_id=match.entry_id,
                match_type=match.match_type,
                matched_on=match.matched_on,
                matched_at=match.matched_at,
                relevance=match.relevance,
                entry_title=entry_title,
                entry_url=entry_url,
                entry_published_at=entry_published_at,
            )
        )

    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset, has_more=(offset + limit) < total)


@router.post("/{requirement_id}/match", status_code=201)
async def manual_match(
    requirement_id: uuid.UUID = Path(..., description="Intelligence requirement UUID."),
    body: RequirementManualMatchRequest = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Manually match an entry to a requirement."""
    requirement = await db.get(IntelligenceRequirement, requirement_id)
    if not requirement:
        raise AppError(code="not_found", message="Requirement not found", status_code=404)

    # Check entry exists
    entry = await db.get(Entry, body.entry_id)
    if not entry:
        raise AppError(code="not_found", message="Entry not found", status_code=404)

    # Check for existing match
    existing = await db.execute(
        select(RequirementMatch).where(
            RequirementMatch.requirement_id == requirement_id,
            RequirementMatch.entry_id == body.entry_id,
        )
    )
    if existing.scalar_one_or_none():
        raise AppError(code="conflict", message="Entry already matched to this requirement", status_code=409)

    match = RequirementMatch(
        requirement_id=requirement_id,
        entry_id=body.entry_id,
        match_type="manual",
        matched_on="Manually matched by analyst",
        relevance=body.relevance,
    )
    db.add(match)
    requirement.match_count += 1
    requirement.last_matched_at = datetime.now(UTC)
    await db.flush()
    return {"status": "matched"}


@router.post("/{requirement_id}/fulfill", response_model=RequirementResponse)
async def fulfill_requirement(
    requirement_id: uuid.UUID = Path(..., description="Intelligence requirement UUID."),
    body: RequirementFulfillRequest = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Mark a requirement fulfilled, optionally linking the report that fulfilled it."""
    requirement = await db.get(IntelligenceRequirement, requirement_id)
    if not requirement:
        raise AppError(code="not_found", message="Requirement not found", status_code=404)

    if body.report_id:
        report = await db.get(IntelReport, body.report_id)
        if not report:
            raise AppError(code="not_found", message="Report not found", status_code=404)

    requirement.status = "fulfilled"
    requirement.fulfilled_by_report_id = body.report_id
    db.add(requirement)
    await db.flush()
    await db.refresh(requirement)
    return RequirementResponse.model_validate(requirement)


@router.get("/{requirement_id}/entities")
async def get_requirement_entities(
    requirement_id: uuid.UUID = Path(..., description="Intelligence requirement UUID."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Entities extracted from entries matched to this requirement."""
    requirement = await db.get(IntelligenceRequirement, requirement_id)
    if not requirement:
        raise AppError(code="not_found", message="Requirement not found", status_code=404)

    # Get all matched entry IDs
    match_result = await db.execute(
        select(RequirementMatch.entry_id).where(RequirementMatch.requirement_id == requirement_id)
    )
    entry_ids = [row[0] for row in match_result.all()]
    if not entry_ids:
        return {"ttps": [], "cves": [], "threat_actors": [], "malware": []}

    # Query entities linked to matched entries
    ttp_result = await db.execute(
        select(TTP).join(EntryTTP, EntryTTP.ttp_id == TTP.id).where(EntryTTP.entry_id.in_(entry_ids)).distinct()
    )
    cve_result = await db.execute(
        select(CVE).join(EntryCVE, EntryCVE.cve_id == CVE.id).where(EntryCVE.entry_id.in_(entry_ids)).distinct()
    )
    actor_result = await db.execute(
        select(ThreatActor)
        .join(EntryThreatActor, EntryThreatActor.threat_actor_id == ThreatActor.id)
        .where(EntryThreatActor.entry_id.in_(entry_ids))
        .distinct()
    )
    malware_result = await db.execute(
        select(MalwareFamily)
        .join(EntryMalware, EntryMalware.malware_id == MalwareFamily.id)
        .where(EntryMalware.entry_id.in_(entry_ids))
        .distinct()
    )

    return {
        "ttps": [
            {"id": str(t.id), "technique_id": t.technique_id, "name": t.name, "tactic": t.tactic}
            for t in ttp_result.scalars().all()
        ],
        "cves": [
            {"id": str(c.id), "cve_id": c.cve_id, "description": c.description, "cvss_score": c.cvss_score}
            for c in cve_result.scalars().all()
        ],
        "threat_actors": [
            {"id": str(a.id), "name": a.name, "aliases": a.aliases} for a in actor_result.scalars().all()
        ],
        "malware": [{"id": str(m.id), "name": m.name, "type": m.malware_type} for m in malware_result.scalars().all()],
    }


@router.delete("/{requirement_id}/matches/{entry_id}", status_code=204)
async def remove_match(
    requirement_id: uuid.UUID = Path(..., description="Intelligence requirement UUID."),
    entry_id: uuid.UUID = Path(..., description="Entry UUID of the match to remove."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Remove a matched entry from a requirement and decrement its match count."""
    requirement = await db.get(IntelligenceRequirement, requirement_id)
    if not requirement:
        raise AppError(code="not_found", message="Requirement not found", status_code=404)

    result = await db.execute(
        select(RequirementMatch).where(
            RequirementMatch.requirement_id == requirement_id,
            RequirementMatch.entry_id == entry_id,
        )
    )
    match = result.scalar_one_or_none()
    if not match:
        raise AppError(code="not_found", message="Match not found", status_code=404)

    # Decrement match count
    requirement = await db.get(IntelligenceRequirement, requirement_id)
    if requirement and requirement.match_count > 0:
        requirement.match_count -= 1

    await db.delete(match)
    await db.flush()
