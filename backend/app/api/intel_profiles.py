"""Intel profiles — named, reusable report scopes (regions × verticals).

Profiles are instance-shared objects like feeds: any signed-in analyst can
read and use them; editing follows the author-or-admin rule.
"""

import uuid

from fastapi import APIRouter, Body, Depends, Path, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppError
from app.core.pagination import PaginatedResponse
from app.core.security import get_current_user
from app.database import get_db
from app.intelligence.sectors import normalize_sector, sector_label
from app.intelligence.threat_surface import build_threat_surface
from app.models.country import Country
from app.models.intel_profile import IntelProfile
from app.models.user import User
from app.schemas.intel_profile import (
    IntelProfileCreate,
    IntelProfileResponse,
    IntelProfileUpdate,
    ThreatSurfaceRequest,
)

router = APIRouter()


def _normalize_sectors(raw: list[str]) -> list[str]:
    seen: list[str] = []
    for value in raw:
        slug = normalize_sector(value)
        if slug and slug not in seen:
            seen.append(slug)
    return seen


async def _to_response(db: AsyncSession, profile: IntelProfile) -> IntelProfileResponse:
    resp = IntelProfileResponse.model_validate(profile)
    if profile.country_ids:
        rows = await db.execute(select(Country.id, Country.name).where(Country.id.in_(profile.country_ids)))
        resp.countries = [{"id": str(cid), "name": name} for cid, name in rows.all()]
    resp.sector_labels = [sector_label(s) for s in profile.sectors or []]
    return resp


def _require_author_or_admin(profile: IntelProfile, user: User) -> None:
    if user.role != "admin" and profile.created_by is not None and profile.created_by != user.id:
        raise AppError(code="forbidden", message="Only the profile's author or an admin can modify it", status_code=403)


@router.get("", response_model=PaginatedResponse[IntelProfileResponse])
async def list_intel_profiles(
    limit: int = Query(50, ge=1, le=200, description="Maximum number of profiles to return."),
    offset: int = Query(0, ge=0, description="Number of profiles to skip for pagination."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List intel profiles (instance-shared), alphabetical."""
    total = (await db.execute(select(func.count()).select_from(IntelProfile))).scalar() or 0
    rows = await db.execute(select(IntelProfile).order_by(IntelProfile.name).limit(limit).offset(offset))
    items = [await _to_response(db, p) for p in rows.scalars().all()]
    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset, has_more=(offset + limit) < total)


@router.post("", response_model=IntelProfileResponse, status_code=201)
async def create_intel_profile(
    body: IntelProfileCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create an intel profile. Sector values are normalized to canonical slugs."""
    existing = (
        (await db.execute(select(IntelProfile).where(func.lower(IntelProfile.name) == body.name.lower())))
        .scalars()
        .first()
    )
    if existing:
        raise AppError(code="duplicate", message="A profile with this name already exists", status_code=409)

    profile = IntelProfile(
        name=body.name,
        description=body.description,
        country_ids=body.country_ids,
        sectors=_normalize_sectors(body.sectors),
        window_days=body.window_days,
        created_by=user.id,
    )
    db.add(profile)
    await db.flush()
    await db.refresh(profile)
    return await _to_response(db, profile)


@router.get("/sector-vocabulary")
async def list_sector_vocabulary(user: User = Depends(get_current_user)):
    """The closed sector vocabulary as [{slug, label}], for scope pickers."""
    from app.intelligence.sectors import CANONICAL_SECTORS

    return [{"slug": slug, "label": label} for slug, label in CANONICAL_SECTORS.items()]


@router.get("/{profile_id}", response_model=IntelProfileResponse)
async def get_intel_profile(
    profile_id: uuid.UUID = Path(..., description="Intel profile UUID."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Fetch one intel profile with resolved country names and sector labels."""
    profile = await db.get(IntelProfile, profile_id)
    if not profile:
        raise AppError(code="not_found", message="Intel profile not found", status_code=404)
    return await _to_response(db, profile)


@router.put("/{profile_id}", response_model=IntelProfileResponse)
async def update_intel_profile(
    profile_id: uuid.UUID = Path(..., description="Intel profile UUID."),
    body: IntelProfileUpdate = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update a profile's scope (author or admin only)."""
    profile = await db.get(IntelProfile, profile_id)
    if not profile:
        raise AppError(code="not_found", message="Intel profile not found", status_code=404)
    _require_author_or_admin(profile, user)

    if body.name is not None:
        profile.name = body.name
    if body.description is not None:
        profile.description = body.description
    if body.country_ids is not None:
        profile.country_ids = body.country_ids
    if body.sectors is not None:
        profile.sectors = _normalize_sectors(body.sectors)
    if body.window_days is not None:
        profile.window_days = body.window_days

    db.add(profile)
    await db.flush()
    await db.refresh(profile)
    return await _to_response(db, profile)


@router.delete("/{profile_id}", status_code=204)
async def delete_intel_profile(
    profile_id: uuid.UUID = Path(..., description="Intel profile UUID."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete a profile (author or admin only). Reports built from it keep their frozen scope."""
    profile = await db.get(IntelProfile, profile_id)
    if not profile:
        raise AppError(code="not_found", message="Intel profile not found", status_code=404)
    _require_author_or_admin(profile, user)
    await db.delete(profile)
    await db.flush()


@router.get("/{profile_id}/surface")
async def get_profile_threat_surface(
    profile_id: uuid.UUID = Path(..., description="Intel profile UUID."),
    limit: int = Query(25, ge=1, le=100, description="Maximum matched entities per type."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Matched threat surface for a saved profile: actors and malware active
    against its regions × verticals, each with why-matched evidence."""
    profile = await db.get(IntelProfile, profile_id)
    if not profile:
        raise AppError(code="not_found", message="Intel profile not found", status_code=404)
    surface = await build_threat_surface(
        db,
        country_ids=list(profile.country_ids or []),
        sectors=list(profile.sectors or []),
        window_days=profile.window_days,
        limit=limit,
    )
    surface["profile_id"] = str(profile.id)
    surface["curation"] = profile.curation or {}
    return surface


@router.post("/surface-preview")
async def preview_threat_surface(
    body: ThreatSurfaceRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Threat surface for an ad-hoc scope — lets the builder preview matches
    before the analyst saves a profile."""
    return await build_threat_surface(
        db,
        country_ids=body.country_ids,
        sectors=body.sectors,
        window_days=body.window_days,
        limit=body.limit,
    )
