"""Webhook Presets API — saved webhook URL + payload combinations for reuse in automations."""

import uuid

from fastapi import APIRouter, Body, Depends, Path, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppError
from app.core.pagination import PaginatedResponse
from app.core.security import get_current_user
from app.database import get_db
from app.models.user import User
from app.models.webhook_preset import WebhookPreset
from app.schemas.webhook_preset import (
    WebhookPresetCreate,
    WebhookPresetResponse,
    WebhookPresetUpdate,
)

router = APIRouter()


@router.get("", response_model=PaginatedResponse[WebhookPresetResponse])
async def list_webhook_presets(
    preset_type: str | None = Query(None, description="Filter by preset type (e.g. 'webhook', 'notification')"),
    limit: int = Query(100, ge=1, le=500, description="Maximum number of presets to return"),
    offset: int = Query(0, ge=0, description="Number of presets to skip for pagination"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List saved webhook presets ordered by name, optionally filtered by preset type."""
    filters = []
    if preset_type:
        filters.append(WebhookPreset.preset_type == preset_type)
    base = select(WebhookPreset)
    count_base = select(func.count()).select_from(WebhookPreset)
    if filters:
        base = base.where(*filters)
        count_base = count_base.where(*filters)
    total = (await db.execute(count_base)).scalar() or 0
    result = await db.execute(base.order_by(WebhookPreset.name).limit(limit).offset(offset))
    items = [WebhookPresetResponse.model_validate(p) for p in result.scalars().all()]
    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset, has_more=(offset + limit) < total)


@router.post("", response_model=WebhookPresetResponse, status_code=201)
async def create_webhook_preset(
    data: WebhookPresetCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a webhook preset (a reusable URL + payload + headers combination for automation actions)."""
    preset = WebhookPreset(created_by=user.id, **data.model_dump())
    db.add(preset)
    await db.flush()
    return WebhookPresetResponse.model_validate(preset)


@router.get("/{preset_id}", response_model=WebhookPresetResponse)
async def get_webhook_preset(
    preset_id: uuid.UUID = Path(..., description="ID of the webhook preset"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return a single webhook preset by ID."""
    result = await db.execute(select(WebhookPreset).where(WebhookPreset.id == preset_id))
    preset = result.scalar_one_or_none()
    if not preset:
        raise AppError("NOT_FOUND", "Webhook preset not found", status_code=404)
    return WebhookPresetResponse.model_validate(preset)


@router.put("/{preset_id}", response_model=WebhookPresetResponse)
async def update_webhook_preset(
    preset_id: uuid.UUID = Path(..., description="ID of the webhook preset to update"),
    data: WebhookPresetUpdate = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Partially update a webhook preset; only the fields present in the body are changed."""
    result = await db.execute(select(WebhookPreset).where(WebhookPreset.id == preset_id))
    preset = result.scalar_one_or_none()
    if not preset:
        raise AppError("NOT_FOUND", "Webhook preset not found", status_code=404)
    if user.role != "admin" and preset.created_by != user.id:
        # Other users' automation rules may target this preset's URL
        raise AppError("FORBIDDEN", "Only the preset's owner or an admin can modify it", status_code=403)
    for key, val in data.model_dump(exclude_unset=True).items():
        setattr(preset, key, val)
    await db.flush()
    return WebhookPresetResponse.model_validate(preset)


@router.delete("/{preset_id}", status_code=204)
async def delete_webhook_preset(
    preset_id: uuid.UUID = Path(..., description="ID of the webhook preset to delete"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete a webhook preset."""
    result = await db.execute(select(WebhookPreset).where(WebhookPreset.id == preset_id))
    preset = result.scalar_one_or_none()
    if not preset:
        raise AppError("NOT_FOUND", "Webhook preset not found", status_code=404)
    if user.role != "admin" and preset.created_by != user.id:
        raise AppError("FORBIDDEN", "Only the preset's owner or an admin can delete it", status_code=403)
    await db.delete(preset)
