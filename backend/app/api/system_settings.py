"""System settings API — admin-only configuration of runtime settings."""

from typing import Any

from fastapi import APIRouter, Depends, Path
from pydantic import BaseModel, ConfigDict
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppError
from app.core.security import get_admin_user
from app.database import get_db
from app.models.user import User
from app.services.system_settings import (
    GROUP_LABELS,
    get_all_settings,
    get_public_rss_token,
    regenerate_public_rss_token,
    reset_setting,
    update_settings,
)

router = APIRouter()


class SystemSettingsUpdate(BaseModel):
    settings: dict[str, Any]

    model_config = ConfigDict(
        json_schema_extra={
            "example": {"settings": {"registration_enabled": False, "registration_invite_code": "TEAM-2026"}}
        }
    )


@router.get("")
async def get_system_settings_endpoint(
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Get all system settings with current effective values."""
    settings = await get_all_settings(db)
    return {"settings": settings, "groups": GROUP_LABELS}


@router.patch("")
async def update_system_settings_endpoint(
    body: SystemSettingsUpdate,
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Update system settings. Set a value to null to reset to default."""
    try:
        settings = await update_settings(db, body.settings)
    except ValueError as e:
        raise AppError(code="invalid_setting", message=str(e), status_code=400)
    return {"settings": settings, "groups": GROUP_LABELS}


@router.delete("/{key}")
async def reset_setting_endpoint(
    key: str = Path(..., description='Setting key to reset, e.g. "registration_enabled"'),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Reset a single setting back to its env/default value."""
    try:
        settings = await reset_setting(db, key)
    except ValueError as e:
        raise AppError(code="invalid_setting", message=str(e), status_code=400)
    return {"settings": settings, "groups": GROUP_LABELS}


@router.get("/public-rss/token")
async def get_public_rss_token_endpoint(
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Return (or auto-create) the token used in public RSS URLs."""
    token = await get_public_rss_token(db, create_if_missing=True)
    return {"token": token}


@router.post("/public-rss/regenerate-token")
async def regenerate_public_rss_token_endpoint(
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Issue a new token. Any previously shared URLs stop working immediately."""
    token = await regenerate_public_rss_token(db)
    return {"token": token}
