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


async def _sync_enrichment_pause(db: AsyncSession, keys) -> None:
    """The gateways read the pause from Redis: copy a change there now rather
    than at the dispatcher's next tick, once the change is committed."""
    from app.enrichment.pause import SETTING, sync_pause
    from app.services.engine_switch import SETTING as ENGINE_SETTING

    # A stopped engine pauses enrichment too.
    if SETTING in keys or ENGINE_SETTING in keys:
        await db.commit()
        await sync_pause(db)


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


def _refuse_key_settings(keys) -> None:
    """Enrichment's Keys view is the one place its keys are set."""
    from app.enrichment.keys import credentials

    owned = sorted({c.setting for c in credentials().values() if c.setting} & set(keys))
    if owned:
        raise AppError(
            code="set_in_enrichment_keys",
            message=f"{', '.join(owned)}: set it under Settings → Engine → Enrichment → Keys",
            status_code=400,
        )


@router.patch("")
async def update_system_settings_endpoint(
    body: SystemSettingsUpdate,
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Update system settings. Set a value to null to reset to default. The API
    keys enrichment reads (``nvd_api_key``, ``github_token``) are set under
    ``/enrichment/keys`` instead."""
    _refuse_key_settings(body.settings)
    try:
        settings = await update_settings(db, body.settings)
    except ValueError as e:
        raise AppError(code="invalid_setting", message=str(e), status_code=400)
    await _sync_enrichment_pause(db, body.settings)
    return {"settings": settings, "groups": GROUP_LABELS}


@router.delete("/{key}")
async def reset_setting_endpoint(
    key: str = Path(..., description='Setting key to reset, e.g. "registration_enabled"'),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Reset a single setting back to its env/default value."""
    _refuse_key_settings({key})
    try:
        settings = await reset_setting(db, key)
    except ValueError as e:
        raise AppError(code="invalid_setting", message=str(e), status_code=400)
    await _sync_enrichment_pause(db, {key})
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


class TestEmailRequest(BaseModel):
    to: str

    model_config = ConfigDict(json_schema_extra={"example": {"to": "analyst@example.com"}})


@router.post("/email/test")
async def send_test_email_endpoint(
    body: TestEmailRequest,
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Send a test message through the saved SMTP settings to one address."""
    from app.services.mailer import NOT_CONFIGURED, MailError, load_smtp_config, parse_recipients, send_mail

    to, invalid = parse_recipients(body.to)
    if invalid or len(to) != 1:
        raise AppError(code="invalid_recipient", message="Enter one valid email address", status_code=400)
    cfg = await load_smtp_config(db)
    if cfg is None:
        raise AppError(code="email_not_configured", message=NOT_CONFIGURED, status_code=400)
    try:
        await send_mail(
            cfg,
            to=to,
            subject="IntelFeed test email",
            text_body="This is a test from IntelFeed. Your SMTP settings work.",
        )
    except MailError as e:
        # 400, not 502: an edge proxy (Cloudflare) can swap an origin 502 for
        # its own page and the SMTP reason would never reach the admin.
        raise AppError(code="email_failed", message=str(e), status_code=400)
    return {"status": "sent", "to": to[0]}
