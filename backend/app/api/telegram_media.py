"""Auth-gated static-file route for Telegram media downloaded by the adapter.

Telegram media has no public URL — bytes are downloaded over MTProto by the
celery-worker, written to local disk, and served from this route. The api+worker
must share the same telegram_media volume mount.
"""

import logging
import mimetypes
import re
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi import Path as FPath
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.exceptions import AppError
from app.core.security import decode_token
from app.database import get_db
from app.models.user import User

logger = logging.getLogger(__name__)
router = APIRouter()

# channel_id is signed (negative for channels), filename is "<id>.<ext>" or "<id>.thumb.jpg"
_PATH_PATTERN = re.compile(r"^-?\d+$")
_FILENAME_PATTERN = re.compile(r"^\d+\.(?:[a-z0-9]+|thumb\.jpg|thumb\.jpeg)$")


async def _resolve_user(request: Request, token: str | None, db: AsyncSession) -> User:
    """Accept JWT via Authorization header (CLI/fetch) or `?token=` (img/video tags)."""
    raw_token: str | None = None
    auth_header = request.headers.get("authorization") or request.headers.get("Authorization")
    if auth_header and auth_header.lower().startswith("bearer "):
        raw_token = auth_header.split(" ", 1)[1].strip()
    elif token:
        raw_token = token
    if not raw_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token")
    payload = decode_token(raw_token)
    if payload.get("type") != "access":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    result = await db.execute(select(User).where(User.id == uuid.UUID(user_id)))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


@router.get("/{channel_id}/{filename}")
async def get_telegram_media(
    request: Request,
    channel_id: str = FPath(..., description="Numeric Telegram channel id (negative for channels)"),
    filename: str = FPath(..., description="Media filename, '<message_id>.<ext>' or '<message_id>.thumb.jpg'"),
    token: str | None = Query(
        default=None,
        description="JWT access token, for <img>/<video> tags that cannot send an Authorization header",
    ),
    db: AsyncSession = Depends(get_db),
) -> FileResponse:
    """Serve a Telegram-downloaded media file from disk.

    Auth-required (header or `?token=` query). Path-validated. Returns 404 if missing.
    """
    await _resolve_user(request, token, db)
    if not _PATH_PATTERN.match(channel_id) or not _FILENAME_PATTERN.match(filename):
        raise AppError(
            code="invalid_telegram_media_path",
            message="Invalid telegram media path.",
            status_code=400,
        )

    base = Path(settings.telegram_media_dir).resolve()
    target = (base / channel_id / filename).resolve()
    try:
        target.relative_to(base)
    except ValueError:
        raise AppError(
            code="invalid_telegram_media_path",
            message="Telegram media path traversal blocked.",
            status_code=400,
        )

    if not target.is_file():
        raise AppError(
            code="telegram_media_not_found",
            message="Telegram media not found.",
            status_code=404,
        )

    content_type, _ = mimetypes.guess_type(str(target))
    return FileResponse(
        str(target),
        media_type=content_type or "application/octet-stream",
        headers={"Cache-Control": "private, max-age=86400"},
    )
