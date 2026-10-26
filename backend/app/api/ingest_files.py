"""Auth-gated download route for the original files behind manual uploads.

Same shape as api/telegram_media.py: the api and celery-worker share the
``ingest_files`` mount, the JWT may arrive in the Authorization header (fetch,
CLI) or as ``?token=`` (a plain link or an ``<a download>``), and the path on
disk is never built from anything the client sent — only from the file row.
"""

import logging
import uuid
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppError
from app.core.security import decode_token
from app.database import get_db
from app.models.ingest_batch import IngestFile
from app.models.user import User
from app.services import ingest_files as store

logger = logging.getLogger(__name__)
router = APIRouter()


async def _resolve_user(request: Request, token: str | None, db: AsyncSession) -> User:
    """Accept JWT via Authorization header (CLI/fetch) or `?token=` (plain links)."""
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


@router.get("/{file_id}")
async def download_ingest_file(
    request: Request,
    file_id: uuid.UUID,
    token: str | None = Query(default=None, description="JWT access token, for links that cannot send a header"),
    inline: bool = Query(default=False, description="Open in the browser instead of downloading (PDFs, images)"),
    db: AsyncSession = Depends(get_db),
) -> FileResponse:
    """Serve the original bytes of a manual upload.

    Auth-required (header or `?token=`). 404 when the file was never stored
    or the retention sweep has evicted it; the entry itself is unaffected.
    """
    await _resolve_user(request, token, db)
    row = (await db.execute(select(IngestFile).where(IngestFile.id == file_id))).scalar_one_or_none()
    if row is None:
        raise AppError(code="ingest_file_not_found", message="Original file not found.", status_code=404)
    if row.evicted_at is not None:
        raise AppError(
            code="ingest_file_evicted",
            message="The original file was removed by the retention sweep; the entry's text is still here.",
            status_code=404,
        )
    target = store.absolute_path(row.path)
    if target is None:
        raise AppError(code="invalid_ingest_file_path", message="Ingest file path traversal blocked.", status_code=400)
    if not target.is_file():
        raise AppError(code="ingest_file_not_found", message="Original file not found on disk.", status_code=404)

    disposition = "inline" if inline else "attachment"
    ascii_name = row.filename.encode("ascii", "replace").decode("ascii").replace('"', "")
    return FileResponse(
        str(target),
        media_type=row.content_type or "application/octet-stream",
        headers={
            "Content-Disposition": f"{disposition}; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(row.filename)}",
            "Cache-Control": "private, max-age=86400",
        },
    )
