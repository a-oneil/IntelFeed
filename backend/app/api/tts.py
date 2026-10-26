"""Server-side read-aloud (Piper TTS) endpoints.

- POST /api/tts/prepare  — enqueue/lookup synthesis for an entry or daily summary.
- GET  /api/tts/file/{cache_key}.mp3 — stream a generated MP3 (JWT via header or ?token=).

The public, share-token-gated variants live in app/api/shared.py so they can be
served without a login (a bare <audio> element on the public share page).
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.exceptions import AppError
from app.core.security import AnonymousViewer, decode_token, get_current_user, get_viewer, public_read_only_enabled
from app.database import get_db
from app.models.entry import Entry
from app.models.user import User
from app.services import tts
from app.services.tts_text import normalize_plain_text, text_from_html

router = APIRouter()


class PrepareRequest(BaseModel):
    source: str  # "entry" | "summary" | "entity"
    id: str  # entry/entity id (uuid) or day_key for summaries
    # For source="summary": the filter context (same as GET /entries/daily-summary)
    # used to resolve which cached summary to read. Text is resolved server-side so
    # the cache key matches the morning pre-generation.
    filters: dict | None = None
    # For source="entity": which workbench entity type the id refers to.
    entity_type: str | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "source": "entry",
                "id": "d5b2c8a1-4f3e-4b7a-9c6d-2e8f1a0b3c4d",
            }
        }
    )


class TTSStatusResponse(BaseModel):
    cache_key: str | None
    status: str  # pending | ready | error
    duration: float | None = None
    error: str | None = None


async def _entity_speech_text(db: AsyncSession, entity_type: str | None, entity_id: str) -> str:
    """Speech text for a workbench entity's assessment: name + description,
    with markdown stripped to read naturally."""
    import re

    from app.intelligence.correlation import ENTITY_CONFIG

    if not entity_type or entity_type not in ENTITY_CONFIG:
        raise AppError(code="invalid_source", message="Unknown entity type.", status_code=400)
    try:
        eid = uuid.UUID(entity_id)
    except ValueError:
        raise AppError(code="invalid_id", message="Invalid entity id.", status_code=400)
    model = ENTITY_CONFIG[entity_type][0]
    entity = (await db.execute(select(model).where(model.id == eid))).scalar_one_or_none()
    if entity is None:
        raise AppError(code="not_found", message="Entity not found.", status_code=404)
    name = (
        getattr(entity, "name", None)
        or getattr(entity, "cve_id", None)
        or getattr(entity, "technique_name", None)
        or getattr(entity, "technique_id", None)
        or "this entity"
    )
    desc = getattr(entity, "description", None) or ""
    if not desc.strip():
        raise AppError(code="no_assessment", message="No assessment to read yet.", status_code=404)
    # Markdown → plain: unwrap links, drop emphasis/heading/code markers.
    desc = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", desc)
    desc = re.sub(r"[#*_`>|]+", " ", desc)
    return normalize_plain_text(f"{name}. Intelligence assessment.\n\n{desc}")


async def _entry_speech_text(db: AsyncSession, entry_id: str) -> tuple[Entry, str]:
    try:
        eid = uuid.UUID(entry_id)
    except ValueError:
        raise AppError(code="invalid_id", message="Invalid entry id.", status_code=400)
    entry = (await db.execute(select(Entry).where(Entry.id == eid))).scalar_one_or_none()
    if entry is None:
        raise AppError(code="not_found", message="Entry not found.", status_code=404)
    if entry.content_html:
        text = text_from_html(entry.content_html, entry.title)
    else:
        body = entry.content_text or entry.summary or ""
        text = normalize_plain_text(f"{entry.title}\n\n{body}" if entry.title else body)
    return entry, text


@router.post("/prepare", response_model=TTSStatusResponse)
async def prepare_tts(
    body: PrepareRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Enqueue (or look up cached) read-aloud audio; poll GET /file when ready."""
    if not settings.tts_enabled:
        raise AppError(code="tts_disabled", message="Server-side read-aloud is disabled.", status_code=503)

    if body.source == "entry":
        _, text = await _entry_speech_text(db, body.id)
        result = await tts.get_or_enqueue(db, source="entry", ref_id=body.id, text=text)
    elif body.source == "summary":
        # Resolve the summary text server-side (same derivation as the morning
        # pre-generation) so the cache key matches and pre-gen'd audio is a hit.
        text = await tts.resolve_summary_speech_text(db, body.id, body.filters, user.id)
        if not text:
            raise AppError(code="summary_not_ready", message="Daily summary not available.", status_code=404)
        result = await tts.get_or_enqueue(db, source="summary", ref_id=body.id, text=text)
    elif body.source == "entity":
        text = await _entity_speech_text(db, body.entity_type, body.id)
        result = await tts.get_or_enqueue(db, source="entity", ref_id=f"{body.entity_type}:{body.id}", text=text)
    else:
        raise AppError(code="invalid_source", message="Unknown TTS source.", status_code=400)

    return TTSStatusResponse(**result)


async def _resolve_user_from_token(request: Request, token: str | None, db: AsyncSession) -> User | AnonymousViewer:
    """Accept a JWT via Authorization header (fetch) or ?token= (bare <audio>).

    With no token at all the caller is a visitor while public read-only mode
    is on: existing audio may be played, nothing is made or recorded.
    """
    raw = None
    auth_header = request.headers.get("authorization") or request.headers.get("Authorization")
    if auth_header and auth_header.lower().startswith("bearer "):
        raw = auth_header.split(" ", 1)[1].strip()
    elif token:
        raw = token
    if not raw:
        if public_read_only_enabled():
            return AnonymousViewer()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token")
    payload = decode_token(raw)
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


def _serve_audio_file(cache_key: str) -> FileResponse:
    """Shared file-serving helper (also used by the public share route)."""
    if not _valid_cache_key(cache_key):
        raise AppError(code="invalid_tts_key", message="Invalid audio key.", status_code=400)
    path = tts.audio_path(cache_key)
    if not path.is_file():
        raise AppError(code="tts_not_found", message="Audio not found.", status_code=404)
    return FileResponse(
        str(path),
        media_type="audio/mpeg",
        headers={"Cache-Control": "private, max-age=86400"},
    )


def _valid_cache_key(cache_key: str) -> bool:
    return len(cache_key) == 64 and all(c in "0123456789abcdef" for c in cache_key)


@router.get("/file/{cache_key}.mp3")
async def get_tts_file(
    request: Request,
    cache_key: str = Path(..., description="64-char hex cache key returned by POST /api/tts/prepare"),
    token: str | None = Query(
        default=None, description="JWT access token, for bare <audio> tags that cannot send an Authorization header"
    ),
    db: AsyncSession = Depends(get_db),
) -> FileResponse:
    """Stream a generated MP3. Auth via Authorization header or ?token= query."""
    user = await _resolve_user_from_token(request, token, db)
    response = _serve_audio_file(cache_key)
    if not user.is_anonymous:
        # A visitor's playback must not count as use: the stamp drives eviction.
        await tts.touch(db, cache_key)
    return response


@router.get("/existing", response_model=TTSStatusResponse)
async def existing_tts(
    source: str = Query(..., description='"entry" or "entity"'),
    id: str = Query(..., description="Entry id, or entity id for source=entity"),
    entity_type: str | None = Query(None, description="For source=entity: the workbench entity type"),
    user: User | AnonymousViewer = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Whether read-aloud audio already exists for an entry or entity, without making any.

    This is what a visitor's player asks: POST /prepare would synthesize on a
    miss, which visitors may not cause. 404 when no audio has been made.
    """
    if not settings.tts_enabled:
        raise AppError(code="tts_disabled", message="Server-side read-aloud is disabled.", status_code=503)
    if source == "entry":
        _, text = await _entry_speech_text(db, id)
        ref_id = id
    elif source == "entity":
        text = await _entity_speech_text(db, entity_type, id)
        ref_id = f"{entity_type}:{id}"
    else:
        raise AppError(code="invalid_source", message="Unknown TTS source.", status_code=400)
    cache_key = tts.compute_cache_key(source, ref_id, text, settings.piper_voice)
    status_row = await tts.get_status(db, cache_key)
    if status_row is None or status_row["status"] != "ready" or not tts.audio_path(cache_key).is_file():
        raise AppError(code="tts_not_found", message="No audio for this item yet.", status_code=404)
    return TTSStatusResponse(**status_row)
