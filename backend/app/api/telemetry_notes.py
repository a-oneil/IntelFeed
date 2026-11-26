"""Notes and saved links about telemetry sources.

Shared across users, like entity notes: everyone reads them, the author or an
admin edits. Keyed by source name so a catalog source nobody has enabled yet
can collect notes (see TelemetrySourceNote).
"""

import re
import uuid
from urllib.parse import urlsplit

from fastapi import APIRouter, Body, Depends, Path, Query
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.telemetry_sources import DATA_SOURCE_CATALOG
from app.core.exceptions import AppError
from app.core.pagination import PaginatedResponse
from app.core.security import get_current_user
from app.database import get_db
from app.models.telemetry_source import TelemetrySource
from app.models.telemetry_source_note import TelemetrySourceNote
from app.models.user import User
from app.schemas.telemetry_source import (
    TelemetrySourceNoteCreate,
    TelemetrySourceNoteResponse,
    TelemetrySourceNoteUpdate,
    TelemetrySourceSuggestion,
)

router = APIRouter()


def _clean(value: str | None) -> str | None:
    value = (value or "").strip()
    return value or None


def _response(note: TelemetrySourceNote, username: str | None) -> TelemetrySourceNoteResponse:
    return TelemetrySourceNoteResponse(
        id=note.id,
        source_name=note.source_name,
        user_id=note.user_id,
        username=username,
        url=note.url,
        page_title=note.page_title,
        quote=note.quote,
        content=note.content,
        created_at=note.created_at,
        updated_at=note.updated_at,
    )


async def known_source(db: AsyncSession, name: str) -> str | None:
    """The source's stored spelling: a catalog name, else an inventory row's name."""
    for item in DATA_SOURCE_CATALOG:
        if item["name"].lower() == name.lower():
            return item["name"]
    return (
        await db.execute(select(TelemetrySource.name).where(func.lower(TelemetrySource.name) == name.lower()).limit(1))
    ).scalar_one_or_none()


# Longest value each field accepts, the same limits as TelemetrySourceNoteCreate.
FIELD_LIMITS = {"url": 4000, "page_title": 500, "quote": 10000, "content": 20000}


def checked_note_fields(
    url: str | None, page_title: str | None, quote: str | None, content: str | None
) -> dict[str, str | None]:
    """Strip the fields, turn blanks into None, and check them.

    Raises AppError (422) when a field is too long, when the note has neither a
    link nor text, or when the link is not http(s). Used by the API and by the
    add_telemetry_source_note tool, so both give the same errors.
    """
    fields = {"url": _clean(url), "page_title": _clean(page_title), "quote": _clean(quote), "content": _clean(content)}
    for field, limit in FIELD_LIMITS.items():
        if fields[field] is not None and len(fields[field]) > limit:
            raise AppError(code="too_long", message=f"{field} is longer than {limit} characters", status_code=422)
    if fields["url"] is None and fields["content"] is None:
        raise AppError(code="empty_note", message="Add a link, a note, or both.", status_code=422)
    if fields["url"] is not None and not fields["url"].lower().startswith(("http://", "https://")):
        raise AppError(code="invalid_url", message="Links must start with http:// or https://", status_code=422)
    return fields


async def create_note(
    db: AsyncSession,
    user_id: uuid.UUID,
    source_name: str,
    *,
    url: str | None = None,
    page_title: str | None = None,
    quote: str | None = None,
    content: str | None = None,
) -> TelemetrySourceNote:
    """Check and add one note. Raises AppError (422) for an unknown source or bad fields."""
    name = await known_source(db, source_name.strip())
    if name is None:
        raise AppError(
            code="unknown_source",
            message=f"No telemetry source named {source_name!r} in the catalog or the inventory",
            status_code=422,
        )
    note = TelemetrySourceNote(
        source_name=name, user_id=user_id, **checked_note_fields(url, page_title, quote, content)
    )
    db.add(note)
    await db.flush()
    return note


@router.get("", response_model=PaginatedResponse[TelemetrySourceNoteResponse])
async def list_telemetry_notes(
    source: str | None = Query(
        None, max_length=255, description="One source's notes, e.g. AWS GuardDuty; omit for all"
    ),
    q: str | None = Query(None, max_length=200, description="Text in the note, quote, page title, link or source name"),
    limit: int = Query(100, ge=1, le=500, description="Page size"),
    offset: int = Query(0, ge=0, description="Rows to skip for pagination"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Notes and saved links about telemetry sources, newest first: one source's,
    or every source's for the Notes page."""
    conditions = []
    if source:
        conditions.append(func.lower(TelemetrySourceNote.source_name) == source.strip().lower())
    if q and q.strip():
        like = f"%{q.strip()}%"
        conditions.append(
            or_(
                TelemetrySourceNote.content.ilike(like),
                TelemetrySourceNote.quote.ilike(like),
                TelemetrySourceNote.page_title.ilike(like),
                TelemetrySourceNote.url.ilike(like),
                TelemetrySourceNote.source_name.ilike(like),
            )
        )
    total = (await db.execute(select(func.count()).select_from(TelemetrySourceNote).where(*conditions))).scalar() or 0
    rows = (
        await db.execute(
            select(TelemetrySourceNote, User.username)
            .join(User, User.id == TelemetrySourceNote.user_id)
            .where(*conditions)
            .order_by(TelemetrySourceNote.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
    ).all()
    items = [_response(note, username) for note, username in rows]
    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset, has_more=(offset + limit) < total)


@router.get("/counts", response_model=dict[str, int])
async def telemetry_note_counts(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Number of notes and links per source name, for badges on the catalog."""
    rows = await db.execute(
        select(TelemetrySourceNote.source_name, func.count()).group_by(TelemetrySourceNote.source_name)
    )
    return dict(rows.all())


# ── suggestions ─────────────────────────────────────────────────────────────

_STOP = {"for", "the", "and", "of", "on", "a", "an", "to", "with", "by", "in", "logs", "log"}


def _words(text: str) -> list[str]:
    return [w for w in re.split(r"[^a-z0-9]+", text.lower()) if w]


def _site_prefix(url: str) -> str | None:
    """host + the first two path segments: the part of a docs site one product lives under."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if not parts.hostname:
        return None
    segments = [s for s in parts.path.split("/") if s][:2]
    return "/".join([parts.hostname.lower(), *segments])


def name_matches(url: str, title: str) -> list[tuple[int, dict]]:
    """Catalog items whose product (or name) shows up in the page's address or title.

    A product matches when all its significant words are words of the page, or
    when its words run together appear in the page run together ("guardduty"
    in "/guardduty/latest/ug/"). Scored by the length of what matched, so
    "Defender for Endpoint" outranks "Defender"; products shorter than four
    letters ("DNS") never match on their own.
    """
    try:
        host_path = urlsplit(url)
        address = f"{host_path.hostname or ''} {host_path.path}"
    except ValueError:
        address = ""
    page_words = set(_words(f"{address} {title}"))
    page_compact = "".join(_words(f"{address} {title}"))
    scored: list[tuple[int, dict]] = []
    for item in DATA_SOURCE_CATALOG:
        best = 0
        for label in {item.get("product") or "", item["name"]}:
            words = [w for w in _words(label) if w not in _STOP]
            compact = "".join(words)
            if len(compact) < 4:
                continue
            if all(w in page_words for w in words) or (len(compact) >= 6 and compact in page_compact):
                best = max(best, len(compact))
        if best:
            if any(w in page_words for w in _words(item.get("vendor") or "") if w not in _STOP and len(w) > 2):
                best += 3
            scored.append((best, item))
    scored.sort(key=lambda pair: (-pair[0], pair[1]["name"]))
    return scored


@router.get("/suggest", response_model=list[TelemetrySourceSuggestion])
async def suggest_telemetry_source(
    url: str = Query(..., max_length=4000, description="The page being read"),
    title: str = Query("", max_length=1000, description="The page's title"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Up to five sources the page is probably about, best first.

    Sources someone already saved a link to from the same part of the site
    come first (``saved_before``), then catalog products named in the address
    or title (``name_match``).
    """
    by_name = {item["name"]: item for item in DATA_SOURCE_CATALOG}
    out: list[TelemetrySourceSuggestion] = []
    seen: set[str] = set()

    prefix = _site_prefix(url)
    if prefix:
        host = prefix.split("/", 1)[0]
        rows = (
            await db.execute(
                select(TelemetrySourceNote.source_name, TelemetrySourceNote.url)
                .where(TelemetrySourceNote.url.ilike(f"%{host}%"))
                .order_by(TelemetrySourceNote.created_at.desc())
                .limit(200)
            )
        ).all()
        counts: dict[str, int] = {}
        for name, note_url in rows:
            if note_url and _site_prefix(note_url) == prefix:
                counts[name] = counts.get(name, 0) + 1
        for name in sorted(counts, key=lambda n: -counts[n]):
            out.append(
                TelemetrySourceSuggestion(
                    name=name, category=(by_name.get(name) or {}).get("category"), reason="saved_before"
                )
            )
            seen.add(name)

    for _, item in name_matches(url, title):
        if item["name"] not in seen:
            out.append(TelemetrySourceSuggestion(name=item["name"], category=item["category"], reason="name_match"))
            seen.add(item["name"])
    return out[:5]


# ── writes ──────────────────────────────────────────────────────────────────


@router.post("", response_model=TelemetrySourceNoteResponse, status_code=201)
async def create_telemetry_note(
    body: TelemetrySourceNoteCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Save a note, or a link with an optional note, about one telemetry source."""
    note = await create_note(
        db,
        user.id,
        body.source_name,
        url=body.url,
        page_title=body.page_title,
        quote=body.quote,
        content=body.content,
    )
    await db.refresh(note)
    return _response(note, user.username)


async def _owned(db: AsyncSession, note_id: uuid.UUID, user: User, verb: str) -> TelemetrySourceNote:
    note = (await db.execute(select(TelemetrySourceNote).where(TelemetrySourceNote.id == note_id))).scalar_one_or_none()
    if not note:
        raise AppError(code="not_found", message="Note not found", status_code=404)
    if user.role != "admin" and note.user_id != user.id:
        raise AppError(code="forbidden", message=f"Only the note's author or an admin can {verb} it", status_code=403)
    return note


@router.put("/{note_id}", response_model=TelemetrySourceNoteResponse)
async def update_telemetry_note(
    note_id: uuid.UUID = Path(..., description="Note UUID"),
    body: TelemetrySourceNoteUpdate = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Edit a note. Fields left out are unchanged; an empty string clears one."""
    note = await _owned(db, note_id, user, "edit")
    # Check the edited note before touching the row: a dirty row that breaks
    # the url-or-content constraint would still be flushed by the next query.
    merged = {field: getattr(note, field) for field in FIELD_LIMITS}
    merged.update({field: getattr(body, field) for field in body.model_fields_set})
    checked = checked_note_fields(**merged)
    for field in body.model_fields_set:
        setattr(note, field, checked[field])
    db.add(note)
    await db.flush()
    await db.refresh(note)
    username = (await db.execute(select(User.username).where(User.id == note.user_id))).scalar_one_or_none()
    return _response(note, username)


@router.delete("/{note_id}", status_code=204)
async def delete_telemetry_note(
    note_id: uuid.UUID = Path(..., description="Note UUID"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete a note or saved link."""
    note = await _owned(db, note_id, user, "delete")
    await db.delete(note)
    await db.flush()
