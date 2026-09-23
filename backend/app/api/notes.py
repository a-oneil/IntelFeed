import uuid

from fastapi import APIRouter, Body, Depends, Path, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppError
from app.core.pagination import PaginatedResponse
from app.core.security import get_current_user
from app.database import get_db
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.note import Note
from app.models.user import User
from app.schemas.note import NoteCreate, NoteResponse, NoteUpdate
from app.services.markdown import render_markdown

router = APIRouter()


def _assert_note_author(note: Note, user: User) -> None:
    """Notes are platform-wide readable, but only the author (or an admin) may change or delete one."""
    if user.role != "admin" and note.created_by != user.id:
        raise AppError(
            code="forbidden",
            message="Only the note's author or an admin can modify it",
            status_code=403,
        )


@router.get("", response_model=PaginatedResponse[NoteResponse])
async def list_notes(
    entry_id: uuid.UUID | None = Query(None, description="Only return notes attached to this entry"),
    is_pinned: bool | None = Query(None, description="Filter by pinned state"),
    q: str | None = Query(None, description="Case-insensitive substring search over note title and markdown content"),
    limit: int = Query(50, ge=1, le=500, description="Maximum number of notes to return"),
    offset: int = Query(0, ge=0, description="Number of notes to skip for pagination"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List analyst notes across all users, pinned first then most recently updated.

    Each note is returned with its creator username and, when attached to an entry,
    the entry and feed titles.
    """
    query = (
        select(
            Note,
            Entry.title.label("entry_title"),
            func.coalesce(Feed.custom_title, Feed.title).label("feed_title"),
            User.username.label("creator_username"),
        )
        .outerjoin(Entry, Entry.id == Note.entry_id)
        .outerjoin(Feed, Feed.id == Entry.feed_id)
        .outerjoin(User, User.id == Note.created_by)
    )

    if entry_id is not None:
        query = query.where(Note.entry_id == entry_id)
    if is_pinned is not None:
        query = query.where(Note.is_pinned == is_pinned)
    if q:
        search_filter = Note.title.ilike(f"%{q}%") | Note.content_markdown.ilike(f"%{q}%")
        query = query.where(search_filter)

    # Count
    count_q = select(func.count()).select_from(Note)
    if entry_id is not None:
        count_q = count_q.where(Note.entry_id == entry_id)
    if is_pinned is not None:
        count_q = count_q.where(Note.is_pinned == is_pinned)
    if q:
        count_q = count_q.where(Note.title.ilike(f"%{q}%") | Note.content_markdown.ilike(f"%{q}%"))
    total = (await db.execute(count_q)).scalar() or 0

    query = query.order_by(Note.is_pinned.desc(), Note.updated_at.desc())
    query = query.limit(limit).offset(offset)

    result = await db.execute(query)
    items = []
    for note, entry_title, feed_title, creator_username in result.all():
        items.append(
            NoteResponse(
                id=note.id,
                created_by=note.created_by,
                entry_id=note.entry_id,
                title=note.title,
                content_markdown=note.content_markdown,
                content_html=note.content_html,
                tags=note.tags,
                is_pinned=note.is_pinned,
                created_at=note.created_at,
                updated_at=note.updated_at,
                creator_username=creator_username,
                entry_title=entry_title,
                feed_title=feed_title,
            )
        )

    return PaginatedResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
        has_more=(offset + limit) < total,
    )


@router.post("", response_model=NoteResponse, status_code=201)
async def create_note(
    body: NoteCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a standalone note (not attached to an entry). Markdown content is also rendered and stored as HTML."""
    note = Note(
        created_by=user.id,
        title=body.title,
        content_markdown=body.content_markdown,
        content_html=render_markdown(body.content_markdown),
        tags=body.tags,
        is_pinned=body.is_pinned,
    )
    db.add(note)
    await db.flush()
    await db.refresh(note)
    return NoteResponse(
        id=note.id,
        created_by=note.created_by,
        entry_id=note.entry_id,
        title=note.title,
        content_markdown=note.content_markdown,
        content_html=note.content_html,
        tags=note.tags,
        is_pinned=note.is_pinned,
        created_at=note.created_at,
        updated_at=note.updated_at,
        creator_username=user.username,
    )


@router.get("/{note_id}", response_model=NoteResponse)
async def get_note(
    note_id: uuid.UUID = Path(..., description="UUID of the note"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get a single note by id, including its creator username. Returns 404 if not found."""
    result = await db.execute(
        select(Note, User.username.label("creator_username"))
        .outerjoin(User, User.id == Note.created_by)
        .where(Note.id == note_id)
    )
    row = result.one_or_none()
    if not row:
        raise AppError(
            code="not_found",
            message="Note not found",
            status_code=404,
        )
    note, creator_username = row
    resp = NoteResponse.model_validate(note)
    resp.creator_username = creator_username
    return resp


@router.put("/{note_id}", response_model=NoteResponse)
async def update_note(
    note_id: uuid.UUID = Path(..., description="UUID of the note to update"),
    body: NoteUpdate = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Partially update a note; only fields present in the request are changed.

    Updating content_markdown re-renders the stored HTML.
    """
    result = await db.execute(select(Note).where(Note.id == note_id))
    note = result.scalar_one_or_none()
    if not note:
        raise AppError(
            code="not_found",
            message="Note not found",
            status_code=404,
        )
    _assert_note_author(note, user)

    if body.title is not None:
        note.title = body.title
    if body.content_markdown is not None:
        note.content_markdown = body.content_markdown
        note.content_html = render_markdown(body.content_markdown)
    if body.tags is not None:
        note.tags = body.tags
    if body.is_pinned is not None:
        note.is_pinned = body.is_pinned

    db.add(note)
    await db.flush()
    await db.refresh(note)
    # Resolve creator username
    creator_username = None
    if note.created_by:
        creator_result = await db.execute(select(User.username).where(User.id == note.created_by))
        creator_username = creator_result.scalar_one_or_none()
    resp = NoteResponse.model_validate(note)
    resp.creator_username = creator_username
    return resp


@router.delete("/{note_id}", status_code=204)
async def delete_note(
    note_id: uuid.UUID = Path(..., description="UUID of the note to delete"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete a note. Returns 404 if it does not exist."""
    result = await db.execute(select(Note).where(Note.id == note_id))
    note = result.scalar_one_or_none()
    if not note:
        raise AppError(
            code="not_found",
            message="Note not found",
            status_code=404,
        )
    _assert_note_author(note, user)
    await db.delete(note)
    await db.flush()


@router.post(
    "/entry/{entry_id}",
    response_model=NoteResponse,
    status_code=201,
)
async def create_entry_note(
    entry_id: uuid.UUID = Path(..., description="UUID of the entry to attach the note to"),
    body: NoteCreate = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a note attached to a feed entry. Returns 404 if the entry does not exist."""
    # Verify entry exists
    entry_result = await db.execute(select(Entry).where(Entry.id == entry_id))
    entry = entry_result.scalar_one_or_none()
    if not entry:
        raise AppError(
            code="not_found",
            message="Entry not found",
            status_code=404,
        )

    note = Note(
        created_by=user.id,
        entry_id=entry_id,
        title=body.title,
        content_markdown=body.content_markdown,
        content_html=render_markdown(body.content_markdown),
        tags=body.tags,
        is_pinned=body.is_pinned,
    )
    db.add(note)
    await db.flush()
    await db.refresh(note)
    return NoteResponse(
        id=note.id,
        created_by=note.created_by,
        entry_id=note.entry_id,
        title=note.title,
        content_markdown=note.content_markdown,
        content_html=note.content_html,
        tags=note.tags,
        is_pinned=note.is_pinned,
        created_at=note.created_at,
        updated_at=note.updated_at,
        creator_username=user.username,
    )


@router.get(
    "/entry/{entry_id}",
    response_model=list[NoteResponse],
)
async def list_entry_notes(
    entry_id: uuid.UUID = Path(..., description="UUID of the entry whose notes to list"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all notes attached to an entry, newest first."""
    result = await db.execute(
        select(Note, User.username.label("creator_username"))
        .outerjoin(User, User.id == Note.created_by)
        .where(Note.entry_id == entry_id)
        .order_by(Note.created_at.desc())
    )
    items = []
    for note, creator_username in result.all():
        resp = NoteResponse.model_validate(note)
        resp.creator_username = creator_username
        items.append(resp)
    return items
