import uuid

from fastapi import APIRouter, Body, Depends, Path, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppError
from app.core.pagination import PaginatedResponse
from app.core.security import get_current_user
from app.database import get_db
from app.models.campaign import Campaign
from app.models.cve import CVE
from app.models.entity_note import EntityNote
from app.models.malware_family import MalwareFamily
from app.models.product import Product
from app.models.sector import Sector
from app.models.threat_actor import ThreatActor
from app.models.ttp import TTP
from app.models.user import User
from app.models.vendor import Vendor
from app.schemas.entity_note import EntityNoteCreate, EntityNoteResponse, EntityNoteUpdate
from app.services.entity_names import resolve_entity_names

router = APIRouter()

# Map entity_type to (Model, name_column)
_ENTITY_NAME_MAP: dict[str, tuple] = {
    "threat_actor": (ThreatActor, ThreatActor.name),
    "malware": (MalwareFamily, MalwareFamily.name),
    "cve": (CVE, CVE.cve_id),
    "ttp": (TTP, TTP.technique_name),
    "campaign": (Campaign, Campaign.name),
    "vendor": (Vendor, Vendor.name),
    "product": (Product, Product.name),
    "sector": (Sector, Sector.name),
}


@router.get("/search", response_model=PaginatedResponse[EntityNoteResponse])
async def search_entity_notes(
    q: str | None = Query(None, description="Case-insensitive substring match against note content."),
    tag: str | None = Query(None, description="Only notes carrying this tag."),
    note_type: str | None = Query(
        None, description="Filter by note type (annotation, analysis, action_taken, false_positive, context)."
    ),
    entity_type: str | None = Query(None, description="Restrict to notes on entities of this type."),
    limit: int = Query(50, ge=1, le=500, description="Maximum notes per page."),
    offset: int = Query(0, ge=0, description="Number of notes to skip for pagination."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Search across all entity notes by text content, tag, type, or entity type."""
    base = select(EntityNote)
    count_base = select(func.count()).select_from(EntityNote)

    if q:
        base = base.where(EntityNote.content.ilike(f"%{q}%"))
        count_base = count_base.where(EntityNote.content.ilike(f"%{q}%"))
    if entity_type:
        base = base.where(EntityNote.entity_type == entity_type)
        count_base = count_base.where(EntityNote.entity_type == entity_type)
    if tag:
        base = base.where(EntityNote.tags.any(tag))
        count_base = count_base.where(EntityNote.tags.any(tag))
    if note_type:
        base = base.where(EntityNote.note_type == note_type)
        count_base = count_base.where(EntityNote.note_type == note_type)

    total = (await db.execute(count_base)).scalar() or 0
    query = base.order_by(EntityNote.created_at.desc()).limit(limit).offset(offset)
    result = await db.execute(query)
    notes = result.scalars().all()

    user_ids = {n.user_id for n in notes}
    if user_ids:
        users_result = await db.execute(select(User.id, User.username).where(User.id.in_(user_ids)))
        user_map = {row.id: row.username for row in users_result.all()}
    else:
        user_map = {}

    entity_name_map = await resolve_entity_names(db, notes, _ENTITY_NAME_MAP)

    items = [
        EntityNoteResponse(
            id=n.id,
            entity_type=n.entity_type,
            entity_id=n.entity_id,
            user_id=n.user_id,
            title=n.title,
            content=n.content,
            note_type=n.note_type,
            tags=n.tags,
            created_at=n.created_at,
            updated_at=n.updated_at,
            username=user_map.get(n.user_id),
            entity_name=entity_name_map.get((n.entity_type, n.entity_id)),
        )
        for n in notes
    ]

    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset, has_more=(offset + limit) < total)


@router.get("", response_model=PaginatedResponse[EntityNoteResponse])
async def list_entity_notes(
    entity_type: str = Query(
        ...,
        description="Entity type the notes are attached to "
        "(threat_actor, malware, cve, ttp, campaign, vendor, product).",
    ),
    entity_id: uuid.UUID = Query(..., description="UUID of the entity whose notes to list."),
    note_type: str | None = Query(
        None, description="Filter by note type (annotation, analysis, action_taken, false_positive, context)."
    ),
    limit: int = Query(50, ge=1, le=500, description="Maximum notes per page."),
    offset: int = Query(0, ge=0, description="Number of notes to skip for pagination."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List the notes attached to one entity, newest first, with author username and entity display name resolved."""
    base = select(EntityNote).where(
        EntityNote.entity_type == entity_type,
        EntityNote.entity_id == entity_id,
    )
    count_base = (
        select(func.count())
        .select_from(EntityNote)
        .where(
            EntityNote.entity_type == entity_type,
            EntityNote.entity_id == entity_id,
        )
    )

    if note_type:
        base = base.where(EntityNote.note_type == note_type)
        count_base = count_base.where(EntityNote.note_type == note_type)

    total = (await db.execute(count_base)).scalar() or 0

    query = base.order_by(EntityNote.created_at.desc()).limit(limit).offset(offset)
    result = await db.execute(query)
    notes = result.scalars().all()

    # Fetch usernames
    user_ids = {n.user_id for n in notes}
    if user_ids:
        users_result = await db.execute(select(User.id, User.username).where(User.id.in_(user_ids)))
        user_map = {row.id: row.username for row in users_result.all()}
    else:
        user_map = {}

    entity_name_map = await resolve_entity_names(db, notes, _ENTITY_NAME_MAP)

    items = [
        EntityNoteResponse(
            id=n.id,
            entity_type=n.entity_type,
            entity_id=n.entity_id,
            user_id=n.user_id,
            title=n.title,
            content=n.content,
            note_type=n.note_type,
            tags=n.tags,
            created_at=n.created_at,
            updated_at=n.updated_at,
            username=user_map.get(n.user_id),
            entity_name=entity_name_map.get((n.entity_type, n.entity_id)),
        )
        for n in notes
    ]

    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset, has_more=(offset + limit) < total)


@router.post("", response_model=EntityNoteResponse, status_code=201)
async def create_entity_note(
    body: EntityNoteCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Attach a note to an entity. The note is stamped with the calling user as its author."""
    note = EntityNote(
        entity_type=body.entity_type,
        entity_id=body.entity_id,
        user_id=user.id,
        title=body.title or None,
        content=body.content,
        note_type=body.note_type,
        tags=body.tags,
    )
    db.add(note)
    await db.flush()
    await db.refresh(note)
    return EntityNoteResponse(
        id=note.id,
        entity_type=note.entity_type,
        entity_id=note.entity_id,
        user_id=note.user_id,
        title=note.title,
        content=note.content,
        note_type=note.note_type,
        tags=note.tags,
        created_at=note.created_at,
        updated_at=note.updated_at,
        username=user.username,
    )


@router.put("/{note_id}", response_model=EntityNoteResponse)
async def update_entity_note(
    note_id: uuid.UUID = Path(..., description="UUID of the note to update."),
    body: EntityNoteUpdate = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update the title, content, type, or tags of an existing note. Only the provided fields change."""
    result = await db.execute(select(EntityNote).where(EntityNote.id == note_id))
    note = result.scalar_one_or_none()
    if not note:
        raise AppError(code="not_found", message="Entity note not found", status_code=404)
    if user.role != "admin" and note.user_id != user.id:
        raise AppError(code="forbidden", message="Only the note's author or an admin can modify it", status_code=403)

    if body.title is not None:
        note.title = body.title or None
    if body.content is not None:
        note.content = body.content
    if body.note_type is not None:
        note.note_type = body.note_type
    if body.tags is not None:
        note.tags = body.tags

    db.add(note)
    await db.flush()
    await db.refresh(note)
    return EntityNoteResponse(
        id=note.id,
        entity_type=note.entity_type,
        entity_id=note.entity_id,
        user_id=note.user_id,
        title=note.title,
        content=note.content,
        note_type=note.note_type,
        tags=note.tags,
        created_at=note.created_at,
        updated_at=note.updated_at,
        username=user.username,
    )


@router.delete("/{note_id}", status_code=204)
async def delete_entity_note(
    note_id: uuid.UUID = Path(..., description="UUID of the note to delete."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Permanently delete an entity note."""
    result = await db.execute(select(EntityNote).where(EntityNote.id == note_id))
    note = result.scalar_one_or_none()
    if not note:
        raise AppError(code="not_found", message="Entity note not found", status_code=404)
    if user.role != "admin" and note.user_id != user.id:
        raise AppError(code="forbidden", message="Only the note's author or an admin can delete it", status_code=403)
    await db.delete(note)
    await db.flush()
