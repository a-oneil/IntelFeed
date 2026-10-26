import logging
import uuid

from fastapi import APIRouter, Body, Depends, Path
from sqlalchemy import and_, delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppError
from app.core.security import get_current_user, get_entry_viewer, get_viewer
from app.database import get_db
from app.models.entry import Entry
from app.models.tag import EntryTag, Tag
from app.models.user import User
from app.schemas.tag import (
    BulkTagRequest,
    EntryTagsRequest,
    TagCreate,
    TagMergeRequest,
    TagResponse,
    TagUpdate,
)
from app.services.entry_tags import (
    ensure_assignment,
    make_tag_global,
    make_tag_personal,
    merge_assignments,
    sync_entry_tags_to_search,
    visible_to,
)

logger = logging.getLogger(__name__)

router = APIRouter()


async def _reindex_entries_tags(db: AsyncSession, entry_ids: list[uuid.UUID]):
    """Recompute + push the tag fields for these entries to the search index.

    Every tag write ends here: a rename, scope flip, delete or merge can touch
    thousands of entries, a single tag/untag just one. Entries that end up with
    no tags are cleared. Batched in one pass.
    """
    await sync_entry_tags_to_search(db, entry_ids)


def _tag_response(tag: Tag, entry_count: int) -> TagResponse:
    return TagResponse(
        id=tag.id,
        name=tag.name,
        color=tag.color,
        display_as_chip=tag.display_as_chip,
        description=tag.description,
        is_global=tag.is_global,
        entry_count=entry_count,
        created_at=tag.created_at,
    )


async def _visible_entry_count(db: AsyncSession, tag_id: uuid.UUID, user_id: uuid.UUID) -> int:
    """Entries carrying the tag as this user sees them: their own assignments,
    or everyone's if the tag is global."""
    result = await db.execute(
        select(func.count(func.distinct(EntryTag.entry_id))).where(EntryTag.tag_id == tag_id, visible_to(user_id))
    )
    return result.scalar() or 0


@router.get("", response_model=list[TagResponse])
async def list_tags(
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """List all tags with their per-tag entry counts, ordered by name.

    The tag list is shared; the counts are the caller's view (their own
    assignments of a personal tag, everyone's of a global one).
    """
    if user.is_anonymous:
        # A visitor sees global tags only (a personal tag's name is someone's
        # own), counted over visible articles, and none that tags nothing
        # they can read.
        result = await db.execute(
            select(Tag, func.count(func.distinct(EntryTag.entry_id)).label("entry_count"))
            .join(EntryTag, and_(EntryTag.tag_id == Tag.id, visible_to(None)))
            .join(Entry, Entry.id == EntryTag.entry_id)
            .where(Tag.is_global.is_(True))
            .group_by(Tag.id)
            .order_by(Tag.name)
        )
        return [_tag_response(tag, count) for tag, count in result.all()]
    result = await db.execute(
        select(
            Tag,
            func.count(func.distinct(EntryTag.entry_id)).label("entry_count"),
        )
        .outerjoin(EntryTag, and_(EntryTag.tag_id == Tag.id, visible_to(user.id)))
        .group_by(Tag.id)
        .order_by(Tag.name)
    )
    return [_tag_response(tag, count) for tag, count in result.all()]


@router.post("", response_model=TagResponse, status_code=201)
async def create_tag(
    body: TagCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a tag; names are unique (409 on duplicate)."""
    # Check for duplicate name
    existing = await db.execute(
        select(Tag).where(
            Tag.name == body.name,
        )
    )
    if existing.scalar_one_or_none():
        raise AppError(
            code="conflict",
            message="Tag with this name already exists",
            status_code=409,
        )

    tag = Tag(
        created_by=user.id,
        name=body.name,
        color=body.color,
        display_as_chip=body.display_as_chip,
        description=body.description or None,
        is_global=body.is_global,
    )
    db.add(tag)
    await db.flush()
    await db.refresh(tag)
    return _tag_response(tag, 0)


@router.put("/{tag_id}", response_model=TagResponse)
async def update_tag(
    tag_id: uuid.UUID = Path(..., description="Tag UUID"),
    body: TagUpdate = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Rename, recolor, promote/demote, describe, or change the scope of a tag
    (409 if the new name is taken).

    A rename reindexes every tagged entry so `tag:` search stays correct. A
    scope change re-homes the tag's assignments: to global, everyone's rows
    collapse into one shared row per entry; to personal, the shared row is
    handed to every human account as their own. Those entries are reindexed too.
    """
    result = await db.execute(select(Tag).where(Tag.id == tag_id))
    tag = result.scalar_one_or_none()
    if not tag:
        raise AppError(
            code="not_found",
            message="Tag not found",
            status_code=404,
        )

    if body.name is not None:
        # Check for duplicate name
        dup = await db.execute(
            select(Tag).where(
                Tag.name == body.name,
                Tag.id != tag_id,
            )
        )
        if dup.scalar_one_or_none():
            raise AppError(
                code="conflict",
                message="Tag with this name already exists",
                status_code=409,
            )
        tag.name = body.name
    if body.color is not None:
        tag.color = body.color
    if body.display_as_chip is not None:
        tag.display_as_chip = body.display_as_chip
    if body.description is not None:
        tag.description = body.description or None

    reindex: set[uuid.UUID] = set()
    if body.is_global is not None and body.is_global != tag.is_global:
        rehome = make_tag_global if body.is_global else make_tag_personal
        affected = await rehome(db, tag)
        reindex.update(affected)
        # A flip to global publishes everyone's private tagging of this tag to
        # the whole team; worth a line in the log with who did it.
        logger.info(
            "tag %r made %s by user %s (%d entries re-homed)",
            tag.name,
            "global" if body.is_global else "personal",
            user.id,
            len(affected),
        )

    db.add(tag)
    await db.flush()

    # A rename changes the tag name stored on every tagged entry in the search
    # index, and a scope change moves the name between the `tags` and
    # `user_tags` fields — reindex those entries so `tag:` search keeps working.
    if body.name is not None:
        rows = await db.execute(select(EntryTag.entry_id).where(EntryTag.tag_id == tag.id))
        reindex.update(r[0] for r in rows.all())
    if reindex:
        await _reindex_entries_tags(db, list(reindex))

    return _tag_response(tag, await _visible_entry_count(db, tag.id, user.id))


@router.delete("/{tag_id}", status_code=204)
async def delete_tag(
    tag_id: uuid.UUID = Path(..., description="Tag UUID"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete a tag, detaching it from all entries and reindexing them in search."""
    result = await db.execute(select(Tag).where(Tag.id == tag_id))
    tag = result.scalar_one_or_none()
    if not tag:
        raise AppError(
            code="not_found",
            message="Tag not found",
            status_code=404,
        )
    # Capture the affected entries before the cascade removes the links, then
    # reindex them (with the tag gone) so the search index doesn't keep a stale
    # tag name.
    rows = await db.execute(select(EntryTag.entry_id).where(EntryTag.tag_id == tag.id))
    affected = [r[0] for r in rows.all()]
    await db.delete(tag)
    await db.flush()
    await _reindex_entries_tags(db, affected)


@router.post("/entries/bulk-tag")
async def bulk_tag_entries(
    body: BulkTagRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Attach one or more tags to many entries at once; existing assignments and
    unknown tag IDs are skipped. Returns the number of links added.

    Each assignment is the caller's own unless the tag is global.
    """
    tags = (await db.execute(select(Tag).where(Tag.id.in_(body.tag_ids)))).scalars().all()
    added = 0
    for entry_id in body.entry_ids:
        for tag in tags:
            if await ensure_assignment(db, entry_id, tag, user.id):
                added += 1

    await db.flush()
    if added > 0:
        await _reindex_entries_tags(db, body.entry_ids)
    return {"added": added}


@router.post("/entries/bulk-untag")
async def bulk_untag_entries(
    body: BulkTagRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Remove one or more tags from many entries at once — the caller's own
    assignments, or the shared one for a global tag. Other users' assignments
    of a personal tag are left alone."""
    if not body.entry_ids or not body.tag_ids:
        return {"removed": 0}
    result = await db.execute(
        delete(EntryTag).where(
            EntryTag.entry_id.in_(body.entry_ids),
            EntryTag.tag_id.in_(body.tag_ids),
            visible_to(user.id),
        )
    )
    await db.flush()
    await _reindex_entries_tags(db, body.entry_ids)
    return {"removed": result.rowcount or 0}


@router.get("/entries/{entry_id}", response_model=list[TagResponse])
async def get_entry_tags(
    entry_id: uuid.UUID = Path(..., description="Entry UUID"),
    user: User = Depends(get_entry_viewer),
    db: AsyncSession = Depends(get_db),
):
    """List the tags attached to one entry as the caller sees them, ordered by name."""
    result = await db.execute(
        select(Tag)
        .join(EntryTag, EntryTag.tag_id == Tag.id)
        .where(EntryTag.entry_id == entry_id, visible_to(user.id))
        .distinct()
        .order_by(Tag.name)
    )
    return [_tag_response(tag, await _visible_entry_count(db, tag.id, user.id)) for tag in result.scalars().all()]


@router.post("/entries/{entry_id}")
async def add_tags_to_entry(
    entry_id: uuid.UUID = Path(..., description="Entry UUID"),
    body: EntryTagsRequest = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Attach tags to a single entry, skipping ones it already has and unknown tag
    IDs. Returns the number of links added.

    Each assignment is the caller's own unless the tag is global.
    """
    tags = (await db.execute(select(Tag).where(Tag.id.in_(body.tag_ids)))).scalars().all()
    added = 0
    for tag in tags:
        if await ensure_assignment(db, entry_id, tag, user.id):
            added += 1

    await db.flush()
    if added > 0:
        await _reindex_entries_tags(db, [entry_id])
    return {"added": added}


@router.delete("/entries/{entry_id}/{tag_id}", status_code=204)
async def remove_tag_from_entry(
    entry_id: uuid.UUID = Path(..., description="Entry UUID"),
    tag_id: uuid.UUID = Path(..., description="Tag UUID"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Detach one tag from one entry (404 if it isn't assigned).

    Removes what the caller sees: their own assignment, or the shared one for a
    global tag. Another user's assignment of a personal tag stays on their card.
    """
    result = await db.execute(
        delete(EntryTag).where(
            EntryTag.entry_id == entry_id,
            EntryTag.tag_id == tag_id,
            visible_to(user.id),
        )
    )
    if not result.rowcount:
        raise AppError(
            code="not_found",
            message="Tag assignment not found",
            status_code=404,
        )
    await db.flush()
    await _reindex_entries_tags(db, [entry_id])


@router.post("/merge", response_model=TagResponse)
async def merge_tags(
    body: TagMergeRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Fold one or more source tags into a target tag.

    Every article carrying a source tag gains the target tag (if it doesn't
    already) under the target's scope — personal assignments keep their owner,
    and everything collapses to shared rows if the target is global. The source
    tags are deleted and all affected articles are reindexed so search stays
    correct.
    """
    target = (await db.execute(select(Tag).where(Tag.id == body.target_id))).scalar_one_or_none()
    if not target:
        raise AppError(code="not_found", message="Target tag not found", status_code=404)

    sources = [sid for sid in body.source_ids if sid != body.target_id]
    if not sources:
        raise AppError(code="bad_request", message="No source tags to merge", status_code=400)

    affected = await merge_assignments(db, sources, target)
    # Deleting the source tags cascades their EntryTag links (FK ondelete=CASCADE).
    await db.execute(delete(Tag).where(Tag.id.in_(sources)))
    await db.flush()

    await _reindex_entries_tags(db, affected)

    return _tag_response(target, await _visible_entry_count(db, target.id, user.id))
