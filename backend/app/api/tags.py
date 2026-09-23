import uuid

from fastapi import APIRouter, Body, Depends, Path
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppError
from app.core.security import get_current_user
from app.database import get_db
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
from app.services import meilisearch_client

router = APIRouter()


async def _sync_entry_tags_to_search(db: AsyncSession, entry_id: uuid.UUID):
    """Fetch current tag names for an entry and update the search index."""
    result = await db.execute(
        select(Tag.name).join(EntryTag, EntryTag.tag_id == Tag.id).where(EntryTag.entry_id == entry_id)
    )
    tag_names = [r[0] for r in result.all()]
    meilisearch_client.update_entry_tags(entry_id, tag_names)


async def _reindex_entries_tags(db: AsyncSession, entry_ids: list[uuid.UUID]):
    """Recompute + push the full tag list for many entries to the search index.

    Used by rename / delete / merge, which change the tag names stored on
    potentially thousands of entries. Entries that end up with no tags are
    cleared (they appear in the map with an empty list). Batched in one pass.
    """
    if not entry_ids:
        return
    tag_map: dict[str, list[str]] = {str(eid): [] for eid in entry_ids}
    result = await db.execute(
        select(EntryTag.entry_id, Tag.name).join(Tag, Tag.id == EntryTag.tag_id).where(EntryTag.entry_id.in_(entry_ids))
    )
    for entry_id, name in result.all():
        tag_map[str(entry_id)].append(name)
    meilisearch_client.bulk_update_entry_tags(tag_map)


@router.get("", response_model=list[TagResponse])
async def list_tags(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all tags with their per-tag entry counts, ordered by name."""
    result = await db.execute(
        select(
            Tag,
            func.count(EntryTag.entry_id).label("entry_count"),
        )
        .outerjoin(EntryTag, EntryTag.tag_id == Tag.id)
        .group_by(Tag.id)
        .order_by(Tag.name)
    )
    items = []
    for tag, count in result.all():
        items.append(
            TagResponse(
                id=tag.id,
                name=tag.name,
                color=tag.color,
                entry_count=count,
                created_at=tag.created_at,
            )
        )
    return items


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
    )
    db.add(tag)
    await db.flush()
    await db.refresh(tag)
    return TagResponse(
        id=tag.id,
        name=tag.name,
        color=tag.color,
        entry_count=0,
        created_at=tag.created_at,
    )


@router.put("/{tag_id}", response_model=TagResponse)
async def update_tag(
    tag_id: uuid.UUID = Path(..., description="Tag UUID"),
    body: TagUpdate = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Rename and/or recolor a tag (409 if the new name is taken). A rename
    reindexes every tagged entry so `tag:` search stays correct."""
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

    db.add(tag)
    await db.flush()

    # A rename changes the tag name stored on every tagged entry in the search
    # index — reindex them so `tag:` search keeps working.
    if body.name is not None:
        rows = await db.execute(select(EntryTag.entry_id).where(EntryTag.tag_id == tag.id))
        await _reindex_entries_tags(db, [r[0] for r in rows.all()])

    # Get entry count
    count_result = await db.execute(select(func.count()).select_from(EntryTag).where(EntryTag.tag_id == tag.id))
    count = count_result.scalar() or 0

    return TagResponse(
        id=tag.id,
        name=tag.name,
        color=tag.color,
        entry_count=count,
        created_at=tag.created_at,
    )


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
    unknown tag IDs are skipped. Returns the number of links added."""
    added = 0
    for entry_id in body.entry_ids:
        for tag_id in body.tag_ids:
            # Verify tag exists
            tag_result = await db.execute(select(Tag).where(Tag.id == tag_id))
            if not tag_result.scalar_one_or_none():
                continue

            existing = await db.execute(
                select(EntryTag).where(
                    EntryTag.entry_id == entry_id,
                    EntryTag.tag_id == tag_id,
                )
            )
            if not existing.scalar_one_or_none():
                db.add(
                    EntryTag(
                        entry_id=entry_id,
                        tag_id=tag_id,
                    )
                )
                added += 1

    await db.flush()
    if added > 0:
        for entry_id in body.entry_ids:
            await _sync_entry_tags_to_search(db, entry_id)
    return {"added": added}


@router.post("/entries/bulk-untag")
async def bulk_untag_entries(
    body: BulkTagRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Remove one or more tags from many entries at once."""
    if not body.entry_ids or not body.tag_ids:
        return {"removed": 0}
    result = await db.execute(
        delete(EntryTag).where(
            EntryTag.entry_id.in_(body.entry_ids),
            EntryTag.tag_id.in_(body.tag_ids),
        )
    )
    await db.flush()
    await _reindex_entries_tags(db, body.entry_ids)
    return {"removed": result.rowcount or 0}


@router.get("/entries/{entry_id}", response_model=list[TagResponse])
async def get_entry_tags(
    entry_id: uuid.UUID = Path(..., description="Entry UUID"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List the tags attached to one entry, ordered by name."""
    result = await db.execute(
        select(Tag).join(EntryTag, EntryTag.tag_id == Tag.id).where(EntryTag.entry_id == entry_id).order_by(Tag.name)
    )
    tags = result.scalars().all()
    items = []
    for tag in tags:
        count_result = await db.execute(select(func.count()).select_from(EntryTag).where(EntryTag.tag_id == tag.id))
        count = count_result.scalar() or 0
        items.append(
            TagResponse(
                id=tag.id,
                name=tag.name,
                color=tag.color,
                entry_count=count,
                created_at=tag.created_at,
            )
        )
    return items


@router.post("/entries/{entry_id}")
async def add_tags_to_entry(
    entry_id: uuid.UUID = Path(..., description="Entry UUID"),
    body: EntryTagsRequest = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Attach tags to a single entry, skipping ones it already has and unknown tag
    IDs. Returns the number of links added."""
    added = 0
    for tag_id in body.tag_ids:
        # Verify tag exists
        tag_result = await db.execute(select(Tag).where(Tag.id == tag_id))
        if not tag_result.scalar_one_or_none():
            continue

        # Check if already exists
        existing = await db.execute(
            select(EntryTag).where(
                EntryTag.entry_id == entry_id,
                EntryTag.tag_id == tag_id,
            )
        )
        if not existing.scalar_one_or_none():
            db.add(
                EntryTag(
                    entry_id=entry_id,
                    tag_id=tag_id,
                )
            )
            added += 1

    await db.flush()
    if added > 0:
        await _sync_entry_tags_to_search(db, entry_id)
    return {"added": added}


@router.delete("/entries/{entry_id}/{tag_id}", status_code=204)
async def remove_tag_from_entry(
    entry_id: uuid.UUID = Path(..., description="Entry UUID"),
    tag_id: uuid.UUID = Path(..., description="Tag UUID"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Detach one tag from one entry (404 if it isn't assigned)."""
    result = await db.execute(
        select(EntryTag).where(
            EntryTag.entry_id == entry_id,
            EntryTag.tag_id == tag_id,
        )
    )
    et = result.scalar_one_or_none()
    if not et:
        raise AppError(
            code="not_found",
            message="Tag assignment not found",
            status_code=404,
        )
    await db.delete(et)
    await db.flush()
    await _sync_entry_tags_to_search(db, entry_id)


@router.post("/merge", response_model=TagResponse)
async def merge_tags(
    body: TagMergeRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Fold one or more source tags into a target tag.

    Every article carrying a source tag gains the target tag (if it doesn't
    already), the source tags are deleted, and all affected articles are
    reindexed so search stays correct.
    """
    target = (await db.execute(select(Tag).where(Tag.id == body.target_id))).scalar_one_or_none()
    if not target:
        raise AppError(code="not_found", message="Target tag not found", status_code=404)

    sources = [sid for sid in body.source_ids if sid != body.target_id]
    if not sources:
        raise AppError(code="bad_request", message="No source tags to merge", status_code=400)

    # Entries currently on any source tag, and those already on the target.
    src_rows = await db.execute(select(EntryTag.entry_id).where(EntryTag.tag_id.in_(sources)).distinct())
    on_source = {r[0] for r in src_rows.all()}
    tgt_rows = await db.execute(select(EntryTag.entry_id).where(EntryTag.tag_id == body.target_id))
    on_target = {r[0] for r in tgt_rows.all()}

    db.add_all([EntryTag(entry_id=eid, tag_id=body.target_id) for eid in (on_source - on_target)])
    # Deleting the source tags cascades their EntryTag links (FK ondelete=CASCADE).
    await db.execute(delete(Tag).where(Tag.id.in_(sources)))
    await db.flush()

    await _reindex_entries_tags(db, list(on_source))

    count = (
        await db.execute(select(func.count()).select_from(EntryTag).where(EntryTag.tag_id == target.id))
    ).scalar() or 0
    return TagResponse(
        id=target.id,
        name=target.name,
        color=target.color,
        entry_count=count,
        created_at=target.created_at,
    )
