"""Who sees which tag on an entry, and how that reaches the search index.

An `EntryTag` row is either shared (`user_id` NULL — everything tagged by hand
and every plain tag a rule applies) or a personal stamp (`user_id` set — a chip
an automation rule applied for its owner). Every read of an entry's tags on
behalf of a user goes through `visible_to`, so a personal stamp never leaks
onto another analyst's card, count, or search.

The search index keeps the two apart: `tags` holds shared names (searchable and
faceted, as before) and `user_tags` holds `"<user_id>:<name>"` tokens, which
the query planner only ever matches against the searcher's own id.
"""

import uuid
from collections.abc import Iterable

from sqlalchemy import ColumnElement, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.tag import EntryTag, Tag


def visible_to(user_id: uuid.UUID | str | None) -> ColumnElement[bool]:
    """Filter clause for the `EntryTag` rows a user can see.

    `None` (no user in context, e.g. an export or an admin-wide count) sees
    shared rows only.
    """
    if user_id is None:
        return EntryTag.user_id.is_(None)
    return or_(EntryTag.user_id.is_(None), EntryTag.user_id == uuid.UUID(str(user_id)))


async def load_entry_tags(
    db: AsyncSession, entry_ids: Iterable[uuid.UUID], user_id: uuid.UUID | str | None
) -> dict[uuid.UUID, list[dict]]:
    """The tags each entry carries as `user_id` sees them, for API responses.

    One item per tag, ordered by name: `{id, name, color, display_as_chip,
    description, personal}`. `personal` is true only when the tag is on the
    entry solely as the user's own stamp.
    """
    ids = list(entry_ids)
    if not ids:
        return {}
    result = await db.execute(
        select(EntryTag.entry_id, EntryTag.user_id, Tag)
        .join(Tag, Tag.id == EntryTag.tag_id)
        .where(EntryTag.entry_id.in_(ids), visible_to(user_id))
        .order_by(Tag.name)
    )
    by_entry: dict[uuid.UUID, dict[uuid.UUID, dict]] = {}
    for entry_id, owner, tag in result.all():
        tags = by_entry.setdefault(entry_id, {})
        item = tags.get(tag.id)
        if item is None:
            tags[tag.id] = {
                "id": str(tag.id),
                "name": tag.name,
                "color": tag.color,
                "display_as_chip": tag.display_as_chip,
                "description": tag.description,
                "personal": owner is not None,
            }
        elif owner is None:
            item["personal"] = False
    return {entry_id: list(tags.values()) for entry_id, tags in by_entry.items()}


def personal_tag_token(user_id: uuid.UUID | str, name: str) -> str:
    """The `user_tags` value a personal stamp is indexed under."""
    return f"{user_id}:{name}"


async def search_tag_fields(db: AsyncSession, entry_ids: Iterable[uuid.UUID]) -> dict[str, dict[str, list[str]]]:
    """`{"tags": [...], "user_tags": [...]}` per entry, ready for the index.

    Every requested entry appears, so one that lost its last tag is cleared.
    """
    ids = list(entry_ids)
    fields: dict[str, dict[str, list[str]]] = {str(eid): {"tags": [], "user_tags": []} for eid in ids}
    if not ids:
        return fields
    result = await db.execute(
        select(EntryTag.entry_id, EntryTag.user_id, Tag.name)
        .join(Tag, Tag.id == EntryTag.tag_id)
        .where(EntryTag.entry_id.in_(ids))
    )
    for entry_id, user_id, name in result.all():
        doc = fields[str(entry_id)]
        if user_id is None:
            if name not in doc["tags"]:
                doc["tags"].append(name)
        else:
            doc["user_tags"].append(personal_tag_token(user_id, name))
    return fields


async def sync_entry_tags_to_search(db: AsyncSession, entry_ids: Iterable[uuid.UUID]) -> None:
    """Recompute and push the tag fields for these entries (best-effort)."""
    from app.services import meilisearch_client

    fields = await search_tag_fields(db, entry_ids)
    if fields:
        meilisearch_client.bulk_update_entry_tags(fields)
