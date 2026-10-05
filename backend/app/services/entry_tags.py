"""Who sees which tag on an entry, and how that reaches the search index.

The tag list is shared: one `Tag` row per name, with its colour, chip flag and
tooltip. Assignments are not. An `EntryTag` row belongs to the user who applied
the tag (`user_id` set) and nobody else sees it — unless the tag is global, in
which case there is one shared row per entry (`user_id` NULL) that everyone
sees. Every read of an entry's tags on behalf of a user goes through
`visible_to`; every write goes through `ensure_assignment`, which derives the
owner from the tag's scope.

The search index keeps the two apart: `tags` holds the names of global tags on
the document (searchable and faceted, as before) and `user_tags` holds
`"<user_id>:<name>"` tokens for personal assignments, which the query planner
only ever matches against the searcher's own id.
"""

import uuid
from collections.abc import Iterable

from sqlalchemy import ColumnElement, and_, cast, delete, distinct, literal, null, or_, select, true
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.tag import EntryTag, Tag
from app.models.user import User

ASSIGNMENT_UNIQUE = "uq_entry_tags_entry_tag_user"
# A shared row's owner column in INSERT … SELECT: Postgres infers a bare NULL as
# text and refuses to put it in a uuid column, so it is cast.
_NO_OWNER = cast(null(), PG_UUID(as_uuid=True))


class MissingOwner(ValueError):
    """A personal tag was applied with nobody to own the assignment."""

    def __init__(self, tag_name: str):
        super().__init__(f"personal tag '{tag_name}' needs an owner")
        self.tag_name = tag_name


def visible_to(user_id: uuid.UUID | str | None) -> ColumnElement[bool]:
    """Filter clause for the `EntryTag` rows a user can see: global tags'
    shared rows plus their own.

    A shared row (`user_id` NULL) counts only while its tag is global. A stray
    NULL row on a personal tag — a worker that read the tag just before someone
    flipped it — is therefore invisible to everyone rather than published to
    everyone, and the next flip to global and back sweeps it up.

    `None` (no user in context, e.g. an unauthenticated export) sees global
    rows only.
    """
    shared = and_(
        EntryTag.user_id.is_(None),
        EntryTag.tag_id.in_(select(Tag.id).where(Tag.is_global.is_(True))),
    )
    if user_id is None:
        return shared
    return or_(shared, EntryTag.user_id == uuid.UUID(str(user_id)))


def assignment_owner(tag: Tag, user_id: uuid.UUID | str | None) -> uuid.UUID | None:
    """Who an assignment of `tag` belongs to when `user_id` applies it.

    A global tag's assignment is shared (None). A personal tag's assignment
    belongs to the actor; with no actor there is nobody to own it, which the
    caller must surface as "cannot tag" rather than fall back to shared.
    """
    if tag.is_global:
        return None
    if user_id is None:
        raise MissingOwner(tag.name)
    return uuid.UUID(str(user_id))


def owner_clause(owner: uuid.UUID | None) -> ColumnElement[bool]:
    """Match the one row an owner would hold (NULL for a shared row)."""
    return EntryTag.user_id.is_(None) if owner is None else EntryTag.user_id == owner


async def ensure_assignment(db: AsyncSession, entry_id: uuid.UUID, tag: Tag, user_id: uuid.UUID | str | None) -> bool:
    """Put `tag` on `entry_id` under the tag's scope rule. True if a row was added.

    Inserts with ON CONFLICT so the API and a worker tagging the same entry at
    once cannot both see "not there yet" and collide on the unique constraint.
    """
    owner = assignment_owner(tag, user_id)
    stmt = (
        pg_insert(EntryTag)
        .values(id=uuid.uuid4(), entry_id=entry_id, tag_id=tag.id, user_id=owner)
        .on_conflict_do_nothing(constraint=ASSIGNMENT_UNIQUE)
    )
    result = await db.execute(stmt)
    return bool(result.rowcount)


async def load_entry_tags(
    db: AsyncSession, entry_ids: Iterable[uuid.UUID], user_id: uuid.UUID | str | None
) -> dict[uuid.UUID, list[dict]]:
    """The tags each entry carries as `user_id` sees them, for API responses.

    One item per tag, ordered by name: `{id, name, color, display_as_chip,
    description, is_global, personal}`. `personal` is true when the row is the
    user's own assignment (a personal tag); false for a global tag's shared row.
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
                "is_global": tag.is_global,
                "personal": owner is not None,
            }
        elif owner is None:
            # A shared row and the user's own row can coexist briefly while a
            # scope flip is in flight; the shared one wins the label.
            item["personal"] = False
    return {entry_id: list(tags.values()) for entry_id, tags in by_entry.items()}


def personal_tag_token(user_id: uuid.UUID | str, name: str) -> str:
    """The `user_tags` value a personal assignment is indexed under."""
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
        select(EntryTag.entry_id, EntryTag.user_id, Tag.name, Tag.is_global)
        .join(Tag, Tag.id == EntryTag.tag_id)
        .where(EntryTag.entry_id.in_(ids))
    )
    for entry_id, user_id, name, is_global in result.all():
        doc = fields[str(entry_id)]
        if user_id is None:
            # Same rule as visible_to: a shared row only counts while its tag is
            # global, so a stray one on a personal tag is not published either.
            if is_global and name not in doc["tags"]:
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


# ── Scope changes ────────────────────────────────────────
#
# Flipping a tag between personal and global re-homes every assignment it has.
# Both directions insert first and delete second, with ON CONFLICT, so a row
# that already exists in the target shape (a user's own row alongside the
# shared one, or a shared row left by a raced rule) is simply kept.
#
# The INSERT … SELECT statements pass `include_defaults=False`: otherwise
# SQLAlchemy evaluates the model's Python-side `id` default once and stamps
# that single UUID on every selected row. The column's server default
# (`gen_random_uuid()`) mints one per row instead.


async def _entry_ids_for(db: AsyncSession, tag_id: uuid.UUID) -> list[uuid.UUID]:
    rows = await db.execute(select(distinct(EntryTag.entry_id)).where(EntryTag.tag_id == tag_id))
    return [r[0] for r in rows.all()]


async def make_tag_global(db: AsyncSession, tag: Tag) -> list[uuid.UUID]:
    """Collapse everyone's assignments of `tag` into one shared row per entry.

    Returns the entries whose index documents need re-pushing.
    """
    affected = await _entry_ids_for(db, tag.id)
    shared_rows = (
        select(EntryTag.entry_id, EntryTag.tag_id, _NO_OWNER)
        .where(EntryTag.tag_id == tag.id, EntryTag.user_id.isnot(None))
        .distinct()
    )
    await db.execute(
        pg_insert(EntryTag)
        .from_select(["entry_id", "tag_id", "user_id"], shared_rows, include_defaults=False)
        .on_conflict_do_nothing(constraint=ASSIGNMENT_UNIQUE)
    )
    await db.execute(delete(EntryTag).where(EntryTag.tag_id == tag.id, EntryTag.user_id.isnot(None)))
    tag.is_global = True
    return affected


async def make_tag_personal(db: AsyncSession, tag: Tag) -> list[uuid.UUID]:
    """Hand the shared assignments of `tag` to every human account as their own.

    Nobody loses sight of a tag they could see; each can then remove their copy.
    Returns the entries whose index documents need re-pushing.
    """
    affected = await _entry_ids_for(db, tag.id)
    personal_rows = (
        select(EntryTag.entry_id, EntryTag.tag_id, User.id)
        .join(User, true())
        .where(EntryTag.tag_id == tag.id, EntryTag.user_id.is_(None), User.role != "system")
    )
    await db.execute(
        pg_insert(EntryTag)
        .from_select(["entry_id", "tag_id", "user_id"], personal_rows, include_defaults=False)
        .on_conflict_do_nothing(constraint=ASSIGNMENT_UNIQUE)
    )
    await db.execute(delete(EntryTag).where(EntryTag.tag_id == tag.id, EntryTag.user_id.is_(None)))
    tag.is_global = False
    return affected


async def merge_assignments(db: AsyncSession, source_ids: list[uuid.UUID], target: Tag) -> list[uuid.UUID]:
    """Re-home every source tag's assignments onto `target`, under the target's scope.

    Into a global target everything collapses to one shared row per entry. Into
    a personal target, personal rows keep their owner and a global source's
    shared rows fan out to every human account, as `make_tag_personal` does.
    The caller deletes the source tags afterwards (their rows cascade).
    Returns the entries whose index documents need re-pushing.
    """
    rows = await db.execute(select(distinct(EntryTag.entry_id)).where(EntryTag.tag_id.in_(source_ids)))
    affected = [r[0] for r in rows.all()]
    if not affected:
        return affected

    def _insert(select_stmt):
        return (
            pg_insert(EntryTag)
            .from_select(["entry_id", "tag_id", "user_id"], select_stmt, include_defaults=False)
            .on_conflict_do_nothing(constraint=ASSIGNMENT_UNIQUE)
        )

    if target.is_global:
        await db.execute(
            _insert(
                select(EntryTag.entry_id, literal(target.id), _NO_OWNER)
                .where(EntryTag.tag_id.in_(source_ids))
                .distinct()
            )
        )
        return affected

    await db.execute(
        _insert(
            select(EntryTag.entry_id, literal(target.id), EntryTag.user_id)
            .where(EntryTag.tag_id.in_(source_ids), EntryTag.user_id.isnot(None))
            .distinct()
        )
    )
    await db.execute(
        _insert(
            select(EntryTag.entry_id, literal(target.id), User.id)
            .join(User, true())
            .where(EntryTag.tag_id.in_(source_ids), EntryTag.user_id.is_(None), User.role != "system")
            .distinct()
        )
    )
    return affected
