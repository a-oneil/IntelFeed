"""Campaign sources — standing intake owned by the campaign itself.

A *linked saved search* is a query maintained alongside the campaign and owned
by one analyst: it is invisible to their teammates, and it drifts as the
campaign's understanding of its subject moves and the query does not. The three
sources here all belong to the campaign instead.

* ``entity`` — the actor, malware or other entity the campaign names. Every
  article carrying that entity belongs, which is exactly the set the autolinker
  already computes; nothing new has to be matched.
* ``story`` — a thread the campaign already holds part of. A story is a
  persistent object, so "I accepted this story" can mean "and its later waves
  too" rather than a suggestion to re-accept on every wave.
* ``query`` — a query-language string typed into the campaign. This one *does*
  drift the way a saved search does, but it is the only intake that catches
  something nobody has named yet, and being campaign-owned means a teammate can
  read the query, see what it pulled in, and fix or pause it.

All three resolve to a set of entry ids and then take the same path as every
other intake: insert the ones the campaign does not already hold. Deliberately
the *full* claimed set every run rather than a delta — see ``source_entry_ids``.
"""

import uuid
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppError
from app.intelligence.correlation import VALID_ENTITY_TYPES, entry_scope_junction
from app.models.campaign import CampaignEntry, CampaignSource
from app.models.entry import Entry
from app.models.story_thread import StoryThread, StoryThreadEntry

SOURCE_KINDS = ("entity", "story", "query")

#: Entity types a source can follow. ``source_entry_ids`` resolves an entity
#: type through ``entry_scope_junction``, which answers None for a type that
#: owns no entries — a source on one of those would be created and then never
#: add anything, so adding one is refused rather than silently inert.
FOLLOWABLE_ENTITY_TYPES: tuple[str, ...] = tuple(
    sorted(t for t in VALID_ENTITY_TYPES if entry_scope_junction(t) is not None)
)

#: What the campaign page's entity picker may offer: followable *and* findable
#: by name through ``/intelligence/search``. Observables are followable but that
#: endpoint does not search them — they reach a campaign by being promoted in
#: the IOC ledger, not by being typed into a picker.
PICKABLE_ENTITY_TYPES: tuple[str, ...] = tuple(t for t in FOLLOWABLE_ENTITY_TYPES if t != "observable")

#: How much of a query's text to keep as the row's label. The whole query is
#: stored and shown on the row; this only bounds what gets frozen into ``label``
#: for the places that render a source as one short name.
LABEL_MAX = 120


def query_unknown_fields(query: str | None) -> list[str]:
    """Field names this query uses that the query language does not have."""
    from app.search.entry_query import query_unknown_fields as _unknown

    return _unknown(query or "")


def query_parse_error(query: str | None) -> str | None:
    """The parser's complaint about this query, or None if it parses."""
    from app.search.query_parser import ParseError, parse_query

    try:
        parse_query(query or "")
    except ParseError as exc:
        return str(exc)
    return None


def validate_source_target(kind: str, entity_type: str | None, ref_id: uuid.UUID | None, query: str | None) -> None:
    """Refuse a source that could never add anything, before the row exists.

    Three ways to get a permanently inert source, each caught here rather than
    discovered a sweep later: an unknown kind, an entity type with no entry
    junction (``source_entry_ids`` answers the empty set for those forever), and
    a query/ref_id shape that does not match the kind.
    """
    if kind not in SOURCE_KINDS:
        raise AppError(
            code="bad_request",
            message=f"kind must be one of {', '.join(SOURCE_KINDS)}",
            status_code=422,
        )

    if kind == "query":
        if not (query or "").strip():
            raise AppError(code="bad_request", message="query is required for a query source", status_code=422)
        if ref_id is not None:
            raise AppError(code="bad_request", message="a query source takes no ref_id", status_code=422)
        # A query that does not parse resolves to the empty set forever, which
        # is the one failure the analyst cannot see from the row.
        problem = query_parse_error(query)
        if problem:
            raise AppError(code="bad_request", message=f"Query does not parse: {problem}", status_code=422)
        return

    if ref_id is None:
        raise AppError(code="bad_request", message=f"ref_id is required for a {kind} source", status_code=422)
    if query is not None:
        raise AppError(code="bad_request", message=f"a {kind} source takes no query", status_code=422)

    if kind == "entity":
        if not entity_type:
            raise AppError(code="bad_request", message="entity_type is required for an entity source", status_code=422)
        if entity_type not in FOLLOWABLE_ENTITY_TYPES:
            raise AppError(
                code="bad_request",
                message=(
                    f"'{entity_type}' owns no articles, so following it would never add any. "
                    f"Followable types: {', '.join(FOLLOWABLE_ENTITY_TYPES)}"
                ),
                status_code=422,
            )
    elif entity_type is not None:
        raise AppError(code="bad_request", message="entity_type only applies to an entity source", status_code=422)


async def resolve_source_label(
    db: AsyncSession,
    kind: str,
    entity_type: str | None,
    ref_id: uuid.UUID | None,
    query: str | None = None,
) -> str:
    """The target's current name, frozen onto the row at link time.

    A source outlives its target: entities get merged away and threads get
    pruned when their articles age out. Storing the label means a stale row
    still says what it was following instead of rendering as a bare UUID.

    A query source has no target to name, so its label is the query text — the
    one thing that makes the row legible.
    """
    if kind == "query":
        text = (query or "").strip()
        return text if len(text) <= LABEL_MAX else text[: LABEL_MAX - 1].rstrip() + "\u2026"

    if kind == "story":
        title = (await db.execute(select(StoryThread.title).where(StoryThread.id == ref_id))).scalar_one_or_none()
        if title is None:
            raise AppError(code="not_found", message="Story not found", status_code=404)
        return title

    from app.intelligence.correlation import get_entity

    if not entity_type:
        raise AppError(code="bad_request", message="entity_type is required for an entity source", status_code=422)
    entity = await get_entity(db, entity_type, ref_id)
    if entity is None:
        raise AppError(code="not_found", message="Entity not found", status_code=404)
    return getattr(entity, "name", None) or str(ref_id)


async def source_entry_ids(db: AsyncSession, source: CampaignSource) -> set[uuid.UUID]:
    """Every entry this source currently claims — not only the new ones.

    Deliberately the full set rather than a delta: an article can join a story,
    gain an entity link or start matching a query long after it was published,
    and a delta keyed on time would miss it permanently. (The older saved-search
    sweep does diff, which is why an article that gains a link later never
    reaches a campaign through one.) ``sync_source`` is what makes recomputing
    cheap to repeat: it inserts only the ids the campaign does not already hold.
    """
    if source.kind == "query":
        if not (source.query or "").strip():
            return set()
        from app.search.entry_query import search_entry_ids

        _, hit_ids = await search_entry_ids(source.query, db)
        # Meili hands back string ids; a malformed one is dropped rather than
        # raising, because one bad hit must not stop the source syncing.
        out: set[uuid.UUID] = set()
        for hit_id in hit_ids:
            try:
                out.add(uuid.UUID(hit_id))
            except (ValueError, AttributeError, TypeError):
                continue
        return out

    if source.kind == "story":
        rows = await db.execute(select(StoryThreadEntry.entry_id).where(StoryThreadEntry.thread_id == source.ref_id))
        return {row[0] for row in rows.all()}

    scope = entry_scope_junction(source.entity_type or "")
    if scope is None:
        return set()
    junction, fk_col = scope
    rows = await db.execute(select(junction.entry_id).where(fk_col == source.ref_id))
    return {row[0] for row in rows.all()}


async def sync_source(db: AsyncSession, source: CampaignSource, user_id: uuid.UUID | None) -> int:
    """Pull this source's entries into its campaign. Returns how many were new."""
    wanted = await source_entry_ids(db, source)
    if not wanted:
        source.last_synced_at = datetime.now(UTC)
        return 0

    held = {
        row[0]
        for row in (
            await db.execute(
                select(CampaignEntry.entry_id).where(
                    CampaignEntry.campaign_id == source.campaign_id,
                    CampaignEntry.entry_id.in_(wanted),
                )
            )
        ).all()
    }
    # An id whose entry has since been deleted would take the whole insert down
    # with a foreign key error, so the set is confirmed against entries first.
    missing = wanted - held
    real = (
        {row[0] for row in (await db.execute(select(Entry.id).where(Entry.id.in_(missing)))).all()}
        if missing
        else set()
    )

    for entry_id in real:
        db.add(
            CampaignEntry(
                campaign_id=source.campaign_id,
                entry_id=entry_id,
                added_by=user_id,
                notes=f"Added by campaign source: {source.label}",
            )
        )

    source.last_synced_at = datetime.now(UTC)
    source.entries_added = (source.entries_added or 0) + len(real)
    await db.flush()
    return len(real)


async def sync_campaign_sources(db: AsyncSession, campaign_id: uuid.UUID | None = None) -> dict:
    """Run every auto-syncing source, optionally scoped to one campaign.

    Called by the beat-scheduled sweep and by the campaign page's "Run now".
    """
    from app.models.campaign import Campaign

    # Closed and historical campaigns stop collecting — the same rule the
    # saved-search sweep follows. A closed campaign that kept growing would
    # quietly undo the act of closing it.
    query = (
        select(CampaignSource)
        .join(Campaign, Campaign.id == CampaignSource.campaign_id)
        .where(CampaignSource.auto_sync.is_(True), Campaign.status.in_(["active", "monitoring"]))
    )
    if campaign_id is not None:
        query = query.where(CampaignSource.campaign_id == campaign_id)

    sources = (await db.execute(query)).scalars().all()
    added = 0
    for source in sources:
        added += await sync_source(db, source, source.added_by)
    return {"sources": len(sources), "entries_added": added}


async def preview_source(
    db: AsyncSession,
    campaign_id: uuid.UUID,
    kind: str,
    entity_type: str | None = None,
    ref_id: uuid.UUID | None = None,
    query: str | None = None,
    sample: int = 5,
    held: set[uuid.UUID] | None = None,
) -> dict:
    """What following this *would* add, without creating the row.

    The count alone is not enough to decide — following a prolific actor can add
    several hundred articles, and "adds 700" tells you the size of the mistake
    but not whether it is one. The titles are what make the click informed, so
    offers have always carried them; a typed query or a hand-picked entity gets
    the same dry run before the follow exists.
    """
    if held is None:
        held = {
            row[0]
            for row in (
                await db.execute(select(CampaignEntry.entry_id).where(CampaignEntry.campaign_id == campaign_id))
            ).all()
        }
    problem = query_parse_error(query) if kind == "query" else None
    if problem:
        return {
            "kind": kind,
            "entity_type": entity_type,
            "ref_id": None,
            "query": query,
            "would_add": 0,
            "already_held": 0,
            "preview": [],
            "error": problem,
            "unknown_fields": [],
        }

    probe = CampaignSource(
        campaign_id=campaign_id,
        kind=kind,
        entity_type=entity_type,
        ref_id=ref_id,
        query=query,
    )
    claimed = await source_entry_ids(db, probe)
    new_ids = claimed - held
    titles: list[dict] = []
    if new_ids:
        rows = await db.execute(
            select(Entry.id, Entry.title, Entry.published_at)
            .where(Entry.id.in_(new_ids))
            .order_by(Entry.published_at.desc().nullslast())
            .limit(sample)
        )
        titles = [
            {
                "entry_id": str(r.id),
                "title": r.title,
                "published_at": r.published_at.isoformat() if r.published_at else None,
            }
            for r in rows.all()
        ]
    return {
        "kind": kind,
        "entity_type": entity_type,
        "ref_id": str(ref_id) if ref_id else None,
        "query": query,
        "would_add": len(new_ids),
        # Articles it claims that the campaign already holds — the difference
        # between "this source is useless" and "you already did this by hand".
        "already_held": len(claimed) - len(new_ids),
        "preview": titles,
        "error": None,
        # Not fatal, but worth saying: an unknown field silently becomes a text
        # term, and a standing source built on one keeps answering plausibly.
        "unknown_fields": query_unknown_fields(query) if kind == "query" else [],
    }


async def suggested_sources(db: AsyncSession, campaign_id: uuid.UUID, limit: int = 8) -> list[dict]:
    """What this campaign could follow, given what it already holds.

    Entities it has named with a role, and stories it already holds part of —
    the same two things the sources themselves read, offered before they are
    linked. Anything already linked is filtered out. A typed query is never
    suggested — nothing in the campaign implies one.
    """
    from app.models.campaign import CampaignEntity

    linked = {
        (row[0], row[1], row[2])
        for row in (
            await db.execute(
                select(CampaignSource.kind, CampaignSource.entity_type, CampaignSource.ref_id).where(
                    CampaignSource.campaign_id == campaign_id
                )
            )
        ).all()
    }

    held_now = {
        row[0]
        for row in (
            await db.execute(select(CampaignEntry.entry_id).where(CampaignEntry.campaign_id == campaign_id))
        ).all()
    }

    async def _preview(kind: str, entity_type: str | None, ref_id: uuid.UUID) -> tuple[int, list[dict]]:
        """How many this offer would add, and the newest few by name."""
        got = await preview_source(db, campaign_id, kind, entity_type=entity_type, ref_id=ref_id, held=held_now)
        return got["would_add"], got["preview"]

    out: list[dict] = []

    # Curated entities first — the campaign named these itself.
    entity_rows = await db.execute(
        select(CampaignEntity.entity_type, CampaignEntity.entity_id, CampaignEntity.role)
        .where(CampaignEntity.campaign_id == campaign_id)
        .order_by(CampaignEntity.role)
    )
    for entity_type, entity_id, role in entity_rows.all():
        if ("entity", entity_type, entity_id) in linked:
            continue
        try:
            label = await resolve_source_label(db, "entity", entity_type, entity_id)
        except AppError:
            continue
        would_add, preview = await _preview("entity", entity_type, entity_id)
        out.append(
            {
                "kind": "entity",
                "entity_type": entity_type,
                "ref_id": str(entity_id),
                "label": label,
                "why": f"named as {role} in this campaign",
                "would_add": would_add,
                "preview": preview,
            }
        )

    # Then stories it already holds part of.
    story_rows = await db.execute(
        select(
            StoryThread.id,
            StoryThread.title,
            StoryThread.entry_count,
            func.count(func.distinct(StoryThreadEntry.entry_id)).label("held"),
        )
        .join(StoryThreadEntry, StoryThreadEntry.thread_id == StoryThread.id)
        .join(CampaignEntry, CampaignEntry.entry_id == StoryThreadEntry.entry_id)
        .where(CampaignEntry.campaign_id == campaign_id)
        .group_by(StoryThread.id)
        .order_by(func.count(func.distinct(StoryThreadEntry.entry_id)).desc())
        .limit(limit)
    )
    for thread_id, title, entry_count, held in story_rows.all():
        if ("story", None, thread_id) in linked:
            continue
        would_add, preview = await _preview("story", None, thread_id)
        out.append(
            {
                "kind": "story",
                "entity_type": None,
                "ref_id": str(thread_id),
                "label": title,
                "why": f"you hold {held} of {entry_count} articles",
                "would_add": would_add,
                "preview": preview,
            }
        )

    return out[:limit]
