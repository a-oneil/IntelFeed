"""Campaign sources — intake that follows what a campaign has already declared.

A linked saved search is a query maintained alongside the campaign, and it
drifts: the campaign's understanding of its subject moves and the query does
not. The two sources here read the campaign's own curation instead.

* ``entity`` — the actor, malware or other entity the campaign names. Every
  article carrying that entity belongs, which is exactly the set the autolinker
  already computes; nothing new has to be matched.
* ``story`` — a thread the campaign already holds part of. A story is a
  persistent object, so "I accepted this story" can mean "and its later waves
  too" rather than a suggestion to re-accept on every wave.

Both resolve to a set of entry ids and then take the same path as every other
intake: insert the ones the campaign does not already hold.
"""

import uuid
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppError
from app.intelligence.correlation import entry_scope_junction
from app.models.campaign import CampaignEntry, CampaignSource
from app.models.entry import Entry
from app.models.story_thread import StoryThread, StoryThreadEntry

SOURCE_KINDS = ("entity", "story")


async def resolve_source_label(db: AsyncSession, kind: str, entity_type: str | None, ref_id: uuid.UUID) -> str:
    """The target's current name, frozen onto the row at link time.

    A source outlives its target: entities get merged away and threads get
    pruned when their articles age out. Storing the label means a stale row
    still says what it was following instead of rendering as a bare UUID.
    """
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

    Deliberately the full set rather than a delta: an article can join a story
    or gain an entity link long after it was published, and a delta keyed on
    time would miss it permanently.
    """
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


async def suggested_sources(db: AsyncSession, campaign_id: uuid.UUID, limit: int = 8) -> list[dict]:
    """What this campaign could follow, given what it already holds.

    Entities it has named with a role, and stories it already holds part of —
    the same two things the sources themselves read, offered before they are
    linked. Anything already linked is filtered out.
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
        """What linking this would pull in: how many, and the newest few by name.

        The count alone is not enough to decide — following a prolific actor can
        add several hundred articles, and "adds 700" tells you the size of the
        mistake but not whether it is one. The titles are what make the click
        informed.
        """
        probe = CampaignSource(campaign_id=campaign_id, kind=kind, entity_type=entity_type, ref_id=ref_id)
        new_ids = await source_entry_ids(db, probe) - held_now
        if not new_ids:
            return 0, []
        rows = await db.execute(
            select(Entry.id, Entry.title, Entry.published_at)
            .where(Entry.id.in_(new_ids))
            .order_by(Entry.published_at.desc().nullslast())
            .limit(5)
        )
        return len(new_ids), [
            {
                "entry_id": str(r.id),
                "title": r.title,
                "published_at": r.published_at.isoformat() if r.published_at else None,
            }
            for r in rows.all()
        ]

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
