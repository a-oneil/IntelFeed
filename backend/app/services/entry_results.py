"""What the pipeline found in one entry, and the story it belongs to.

For the browser extension: after it sends a page it polls ``results`` until
the pipeline is done, then tells the sender what came out of it. ``thread``
also feeds the URL lookup, so a page already in IntelFeed shows its story.
"""

import re
import uuid
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.cve import CVE, EntryCVE
from app.models.detection_rule import DetectionRule
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.observable import EntryObservable, Observable
from app.models.story_thread import StoryThread, StoryThreadEntry
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.tool import EntryTool, Tool
from app.models.ttp import TTP, EntryTTP

# Maximum names returned per entity type.
LIST_CAP = 12


async def visible_entry(db: AsyncSession, entry_id: uuid.UUID, user_id) -> Entry | None:
    """The entry, when the user can see its feed (or it is on Manual Uploads)."""
    from app.services.feed_visibility import subscriptions_enabled, visible_feed_ids_query
    from app.services.manual_ingest import MANUAL_FEED_URL

    visible = visible_feed_ids_query(user_id, enabled=await subscriptions_enabled(db), include_muted=True)
    manual = select(Feed.id).where(Feed.url == MANUAL_FEED_URL)
    return (
        await db.execute(select(Entry).where(Entry.id == entry_id, Entry.feed_id.in_(visible.union(manual))))
    ).scalar_one_or_none()


async def entry_thread(db: AsyncSession, entry_id: uuid.UUID) -> dict | None:
    """The story thread this entry belongs to (an entry joins at most one)."""
    row = (
        await db.execute(
            select(StoryThread.slug, StoryThread.title, StoryThread.entry_count, StoryThread.source_count)
            .join(StoryThreadEntry, StoryThreadEntry.thread_id == StoryThread.id)
            .where(StoryThreadEntry.entry_id == entry_id)
        )
    ).first()
    return None if row is None else _thread_ref(row)


def _thread_ref(thread) -> dict:
    return {
        "slug": thread.slug,
        "title": thread.title,
        "entry_count": thread.entry_count,
        "source_count": thread.source_count,
    }


async def entry_findings(db: AsyncSession, entry_id: uuid.UUID) -> dict:
    """Entities, rules and indicators linked to the entry."""

    async def names(model, junction, fk) -> list[dict]:
        rows = await db.execute(
            select(model.id, model.name)
            .join(junction, fk == model.id)
            .where(junction.entry_id == entry_id)
            .order_by(model.name)
            .limit(LIST_CAP)
        )
        return [{"id": str(i), "name": n} for i, n in rows.all()]

    cves = await db.execute(
        select(CVE.id, CVE.cve_id, CVE.cvss_score)
        .join(EntryCVE, EntryCVE.cve_id == CVE.id)
        .where(EntryCVE.entry_id == entry_id)
        .order_by(CVE.cvss_score.desc().nulls_last(), CVE.cve_id)
        .limit(LIST_CAP)
    )
    ttps = await db.execute(
        select(TTP.id, TTP.technique_id, TTP.technique_name)
        .join(EntryTTP, EntryTTP.ttp_id == TTP.id)
        .where(EntryTTP.entry_id == entry_id)
        .order_by(TTP.technique_id)
        .limit(LIST_CAP)
    )
    # A rule counts when it was drawn from this entry, or lists it among its sources.
    rule_count = (
        await db.execute(
            select(func.count())
            .select_from(DetectionRule)
            .where(or_(DetectionRule.entry_id == entry_id, DetectionRule.source_entries.any(entry_id)))
        )
    ).scalar() or 0
    observable_count = (
        await db.execute(
            select(func.count())
            .select_from(EntryObservable)
            .join(Observable, Observable.id == EntryObservable.observable_id)
            .where(EntryObservable.entry_id == entry_id, Observable.is_denied.is_(False))
        )
    ).scalar() or 0
    return {
        "actors": await names(ThreatActor, EntryThreatActor, EntryThreatActor.threat_actor_id),
        "malware": await names(MalwareFamily, EntryMalware, EntryMalware.malware_family_id),
        "tools": await names(Tool, EntryTool, EntryTool.tool_id),
        "cves": [
            {"id": str(i), "cve_id": c, "cvss_score": float(s) if s is not None else None} for i, c, s in cves.all()
        ],
        "ttps": [{"id": str(i), "technique_id": t, "name": n} for i, t, n in ttps.all()],
        "rule_count": rule_count,
        "observable_count": observable_count,
    }


# Coverage of a page that is not in IntelFeed yet.


def _outlet(url: str | None, feed_id) -> str:
    """The outlet is the entry URL's host without ``www.``, as story threads count sources.
    An entry with no URL counts as its own outlet, keyed by feed."""
    host = (urlsplit(url).hostname or "") if url else ""
    return host.removeprefix("www.") or str(feed_id)


COVERAGE_DAYS = 14


async def page_coverage(db: AsyncSession, user_id, *, title: str, url: str | None) -> dict:
    """Recent entries the user can see that tell the same story as an unsent page.

    Keyword search on the page title (the reader's "More like this" keyword
    path), kept to the last COVERAGE_DAYS days and to hits whose titles share
    enough of those keywords, then counted by outlet rather than feed row.
    """
    from app.services import meilisearch_client
    from app.services.feed_visibility import subscriptions_enabled, visible_feed_ids_query
    from app.services.manual_ingest import strip_fragment

    empty = {"outlet_count": 0, "entries": [], "thread": None}
    if len(title.split()) < 3:
        return empty
    since = int((datetime.now(UTC) - timedelta(days=COVERAGE_DAYS)).timestamp())
    found = meilisearch_client.find_similar_entries(
        entry_id="", title=title, limit=30, filter=f"published_at >= {since}"
    )
    keywords = set(found.get("query_keywords") or [])
    if not keywords:
        return empty
    need = max(2, -(-len(keywords) * 2 // 5))  # at least 40% of the keywords, and never fewer than two
    ids = []
    for hit in found.get("hits", []):
        words = set(re.findall(r"[a-zA-Z0-9\-]{3,}", (hit.get("title") or "").lower()))
        if len(words & keywords) >= need:
            ids.append(hit["id"])
    if not ids:
        return empty

    visible = visible_feed_ids_query(user_id, enabled=await subscriptions_enabled(db), include_muted=True)
    rows = (
        await db.execute(
            select(Entry.id, Entry.title, Entry.url, Entry.published_at, Entry.feed_id, Feed.title.label("feed_title"))
            .join(Feed, Feed.id == Entry.feed_id)
            .where(Entry.id.in_([uuid.UUID(i) for i in ids]), Entry.feed_id.in_(visible))
        )
    ).all()
    if url:
        bare = strip_fragment(url)
        rows = [r for r in rows if strip_fragment(r.url or "") != bare]
    if not rows:
        return empty
    order = {i: n for n, i in enumerate(ids)}
    rows.sort(key=lambda r: order.get(str(r.id), 0))

    # The thread most of the hits sit in, if any.
    threads = (
        await db.execute(
            select(StoryThreadEntry.thread_id, func.count())
            .where(StoryThreadEntry.entry_id.in_([r.id for r in rows]))
            .group_by(StoryThreadEntry.thread_id)
            .order_by(func.count().desc())
            .limit(1)
        )
    ).first()
    thread = None
    if threads is not None:
        thread = _thread_ref((await db.execute(select(StoryThread).where(StoryThread.id == threads[0]))).scalar_one())

    return {
        "outlet_count": len({_outlet(r.url, r.feed_id) for r in rows}),
        "entries": [
            {"id": str(r.id), "title": r.title, "feed_title": r.feed_title, "published_at": r.published_at}
            for r in rows[:5]
        ],
        "thread": thread,
    }
