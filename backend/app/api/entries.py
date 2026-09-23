import base64
import json
import uuid
from datetime import UTC, date, datetime, timedelta

import structlog
from fastapi import APIRouter, Depends, Path, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import and_, case, false, func, insert, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app import entity_types
from app.core.exceptions import AppError
from app.core.pagination import CursorPaginatedResponse
from app.core.security import get_current_user
from app.database import get_db
from app.intelligence import story_threads
from app.intelligence.sectors import sector_label
from app.models.country import Country, EntryCountry
from app.models.cve import CVE, EntryCVE
from app.models.entry import Entry
from app.models.entry_media import EntryMedia
from app.models.entry_sector import EntrySector
from app.models.entry_state import UserEntryState
from app.models.feed import Feed
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.mitigation import EntryMitigation, Mitigation
from app.models.product import EntryProduct, Product
from app.models.tag import EntryTag, Tag
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.tool import EntryTool, Tool
from app.models.ttp import TTP, EntryTTP
from app.models.user import User
from app.models.vendor import EntryVendor, Vendor
from app.schemas.atlas import CalendarBucket, MapBucket
from app.schemas.entry import (
    BulkActionRequest,
    EchoOf,
    EntryDetailResponse,
    EntryDuplicate,
    EntryMediaBrief,
    EntryResponse,
    MarkAllReadRequest,
    TranslateEntryResponse,
)
from app.schemas.media import EntryMediaResponse
from app.schemas.priority_queue import PriorityQueueResponse, PriorityQueueRow
from app.schemas.thread import ThreadSummary
from app.services import meilisearch_client, translation
from app.services.atlas import build_atlas_entry_id_query
from app.services.feed_visibility import subscriptions_enabled, visible_feed_ids_query
from app.services.iso_codes import ALPHA2_TO_ALPHA3
from app.services.read_state import has_no_state_for_user
from app.services.system_settings import get_setting
from app.services.triage import get_triage_entries

# Entries that arrive already older than this (backdated publish date vs. when we
# first fetched them — e.g. NVD backfilling old CVEs, blogs reposting old content)
# are treated as already-read for the Hide-Read view so they don't sink to the
# bottom of the feed as stray unread stragglers. Tunable; promote to a system
# setting if it needs to be UI-editable.
_STALE_ON_ARRIVAL_DAYS = 14

_VALID_COUNTRY_ROLES = {"origin", "target", "infrastructure", "mentioned"}

_CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}
_ENTITY_TOP_QUERIES: list[tuple[str, type, str, type, object]] = [
    (
        "threat_actor",
        EntryThreatActor,
        "threat_actor_id",
        ThreatActor,
        ThreatActor.name,
    ),
    ("malware", EntryMalware, "malware_family_id", MalwareFamily, MalwareFamily.name),
    ("cve", EntryCVE, "cve_id", CVE, CVE.cve_id),
    ("ttp", EntryTTP, "ttp_id", TTP, TTP.technique_id),
    ("vendor", EntryVendor, "vendor_id", Vendor, Vendor.name),
    ("product", EntryProduct, "product_id", Product, Product.name),
    ("country", EntryCountry, "country_id", Country, Country.name),
]

router = APIRouter()
logger = structlog.get_logger("app.entries")


def _actively_exploited_cve_ids():
    """CVE ids that count as *actively exploited* — one definition, two readers.

    The day-divider's "N actively exploited" signal and the entry filter behind
    clicking it both read this, so the badge's number and the list it opens can
    never drift apart. KEV membership and an explicit active-exploitation
    reading are separate columns: NVD/CISA sets the first, analysts and the
    extraction pipeline set the second, and either one alone is enough.
    """
    return select(CVE.id).where(or_(CVE.is_kev.is_(True), CVE.exploit_availability == "active_exploitation"))


def _exploited_cve_entry_ids():
    """Entry ids mentioning at least one actively-exploited CVE."""
    return select(EntryCVE.entry_id).where(EntryCVE.cve_id.in_(_actively_exploited_cve_ids()))


#: Entity type → (entry-id column, entity-id column) on its entry junction table.
#: The reader's day-divider chips filter the list through this: every chip names
#: an entity, and clicking one asks for that day's entries linked to it. Keyed by
#: the canonical slugs so the query param speaks the same vocabulary as the rest
#: of the app. CWE, ransomware victims and observables are absent because they
#: have no direct entry junction.
_ENTRY_ENTITY_LINKS: dict[str, tuple] = {
    entity_types.THREAT_ACTOR: (EntryThreatActor.entry_id, EntryThreatActor.threat_actor_id),
    entity_types.MALWARE: (EntryMalware.entry_id, EntryMalware.malware_family_id),
    entity_types.CVE: (EntryCVE.entry_id, EntryCVE.cve_id),
    entity_types.TTP: (EntryTTP.entry_id, EntryTTP.ttp_id),
    entity_types.VENDOR: (EntryVendor.entry_id, EntryVendor.vendor_id),
    entity_types.PRODUCT: (EntryProduct.entry_id, EntryProduct.product_id),
    entity_types.COUNTRY: (EntryCountry.entry_id, EntryCountry.country_id),
    entity_types.TOOL: (EntryTool.entry_id, EntryTool.tool_id),
    entity_types.MITIGATION: (EntryMitigation.entry_id, EntryMitigation.mitigation_id),
}


def _validate_entity_filter(entity_type: str | None, entity_id: uuid.UUID | None) -> None:
    """Both halves of the entity filter are required, and the type must be linkable."""
    if entity_type is None and entity_id is None:
        return
    if entity_type is None or entity_id is None:
        raise AppError(
            code="bad_request",
            message="entity_type and entity_id must be given together",
            status_code=422,
        )
    if entity_type not in _ENTRY_ENTITY_LINKS:
        raise AppError(
            code="bad_request",
            message=f"Unsupported entity_type: {entity_type}. "
            f"Expected one of: {', '.join(sorted(_ENTRY_ENTITY_LINKS))}",
            status_code=422,
        )


def _apply_entity_filters(query, entity_type: str | None, entity_id: uuid.UUID | None, sector: str | None):
    """Narrow a list/count query to entries linked to one entity or sector."""
    if entity_type is not None and entity_id is not None:
        entry_col, id_col = _ENTRY_ENTITY_LINKS[entity_type]
        query = query.where(Entry.id.in_(select(entry_col).where(id_col == entity_id)))
    if sector:
        query = query.where(Entry.id.in_(select(EntrySector.entry_id).where(EntrySector.sector == sector)))
    return query


def _exclude_stale_on_arrival(query):
    """Drop entries that arrived already older than ``_STALE_ON_ARRIVAL_DAYS``.

    Backdated content (an old ``published_at`` fetched only now) otherwise sinks to
    the bottom of the feed as stray unread stragglers you never scroll to. We treat
    it as already-read for unread views only — it stays visible when Hide-Read is
    off (sorted by its publish date) and is always reachable via search. Entries
    with no publish date are never considered stale.
    """
    return query.where(
        or_(
            Entry.published_at.is_(None),
            Entry.published_at >= Entry.fetched_at - timedelta(days=_STALE_ON_ARRIVAL_DAYS),
        )
    )


@router.get("/triage")
async def triage_queue(
    days: int = Query(7, ge=1, le=30, description="Lookback window in days"),
    limit: int = Query(50, ge=1, le=500, description="Maximum entries to return"),
    offset: int = Query(0, ge=0, description="Number of entries to skip (paging)"),
    mode: str | None = Query(
        None,
        pattern="^(legacy|signals)$",
        description="Ranking implementation; defaults to signals when signal_engine_surface is on, else legacy",
    ),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Priority-scored entry queue for analyst triage.

    mode=signals returns the signal-engine ranking (shadow validation while
    signal_engine_surface is off; becomes the default path in phase 3).
    """
    if mode is None:
        surface = bool(await get_setting("signal_engine_surface", db))
        mode = "signals" if surface else "legacy"
    if mode == "signals":
        from app.services.triage import get_triage_entries_signals

        return await get_triage_entries_signals(
            db,
            user.id,
            days=days,
            limit=limit,
            offset=offset,
            user_id_for_watches=user.id,
        )
    return await get_triage_entries(
        db,
        user.id,
        days=days,
        limit=limit,
        offset=offset,
        user_settings=user.settings,
    )


def _normalize_iso(code: str | None) -> str | None:
    if code is None:
        return None
    code = code.strip().upper()
    if len(code) == 3:
        return code
    if len(code) == 2:
        return ALPHA2_TO_ALPHA3.get(code)
    return None


@router.get("/calendar", response_model=list[CalendarBucket], response_model_exclude_none=True)
async def calendar_buckets(
    from_: date = Query(..., alias="from", description="Range start date, inclusive (YYYY-MM-DD)"),
    to: date = Query(..., description="Range end date, inclusive; at most 366 days after `from`"),
    feed_id: uuid.UUID | None = Query(None, description="Restrict to entries from this feed"),
    category_id: uuid.UUID | None = Query(None, description="Restrict to feeds in this category"),
    entity_type: str | None = Query(
        None,
        description=("With entity_id: entity type (threat_actor, malware, cve, ttp, vendor, product, country)"),
    ),
    entity_id: uuid.UUID | None = Query(None, description="Restrict to entries linked to this entity"),
    region: str | None = Query(None, description="Restrict to entries linked to countries in this region"),
    saved_search_id: uuid.UUID | None = Query(None, description="Restrict to entries matching this saved search"),
    campaign_id: uuid.UUID | None = Query(None, description="Restrict to entries attached to this campaign"),
    with_top_entities: bool = Query(
        False, description="Attach each day's 10 most-mentioned entities (range limited to 92 days)"
    ),
    tz: str | None = Query(None, description="Accepted for API symmetry; currently unused — days bucket by UTC date"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Per-day entry counts over a date range for the Atlas calendar view.

    Applies the shared Atlas filters (feed/category/entity/region/saved
    search/campaign); with_top_entities additionally attaches the day's
    most-mentioned entities. Days with zero matching entries are omitted.
    """
    days = (to - from_).days
    if days < 0 or days > 366:
        raise AppError(
            code="bad_request",
            message="Date range too large (max 366 days)",
            status_code=422,
        )
    if with_top_entities and days > 92:
        raise AppError(
            code="bad_request",
            message="Date range too large for top_entities (max 92 days)",
            status_code=422,
        )

    base_query = await build_atlas_entry_id_query(
        db,
        from_=from_,
        to=to,
        feed_id=feed_id,
        category_id=category_id,
        entity_type=entity_type,
        entity_id=entity_id,
        region=region,
        campaign_id=campaign_id,
        saved_search_id=saved_search_id,
    )
    if base_query is None:
        return []

    base_subq = base_query.subquery()
    date_col = func.date(Entry.published_at).label("d")
    q = (
        select(date_col, func.count(Entry.id).label("c"))
        .where(Entry.id.in_(select(base_subq.c.id)))
        .group_by(date_col)
        .order_by(date_col)
    )
    rows = (await db.execute(q)).all()
    buckets: list[dict] = [{"date": r.d, "entry_count": r.c} for r in rows]

    if with_top_entities and buckets:
        per_day: dict[date, list[dict]] = {b["date"]: [] for b in buckets}
        for (
            type_name,
            junction_cls,
            fk_col,
            entity_cls,
            name_col,
        ) in _ENTITY_TOP_QUERIES:
            entity_id_col = getattr(junction_cls, fk_col)
            q_top = (
                select(
                    func.date(Entry.published_at).label("d"),
                    entity_id_col.label("eid"),
                    name_col.label("ename"),
                    func.count(func.distinct(Entry.id)).label("c"),
                )
                .join(junction_cls, junction_cls.entry_id == Entry.id)
                .join(entity_cls, entity_cls.id == entity_id_col)
                .where(Entry.id.in_(select(base_subq.c.id)))
                .group_by(func.date(Entry.published_at), entity_id_col, name_col)
            )
            for r in (await db.execute(q_top)).all():
                if r.d in per_day:
                    per_day[r.d].append({"type": type_name, "id": r.eid, "name": r.ename, "count": r.c})

        for bucket in buckets:
            items = per_day.get(bucket["date"], [])
            items.sort(key=lambda x: (-x["count"], x["name"]))
            bucket["top_entities"] = items[:10]

    return buckets


@router.get("/map", response_model=list[MapBucket])
async def map_buckets(
    from_: date = Query(..., alias="from", description="Range start date, inclusive (YYYY-MM-DD)"),
    to: date = Query(..., description="Range end date, inclusive; at most 366 days after `from`"),
    feed_id: uuid.UUID | None = Query(None, description="Restrict to entries from this feed"),
    category_id: uuid.UUID | None = Query(None, description="Restrict to feeds in this category"),
    entity_type: str | None = Query(
        None,
        description=("With entity_id: entity type (threat_actor, malware, cve, ttp, vendor, product, country)"),
    ),
    entity_id: uuid.UUID | None = Query(None, description="Restrict to entries linked to this entity"),
    region: str | None = Query(None, description="Restrict to entries linked to countries in this region"),
    saved_search_id: uuid.UUID | None = Query(None, description="Restrict to entries matching this saved search"),
    campaign_id: uuid.UUID | None = Query(None, description="Restrict to entries attached to this campaign"),
    role: list[str] | None = Query(
        default=None,
        description="Count only entry–country links with these roles (origin, target, infrastructure, mentioned)",
    ),
    min_confidence: str | None = Query(
        None, description="Count only entry–country links at or above this confidence (low, medium, high)"
    ),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Per-country entry counts over a date range for the Atlas map view.

    Applies the shared Atlas filters, then aggregates entry–country links into
    one bucket per country with a per-role breakdown; role and min_confidence
    filter which links count.
    """
    if (to - from_).days < 0 or (to - from_).days > 366:
        raise AppError(
            code="bad_request",
            message="Date range too large (max 366 days)",
            status_code=422,
        )

    if role:
        bad = [r for r in role if r not in _VALID_COUNTRY_ROLES]
        if bad:
            raise AppError(
                code="bad_request",
                message=f"Invalid role(s): {','.join(bad)}",
                status_code=422,
            )

    if min_confidence is not None and min_confidence not in _CONFIDENCE_RANK:
        raise AppError(
            code="bad_request",
            message=f"Invalid min_confidence: {min_confidence}",
            status_code=422,
        )

    base_query = await build_atlas_entry_id_query(
        db,
        from_=from_,
        to=to,
        feed_id=feed_id,
        category_id=category_id,
        entity_type=entity_type,
        entity_id=entity_id,
        region=region,
        campaign_id=campaign_id,
        saved_search_id=saved_search_id,
    )
    if base_query is None:
        return []

    base_subq = base_query.subquery()
    q = (
        select(
            Country.id.label("country_id"),
            Country.iso_code.label("iso_code"),
            Country.name.label("country_name"),
            Country.region.label("country_region"),
            EntryCountry.role.label("role"),
            EntryCountry.confidence.label("confidence"),
            EntryCountry.entry_id.label("entry_id"),
        )
        .join(EntryCountry, EntryCountry.country_id == Country.id)
        .where(EntryCountry.entry_id.in_(select(base_subq.c.id)))
    )
    if role:
        q = q.where(EntryCountry.role.in_(role))
    if min_confidence is not None:
        min_rank = _CONFIDENCE_RANK[min_confidence]
        allowed = [k for k, v in _CONFIDENCE_RANK.items() if v >= min_rank]
        q = q.where(EntryCountry.confidence.in_(allowed))

    rows = (await db.execute(q)).all()

    by_country: dict[uuid.UUID, dict] = {}
    for r in rows:
        bucket = by_country.get(r.country_id)
        if bucket is None:
            bucket = {
                "country_id": r.country_id,
                "iso_code": _normalize_iso(r.iso_code),
                "country_name": r.country_name,
                "region": r.country_region,
                "entries": set(),
                "role_breakdown": {},
            }
            by_country[r.country_id] = bucket
        bucket["entries"].add(r.entry_id)
        if r.role:
            bucket["role_breakdown"][r.role] = bucket["role_breakdown"].get(r.role, 0) + 1

    return [
        {
            "country_id": b["country_id"],
            "iso_code": b["iso_code"],
            "country_name": b["country_name"],
            "region": b["region"],
            "entry_count": len(b["entries"]),
            "role_breakdown": b["role_breakdown"],
        }
        for b in by_country.values()
    ]


@router.get("", response_model=CursorPaginatedResponse[EntryResponse])
async def list_entries(
    feed_id: uuid.UUID | None = Query(None, description="Restrict to one feed (works even if the feed is muted)"),
    category_id: uuid.UUID | None = Query(
        None, description="Restrict to feeds in this category (muted feeds included)"
    ),
    is_read: bool | None = Query(
        None, description="Filter by read state; false also hides entries that arrived already stale"
    ),
    is_starred: bool | None = Query(None, description="true keeps only starred entries"),
    is_bookmarked: bool | None = Query(None, description="true keeps only bookmarked entries"),
    content_type: str | None = Query(None, description="Match metadata.content_type (e.g. github_repo entries)"),
    change_type: str | None = Query(None, description="Match metadata.change_type (e.g. github_repo entries)"),
    since: datetime | None = Query(None, description="Only entries published at or after this timestamp"),
    before: datetime | None = Query(None, description="Only entries published at or before this timestamp"),
    country_id: uuid.UUID | None = Query(None, description="Only entries linked to this country"),
    country_role: str | None = Query(
        None, description="With country_id: link role (origin, target, infrastructure, mentioned)"
    ),
    campaign_id: uuid.UUID | None = Query(None, description="Only entries attached to this campaign"),
    exploited_cves: bool | None = Query(
        None,
        description="true keeps only entries mentioning a CVE in CISA KEV or under active exploitation",
    ),
    entity_type: str | None = Query(
        None,
        description="With entity_id: keep only entries linked to that entity "
        "(threat_actor, malware, cve, ttp, vendor, product, country, tool, mitigation)",
    ),
    entity_id: uuid.UUID | None = Query(None, description="With entity_type: the entity to filter by"),
    sector: str | None = Query(None, description="Only entries whose targeted sector matches this slug"),
    watched: bool | None = Query(None, description="true keeps only entries matching the user's entity watchlist"),
    sort: str = Query(
        "newest", description="newest, oldest, title_asc, title_desc, shortest, longest, or radar (Priority Queue)"
    ),
    dedup: bool = Query(True, description="Collapse same-content duplicates to the earliest-ingested copy"),
    limit: int = Query(50, ge=1, le=500, description="Page size"),
    cursor: str | None = Query(None, description="Opaque pagination cursor from the previous page's next_cursor"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Cursor-paginated entry list for the reader.

    Joins per-user read/star/bookmark state and batch-loads media, tags, and —
    when the signal engine surfaces — signal chips. Hidden entries are always
    excluded; muted feeds are excluded from the all-feeds view but included when
    feed_id or category_id is given.
    """
    return await _entry_page(
        db,
        user,
        feed_id=feed_id,
        category_id=category_id,
        is_read=is_read,
        is_starred=is_starred,
        is_bookmarked=is_bookmarked,
        content_type=content_type,
        change_type=change_type,
        since=since,
        before=before,
        country_id=country_id,
        country_role=country_role,
        campaign_id=campaign_id,
        exploited_cves=exploited_cves,
        entity_type=entity_type,
        entity_id=entity_id,
        sector=sector,
        watched=watched,
        sort=sort,
        dedup=dedup,
        limit=limit,
        cursor=cursor,
    )


async def _entry_page(
    db: AsyncSession,
    user: User,
    *,
    feed_id: uuid.UUID | None = None,
    category_id: uuid.UUID | None = None,
    is_read: bool | None = None,
    is_starred: bool | None = None,
    is_bookmarked: bool | None = None,
    content_type: str | None = None,
    change_type: str | None = None,
    since: datetime | None = None,
    before: datetime | None = None,
    country_id: uuid.UUID | None = None,
    country_role: str | None = None,
    campaign_id: uuid.UUID | None = None,
    exploited_cves: bool | None = None,
    entity_type: str | None = None,
    entity_id: uuid.UUID | None = None,
    sector: str | None = None,
    watched: bool | None = None,
    sort: str = "newest",
    dedup: bool = True,
    limit: int = 50,
    cursor: str | None = None,
    exclude_ids: set[uuid.UUID] | None = None,
    rank_scores: dict[uuid.UUID, float] | None = None,
) -> CursorPaginatedResponse[EntryResponse]:
    """Shared body behind GET /api/entries and the surfaces built on it.

    Plain keyword defaults rather than FastAPI ``Query`` objects, so other
    endpoints (the feed entry list, the Priority Queue) can call it in-process
    without every unpassed argument arriving as a ``Query`` instance.

    ``exclude_ids`` drops specific entries from the page — the Priority Queue
    uses it to keep a story thread's members out of the ranked list once the
    thread row stands for them. A dict passed as ``rank_scores`` is filled with
    the score each entry was actually ordered by, which is the raw priority score
    only when no read-time lift (exposure, personalisation) is in play.
    """
    if country_role is not None and country_role not in _VALID_COUNTRY_ROLES:
        raise AppError(
            code="bad_request",
            message=f"Invalid country_role: {country_role}",
            status_code=422,
        )
    _validate_entity_filter(entity_type, entity_id)
    # Resolve feed IDs
    if feed_id:
        # When requesting a specific feed, allow muted feeds (they still index/show articles,
        # they just don't count towards unread in the sidebar).
        feed_check = await db.get(Feed, feed_id)
        if not feed_check:
            raise AppError(code="not_found", message="Feed not found", status_code=404)
        feed_ids = [feed_id]
    else:
        # Mute hides a feed from "All Feeds" aggregation, but a user navigating into
        # a specific category has explicitly opted into that scope, so muted feeds
        # are kept in category views.
        feed_query = visible_feed_ids_query(
            user.id,
            enabled=await subscriptions_enabled(db),
            include_muted=bool(category_id),
            category_id=category_id,
        )
        feed_ids_result = await db.execute(feed_query)
        feed_ids = [row[0] for row in feed_ids_result.all()]

    if not feed_ids:
        return CursorPaginatedResponse(items=[], next_cursor=None, has_more=False)

    # Build query
    query = (
        select(
            Entry,
            UserEntryState,
            func.coalesce(Feed.custom_title, Feed.title).label("feed_title"),
            Feed.feed_type.label("feed_type"),
        )
        .outerjoin(
            UserEntryState,
            and_(UserEntryState.entry_id == Entry.id, UserEntryState.user_id == user.id),
        )
        .join(Feed, Feed.id == Entry.feed_id)
        .where(Entry.feed_id.in_(feed_ids))
    )

    # Apply filters
    if is_read is not None:
        if is_read:
            query = query.where(UserEntryState.is_read == True)  # noqa: E712
        else:
            query = query.where(
                or_(UserEntryState.is_read == False, UserEntryState.id.is_(None))  # noqa: E712
            )  # noqa: E711, E712
            query = _exclude_stale_on_arrival(query)

    if is_starred is True:
        query = query.where(UserEntryState.is_starred == True)  # noqa: E712

    if is_bookmarked is True:
        query = query.where(UserEntryState.is_bookmarked == True)  # noqa: E712

    if watched is True:
        from app.models.user_entity_watch import UserEntityWatch
        from app.services.triage import _entity_watch_filters

        watch_rows = (
            (
                await db.execute(
                    select(UserEntityWatch).where(
                        UserEntityWatch.created_by == user.id,
                        UserEntityWatch.mode == "watch",
                    )
                )
            )
            .scalars()
            .all()
        )
        watch_clauses = _entity_watch_filters(watch_rows)
        if watch_clauses:
            query = query.where(or_(*watch_clauses))
        else:
            # No watches configured — nothing can match.
            query = query.where(false())

    # Exclude hidden entries
    query = query.where(
        or_(UserEntryState.is_hidden == False, UserEntryState.is_hidden.is_(None))  # noqa: E712
    )  # noqa: E712

    # Caller-supplied suppression (Priority Queue: story-thread members, which
    # the thread row already stands for).
    if exclude_ids:
        query = query.where(Entry.id.notin_(exclude_ids))

    # Metadata filters (for github_repo content types)
    if content_type:
        query = query.where(Entry.metadata_["content_type"].astext == content_type)
    if change_type:
        query = query.where(Entry.metadata_["change_type"].astext == change_type)

    if since:
        query = query.where(Entry.published_at >= since)
    if before:
        query = query.where(Entry.published_at <= before)

    if country_id is not None:
        country_subq = select(EntryCountry.entry_id).where(EntryCountry.country_id == country_id)
        if country_role is not None:
            country_subq = country_subq.where(EntryCountry.role == country_role)
        query = query.where(Entry.id.in_(country_subq))

    if campaign_id is not None:
        from app.models.campaign import CampaignEntry

        query = query.where(
            Entry.id.in_(select(CampaignEntry.entry_id).where(CampaignEntry.campaign_id == campaign_id))
        )

    # The day divider's intel chips: clicking one narrows the list to the
    # articles behind it, rather than leaving the reader for a profile page.
    if exploited_cves is True:
        query = query.where(Entry.id.in_(_exploited_cve_entry_ids()))
    query = _apply_entity_filters(query, entity_type, entity_id, sector)

    # Dedup: for each content_hash, keep only one entry (the earliest ingested)
    if dedup:
        canonical_subq = (
            select(Entry.id.label("entry_id"))
            .where(Entry.feed_id.in_(feed_ids))
            .where(Entry.content_hash.isnot(None))
            .distinct(Entry.content_hash)
            .order_by(Entry.content_hash, Entry.created_at.asc())
        ).subquery()
        query = query.where(
            or_(
                Entry.content_hash.is_(None),
                Entry.id.in_(select(canonical_subq.c.entry_id)),
            )
        )

    # Consumption time expression for shortest/longest sorting
    # Uses media duration when available, otherwise estimates reading time from word count
    consumption_time_expr = None
    if sort in ("shortest", "longest"):
        media_duration_subq = (
            select(func.max(EntryMedia.duration_seconds))
            .where(EntryMedia.entry_id == Entry.id)
            .correlate(Entry)
            .scalar_subquery()
        )
        consumption_time_expr = func.coalesce(
            media_duration_subq,
            Entry.word_count * 60 / 200,
            0,
        )

    # My Stack exposure (read-time, per-user, Radar only): float CVEs affecting the
    # user's declared stack. Adds a joined (entry_id, lift) subquery and re-ranks by
    # effective_score = priority_score + lift. Gated by surface + the exposure flag +
    # a non-empty stack; otherwise the Radar behaves exactly as before.
    surface_on = bool(await get_setting("signal_engine_surface", db))
    exposure_active = False
    exposure_vendor_ids: list = []
    exposure_product_ids: list = []
    exposure_epss_threshold = 0.1
    effective_score = Entry.priority_score
    exposure_sq = None
    if sort == "radar" and surface_on and bool(await get_setting("my_stack_exposure_enabled", db)):
        from app.intelligence.cve import get_epss_high_risk_threshold
        from app.services.exposure import exposure_lift_subquery, get_user_stack

        exposure_vendor_ids, exposure_product_ids = await get_user_stack(db, user.id)
        if exposure_vendor_ids or exposure_product_ids:
            exposure_epss_threshold = get_epss_high_risk_threshold()
            exposure_sq = exposure_lift_subquery(exposure_vendor_ids, exposure_product_ids, exposure_epss_threshold)
            if exposure_sq is not None:
                query = query.outerjoin(exposure_sq, exposure_sq.c.entry_id == Entry.id)
                effective_score = func.coalesce(Entry.priority_score, 0.0) + func.coalesce(exposure_sq.c.lift, 0.0)
                exposure_active = True

    # Learned Radar weights (read-time, per-user, Radar only): lift each entry by
    # the gap between the global family multipliers baked into priority_score and
    # this analyst's own fitted weights. Personalisation RE-ORDERS the Priority
    # Queue and deliberately does not change its membership — the radar threshold
    # below still gates on the global score, so a learned weight can never hide an
    # entry the badge counted, and turning it off restores the house ranking
    # exactly. See app/services/radar_personalization.py.
    personal_active = False
    personal_coeffs: dict[str, float] = {}
    personal_weights: dict[str, float] = {}
    if sort == "radar" and surface_on and bool(await get_setting("radar_personalization_enabled", db)):
        from app.services.radar_personalization import (
            get_personal_coefficients,
            get_user_weights,
            is_personalization_opted_in,
            personal_lift_subquery,
        )

        if is_personalization_opted_in(user.settings):
            personal_coeffs = await get_personal_coefficients(db, user.id)
            personal_sq = personal_lift_subquery(personal_coeffs)
            if personal_sq is not None:
                personal_weights = await get_user_weights(db, user.id)
                query = query.outerjoin(personal_sq, personal_sq.c.entry_id == Entry.id)
                base_expr = effective_score if exposure_active else func.coalesce(Entry.priority_score, 0.0)
                effective_score = base_expr + func.coalesce(personal_sq.c.lift, 0.0)
                personal_active = True

    # Either read-time lift makes effective_score a coalesced expression rather
    # than the raw priority_score column — cursor and ORDER BY branch on this.
    score_lifted = exposure_active or personal_active

    # Cursor pagination
    if cursor:
        try:
            cursor_data = json.loads(base64.b64decode(cursor))
            cursor_id = uuid.UUID(cursor_data["id"])
            if sort in ("title_asc", "title_desc"):
                cursor_title = cursor_data["title"]
                if sort == "title_asc":
                    query = query.where(
                        or_(
                            Entry.title > cursor_title,
                            and_(Entry.title == cursor_title, Entry.id > cursor_id),
                        )
                    )
                else:
                    query = query.where(
                        or_(
                            Entry.title < cursor_title,
                            and_(Entry.title == cursor_title, Entry.id < cursor_id),
                        )
                    )
            elif sort in ("shortest", "longest"):
                cursor_time = int(cursor_data["consumption_time"])
                if sort == "shortest":
                    query = query.where(
                        or_(
                            consumption_time_expr > cursor_time,
                            and_(
                                consumption_time_expr == cursor_time,
                                Entry.id > cursor_id,
                            ),
                        )
                    )
                else:
                    query = query.where(
                        or_(
                            consumption_time_expr < cursor_time,
                            and_(
                                consumption_time_expr == cursor_time,
                                Entry.id < cursor_id,
                            ),
                        )
                    )
            elif sort == "radar":
                cursor_score = cursor_data.get("priority_score")
                if score_lifted:
                    # effective_score is coalesced (never NULL) — always numeric branch
                    score_val = float(cursor_score) if cursor_score is not None else 0.0
                    query = query.where(
                        or_(
                            effective_score < score_val,
                            and_(effective_score == score_val, Entry.id < cursor_id),
                        )
                    )
                elif cursor_score is None:
                    query = query.where(and_(Entry.priority_score.is_(None), Entry.id < cursor_id))
                else:
                    query = query.where(
                        or_(
                            Entry.priority_score < float(cursor_score),
                            and_(
                                Entry.priority_score == float(cursor_score),
                                Entry.id < cursor_id,
                            ),
                        )
                    )
            else:
                cursor_pub = cursor_data.get("published_at", "")
                if cursor_pub:
                    cursor_date = datetime.fromisoformat(cursor_pub)
                    # Use capped_published (least of published_at, now()) to match sort order
                    capped = func.least(Entry.published_at, func.now())
                    if sort == "newest":
                        query = query.where(
                            or_(
                                capped < cursor_date,
                                and_(capped == cursor_date, Entry.id < cursor_id),
                            )
                        )
                    else:
                        query = query.where(
                            or_(
                                capped > cursor_date,
                                and_(capped == cursor_date, Entry.id > cursor_id),
                            )
                        )
                else:
                    # Null published_at sorts last (nullslast/nullsfirst) — use ID-only cursor
                    if sort == "newest":
                        query = query.where(and_(Entry.published_at.is_(None), Entry.id < cursor_id))
                    else:
                        query = query.where(and_(Entry.published_at.is_(None), Entry.id > cursor_id))
        except AppError:
            raise
        except Exception:
            raise AppError(code="bad_request", message="Invalid cursor", status_code=400)

    # Priority Queue: when radar-sorted and surfacing is on, restrict to entries
    # that clear the radar threshold — mirrors the badge count, so the list holds
    # only genuinely surfaced (signal-bearing) entries instead of re-sorting the
    # entire unread feed. Reused below for signal-chip gating.
    radar_threshold: float | None = None
    if surface_on:
        from app.intelligence.signals import get_radar_threshold

        radar_threshold, _ = await get_radar_threshold()
        if sort == "radar":
            if exposure_active:
                # Keep entries that clear the threshold OR affect the user's stack
                # (a stack-relevant CVE surfaces even when the base score is low).
                query = query.where(
                    or_(
                        Entry.priority_score >= radar_threshold,
                        exposure_sq.c.lift.is_not(None),
                    )
                )
            else:
                query = query.where(Entry.priority_score >= radar_threshold)

    # Sort — cap published_at at now() so future-dated entries don't float to the top
    # Use CASE to preserve NULLs (LEAST ignores NULLs, turning NULL into now())
    capped_published = case(
        (Entry.published_at.is_(None), None),
        else_=func.least(Entry.published_at, func.now()),
    )
    if sort == "newest":
        query = query.order_by(capped_published.desc().nullslast(), Entry.id.desc())
    elif sort == "oldest":
        query = query.order_by(capped_published.asc().nullsfirst(), Entry.id.asc())
    elif sort == "title_asc":
        query = query.order_by(Entry.title.asc().nullslast(), Entry.id.asc())
    elif sort == "title_desc":
        query = query.order_by(Entry.title.desc().nullsfirst(), Entry.id.desc())
    elif sort == "shortest":
        query = query.order_by(consumption_time_expr.asc(), Entry.id.asc())
    elif sort == "longest":
        query = query.order_by(consumption_time_expr.desc(), Entry.id.desc())
    elif sort == "radar":
        if score_lifted:
            query = query.order_by(effective_score.desc().nullslast(), Entry.id.desc())
        else:
            query = query.order_by(Entry.priority_score.desc().nullslast(), Entry.id.desc())
    else:
        query = query.order_by(capped_published.desc().nullslast(), Entry.id.desc())

    # Fetch limit + 1 to check has_more. When a read-time lift is in play the
    # ordering key is a computed expression, so select it too: rebuilding it in
    # Python for the cursor drifts from the value Postgres compared against
    # (float summation order, display rounding) and lands rows on two pages.
    if score_lifted:
        query = query.add_columns(effective_score.label("effective_score"))
    result = await db.execute(query.limit(limit + 1))
    rows = result.all()

    has_more = len(rows) > limit
    rows = rows[:limit]
    effective_by_id: dict[uuid.UUID, float] = (
        {row[0].id: float(row[4]) for row in rows if row[4] is not None} if score_lifted else {}
    )
    if rank_scores is not None:
        for row in rows:
            rank_scores[row[0].id] = effective_by_id.get(row[0].id, float(row[0].priority_score or 0.0))

    # Batch-load media for all entries
    entry_ids = [row[0].id for row in rows]
    media_map: dict[uuid.UUID, list[EntryMediaBrief]] = {}
    if entry_ids:
        media_result = await db.execute(select(EntryMedia).where(EntryMedia.entry_id.in_(entry_ids)))
        for m in media_result.scalars().all():
            media_map.setdefault(m.entry_id, []).append(
                EntryMediaBrief(
                    id=m.id,
                    media_type=m.media_type,
                    url=m.url,
                    thumbnail_url=m.thumbnail_url,
                    duration_seconds=m.duration_seconds,
                )
            )

    # Batch-load tags for all entries
    tags_map: dict[uuid.UUID, list[dict]] = {}
    if entry_ids:
        tag_result = await db.execute(
            select(EntryTag.entry_id, Tag.name, Tag.color)
            .join(Tag, Tag.id == EntryTag.tag_id)
            .where(EntryTag.entry_id.in_(entry_ids))
        )
        for entry_id, tag_name, tag_color in tag_result.all():
            tags_map.setdefault(entry_id, []).append({"name": tag_name, "color": tag_color})

    # Batch-load signal chips (signal engine, only when surfaced)
    signals_map: dict[uuid.UUID, list[dict]] = {}
    echo_entries: set[uuid.UUID] = set()
    chip_threshold: float | None = radar_threshold
    if entry_ids and surface_on:
        from app.models.entry_signal import EntrySignal

        sig_result = await db.execute(
            select(EntrySignal).where(EntrySignal.entry_id.in_(entry_ids)).order_by(EntrySignal.score.desc())
        )
        for sig in sig_result.scalars().all():
            if sig.signal_type == "feed_echo":
                echo_entries.add(sig.entry_id)
                continue
            chips = signals_map.setdefault(sig.entry_id, [])
            if len(chips) < 2:
                chips.append({"type": sig.signal_type, "explanation": sig.explanation})

    # My Stack exposure decoration for the returned page (posture + missing telemetry)
    exposure_map: dict[uuid.UUID, dict] = {}
    if exposure_active and entry_ids:
        from app.services.exposure import enrich_exposure

        exposure_map = await enrich_exposure(
            db,
            entry_ids,
            exposure_vendor_ids,
            exposure_product_ids,
            exposure_epss_threshold,
        )

    # Learned-weight decoration for the returned page (lift + the families behind it)
    personal_map: dict[uuid.UUID, dict] = {}
    if personal_active and entry_ids:
        from app.services.radar_personalization import enrich_personal

        personal_map = await enrich_personal(db, entry_ids, personal_coeffs, personal_weights)

    items = []
    for entry, state, feed_title, feed_type, *_lift in rows:
        items.append(
            EntryResponse(
                id=entry.id,
                feed_id=entry.feed_id,
                guid=entry.guid,
                url=entry.url,
                title=entry.title,
                translated_title=entry.translated_title,
                author=entry.author,
                summary=entry.summary,
                published_at=entry.published_at,
                fetched_at=entry.fetched_at,
                word_count=entry.word_count,
                content_hash=entry.content_hash,
                image_url=entry.image_url,
                feed_title=feed_title,
                feed_type=feed_type,
                metadata=entry.metadata_,
                media=media_map.get(entry.id, []),
                is_read=state.is_read if state else False,
                is_starred=state.is_starred if state else False,
                is_bookmarked=state.is_bookmarked if state else False,
                tags=tags_map.get(entry.id, []),
                priority_score=(
                    entry.priority_score
                    if chip_threshold is not None
                    and entry.priority_score is not None
                    and entry.priority_score >= chip_threshold
                    else None
                ),
                top_signals=(
                    signals_map.get(entry.id, [])
                    if chip_threshold is not None
                    and entry.priority_score is not None
                    and entry.priority_score >= chip_threshold
                    else []
                ),
                is_echo=entry.id in echo_entries,
                exposure=exposure_map.get(entry.id),
                personal=personal_map.get(entry.id),
            )
        )

    # Build next cursor
    next_cursor = None
    if has_more and items:
        last = items[-1]
        last_entry = rows[-1][0]  # Entry object for computing consumption time
        if sort in ("title_asc", "title_desc"):
            cursor_data = {
                "title": last.title or "",
                "id": str(last.id),
            }
        elif sort == "radar":
            if score_lifted:
                # The exact effective_score Postgres ordered by, carried back from
                # the SELECT rather than re-added here.
                cursor_data = {
                    "priority_score": effective_by_id.get(last_entry.id, float(last_entry.priority_score or 0.0)),
                    "id": str(last.id),
                }
            else:
                cursor_data = {
                    "priority_score": last_entry.priority_score,
                    "id": str(last.id),
                }
        elif sort in ("shortest", "longest"):
            # Compute consumption time matching the SQL expression
            media_list = media_map.get(last_entry.id, [])
            max_duration = max((m.duration_seconds or 0 for m in media_list), default=0)
            read_seconds = (last_entry.word_count or 0) * 60 // 200
            ct = max_duration if max_duration > 0 else read_seconds
            cursor_data = {
                "consumption_time": ct,
                "id": str(last.id),
            }
        else:
            # Cap published_at at now() to match the capped sort order
            pub = last.published_at
            if pub:
                now = datetime.now(UTC)
                capped_pub = min(pub if pub.tzinfo else pub.replace(tzinfo=UTC), now)
            else:
                capped_pub = None
            cursor_data = {
                "published_at": capped_pub.isoformat() if capped_pub else "",
                "id": str(last.id),
            }
        next_cursor = base64.b64encode(json.dumps(cursor_data).encode()).decode()

    return CursorPaginatedResponse(items=items, next_cursor=next_cursor, has_more=has_more)


@router.get("/count")
async def count_entries(
    feed_id: uuid.UUID | None = Query(None, description="Restrict to one feed (works even if the feed is muted)"),
    category_id: uuid.UUID | None = Query(
        None, description="Restrict to feeds in this category (muted feeds included)"
    ),
    is_read: bool | None = Query(
        None, description="Filter by read state; false also excludes entries that arrived already stale"
    ),
    is_starred: bool | None = Query(None, description="true counts only starred entries"),
    is_bookmarked: bool | None = Query(None, description="true counts only bookmarked entries"),
    watched: bool | None = Query(None, description="true counts only entries matching the user's entity watchlist"),
    content_type: str | None = Query(None, description="Match metadata.content_type (e.g. github_repo entries)"),
    change_type: str | None = Query(None, description="Match metadata.change_type (e.g. github_repo entries)"),
    since: datetime | None = Query(None, description="Only entries published at or after this timestamp"),
    before: datetime | None = Query(None, description="Only entries published at or before this timestamp"),
    country_id: uuid.UUID | None = Query(None, description="Only entries linked to this country"),
    country_role: str | None = Query(
        None, description="With country_id: link role (origin, target, infrastructure, mentioned)"
    ),
    campaign_id: uuid.UUID | None = Query(None, description="Only entries attached to this campaign"),
    exploited_cves: bool | None = Query(
        None,
        description="true keeps only entries mentioning a CVE in CISA KEV or under active exploitation",
    ),
    entity_type: str | None = Query(
        None,
        description="With entity_id: keep only entries linked to that entity "
        "(threat_actor, malware, cve, ttp, vendor, product, country, tool, mitigation)",
    ),
    entity_id: uuid.UUID | None = Query(None, description="With entity_type: the entity to filter by"),
    sector: str | None = Query(None, description="Only entries whose targeted sector matches this slug"),
    dedup: bool = Query(True, description="Collapse same-content duplicates to the earliest-ingested copy"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, int]:
    """Count entries matching the same filters as the list endpoint (no pagination).

    Returns ``{"total": n}``.
    """
    if country_role is not None and country_role not in _VALID_COUNTRY_ROLES:
        raise AppError(
            code="bad_request",
            message=f"Invalid country_role: {country_role}",
            status_code=422,
        )
    _validate_entity_filter(entity_type, entity_id)

    if feed_id:
        feed_check = await db.get(Feed, feed_id)
        if not feed_check:
            raise AppError(code="not_found", message="Feed not found", status_code=404)
        feed_ids = [feed_id]
    else:
        feed_query = visible_feed_ids_query(
            user.id,
            enabled=await subscriptions_enabled(db),
            include_muted=bool(category_id),
            category_id=category_id,
        )
        feed_ids_result = await db.execute(feed_query)
        feed_ids = [row[0] for row in feed_ids_result.all()]

    if not feed_ids:
        return {"total": 0}

    query = (
        # count(*), not count(DISTINCT entries.id): the only join here is the
        # LEFT JOIN to user_entry_states, which carries UNIQUE (user_id,
        # entry_id), so it can never yield more than one row per entry — every
        # other filter is a column predicate or an IN/EXISTS subquery. The
        # DISTINCT was buying nothing and forcing a sort over the whole matching
        # set (measured on prod: 923ms vs 663ms, same 142,103 answer).
        select(func.count())
        .select_from(Entry)
        .outerjoin(
            UserEntryState,
            and_(UserEntryState.entry_id == Entry.id, UserEntryState.user_id == user.id),
        )
        .where(Entry.feed_id.in_(feed_ids))
    )

    if is_read is not None:
        if is_read:
            query = query.where(UserEntryState.is_read == True)  # noqa: E712
        else:
            query = query.where(
                or_(UserEntryState.is_read == False, UserEntryState.id.is_(None))  # noqa: E712
            )  # noqa: E711, E712
            query = _exclude_stale_on_arrival(query)

    if is_starred is True:
        query = query.where(UserEntryState.is_starred == True)  # noqa: E712

    if is_bookmarked is True:
        query = query.where(UserEntryState.is_bookmarked == True)  # noqa: E712

    if watched is True:
        from app.models.user_entity_watch import UserEntityWatch
        from app.services.triage import _entity_watch_filters

        watch_rows = (
            (
                await db.execute(
                    select(UserEntityWatch).where(
                        UserEntityWatch.created_by == user.id,
                        UserEntityWatch.mode == "watch",
                    )
                )
            )
            .scalars()
            .all()
        )
        watch_clauses = _entity_watch_filters(watch_rows)
        if watch_clauses:
            query = query.where(or_(*watch_clauses))
        else:
            query = query.where(false())

    query = query.where(
        or_(UserEntryState.is_hidden == False, UserEntryState.is_hidden.is_(None))  # noqa: E712
    )  # noqa: E712

    if content_type:
        query = query.where(Entry.metadata_["content_type"].astext == content_type)
    if change_type:
        query = query.where(Entry.metadata_["change_type"].astext == change_type)

    if since:
        query = query.where(Entry.published_at >= since)
    if before:
        query = query.where(Entry.published_at <= before)

    if country_id is not None:
        country_subq = select(EntryCountry.entry_id).where(EntryCountry.country_id == country_id)
        if country_role is not None:
            country_subq = country_subq.where(EntryCountry.role == country_role)
        query = query.where(Entry.id.in_(country_subq))

    if campaign_id is not None:
        from app.models.campaign import CampaignEntry

        query = query.where(
            Entry.id.in_(select(CampaignEntry.entry_id).where(CampaignEntry.campaign_id == campaign_id))
        )

    # The day divider's intel chips: clicking one narrows the list to the
    # articles behind it, rather than leaving the reader for a profile page.
    if exploited_cves is True:
        query = query.where(Entry.id.in_(_exploited_cve_entry_ids()))
    query = _apply_entity_filters(query, entity_type, entity_id, sector)

    if dedup:
        canonical_subq = (
            select(Entry.id.label("entry_id"))
            .where(Entry.feed_id.in_(feed_ids))
            .where(Entry.content_hash.isnot(None))
            .distinct(Entry.content_hash)
            .order_by(Entry.content_hash, Entry.created_at.asc())
        ).subquery()
        query = query.where(
            or_(
                Entry.content_hash.is_(None),
                Entry.id.in_(select(canonical_subq.c.entry_id)),
            )
        )

    result = await db.execute(query)
    total = result.scalar_one() or 0
    return {"total": int(total)}


@router.get("/priority-unread-count")
async def priority_unread_count(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, int]:
    """Unread, radar-surfaced entries — the Priority Queue badge count.

    "Surfaced" mirrors the list/detail endpoints: only when signal_engine_surface
    is on and the entry's priority_score clears the current radar threshold.
    Returns 0 when surfacing is disabled.
    """
    from app.intelligence.signals import get_radar_threshold

    if not bool(await get_setting("signal_engine_surface", db)):
        return {"unread_count": 0}

    threshold, _ = await get_radar_threshold()

    feed_ids = [
        row[0]
        for row in (await db.execute(visible_feed_ids_query(user.id, enabled=await subscriptions_enabled(db)))).all()
    ]
    if not feed_ids:
        return {"unread_count": 0}

    query = (
        # See count_entries: same single unique-constrained join, so DISTINCT
        # would only add a sort.
        select(func.count())
        .select_from(Entry)
        .outerjoin(
            UserEntryState,
            and_(UserEntryState.entry_id == Entry.id, UserEntryState.user_id == user.id),
        )
        .where(Entry.feed_id.in_(feed_ids))
        .where(Entry.priority_score >= threshold)
        .where(
            or_(UserEntryState.is_read == False, UserEntryState.id.is_(None))  # noqa: E712
        )  # noqa: E711, E712
        .where(
            or_(UserEntryState.is_hidden == False, UserEntryState.is_hidden.is_(None))  # noqa: E712
        )  # noqa: E712
    )
    # Backdated stragglers are hidden from the Hide-Read list, so keep them out of
    # its badge too.
    query = _exclude_stale_on_arrival(query)
    total = (await db.execute(query)).scalar_one() or 0
    return {"unread_count": int(total)}


# --- Priority Queue ---------------------------------------------------------
#
# The ranked reading queue as the reader actually renders it: radar-sorted
# entries with story threads folded in, so a story eleven outlets covered is one
# row rather than eleven. Assembled here rather than in the client so the SPA,
# the CLI and an agent all get the same queue in the same order.

# Each independent outlet beyond the first lifts a thread above a lone article of
# the same base score — corroboration across newsrooms is itself a signal. Capped
# so a story everyone covered can't own the whole top of the queue.
_THREAD_OUTLET_BUMP = 1.0
_THREAD_OUTLET_BUMP_CAP = 5.0
# How deep into the open-thread list the queue looks. Threads are ranked by their
# best unread beat, and one below this many is not going to outrank anything.
_QUEUE_THREAD_LIMIT = 40


def _thread_queue_score(row: dict) -> float:
    """The rank a thread row takes: its best unread beat plus the outlet bump."""
    outlets = int(row.get("source_count") or 0)
    bump = min(max(outlets - 1, 0) * _THREAD_OUTLET_BUMP, _THREAD_OUTLET_BUMP_CAP)
    return float(row.get("top_score") or 0.0) + bump


def _thread_sort_key(row: dict) -> tuple[float, str]:
    """Total order over thread rows — score first, id to break ties stably."""
    return (-_thread_queue_score(row), str(row["id"]))


@router.get(
    "/priority-queue",
    response_model=PriorityQueueResponse,
    summary="Priority Queue",
    description=(
        "The ranked reading queue: unread entries that clear the radar threshold, with open story "
        "threads folded in as single rows. A thread ranks by the score of its best unread beat plus "
        "a capped bump for each extra outlet covering the story, and its members are withheld from "
        "the queue as standalone entries — the thread row stands for them. Threads with nothing "
        "unread never appear: the queue answers 'what should I read next', and a story you have "
        "finished has no answer to give."
    ),
)
async def priority_queue(
    unread_only: bool = Query(True, description="false also returns entries already read"),
    with_threads: bool = Query(True, description="false returns entries only, without folding story threads"),
    exclude_thread_ids: list[uuid.UUID] = Query(
        [], description="Threads to leave out entirely — their members return as standalone entries"
    ),
    limit: int = Query(50, ge=1, le=200, description="Entries per page; thread rows are additional"),
    cursor: str | None = Query(None, description="Opaque pagination cursor from the previous page's next_cursor"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    return await build_priority_queue(
        db,
        user,
        unread_only=unread_only,
        with_threads=with_threads,
        exclude_thread_ids=exclude_thread_ids,
        limit=limit,
        cursor=cursor,
    )


async def build_priority_queue(
    db: AsyncSession,
    user: User,
    *,
    unread_only: bool = True,
    with_threads: bool = True,
    exclude_thread_ids: list[uuid.UUID] | None = None,
    limit: int = 50,
    cursor: str | None = None,
) -> PriorityQueueResponse:
    """Assemble one page of the Priority Queue. Shared by the endpoint and the tool."""
    entry_cursor: str | None = None
    thread_after: tuple[float, str] | None = None
    if cursor:
        try:
            payload = json.loads(base64.b64decode(cursor).decode())
            entry_cursor = payload.get("entry")
            after = payload.get("thread")
            if after:
                thread_after = (float(after[0]), str(after[1]))
        except Exception:
            raise AppError(code="bad_request", message="Invalid cursor", status_code=400)

    # Live threads: open, something still unread, not dismissed by this reader.
    pending: list[dict] = []
    member_ids: set[uuid.UUID] = set()
    if with_threads:
        dismissed = set(exclude_thread_ids or [])
        rows = await story_threads.list_threads(db, user.id, status="open", limit=_QUEUE_THREAD_LIMIT)
        live = [r for r in rows if (r.get("unread_count") or 0) > 0 and r["id"] not in dismissed]
        live.sort(key=_thread_sort_key)
        for row in live:
            # Every member of a live thread is withheld, including those on pages
            # still to come. A thread scores at or above its best unread member, so
            # the row is always reached before the articles it stands for — the
            # story is never missing from the queue, only folded.
            member_ids.update(row.get("entry_ids") or [])
        pending = [r for r in live if thread_after is None or _thread_sort_key(r) > thread_after]

    rank_scores: dict[uuid.UUID, float] = {}
    page = await _entry_page(
        db,
        user,
        is_read=False if unread_only else None,
        sort="radar",
        dedup=True,
        limit=limit,
        cursor=entry_cursor,
        exclude_ids=member_ids or None,
        rank_scores=rank_scores,
    )

    radar_threshold: float | None = None
    if bool(await get_setting("signal_engine_surface", db)):
        from app.intelligence.signals import get_radar_threshold

        radar_threshold, _ = await get_radar_threshold()

    # Two-pointer merge: entries keep their ranked order and a thread slots in
    # ahead of the first entry it outranks. The comparison is against the score
    # the entries were actually ordered by — a stack-exposure or learned-weight
    # lift moves an entry within the queue, so comparing threads against the raw
    # column instead would interleave them against an order that isn't there.
    # Thread rows carry no such lift: they rank on the house score of their best
    # unread beat.
    items: list[PriorityQueueRow] = []
    ti = 0
    last_thread: dict | None = None
    for entry in page.items:
        escore = rank_scores.get(entry.id, entry.priority_score or 0.0)
        while ti < len(pending) and _thread_queue_score(pending[ti]) >= escore:
            last_thread = pending[ti]
            items.append(_thread_row(last_thread, member_ids))
            ti += 1
        items.append(PriorityQueueRow(kind="entry", score=escore, entry=entry))

    if not page.has_more:
        # Last page of entries — nothing left for a thread to outrank, so flush
        # the tail rather than stranding it behind a cursor that never comes.
        while ti < len(pending):
            last_thread = pending[ti]
            items.append(_thread_row(last_thread, member_ids))
            ti += 1

    has_more = page.has_more
    next_cursor = None
    if has_more:
        # Carry thread progress forward even on a page that emitted no thread row —
        # resetting it would re-emit every thread already shown.
        resume = _thread_sort_key(last_thread) if last_thread else thread_after
        next_cursor = base64.b64encode(
            json.dumps({"entry": page.next_cursor, "thread": list(resume) if resume else None}).encode()
        ).decode()

    return PriorityQueueResponse(
        items=items,
        next_cursor=next_cursor,
        has_more=has_more,
        radar_threshold=radar_threshold,
    )


def _thread_row(row: dict, member_ids: set[uuid.UUID]) -> PriorityQueueRow:
    summary = ThreadSummary.from_row(row)
    return PriorityQueueRow(
        kind="thread",
        score=_thread_queue_score(row),
        thread=summary,
        absorbed_entry_ids=[eid for eid in summary.entry_ids if eid in member_ids],
    )


# --- Daily divider summary --------------------------------------------------
#
# Generates and caches an AI summary of the entries in one day-divider group
# from the entry list. Cached via the existing AIResult table with a stable
# uuid5 derived from (user_id, day_key, filter_key) so revisits don't burn
# tokens. The same set of list filters as /entries is accepted, and the day
# window is delimited explicitly by since/before (passed by the client in its
# local timezone) to keep the server timezone-agnostic.

_DAILY_SUMMARY_NS = uuid.UUID("d3c1b1e0-1a8d-4b0a-9d83-7d3f1f2d9a01")
_DAILY_SUMMARY_MAX_ENTRIES = 60

# The default, unfiltered daily briefing is identical for every user, so it's
# cached once under this sentinel "user" instead of per-account. Filtered
# summaries (single feed, starred, bookmarked, …) stay keyed to the real user
# since those views differ per person.
GLOBAL_SUMMARY_USER = uuid.UUID(int=0)  # 00000000-0000-0000-0000-000000000000


def _is_global_scope(filters: dict) -> bool:
    """True when the summary is the shared, unfiltered daily briefing — every
    filter unset (dedup, which is always on, doesn't count)."""
    return all(v is None for k, v in filters.items() if k != "dedup")


def _scope_user_id(user_id: uuid.UUID, filters: dict) -> uuid.UUID:
    """Global scope keys on a fixed sentinel so one row serves all users;
    filtered scope stays per-user."""
    return GLOBAL_SUMMARY_USER if _is_global_scope(filters) else user_id


class DailySummaryRequest(BaseModel):
    day_key: str  # "YYYY-MM-DD" — used as part of the cache key
    since: datetime  # day window lower bound (>=)
    before: datetime  # day window upper bound (<=)
    feed_id: uuid.UUID | None = None
    category_id: uuid.UUID | None = None
    is_read: bool | None = None
    is_starred: bool | None = None
    is_bookmarked: bool | None = None
    content_type: str | None = None
    change_type: str | None = None
    country_id: uuid.UUID | None = None
    country_role: str | None = None
    campaign_id: uuid.UUID | None = None
    dedup: bool = True
    force: bool = False

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "day_key": "2026-08-26",
                "since": "2026-08-26T00:00:00Z",
                "before": "2026-08-26T23:59:59Z",
                "dedup": True,
                "force": False,
            }
        }
    )


def _daily_summary_target_id(user_id: uuid.UUID, day_key: str, filters: dict) -> uuid.UUID:
    """Stable UUID for the (user, day, filter) cache key."""
    canonical_filters = {k: v for k, v in sorted(filters.items()) if v is not None}
    payload = json.dumps(
        {"u": str(user_id), "d": day_key, "f": canonical_filters},
        sort_keys=True,
        default=str,
    )
    return uuid.uuid5(_DAILY_SUMMARY_NS, payload)


def _filters_for_cache_key(req: "DailySummaryRequest") -> dict:
    """Filter subset that defines a distinct cache key. Excludes the day window
    bounds themselves (the day_key captures that) and the force flag."""
    return {
        "feed_id": str(req.feed_id) if req.feed_id else None,
        "category_id": str(req.category_id) if req.category_id else None,
        "is_read": req.is_read,
        "is_starred": req.is_starred,
        "is_bookmarked": req.is_bookmarked,
        "content_type": req.content_type,
        "change_type": req.change_type,
        "country_id": str(req.country_id) if req.country_id else None,
        "country_role": req.country_role,
        "campaign_id": str(req.campaign_id) if req.campaign_id else None,
        "dedup": req.dedup,
    }


async def _fetch_day_entries(
    db: AsyncSession,
    user: User | None,
    req: "DailySummaryRequest",
) -> list[dict]:
    """Fetch the entries that fall in the day window under the given filters,
    returned as prompt-friendly dicts. Mirrors the filter logic of list_entries
    but ignores sort/pagination.

    ``user`` is ``None`` for the shared global briefing: the per-user
    UserEntryState join is skipped entirely (no is_read/starred/bookmarked/hidden
    filtering), so the summary reflects every non-muted entry of the day."""
    # Resolve feed IDs (same logic as list_entries — single feed bypasses mute)
    if req.feed_id:
        feed_check = await db.get(Feed, req.feed_id)
        if not feed_check:
            raise AppError(code="not_found", message="Feed not found", status_code=404)
        feed_ids = [req.feed_id]
    else:
        feed_query = visible_feed_ids_query(
            user.id if user is not None else None,
            enabled=await subscriptions_enabled(db),
            include_muted=bool(req.category_id),
            category_id=req.category_id,
        )
        feed_ids = [row[0] for row in (await db.execute(feed_query)).all()]

    if not feed_ids:
        return []

    query = select(Entry, func.coalesce(Feed.custom_title, Feed.title).label("feed_title"))
    if user is not None:
        query = query.outerjoin(
            UserEntryState,
            and_(UserEntryState.entry_id == Entry.id, UserEntryState.user_id == user.id),
        )
    query = (
        query.join(Feed, Feed.id == Entry.feed_id)
        .where(Entry.feed_id.in_(feed_ids))
        .where(Entry.published_at >= req.since)
        .where(Entry.published_at <= req.before)
    )

    # Per-user read/star/bookmark/hidden state only applies to per-user summaries.
    # The global briefing (user is None) reflects every non-muted entry.
    if user is not None:
        if req.is_read is True:
            query = query.where(UserEntryState.is_read == True)  # noqa: E712
        elif req.is_read is False:
            query = query.where(
                or_(UserEntryState.is_read == False, UserEntryState.id.is_(None))  # noqa: E712
            )  # noqa: E711, E712
        if req.is_starred is True:
            query = query.where(UserEntryState.is_starred == True)  # noqa: E712
        if req.is_bookmarked is True:
            query = query.where(UserEntryState.is_bookmarked == True)  # noqa: E712
        query = query.where(
            or_(UserEntryState.is_hidden == False, UserEntryState.is_hidden.is_(None))  # noqa: E712
        )  # noqa: E712
    if req.content_type:
        query = query.where(Entry.metadata_["content_type"].astext == req.content_type)
    if req.change_type:
        query = query.where(Entry.metadata_["change_type"].astext == req.change_type)
    if req.country_id is not None:
        country_subq = select(EntryCountry.entry_id).where(EntryCountry.country_id == req.country_id)
        if req.country_role is not None:
            country_subq = country_subq.where(EntryCountry.role == req.country_role)
        query = query.where(Entry.id.in_(country_subq))
    if req.campaign_id is not None:
        from app.models.campaign import CampaignEntry

        query = query.where(
            Entry.id.in_(select(CampaignEntry.entry_id).where(CampaignEntry.campaign_id == req.campaign_id))
        )
    if req.dedup:
        canonical_subq = (
            select(Entry.id.label("entry_id"))
            .where(Entry.feed_id.in_(feed_ids))
            .where(Entry.content_hash.isnot(None))
            .distinct(Entry.content_hash)
            .order_by(Entry.content_hash, Entry.created_at.asc())
        ).subquery()
        query = query.where(
            or_(
                Entry.content_hash.is_(None),
                Entry.id.in_(select(canonical_subq.c.entry_id)),
            )
        )

    query = query.order_by(Entry.published_at.desc().nullslast(), Entry.id.desc())
    query = query.limit(_DAILY_SUMMARY_MAX_ENTRIES)

    rows = (await db.execute(query)).all()

    # One article per story. A day where eight outlets covered the same PaperCut
    # zero-day is one development, and a briefing that lists it eight times
    # spends the reader's attention on the repetition rather than the day. The
    # thread keeps the strongest account and reports how many outlets carried
    # it; articles no thread holds are untouched (see fold_by_thread).
    from app.intelligence.story_threads import fold_by_thread

    feed_titles = {entry.id: feed_title for entry, feed_title in rows}
    kept, coverage = await fold_by_thread(db, [entry for entry, _ in rows])
    rows = [(entry, feed_titles.get(entry.id)) for entry in kept]

    # Signal-grounded digest: attach explanation sentences so the briefing can
    # say WHY an article matters (KEV adds, novel actors, under-reported CVEs)
    signal_map: dict[uuid.UUID, list[str]] = {}
    row_entry_ids = [entry.id for entry, _ in rows]
    if row_entry_ids:
        from app.models.entry_signal import EntrySignal

        sig_rows = (
            (
                await db.execute(
                    select(EntrySignal)
                    .where(
                        EntrySignal.entry_id.in_(row_entry_ids),
                        EntrySignal.signal_type != "feed_echo",
                    )
                    .order_by(EntrySignal.score.desc())
                )
            )
            .scalars()
            .all()
        )
        for sig in sig_rows:
            lst = signal_map.setdefault(sig.entry_id, [])
            if len(lst) < 3:
                lst.append(sig.explanation)

    return [
        {
            "title": entry.title or "(untitled)",
            "feed_title": feed_title or "",
            # In-app deep link to the article reader. The frontend's homepage
            # reads ?entry=<id> from the URL and opens that entry. The model
            # uses this value as the URL for [Title](URL) markdown links so
            # clicking goes to the IntelFeed reader, not the external source.
            "url": f"/?entry={entry.id}",
            "external_url": entry.url or None,
            "published_at": (entry.published_at.isoformat() if entry.published_at else None),
            "summary": (entry.summary or "").strip() or None,
            "content_text": (entry.content_text or "").strip() or None,
            "priority_signals": signal_map.get(entry.id) or None,
            # Coverage of the story this article stands for, when a thread holds
            # it: how many outlets carried it, and how many of the day's other
            # articles were folded into this one.
            "outlet_count": coverage.get(entry.id, {}).get("outlet_count") or None,
            "also_reported_by": coverage.get(entry.id, {}).get("also_reported_by") or None,
        }
        for entry, feed_title in rows
    ]


@router.get("/daily-summary")
async def get_daily_summary(
    day_key: str = Query(..., description="YYYY-MM-DD day key"),
    feed_id: uuid.UUID | None = Query(None, description="Cache-key filter: single feed scope"),
    category_id: uuid.UUID | None = Query(None, description="Cache-key filter: category scope"),
    is_read: bool | None = Query(None, description="Cache-key filter: read state"),
    is_starred: bool | None = Query(None, description="Cache-key filter: starred only"),
    is_bookmarked: bool | None = Query(None, description="Cache-key filter: bookmarked only"),
    content_type: str | None = Query(None, description="Cache-key filter: metadata.content_type"),
    change_type: str | None = Query(None, description="Cache-key filter: metadata.change_type"),
    country_id: uuid.UUID | None = Query(None, description="Cache-key filter: linked country"),
    country_role: str | None = Query(None, description="Cache-key filter: country link role"),
    campaign_id: uuid.UUID | None = Query(None, description="Cache-key filter: campaign scope"),
    dedup: bool = Query(True, description="Cache-key filter: duplicate collapsing (part of the key)"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return the cached daily summary if present, else null. Never generates."""
    from app.models.ai_result import AIResult
    from app.models.ai_task import AITask

    filters_dict = {
        "feed_id": str(feed_id) if feed_id else None,
        "category_id": str(category_id) if category_id else None,
        "is_read": is_read,
        "is_starred": is_starred,
        "is_bookmarked": is_bookmarked,
        "content_type": content_type,
        "change_type": change_type,
        "country_id": str(country_id) if country_id else None,
        "country_role": country_role,
        "campaign_id": str(campaign_id) if campaign_id else None,
        "dedup": dedup,
    }
    # Default unfiltered briefings are shared across users (keyed on a sentinel);
    # filtered ones stay per-user.
    primary_target_id = _daily_summary_target_id(_scope_user_id(user.id, filters_dict), day_key, filters_dict)

    task_row = await db.execute(select(AITask.id).where(AITask.name == "daily_summary"))
    task_id = task_row.scalar_one_or_none()
    if not task_id:
        return {"summary": None, "cached": False, "generated_at": None}

    candidate_target_ids = [primary_target_id]

    # Transition fallback: before the shared row exists, resolve this user's own
    # previously-cached summary for the same day/filters.
    per_user_target_id = _daily_summary_target_id(user.id, day_key, filters_dict)
    if per_user_target_id not in candidate_target_ids:
        candidate_target_ids.append(per_user_target_id)

    # Backward compat: the frontend used to include `is_read=False` in the
    # cache key whenever Hide Read was on. We've since dropped that field
    # from the key (a summary describes the day regardless of read state),
    # but summaries cached under the old "is_read=False" hash are still on
    # disk. Fall back to that legacy hash if the canonical one misses.
    if is_read is None:
        legacy_target_id = _daily_summary_target_id(user.id, day_key, {**filters_dict, "is_read": False})
        if legacy_target_id not in candidate_target_ids:
            candidate_target_ids.append(legacy_target_id)

    result = await db.execute(
        select(AIResult)
        .where(
            AIResult.target_type == "daily_summary",
            AIResult.target_id.in_(candidate_target_ids),
            AIResult.task_id == task_id,
            AIResult.is_current == True,  # noqa: E712
        )
        .order_by(AIResult.created_at.desc())
        .limit(1)
    )
    cached = result.scalar_one_or_none()
    if not cached or not cached.parsed_result or "summary" not in (cached.parsed_result or {}):
        return {"summary": None, "cached": False, "generated_at": None}

    return {
        "summary": cached.parsed_result.get("summary"),
        "cached": True,
        "generated_at": cached.created_at,
    }


@router.get("/day-intel")
async def day_intel(
    since: datetime = Query(..., description="Start of day window (inclusive)"),
    before: datetime = Query(..., description="End of day window (inclusive)"),
    feed_id: uuid.UUID | None = Query(None, description="Restrict to entries from this feed"),
    category_id: uuid.UUID | None = Query(None, description="Restrict to feeds in this category"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Top entities + urgency signals for the given day window.

    Powers the day divider in the entry list, giving analysts a 3-second read on
    what the day was about without opening every entry. Returns the top-mentioned
    entity of each type (actor / malware / cve / ttp / sector / product / country),
    an exploited-first CVE pick, and lightweight signals (actively-exploited count,
    newly-tracked entities).
    """

    _subs_enabled = await subscriptions_enabled(db)

    def _apply_filters(q):
        if feed_id:
            q = q.where(Entry.feed_id == feed_id)
        elif category_id:
            q = q.join(Feed, Feed.id == Entry.feed_id).where(Feed.category_id == category_id)
        else:
            # Muted feeds still count here. Mute means "keep this out of my
            # reading list", not "ignore it" — a lot of muted sources are
            # high-volume technical feeds whose CVEs/TTPs are exactly the
            # context this strip exists to surface. The day's summary prose
            # stays unmuted-only (see _fetch_day_entries); these chips
            # deliberately read wider than the list below them.
            q = q.where(Entry.feed_id.in_(visible_feed_ids_query(user.id, enabled=_subs_enabled, include_muted=True)))
        return q

    base = _apply_filters(select(Entry.id).where(Entry.published_at >= since, Entry.published_at <= before))
    base_sub = base.subquery()
    entry_ids = select(base_sub.c.id)

    result: dict[str, object] = {
        "threat_actor": None,
        "malware": None,
        "cve": None,
        "ttp": None,
        "sector": None,
        "product": None,
        "country": None,
    }

    # --- simple named entities: top by distinct-entry mention count ---
    simple_targets: list[tuple[str, type, str, type, object]] = [
        ("threat_actor", EntryThreatActor, "threat_actor_id", ThreatActor, ThreatActor.name),
        (
            "malware",
            EntryMalware,
            "malware_family_id",
            MalwareFamily,
            MalwareFamily.name,
        ),
        ("product", EntryProduct, "product_id", Product, Product.name),
        ("country", EntryCountry, "country_id", Country, Country.name),
    ]
    for type_name, junction_cls, fk_col, entity_cls, name_col in simple_targets:
        entity_id_col = getattr(junction_cls, fk_col)
        count_col = func.count(func.distinct(junction_cls.entry_id))
        q = (
            select(entity_id_col.label("id"), name_col.label("name"), count_col.label("c"))
            .join(entity_cls, entity_cls.id == entity_id_col)
            .where(junction_cls.entry_id.in_(entry_ids))
            .group_by(entity_id_col, name_col)
            .order_by(count_col.desc(), name_col.asc())
            .limit(1)
        )
        row = (await db.execute(q)).first()
        if row:
            result[type_name] = {"id": str(row.id), "name": row.name, "count": row.c}

    # --- TTP: carry both the ATT&CK id and the readable technique name ---
    ttp_count = func.count(func.distinct(EntryTTP.entry_id))
    ttp_row = (
        await db.execute(
            select(TTP.id, TTP.technique_id, TTP.technique_name, ttp_count.label("c"))
            .join(TTP, TTP.id == EntryTTP.ttp_id)
            .where(EntryTTP.entry_id.in_(entry_ids))
            .group_by(TTP.id, TTP.technique_id, TTP.technique_name)
            .order_by(ttp_count.desc(), TTP.technique_id.asc())
            .limit(1)
        )
    ).first()
    if ttp_row:
        result["ttp"] = {
            "id": str(ttp_row.id),
            "technique_id": ttp_row.technique_id,
            "name": ttp_row.technique_name,
            "count": ttp_row.c,
        }

    # --- Sector: controlled-vocab slug, no entity table; group by the slug ---
    sec_count = func.count(func.distinct(EntrySector.entry_id))
    sec_row = (
        await db.execute(
            select(EntrySector.sector, sec_count.label("c"))
            .where(EntrySector.entry_id.in_(entry_ids))
            .group_by(EntrySector.sector)
            .order_by(sec_count.desc(), EntrySector.sector.asc())
            .limit(1)
        )
    ).first()
    if sec_row:
        result["sector"] = {
            "slug": sec_row.sector,
            "name": sector_label(sec_row.sector),
            "count": sec_row.c,
        }

    # --- CVE: exploited-first (KEV, then active exploitation), then by count ---
    cve_count = func.count(func.distinct(EntryCVE.entry_id))
    cve_row = (
        await db.execute(
            select(
                CVE.id,
                CVE.cve_id,
                CVE.cvss_score,
                CVE.severity,
                CVE.is_kev,
                cve_count.label("c"),
            )
            .join(CVE, CVE.id == EntryCVE.cve_id)
            .where(EntryCVE.entry_id.in_(entry_ids))
            .group_by(CVE.id)
            .order_by(
                CVE.is_kev.desc(),
                (CVE.exploit_availability == "active_exploitation").desc(),
                cve_count.desc(),
                CVE.cve_id.asc(),
            )
            .limit(1)
        )
    ).first()
    if cve_row:
        result["cve"] = {
            "id": str(cve_row.id),
            "name": cve_row.cve_id,
            "count": cve_row.c,
            "cvss_score": (float(cve_row.cvss_score) if cve_row.cvss_score is not None else None),
            "severity": cve_row.severity,
            "kev": bool(cve_row.is_kev),
        }

    # --- signal: distinct actively-exploited CVEs in the window ---
    actively_exploited = (
        await db.execute(
            select(func.count(func.distinct(EntryCVE.cve_id))).where(
                EntryCVE.entry_id.in_(entry_ids),
                EntryCVE.cve_id.in_(_actively_exploited_cve_ids()),
            )
        )
    ).scalar() or 0

    # --- signal: entities first tracked within this window (mentioned in-window) ---
    new_entities: list[dict] = []
    for type_name, junction_cls, fk_col, entity_cls in (
        ("threat_actor", EntryThreatActor, "threat_actor_id", ThreatActor),
        ("malware", EntryMalware, "malware_family_id", MalwareFamily),
    ):
        entity_id_col = getattr(junction_cls, fk_col)
        rows = (
            await db.execute(
                select(entity_cls.id, entity_cls.name)
                .join(junction_cls, entity_id_col == entity_cls.id)
                .where(
                    junction_cls.entry_id.in_(entry_ids),
                    entity_cls.first_seen_at >= since,
                    entity_cls.first_seen_at <= before,
                )
                .distinct()
            )
        ).all()
        for r in rows:
            new_entities.append({"type": type_name, "id": str(r.id), "name": r.name})
    new_signal = {**new_entities[0], "total": len(new_entities)} if new_entities else None

    result["signals"] = {"actively_exploited": actively_exploited, "new": new_signal}

    return result


@router.get("/day-entities")
async def day_entities(
    since: datetime = Query(..., description="Start of day window (inclusive)"),
    before: datetime = Query(..., description="End of day window (inclusive)"),
    feed_id: uuid.UUID | None = Query(None, description="Restrict to entries from this feed"),
    category_id: uuid.UUID | None = Query(None, description="Restrict to feeds in this category"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Distinct entities mentioned by all entries in the day window.

    Powers inline entity linking on the day's AI summary. For named entities
    (actor / malware / vendor / product / country / tool) we also surface the
    aggregated junction ``matched_names`` — those are the actual surface forms
    the autolinker found in the source articles, which is exactly what the
    summary model is most likely to reuse verbatim.
    """
    base = select(Entry.id).where(
        Entry.published_at >= since,
        Entry.published_at <= before,
    )
    if feed_id:
        base = base.where(Entry.feed_id == feed_id)
    elif category_id:
        base = base.join(Feed, Feed.id == Entry.feed_id).where(Feed.category_id == category_id)
    else:
        # Muted feeds included, matching day_intel: this powers entity linking
        # over the day's text, so the vocabulary has to cover every entity the
        # day actually mentioned, not just the ones from unmuted sources.
        base = base.where(
            Entry.feed_id.in_(
                visible_feed_ids_query(user.id, enabled=await subscriptions_enabled(db), include_muted=True)
            )
        )
    entry_ids_select = select(base.subquery().c.id)

    cves_rows = (
        (
            await db.execute(
                select(CVE)
                .join(EntryCVE, EntryCVE.cve_id == CVE.id)
                .where(EntryCVE.entry_id.in_(entry_ids_select))
                .distinct()
            )
        )
        .scalars()
        .all()
    )
    cves = [
        {
            "id": str(c.id),
            "cve_id": c.cve_id,
            "cvss_score": float(c.cvss_score) if c.cvss_score is not None else None,
            "severity": c.severity,
            "description": c.description,
            "exploit_status": c.exploit_status,
            "epss_score": c.epss_score,
            "is_kev": c.is_kev,
            "github_poc_count": c.github_poc_count,
            "metasploit_module": c.metasploit_module,
            "first_seen_at": c.first_seen_at.isoformat() if c.first_seen_at else None,
        }
        for c in cves_rows
    ]

    ttps_rows = (
        (
            await db.execute(
                select(TTP)
                .join(EntryTTP, EntryTTP.ttp_id == TTP.id)
                .where(EntryTTP.entry_id.in_(entry_ids_select))
                .distinct()
            )
        )
        .scalars()
        .all()
    )
    ttps = [
        {
            "id": str(t.id),
            "technique_id": t.technique_id,
            "technique_name": t.technique_name,
            "tactic": t.tactic,
            "description": t.description,
            "article_count": t.article_count,
            "first_seen_at": t.first_seen_at.isoformat() if t.first_seen_at else None,
        }
        for t in ttps_rows
    ]

    def _named_common(o) -> dict:
        """Metadata shared by every named-entity type — the same fields the
        entry reader's popover renders (description, aliases, image, counts)."""
        return {
            "id": str(o.id),
            "name": o.name,
            "aliases": list(o.aliases or []),
            "description": o.description,
            "article_count": o.article_count,
            "first_seen_at": o.first_seen_at.isoformat() if o.first_seen_at else None,
            "wikipedia_url": o.wikipedia_url,
            "wikipedia_image_url": o.wikipedia_image_url,
        }

    async def _named_with_matched(model, junction_model, junction_fk_attr: str, serialize):
        """Fetch named entities + the union of matched_names from any junction
        row linking that entity to an entry in the day window. ``serialize``
        builds the per-type payload from the full ORM object."""
        fk = getattr(junction_model, junction_fk_attr)
        rows = (
            await db.execute(
                select(model, junction_model.matched_names)
                .join(junction_model, fk == model.id)
                .where(junction_model.entry_id.in_(entry_ids_select))
            )
        ).all()

        by_id: dict[uuid.UUID, dict] = {}
        for obj, matched in rows:
            entry = by_id.get(obj.id)
            if entry is None:
                entry = serialize(obj)
                entry["_matched"] = set()
                by_id[obj.id] = entry
            if matched:
                entry["_matched"].update(matched)

        out = []
        for v in by_id.values():
            v["matched_names"] = sorted(v.pop("_matched"))
            out.append(v)
        return out

    def _ser_actor(o):
        return {
            **_named_common(o),
            "mitre_id": o.mitre_id,
            "country": o.country,
            "motivation": o.motivation,
            "targeted_sectors": list(o.targeted_sectors or []),
        }

    def _ser_malware(o):
        return {
            **_named_common(o),
            "malware_type": o.malware_type,
            "malpedia_url": o.malpedia_url,
        }

    def _ser_vendor(o):
        return {**_named_common(o), "vendor_type": o.vendor_type, "website": o.website}

    def _ser_product(o):
        return {
            **_named_common(o),
            "product_type": o.product_type,
            "website": o.website,
        }

    def _ser_country(o):
        return {**_named_common(o), "region": o.region}

    def _ser_tool(o):
        return {
            **_named_common(o),
            "tool_type": o.tool_type,
            "platforms": list(o.platforms or []),
            "github_url": o.github_url,
            "malpedia_url": o.malpedia_url,
            "detection_artifacts": o.detection_artifacts or {},
        }

    actors = await _named_with_matched(ThreatActor, EntryThreatActor, "threat_actor_id", _ser_actor)
    malware = await _named_with_matched(MalwareFamily, EntryMalware, "malware_family_id", _ser_malware)
    vendors = await _named_with_matched(Vendor, EntryVendor, "vendor_id", _ser_vendor)
    products = await _named_with_matched(Product, EntryProduct, "product_id", _ser_product)
    countries = await _named_with_matched(Country, EntryCountry, "country_id", _ser_country)
    tools = await _named_with_matched(Tool, EntryTool, "tool_id", _ser_tool)

    # Mitigation has no aliases / no matched_names junction column; surface
    # name + MITRE M-ID as link targets.
    mitigations_rows = (
        (
            await db.execute(
                select(Mitigation)
                .join(EntryMitigation, EntryMitigation.mitigation_id == Mitigation.id)
                .where(EntryMitigation.entry_id.in_(entry_ids_select))
                .distinct()
            )
        )
        .scalars()
        .all()
    )
    mitigations = [
        {
            "id": str(m.id),
            "name": m.name,
            "mitre_id": m.mitre_id,
            "mitre_url": m.mitre_url,
            "description": m.description,
            "article_count": m.article_count,
            "first_seen_at": m.first_seen_at.isoformat() if m.first_seen_at else None,
            "wikipedia_url": m.wikipedia_url,
            "wikipedia_image_url": m.wikipedia_image_url,
        }
        for m in mitigations_rows
    ]

    return {
        "cves": cves,
        "ttps": ttps,
        "actors": actors,
        "malware": malware,
        "vendors": vendors,
        "products": products,
        "countries": countries,
        "tools": tools,
        "mitigations": mitigations,
    }


@router.post("/daily-summary")
async def generate_daily_summary(
    req: DailySummaryRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate an AI summary of all entries in the given day-window+filters.

    Cached on the AIResult table — same (user, day_key, filters) returns the
    cached summary unless force=True. The cache survives across sessions so
    revisits to a day divider don't re-spend tokens."""
    from app.ai.engine import run_task
    from app.models.ai_result import AIResult
    from app.models.ai_task import AITask

    filters_dict = _filters_for_cache_key(req)
    # A "Summarize day" on the default all-view writes the shared global row so
    # every user benefits; filtered summaries stay per-user.
    is_global = _is_global_scope(filters_dict)
    scoped_user_id = _scope_user_id(user.id, filters_dict)
    target_id = _daily_summary_target_id(scoped_user_id, req.day_key, filters_dict)

    # Fast path: serve cache without an AI call (unless forced re-run)
    if not req.force:
        task_row = await db.execute(select(AITask.id).where(AITask.name == "daily_summary"))
        task_id = task_row.scalar_one_or_none()
        if task_id:
            existing = await db.execute(
                select(AIResult)
                .where(
                    AIResult.target_type == "daily_summary",
                    AIResult.target_id == target_id,
                    AIResult.task_id == task_id,
                    AIResult.is_current == True,  # noqa: E712
                )
                .order_by(AIResult.created_at.desc())
                .limit(1)
            )
            cached = existing.scalar_one_or_none()
            if cached and cached.parsed_result and "summary" in (cached.parsed_result or {}):
                return {
                    "summary": cached.parsed_result.get("summary"),
                    "cached": True,
                    "generated_at": cached.created_at,
                    "entry_count": None,
                }

    # Gather entries for the day-window (already projected to prompt-friendly dicts).
    # Global scope ignores the caller's per-user state (hidden/read/…).
    entry_payloads = await _fetch_day_entries(db, None if is_global else user, req)
    if not entry_payloads:
        raise AppError(
            code="bad_request",
            message="No entries match this day's filters",
            status_code=400,
        )

    scope_bits: list[str] = []
    if req.feed_id:
        scope_bits.append("single feed")
    elif req.category_id:
        scope_bits.append("category")
    if req.is_starred:
        scope_bits.append("starred")
    if req.is_bookmarked:
        scope_bits.append("bookmarked")
    if req.is_read is False:
        scope_bits.append("unread")
    scope_label = ", ".join(scope_bits)

    parsed = await run_task(
        db,
        scoped_user_id,
        task_name="daily_summary",
        variables={
            "entries": entry_payloads,
            "entry_count": len(entry_payloads),
            "date_label": req.day_key,
            "scope_label": scope_label,
        },
        target_type="daily_summary",
        target_id=target_id,
        force=req.force,
    )

    if parsed is None:
        raise AppError(
            code="ai_not_configured",
            message="No AI provider assigned to the daily_summary task. Configure one in Settings → AI Configuration.",
            status_code=503,
        )
    if isinstance(parsed, dict) and parsed.get("_error"):
        raise AppError(
            code="ai_error",
            message=parsed.get("_error") or "AI generation failed",
            status_code=502,
        )

    await db.commit()

    return {
        "summary": (parsed or {}).get("summary"),
        "cached": False,
        "generated_at": datetime.now(UTC),
        "entry_count": len(entry_payloads),
    }


@router.get("/{entry_id}", response_model=EntryDetailResponse)
async def get_entry(
    entry_id: uuid.UUID = Path(..., description="Entry UUID"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Full detail for one entry: content, translation fields, per-user state,
    cross-feed duplicates, and — when the signal engine surfaces — priority
    signals plus My Stack exposure."""
    result = await db.execute(select(Entry).where(Entry.id == entry_id))
    entry = result.scalar_one_or_none()
    if not entry:
        raise AppError(code="not_found", message="Entry not found", status_code=404)

    # Get user state
    state_result = await db.execute(
        select(UserEntryState).where(UserEntryState.user_id == user.id, UserEntryState.entry_id == entry_id)
    )
    state = state_result.scalar_one_or_none()

    # Get feed title and type
    feed_result = await db.execute(select(Feed.title, Feed.feed_type).where(Feed.id == entry.feed_id))
    feed_row = feed_result.one_or_none()
    if not feed_row:
        raise AppError(code="not_found", message="Entry not found", status_code=404)
    feed_title = feed_row[0]
    feed_type = feed_row[1]

    # Get media attachments
    media_result = await db.execute(select(EntryMedia).where(EntryMedia.entry_id == entry_id))
    media_items = [
        EntryMediaBrief(
            id=m.id,
            media_type=m.media_type,
            url=m.url,
            thumbnail_url=m.thumbnail_url,
            duration_seconds=m.duration_seconds,
        )
        for m in media_result.scalars().all()
    ]

    # Get duplicates (entries with same content_hash from different feeds)
    duplicates = []
    if entry.content_hash:
        dup_result = await db.execute(
            select(Entry.id, Feed.title, Feed.id.label("feed_id"))
            .join(Feed, Feed.id == Entry.feed_id)
            .where(
                Entry.content_hash == entry.content_hash,
                Entry.id != entry.id,
                Entry.feed_id != entry.feed_id,
                Feed.title != feed_title,  # skip feeds with the same name
            )
        )
        for dup_entry_id, dup_feed_title, dup_feed_id in dup_result.all():
            duplicates.append(
                EntryDuplicate(
                    entry_id=dup_entry_id,
                    feed_title=dup_feed_title,
                    feed_id=dup_feed_id,
                )
            )

    # Signal engine chips — mirror the list endpoint: only surfaced when the
    # signal_engine_surface setting is on, and the score clears the radar threshold.
    priority_score: float | None = None
    top_signals: list[dict] = []
    priority_signals: list[dict] = []
    personal: dict | None = None
    is_echo = False
    echo_of: EchoOf | None = None
    echo_payload: dict | None = None
    if bool(await get_setting("signal_engine_surface", db)):
        from app.intelligence.signals import (
            DEFAULT_FIRING_RATES,
            ECHO_WEIGHT,
            SIGNAL_FAMILIES,
            get_family_multipliers,
            get_feedback_nudges,
            get_radar_threshold,
            get_signal_rates,
            idf_weight,
        )
        from app.models.entry_signal import EntrySignal

        chip_threshold, _ = await get_radar_threshold()
        # The reader plots each signal's real contribution to the score, not its
        # raw strength: compute_priority_score weights every hit by how rare its
        # type is, so a raw 0.9 from a signal that fires on 43% of entries is
        # worth less than a raw 0.6 from one that fires on 1%. Charting the raw
        # numbers drew the smallest contributor as the longest bar.
        rates = {**DEFAULT_FIRING_RATES, **(await get_signal_rates())}
        # Mirror score_entry exactly, nudges included — multipliers alone put the
        # rows ~20% off the header on any family the pooled feedback has moved.
        multipliers = await get_family_multipliers()
        nudges = await get_feedback_nudges()
        if nudges:
            multipliers = {k: v * nudges.get(k, 1.0) for k, v in multipliers.items()}

        def _weighted(signal_type: str, score: float) -> float:
            family = SIGNAL_FAMILIES.get(signal_type, "interest")
            mult = multipliers.get(family, 1.0)
            base = ECHO_WEIGHT if signal_type == "feed_echo" else idf_weight(rates.get(signal_type, 0.05))
            return round((score or 0) * base * mult, 3)

        sig_result = await db.execute(
            select(EntrySignal).where(EntrySignal.entry_id == entry.id).order_by(EntrySignal.score.desc())
        )
        for sig in sig_result.scalars().all():
            if sig.signal_type == "feed_echo":
                is_echo = True
                echo_payload = sig.payload or {}
                # Still surfaced: an echo *subtracts* from the score, and hiding
                # it left the card unable to explain why a story ranked low.
            elif len(top_signals) < 2:
                top_signals.append({"type": sig.signal_type, "explanation": sig.explanation})
            priority_signals.append(
                {
                    "type": sig.signal_type,
                    "family": SIGNAL_FAMILIES.get(sig.signal_type, "other"),
                    "score": round(sig.score, 3),
                    "weighted": _weighted(sig.signal_type, sig.score),
                    "explanation": sig.explanation,
                }
            )
        if entry.priority_score is not None and entry.priority_score >= chip_threshold:
            priority_score = entry.priority_score
        else:
            top_signals = []
            priority_signals = []

        # Learned Radar weights: the same read-time lift the Radar ordering uses,
        # resolved for this one entry so the reader can show which of the analyst's
        # own families moved it and by how much.
        if priority_score is not None and bool(await get_setting("radar_personalization_enabled", db)):
            from app.services.radar_personalization import (
                enrich_personal,
                get_personal_coefficients,
                get_user_weights,
                is_personalization_opted_in,
            )

            if is_personalization_opted_in(user.settings):
                coeffs = await get_personal_coefficients(db, user.id)
                if coeffs:
                    detail = await enrich_personal(db, [entry.id], coeffs, await get_user_weights(db, user.id))
                    personal = detail.get(entry.id)

        # Resolve the earlier entry this one echoes so the reader can link to it.
        dup_id = (echo_payload or {}).get("duplicate_of")
        if is_echo and dup_id:
            try:
                dup_uuid = uuid.UUID(str(dup_id))
            except (ValueError, TypeError):
                dup_uuid = None
            if dup_uuid:
                orig_row = (
                    await db.execute(
                        select(Entry.title, Entry.published_at, Feed.title)
                        .join(Feed, Feed.id == Entry.feed_id)
                        .where(Entry.id == dup_uuid)
                    )
                ).first()
                if orig_row:
                    echo_of = EchoOf(
                        entry_id=dup_uuid,
                        title=orig_row[0],
                        feed_title=orig_row[2],
                        published_at=orig_row[1],
                        shared=(echo_payload or {}).get("shared"),
                        total=(echo_payload or {}).get("total"),
                    )

    # My Stack exposure for the reader's Why card (read-time, per-user).
    exposure: dict | None = None
    if bool(await get_setting("my_stack_exposure_enabled", db)):
        from app.intelligence.cve import get_epss_high_risk_threshold
        from app.services.exposure import enrich_exposure, get_user_stack

        vendor_ids, product_ids = await get_user_stack(db, user.id)
        if vendor_ids or product_ids:
            exposure_map = await enrich_exposure(
                db, [entry.id], vendor_ids, product_ids, get_epss_high_risk_threshold()
            )
            exposure = exposure_map.get(entry.id)

    return EntryDetailResponse(
        id=entry.id,
        feed_id=entry.feed_id,
        guid=entry.guid,
        url=entry.url,
        title=entry.title,
        translated_title=entry.translated_title,
        author=entry.author,
        summary=entry.summary,
        content_html=entry.content_html,
        content_text=entry.content_text,
        published_at=entry.published_at,
        fetched_at=entry.fetched_at,
        word_count=entry.word_count,
        content_hash=entry.content_hash,
        feed_title=feed_title,
        feed_type=feed_type,
        metadata=entry.metadata_,
        media=media_items,
        is_read=state.is_read if state else False,
        is_starred=state.is_starred if state else False,
        is_bookmarked=state.is_bookmarked if state else False,
        duplicates=duplicates,
        translated_html=entry.translated_html,
        translation_source_language=entry.translation_source_language,
        translation_target_language=entry.translation_target_language,
        translated_at=entry.translated_at,
        priority_score=priority_score,
        top_signals=top_signals,
        priority_signals=priority_signals,
        is_echo=is_echo,
        echo_of=echo_of,
        exposure=exposure,
        personal=personal,
    )


@router.post("/{entry_id}/translate", response_model=TranslateEntryResponse)
async def translate_entry(
    entry_id: uuid.UUID = Path(..., description="Entry UUID"),
    target: str = Query(default="", description="Target ISO-639-1 code; defaults to settings."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Translate an entry's HTML content via the LibreTranslate sidecar.

    Result is cached on the entry row. Re-requesting with the same target
    language returns the cached translation; a different target re-translates.
    """
    from app.config import settings as app_settings

    target_lang = (target or app_settings.get("translation_default_target") or "en").lower()

    result = await db.execute(select(Entry).where(Entry.id == entry_id))
    entry = result.scalar_one_or_none()
    if not entry:
        raise AppError(code="not_found", message="Entry not found", status_code=404)

    source_html = entry.content_html or (f"<p>{entry.summary}</p>" if entry.summary else "")
    if not source_html.strip():
        raise AppError(
            code="bad_request",
            message="Entry has no content to translate",
            status_code=400,
        )

    if entry.translated_html and entry.translation_target_language == target_lang:
        return TranslateEntryResponse(
            entry_id=entry.id,
            translated_html=entry.translated_html,
            translated_title=entry.translated_title,
            source_language=entry.translation_source_language or entry.language or "auto",
            target_language=target_lang,
            translated_at=entry.translated_at or datetime.now(UTC),
            cached=True,
        )

    # /detect is unreliable on short text (returns 0.0-confidence "en" for clearly
    # non-English). Only honor a confident detection; otherwise let /translate
    # auto-detect server-side and don't reject the user's request.
    detected_lang = entry.language
    if not detected_lang:
        sample = (entry.content_text or entry.title or "")[:2000]
        if sample.strip():
            try:
                cand, conf = await translation.detect_language(sample)
                if conf >= 0.5:
                    detected_lang = cand
            except translation.TranslationError:
                detected_lang = None

    if detected_lang and detected_lang.lower() == target_lang:
        raise AppError(
            code="already_target_language",
            message=f"Entry is already in {target_lang}",
            status_code=400,
        )

    translated, body_detected = await translation.translate_html(
        source_html, source=detected_lang or "auto", target=target_lang
    )

    title_source = detected_lang or body_detected or "auto"
    translated_title: str | None = None
    if entry.title and entry.title.strip():
        try:
            translated_title, _ = await translation.translate_text(entry.title, source=title_source, target=target_lang)
        except translation.TranslationError:
            translated_title = None

        if (
            translated_title is not None
            and translated_title.strip() == entry.title.strip()
            and title_source == "auto"
            and body_detected
            and body_detected.lower() != target_lang
        ):
            try:
                retried, _ = await translation.translate_text(entry.title, source=body_detected, target=target_lang)
                if retried and retried.strip() != entry.title.strip():
                    translated_title = retried
            except translation.TranslationError:
                pass

    effective_source = detected_lang or body_detected
    now = datetime.now(UTC)
    entry.translated_html = translated
    if translated_title:
        entry.translated_title = translated_title
    entry.translation_source_language = effective_source or "auto"
    entry.translation_target_language = target_lang
    entry.translated_at = now
    if effective_source and not entry.language:
        entry.language = effective_source
    db.add(entry)
    await db.flush()

    return TranslateEntryResponse(
        entry_id=entry.id,
        translated_html=translated,
        translated_title=translated_title,
        source_language=effective_source or "auto",
        target_language=target_lang,
        translated_at=now,
        cached=False,
    )


@router.get("/{entry_id}/similar")
async def get_similar_entries(
    entry_id: uuid.UUID = Path(..., description="Entry UUID"),
    limit: int = Query(10, ge=1, le=30, description="Maximum similar entries to return"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Find entries similar to the given entry.

    Prefers the embedding index: cosine nearest neighbours find the article that
    tells the same story in different words, which keyword search structurally
    cannot. Falls back to Meilisearch term overlap for entries that have not
    been embedded yet (or when embeddings are switched off entirely), so the
    reader's "More like this" never goes dark.
    """
    result = await db.execute(select(Entry).where(Entry.id == entry_id))
    entry = result.scalar_one_or_none()
    if not entry:
        raise AppError(code="not_found", message="Entry not found", status_code=404)

    # This entry plus its content-hash duplicates: syndicated copies are a
    # perfect match to the anchor and a useless answer on either path.
    duplicate_ids: list[uuid.UUID] = []
    if entry.content_hash:
        dup_result = await db.execute(
            select(Entry.id).where(
                Entry.content_hash == entry.content_hash,
                Entry.id != entry_id,
            )
        )
        duplicate_ids = [row[0] for row in dup_result.all()]

    from app.intelligence.story_threads import similar_entries as vector_similar

    neighbours = await vector_similar(db, entry_id, limit=limit, exclude_ids=duplicate_ids)
    if neighbours:
        thread_slugs = {}
        thread_ids = [n["thread_id"] for n in neighbours if n["thread_id"]]
        if thread_ids:
            from app.models.story_thread import StoryThread

            rows = await db.execute(
                select(StoryThread.id, StoryThread.slug, StoryThread.title).where(StoryThread.id.in_(thread_ids))
            )
            thread_slugs = {r.id: (r.slug, r.title) for r in rows.all()}
        return {
            "items": [
                {
                    "id": str(n["entry_id"]),
                    "title": n["title"],
                    "feed_title": n["feed_title"],
                    "published_at": int(n["published_at"].timestamp()) if n["published_at"] else None,
                    "url": n["url"],
                    "similarity": round(float(n["similarity"] or 0), 3),
                    "thread_slug": thread_slugs.get(n["thread_id"], (None, None))[0],
                    "thread_title": thread_slugs.get(n["thread_id"], (None, None))[1],
                }
                for n in neighbours
            ],
            "total": len(neighbours),
            "query_keywords": [],
            "method": "embedding",
        }

    exclude_ids = [str(entry_id), *(str(d) for d in duplicate_ids)]

    search_result = meilisearch_client.find_similar_entries(
        entry_id=str(entry_id),
        title=entry.title or "",
        summary=entry.summary,
        content_text=entry.content_text,
        exclude_ids=exclude_ids,
        limit=limit,
    )

    return {
        "items": search_result.get("hits", []),
        "total": search_result.get("estimatedTotalHits", 0),
        "query_keywords": search_result.get("query_keywords", []),
        "method": "keyword",
    }


@router.get("/{entry_id}/media", response_model=list[EntryMediaResponse])
async def get_entry_media(
    entry_id: uuid.UUID = Path(..., description="Entry UUID"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get all media attachments for an entry."""
    result = await db.execute(select(Entry).where(Entry.id == entry_id))
    entry = result.scalar_one_or_none()
    if not entry:
        raise AppError(code="not_found", message="Entry not found", status_code=404)

    media_result = await db.execute(select(EntryMedia).where(EntryMedia.entry_id == entry_id))
    return media_result.scalars().all()


@router.get("/{entry_id}/urls")
async def get_entry_urls(
    entry_id: uuid.UUID = Path(..., description="Entry UUID"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Extract referenced URLs from entry HTML content."""
    import re
    from html import unescape
    from urllib.parse import urlparse

    result = await db.execute(select(Entry).where(Entry.id == entry_id))
    entry = result.scalar_one_or_none()
    if not entry:
        raise AppError(code="not_found", message="Entry not found", status_code=404)

    html = entry.content_html or entry.summary or ""
    if not html:
        return []

    # Extract all <a href="...">context</a> pairs
    link_pattern = re.compile(r'<a\s[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL)
    seen = set()
    urls = []
    for match in link_pattern.finditer(html):
        href = unescape(match.group(1)).strip()
        context_html = match.group(2).strip()
        # Strip inner HTML tags for clean context text
        context = re.sub(r"<[^>]+>", "", context_html).strip()

        # Skip non-http, anchors, mailto, javascript
        parsed = urlparse(href)
        if parsed.scheme not in ("http", "https"):
            continue
        # Skip image proxy URLs
        if "/api/image-proxy" in href:
            continue
        # Deduplicate
        if href in seen:
            continue
        seen.add(href)
        urls.append({"url": href, "context": context or href})

    return urls


async def _invalidate_unread_cache(user_id: uuid.UUID) -> None:
    """Delete the cached feed unread counts for a user."""
    try:
        from app.services.redis_client import get_redis

        r = await get_redis()
        await r.delete(f"feed_unreads:{user_id}")
    except Exception:
        pass


async def _get_or_create_state(db: AsyncSession, user_id: uuid.UUID, entry_id: uuid.UUID) -> UserEntryState:
    result = await db.execute(
        select(UserEntryState).where(UserEntryState.user_id == user_id, UserEntryState.entry_id == entry_id)
    )
    state = result.scalar_one_or_none()
    if not state:
        state = UserEntryState(user_id=user_id, entry_id=entry_id)
        db.add(state)
    return state


@router.put("/{entry_id}/read")
async def mark_read(
    entry_id: uuid.UUID = Path(..., description="Entry UUID"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Mark the entry as read for the current user and sync the flag to the search index."""
    state = await _get_or_create_state(db, user.id, entry_id)
    state.is_read = True
    state.read_at = func.now()
    db.add(state)
    await db.flush()
    await _invalidate_unread_cache(user.id)
    meilisearch_client.update_entry_state(entry_id, is_read=True)
    return {"message": "Marked as read"}


@router.put("/{entry_id}/unread")
async def mark_unread(
    entry_id: uuid.UUID = Path(..., description="Entry UUID"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Mark the entry as unread for the current user and sync the flag to the search index."""
    state = await _get_or_create_state(db, user.id, entry_id)
    state.is_read = False
    state.read_at = None
    db.add(state)
    await db.flush()
    await _invalidate_unread_cache(user.id)
    meilisearch_client.update_entry_state(entry_id, is_read=False)
    return {"message": "Marked as unread"}


@router.put("/{entry_id}/star")
async def toggle_star(
    entry_id: uuid.UUID = Path(..., description="Entry UUID"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Toggle the entry's starred flag for the current user; returns the new value."""
    state = await _get_or_create_state(db, user.id, entry_id)
    state.is_starred = not state.is_starred
    db.add(state)
    await db.flush()
    meilisearch_client.update_entry_state(entry_id, is_starred=state.is_starred)
    return {"is_starred": state.is_starred}


@router.put("/{entry_id}/bookmark")
async def toggle_bookmark(
    entry_id: uuid.UUID = Path(..., description="Entry UUID"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Toggle the entry's bookmarked flag for the current user; returns the new value."""
    state = await _get_or_create_state(db, user.id, entry_id)
    state.is_bookmarked = not state.is_bookmarked
    db.add(state)
    await db.flush()
    meilisearch_client.update_entry_state(entry_id, is_bookmarked=state.is_bookmarked)
    return {"is_bookmarked": state.is_bookmarked}


@router.post("/mark-all-read")
async def mark_all_read(
    request: MarkAllReadRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Bulk-mark entries as read, scoped by feed/category and an optional since/before
    window. radar_only restricts it to Priority Queue (radar-surfaced) entries. The
    search-index sync runs on a background worker; returns the number of entries marked."""
    # Get feed IDs to mark — scoped to the caller's visible feeds so "mark all
    # read" doesn't write state rows for feeds they don't subscribe to
    feed_query = visible_feed_ids_query(user.id, enabled=await subscriptions_enabled(db), include_muted=True)
    if request.feed_id:
        feed_query = feed_query.where(Feed.id == request.feed_id)
    if request.category_id:
        feed_query = feed_query.where(Feed.category_id == request.category_id)

    feed_ids_result = await db.execute(feed_query)
    feed_ids = [row[0] for row in feed_ids_result.all()]

    if not feed_ids:
        return {"marked": 0}

    # Subquery: all entry IDs matching the filter
    entry_sub = select(Entry.id).where(Entry.feed_id.in_(feed_ids))
    if request.since:
        entry_sub = entry_sub.where(Entry.published_at >= request.since)
    if request.before:
        entry_sub = entry_sub.where(Entry.published_at <= request.before)

    # Priority Queue: only clear entries that actually surface on the radar, so
    # "Mark All Read" empties the queue rather than every unread entry. If
    # surfacing is off there's no queue to clear — mark nothing.
    if request.radar_only:
        if not bool(await get_setting("signal_engine_surface", db)):
            return {"marked": 0}
        from app.intelligence.signals import get_radar_threshold

        radar_threshold, _ = await get_radar_threshold()
        entry_sub = entry_sub.where(Entry.priority_score >= radar_threshold)

    # 1. Bulk UPDATE: set existing unread states to read (RETURNING so we sync
    #    only the entries we actually changed to the search index, not the whole feed).
    update_result = await db.execute(
        update(UserEntryState)
        .where(
            UserEntryState.user_id == user.id,
            UserEntryState.entry_id.in_(entry_sub),
            UserEntryState.is_read == False,  # noqa: E712
        )
        .values(is_read=True, read_at=func.now())
        .returning(UserEntryState.entry_id)
    )
    updated_ids = [row[0] for row in update_result.all()]
    updated_count = len(updated_ids)

    # 2. Bulk INSERT: create read states for entries that have no state row yet
    missing_sub = entry_sub.where(has_no_state_for_user(user.id))
    missing_result = await db.execute(missing_sub)
    missing_ids = [row[0] for row in missing_result.all()]

    if missing_ids:
        await db.execute(
            insert(UserEntryState),
            [
                {
                    "id": uuid.uuid4(),
                    "user_id": user.id,
                    "entry_id": eid,
                    "is_read": True,
                    "is_starred": False,
                    "is_bookmarked": False,
                    "is_hidden": False,
                    "read_at": datetime.now(UTC),
                }
                for eid in missing_ids
            ],
        )

    marked = updated_count + len(missing_ids)
    if marked == 0:
        return {"marked": 0}

    await db.flush()
    await _invalidate_unread_cache(user.id)

    # Sync read state to Meilisearch off the request path: only the entries we
    # actually marked, dispatched to a Celery worker. Doing this inline for the
    # whole feed previously blocked past the 15s client timeout, which cancelled
    # the request before commit and silently rolled back the read-state write.
    marked_ids = [str(eid) for eid in (updated_ids + missing_ids)]
    try:
        from app.workers.intel_feed_tasks import sync_read_state_to_search

        sync_read_state_to_search.delay(marked_ids, True)
    except Exception:
        logger.warning("Failed to dispatch read-state search sync", exc_info=True)

    return {"marked": marked}


ALLOWED_BULK_ACTIONS = {
    "read",
    "unread",
    "star",
    "unstar",
    "bookmark",
    "unbookmark",
    "hide",
}


@router.post("/bulk-action")
async def bulk_action(
    request: BulkActionRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Apply one state action (read, unread, star, unstar, bookmark, unbookmark, hide)
    to a list of entries; hide also marks entries as read. Returns the count actually
    changed."""
    if request.action not in ALLOWED_BULK_ACTIONS:
        raise AppError(
            code="bad_request",
            message=f"Invalid action. Must be one of: {', '.join(sorted(ALLOWED_BULK_ACTIONS))}",
            status_code=400,
        )

    if not request.entry_ids:
        return {"updated": 0}

    # Batch-fetch existing states to avoid N+1 queries
    existing_result = await db.execute(
        select(UserEntryState).where(
            UserEntryState.user_id == user.id,
            UserEntryState.entry_id.in_(request.entry_ids),
        )
    )
    states_by_entry = {s.entry_id: s for s in existing_result.scalars().all()}

    updated = 0
    for entry_id in request.entry_ids:
        state = states_by_entry.get(entry_id)
        if not state:
            state = UserEntryState(user_id=user.id, entry_id=entry_id)
        if request.action == "read":
            if not state.is_read:
                state.is_read = True
                state.read_at = func.now()
                updated += 1
        elif request.action == "unread":
            if state.is_read:
                state.is_read = False
                state.read_at = None
                updated += 1
        elif request.action == "star":
            if not state.is_starred:
                state.is_starred = True
                updated += 1
        elif request.action == "unstar":
            if state.is_starred:
                state.is_starred = False
                updated += 1
        elif request.action == "bookmark":
            if not state.is_bookmarked:
                state.is_bookmarked = True
                updated += 1
        elif request.action == "unbookmark":
            if state.is_bookmarked:
                state.is_bookmarked = False
                updated += 1
        elif request.action == "hide":
            if not state.is_hidden:
                state.is_hidden = True
                state.is_read = True
                state.read_at = func.now()
                updated += 1
        db.add(state)

    await db.flush()
    if request.action in ("read", "unread", "hide"):
        await _invalidate_unread_cache(user.id)

    # Sync state changes to Meilisearch
    state_map = {
        "read": {"is_read": True},
        "unread": {"is_read": False},
        "star": {"is_starred": True},
        "unstar": {"is_starred": False},
        "bookmark": {"is_bookmarked": True},
        "unbookmark": {"is_bookmarked": False},
        "hide": {"is_read": True},
    }
    meili_kwargs = state_map.get(request.action, {})
    if meili_kwargs:
        for entry_id in request.entry_ids:
            try:
                meilisearch_client.update_entry_state(entry_id, **meili_kwargs)
            except Exception:
                pass  # Non-critical — search state will self-correct

    return {"updated": updated}


class ResolveNamesRequest(BaseModel):
    ids: list[uuid.UUID]

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "ids": [
                    "d5b2f1a4-3c6e-4b8a-9f21-7e5a2c9d1b34",
                    "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
                ]
            }
        }
    )


@router.post("/resolve-names")
async def resolve_entry_names(
    body: ResolveNamesRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Resolve entry UUIDs to {id, title, feed_title} for display."""
    if not body.ids:
        return []
    result = await db.execute(
        select(
            Entry.id,
            Entry.title,
            func.coalesce(Feed.custom_title, Feed.title).label("feed_title"),
        )
        .join(Feed, Entry.feed_id == Feed.id, isouter=True)
        .where(Entry.id.in_(body.ids))
    )
    return [
        {
            "id": str(row.id),
            "title": row.title or "Untitled",
            "feed_title": row.feed_title or "",
        }
        for row in result.all()
    ]
