"""Correlation API — pivot, graph, search, timeline, detection summary, events."""

import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Path, Query
from sqlalchemy import delete as sql_delete
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppError
from app.core.security import get_admin_user, get_current_user, get_entry_viewer, get_viewer
from app.database import get_db
from app.intelligence.correlation import (
    ENTITY_CONFIG,
    PIVOT_SOURCE_TYPES,
    VALID_ENTITY_TYPES,
    _get_entry_ids_for_entity,
    build_entity_graph,
    build_entry_graph,
    entity_timeline,
    get_entity,
    pivot_from_entity,
    search_all_entities,
    temporal_clusters,
)
from app.intelligence.detection_summary import build_detection_summary
from app.models.correlation_event import CorrelationEventRecord
from app.models.detection_summary import DetectionSummary
from app.models.user import User
from app.schemas.intelligence import (
    CategoryCount,
    CorrelationEventListResponse,
    CorrelationEventResponse,
    DetectionSummaryCreateRequest,
    DetectionSummaryRequest,
    DetectionSummaryResponse,
    DetectionSummarySavedResponse,
    EntitySearchResponse,
    GraphResponse,
    GroupedCorrelationEventListResponse,
    GroupedCorrelationEventsEntry,
    PivotResponse,
    TimelineResponse,
)
from app.services.public_view import entities_shown, visitor_events_only

router = APIRouter()


def _validate_pivot_source(entity_type: str) -> None:
    """Pivot / graph / timeline additionally accept a campaign as the source."""
    if entity_type not in PIVOT_SOURCE_TYPES:
        # Same code and status as the stricter validator below — widening the
        # accepted set must not change what a genuinely bad type returns.
        raise AppError(
            code="bad_request",
            message=f"Invalid entity type '{entity_type}'. Must be one of: {', '.join(sorted(PIVOT_SOURCE_TYPES))}",
            status_code=400,
        )


def _validate_entity_type(entity_type: str) -> None:
    if entity_type not in VALID_ENTITY_TYPES:
        raise AppError(
            code="bad_request",
            message=f"Invalid entity type '{entity_type}'. Must be one of: {', '.join(sorted(VALID_ENTITY_TYPES))}",
            status_code=400,
        )


@router.get("/events", response_model=CorrelationEventListResponse)
async def list_correlation_events(
    event_type: str | None = Query(
        None, description="Filter to a single event type (ignored when event_types is provided)."
    ),
    event_types: str | None = Query(default=None, description="Comma-separated list of event types"),
    is_read: bool | None = Query(None, description="Filter by read state (true = read only, false = unread only)."),
    limit: int = Query(default=50, ge=1, le=500, description="Maximum number of events to return."),
    offset: int = Query(default=0, ge=0, description="Number of events to skip for pagination."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List correlation events, newest first."""
    q = select(CorrelationEventRecord).order_by(CorrelationEventRecord.created_at.desc())
    count_q = select(func.count(CorrelationEventRecord.id))
    unread_q = select(func.count(CorrelationEventRecord.id)).where(CorrelationEventRecord.is_read == False)  # noqa: E712

    if event_types:
        type_list = [t.strip() for t in event_types.split(",") if t.strip()]
        q = q.where(CorrelationEventRecord.event_type.in_(type_list))
        count_q = count_q.where(CorrelationEventRecord.event_type.in_(type_list))
        unread_q = unread_q.where(CorrelationEventRecord.event_type.in_(type_list))
    elif event_type:
        q = q.where(CorrelationEventRecord.event_type == event_type)
        count_q = count_q.where(CorrelationEventRecord.event_type == event_type)
    if is_read is not None:
        q = q.where(CorrelationEventRecord.is_read == is_read)
        count_q = count_q.where(CorrelationEventRecord.is_read == is_read)

    total = (await db.execute(count_q)).scalar() or 0
    unread_count = (await db.execute(unread_q)).scalar() or 0

    result = await db.execute(q.offset(offset).limit(limit))
    items = [CorrelationEventResponse.model_validate(r) for r in result.scalars().all()]

    return CorrelationEventListResponse(items=items, total=total, unread_count=unread_count)


EVENT_CATEGORIES: dict[str, list[str]] = {
    "correlations": [
        "new_ttp_for_known_actor",
        "new_ttp_for_known_malware",
        "new_malware_for_known_actor",
        "actor_malware_cooccurrence",
    ],
    "coverage": [
        "coverage_gap",
        "exploit_status_change",
        "cve_score_change",
        "new_exploit_discovered",
        "kev_addition",
        "trending_entity",
    ],
    "feed_health": [
        "feed_stale",
        "feed_error",
    ],
}

CATEGORY_FOR_TYPE: dict[str, str] = {t: cat for cat, types in EVENT_CATEGORIES.items() for t in types}

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}

EVENT_SEVERITY: dict[str, str] = {
    "coverage_gap": "high",
    "exploit_status_change": "high",
    "cve_score_change": "high",
    "new_exploit_discovered": "high",
    "kev_addition": "high",
    "new_ttp_for_known_actor": "medium",
    "new_ttp_for_known_malware": "medium",
    "new_malware_for_known_actor": "medium",
    "actor_malware_cooccurrence": "medium",
    "trending_entity": "medium",
    "feed_stale": "low",
    "feed_error": "low",
}


def _parse_time_bound(value: str | None) -> datetime | None:
    """Parse a time bound: ISO datetime/date, or shorthand like 24h / 7d / 30d.

    Shorthand is resolved relative to now. Naive values are assumed UTC so the
    comparison against the timezone-aware created_at column stays valid.
    """
    if not value:
        return None
    text = value.strip()
    lowered = text.lower()
    if lowered.endswith("h") and lowered[:-1].isdigit():
        return datetime.now(UTC) - timedelta(hours=int(lowered[:-1]))
    if lowered.endswith("d") and lowered[:-1].isdigit():
        return datetime.now(UTC) - timedelta(days=int(lowered[:-1]))
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


@router.get("/events/grouped", response_model=GroupedCorrelationEventListResponse)
async def list_grouped_correlation_events(
    category: str | None = Query(
        None, description="Filter to an event category: correlations, coverage, or feed_health."
    ),
    event_type: str | None = Query(
        None, description="Filter to a single event type (ignored when event_types is provided)."
    ),
    event_types: str | None = Query(default=None, description="Comma-separated list of event types"),
    exclude_types: str | None = Query(default=None, description="Comma-separated event types to exclude"),
    severity: str | None = Query(
        default=None, pattern=r"^(high|medium|low)$", description="Filter to event types of this severity."
    ),
    source_entity_type: str | None = Query(
        None, description="Filter by the source entity's type (e.g. threat_actor, malware, cve)."
    ),
    since: str | None = Query(
        default=None, description="Only events at or after this bound. ISO datetime or shorthand: 24h, 7d, 30d"
    ),
    until: str | None = Query(default=None, description="Only events at or before this ISO datetime."),
    is_read: bool | None = Query(None, description="Filter by read state (true = read only, false = unread only)."),
    limit: int = Query(default=50, ge=1, le=200, description="Maximum number of article groups to return."),
    offset: int = Query(default=0, ge=0, description="Number of article groups to skip for pagination."),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """List correlation events grouped by source article, with category counts."""
    from collections import defaultdict

    from app.models.entry import Entry

    # Build filters
    filters = []
    if exclude_types:
        excluded = [t.strip() for t in exclude_types.split(",") if t.strip()]
        if excluded:
            filters.append(CorrelationEventRecord.event_type.notin_(excluded))
    if category and category in EVENT_CATEGORIES:
        filters.append(CorrelationEventRecord.event_type.in_(EVENT_CATEGORIES[category]))
    if event_types:
        type_list = [t.strip() for t in event_types.split(",") if t.strip()]
        if type_list:
            filters.append(CorrelationEventRecord.event_type.in_(type_list))
    elif event_type:
        filters.append(CorrelationEventRecord.event_type == event_type)
    if severity:
        severity_types = [t for t, s in EVENT_SEVERITY.items() if s == severity]
        if severity_types:
            filters.append(CorrelationEventRecord.event_type.in_(severity_types))
    if source_entity_type:
        filters.append(CorrelationEventRecord.source_entity_type == source_entity_type)
    # Time bounds are kept aside: unlike the type/severity/read filters they
    # also constrain the category counts below, so a ranged view doesn't report
    # all-time totals next to a windowed list.
    time_filters = []
    start_at = _parse_time_bound(since)
    if start_at:
        time_filters.append(CorrelationEventRecord.created_at >= start_at)
    end_at = _parse_time_bound(until)
    if end_at:
        time_filters.append(CorrelationEventRecord.created_at <= end_at)
    filters.extend(time_filters)
    if is_read is not None:
        filters.append(CorrelationEventRecord.is_read == is_read)

    # Fetch events (up to limit * 10 to have enough for grouping)
    q = visitor_events_only(
        select(CorrelationEventRecord)
        .where(*filters)
        .order_by(CorrelationEventRecord.created_at.desc())
        .limit(limit * 10)
    )
    result = await db.execute(q)
    all_events = result.scalars().all()
    if user.is_anonymous:
        refs = {(e.source_entity_type, e.source_entity_id) for e in all_events}
        refs |= {(e.related_entity_type, e.related_entity_id) for e in all_events}
        shown = await entities_shown(db, refs)
        all_events = [
            e
            for e in all_events
            if (e.source_entity_type, e.source_entity_id) in shown
            and (e.related_entity_type, e.related_entity_id) in shown
        ]

    # Category counts (across all events, ignoring category filter)
    count_q = select(
        CorrelationEventRecord.event_type,
        func.count(CorrelationEventRecord.id),
        func.count(CorrelationEventRecord.id).filter(CorrelationEventRecord.is_read == False),  # noqa: E712
    ).group_by(CorrelationEventRecord.event_type)
    if time_filters:
        count_q = count_q.where(*time_filters)
    count_result = await db.execute(visitor_events_only(count_q))
    type_counts = count_result.all()

    # Determine excluded types for consistent counting
    excluded_set = set()
    if exclude_types:
        excluded_set = {t.strip() for t in exclude_types.split(",") if t.strip()}

    cat_totals: dict[str, int] = defaultdict(int)
    cat_unread: dict[str, int] = defaultdict(int)
    total_all = 0
    unread_all = 0
    for event_type, cnt, unread_cnt in type_counts:
        if event_type in excluded_set:
            continue
        cat = CATEGORY_FOR_TYPE.get(event_type, "correlations")
        cat_totals[cat] += cnt
        cat_unread[cat] += unread_cnt
        total_all += cnt
        unread_all += unread_cnt

    categories = [
        CategoryCount(category=cat, count=cat_totals.get(cat, 0), unread=cat_unread.get(cat, 0))
        for cat in EVENT_CATEGORIES
    ]

    # Group by entry_id (None entry_ids get grouped by source_entity_id instead)
    grouped: dict[uuid.UUID, list] = defaultdict(list)
    no_entry_events: list = []
    for ev in all_events:
        if ev.entry_id is not None:
            grouped[ev.entry_id].append(ev)
        else:
            no_entry_events.append(ev)

    # Get entry titles for the groups
    entry_ids = list(grouped.keys())
    entry_map: dict[uuid.UUID, tuple[str | None, str | None]] = {}
    if entry_ids:
        entry_q = select(Entry.id, Entry.title, Entry.url).where(Entry.id.in_(entry_ids))
        entry_result = await db.execute(entry_q)
        for eid, title, url in entry_result.all():
            entry_map[eid] = (title, url)

    # Build grouped response, sorted by most recent event
    groups_list = []
    for entry_id, events in grouped.items():
        events_sorted = sorted(events, key=lambda e: e.created_at, reverse=True)
        unread = sum(1 for e in events_sorted if not e.is_read)
        severities = [EVENT_SEVERITY.get(e.event_type, "low") for e in events_sorted]
        highest = max(severities, key=lambda s: SEVERITY_RANK.get(s, 0))
        title, url = entry_map.get(entry_id, (None, None))
        groups_list.append(
            GroupedCorrelationEventsEntry(
                entry_id=entry_id,
                entry_title=title,
                entry_url=url,
                events=[CorrelationEventResponse.model_validate(e) for e in events_sorted],
                unread_count=unread,
                highest_severity=highest,
                latest_at=events_sorted[0].created_at,
            )
        )

    # System-level events (no entry_id) — each gets its own group
    for ev in no_entry_events:
        sev = EVENT_SEVERITY.get(ev.event_type, "low")
        groups_list.append(
            GroupedCorrelationEventsEntry(
                entry_id=None,
                entry_title=ev.source_entity_label,
                entry_url=None,
                events=[CorrelationEventResponse.model_validate(ev)],
                unread_count=0 if ev.is_read else 1,
                highest_severity=sev,
                latest_at=ev.created_at,
            )
        )

    groups_list.sort(key=lambda g: g.latest_at, reverse=True)
    paginated = groups_list[offset : offset + limit]

    return GroupedCorrelationEventListResponse(
        groups=paginated,
        categories=categories,
        total=total_all,
        unread_count=unread_all,
    )


@router.get("/events/unread-count")
async def get_unread_event_count(
    event_types: str | None = Query(default=None, description="Comma-separated list of event types"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get count of unread correlation events."""
    q = select(func.count(CorrelationEventRecord.id)).where(CorrelationEventRecord.is_read == False)  # noqa: E712
    if event_types:
        type_list = [t.strip() for t in event_types.split(",") if t.strip()]
        q = q.where(CorrelationEventRecord.event_type.in_(type_list))
    result = await db.execute(q)
    return {"unread_count": result.scalar() or 0}


@router.put("/events/{event_id}/read")
async def mark_event_read(
    event_id: uuid.UUID = Path(..., description="Correlation event UUID."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Mark a single correlation event as read."""
    result = await db.execute(select(CorrelationEventRecord).where(CorrelationEventRecord.id == event_id))
    event = result.scalar_one_or_none()
    if not event:
        raise AppError(code="not_found", message="Event not found", status_code=404)
    event.is_read = True
    await db.commit()
    return {"ok": True}


@router.put("/events/read-all")
async def mark_all_events_read(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Mark all correlation events as read."""
    await db.execute(
        update(CorrelationEventRecord).where(CorrelationEventRecord.is_read == False).values(is_read=True)  # noqa: E712
    )
    await db.commit()
    return {"ok": True}


@router.get("/temporal-clusters")
async def get_temporal_clusters(
    days: int = Query(7, ge=1, le=90, description="Look-back window in days for candidate entries."),
    window_hours: int = Query(
        24, ge=1, le=168, description="Maximum publication-time gap (hours) between clustered entries."
    ),
    min_shared: int = Query(2, ge=1, le=10, description="Minimum number of entities entries must share to cluster."),
    limit: int = Query(20, ge=1, le=500, description="Maximum number of clusters to return."),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Find temporal clusters: entries from different feeds within N-hour windows sharing entities."""
    clusters = await temporal_clusters(
        db,
        days=days,
        window_hours=window_hours,
        min_shared_entities=min_shared,
        limit=limit,
        user_id=user.id,
    )
    return {"clusters": clusters, "total": len(clusters)}


async def _resolve_entity_id(db: AsyncSession, entity_type: str, entity_id_str: str) -> uuid.UUID:
    """Resolve a string identifier to a UUID.

    Accepts either a UUID directly, or human-readable IDs like technique_id (T1490)
    for TTPs, cve_id (CVE-2024-1234) for CVEs and cwe_id (CWE-416) for weaknesses.
    """
    # Try as UUID first
    try:
        return uuid.UUID(entity_id_str)
    except ValueError:
        pass

    # Resolve technique IDs for TTPs
    if entity_type == "ttp":
        from app.models.ttp import TTP

        result = await db.execute(select(TTP.id).where(TTP.technique_id == entity_id_str.upper()))
        ttp_id = result.scalar_one_or_none()
        if ttp_id:
            return ttp_id

    # Resolve CWE catalog IDs, with or without the prefix ("CWE-416" or "416")
    if entity_type == "cwe":
        from app.models.cwe import CWE

        key = entity_id_str if entity_id_str.upper().startswith("CWE-") else f"CWE-{entity_id_str}"
        result = await db.execute(select(CWE.id).where(func.upper(CWE.cwe_id) == key.upper()))
        cwe_id = result.scalar_one_or_none()
        if cwe_id:
            return cwe_id

    # Resolve CVE IDs
    if entity_type == "cve":
        from app.models.cve import CVE

        result = await db.execute(select(CVE.id).where(CVE.cve_id == entity_id_str.upper()))
        cve_id = result.scalar_one_or_none()
        if cve_id:
            return cve_id

    raise AppError(code="not_found", message=f"Entity {entity_id_str} not found", status_code=404)


@router.get("/pivot/{entity_type}/{entity_id}", response_model=PivotResponse)
async def pivot_entity(
    entity_type: str = Path(
        ...,
        description="Entity type: ttp, cve, threat_actor, malware, country, mitigation, tool, vendor, or product.",
    ),
    entity_id: str = Path(
        ...,
        description="Entity UUID, or a human-readable id: technique id (T1566.001) or CVE id (CVE-2024-3400).",
    ),
    limit_per_type: int = Query(50, ge=1, le=500, description="Maximum related entities returned per entity type."),
    min_tier: str | None = Query(
        None,
        pattern="^(weak|moderate|strong)$",
        description="Only include relationships at or above this strength tier.",
    ),
    window_days: int | None = Query(
        None, ge=1, le=3650, description="Restrict evidence to entries from the last N days; omit for all time."
    ),
    offset: int = Query(0, ge=0, description="Number of related entities to skip within each type list."),
    sort: str = Query(
        "strength",
        pattern="^(strength|recent|articles)$",
        description="Ranking for related lists: strength score, most recent co-occurrence, or shared article count.",
    ),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Pivot from one entity to all related entities via shared entries.

    Related lists are ranked (`sort`) and sliced to `offset:offset+limit_per_type`
    (pre-slice totals in `related_counts`); `min_tier` filters by strength tier
    and `window_days` restricts the evidence window.
    """
    _validate_pivot_source(entity_type)

    resolved_id = await _resolve_entity_id(db, entity_type, entity_id)
    result = await pivot_from_entity(
        db,
        entity_type,
        resolved_id,
        limit_per_type=limit_per_type,
        min_tier=min_tier,
        window_days=window_days,
        offset=offset,
        sort=sort,
    )
    if not result:
        raise AppError(code="not_found", message="Entity not found", status_code=404)
    return result


@router.get("/graph/{entity_type}/{entity_id}", response_model=GraphResponse)
async def get_entity_graph(
    entity_type: str = Path(
        ...,
        description="Entity type: ttp, cve, threat_actor, malware, country, mitigation, tool, vendor, or product.",
    ),
    entity_id: str = Path(
        ...,
        description="Entity UUID, or a human-readable id: technique id (T1566.001) or CVE id (CVE-2024-3400).",
    ),
    depth: int = Query(1, ge=1, le=3, description="Number of relationship hops to expand from the root entity."),
    window_days: int | None = Query(
        None, ge=1, le=3650, description="Restrict evidence to entries from the last N days; omit for all time."
    ),
    include_observables: bool = Query(
        False, description="Include IOC-ledger observables as graph nodes (off by default to keep maps readable)."
    ),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Get a relationship graph for visualization (nodes + edges)."""
    _validate_pivot_source(entity_type)

    resolved_id = await _resolve_entity_id(db, entity_type, entity_id)
    entity = await get_entity(db, entity_type, resolved_id)
    if not entity:
        raise AppError(code="not_found", message="Entity not found", status_code=404)

    return await build_entity_graph(
        db, entity_type, resolved_id, depth=depth, window_days=window_days, include_observables=include_observables
    )


@router.get("/entry-graph/{entry_id}", response_model=GraphResponse)
async def get_entry_graph(
    entry_id: uuid.UUID = Path(..., description="Entry UUID."),
    include_observables: bool = Query(
        False, description="Include IOC-ledger observables as graph nodes (off by default to keep maps readable)."
    ),
    user: User = Depends(get_entry_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Get a relationship graph of all entities linked to an entry."""
    return await build_entry_graph(db, entry_id, include_observables=include_observables)


@router.get("/search", response_model=EntitySearchResponse)
async def search_entities(
    q: str = Query(min_length=1, max_length=500, description="Search text matched against entity names and aliases."),
    limit: int = Query(50, ge=1, le=500, description="Maximum number of results to return."),
    entity_types: str | None = Query(
        None, description="Comma-separated entity types to search (e.g. detection_rule,cve)"
    ),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Search across all entity types (IOCs, TTPs, CVEs, threat actors, malware, rules).

    Entries are deliberately not included — article full-text search is served
    by the Meilisearch-backed /api/search endpoint.
    """
    types_filter = [t.strip() for t in entity_types.split(",") if t.strip()] if entity_types else None
    results = await search_all_entities(db, q, limit=limit, entity_types=types_filter)
    return EntitySearchResponse(results=results, total=len(results))


@router.get("/timeline/{entity_type}/{entity_id}", response_model=TimelineResponse)
async def get_entity_timeline(
    entity_type: str = Path(
        ...,
        description="Entity type: ttp, cve, threat_actor, malware, country, mitigation, tool, vendor, or product.",
    ),
    entity_id: str = Path(
        ...,
        description="Entity UUID, or a human-readable id: technique id (T1566.001) or CVE id (CVE-2024-3400).",
    ),
    user: User = Depends(get_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Get temporal activity for an entity based on linked entry dates."""
    _validate_pivot_source(entity_type)

    from app.intelligence.correlation import _serialize_entity

    resolved_id = await _resolve_entity_id(db, entity_type, entity_id)
    entity = await get_entity(db, entity_type, resolved_id)
    if not entity:
        raise AppError(code="not_found", message="Entity not found", status_code=404)

    events = await entity_timeline(db, entity_type, resolved_id)
    return TimelineResponse(
        entity=_serialize_entity(entity_type, entity),
        events=events,
    )


@router.delete("/timeline/{entity_type}/{entity_id}", status_code=204)
async def clear_entity_timeline(
    entity_type: str = Path(
        ...,
        description="Entity type: ttp, cve, threat_actor, malware, country, mitigation, tool, vendor, or product.",
    ),
    entity_id: uuid.UUID = Path(..., description="Entity UUID."),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete all correlation events for an entity, resetting its timeline. Admin only."""
    _validate_entity_type(entity_type)
    await db.execute(
        sql_delete(CorrelationEventRecord).where(
            (
                (CorrelationEventRecord.source_entity_type == entity_type)
                & (CorrelationEventRecord.source_entity_id == entity_id)
            )
            | (
                (CorrelationEventRecord.related_entity_type == entity_type)
                & (CorrelationEventRecord.related_entity_id == entity_id)
            )
        )
    )
    await db.commit()


@router.delete("/related/{entity_type}/{entity_id}/{other_type}/{other_id}", status_code=204)
async def unlink_related_entity(
    entity_type: str = Path(
        ...,
        description="Entity type: ttp, cve, threat_actor, malware, country, mitigation, tool, vendor, or product.",
    ),
    entity_id: uuid.UUID = Path(..., description="Entity UUID."),
    other_type: str = Path(
        ...,
        description="Type of the entity to unlink; same allowed values as entity_type.",
    ),
    other_id: uuid.UUID = Path(..., description="UUID of the entity to unlink."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Remove the 'other' entity from all entries shared with 'entity', effectively unlinking it from the profile."""
    from app.intelligence.correlation_cache import invalidate_entity_cache

    _validate_entity_type(entity_type)
    _validate_entity_type(other_type)

    entity_entry_ids = await _get_entry_ids_for_entity(db, entity_type, entity_id)
    if not entity_entry_ids:
        return

    _, other_junction, other_fk_col = ENTITY_CONFIG[other_type]
    await db.execute(
        sql_delete(other_junction).where(
            other_junction.entry_id.in_(entity_entry_ids),
            other_fk_col == other_id,
        )
    )
    await db.flush()

    # Invalidate graph/pivot caches for both entities so graphs rebuild
    await invalidate_entity_cache(entity_type, str(entity_id))
    await invalidate_entity_cache(other_type, str(other_id))


@router.post("/detection-summary", response_model=DetectionSummaryResponse)
async def generate_detection_summary(
    body: DetectionSummaryRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate a detection engineering summary for one or more articles using AI."""
    result = await build_detection_summary(
        db=db,
        user_id=user.id,
        entry_ids=body.entry_ids,
        rule_formats=body.rule_formats,
        focus=body.focus,
        include_existing=body.include_existing_intelligence,
    )
    await db.commit()

    if result is None:
        raise AppError(
            code="bad_request",
            message="No valid entries found or no AI task assignment configured",
            status_code=400,
        )

    # The AI engine returns an error payload (rather than raising) when the
    # provider call fails or times out. Surface it as a real error so the
    # workbench shows a message instead of a silently-empty summary.
    status = result.get("_extraction_status")
    if status in ("provider_error", "provider_paused", "parse_error"):
        raise AppError(
            code="ai_generation_failed",
            message=(
                "Detection summary generation timed out or failed. Try fewer "
                "articles, fewer rule formats, or a faster model."
            ),
            status_code=503,
            details=[str(result.get("_error", status))],
        )

    return DetectionSummaryResponse(**result)


@router.post("/detection-summaries", response_model=DetectionSummarySavedResponse, status_code=201)
async def create_detection_summary(
    body: DetectionSummaryCreateRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate a detection summary and persist it."""
    result = await build_detection_summary(
        db=db,
        user_id=user.id,
        entry_ids=body.entry_ids,
        rule_formats=body.rule_formats,
        focus=body.focus,
        include_existing=body.include_existing_intelligence,
    )

    if result is None:
        raise AppError(
            code="bad_request",
            message="No valid entries found or no AI task assignment configured",
            status_code=400,
        )

    summary = DetectionSummary(
        created_by=user.id,
        title=body.title,
        entry_ids=list(body.entry_ids),
        analysis_focus=body.focus,
        summary_content=result,
    )
    db.add(summary)
    await db.flush()
    await db.refresh(summary)
    await db.commit()

    return DetectionSummarySavedResponse.model_validate(summary)


@router.get("/detection-summaries", response_model=list[DetectionSummarySavedResponse])
async def list_detection_summaries(
    limit: int = Query(50, ge=1, le=500, description="Maximum number of summaries to return."),
    offset: int = Query(0, ge=0, description="Number of summaries to skip for pagination."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List saved detection summaries.

    Coverage sets are stored in the same table (summary_content.kind =
    "coverage_set") but belong to the coverage-workspace sets endpoints — they
    are working state, not analyst summaries, and must not surface here.
    """
    result = await db.execute(
        select(DetectionSummary)
        .where(DetectionSummary.summary_content["kind"].astext.is_distinct_from("coverage_set"))
        .order_by(DetectionSummary.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    summaries = result.scalars().all()
    return [DetectionSummarySavedResponse.model_validate(s) for s in summaries]


@router.get("/detection-summaries/{summary_id}", response_model=DetectionSummarySavedResponse)
async def get_detection_summary_by_id(
    summary_id: uuid.UUID = Path(..., description="Saved detection summary UUID."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get a specific saved detection summary."""
    result = await db.execute(
        select(DetectionSummary).where(
            DetectionSummary.id == summary_id,
        )
    )
    summary = result.scalar_one_or_none()
    if not summary:
        raise AppError(code="not_found", message="Detection summary not found", status_code=404)
    return DetectionSummarySavedResponse.model_validate(summary)


@router.delete("/detection-summaries/{summary_id}", status_code=204)
async def delete_detection_summary(
    summary_id: uuid.UUID = Path(..., description="Saved detection summary UUID."),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete a saved detection summary."""
    result = await db.execute(
        select(DetectionSummary).where(
            DetectionSummary.id == summary_id,
        )
    )
    summary = result.scalar_one_or_none()
    if not summary:
        raise AppError(code="not_found", message="Detection summary not found", status_code=404)
    # Coverage-workspace saved sets live in this table too — they are one
    # user's working notes, not shared state.
    if user.role != "admin" and summary.created_by != user.id:
        raise AppError(code="forbidden", message="Only the summary's owner or an admin can delete it", status_code=403)
    await db.delete(summary)
    await db.commit()
