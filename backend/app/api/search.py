import logging
import time
import uuid
from collections import Counter
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.metrics import SEARCH_QUERIES_TOTAL
from app.core.security import get_admin_user, get_current_user
from app.database import get_db
from app.models.entry_state import UserEntryState
from app.models.user import User
from app.schemas.search import (
    EntitySearchResults,
    EntrySearchResults,
    ParsedFilterSchema,
    SearchQuery,
    SearchResponse,
    UnifiedSearchQuery,
    UnifiedSearchResponse,
)
from app.search.query_planner import IS_FILTER_VALUES, VALID_SORTS
from app.services import meilisearch_client

logger = logging.getLogger(__name__)

router = APIRouter()


def entry_id_condition(entry_ids: list[str]):
    """A WHERE clause restricting entries to `entry_ids`.

    Deliberately not `IN (...)`: that sends one bind parameter per ID and
    asyncpg refuses a statement with more than 32767 of them, so an ordinary
    filter matching more entries than that died with an InterfaceError rather
    than returning results. Comparing against a single array parameter keeps the
    statement at one argument however long the list is.
    """
    from sqlalchemy import ARRAY, cast
    from sqlalchemy.dialects.postgresql import UUID as PG_UUID

    from app.models.entry import Entry

    return Entry.id == func.any(cast([uuid.UUID(eid) for eid in entry_ids], ARRAY(PG_UUID)))


async def _fetch_entries_by_ids(
    db: AsyncSession,
    entry_ids: list[str] | None,
    limit: int = 20,
    offset: int = 0,
    sort: str = "relevance",
    unread_for_user: uuid.UUID | None = None,
) -> dict:
    """Fetch entries directly from PostgreSQL by ID list.

    Used when entity queries produce large entry ID sets that exceed
    Meilisearch's filter size limits, and for `sort:radar`, whose ordering
    column (`priority_score`) is a Postgres column the search index does not
    carry. `entry_ids=None` means "no ID constraint" — only radar uses that.

    `unread_for_user` drops the entries that user has read, counted total
    included — read state is per-user, so it can only be applied here.
    """
    from sqlalchemy.orm import selectinload

    from app.models.entry import Entry

    conditions = []
    if entry_ids is not None:
        conditions.append(entry_id_condition(entry_ids))
    if sort == "radar":
        # An unscored entry has no place in a ranked list.
        conditions.append(Entry.priority_score.isnot(None))
    if unread_for_user is not None:
        conditions.append(_unread_condition(unread_for_user))

    # Count total
    count_stmt = select(func.count()).select_from(Entry).where(*conditions)
    total = (await db.execute(count_stmt)).scalar() or 0

    # Fetch page with feed relationship
    stmt = select(Entry).options(selectinload(Entry.feed)).where(*conditions)
    if sort == "radar":
        stmt = stmt.order_by(Entry.priority_score.desc(), Entry.published_at.desc().nullslast())
    elif sort == "oldest":
        stmt = stmt.order_by(Entry.published_at.asc().nullsfirst())
    elif sort == "title_asc":
        stmt = stmt.order_by(func.lower(Entry.title).asc())
    elif sort == "title_desc":
        stmt = stmt.order_by(func.lower(Entry.title).desc())
    elif sort == "shortest":
        stmt = stmt.order_by(Entry.word_count.asc().nullslast())
    elif sort == "longest":
        stmt = stmt.order_by(Entry.word_count.desc().nullslast())
    else:
        # "newest", "relevance" (no scores available in the PG path), and anything else
        stmt = stmt.order_by(Entry.published_at.desc().nullslast())

    stmt = stmt.offset(offset).limit(limit)
    result = await db.execute(stmt)
    entries = result.scalars().all()

    # Format as Meilisearch-compatible hit dicts
    hits = []
    for e in entries:
        tag_names: list[str] = []  # tags populated by Meilisearch; PG fallback skips them
        hits.append(
            {
                "id": str(e.id),
                "title": e.title,
                "url": e.url,
                "author": e.author,
                "content_text": (e.content_text or "")[:500],
                "content_html": e.content_html,
                "summary": e.summary,
                "published_at": e.published_at.timestamp() if e.published_at else None,
                "fetched_at": e.fetched_at.timestamp() if e.fetched_at else None,
                "feed_id": str(e.feed_id),
                "feed_title": e.feed.title if e.feed else "",
                "feed_type": e.feed.feed_type if e.feed else "",
                "image_url": e.image_url,
                "word_count": e.word_count,
                "language": e.language,
                "tags": tag_names,
                "is_read": False,
                "is_starred": False,
                "is_bookmarked": False,
            }
        )

    return {"hits": hits, "estimatedTotalHits": total, "processingTimeMs": 0}


async def _get_entity_linked_entry_ids(db: AsyncSession, entity_results: list[dict]) -> list[str]:
    """Fetch entry IDs linked to entity results via junction tables."""
    from app.search.entity_builder import ENTITY_TABLE_MAP

    # Group entity IDs by type
    ids_by_type: dict[str, list[str]] = {}
    for ent in entity_results:
        etype = ent.get("type", "")
        eid = ent.get("id", "")
        if not eid:
            continue
        # Normalize type names to match ENTITY_TABLE_MAP keys
        type_key = {
            "threat_actor": "threat_actor",
            "malware": "malware",
            "detection_rule": "rule",
        }.get(etype, etype)
        ids_by_type.setdefault(type_key, []).append(eid)

    all_entry_ids: list[str] = []
    for type_key, entity_ids in ids_by_type.items():
        mapping = ENTITY_TABLE_MAP.get(type_key)
        if not mapping:
            continue
        _model, junction, junction_entity_fk, junction_entry_fk = mapping
        if junction is None or junction_entity_fk is None:
            continue
        uuids = [uuid.UUID(eid) for eid in entity_ids]
        stmt = select(junction_entry_fk).where(junction_entity_fk.in_(uuids))
        result = await db.execute(stmt)
        for row in result.scalars().all():
            all_entry_ids.append(str(row))

    return all_entry_ids


async def _enrich_hits_with_user_state(hits: list[dict], user_id: uuid.UUID, db: AsyncSession) -> None:
    """Overlay actual is_read/is_starred/is_bookmarked from the DB onto search hits.

    Meilisearch state can be stale (bulk operations don't always sync), so we
    always fetch the authoritative per-user state from UserEntryState.
    """
    if not hits:
        return
    entry_ids = []
    for h in hits:
        try:
            entry_ids.append(uuid.UUID(h["id"]))
        except (KeyError, ValueError):
            continue
    if not entry_ids:
        return

    result = await db.execute(
        select(
            UserEntryState.entry_id,
            UserEntryState.is_read,
            UserEntryState.is_starred,
            UserEntryState.is_bookmarked,
        ).where(
            UserEntryState.user_id == user_id,
            UserEntryState.entry_id.in_(entry_ids),
        )
    )
    state_map = {str(row.entry_id): row for row in result.all()}

    for h in hits:
        state = state_map.get(h.get("id"))
        if state:
            h["is_read"] = state.is_read
            h["is_starred"] = state.is_starred
            h["is_bookmarked"] = state.is_bookmarked
        else:
            # No state row = unread, not starred, not bookmarked
            h["is_read"] = False
            h["is_starred"] = False
            h["is_bookmarked"] = False


# How far a Hide Read search scans for unread matches. Read state is per-user
# and lives in Postgres, so the index cannot filter on it — the matches have to
# be listed and then filtered here. Same cap the saved-search counter uses, so
# the sidebar's unread number and this list agree for any search under it.
HIDE_READ_SCAN_CAP = 5000

# How many IDs the builder will put in a Meilisearch `id IN [...]` filter before
# it drops the rest (see meili_builder.execute_entry_search). A constraint above
# this has to be answered from Postgres instead, or its tail goes missing.
MEILI_ID_FILTER_CAP = 500


def _unread_condition(user_id: uuid.UUID):
    """Entry has no read row for this user. Absence of a row means unread."""
    from app.models.entry import Entry

    return ~(
        select(UserEntryState.id)
        .where(
            UserEntryState.entry_id == Entry.id,
            UserEntryState.user_id == user_id,
            UserEntryState.is_read.is_(True),
        )
        .exists()
    )


async def _drop_read_ids(db: AsyncSession, user_id: uuid.UUID, entry_ids: list[str]) -> list[str]:
    """`entry_ids` minus the ones this user has read, order preserved."""
    if not entry_ids:
        return []
    uuids = []
    for eid in entry_ids:
        try:
            uuids.append(uuid.UUID(eid))
        except (TypeError, ValueError):
            continue
    if not uuids:
        return []
    # One bind per ID, which asyncpg caps at 32767 — fine for a scan bounded by
    # HIDE_READ_SCAN_CAP, and the reason that cap cannot grow without switching
    # this to the array form `entry_id_condition` uses.
    result = await db.execute(
        select(UserEntryState.entry_id).where(
            UserEntryState.user_id == user_id,
            UserEntryState.entry_id.in_(uuids),
            UserEntryState.is_read.is_(True),
        )
    )
    read = {str(row) for row in result.scalars().all()}
    return [eid for eid in entry_ids if eid not in read]


async def _search_unread_page(
    db: AsyncSession,
    user_id: uuid.UUID,
    plan,
    entry_id_constraint: list[str] | None,
    limit: int,
    offset: int,
) -> dict:
    """One page of a search, restricted to what this user has not read.

    Filtering the fetched page instead — which is what the results list used to
    do client-side — hides an unread article that ranks below the page break and
    then reports "nothing matched" over a search with unread hits in it.
    """
    from app.search.meili_builder import execute_entry_search

    scan = execute_entry_search(
        plan,
        entry_id_constraint=entry_id_constraint,
        limit=HIDE_READ_SCAN_CAP,
        offset=0,
        attributes_to_retrieve=["id"],
    )
    scanned = [h["id"] for h in scan.get("hits", []) if "id" in h]
    if len(scanned) >= HIDE_READ_SCAN_CAP:
        # The unread total below is then a floor rather than the count, and a
        # page past the cap comes back empty. Saying so beats a number that
        # looks exact.
        logger.warning(
            "Hide Read scan hit its %d-hit cap for query %r; unread total is a floor",
            HIDE_READ_SCAN_CAP,
            plan.meili_query,
        )
    unread_ids = await _drop_read_ids(db, user_id, scanned)
    # `limit` is capped at 500 by the request schema, which is exactly what the
    # builder will accept in an ID filter — so the page below never loses a row.
    page_ids = unread_ids[offset : offset + limit]

    result: dict = {
        "hits": [],
        "estimatedTotalHits": len(unread_ids),
        "processingTimeMs": scan.get("processingTimeMs", 0),
        # Facets describe everything that matched, read or not — the same set
        # the rail's other counts are drawn from.
        "facetDistribution": scan.get("facetDistribution"),
    }
    if not page_ids:
        return result

    # Re-run constrained to the page so the hits come back with their
    # highlighting and cropped snippets, which the ID scan deliberately skips.
    page = execute_entry_search(plan, entry_id_constraint=page_ids, limit=len(page_ids), offset=0)
    by_id = {h["id"]: h for h in page.get("hits", []) if "id" in h}
    result["hits"] = [by_id[eid] for eid in page_ids if eid in by_id]
    return result


@router.get("", response_model=SearchResponse)
async def search_entries(
    q: str = Query("", description="Full-text query; empty string matches everything"),
    feed_id: list[uuid.UUID] | None = Query(None, description="Restrict to these feeds (repeatable)"),
    category_id: list[uuid.UUID] | None = Query(None, description="Restrict to these categories (repeatable)"),
    feed_type: list[str] | None = Query(None, description="Restrict to feed types (e.g. rss, youtube, podcast)"),
    tags: list[str] | None = Query(None, description="Require all of these tag names (repeatable, ANDed)"),
    date_from: datetime | None = Query(None, description="Only entries published at or after this timestamp"),
    date_to: datetime | None = Query(None, description="Only entries published at or before this timestamp"),
    is_read: bool | None = Query(None, description="Filter by read state"),
    is_starred: bool | None = Query(None, description="Filter by starred state"),
    is_bookmarked: bool | None = Query(None, description="Filter by bookmarked state"),
    has_notes: bool | None = Query(None, description="Filter to entries with (or without) user notes"),
    media_type: str | None = Query(None, description="Restrict to entries with this media type (audio, video)"),
    sort: str = Query("relevance", description="relevance, newest, oldest, title_asc, or title_desc"),
    limit: int = Query(20, ge=1, le=500, description="Page size"),
    offset: int = Query(0, ge=0, description="Number of hits to skip (paging)"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Full-text entry search backed by Meilisearch.

    Per-user read/starred/bookmarked flags on each hit are overlaid from
    PostgreSQL, since index state can lag bulk operations.
    """
    SEARCH_QUERIES_TOTAL.inc()
    result = meilisearch_client.search_entries(
        query=q,
        feed_id=([str(fid) for fid in feed_id] if feed_id else None),
        category_id=([str(cid) for cid in category_id] if category_id else None),
        feed_type=feed_type,
        tags=tags,
        date_from=date_from.timestamp() if date_from else None,
        date_to=date_to.timestamp() if date_to else None,
        is_read=is_read,
        is_starred=is_starred,
        is_bookmarked=is_bookmarked,
        has_notes=has_notes,
        media_type=media_type,
        sort=sort,
        limit=limit,
        offset=offset,
    )

    hits = result.get("hits", [])
    await _enrich_hits_with_user_state(hits, user.id, db)

    return SearchResponse(
        hits=hits,
        query=q,
        processingTimeMs=result.get("processingTimeMs", 0),
        estimatedTotalHits=result.get("estimatedTotalHits", 0),
        facetDistribution=result.get("facetDistribution"),
        searchUnavailable=result.get("searchUnavailable", False),
    )


@router.post("/advanced", response_model=SearchResponse)
async def advanced_search(
    body: SearchQuery,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """JSON-body variant of GET /api/search: same Meilisearch query, filters, and response shape."""
    feed_ids = [str(fid) for fid in body.feed_id] if body.feed_id else None
    cat_ids = [str(cid) for cid in body.category_id] if body.category_id else None

    SEARCH_QUERIES_TOTAL.inc()
    result = meilisearch_client.search_entries(
        query=body.q,
        feed_id=feed_ids,
        category_id=cat_ids,
        feed_type=body.feed_type,
        tags=body.tags,
        date_from=(body.date_from.timestamp() if body.date_from else None),
        date_to=(body.date_to.timestamp() if body.date_to else None),
        is_read=body.is_read,
        is_starred=body.is_starred,
        is_bookmarked=body.is_bookmarked,
        has_notes=body.has_notes,
        media_type=body.media_type,
        sort=body.sort,
        limit=body.limit,
        offset=body.offset,
    )

    hits = result.get("hits", [])
    await _enrich_hits_with_user_state(hits, user.id, db)

    return SearchResponse(
        hits=hits,
        query=body.q,
        processingTimeMs=result.get("processingTimeMs", 0),
        estimatedTotalHits=result.get("estimatedTotalHits", 0),
        facetDistribution=result.get("facetDistribution"),
    )


@router.get("/facets")
async def get_search_facets(
    q: str = Query("", description="Full-text query; empty string matches everything"),
    feed_id: list[uuid.UUID] | None = Query(None, description="Restrict to these feeds (repeatable)"),
    category_id: list[uuid.UUID] | None = Query(None, description="Restrict to these categories (repeatable)"),
    feed_type: list[str] | None = Query(None, description="Restrict to feed types (e.g. rss, youtube, podcast)"),
    tags: list[str] | None = Query(None, description="Require all of these tag names (repeatable, ANDed)"),
    date_from: datetime | None = Query(None, description="Only entries published at or after this timestamp"),
    date_to: datetime | None = Query(None, description="Only entries published at or before this timestamp"),
    is_read: bool | None = Query(None, description="Filter by read state"),
    is_starred: bool | None = Query(None, description="Filter by starred state"),
    is_bookmarked: bool | None = Query(None, description="Filter by bookmarked state"),
    has_notes: bool | None = Query(None, description="Filter to entries with (or without) user notes"),
    media_type: str | None = Query(None, description="Restrict to entries with this media type (audio, video)"),
    user: User = Depends(get_current_user),
):
    """Facet distributions (feeds, feed types, tags, …) for the given query and
    filters, used to build filter UIs. Filter semantics match GET /api/search."""
    # Build filter string matching the same logic as search_entries
    filter_parts: list[str] = []
    if feed_id:
        fid_parts = " OR ".join(f'feed_id = "{fid}"' for fid in feed_id)
        filter_parts.append(f"({fid_parts})")
    if category_id:
        cid_parts = " OR ".join(f'category_id = "{cid}"' for cid in category_id)
        filter_parts.append(f"({cid_parts})")
    if feed_type:
        ft_parts = " OR ".join(f'feed_type = "{ft}"' for ft in feed_type)
        filter_parts.append(f"({ft_parts})")
    if tags:
        for tag in tags:
            filter_parts.append(f'tags = "{tag}"')
    if date_from is not None:
        filter_parts.append(f"published_at >= {date_from.timestamp()}")
    if date_to is not None:
        filter_parts.append(f"published_at <= {date_to.timestamp()}")
    if is_read is not None:
        filter_parts.append(f"is_read = {str(is_read).lower()}")
    if is_starred is not None:
        filter_parts.append(f"is_starred = {str(is_starred).lower()}")
    if is_bookmarked is not None:
        filter_parts.append(f"is_bookmarked = {str(is_bookmarked).lower()}")
    if has_notes is not None:
        filter_parts.append(f"has_notes = {str(has_notes).lower()}")
    if media_type:
        filter_parts.append(f'media_type = "{media_type}"')

    filters_str = " AND ".join(filter_parts) if filter_parts else None
    facets = meilisearch_client.get_facets(query=q, filters=filters_str)
    return {"facets": facets}


# ── Unified search ─────────────────────────────────────


async def _suggest_quoted_filter(db: AsyncSession, query: str, user_id: uuid.UUID) -> str | None:
    """Spot `country:North Korea` and propose `country:"North Korea"`.

    A value ends at the first space, so a multi-word value silently splits into a
    narrower filter plus a stray full-text term — `country:North Korea` matches
    Northern Cyprus and Sudan while searching for "Korea". It returns a plausible
    number of articles, which is why it goes unnoticed.

    The parser cannot fix this by consuming greedily: `threat_actor:APT29 ransomware`
    is a legitimate filter-plus-search-term, and quoting it would be just as wrong in
    the other direction. So the shape is only ever *suggested*, and only when the
    extended value is a real value for that field — which is exactly the question the
    autocomplete lookup already answers. Reusing it means every field with a known
    vocabulary is covered, and stays covered as fields are added.

    Returns the corrected query string, or None when there is nothing to suggest.
    """
    from app.search.query_parser import TokenType, _find_field_colon, tokenize

    try:
        tokens = tokenize(query)
    except Exception:
        return None

    # Candidate = a field:value WORD followed by one or more plain WORDs. Operators,
    # phrases and parens end the run, as does the next field:value.
    candidates: list[tuple[int, int, str, str, list[str]]] = []
    for i, tok in enumerate(tokens):
        if tok.type != TokenType.WORD:
            continue
        colon = _find_field_colon(tok.value)
        if colon is None:
            continue
        value = tok.value[colon + 1 :]
        if not value or "*" in value or value[0] in "<>=":
            continue
        trailing: list[str] = []
        end = tok.pos + len(tok.value)
        for nxt in tokens[i + 1 :]:
            if nxt.type != TokenType.WORD or _find_field_colon(nxt.value) is not None:
                break
            trailing.append(nxt.value)
            end = nxt.pos + len(nxt.value)
        if trailing:
            candidates.append((tok.pos, end, tok.value[:colon], value, trailing))

    # Longest extension first, so `country:North Korea attacks` prefers "North Korea
    # attacks" and falls back to "North Korea" rather than stopping at the first hit.
    for start, _end, field_name, value, trailing in candidates[:3]:
        for take in range(len(trailing), 0, -1):
            extended = " ".join([value, *trailing[:take]])
            try:
                matches = await _get_dynamic_values(db, field_name, extended, user_id)
            except Exception:
                return None
            if not any(m.get("text", "").lower() == extended.lower() for m in matches):
                continue
            span_end = start + len(f"{field_name}:{value}") + sum(len(w) + 1 for w in trailing[:take])
            return query[:start] + _value_insert(field_name, extended) + query[span_end:]
    return None


def _trim_entities_per_type(entities: list[dict], per_type: int) -> list[dict]:
    """Keep the first `per_type` of each entity type, preserving relevance order.

    The list arrives sorted by relevance across all types, so a flat slice keeps
    whichever type happens to rank first and drops the rest entirely. Capping per
    type keeps every type that matched representable in the response.
    """
    seen: Counter[str] = Counter()
    kept: list[dict] = []
    for item in entities:
        etype = item.get("type", "")
        if seen[etype] >= per_type:
            continue
        seen[etype] += 1
        kept.append(item)
    return kept


@router.post("/unified", response_model=UnifiedSearchResponse)
async def unified_search(
    body: UnifiedSearchQuery,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Unified search across entries (Meilisearch) and intelligence entities (PostgreSQL).

    Supports a query language with field:value syntax, wildcards, boolean operators,
    and cross-domain search (entries + TTPs/CVEs/actors/malware/rules).
    """
    from app.search.entity_builder import execute_entity_queries
    from app.search.meili_builder import execute_entry_search
    from app.search.query_parser import ParseError, parse_query
    from app.search.query_planner import build_execution_plan

    start = time.monotonic()
    SEARCH_QUERIES_TOTAL.inc()

    # Parse query
    try:
        ast = parse_query(body.q)
    except ParseError:
        # On parse error, fall back to plain text search
        ast = parse_query("")

    # Build execution plan
    plan = build_execution_plan(ast)

    # Resolve pending feed name filters to feed_id Meilisearch filters
    if plan.pending_feed_filters:
        from app.search.query_planner import resolve_feed_filters

        await resolve_feed_filters(db, plan)

    # Resolve the Postgres-backed entry filters (category, signal, sector, url,
    # feed ratings, is:muted/translated/image).
    if plan.pending_entry_filters:
        from app.search.query_planner import resolve_entry_filters

        await resolve_entry_filters(db, plan)

    # `country:North Korea` splits into `country:North` plus a stray "Korea" term and
    # answers with a plausible wrong number. Offer the quoted form when the extended
    # value is real; see _suggest_quoted_filter.
    did_you_mean = await _suggest_quoted_filter(db, body.q, user.id)

    # Execute entity queries if needed
    entity_results: list[dict] = []
    linked_entry_ids: set[str] | None = None

    if plan.has_entity_queries:
        entity_results, found_entry_ids = await execute_entity_queries(
            db, plan.entity_nodes, limit=body.entity_limit, user_id=str(user.id)
        )
        if plan.join_mode == "AND":
            linked_entry_ids = found_entry_ids

    # A Postgres-backed entry filter narrows the same way an entity join does,
    # intersecting with it when both are present.
    if plan.db_entry_ids is not None:
        linked_entry_ids = plan.db_entry_ids if linked_entry_ids is None else linked_entry_ids & plan.db_entry_ids
    if plan.db_excluded_ids and linked_entry_ids is not None:
        linked_entry_ids = linked_entry_ids - plan.db_excluded_ids
    elif plan.meili_query.strip() and not plan.has_entity_queries:
        # Plain text search with no explicit entity filters — also search entities
        from app.intelligence.correlation import search_all_entities

        entity_results = await search_all_entities(db, plan.meili_query.strip(), limit=body.entity_limit)

    # Execute entry search
    entry_result: dict = {"hits": [], "estimatedTotalHits": 0, "processingTimeMs": 0}
    if plan.has_entry_queries or (plan.has_entity_queries and plan.join_mode == "AND"):
        # `sort:radar` orders by the signal engine's priority_score, which lives
        # in Postgres and not the search index — so it takes the PG fetch path
        # rather than a Meilisearch sort.
        if plan.sort == "radar":
            entry_result = await _fetch_entries_by_ids(
                db,
                list(linked_entry_ids) if linked_entry_ids is not None else None,
                limit=body.limit,
                offset=body.offset,
                sort="radar",
                unread_for_user=user.id if body.hide_read else None,
            )
            entry_hits = entry_result.get("hits", [])
            await _enrich_hits_with_user_state(entry_hits, user.id, db)
            entity_counts_early: dict[str, int] = dict(Counter(e["type"] for e in entity_results))
            return UnifiedSearchResponse(
                entries=EntrySearchResults(
                    hits=entry_hits,
                    estimatedTotalHits=entry_result.get("estimatedTotalHits", 0),
                ),
                entities=EntitySearchResults(
                    items=_trim_entities_per_type(entity_results, body.entity_group_limit),
                    counts=entity_counts_early,
                ),
                query=body.q,
                parsed_filters=[
                    ParsedFilterSchema(field=pf.field, value=pf.value, exact=pf.exact, negated=pf.negated, raw=pf.raw)
                    for pf in plan.parsed_filters
                ],
                did_you_mean=did_you_mean,
                unknown_fields=list(plan.unknown_fields),
                processingTimeMs=int((time.monotonic() - start) * 1000),
            )

        entry_id_constraint = list(linked_entry_ids) if linked_entry_ids is not None else None

        # Bypass Meilisearch and read Postgres directly when there is an ID
        # constraint but nothing for the index to actually search: either an
        # entity-only query, or a Postgres-backed entry filter like `signal:`
        # with no text term. Passing tens of thousands of IDs as a Meilisearch
        # filter string is what used to happen, and it silently returned zero.
        #
        # The size threshold is the builder's own `id IN [...]` cap, not a
        # number of its own: the builder keeps the first 500 IDs and drops the
        # rest, so a constraint of 501-800 used to come here, lose its tail in
        # the filter string, and answer with a subset nothing announced.
        _no_text_to_search = not plan.meili_query.strip() and not plan.meili_filters
        if (
            entry_id_constraint is not None
            and len(entry_id_constraint) > 0
            and (not plan.has_entry_queries or _no_text_to_search or len(entry_id_constraint) > MEILI_ID_FILTER_CAP)
        ):
            entry_result = await _fetch_entries_by_ids(
                db,
                entry_id_constraint,
                limit=body.limit,
                offset=body.offset,
                sort=plan.sort,
                unread_for_user=user.id if body.hide_read else None,
            )
        elif body.hide_read:
            entry_result = await _search_unread_page(db, user.id, plan, entry_id_constraint, body.limit, body.offset)
        else:
            entry_result = execute_entry_search(
                plan,
                entry_id_constraint=entry_id_constraint,
                limit=body.limit,
                offset=body.offset,
            )

    # When plain text search found entity matches but few/no entry hits from Meilisearch,
    # also fetch entries linked to those entities and merge them in.
    # Skip when explicit filters are active — those entries would bypass the user's filters.
    if (
        entity_results
        and not plan.has_entity_queries
        and not plan.meili_filters
        and entry_result.get("estimatedTotalHits", 0) < body.limit
    ):
        entity_linked_ids = await _get_entity_linked_entry_ids(db, entity_results)
        # Exclude entries already in the Meilisearch results
        existing_ids = {h["id"] for h in entry_result.get("hits", [])}
        new_ids = [eid for eid in entity_linked_ids if eid not in existing_ids]
        if new_ids:
            remaining = body.limit - len(entry_result.get("hits", []))
            if remaining > 0:
                linked_result = await _fetch_entries_by_ids(
                    db,
                    new_ids[:remaining],
                    limit=remaining,
                    offset=0,
                    sort=plan.sort,
                    unread_for_user=user.id if body.hide_read else None,
                )
                entry_result["hits"] = entry_result.get("hits", []) + linked_result.get("hits", [])
                entry_result["estimatedTotalHits"] = entry_result.get("estimatedTotalHits", 0) + linked_result.get(
                    "estimatedTotalHits", 0
                )

    # Count entities by type BEFORE trimming, so the facet sidebar can offer
    # "Threat Actors 57" while the payload carries only the first page of each
    # group. Trimming first is what made this endpoint answer a plain-text query
    # with ten actors and nothing else: the global slice ran after a relevance
    # sort that puts one type on top.
    entity_counts: dict[str, int] = dict(Counter(e["type"] for e in entity_results))
    entity_results = _trim_entities_per_type(entity_results, body.entity_group_limit)

    # Enrich entry hits with authoritative user state from DB
    entry_hits = entry_result.get("hits", [])
    await _enrich_hits_with_user_state(entry_hits, user.id, db)

    elapsed_ms = int((time.monotonic() - start) * 1000)

    return UnifiedSearchResponse(
        entries=EntrySearchResults(
            hits=entry_hits,
            estimatedTotalHits=entry_result.get("estimatedTotalHits", 0),
            facetDistribution=entry_result.get("facetDistribution"),
        ),
        entities=EntitySearchResults(
            items=entity_results,
            counts=entity_counts,
        ),
        query=body.q,
        parsed_filters=[
            ParsedFilterSchema(
                field=pf.field,
                value=pf.value,
                exact=pf.exact,
                negated=pf.negated,
                raw=pf.raw,
            )
            for pf in plan.parsed_filters
        ],
        did_you_mean=did_you_mean,
        unknown_fields=list(plan.unknown_fields),
        processingTimeMs=elapsed_ms,
    )


# ── Autocomplete ───────────────────────────────────────


# Static field suggestions
FIELD_SUGGESTIONS = [
    {"text": "cve:", "description": "Search CVE identifiers", "category": "entity"},
    {"text": "cve.severity:", "description": "Filter by CVE severity", "category": "entity"},
    {"text": "cve.cvss:", "description": "Filter by CVSS score (e.g. >9.0)", "category": "entity"},
    {"text": "cve.kev:", "description": "In the CISA Known Exploited Vulnerabilities catalog", "category": "entity"},
    {"text": "cve.epss:", "description": "EPSS exploitation probability (e.g. >0.5)", "category": "entity"},
    {"text": "cve.epss_percentile:", "description": "EPSS percentile", "category": "entity"},
    {"text": "cve.poc:", "description": "Public proof-of-concept count (e.g. >0)", "category": "entity"},
    {"text": "cve.exploit:", "description": "Exploitation status", "category": "entity"},
    {"text": "cve.product:", "description": "Affected vendor or product", "category": "entity"},
    {"text": "ttp:", "description": "Search MITRE ATT&CK techniques", "category": "entity"},
    {"text": "ttp.tactic:", "description": "Filter by ATT&CK tactic", "category": "entity"},
    {"text": "ttp.platform:", "description": "Filter by platform (Windows, Linux, macOS)", "category": "entity"},
    {"text": "ttp.data_source:", "description": "Filter by required telemetry", "category": "entity"},
    {"text": "ttp.domain:", "description": "enterprise, mobile or ics", "category": "entity"},
    {"text": "ttp.subtechnique:", "description": "Sub-techniques only", "category": "entity"},
    {"text": "threat_actor:", "description": "Search threat actor names", "category": "entity"},
    {"text": "threat_actor.country:", "description": "Filter by threat actor country", "category": "entity"},
    {"text": "threat_actor.motivation:", "description": "espionage, financial, hacktivism", "category": "entity"},
    {"text": "threat_actor.sector:", "description": "Sector the actor targets", "category": "entity"},
    {"text": "threat_actor.type:", "description": "Actor classification", "category": "entity"},
    {"text": "malware:", "description": "Search malware family names", "category": "entity"},
    {"text": "malware.type:", "description": "Filter by malware type", "category": "entity"},
    {"text": "malware.sector:", "description": "Sector the family targets", "category": "entity"},
    {"text": "country:", "description": "Search by country name", "category": "entity"},
    {"text": "country.region:", "description": "Filter by geographic region", "category": "entity"},
    {"text": "tool:", "description": "Search tool names", "category": "entity"},
    {"text": "tool.type:", "description": "Filter by tool type", "category": "entity"},
    {"text": "tool.platform:", "description": "Filter by platform", "category": "entity"},
    {"text": "vendor:", "description": "Search vendor names", "category": "entity"},
    {"text": "vendor.type:", "description": "Filter by vendor type", "category": "entity"},
    {"text": "product:", "description": "Search product names", "category": "entity"},
    {"text": "product.type:", "description": "Filter by product type", "category": "entity"},
    {"text": "product.vendor:", "description": "Vendor that makes the product", "category": "entity"},
    {"text": "country.iso:", "description": "ISO country code (e.g. RU)", "category": "entity"},
    {"text": "mitigation:", "description": "Search mitigations by name or MITRE ID", "category": "entity"},
    {"text": "campaign:", "description": "Search campaign names", "category": "entity"},
    {"text": "campaign.status:", "description": "Filter by campaign status", "category": "entity"},
    {"text": "ransomware_victim:", "description": "Search ransomware victim organizations", "category": "entity"},
    {"text": "ransomware_victim.sector:", "description": "Filter victims by sector", "category": "entity"},
    {"text": "ransomware_victim.domain:", "description": "Filter victims by domain", "category": "entity"},
    {"text": "ransomware_victim.group:", "description": "Group that posted the victim", "category": "entity"},
    {"text": "intel_report:", "description": "Search intel report titles", "category": "entity"},
    {"text": "intel_report.status:", "description": "Filter reports by status", "category": "entity"},
    {"text": "intel_report.tlp:", "description": "Filter reports by TLP marking", "category": "entity"},
    {"text": "rule:", "description": "Search detection rule titles", "category": "entity"},
    {"text": "rule.type:", "description": "Filter by rule format (sigma, splunk_spl, etc.)", "category": "entity"},
    {"text": "rule.severity:", "description": "Filter by rule severity", "category": "entity"},
    {"text": "rule.data_source:", "description": "Log source the rule requires", "category": "entity"},
    {"text": "rule.tactic:", "description": "ATT&CK tactic the rule covers", "category": "entity"},
    {"text": "rule.tag:", "description": "Filter by rule tag", "category": "entity"},
    {"text": "rule.draft:", "description": "Draft rules only", "category": "entity"},
    {"text": "pir:", "description": "Search intelligence requirement titles", "category": "entity"},
    {"text": "pir.priority:", "description": "Filter by PIR priority", "category": "entity"},
    {"text": "pir.category:", "description": "Filter by PIR category", "category": "entity"},
    {"text": "note:", "description": "Search analyst note titles and bodies", "category": "entity"},
    {"text": "note.tag:", "description": "Filter notes by tag", "category": "entity"},
    {"text": "note.type:", "description": "Entity note type (analysis, context, …)", "category": "entity"},
    {
        "text": "note.about:",
        "description": "What the note is on (entry, standalone, or an entity type)",
        "category": "entity",
    },
    {"text": "note.pinned:", "description": "Pinned notes only", "category": "entity"},
    {"text": "title:", "description": "Search entry titles", "category": "entry"},
    {"text": "content:", "description": "Search entry content", "category": "entry"},
    {"text": "author:", "description": "Search by author name", "category": "entry"},
    {"text": "feed:", "description": "Search by feed name", "category": "entry"},
    {"text": "tag:", "description": "Filter by tag", "category": "entry"},
    {"text": "type:", "description": "Filter by feed type (rss, youtube, podcast)", "category": "entry"},
    {"text": "date:", "description": "Filter by date (>2025-01-01, 2025-01..2025-06)", "category": "entry"},
    {"text": "is:", "description": "Filter by state (starred, unread, bookmarked, noted)", "category": "entry"},
    {
        "text": "sort:",
        "description": "Sort results (newest, oldest, shortest, longest, relevance, title_asc, title_desc)",
        "category": "meta",
    },
    {"text": "media:", "description": "Filter by media type (audio, video)", "category": "entry"},
    {"text": "category:", "description": "Filter by feed folder", "category": "entry"},
    {"text": "signal:", "description": "Signal-engine reason (under_reported, kev_added, …)", "category": "entry"},
    {"text": "sector:", "description": "Sector mentioned in the article", "category": "entry"},
    {"text": "url:", "description": "Article link contains", "category": "entry"},
    {"text": "words:", "description": "Article length (e.g. >1500)", "category": "entry"},
    {"text": "feed.reliability:", "description": "Source reliability grade (A-F)", "category": "entry"},
    {"text": "feed.timeliness:", "description": "Source timeliness grade", "category": "entry"},
    {"text": "feed.relevance:", "description": "Source relevance grade", "category": "entry"},
    {"text": "lang:", "description": "Filter by language", "category": "entry"},
]

# Static value suggestions for known fields
# `is:` and `sort:` are taken from the planner that executes them rather than
# retyped: the hand-written copies here offered five of the eight `is:` values
# and every sort except `radar`, which is the one worth discovering.
STATIC_VALUES = {
    "is": list(IS_FILTER_VALUES),
    "sort": sorted(VALID_SORTS),
    "cve.severity": ["critical", "high", "medium", "low"],
    "rule.type": ["sigma", "splunk_spl", "crowdstrike_ql", "elastic_ql", "kql"],
    "campaign.status": ["active", "monitoring", "closed", "historical"],
    "rule.severity": ["critical", "high", "medium", "low"],
    "note.type": ["annotation", "analysis", "action_taken", "false_positive", "context"],
    # `entry` and `standalone` name the other note table; the rest are the
    # entity kinds a note can hang off.
    "note.about": [
        "entry",
        "standalone",
        "threat_actor",
        "malware",
        "cve",
        "ttp",
        "campaign",
        "vendor",
        "product",
    ],
    "note.pinned": ["true", "false"],
}


@router.get("/autocomplete")
async def search_autocomplete(
    q: str = Query(
        min_length=1,
        max_length=200,
        description="Partial query text to complete — a field prefix (e.g. `act`) or a `field:value` pair",
    ),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return autocomplete suggestions for the search query language.

    Suggests field names when typing partial field prefixes,
    or field values when a complete field: prefix is detected.
    """
    suggestions = []

    # Check if we're completing a field value (e.g., "actor:" or "cve.severity:")
    if ":" in q:
        last_token = q.rsplit(None, 1)[-1] if " " in q else q
        if ":" in last_token:
            field_part, value_part = last_token.split(":", 1)
            value_lower = value_part.lower()

            # Static values
            if field_part in STATIC_VALUES:
                for val in STATIC_VALUES[field_part]:
                    if val.startswith(value_lower):
                        suggestions.append(
                            {
                                "type": "value",
                                "text": val,
                                "field": field_part,
                                "insert": _value_insert(field_part, val),
                            }
                        )
                return suggestions[:10]

            # Dynamic values from database
            suggestions = await _get_dynamic_values(db, field_part, value_lower, user.id)
            return suggestions[:10]

    # Field name suggestions
    q_lower = q.rsplit(None, 1)[-1].lower() if " " in q else q.lower()
    for field_info in FIELD_SUGGESTIONS:
        if field_info["text"].startswith(q_lower) or q_lower in field_info["text"]:
            suggestions.append(
                {
                    "type": "field",
                    "text": field_info["text"],
                    "description": field_info["description"],
                    "category": field_info["category"],
                    "insert": field_info["text"],
                }
            )

    return suggestions[:10]


def _value_insert(field_name: str, value: str) -> str:
    """The text a `field:value` completion inserts.

    A value ends at the first space, so an unquoted multi-word completion parses
    as `field:<first word>` plus a free-text term — `country:North Korea` becomes
    `country:North` AND "Korea", which returns a plausible wrong answer instead of
    failing. Anything containing whitespace is quoted. Embedded double quotes are
    dropped: the grammar reads a phrase to the next quote and has no escape.
    """
    if any(ch.isspace() for ch in value):
        return f'{field_name}:"{value.replace(chr(34), "")}"'
    return f"{field_name}:{value}"


async def _get_dynamic_values(
    db: AsyncSession,
    field_name: str,
    partial_value: str,
    user_id: uuid.UUID,
) -> list[dict]:
    """Query database for dynamic autocomplete values."""
    suggestions = []

    if field_name == "threat_actor":
        from app.models.threat_actor import ThreatActor

        result = await db.execute(
            select(ThreatActor.name)
            .where(ThreatActor.name.ilike(f"%{partial_value}%"))
            .order_by(ThreatActor.article_count.desc())
            .limit(10)
        )
        for (name,) in result.all():
            suggestions.append(
                {"type": "value", "text": name, "field": field_name, "insert": _value_insert(field_name, name)}
            )

    elif field_name == "malware":
        from app.models.malware_family import MalwareFamily

        result = await db.execute(
            select(MalwareFamily.name)
            .where(MalwareFamily.name.ilike(f"%{partial_value}%"))
            .order_by(MalwareFamily.article_count.desc())
            .limit(10)
        )
        for (name,) in result.all():
            suggestions.append(
                {"type": "value", "text": name, "field": field_name, "insert": _value_insert(field_name, name)}
            )

    elif field_name == "ttp":
        from app.models.ttp import TTP

        result = await db.execute(
            select(TTP.technique_id, TTP.technique_name)
            .where(or_(TTP.technique_id.ilike(f"%{partial_value}%"), TTP.technique_name.ilike(f"%{partial_value}%")))
            .order_by(TTP.article_count.desc())
            .limit(10)
        )
        for tid, tname in result.all():
            display = f"{tid} {tname}"
            suggestions.append(
                {"type": "value", "text": display, "field": field_name, "insert": _value_insert(field_name, tid)}
            )

    elif field_name == "ttp.tactic":
        from app.models.ttp import TTP

        result = await db.execute(
            select(func.distinct(TTP.tactic))
            .where(TTP.tactic.ilike(f"%{partial_value}%"))
            .where(TTP.tactic.is_not(None))
            .limit(10)
        )
        for (tactic,) in result.all():
            suggestions.append(
                {"type": "value", "text": tactic, "field": field_name, "insert": _value_insert(field_name, tactic)}
            )

    elif field_name == "cve":
        from app.models.cve import CVE

        result = await db.execute(
            select(CVE.cve_id).where(CVE.cve_id.ilike(f"%{partial_value}%")).order_by(CVE.cve_id.desc()).limit(10)
        )
        for (cve_id,) in result.all():
            suggestions.append(
                {"type": "value", "text": cve_id, "field": field_name, "insert": _value_insert(field_name, cve_id)}
            )

    elif field_name == "note":
        # Titles from both note tables, newest first — a note is looked up by
        # what it was called, and there is no popularity metric to rank by.
        from app.models.entity_note import EntityNote
        from app.models.note import Note

        titles = (
            await db.execute(
                select(Note.title, Note.updated_at)
                .where(Note.title.ilike(f"%{partial_value}%"))
                .order_by(Note.updated_at.desc())
                .limit(10)
            )
        ).all()
        titles += (
            await db.execute(
                select(EntityNote.title, EntityNote.updated_at)
                .where(EntityNote.title.isnot(None))
                .where(EntityNote.title.ilike(f"%{partial_value}%"))
                .order_by(EntityNote.updated_at.desc())
                .limit(10)
            )
        ).all()
        seen: set[str] = set()
        for title, _updated in sorted(titles, key=lambda row: row[1], reverse=True):
            if title in seen:
                continue
            seen.add(title)
            suggestions.append(
                {"type": "value", "text": title, "field": field_name, "insert": _value_insert(field_name, title)}
            )

    elif field_name == "note.tag":
        from app.models.entity_note import EntityNote
        from app.models.note import Note

        tag_rows = (await db.execute(select(func.distinct(func.unnest(Note.tags)).label("tag")).limit(200))).all()
        tag_rows += (
            await db.execute(select(func.distinct(func.unnest(EntityNote.tags)).label("tag")).limit(200))
        ).all()
        seen_tags: set[str] = set()
        for (tag,) in tag_rows:
            if not tag or partial_value not in tag.lower() or tag in seen_tags:
                continue
            seen_tags.add(tag)
            suggestions.append(
                {"type": "value", "text": tag, "field": field_name, "insert": _value_insert(field_name, tag)}
            )

    elif field_name == "tag":
        from app.models.tag import Tag

        result = await db.execute(select(Tag.name).where(Tag.name.ilike(f"%{partial_value}%")).limit(10))
        for (name,) in result.all():
            suggestions.append(
                {"type": "value", "text": name, "field": field_name, "insert": _value_insert(field_name, name)}
            )

    elif field_name == "feed":
        from app.models.feed import Feed

        result = await db.execute(
            select(Feed.title)
            .where(Feed.is_active == True)  # noqa: E712
            .where(Feed.title.ilike(f"%{partial_value}%"))
            .limit(10)
        )
        for (title,) in result.all():
            suggestions.append(
                {"type": "value", "text": title, "field": field_name, "insert": _value_insert(field_name, title)}
            )

    elif field_name == "threat_actor.country":
        from app.models.threat_actor import ThreatActor

        result = await db.execute(
            select(func.distinct(ThreatActor.country))
            .where(ThreatActor.country.ilike(f"%{partial_value}%"))
            .where(ThreatActor.country.is_not(None))
            .limit(10)
        )
        for (country,) in result.all():
            suggestions.append(
                {"type": "value", "text": country, "field": field_name, "insert": _value_insert(field_name, country)}
            )

    elif field_name == "country":
        from app.models.country import Country

        result = await db.execute(
            select(Country.name)
            .where(Country.name.ilike(f"%{partial_value}%"))
            .order_by(Country.article_count.desc().nullslast())
            .limit(10)
        )
        for (name,) in result.all():
            suggestions.append(
                {"type": "value", "text": name, "field": field_name, "insert": _value_insert(field_name, name)}
            )

    elif field_name == "country.region":
        from app.models.country import Country

        result = await db.execute(
            select(func.distinct(Country.region))
            .where(Country.region.ilike(f"%{partial_value}%"))
            .where(Country.region.is_not(None))
            .limit(10)
        )
        for (region,) in result.all():
            suggestions.append(
                {"type": "value", "text": region, "field": field_name, "insert": _value_insert(field_name, region)}
            )

    elif field_name == "malware.type":
        from app.models.malware_family import MalwareFamily

        result = await db.execute(
            select(func.distinct(MalwareFamily.malware_type))
            .where(MalwareFamily.malware_type.ilike(f"%{partial_value}%"))
            .where(MalwareFamily.malware_type.is_not(None))
            .limit(10)
        )
        for (mtype,) in result.all():
            suggestions.append(
                {"type": "value", "text": mtype, "field": field_name, "insert": _value_insert(field_name, mtype)}
            )

    elif field_name in ("observable", "ioc"):
        # Ledger values: never-suggest denied or expired rows, busiest first.
        from app.models.observable import Observable

        result = await db.execute(
            select(Observable.value)
            .where(
                Observable.value.ilike(f"%{partial_value}%"),
                Observable.is_denied.is_(False),
                Observable.status != "expired",
            )
            .order_by(Observable.sighting_count.desc())
            .limit(10)
        )
        for (value,) in result.all():
            suggestions.append(
                {"type": "value", "text": value, "field": field_name, "insert": _value_insert(field_name, value)}
            )

    else:
        suggestions.extend(await _generic_value_suggestions(db, field_name, partial_value))

    return suggestions


# Fields whose values are entity names: (model path, name attr, ordering attr).
# Table-driven because they all differ only by model — the hand-written branches
# above predate the types added in the 2026-08 vocabulary unification.
_NAME_VALUE_FIELDS: dict[str, tuple[str, str, str | None]] = {
    "tool": ("app.models.tool:Tool", "name", "article_count"),
    "vendor": ("app.models.vendor:Vendor", "name", "article_count"),
    "product": ("app.models.product:Product", "name", "article_count"),
    "mitigation": ("app.models.mitigation:Mitigation", "name", "article_count"),
    "cwe": ("app.models.cwe:CWE", "cwe_id", "article_count"),
    "campaign": ("app.models.campaign:Campaign", "name", None),
    "ransomware_victim": ("app.models.ransomware:RansomwareVictim", "name", "disclosure_count"),
    # Titled rather than named, but completed the same way.
    "rule": ("app.models.detection_rule:DetectionRule", "title", None),
    "intel_report": ("app.models.intel_report:IntelReport", "title", None),
}

# Fields whose values are a distinct set drawn from one column. Every field the
# grammar accepts whose values are a vocabulary rather than a range belongs
# here: a field missing from these tables completes its name and then offers
# nothing after the colon, which reads as "no such values" rather than "nobody
# taught the autocomplete this one".
_DISTINCT_VALUE_FIELDS: dict[str, tuple[str, str]] = {
    "tool.type": ("app.models.tool:Tool", "tool_type"),
    "vendor.type": ("app.models.vendor:Vendor", "vendor_type"),
    "product.type": ("app.models.product:Product", "product_type"),
    "ransomware_victim.sector": ("app.models.ransomware:RansomwareVictim", "sector"),
    "ransomware_victim.domain": ("app.models.ransomware:RansomwareVictim", "domain"),
    # Entry-scoped
    "sector": ("app.models.entry_sector:EntrySector", "sector"),
    "category": ("app.models.category:Category", "name"),
    "lang": ("app.models.entry:Entry", "language"),
    "type": ("app.models.feed:Feed", "feed_type"),
    "media": ("app.models.entry_media:EntryMedia", "media_type"),
    "feed.reliability": ("app.models.feed:Feed", "reliability_rating"),
    "feed.timeliness": ("app.models.feed:Feed", "timeliness_rating"),
    "feed.relevance": ("app.models.feed:Feed", "relevance_rating"),
    # Entity attributes. The columns are the ones `entity_builder.FIELD_MAP`
    # filters on, so a completion and the query it lands in read the same one.
    "threat_actor.motivation": ("app.models.threat_actor:ThreatActor", "motivation"),
    "threat_actor.type": ("app.models.threat_actor:ThreatActor", "actor_type"),
    "ttp.domain": ("app.models.ttp:TTP", "matrix_domain"),
    "cve.exploit": ("app.models.cve:CVE", "exploit_status"),
    "pir.priority": ("app.models.intelligence_requirement:IntelligenceRequirement", "priority"),
    "pir.category": ("app.models.intelligence_requirement:IntelligenceRequirement", "category"),
    "intel_report.status": ("app.models.intel_report:IntelReport", "status"),
    "intel_report.tlp": ("app.models.intel_report:IntelReport", "tlp_marking"),
    "intel_report.type": ("app.models.intel_report:IntelReport", "template_type"),
    "rule.license": ("app.models.detection_rule:DetectionRule", "license"),
    "country.iso": ("app.models.country:Country", "iso_code"),
    # Both of these filter through a join, so the vocabulary is the joined
    # table's column rather than the entity's own.
    "ransomware_victim.group": ("app.models.ransomware:VictimDisclosure", "group_name_raw"),
    "product.vendor": ("app.models.vendor:Vendor", "name"),
}

# Fields whose values live inside an array column: one row per element, ranked
# by how many rows carry it. `array` is Postgres ARRAY(Text), `jsonb` is a JSONB
# list — the same split `entity_builder` makes to filter them.
_ARRAY_VALUE_FIELDS: dict[str, tuple[str, str, str]] = {
    "rule.data_source": ("app.models.detection_rule:DetectionRule", "data_sources", "array"),
    "rule.tactic": ("app.models.detection_rule:DetectionRule", "mitre_tactics", "array"),
    "rule.tag": ("app.models.detection_rule:DetectionRule", "tags", "array"),
    "threat_actor.sector": ("app.models.threat_actor:ThreatActor", "targeted_sectors", "array"),
    "malware.sector": ("app.models.malware_family:MalwareFamily", "targeted_sectors", "array"),
    "tool.platform": ("app.models.tool:Tool", "platforms", "array"),
    "note.tag": ("app.models.note:Note", "tags", "array"),
    "ttp.platform": ("app.models.ttp:TTP", "platforms", "jsonb"),
    "ttp.data_source": ("app.models.ttp:TTP", "data_sources", "jsonb"),
}


def _load(model_path: str):
    import importlib

    module_path, class_name = model_path.split(":")
    return getattr(importlib.import_module(module_path), class_name)


def _value_suggestion(field_name: str, value: str) -> dict:
    return {"type": "value", "text": value, "field": field_name, "insert": _value_insert(field_name, value)}


async def _generic_value_suggestions(db: AsyncSession, field_name: str, partial_value: str) -> list[dict]:
    """Value suggestions for the table-driven fields above."""
    from app.search.entity_builder import BOOLEAN_FIELDS

    out: list[dict] = []
    if field_name == "signal":
        # The engine's own registry, not a copy of it: a signal that stops
        # firing is still a thing to search for, and a new one is offered the
        # day it ships rather than the day someone remembers this list.
        from app.intelligence.signals import SIGNAL_FAMILIES

        return [_value_suggestion(field_name, name) for name in sorted(SIGNAL_FAMILIES) if partial_value in name]

    if field_name in BOOLEAN_FIELDS:
        return [_value_suggestion(field_name, v) for v in ("true", "false") if v.startswith(partial_value)]

    if field_name in _ARRAY_VALUE_FIELDS:
        return await _array_element_values(db, field_name, partial_value)

    if field_name == "cve.product":
        # The filter matches either half of the CPE, so both halves are offered
        # — `cve.product:microsoft` is a vendor and works.
        from app.models.cve_affected import CVEAffected

        pattern = f"%{partial_value}%"
        halves = (
            select(CVEAffected.cpe_product.label("value"))
            .where(CVEAffected.cpe_product.ilike(pattern))
            .union_all(select(CVEAffected.cpe_vendor.label("value")).where(CVEAffected.cpe_vendor.ilike(pattern)))
            .subquery()
        )
        result = await db.execute(
            select(halves.c.value).group_by(halves.c.value).order_by(func.count().desc(), halves.c.value).limit(10)
        )
        return [_value_suggestion(field_name, value) for (value,) in result.all() if value]

    if field_name == "pir":
        # Only active requirements are worth completing against.
        from app.models.intelligence_requirement import IntelligenceRequirement

        result = await db.execute(
            select(IntelligenceRequirement.title)
            .where(IntelligenceRequirement.title.ilike(f"%{partial_value}%"))
            .where(IntelligenceRequirement.status == "active")
            .limit(10)
        )
        for (title,) in result.all():
            # Titles contain spaces, so the inserted form has to be quoted.
            out.append(
                {"type": "value", "text": title, "field": field_name, "insert": _value_insert(field_name, title)}
            )
    elif field_name in _NAME_VALUE_FIELDS:
        model_path, name_attr, order_attr = _NAME_VALUE_FIELDS[field_name]
        model = _load(model_path)
        col = getattr(model, name_attr)
        stmt = select(col).where(col.ilike(f"%{partial_value}%"))
        if order_attr:
            stmt = stmt.order_by(getattr(model, order_attr).desc().nullslast())
        for (value,) in (await db.execute(stmt.limit(10))).all():
            out.append(
                {"type": "value", "text": value, "field": field_name, "insert": _value_insert(field_name, value)}
            )
    elif field_name in _DISTINCT_VALUE_FIELDS:
        model_path, attr = _DISTINCT_VALUE_FIELDS[field_name]
        col = getattr(_load(model_path), attr)
        # Case-folded for the same reason as the array fields above: one value
        # spelled two ways is one suggestion, and the filter matches both.
        stmt = (
            select(func.mode().within_group(col).label("value"))
            .where(col.ilike(f"%{partial_value}%"))
            .where(col.is_not(None))
            .group_by(func.lower(col))
            .order_by(func.count().desc(), func.mode().within_group(col))
            .limit(10)
        )
        for (value,) in (await db.execute(stmt)).all():
            out.append(
                {"type": "value", "text": value, "field": field_name, "insert": _value_insert(field_name, value)}
            )
    return out


async def _array_element_values(db: AsyncSession, field_name: str, partial_value: str) -> list[dict]:
    """Distinct elements of an array column, most-used first."""
    model_path, attr, kind = _ARRAY_VALUE_FIELDS[field_name]
    column = getattr(_load(model_path), attr)

    if kind == "jsonb":
        element = func.jsonb_array_elements_text(column)
        # A column holding a JSON object or scalar makes the expansion raise and
        # takes the whole request with it, so only arrays are unpacked.
        rows_stmt = select(element.label("value")).where(column.isnot(None), func.jsonb_typeof(column) == "array")
    else:
        element = func.unnest(column)
        rows_stmt = select(element.label("value")).where(column.isnot(None))

    elements = rows_stmt.subquery()
    # Group case-insensitively and offer the spelling most rows actually use.
    # Tags and log-source names come from upstream rule repos, which write
    # "DNS" and "dns" for one thing, and listing both twice over is what made
    # the dropdown look broken. Folding here rather than rewriting the rows
    # keeps vendor data as published and cannot drift back, and the filter is
    # already case-insensitive, so the suggestion still matches every variant
    # it stands for.
    stmt = (
        select(func.mode().within_group(elements.c.value).label("value"))
        .where(elements.c.value.ilike(f"%{partial_value}%"))
        .group_by(func.lower(elements.c.value))
        .order_by(func.count().desc(), func.mode().within_group(elements.c.value))
        .limit(10)
    )
    result = await db.execute(stmt)
    return [_value_suggestion(field_name, value) for (value,) in result.all() if value]


# ── Entity search (Meilisearch) ─────────────────────────────────


ENTITY_INDEX_MAP = {
    "cve": "entities_cve",
    "ttp": "entities_ttp",
    "threat_actor": "entities_threat_actor",
    "malware": "entities_malware",
}


@router.get("/entities")
async def search_entities_meili(
    q: str = Query("", max_length=500, description="Entity name/identifier query; empty matches everything"),
    entity_type: str = Query("cve", description="Entity type to search (cve, ttp, threat_actor, malware)"),
    limit: int = Query(20, ge=1, le=500, description="Page size"),
    offset: int = Query(0, ge=0, description="Number of hits to skip (paging)"),
    _user: User = Depends(get_current_user),
):
    """Search entities via Meilisearch indexes."""
    index_name = ENTITY_INDEX_MAP.get(entity_type)
    if not index_name:
        return {"hits": [], "estimatedTotalHits": 0, "processingTimeMs": 0}

    result = meilisearch_client.search_entities(
        index_name=index_name,
        query=q,
        limit=limit,
        offset=offset,
    )
    return result


@router.post("/entities/sync")
async def sync_entity_indexes(
    user: User = Depends(get_admin_user),
):
    """Queue a full entity index sync to Meilisearch. Admin only."""
    from app.workers.intel_feed_tasks import sync_entity_indexes as sync_task

    task = sync_task.delay()
    return {"status": "queued", "task_id": task.id}


@router.post("/rebuild")
async def rebuild_search_index(
    user: User = Depends(get_admin_user),
):
    """Queue a rebuild of the entries search index. Admin only."""
    from app.workers.intel_feed_tasks import rebuild_search_index as rebuild_task

    task = rebuild_task.delay(str(user.id))
    return {"status": "queued", "task_id": task.id}
