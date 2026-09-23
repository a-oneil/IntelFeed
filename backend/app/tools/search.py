"""Search & Discovery tools (4 tools)."""

import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.category import Category
from app.models.feed import Feed
from app.models.tag import EntryTag, Tag
from app.search.query_planner import VALID_SORTS
from app.tools import _tool

_SORT_VALUES = sorted(VALID_SORTS)


async def _run_search_plan(
    db: AsyncSession,
    user_id: uuid.UUID,
    query: str,
    *,
    limit: int,
    offset: int = 0,
    sort: str | None = None,
    entity_limit: int = 10,
    search_entities_for_text: bool = True,
) -> tuple[object, dict, list[dict]]:
    """Parse ``query`` and execute the full search plan the way POST /api/search/unified does.

    Handles field:value syntax (feed:, tag:, date:, is:, sort:, and entity filters like
    threat_actor:APT29), boolean operators, feed-name resolution, and entity-linked entry
    joins — instead of running only the Meilisearch half of the plan.

    Returns (plan, entry_result, entity_results).
    """
    from app.api.search import _fetch_entries_by_ids, _get_entity_linked_entry_ids
    from app.intelligence.correlation import search_all_entities
    from app.search.entity_builder import execute_entity_queries
    from app.search.meili_builder import execute_entry_search
    from app.search.query_parser import ParseError, parse_query
    from app.search.query_planner import build_execution_plan, resolve_deferred_filters

    try:
        ast = parse_query(query)
    except ParseError:
        ast = parse_query("")
    plan = build_execution_plan(ast)
    # An explicit sort argument wins; otherwise any sort: field in the query applies.
    if sort and sort != "relevance":
        plan.sort = sort

    # Feed-name lookups and the Postgres-backed entry filters (category:, signal:,
    # sector:, url:, feed.*, is:muted/translated/image). Without this the filters
    # parse and are then silently dropped, so `signal:under_reported` answers with
    # every entry. Both resolvers together, per resolve_deferred_filters.
    await resolve_deferred_filters(db, plan)

    entity_results: list[dict] = []
    linked_entry_ids: set[str] | None = None
    if plan.has_entity_queries:
        entity_results, found_entry_ids = await execute_entity_queries(
            db, plan.entity_nodes, limit=entity_limit, user_id=str(user_id)
        )
        if plan.join_mode == "AND":
            linked_entry_ids = found_entry_ids
    elif plan.meili_query.strip() and search_entities_for_text:
        entity_results = await search_all_entities(db, plan.meili_query.strip(), limit=entity_limit)

    # A Postgres-backed entry filter narrows the same way an entity join does.
    if plan.db_entry_ids is not None:
        linked_entry_ids = plan.db_entry_ids if linked_entry_ids is None else linked_entry_ids & plan.db_entry_ids
    if plan.db_excluded_ids and linked_entry_ids is not None:
        linked_entry_ids = linked_entry_ids - plan.db_excluded_ids

    entry_result: dict = {"hits": [], "estimatedTotalHits": 0, "processingTimeMs": 0}
    if plan.has_entry_queries or (plan.has_entity_queries and plan.join_mode == "AND"):
        entry_id_constraint = list(linked_entry_ids) if linked_entry_ids is not None else None
        # `sort:radar` orders by priority_score, a Postgres column the search
        # index does not carry, so it always takes the PG path.
        if plan.sort == "radar":
            entry_result = await _fetch_entries_by_ids(
                db, entry_id_constraint, limit=limit, offset=offset, sort="radar"
            )
        # Nothing for the index to search: entity-only, or a Postgres-backed
        # filter with no text term. Passing tens of thousands of IDs as a
        # Meilisearch filter string silently returns zero.
        elif (
            entry_id_constraint is not None
            and len(entry_id_constraint) > 0
            and (
                not plan.has_entry_queries
                or (not plan.meili_query.strip() and not plan.meili_filters)
                or len(entry_id_constraint) > 800
            )
        ):
            entry_result = await _fetch_entries_by_ids(
                db, entry_id_constraint, limit=limit, offset=offset, sort=plan.sort
            )
        else:
            entry_result = execute_entry_search(
                plan, entry_id_constraint=entry_id_constraint, limit=limit, offset=offset
            )

    # Plain-text queries that matched entities but few entries: merge in entries linked
    # to those entities (mirrors the unified search endpoint). Skipped when explicit
    # filters are active, since the linked entries would bypass them.
    if (
        entity_results
        and not plan.has_entity_queries
        and not plan.meili_filters
        and entry_result.get("estimatedTotalHits", 0) < limit
    ):
        entity_linked_ids = await _get_entity_linked_entry_ids(db, entity_results)
        existing_ids = {h["id"] for h in entry_result.get("hits", [])}
        new_ids = [eid for eid in entity_linked_ids if eid not in existing_ids]
        remaining = limit - len(entry_result.get("hits", []))
        if new_ids and remaining > 0:
            linked_result = await _fetch_entries_by_ids(
                db, new_ids[:remaining], limit=remaining, offset=0, sort=plan.sort
            )
            entry_result["hits"] = entry_result.get("hits", []) + linked_result.get("hits", [])
            entry_result["estimatedTotalHits"] = entry_result.get("estimatedTotalHits", 0) + linked_result.get(
                "estimatedTotalHits", 0
            )

    return plan, entry_result, entity_results


@_tool(
    name="search_entries",
    description=(
        "Full-text search across RSS entries. Returns titles, summaries, dates, and feed names. "
        "Supports the full query language: AND/OR/NOT, quoted phrases, entry fields "
        "(feed:, tag:, type:, date:, is:, media:, lang:, title:, author:), entity filters "
        "(threat_actor:APT29, malware:, cve:, ttp:, tool:, vendor:, product:, country:, campaign:, rule:), "
        "and sort: — all filters are executed, not just the text terms. "
        "Supports pagination via offset for pulling large result sets."
    ),
    input_schema={
        "properties": {
            "query": {"type": "string", "description": "Search query (text, boolean operators, field:value filters)"},
            "limit": {"type": "integer", "description": "Max results per call (default 20, max 1000)", "default": 20},
            "offset": {
                "type": "integer",
                "description": "Pagination offset for paging through large result sets (default 0)",
                "default": 0,
            },
            "sort": {"type": "string", "enum": _SORT_VALUES, "default": "relevance"},
        },
        "required": ["query"],
    },
)
async def _search_entries(
    db: AsyncSession, user_id: uuid.UUID, query: str, limit: int = 20, offset: int = 0, sort: str = "relevance"
) -> dict:
    limit = max(1, min(limit, 1000))
    offset = max(0, offset)
    _plan, results, _entities = await _run_search_plan(
        db, user_id, query, limit=limit, offset=offset, sort=sort, entity_limit=20
    )
    hits = results.get("hits", [])
    return {
        "total": results.get("estimatedTotalHits", 0),
        "limit": limit,
        "offset": offset,
        "entries": [
            {
                "id": h.get("id"),
                "title": h.get("title", ""),
                "summary": (h.get("content_text") or "")[:300],
                "feed_title": h.get("feed_title", ""),
                "published_at": h.get("published_at"),
                "url": h.get("url"),
            }
            for h in hits
        ],
    }


@_tool(
    name="search_entities",
    description=(
        "Search across all 13 intelligence entity types — TTPs, CVEs, CWEs (weaknesses), threat "
        "actors, malware, detection rules, tools, vendors, products, countries, mitigations, "
        "campaigns, intel reports — plus the analyst notes stored on the instance. Returns matching entities with "
        "type and key details. Note results use type 'note' and carry note_source ('note' for a "
        "note on an article or a standalone one, 'entity_note' for one attached to an entity), "
        "with a description snippet centred on the match rather than the note's opening line."
    ),
    input_schema={
        "properties": {
            "query": {"type": "string", "description": "Search term"},
            "limit": {"type": "integer", "default": 30},
        },
        "required": ["query"],
    },
)
async def _search_entities(db: AsyncSession, user_id: uuid.UUID, query: str, limit: int = 30) -> dict:
    from app.intelligence.correlation import search_all_entities

    results = await search_all_entities(db, query, limit=min(limit, 50))
    return {"results": results, "count": len(results)}


@_tool(
    name="search_unified",
    description=(
        "Unified search across both entries and entities simultaneously, with the full query "
        "language (boolean operators, entry fields like feed:/tag:/date:, entity filters like "
        "threat_actor:APT29, sort:). Entity filters constrain entry results via linked entries. "
        "Returns combined results grouped by type."
    ),
    input_schema={
        "properties": {
            "query": {"type": "string", "description": "Search query (text, boolean operators, field:value filters)"},
            "limit": {"type": "integer", "default": 20},
        },
        "required": ["query"],
    },
)
async def _search_unified(db: AsyncSession, user_id: uuid.UUID, query: str, limit: int = 20) -> dict:
    limit = min(limit, 30)
    _plan, entry_results, entity_results = await _run_search_plan(
        db, user_id, query, limit=limit, entity_limit=min(limit, 30)
    )
    hits = entry_results.get("hits", [])
    return {
        "entries": {
            "total": entry_results.get("estimatedTotalHits", 0),
            "items": [
                {
                    "id": h.get("id"),
                    "title": h.get("title", ""),
                    "summary": (h.get("content_text") or "")[:200],
                    "feed_title": h.get("feed_title", ""),
                    "published_at": h.get("published_at"),
                }
                for h in hits
            ],
        },
        "entities": {
            "total": len(entity_results),
            "items": entity_results,
        },
    }


@_tool(
    name="get_search_facets",
    description=(
        "Get available search facets: feed types (feed count per type), categories "
        "(feed count per category), and top tags (by entry usage). Useful for "
        "understanding what's in the system before searching."
    ),
    input_schema={"properties": {}},
)
async def _get_search_facets(db: AsyncSession, user_id: uuid.UUID) -> dict:
    type_q = await db.execute(select(Feed.feed_type, func.count(Feed.id)).group_by(Feed.feed_type))
    feed_types = {row[0]: row[1] for row in type_q}

    cat_q = await db.execute(
        select(Category.name, func.count(Feed.id)).join(Feed, Feed.category_id == Category.id).group_by(Category.name)
    )
    categories = {row[0]: row[1] for row in cat_q}

    tag_q = await db.execute(
        select(Tag.name, func.count(EntryTag.entry_id))
        .join(EntryTag, EntryTag.tag_id == Tag.id)
        .group_by(Tag.name)
        .order_by(func.count(EntryTag.entry_id).desc())
        .limit(50)
    )
    tags = {row[0]: row[1] for row in tag_q}

    return {"feed_types": feed_types, "categories": categories, "tags": tags}
