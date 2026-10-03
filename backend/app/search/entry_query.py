"""Run a query-language string and get back plain entry ids.

The reading surfaces want hits with scores, highlights and per-user read state;
the *intake* surfaces — a campaign's linked saved search, a campaign query
source — want only the id set, so they can diff it against what the campaign
already holds. This is that narrow form, in one place because two sweeps need
identical semantics.

It is narrow but not naive. The earlier version of this (``_get_search_total_
and_ids`` in the saved-search worker) planned the query and went straight to
Meilisearch, which meant three silent zeroes:

* **Entity filters never ran.** ``malware:"Akira"`` resolves through
  ``execute_entity_queries``, not the index. The old helper skipped that step
  and then bailed on its own guard, so the single most natural intake query —
  "every article about this malware family" — synced nothing while
  ``/api/search`` answered 506 for the same string.
* **Entity-only plans were refused.** The guard asked for a text query or an
  entry filter, and an entity filter is neither.
* **Large id constraints lost their tail.** ``execute_entry_search`` keeps the
  first 500 ids of a constraint and drops the rest, so a query narrowed to a few
  thousand entries answered with an arbitrary subset.

The order below mirrors ``/api/search``: resolve the deferred filters, run the
entity side, intersect the id sets, and only ask the index when there is
actually text for it to match.
"""

import logging

from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

#: Ceiling on ids pulled back for one query. A standing intake query matching
#: more than this is too broad to be intake, and the cap keeps one pathological
#: source from stalling the whole sweep.
MAX_QUERY_IDS = 5000

#: ``execute_entry_search`` renders an id constraint as a Meilisearch
#: ``id IN [...]`` clause and keeps only the first 500 — past that the index
#: cannot be asked, and the constraint is the answer on its own.
MEILI_ID_FILTER_CAP = 500

#: How many *entities* an entity filter may resolve to. Generous because the
#: entries come from the matched entities: `actor:lazarus` naming one actor is
#: the normal case, but an alias-wide match that silently kept 50 of 300
#: products would drop the articles of the other 250.
ENTITY_MATCH_LIMIT = 500


def query_unknown_fields(query_str: str) -> list[str]:
    """Field names in this query the language does not know.

    They are not an error — the planner folds an unknown ``foo:bar`` into the
    text query — but on a *standing* source they are the quiet kind of wrong:
    ``actor:"Scattered Spider"`` (the field is ``threat_actor:``) becomes a
    phrase search that keeps answering with a plausible number forever.
    """
    from app.search.query_parser import ParseError, parse_query
    from app.search.query_planner import build_execution_plan

    try:
        plan = build_execution_plan(parse_query(query_str or ""))
    except ParseError:
        return []
    return sorted(set(plan.unknown_fields))


async def search_entry_ids(
    query_str: str,
    db: AsyncSession,
    limit: int = MAX_QUERY_IDS,
) -> tuple[int, list[str]]:
    """``(total_hits, entry_ids)`` for a query-language string.

    Returns ``(0, [])`` for an unparseable query and for one that resolves to no
    executable filter at all — a standing source must not take its campaign down
    with it when somebody mistypes a field name.
    """
    from app.search.entity_builder import execute_entity_queries
    from app.search.meili_builder import execute_entry_search
    from app.search.query_parser import ParseError, parse_query
    from app.search.query_planner import build_execution_plan, resolve_deferred_filters

    try:
        ast = parse_query(query_str)
    except ParseError:
        return 0, []

    plan = build_execution_plan(ast)
    await resolve_deferred_filters(db, plan)

    # The entity side of the query: `actor:`, `malware:`, `cve:` and friends
    # resolve to the entries those entities are linked to.
    constraint_ids: set[str] | None = None
    if plan.has_entity_queries:
        _, linked = await execute_entity_queries(db, plan.entity_nodes, limit=ENTITY_MATCH_LIMIT)
        # OR-joined entity filters widen the result rather than narrowing it, so
        # they are not a constraint — the same rule /api/search follows.
        if plan.join_mode == "AND":
            constraint_ids = linked
    if plan.db_entry_ids is not None:
        constraint_ids = plan.db_entry_ids if constraint_ids is None else constraint_ids & plan.db_entry_ids
    if plan.db_excluded_ids and constraint_ids is not None:
        constraint_ids -= plan.db_excluded_ids

    if constraint_ids is not None and not constraint_ids:
        # Something was named and matched nothing. Not an error, just empty.
        return 0, []

    if not (plan.has_entry_queries or plan.meili_query.strip() or constraint_ids):
        return 0, []

    # Nothing for the index to match, or more ids than it can be handed: the
    # constraint already *is* the answer. Sorted so a truncated result is at
    # least deterministic rather than whatever the set happened to iterate as.
    index_has_work = bool(plan.meili_query.strip() or plan.meili_filters)
    if constraint_ids is not None and (not index_has_work or len(constraint_ids) > MEILI_ID_FILTER_CAP):
        entry_ids = sorted(constraint_ids)[:limit]
        return len(entry_ids), entry_ids

    ids_result = execute_entry_search(plan, list(constraint_ids) if constraint_ids is not None else None, limit, 0)
    entry_ids = [hit["id"] for hit in ids_result.get("hits", []) if "id" in hit]
    # The real hit count, not estimatedTotalHits — Meili overcounts that.
    return len(entry_ids), entry_ids
