"""
Meilisearch query builder: converts the entry portion of an execution plan
into Meilisearch search parameters.
"""

from __future__ import annotations

import fnmatch

from app.search.query_planner import ExecutionPlan, PendingFacetFilter, SearchBranch
from app.services import meilisearch_client

# Maps plan.sort values to Meilisearch sort parameters.
# title and word_count are in the index's sortableAttributes (see
# meilisearch_client setup) alongside published_at.
_SORT_MAP = {
    "newest": ["published_at:desc"],
    "oldest": ["published_at:asc"],
    "title_asc": ["title:asc"],
    "title_desc": ["title:desc"],
    "shortest": ["word_count:asc"],
    "longest": ["word_count:desc"],
}

# A multi-branch query has to over-fetch from each branch to page correctly,
# since the union is assembled here rather than in the index. This bounds the
# damage a deep offset can do.
_MAX_BRANCH_FETCH = 1000


def _resolve_facet_filters(index, pending: list[PendingFacetFilter]) -> list[str]:
    """Expand wildcard attribute filters against the values actually indexed.

    Meilisearch compares filter values exactly, so `tags = "apt*"` matches a tag
    literally named `apt*` and nothing else. The facet distribution is the list
    of values the attribute really takes, which is what the pattern gets matched
    against.
    """
    clauses: list[str] = []
    for pf in pending:
        try:
            facets = index.search("", {"limit": 0, "facets": [pf.attribute]})
            values = list((facets.get("facetDistribution") or {}).get(pf.attribute, {}))
        except Exception:
            values = []

        pattern = pf.pattern.lower()
        matched = [v for v in values if fnmatch.fnmatchcase(str(v).lower(), pattern)]

        if not matched:
            # No value matches, so the positive form matches nothing; the negated
            # form excludes nothing and is simply dropped.
            if not pf.negated:
                clauses.append(f'{pf.attribute} = "__no_match__"')
            continue

        joined = " OR ".join(f'{pf.attribute} = "{v}"' for v in matched)
        clause = f"({joined})" if len(matched) > 1 else joined
        clauses.append(f"NOT {clause}" if pf.negated else clause)
    return clauses


def _sort_key(sort: str):
    """(attribute, reverse) for a plan sort, or None for relevance ordering."""
    params = _SORT_MAP.get(sort)
    if not params:
        return None
    attribute, _, direction = params[0].partition(":")
    return attribute, direction == "desc"


def _merge_branch_hits(results: list[dict], sort: str) -> list[dict]:
    """Union the per-branch hit lists into one ordered, deduplicated list."""
    key = _sort_key(sort)
    if key is not None:
        attribute, reverse = key
        merged = {h["id"]: h for result in results for h in result.get("hits", [])}
        return sorted(
            merged.values(),
            key=lambda h: (h.get(attribute) is None, h.get(attribute)),
            reverse=reverse,
        )

    # Relevance: each branch ranked its own hits and the scores are not
    # comparable across searches, so interleave by rank instead of trusting one
    # branch's ordering over another's.
    ordered: list[dict] = []
    seen: set[str] = set()
    hit_lists = [result.get("hits", []) for result in results]
    for rank in range(max((len(h) for h in hit_lists), default=0)):
        for hits in hit_lists:
            if rank < len(hits) and hits[rank]["id"] not in seen:
                seen.add(hits[rank]["id"])
                ordered.append(hits[rank])
    return ordered


def _merge_facets(results: list[dict]) -> dict | None:
    """Sum facet counts across branches (an over-count where branches overlap)."""
    merged: dict[str, dict[str, int]] = {}
    for result in results:
        for attribute, values in (result.get("facetDistribution") or {}).items():
            bucket = merged.setdefault(attribute, {})
            for value, count in values.items():
                bucket[value] = bucket.get(value, 0) + count
    return merged or None


def execute_entry_search(
    plan: ExecutionPlan,
    entry_id_constraint: list[str] | None = None,
    limit: int = 20,
    offset: int = 0,
    attributes_to_retrieve: list[str] | None = None,
) -> dict:
    """Execute entry search against Meilisearch using the execution plan.

    Args:
        plan: The execution plan from the query planner.
        entry_id_constraint: Optional list of entry IDs to restrict results to
            (from entity query results, for AND join mode).
        limit: Max results to return.
        offset: Pagination offset.
        attributes_to_retrieve: Fields each hit should carry. Passing `["id"]`
            turns a wide scan into an ID list — entries index up to 50k
            characters of body text apiece, so a thousand full documents is
            tens of megabytes for something the caller only wants IDs from.

    Returns:
        Meilisearch response dict with hits, estimatedTotalHits, etc.
    """
    # If entity constraints yielded no entries, return empty results
    if entry_id_constraint is not None and len(entry_id_constraint) == 0:
        return {"hits": [], "estimatedTotalHits": 0, "processingTimeMs": 0}

    try:
        client = meilisearch_client._get_client()
        index = client.index(meilisearch_client.INDEX_NAME)
    except Exception:
        return {"hits": [], "estimatedTotalHits": 0, "processingTimeMs": 0}

    branches = plan.branches or [SearchBranch(query=plan.meili_query, filters=list(plan.meili_filters))]

    # Filters that apply to every branch: wildcard attribute filters, which need
    # the index to resolve, and the entity join's ID constraint.
    shared: list[str] = _resolve_facet_filters(index, plan.pending_facet_filters)
    if entry_id_constraint is not None:
        # Use Meilisearch IN operator for compact filtering
        # Cap at 500 IDs to stay within filter size limits
        ids = entry_id_constraint[:500]
        id_list = ", ".join(f"'{eid}'" for eid in ids)
        shared.append(f"id IN [{id_list}]")

    base_params: dict = {
        "showMatchesPosition": True,
        "attributesToHighlight": ["title", "content_text"],
        "highlightPreTag": "<mark>",
        "highlightPostTag": "</mark>",
        "attributesToCrop": ["content_text"],
        "cropLength": 200,
        # Terms are ANDed. Meilisearch's default ("last") drops trailing words
        # when strict matching runs short, which made `a AND b` return very
        # nearly what `a` alone returns.
        "matchingStrategy": "all",
        # Everything the search page's Entries facets offer. feed_title rather
        # than feed_id so the counts arrive already human-readable; the index's
        # maxValuesPerFacet is 5000, well clear of the feed count.
        "facets": ["feed_type", "feed_title", "tags", "media_type", "language"],
    }

    # Sort ("relevance" uses default ranking rules — no explicit sort)
    sort_param = _SORT_MAP.get(plan.sort)
    if sort_param:
        base_params["sort"] = sort_param

    if attributes_to_retrieve is not None:
        attrs = list(attributes_to_retrieve)
        # A multi-branch union is merged and sorted here, on the hits' own
        # values — dropping the sort attribute would scramble that ordering.
        key = _sort_key(plan.sort)
        if key is not None and key[0] not in attrs:
            attrs.append(key[0])
        base_params["attributesToRetrieve"] = attrs
        # Highlighting and cropping exist for a page a person reads; a scan
        # pays for them on every hit and shows none of them.
        for param in ("showMatchesPosition", "attributesToHighlight", "attributesToCrop", "cropLength"):
            base_params.pop(param, None)

    def run(branch: SearchBranch, branch_limit: int, branch_offset: int) -> dict:
        params = dict(base_params)
        params["limit"] = branch_limit
        params["offset"] = branch_offset
        # A caller that skipped resolve_feed_filters/resolve_entry_filters leaves
        # placeholders behind. Dropping those clauses degrades to "filter
        # ignored", which is what such a caller got before the filter could take
        # part in an OR — far better than handing Meilisearch a filter it cannot
        # parse and losing the whole search.
        filters = [f for f in shared + branch.filters if "\x00pending:" not in f]
        if filters:
            params["filter"] = " AND ".join(filters)
        try:
            return index.search(branch.query, params)
        except Exception:
            return {"hits": [], "estimatedTotalHits": 0, "processingTimeMs": 0}

    # The common case: one search, and the index does the paging.
    if len(branches) == 1:
        return meilisearch_client.strip_private_fields(run(branches[0], limit, offset))

    # An OR across text terms cannot be one search, so the union is assembled
    # here. Each branch is fetched from the top — a branch's own offset means
    # nothing to the merged ordering — and the page is cut from the result.
    need = min(offset + limit, _MAX_BRANCH_FETCH)
    results = [run(branch, need, 0) for branch in branches]

    merged_hits = _merge_branch_hits(results, plan.sort)
    page = merged_hits[offset : offset + limit]

    # An upper bound: branches that overlap are counted twice, and the true
    # union size is not knowable without enumerating it. Deliberately *not*
    # corrected by the overlap visible in this page — that would make the total
    # drift every time the user pages, which reads as a bug in the UI.
    estimated = max(sum(r.get("estimatedTotalHits", 0) for r in results), len(merged_hits))

    return meilisearch_client.strip_private_fields(
        {
            "hits": page,
            "estimatedTotalHits": estimated,
            "processingTimeMs": sum(r.get("processingTimeMs", 0) for r in results),
            "facetDistribution": _merge_facets(results),
        }
    )
