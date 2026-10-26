import logging
import time
import uuid
from datetime import UTC

import meilisearch

from app.config import settings
from app.search.query_planner import tag_filter_clause

logger = logging.getLogger(__name__)

_client: meilisearch.Client | None = None

INDEX_NAME = "entries"


def _get_client() -> meilisearch.Client:
    global _client
    if _client is None:
        try:
            client = meilisearch.Client(settings.meili_url, settings.meili_master_key, timeout=settings.meili_timeout)
            # Verify connectivity before committing
            client.health()
            _client = client
            _ensure_index()
        except Exception as e:
            logger.warning("Meilisearch connection failed, will retry next call: %s", e)
            raise
    return _client


# Attributes the query builder filters on. `id` is here because the entity join
# constrains the entry search with `id IN [...]`; without it Meilisearch answers
# 400 and execute_entry_search swallows the error, so every text term combined
# with an entity filter silently returned zero articles.
FILTERABLE_ATTRIBUTES = [
    "id",
    "feed_id",
    "feed_title",
    "category_id",
    "feed_type",
    "published_at",
    "author",
    "is_read",
    "is_starred",
    "is_bookmarked",
    "has_notes",
    "media_type",
    "tags",
    # Personal tag assignments as "<user_id>:<name>" — filter-only and never
    # searched. Faceted only to be folded into `tags` for the one viewer whose
    # tokens they are (see fold_viewer_tags), so one analyst's tags can't
    # surface for another.
    "user_tags",
    "language",
    # Already indexed and sortable; filterable is what `words:>1500` needs.
    "word_count",
]


def strip_private_fields(result: dict) -> dict:
    """Drop index-only fields from search hits before they leave the server.

    `user_tags` carries every user's personal tag assignments; the query
    planner filters on it, but no response may show one user's tags to another.
    """
    for hit in result.get("hits") or []:
        hit.pop("user_tags", None)
    return result


def viewer_facets(base: list[str], viewer_id: str | None) -> list[str]:
    """The facets to request: `base`, plus `user_tags` when there is a viewer
    whose tokens `fold_viewer_tags` can fold into `tags`."""
    if viewer_id and "tags" in base and "user_tags" not in base:
        return [*base, "user_tags"]
    return base


def fold_viewer_tags(result: dict, viewer_id: str | None) -> dict:
    """Fold the viewer's own `user_tags` facet tokens into the `tags` facet.

    The raw `user_tags` distribution carries every user's tokens, so it never
    leaves the server: the viewer's `"<user_id>:<name>"` entries are added to
    `tags` under their bare name and the rest are dropped. Counts add cleanly
    because a tag's name is in `tags` (global) or in `user_tags` (personal) on
    any one document, never both — once scripts/maintenance/reindex_entry_tags.py
    has run after the migration.
    """
    dist = result.get("facetDistribution")
    if not dist or "user_tags" not in dist:
        return result
    tokens = dist.pop("user_tags") or {}
    if viewer_id:
        prefix = f"{viewer_id}:"
        tags = dist.setdefault("tags", {})
        for token, count in tokens.items():
            if token.startswith(prefix):
                name = token[len(prefix) :]
                tags[name] = tags.get(name, 0) + count
    return result


def _ensure_index():
    """Create the entries index if it doesn't exist and configure it."""
    client = _client
    if client is None:
        return
    try:
        client.get_index(INDEX_NAME)
    except meilisearch.errors.MeilisearchApiError:
        client.create_index(INDEX_NAME, {"primaryKey": "id"})

    index = client.index(INDEX_NAME)
    index.update_filterable_attributes(FILTERABLE_ATTRIBUTES)
    index.update_sortable_attributes(["published_at", "title", "word_count"])
    index.update_searchable_attributes(["title", "content_text", "summary", "author", "feed_title", "tags"])
    index.update_typo_tolerance(
        {
            "enabled": True,
            "minWordSizeForTypos": {"oneTypo": 4, "twoTypos": 8},
        }
    )
    index.update_ranking_rules(
        [
            "sort",
            "words",
            "typo",
            "proximity",
            "attribute",
            "exactness",
        ]
    )
    # Default cap is 100 — too low for feed_id (one entry per feed). Raised so
    # facet-distribution queries can enumerate every feed_id in the index,
    # which the search-index reconcile script relies on.
    index.update_faceting_settings({"maxValuesPerFacet": 5000})
    try:
        index.update_pagination_settings({"maxTotalHits": 100000})
    except (AttributeError, meilisearch.errors.MeilisearchApiError):
        pass


def index_entry(
    entry_id: uuid.UUID,
    feed_id: uuid.UUID,
    title: str,
    content_text: str | None,
    summary: str | None,
    author: str | None,
    published_at: str | None,
    feed_type: str = "rss",
    category_id: str | None = None,
    feed_title: str | None = None,
    url: str | None = None,
    media_type: str | None = None,
    language: str | None = None,
    tags: list[str] | None = None,
    is_read: bool = False,
    is_starred: bool = False,
    is_bookmarked: bool = False,
    has_notes: bool = False,
    word_count: int | None = None,
):
    """Index an entry in Meilisearch."""
    try:
        client = _get_client()
        index = client.index(INDEX_NAME)

        # Convert ISO string to Unix timestamp for reliable sorting
        published_ts: int = 0
        if published_at:
            from datetime import datetime

            try:
                dt = datetime.fromisoformat(published_at)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=UTC)
                published_ts = int(dt.timestamp())
            except (ValueError, TypeError):
                published_ts = 0

        doc = {
            "id": str(entry_id),
            "feed_id": str(feed_id),
            "title": title,
            "content_text": (content_text or "")[:50000],
            "summary": summary or "",
            "author": author or "",
            "published_at": published_ts,
            "feed_type": feed_type,
            "category_id": str(category_id) if category_id else None,
            "feed_title": feed_title or "",
            "url": url or "",
            "media_type": media_type,
            "language": language,
            **({"tags": tags} if tags is not None else {}),
            "is_read": is_read,
            "is_starred": is_starred,
            "is_bookmarked": is_bookmarked,
            "has_notes": has_notes,
            "word_count": word_count or 0,
        }
        # update_documents, not add_documents: a re-index of an existing entry
        # (transcript append, reconcile, retry) must not wipe the `tags` /
        # `user_tags` fields that only the tag write paths know how to compute.
        index.update_documents([doc])
    except Exception as e:
        logger.warning(
            "Failed to index entry %s in Meilisearch: %s",
            entry_id,
            e,
        )
        raise


def bulk_update_entry_tags(tag_map: dict[str, dict[str, list[str]]]):
    """Partial-update the tag fields for many entries in one batch.

    ``tag_map`` maps entry id (str) -> ``{"tags": [...], "user_tags": [...]}``
    as built by ``app.services.entry_tags.search_tag_fields``. Only those
    fields are touched, so other document fields are preserved. Used by every
    tag write, including rename / delete / merge, which can affect thousands
    of entries at once.
    """
    if not tag_map:
        return
    try:
        index = _get_client().index(INDEX_NAME)
        docs = [{"id": eid, **fields} for eid, fields in tag_map.items()]
        for i in range(0, len(docs), 1000):
            index.update_documents(docs[i : i + 1000])
    except Exception as e:
        logger.warning("Failed to bulk-update entry tags in Meilisearch: %s", e)


def update_entry_state(
    entry_id: uuid.UUID,
    is_read: bool | None = None,
    is_starred: bool | None = None,
    is_bookmarked: bool | None = None,
    has_notes: bool | None = None,
):
    """Partial update of entry state fields in the search index."""
    try:
        client = _get_client()
        index = client.index(INDEX_NAME)
        doc: dict = {"id": str(entry_id)}
        if is_read is not None:
            doc["is_read"] = is_read
        if is_starred is not None:
            doc["is_starred"] = is_starred
        if is_bookmarked is not None:
            doc["is_bookmarked"] = is_bookmarked
        if has_notes is not None:
            doc["has_notes"] = has_notes
        index.update_documents([doc])
    except Exception as e:
        logger.warning("Failed to update entry state %s in Meilisearch: %s", entry_id, e)


def bulk_update_read_state(entry_ids: list[str], is_read: bool):
    """Batch-update is_read for many entries in the search index.

    Used by the mark-all-read background task. Best-effort — search state
    self-corrects on the next full reconcile if this fails.
    """
    if not entry_ids:
        return
    try:
        client = _get_client()
        index = client.index(INDEX_NAME)
        docs = [{"id": str(eid), "is_read": is_read} for eid in entry_ids]
        for i in range(0, len(docs), 1000):
            index.update_documents(docs[i : i + 1000])
    except Exception as e:
        logger.warning("Failed to bulk-update read state in Meilisearch (%d ids): %s", len(entry_ids), e)


def delete_entry(entry_id: uuid.UUID):
    """Remove an entry from the search index."""
    try:
        client = _get_client()
        index = client.index(INDEX_NAME)
        index.delete_document(str(entry_id))
    except Exception as e:
        logger.warning(
            "Failed to delete entry %s from Meilisearch: %s",
            entry_id,
            e,
        )


def delete_entries_by_feed(feed_id: uuid.UUID):
    """Remove all entries for a feed from the search index."""
    try:
        client = _get_client()
        index = client.index(INDEX_NAME)
        index.delete_documents(filter=f'feed_id = "{feed_id}"')
        logger.info("Deleted search index entries for feed %s", feed_id)
    except Exception as e:
        logger.warning(
            "Failed to delete entries for feed %s from Meilisearch: %s",
            feed_id,
            e,
        )


def delete_entries_batch(entry_ids: list[uuid.UUID]):
    """Remove multiple entries from the search index by ID."""
    if not entry_ids:
        return
    try:
        client = _get_client()
        index = client.index(INDEX_NAME)
        index.delete_documents([str(eid) for eid in entry_ids])
    except Exception as e:
        logger.warning(
            "Failed to batch delete %d entries from Meilisearch: %s",
            len(entry_ids),
            e,
        )


def search_entries(
    query: str,
    feed_id: str | list[str] | None = None,
    category_id: str | list[str] | None = None,
    feed_type: list[str] | None = None,
    tags: list[str] | None = None,
    date_from: float | None = None,
    date_to: float | None = None,
    is_read: bool | None = None,
    is_starred: bool | None = None,
    is_bookmarked: bool | None = None,
    has_notes: bool | None = None,
    media_type: str | None = None,
    sort: str = "relevance",
    limit: int = 20,
    offset: int = 0,
    show_matches: bool = True,
    facets: list[str] | None = None,
    viewer_id: str | None = None,
) -> dict:
    """Search entries with advanced filtering and facets.

    `viewer_id` is the searching user's id. With it, `tags` filters also match
    their own personal assignments and the `tags` facet includes them; without
    it, only global tags take part.
    """
    try:
        client = _get_client()
        index = client.index(INDEX_NAME)

        # Build filter conditions
        filters = []
        if feed_id:
            if isinstance(feed_id, list):
                fid_parts = " OR ".join(f'feed_id = "{fid}"' for fid in feed_id)
                filters.append(f"({fid_parts})")
            else:
                filters.append(f'feed_id = "{feed_id}"')
        if category_id:
            if isinstance(category_id, list):
                cid_parts = " OR ".join(f'category_id = "{cid}"' for cid in category_id)
                filters.append(f"({cid_parts})")
            else:
                filters.append(f'category_id = "{category_id}"')
        if feed_type:
            type_filters = " OR ".join(f'feed_type = "{ft}"' for ft in feed_type)
            filters.append(f"({type_filters})")
        if tags:
            for tag in tags:
                filters.append(tag_filter_clause(tag, viewer_id))
        if date_from is not None:
            filters.append(f"published_at >= {date_from}")
        if date_to is not None:
            filters.append(f"published_at <= {date_to}")
        if is_read is not None:
            filters.append(f"is_read = {str(is_read).lower()}")
        if is_starred is not None:
            filters.append(f"is_starred = {str(is_starred).lower()}")
        if is_bookmarked is not None:
            filters.append(f"is_bookmarked = {str(is_bookmarked).lower()}")
        if has_notes is not None:
            filters.append(f"has_notes = {str(has_notes).lower()}")
        if media_type:
            filters.append(f'media_type = "{media_type}"')

        params: dict = {
            "limit": limit,
            "offset": offset,
            "showMatchesPosition": show_matches,
            "attributesToHighlight": ["title", "content_text"],
            "highlightPreTag": "<mark>",
            "highlightPostTag": "</mark>",
            "attributesToCrop": ["content_text"],
            "cropLength": 200,
        }

        if filters:
            params["filter"] = " AND ".join(filters)

        if sort == "newest":
            params["sort"] = ["published_at:desc"]
        elif sort == "oldest":
            params["sort"] = ["published_at:asc"]
        elif sort == "title_asc":
            params["sort"] = ["title:asc"]
        elif sort == "title_desc":
            params["sort"] = ["title:desc"]
        elif sort == "shortest":
            params["sort"] = ["word_count:asc"]
        elif sort == "longest":
            params["sort"] = ["word_count:desc"]
        # "relevance" uses default ranking rules (no explicit sort)

        params["facets"] = viewer_facets(facets or ["feed_type", "tags", "media_type"], viewer_id)

        return strip_private_fields(fold_viewer_tags(index.search(query, params), viewer_id))
    except Exception as e:
        logger.warning(f"Meilisearch search failed: {e}")
        return {"hits": [], "estimatedTotalHits": 0, "processingTimeMs": 0, "searchUnavailable": True}


def find_similar_entries(
    entry_id: str,
    title: str,
    summary: str | None = None,
    content_text: str | None = None,
    exclude_ids: list[str] | None = None,
    limit: int = 10,
    filter: str | None = None,
) -> dict:
    """Find entries similar to a given entry using keyword extraction + BM25.

    ``filter`` is a Meilisearch filter on the candidates (a visitor's feeds).

    Extracts significant terms from the entry's title and summary, then queries
    Meilisearch. Excludes the source entry and any duplicates.
    """
    import re
    from collections import Counter

    # Build a text corpus from title + summary for keyword extraction
    corpus = title or ""
    if summary:
        corpus += " " + summary
    if not corpus.strip() and content_text:
        # Fallback to first 500 chars of content
        corpus = content_text[:500]

    if not corpus.strip():
        return {"hits": [], "estimatedTotalHits": 0, "query": ""}

    # Extract keywords: tokenize, remove stopwords and short words
    stopwords = {
        "the",
        "a",
        "an",
        "and",
        "or",
        "but",
        "in",
        "on",
        "at",
        "to",
        "for",
        "of",
        "with",
        "by",
        "from",
        "is",
        "it",
        "as",
        "be",
        "was",
        "are",
        "were",
        "been",
        "being",
        "have",
        "has",
        "had",
        "do",
        "does",
        "did",
        "will",
        "would",
        "could",
        "should",
        "may",
        "might",
        "shall",
        "can",
        "this",
        "that",
        "these",
        "those",
        "not",
        "no",
        "its",
        "we",
        "our",
        "you",
        "your",
        "they",
        "their",
        "them",
        "he",
        "she",
        "his",
        "her",
        "what",
        "which",
        "who",
        "how",
        "when",
        "where",
        "why",
        "about",
        "all",
        "each",
        "every",
        "both",
        "few",
        "more",
        "most",
        "other",
        "some",
        "such",
        "than",
        "too",
        "very",
        "just",
        "also",
        "into",
        "over",
        "after",
        "before",
        "between",
        "under",
        "new",
        "use",
        "used",
        "using",
        "one",
        "two",
        "get",
        "set",
        "via",
        "see",
        "now",
        "says",
    }
    words = re.findall(r"[a-zA-Z0-9\-]{3,}", corpus.lower())
    # Count word frequency, prefer words that appear in title
    title_words = set(re.findall(r"[a-zA-Z0-9\-]{3,}", (title or "").lower()))
    word_counts: Counter = Counter()
    for w in words:
        if w not in stopwords and not w.isdigit():
            # Boost title words
            word_counts[w] += 3 if w in title_words else 1

    # Take top keywords
    keywords = [w for w, _ in word_counts.most_common(8)]
    if not keywords:
        return {"hits": [], "estimatedTotalHits": 0, "query": ""}

    query = " ".join(keywords)

    try:
        client = _get_client()
        index = client.index(INDEX_NAME)

        exclude_set = set(exclude_ids or [])
        exclude_set.add(entry_id)

        # Fetch extra results to allow for client-side exclusion filtering
        fetch_limit = limit + len(exclude_set) + 5

        params: dict = {
            "limit": fetch_limit,
            "attributesToRetrieve": [
                "id",
                "title",
                "feed_title",
                "feed_id",
                "published_at",
                "summary",
                "author",
                "url",
                "feed_type",
                "media_type",
                "image_url",
                "word_count",
            ],
        }

        if filter:
            params["filter"] = filter
        result = index.search(query, params)

        # Filter out excluded entries client-side
        filtered_hits = [hit for hit in result.get("hits", []) if hit.get("id") not in exclude_set][:limit]

        return {
            "hits": filtered_hits,
            "estimatedTotalHits": len(filtered_hits),
            "query": query,
            "query_keywords": keywords,
        }
    except Exception as e:
        logger.warning("Meilisearch similar-entries search failed: %s", e)
        return {"hits": [], "estimatedTotalHits": 0, "query": "", "query_keywords": []}


def get_facets(
    query: str = "",
    filters: str | None = None,
    viewer_id: str | None = None,
) -> dict:
    """Get facet distribution for search refinement.

    With a `viewer_id`, the `tags` facet includes that user's personal tags.
    """
    try:
        client = _get_client()
        index = client.index(INDEX_NAME)
        params: dict = {
            "limit": 0,
            "facets": viewer_facets(["feed_type", "tags", "media_type", "language"], viewer_id),
        }
        if filters:
            params["filter"] = filters
        result = fold_viewer_tags(index.search(query, params), viewer_id)
        return result.get("facetDistribution", {})
    except Exception as e:
        logger.warning(f"Meilisearch facet query failed: {e}")
        return {}


# Everything about a rule except its body. Doubles as the `metadata` search
# scope, so the box can be pointed at what a rule *is* rather than what it does.
RULE_METADATA_ATTRS = [
    "title",
    "description",
    "tags",
    "mitre_tactics",
    "source_products",
    "source_repo",
    "source_author",
    "techniques",
    "actors",
    "malware",
    "tools",
    "vendors",
    "products",
]

RULE_FACETS = [
    "rule_type",
    "actors",
    "malware",
    "tools",
    "vendors",
    "products",
    "techniques",
    "source_repo",
    "source_author",
    "mitre_tactics",
    # The rail faces the full telemetry need, not just the declared
    # `data_sources` — 8,479 of the corpus leave that column empty and would be
    # untickable. `data_sources` stays filterable for the `data_source=` param.
    "telemetry_tokens",
    "severity",
    "license",
    "tags",
]
# `source_products` stays indexed and searchable but is deliberately not a facet:
# only 15 rules declare it, and the values are raw CPE strings
# ("6bk1602-0aa12-0tp0_firmware"). The Products group uses the entry-derived
# `products` instead, which is the same vocabulary the rest of the app uses.


# Which attributes each search scope looks at. `both` searches everything, so it
# passes no restriction at all rather than an explicit list.
RULE_SEARCH_SCOPES: dict[str, list[str] | None] = {
    "metadata": RULE_METADATA_ATTRS,
    "content": ["rule_content"],
    "both": None,
}


def search_rules(
    query: str = "",
    facet_filters: dict[str, str] | None = None,
    global_filters: list[str] | None = None,
    sort: list[str] | None = None,
    limit: int = 100,
    offset: int = 0,
    facets: list[str] | None = None,
    scope: str = "both",
) -> dict:
    """Search the detection-rule index, returning hits plus facet distribution.

    Uses `page`/`hitsPerPage` rather than `limit`/`offset` so `totalHits` is
    exact — the library header prints the count, and Meili's `estimatedTotalHits`
    is only an estimate once the result set is large.

    Facet counts are *disjunctive*: each facet is counted with every other
    filter applied but not its own. Meilisearch's own facetDistribution is
    conjunctive, which collapses a facet to the single value you just picked —
    selecting "sigma" would hide the other eight rule formats and leave no way
    to switch. So each active facet gets one extra query with its own clause
    dropped, batched into a single multi-search round trip.

    `facet_filters` is keyed by the facet attribute so a clause can be excluded
    from its own count; `global_filters` are clauses with no facet group of
    their own (draft state, provenance, date windows) and always apply.

    Raises on failure rather than returning empty: the caller serves the whole
    rule library from this, and a silent [] would read as "you have no rules".
    """
    facet_filters = facet_filters or {}
    global_filters = global_filters or []
    facets = facets if facets is not None else RULE_FACETS
    search_on = RULE_SEARCH_SCOPES.get(scope)
    client = _get_client()

    def _query(clauses: list[str], facet_names: list[str], rows: int, page: int, sorted_: bool) -> dict:
        q: dict = {
            "indexUid": "rules",
            "q": query,
            "facets": facet_names,
            # Only the id is used — rows are hydrated from Postgres so derived
            # fields (telemetry coverage, linked entries) stay authoritative.
            "attributesToRetrieve": ["id"],
            "hitsPerPage": rows,
            "page": page,
        }
        if clauses:
            q["filter"] = " AND ".join(clauses)
        if sorted_ and sort:
            q["sort"] = sort
        # Applied to the facet sub-queries too — scoping only the main query
        # would make the rail's counts describe a different result set.
        if search_on:
            q["attributesToSearchOn"] = search_on
        return q

    all_clauses = global_filters + list(facet_filters.values())
    active = list(facet_filters)
    queries = [_query(all_clauses, facets, limit, (offset // limit) + 1 if limit else 1, True)]
    # One extra per active facet. hitsPerPage=1 rather than 0: Meilisearch
    # rejects 0, and the hit itself is discarded — only the counts are read.
    for name in active:
        others = global_filters + [c for k, c in facet_filters.items() if k != name]
        queries.append(_query(others, [name], 1, 1, False))

    # Posted directly rather than via client.multi_search(): that helper always
    # sends a `federation` key, which Meilisearch rejects before v1.10.
    results = client.http.post("/multi-search", body={"queries": queries})["results"]
    main = results[0]
    distribution = dict(main.get("facetDistribution") or {})
    for name, extra in zip(active, results[1:], strict=True):
        # Self-excluded count replaces the collapsed one from the main query.
        distribution[name] = (extra.get("facetDistribution") or {}).get(name, {})
    main["facetDistribution"] = distribution
    return main


def rule_facet_values(attribute: str) -> list[str]:
    """Every distinct value of one filterable attribute in the rule index.

    Lets a predicate that can only be evaluated in Python — telemetry
    feasibility, which depends on the live inventory — be pushed down into
    Meilisearch: score the vocabulary here, send the verdict back as a value
    list. One facet-only query, no hits retrieved.
    """
    client = _get_client()
    result = client.index("rules").search("", {"facets": [attribute], "limit": 1, "attributesToRetrieve": ["id"]})
    return list((result.get("facetDistribution") or {}).get(attribute, {}).keys())


def bulk_index_entries(documents: list[dict], retries: int = 5):
    """Bulk index multiple entries with retry for transient connection errors."""
    if not documents:
        return
    for attempt in range(retries):
        try:
            client = _get_client()
            index = client.index(INDEX_NAME)
            index.add_documents(documents)
            return
        except meilisearch.errors.MeilisearchCommunicationError as e:
            if attempt < retries - 1:
                wait = 2**attempt  # 1, 2, 4, 8, 16s
                logger.warning(
                    "Meilisearch unavailable (attempt %d/%d), retrying in %ds",
                    attempt + 1,
                    retries,
                    wait,
                )
                # Reset client so next attempt re-establishes connection
                global _client
                _client = None
                time.sleep(wait)
            else:
                logger.error(
                    "Meilisearch bulk index failed after %d attempts (%d docs dropped): %s",
                    retries,
                    len(documents),
                    e,
                )
        except Exception as e:
            logger.warning("Meilisearch bulk index failed: %s", e)
            return


def rebuild_index() -> bool:
    """Delete and recreate the index (admin operation).

    Waits for Meilisearch to be healthy after deletion before returning,
    so the caller can safely start indexing batches.
    Returns True if the index was successfully recreated.
    """
    global _client

    # Delete the existing index
    try:
        client = _get_client()
        try:
            client.delete_index(INDEX_NAME)
        except meilisearch.errors.MeilisearchApiError:
            pass
    except Exception as e:
        logger.warning("Meilisearch rebuild: could not delete index: %s", e)

    # Reset client and wait for Meilisearch to be ready before recreating
    _client = None
    for attempt in range(10):
        try:
            _get_client()  # Recreates the index via _ensure_index
            logger.info("Meilisearch index recreated and ready")
            return True
        except Exception:
            wait = min(2**attempt, 30)
            logger.warning(
                "Meilisearch not ready after index delete (attempt %d/10), retrying in %ds",
                attempt + 1,
                wait,
            )
            _client = None
            time.sleep(wait)

    logger.error("Meilisearch not available after rebuild — index may be empty")
    return False


# --- Entity Indexes ---


ENTITY_INDEXES = {
    "entities_cve": {
        "searchable": ["cve_id", "description", "severity"],
        "filterable": ["severity", "first_seen_at"],
        "sortable": ["first_seen_at", "cve_id"],
    },
    "entities_ttp": {
        "searchable": ["technique_id", "technique_name", "tactic"],
        "filterable": ["tactic", "first_seen_at"],
        "sortable": ["first_seen_at", "article_count"],
    },
    "entities_threat_actor": {
        "searchable": ["name", "aliases", "country", "motivation"],
        "filterable": ["country", "motivation", "first_seen_at"],
        "sortable": ["first_seen_at", "article_count"],
    },
    "entities_malware": {
        "searchable": ["name", "aliases", "malware_type"],
        "filterable": ["malware_type", "first_seen_at"],
        "sortable": ["first_seen_at", "article_count"],
    },
    "entities_country": {
        "searchable": ["name", "aliases", "iso_code", "region"],
        "filterable": ["region", "iso_code", "first_seen_at"],
        "sortable": ["first_seen_at", "article_count"],
    },
    "entities_sector": {
        "searchable": ["name", "aliases", "slug"],
        "filterable": ["slug", "first_seen_at"],
        "sortable": ["first_seen_at", "article_count"],
    },
    "entities_cwe": {
        # alternate_terms is searchable but never fed to the autolinker — a
        # human typing "use after free" should land on CWE-416; the dictionary
        # scanner matching that phrase in prose is what caused the 2026-07 FP
        # epidemic, so the two paths stay separate on purpose.
        "searchable": ["cwe_id", "name", "alternate_terms", "description"],
        "filterable": ["abstraction", "kind", "mapping_usage", "is_deprecated", "first_seen_at"],
        "sortable": ["first_seen_at", "article_count"],
    },
    "entities_mitigation": {
        "searchable": ["name", "mitre_id", "description", "cis_controls", "nist_controls"],
        "filterable": ["mitre_id", "first_seen_at"],
        "sortable": ["first_seen_at", "article_count"],
    },
    "entities_observable": {
        "searchable": ["value", "label", "role"],
        "filterable": ["kind", "role", "status", "created_via", "infra_tag", "first_seen_at"],
        "sortable": [
            "first_seen_at",
            "last_seen_at",
            "article_count",
            "sighting_count",
            "report_count",
            "current_confidence",
        ],
    },
    "entities_tool": {
        "searchable": ["name", "aliases", "tool_type", "description"],
        "filterable": ["tool_type", "first_seen_at"],
        "sortable": ["first_seen_at", "article_count"],
    },
    # The rule library reads its list AND its facet counts from this index, so
    # every column the rail facets on has to be filterable here — a value that
    # is missing from `filterable` simply returns no distribution, silently.
    # Timestamps are epoch ints, not ISO strings, so range filters and sorts
    # compare numerically.
    "rules": {
        # Order is ranking: Meilisearch weights earlier attributes higher, so a
        # title match beats a body match. rule_content is deliberately last.
        "searchable": RULE_METADATA_ATTRS + ["rule_content"],
        "filterable": [
            "rule_type",
            "severity",
            "is_draft",
            "source_repo",
            "source_author",
            "license",
            "authored_local",
            "mitre_tactics",
            "data_sources",
            # Required telemetry across every rule format (see
            # detection_coverage.telemetry_tokens_from_rule). Filterable, not
            # faceted: the rail's "Data source" group stays on the declared
            # data_sources, while this backs the telemetry feasibility filter.
            "telemetry_tokens",
            "source_products",
            "source_cves",
            "has_cve",
            "techniques",
            "actors",
            "malware",
            "tools",
            "vendors",
            "products",
            "tags",
            "entry_id",
            "created_at",
            "upstream_updated_at",
        ],
        "sortable": [
            "title",
            "rule_type",
            "severity",
            "is_draft",
            "created_at",
            "updated_at",
            "upstream_updated_at",
        ],
        # Meilisearch caps both `totalHits` and paging depth at maxTotalHits
        # (default 1000). The library prints the total and scrolls the whole
        # corpus, so this has to clear the rule count with room to grow —
        # otherwise the header under-reports and infinite scroll dead-ends.
        "max_total_hits": 100_000,
        # Facet values are truncated to maxValuesPerFacet (default 100) *before*
        # the response is built, and `alpha` decides which survive — so the
        # library's Technique facet stopped at T1068 and dropped T1078, its most
        # common technique. Sort by count so truncation keeps the meaningful
        # values, and raise the cap past the widest facet (tags: ~1.9k).
        "max_values_per_facet": 5000,
    },
}


def _ensure_entity_indexes():
    """Create entity indexes if they don't exist."""
    client = _get_client()
    # 2026-08 offensive_tools→tools rename: retire the legacy index so stale
    # docs can't surface in entity search (idempotent; no-op once gone).
    try:
        client.delete_index("entities_offensive_tool")
    except Exception:
        pass
    for index_name, config in ENTITY_INDEXES.items():
        try:
            client.get_index(index_name)
        except meilisearch.errors.MeilisearchApiError:
            client.create_index(index_name, {"primaryKey": "id"})

        index = client.index(index_name)
        index.update_searchable_attributes(config["searchable"])
        index.update_filterable_attributes(config["filterable"])
        index.update_sortable_attributes(config["sortable"])
        if config.get("max_total_hits"):
            index.update_pagination_settings({"maxTotalHits": config["max_total_hits"]})
        if config.get("max_values_per_facet"):
            index.update_faceting_settings(
                {"maxValuesPerFacet": config["max_values_per_facet"], "sortFacetValuesBy": {"*": "count"}}
            )


def index_entity(index_name: str, doc: dict):
    """Index a single entity document."""
    try:
        client = _get_client()
        index = client.index(index_name)
        index.add_documents([doc])
    except Exception as e:
        logger.warning("Failed to index entity in %s: %s", index_name, e)


def delete_entity(index_name: str, doc_id: str):
    """Remove a single entity document from an entity index (best effort)."""
    try:
        client = _get_client()
        client.index(index_name).delete_document(doc_id)
    except Exception as e:
        logger.warning("Failed to delete entity %s from %s: %s", doc_id, index_name, e)


def bulk_index_entities(index_name: str, documents: list[dict], retries: int = 5):
    """Bulk index entities into a specific index with retry for transient errors."""
    if not documents:
        return
    for attempt in range(retries):
        try:
            client = _get_client()
            index = client.index(index_name)
            for i in range(0, len(documents), 1000):
                batch = documents[i : i + 1000]
                index.add_documents(batch)
            return
        except meilisearch.errors.MeilisearchCommunicationError as e:
            if attempt < retries - 1:
                wait = 2**attempt
                logger.warning(
                    "Meilisearch unavailable for %s (attempt %d/%d), retrying in %ds",
                    index_name,
                    attempt + 1,
                    retries,
                    wait,
                )
                global _client
                _client = None
                time.sleep(wait)
            else:
                logger.error(
                    "Failed to bulk index entities in %s after %d attempts (%d docs): %s",
                    index_name,
                    retries,
                    len(documents),
                    e,
                )
        except Exception as e:
            logger.warning("Failed to bulk index entities in %s: %s", index_name, e)
            return


def search_entities(
    index_name: str,
    query: str,
    filters: str | None = None,
    sort: list[str] | None = None,
    limit: int = 20,
    offset: int = 0,
) -> dict:
    """Search entities in a specific entity index."""
    try:
        client = _get_client()
        index = client.index(index_name)
        params: dict = {
            "limit": limit,
            "offset": offset,
            "showMatchesPosition": True,
            "attributesToHighlight": ["*"],
            "highlightPreTag": "<mark>",
            "highlightPostTag": "</mark>",
        }
        if filters:
            params["filter"] = filters
        if sort:
            params["sort"] = sort
        return index.search(query, params)
    except Exception as e:
        logger.warning("Meilisearch entity search failed on %s: %s", index_name, e)
        return {"hits": [], "estimatedTotalHits": 0, "processingTimeMs": 0}


def rebuild_entity_indexes():
    """Delete and recreate all entity indexes."""
    try:
        client = _get_client()
        for index_name in ENTITY_INDEXES:
            try:
                client.delete_index(index_name)
            except meilisearch.errors.MeilisearchApiError:
                pass
        _ensure_entity_indexes()
    except Exception as e:
        logger.warning("Meilisearch entity index rebuild failed: %s", e)
