# Query Routing Flow

How a unified search query travels from the search bar to results. Referenced from
[docs/query-language.md](../query-language.md) ("How Queries Route").

```mermaid
flowchart TD
    Q["Query string<br/>e.g. threat_actor:APT29 signal:kev_added is:unread"] --> P["parse_query()<br/>backend/app/search/query_parser.py<br/>→ AST (text / field / bool / not)"]
    P --> PL["build_execution_plan()<br/>backend/app/search/query_planner.py<br/>classifies each field into one of three lanes"]

    PL -->|"bare text, title:, content:, author:"| MQ["Meilisearch query string"]
    PL -->|"tag:, type:, media:, lang:, words:, date:,<br/>is:starred/read/unread/bookmarked/noted"| MF["Meilisearch filter clauses"]
    PL -->|"feed:"| FR["resolve_deferred_filters()<br/>feed name → feed_id clauses"]
    PL -->|"category:, signal:, sector:, url:, feed.reliability:,<br/>feed.timeliness:, feed.relevance:,<br/>is:muted / translated / image"| ER["resolve_deferred_filters()<br/>PostgreSQL"]
    PL -->|"cve:, threat_actor:, ttp:, malware:, country:, tool:,<br/>vendor:, product:, mitigation:, campaign:,<br/>ransomware_victim:, rule:, intel_report:, pir:, note:<br/>(+ dotted sub-fields)"| EG["Entity filter groups"]
    PL -->|"sort:"| S["Sort (relevance / newest / oldest /<br/>title_asc / title_desc / shortest / longest / radar)"]

    FR --> MF
    ER -->|"feed-scoped kinds → feed_id clauses"| MF
    ER -->|"entry-scoped kinds → plan.db_entry_ids"| IX["Intersect entry-ID sets"]
    EG --> PG["execute_entity_queries()<br/>backend/app/search/entity_builder.py<br/>PostgreSQL entity + junction tables<br/>→ entities + linked entry IDs"]
    PG -->|"AND join"| IX

    MQ --> MS["execute_entry_search()<br/>backend/app/search/meili_builder.py"]
    MF --> MS
    S --> MS
    IX -->|"≤ 800 IDs and something to search"| MS

    IX -.->|"entity-only, no indexed filter,<br/>or > 800 IDs"| PGF["_fetch_entries_by_ids()<br/>PostgreSQL — bypasses Meilisearch<br/>exact counts"]
    S -.->|"sort:radar → priority_score<br/>(not in the index)"| PGF

    MS --> R["Unified response<br/>entry hits + facetDistribution<br/>+ entity items (match_kind, trimmed per type)<br/>+ untrimmed entity counts + parsed filter chips"]
    PGF --> R
```

Three lanes, not two: indexed entry fields go to Meilisearch, entity fields go to the
entity tables, and a middle group (`category:`, `signal:`, `sector:`, `url:`, feed
grades, `is:muted/translated/image`) is answered from PostgreSQL because those columns
are not in the search index and adding them would mean re-indexing every document.

Feed-scoped PostgreSQL filters resolve to a few hundred feed IDs and become ordinary
Meilisearch clauses. Entry-scoped ones resolve to a set of entry IDs that intersects
with the entity join — one `IN` list instead of thousands of OR clauses.

Join semantics: entity results constrain entry results (AND) by default; an `OR`
between an entry predicate and an entity predicate switches the plan to OR mode,
returning the union instead.

Negation of an entry-scoped PostgreSQL filter is subtractive only — the complement is
every other entry, which is unbounded — so it removes matches from a positive set and
does nothing on its own.
