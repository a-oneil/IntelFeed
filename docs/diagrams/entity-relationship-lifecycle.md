# Entity Relationship Lifecycle

For analysts and developers working with typed relationships (`/api/entity-relationships`). It shows how an edge's `source` (who asserted it) changes over its life. Confidence (`confirmed` > `probable` > `possible`) moves separately, except that confirming an edge also sets its confidence to `confirmed`.

```mermaid
stateDiagram-v2
    [*] --> co_occurrence : co-occurrence engine\n(starts at possible)
    [*] --> auto_extracted : AI extraction,\nTelegram forwards
    [*] --> analyst_created : POST /entity-relationships
    [*] --> external_feed : MITRE ATT&CK import\n(confidence confirmed)
    [*] --> enrichment : enrichment source relation claim\n(confidence probable)

    co_occurrence --> analyst_confirmed : POST {id}/confirm\n(confidence → confirmed)
    co_occurrence --> analyst_rejected : POST {id}/reject
    auto_extracted --> analyst_confirmed : POST {id}/confirm\n(confidence → confirmed)
    auto_extracted --> analyst_rejected : POST {id}/reject
    analyst_created --> analyst_confirmed : POST {id}/confirm
    analyst_created --> analyst_rejected : POST {id}/reject
    analyst_confirmed --> analyst_rejected : POST {id}/reject

    enrichment --> [*] : last claim withdrawn

    analyst_rejected --> analyst_created : POST /entity-relationships\n(an explicit re-create brings it back)

    note right of analyst_rejected
        Hidden from pivots, graphs and lists.
        The engine never adds evidence to it.
        The row stays so new articles can't recreate the pair.
    end note

    note right of co_occurrence
        New articles add to evidence_entry_ids
        instead of creating a second row.
        Drawn only from articles the adjudicate stage reviews.
        Each article's review and the edge sweep write
        relationship_reviews rows; the verdict follows from them:
        kept (a review found it stated),
        corroborated (kept by 2+ feeds → confirmed),
        disputed (articles disagree, stays in Review),
        coincidental (→ possible, hidden from pivots and graphs).
    end note
```

Every write path (co-occurrence, AI extraction, copilot tools, the REST API) checks the `(source_type, verb, target_type)` triple against the allowlist in `backend/app/intelligence/relationship_matrix.py`. An assertion written the wrong way round is flipped to the allowed direction.

Referenced from [`docs/api-reference.md`](../api-reference.md) (Entity Relationships section).
