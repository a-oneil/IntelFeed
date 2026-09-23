# Entity Relationship Lifecycle

Provenance (`source`) lifecycle for typed entity relationships (`/api/entity-relationships`). Confidence tiers (`confirmed` > `probable` > `possible`) are orthogonal, except that confirming forces `confidence: confirmed`.

```mermaid
stateDiagram-v2
    [*] --> auto_extracted : co-occurrence engine
    [*] --> analyst_created : POST /entity-relationships
    [*] --> external_feed : MITRE ATT&CK import\n(confidence confirmed)

    auto_extracted --> analyst_confirmed : POST {id}/confirm\n(confidence → confirmed)
    auto_extracted --> analyst_rejected : POST {id}/reject
    analyst_created --> analyst_confirmed : POST {id}/confirm
    analyst_created --> analyst_rejected : POST {id}/reject
    analyst_confirmed --> analyst_rejected : POST {id}/reject

    analyst_rejected --> analyst_created : POST /entity-relationships\n(explicit re-create resurrects)

    note right of analyst_rejected
        Tombstone: hidden from pivot/graph/list,
        engine never accumulates evidence on it.
        Row kept so re-ingestion can't recreate the pair.
    end note

    note right of auto_extracted
        Re-ingestion merges evidence_entry_ids
        instead of duplicating the row.
        Nightly AI adjudication stamps
        adjudication_verdict: corroborated
        (confidence → confirmed) or coincidental
        (→ possible, never re-promoted).
    end note
```

All write paths (co-occurrence, AI extraction, copilot tools, the REST API) validate the `(source_type, verb, target_type)` triple against the semantic allowlist in `backend/app/intelligence/relationship_matrix.py`; reversed assertions are flipped to the allowed orientation.

Referenced from [`docs/api-reference.md`](../api-reference.md) (Entity Relationships section).
