# Entity creation guards: resolver gates, junk-alias filtering and cross-type resurrection suppression

The checks a new entity name passes, in order, before `resolve_entity_creation()` lets a row be created: duplicate matching, reclassify tombstones, the always-on junk blocks, the switchable gates, and alias filtering.

```mermaid
flowchart TD
    subgraph sources [Entity sources]
        AI["AI extraction<br/>intelligence/enrichment.py"]
        CG["Cybergeist sync<br/>intelligence/external_feeds.py"]
        CLI["Tool registry write tools<br/>tools/write.py"]
        MANUAL["Manual creation (UI)<br/>api/entity_profiles.py"]
        MP["Malpedia sync<br/>workers/enrichment_tasks.py"]
    end

    AI --> RES["resolve_entity_creation()<br/>intelligence/entity_resolution.py<br/>every decision logged to EntityMaintenanceLog"]
    CG --> RES
    CLI --> RES
    MANUAL --> RES

    RES --> MATCH{"Existing entity?<br/>exact name/alias, then normalized<br/>match via entity_alias_index,<br/>then known actor synonyms"}
    MATCH -- found --> MERGE[Use existing entity]
    MATCH -- no --> TOMB{"find_reclassify_tombstone()<br/>(source_type, normalized_name) active?"}
    TOMB -- hit --> LINK["link_entry_to_entity()<br/>idempotent junction insert to<br/>surviving (target_type, target_id)"]
    TOMB -- miss --> JUNK{"Always-on blocks:<br/>is_fp_entity_name() (automated sources),<br/>do-not-recreate denylist,<br/>CVE id as a name, concept terms"}
    JUNK -- hit --> DROP1["blocked — skip creation"]
    JUNK -- clear --> GATES{"Creation gates<br/>(entity_creation_gates: off / shadow / on,<br/>default on)"}
    GATES -- "would block, mode on" --> DROP1
    GATES -- "clear, or shadow (logged)" --> CAND{"Stripped / fuzzy<br/>candidate match?"}
    CAND -- yes --> HELD["held — advisory logged,<br/>never auto-merged"]
    CAND -- no --> CREATE[Create new entity]

    MANUAL -. "force=true overrides a gate" .-> CREATE

    MERGE --> ALIAS{"is_junk_alias()?<br/>per incoming alias"}
    MP --> FILT["filter_aliases()<br/>drop junk + dedupe"]
    ALIAS -- junk --> DROP2[Alias discarded]
    ALIAS -- clean --> STORE[Alias merged into aliases array]
    FILT --> STORE

    RECLASS["Cross-type reclassify / convert<br/>api/entity_merge.py · /entities/convert"] -- "writes one row per folded name/alias" --> TSTONE[("entity_reclassify_tombstones")]
    TSTONE -.-> TOMB
```

Notes:
- Vendor, Product, Tool, and Mitigation names skip the false-positive name set in the autolinker vocabulary, so real vendors (such as Norton) still match.
- Same-type merges survive re-import through the survivor's `aliases` array; tombstones cover the cross-type case.
- Set `active=False` on a tombstone row to allow a deliberate split later.
- A manual create that a check refuses returns `entity_creation_gated`; retrying with `force=true` creates it anyway and logs the override.
