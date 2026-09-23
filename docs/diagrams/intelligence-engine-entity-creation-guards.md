# Entity creation guards: resolver gates, junk-alias filtering and cross-type resurrection suppression

```mermaid
flowchart TD
    subgraph sources [Automated entity sources]
        AI["AI extraction<br/>intelligence/enrichment.py"]
        CG["Cybergeist sync<br/>intelligence/external_feeds.py"]
        MP["Malpedia sync<br/>workers/enrichment_tasks.py"]
    end

    AI --> RES["resolve_entity_creation()<br/>intelligence/entity_resolution.py<br/>every decision logged to EntityMaintenanceLog"]
    CG --> RES
    RES --> FP{"is_fp_entity_name() or<br/>entity_name_denylist hit?<br/>FP name set + *.exe/*.dll/*.sys"}
    FP -- yes --> DROP1["blocked — skip creation<br/>(entity_creation_gates: off / shadow / on,<br/>default shadow = log + still create)"]
    FP -- no --> TOMB{"find_reclassify_tombstone()<br/>(source_type, normalized_name) active?"}
    TOMB -- hit --> LINK["link_entry_to_entity()<br/>idempotent junction insert to<br/>surviving (target_type, target_id)"]
    TOMB -- miss --> DEDUP["Normalized exact match via<br/>entity_alias_index +<br/>find_entity_by_name_or_alias()"]
    DEDUP -- found --> MERGE[Update existing entity]
    DEDUP -- "candidate only<br/>(stripped / fuzzy)" --> HELD["held — advisory logged,<br/>never auto-merged"]
    DEDUP -- not found --> CREATE[Create new entity]

    MERGE --> ALIAS{"is_junk_alias()?<br/>per incoming alias"}
    MP --> FILT["filter_aliases()<br/>drop junk + dedupe"]
    ALIAS -- junk --> DROP2[Alias discarded]
    ALIAS -- clean --> STORE[Alias merged into aliases array]
    FILT --> STORE

    RECLASS["Cross-type reclassify / convert<br/>api/entity_merge.py · /entities/convert"] -- "writes one row per folded name/alias" --> TSTONE[("entity_reclassify_tombstones")]
    TSTONE -.-> TOMB

    MANUAL["Manual creation (UI)"] -- "not gated (trusted)" --> CREATE
```

Notes:
- Vendor, Product, Tool, and Mitigation names deliberately bypass the FP name set in the autolinker vocabulary so legitimate vendors (e.g. Norton) still match.
- Same-type merges already survive re-import via the survivor's `aliases` array; tombstones only close the cross-type gap.
- Set `active=False` on a tombstone row to re-allow a deliberate split later.
- `entity_creation_gates` lives in system_settings: `shadow` logs the would-block/would-hold decision and still creates; `on` enforces it.
