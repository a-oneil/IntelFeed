# Entry Processing Pipeline

Chord structure built by `dispatch_entry_pipeline()` (`backend/app/workers/feed_tasks.py`) from the stage registry in `backend/app/pipeline/registry.py`. Referenced from [architecture.md](../architecture.md#stage-6-task-fan-out).

```mermaid
flowchart TD
    FETCH["fetch_feed worker<br/>(inline stages: sanitize, dedup,<br/>relevance, index)"] --> NEW["New entry persisted"]

    NEW --> TR{"feed.auto_translate?"}
    TR -- yes --> TRANSLATE["pre: translate_entry_task<br/>(chained prologue, never raises)"]
    TR -- no --> HDR
    TRANSLATE --> HDR

    subgraph HDR["Chord header — parallel stages"]
        AUTOLINK["autolink<br/>autolink_entry_task"]
        OBSERV["observables<br/>observables_entry_task<br/>(stage candidates, sight known values)"]
        TGLINKS["telegram_links<br/>scan_telegram_links_task"]
        EXTRACT["extract<br/>extract_entry_intel_task<br/>(default off; per-feed / PipelinePlan)"]
    end

    HDR --> CB["Callback: entry_post_processing"]

    subgraph POST["Post stages"]
        COOC["cooccurrence<br/>create_cooccurrence_relationships_task<br/>→ typed EntityRelationship edges"]
        CORR["correlation<br/>detect_correlation_events"]
        REQ["requirements<br/>match_requirements_task<br/>(keyword + linked-entity PIR matching)"]
    end

    CB --> POST
    POST --> FINAL["final: score<br/>signal scoring + one-pass<br/>AI analysis enqueue"]

    NEW -. "side (independent of chord)" .-> AUTO["run_entry_automations<br/>+ keyword alerts"]
```

Stage composition is data-driven: `PipelinePlan` rows (feed > category > global) decide which parallel stages run when the pipeline engine is enabled; otherwise the legacy `feed.auto_extract_on_ingest` boolean gates the `extract` stage.
