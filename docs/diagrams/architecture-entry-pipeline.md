# Entry Processing Pipeline

What happens to a new article after it is saved. `dispatch_entry_pipeline()` (`backend/app/workers/feed_tasks.py`) builds a Celery chord from the stage list in `backend/app/pipeline/registry.py`. Referenced from [architecture.md](../architecture.md#stage-6-task-fan-out).

```mermaid
flowchart TD
    FETCH["fetch_feed worker<br/>(inline stages: sanitize, dedup,<br/>relevance, index)"] --> NEW["New entry saved"]

    NEW --> TR{"feed.auto_translate?"}
    TR -- yes --> TRANSLATE["pre: translate_entry_task<br/>(runs first, never raises)"]
    TR -- no --> HDR
    TRANSLATE --> HDR

    subgraph HDR["Chord header: parallel stages"]
        AUTOLINK["autolink<br/>autolink_entry_task"]
        OBSERV["observables<br/>observables_entry_task<br/>(mark candidates, sight known values)"]
        TGLINKS["telegram_links<br/>scan_telegram_links_task"]
        EXTRACT["extract<br/>extract_entry_intel_task<br/>(off unless the feed or plan turns it on)"]
    end

    HDR --> CB["Callback: entry_post_processing"]

    subgraph POST["Post stages"]
        COOC["cooccurrence<br/>create_cooccurrence_relationships_task<br/>(EntityRelationship edges)"]
        CORR["correlation<br/>detect_correlation_events"]
        REQ["requirements<br/>match_requirements_task<br/>(keyword + linked-entity PIR matching)"]
    end

    CB --> POST
    POST --> FINAL["final: score_entry_task<br/>signal scoring, then queue<br/>one-pass AI analysis"]
    FINAL -. "minutes to hours later, ai queue" .-> ADJ["post_analysis: adjudicate_entry_task<br/>(AI review of what the analysis wrote)"]

    NEW -. "side: dispatched by fetch_feed" .-> AUTO["run_entry_automations"]
    NEW -. "side: when a new entity is created" .-> ENRICH["auto_enrich_entity"]
```

When pipeline plans are on (`pipeline_engine_enabled`), `PipelinePlan` rows (feed, then category, then global) decide which parallel stages run. Otherwise `feed_runs_extraction()` decides the `extract` stage from the feed's `auto_extract_on_ingest` and `extract_detection_rules` switches.
