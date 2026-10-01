# Workers, Search, and Dashboards

A comprehensive guide to the asynchronous task execution layer, full-text search system, and customizable dashboard framework.

## Table of Contents

1. [Worker Architecture](#worker-architecture)
2. [Meilisearch Integration](#meilisearch-integration)
3. [Dashboards & Widgets](#dashboards--widgets)

---

## Worker Architecture

IntelFeed uses **Celery 5 + Redis** to handle background workloads at scale: feed polling, entity enrichment, intelligence extraction, automation rule execution, report generation, and maintenance tasks. The system is designed for horizontal scaling with careful attention to resource cleanup and distributed coordination.

### Celery App Configuration

**File:** `backend/app/workers/celery_app.py` (lines 13-52)

```python
celery_app = Celery(
    "intelfeed",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=[
        "app.workers.feed_tasks",
        "app.workers.maintenance",
        # ... task modules ...
    ],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    beat_schedule=build_beat_schedule(),
    worker_hijack_root_logger=False,
)
```

**Key Configuration:**
- **Broker & Backend:** Both use the same Redis instance (`settings.redis_url`). The broker is the task queue; the backend stores task results. `result_expires=3600` caps result-backend retention so results can't accumulate to Redis maxmemory.
- **Serializer:** JSON for broad language compatibility and debugging.
- **Logging:** Celery's root logger is disabled (`worker_hijack_root_logger=False`) to allow structlog integration (via `setup_logging()`).
- **Beat Schedule:** Built dynamically from the job registry (see [Beat Schedule](#beat-schedule-and-runtime-overrides)).
- **Queue Routing:** `task_default_queue="celery"`, plus `task_routes` pinning every Claude Code CLI-invoking task to the dedicated `ai` queue (a worker with `--concurrency=1`, to avoid OAuth-session corruption and respect rate limits): the link-validation tasks, entity-maintenance tasks (`process_merge_candidate`, `refresh_actor_profile`, `process_name_normalization_batch`, `ai_enrich_gap_batch`), `review_hygiene_proposal_batch`, `adjudicate_relationship_batch`, `run_copilot_stream`, and the copilot auth tasks. Any new CLI-calling task must be routed here — the default worker has no CLI credentials.

### Per-Worker Async Pattern and Connection Management

**File:** `backend/app/workers/db.py` (lines 20-57)

IntelFeed keeps a **persistent per-process event loop** and creates/disposes **short-lived database engines per task**. This design prevents both connection pool exhaustion and "Event loop is closed" errors in Celery's prefork pool.

```python
_local = threading.local()

def run_async(coro):
    """Run an async coroutine using a persistent per-process event loop."""
    loop = getattr(_local, "loop", None)
    if loop is None or loop.is_closed():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        _local.loop = loop
    return loop.run_until_complete(coro)

@asynccontextmanager
async def worker_session():
    """Create a short-lived engine + session for a single worker task."""
    engine = create_async_engine(
        settings.database_url,
        pool_size=settings.worker_db_pool_size,
        max_overflow=settings.worker_db_max_overflow,
        pool_pre_ping=True,
        pool_recycle=1800,
    )
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    try:
        async with session_factory() as session:
            yield session
    finally:
        await engine.dispose()
```

**Why This Pattern:**
- The event loop is thread-local and created once per forked worker process, avoiding "Event loop is closed" errors.
- Each task calls `worker_session()` to create a fresh database engine with a small pool, ensuring that connections are properly cleaned up via `engine.dispose()` after the task completes.
- `pool_pre_ping=True` detects stale connections; `pool_recycle=1800` (30 min) closes old connections.
- Settings `worker_db_pool_size` and `worker_db_max_overflow` are typically small (e.g., 3 and 1) to avoid exhausting the database.

### Task Catalog and Schedules

**File:** `backend/app/workers/job_registry.py:44`

The `JOB_REGISTRY` is a declarative map of all **70** scheduled tasks, each with a default cadence, a category, and (where relevant) the `settings_keys` that govern it — which is how the Jobs browse screen shows a job's settings inline. Celery beat reads this and dispatches tasks on schedule. Every setting named there is documented in [engine-settings.md](engine-settings.md#setting--scheduled-job).

#### Feed Polling & Health

| Task | Default Schedule | Purpose |
|------|------------------|---------|
| `poll_due_feeds` | Every 60 seconds | Check feeds due for polling, dispatch fetch tasks |
| `check_feed_health` | Every 6 hours at :30 (00:30, 06:30, 12:30, 18:30 UTC) | Detect stale feeds, persistent fetch errors |

**Feed polling** works via an NX lock in Redis to prevent multiple workers polling the same feed simultaneously (`_poll_due_feeds()` in `feed_tasks.py`, line 179).

#### Intelligence Feeds & Entity Auto-Linking

| Task | Default Schedule | Purpose |
|------|------------------|---------|
| `sync_kev_feed` | Every 6 hours at :15 | Sync CISA Known Exploited Vulnerabilities |
| `sync_cybergeist_feeds` | Daily at 02:30 UTC | Sync threat actor and malware feeds |
| `sync_ransomware_victims` | Every 30 minutes | Collect ransomware leak-site victim postings into structured records |
| `refresh_autolinker_vocabulary` | Every 30 minutes | Rebuild Aho-Corasick automaton for entity matching |
| `rebuild_entity_profiles` | Daily at 03:30 UTC | Reconstruct entity correlation profiles |
| `archive_correlation_events` | Daily at 04:45 UTC | Archive old/processed correlation events |
| `check_requirement_expiry_task` | Daily at 00:30 UTC | Check intelligence requirement expiry |
| `build_telegram_forward_relationships` | Every 4 hours at :20 | Derive actor-to-actor 'communicates_with' edges |
| `embed_pending_entries` | Every 15 minutes | Embed entries with no current vector (newest first) — the substrate for story threads and "more like this". No-op until `embeddings_enabled` |
| `rebuild_story_threads` | Every 30 minutes | Group embedded entries into story threads: join, seed, fold echoes, merge split threads, prune threads whose articles are gone |
| `narrate_story_threads` | Daily at 06:10 UTC | Write the AI spine for threads that still need one — never narrated, or changed since they were (AI, `ai` queue) |
| `kickoff_actor_profile_refresh` | Weekly Monday at 03:00 UTC | Claude-Code refresh of top-N threat actor profile descriptions (AI) |
| `submit_analysis_batches` | Every 30 minutes | Submit pending entries to one-pass AI analysis batch (priority-ordered, budget-capped) |
| `poll_analysis_batches` | Every 10 minutes | Ingest completed AI analysis batches (results, entity links, costs) |
| `recompute_signal_rates` | Daily at 04:20 UTC | Recompute 30-day signal firing rates for IDF self-tuning weights |
| `rescore_recent_entries` | Every 6 hours at :35 | Re-score recent entries so KEV/EPSS changes propagate to priority scores |
| `rescore_all_entries` | Weekly Sunday at 03:00 UTC | Full rescore of every scored entry — heals stored signals/explanations; also dispatchable via the Run now button |
| `fit_user_signal_weights` | Daily at 04:35 UTC | Fit per-analyst Radar signal weights from each user's own thumbs (behind `radar_personalization_enabled`) |
| `refresh_cwe_catalog` | Weekly Monday at 03:45 UTC | Re-pull the MITRE CWE catalog and re-resolve unmatched NVD weakness refs |
| `kickoff_assessment_backfill` | Daily at 05:45 UTC | Draft AI assessments for entities with linked reporting but no description, and re-write its own once enough new reporting makes them stale. Never overwrites text it did not write; skips CVEs, whose descriptions come from NVD (AI) |
| `rank_threat_board` | Daily at 04:20 UTC | Recompute the Threats ranking; reopen handled threats that have new tradecraft |
| `promote_watchlist_threats` | Daily at 04:30 UTC | Pin watched actors/malware with window activity onto the Threats board as tracked |
| `generate_threat_briefs` | Daily at 04:40 UTC | Write the two-sentence story line for each open Threats and vulnerability row from its window's articles (AI) |

**Vocab Versioning:** When `sync_cybergeist_feeds` creates new entities (see line 74-76 in `intel_feed_tasks.py`), it triggers `refresh_autolinker_vocabulary.delay()` with a 30-second countdown and optionally `rescan_recent_entries.apply_async(countdown=30)`. This ensures the auto-linker vocabulary is refreshed before entries are rescanned.

#### Enrichment (EPSS, MITRE ATT&CK, PoC)

| Task | Default Schedule | Purpose |
|------|------------------|---------|
| `run_scheduled_enrichment` | Every 15 minutes | Execute scheduled enrichment source syncs |
| `run_epss_bulk_sync` | Daily at 06:30 UTC | Update all CVEs with EPSS scores |
| `run_mitre_attack_sync` | Weekly Sunday at 03:00 UTC | Sync MITRE ATT&CK techniques, groups, and mitigations |
| `run_misp_galaxy_sync` | Weekly Sunday at 03:30 UTC | Refresh reference alias knowledge (`known_alias_map`) from the MISP Galaxy threat-actor cluster |
| `run_malpedia_sync` | Weekly Sunday at 03:30 UTC | Sync malware families (aliases pass the junk-alias filter, `filter_aliases()`) |
| `run_cve_nvd_refresh` | Daily at 12:00 UTC | Re-check NVD for CVSS score changes |
| `run_cve_nvd_backfill` | Daily at 01:30 UTC | Backfill NVD data (CVSS, description, products, references) for CVEs missing it |
| `run_github_poc_scan` | Daily at 05:00 UTC | Scan GitHub for PoC exploits |
| `run_wikipedia_bulk_sync` | Weekly Wednesday at 04:00 UTC | Enrich entities with Wikipedia content |
| `run_metasploit_sync` | Weekly Sunday at 03:45 UTC | Map tracked CVEs to Metasploit modules and escalate weaponized exploit status |

#### Maintenance & Housekeeping

| Task | Default Schedule | Purpose |
|------|------------------|---------|
| `cleanup_expired_entries` | Daily at 02:05 UTC | Delete entries older than retention policy |
| `reenrich_cve_nvd` | Daily at 03:05 UTC | Re-fetch NVD data for CVEs missing it (bulk-imported or awaiting NVD analysis) |
| `resolve_cve_affected` | Daily at 03:35 UTC | Re-resolve unmatched `cve_affected` CPE pairs against current vendor/product entities |
| `evict_image_cache` | Daily at 04:10 UTC | Delete cached images past TTL |
| `evict_tts_cache` | Daily at 04:15 UTC | Evict server-side read-aloud (Piper) audio past TTL or over the size cap |
| `cleanup_telegram_media` | Weekly Sunday at 04:20 UTC | Prune Telegram media whose parent entry is deleted |
| `evict_old_telegram_media` | Daily at 04:25 UTC | Delete Telegram media files older than the configured TTL (entries/intel kept) |
| `backup_database` | Daily at 02:00 UTC | Run pg_dump with gzip compression |
| `refresh_correlation_cache` | Every 15 minutes | Pre-warm correlation cache |
| `sync_entity_search_indexes` | Every 4 hours at :45 | Sync intelligence entities to Meilisearch |
| `retry_failed_indexing` | Every 5 minutes | Re-index entries that failed Meilisearch indexing |
| `reconcile_meilisearch` | Daily at 07:15 UTC | Detect and repair PostgreSQL ↔ Meilisearch drift |
| `cleanup_orphaned_references` | Daily at 03:15 UTC | Remove references to deleted entities |
| `decay_relationship_confidence` | Weekly Sunday at 03:45 UTC | Demote stale co-occurrence relationships from probable to possible |
| `validate_entity_links` | Daily at 04:00 UTC | Re-validate autolinker entity links with Claude Code; flag/remove out-of-context links (AI) |
| `kickoff_entity_merge_maintenance` | Weekly Sunday at 03:00 UTC | Find duplicates/misclassifications across entity types; merge or reclassify via Claude Code (AI, shadow by default) |
| `review_hygiene_proposals` | Daily at 05:30 UTC | AI-review pending hygiene proposals (reclassify/merge/rename/alias trim/vendor link/id fix); verdicts gate bulk apply (AI) |
| `adjudicate_relationships` | Daily at 06:30 UTC | AI-adjudicate probable relationship edges from evidence headlines; corroborated → confirmed, coincidental demoted (behind `relationship_adjudication_enabled`) (AI) |
| `retry_untranslated_entries` | Every 30 minutes | Backfill translations missed while the LibreTranslate sidecar was off (auto-translate feeds) |
| `refresh_claude_auth_status` | Every 30 minutes | Refresh copilot Claude Code OAuth credential health snapshot |
| `flag_stale_entities` | Weekly Sunday at 05:30 UTC | Flag entities with ≤1 article, no relationships, 90+ days idle (never deletes) |
| `prune_engine_tables` | Daily at 02:40 UTC | Delete engine bookkeeping rows older than 30 days (job_runs, …) |
| `decay_observable_confidence` | Daily at 02:20 UTC | Nightly confidence decay and lifecycle transitions for the observables ledger |
| `reconcile_observable_counters` | Daily at 02:50 UTC | Recount observable sighting/article counters from the junction — deletion cascades drift them |
| `retro_sight_observables` | Every 6 hours at :40 | Exact-string retro-sighting of recently confirmed observables across the corpus |
| `rebuild_rule_coverage` | Daily at 03:50 UTC | Re-resolve detection rules to the CVEs, techniques and actors they cover (`rule_coverage`) |
| `backfill_rule_attack_mappings` | Weekly Sunday at 05:30 UTC | Re-fetch GitHub-sourced rules to recover ATT&CK mappings, and derive tactics from techniques |
| `backfill_rule_data_sources` | Weekly Sunday at 04:50 UTC | Derive detection-rule `data_sources` from stored log sources, for telemetry coverage |
| `rollup_targeted_sectors` | Daily at 04:20 UTC | Derive actor/malware target-sector claims (`source=rollup`, with article evidence) from the victim sectors on their articles; rebuild the `targeted_sectors` cache |

#### Automation & Saved Searches

| Task | Default Schedule | Purpose |
|------|------------------|---------|
| `run_scheduled_automations` | Every 60 seconds | Evaluate on_schedule automation rules |
| `refresh_saved_search_counts` | Every 5 minutes | Refresh match counts and dispatch alerts |
| `sync_campaign_saved_searches` | Every 5 minutes | Auto-sync campaign searches and add entries |
| `sync_campaign_sources` | Every 15 minutes | Pull in articles for the entities and stories each campaign follows (`campaign_sources`) |

#### Content Generation

| Task | Default Schedule | Purpose |
|------|------------------|---------|
| `generate_reddit_digest` | Daily at 07:00 UTC | Generate AI digest of top Reddit security posts |
| `generate_daily_summaries` | Daily at 06:00 UTC | Pre-generate yesterday's shared Triage daily-divider summary (AI) |

### Beat Schedule and Runtime Overrides

**File:** `backend/app/workers/job_registry.py:789` (`build_beat_schedule`)

The beat schedule is built at worker startup via `build_beat_schedule()`, which applies any overrides from Redis:

```python
def build_beat_schedule(overrides: dict[str, Any] | None = None) -> dict:
    """Build celery beat schedule, applying any overrides."""
    if overrides is None:
        overrides = read_overrides_from_redis()
    
    schedule = {}
    for name, job in JOB_REGISTRY.items():
        override = overrides.get(name, {})
        
        if override.get("enabled") is False:
            continue
        
        sched = override.get("schedule") or job["default_schedule"]
        schedule[name] = {
            "task": job["task"],
            "schedule": schedule_dict_to_celery(sched),
        }
    
    return schedule
```

**Override Storage:** The `JobSchedules.tsx` frontend component allows runtime cadence changes (e.g., changing "poll-feeds" from 60 seconds to 120 seconds). These are persisted in Redis at key `intelfeed:job_schedule_overrides` and applied on the next beat worker restart or via `celery_app.conf.update()`.

**Helper Functions:**
- `schedule_to_human(sched)` (line 337): Converts schedule dicts to human-readable strings ("Every 30 minutes", "Daily at 7:00 AM").
- `schedule_dict_to_celery(sched)` (line 389): Converts dicts to Celery schedule objects (`float` for intervals, `crontab()` for cron expressions).

### Task Time Limits and Retries

Each task is decorated with:
- **`soft_time_limit`:** Graceful timeout; task can catch `SoftTimeLimitExceeded` and cleanup.
- **`time_limit`:** Hard timeout; worker kills the task if it exceeds.
- **`max_retries`:** Number of automatic retries on failure (e.g., `max_retries=2` for `run_entry_automations`).
- **`bind=True`:** Provides `self` (the task instance) for access to retry logic.

Example from `automation_tasks.py`, line 27-35:
```python
@celery_app.task(
    name="app.workers.automation_tasks.run_entry_automations",
    bind=True,
    max_retries=2,
    soft_time_limit=120,
    time_limit=180,
)
def run_entry_automations(self, entry_id: str, feed_id: str):
    # ... task code ...
    except Exception as exc:
        CELERY_TASKS_TOTAL.labels(task_name="run_entry_automations", status="retry").inc()
        raise self.retry(exc=exc, countdown=min(300, 2 ** self.request.retries * 10 + random.uniform(0, 10)))
```

Retries use exponential backoff with jitter to avoid thundering herd problems.

### Task Categories and Key Workflows

#### Feed Ingestion Pipeline

1. **Polling trigger:** `poll_due_feeds()` finds feeds due for polling.
2. **Fetch:** `fetch_feed()` retrieves feed content, deduplicates, creates Entry records.
3. **Dispatch:** For each new entry, `dispatch_entry_pipeline()` creates a Celery chord (line 117 in `feed_tasks.py`):
   ```python
   def dispatch_entry_pipeline(entry_id: str, *, run_extraction: bool = False):
       prereqs = [autolink_entry_task.si(entry_id), scan_telegram_links_task.si(entry_id)]
       if run_extraction:
           prereqs.append(extract_entry_intel_task.si(entry_id))
       
       callback = entry_post_processing.si(entry_id=entry_id)
       chord(group(prereqs), callback).apply_async()
   ```
   - Prerequisite tasks (autolink, Telegram scan, optional extraction) run in parallel via `group()`.
   - Only when all are done, the callback `entry_post_processing()` runs.
4. **Post-processing:** Creates cooccurrence relationships, detects correlation events, matches intelligence requirements.

#### Automation Execution

`run_scheduled_automations()` (60-second cadence) evaluates all `on_schedule` automation rules and dispatches actions:
- **Tagging:** Add tags to entries.
- **Enrichment:** Trigger manual enrichment sources.
- **Notification:** Send SSE broadcasts or webhooks.
- **Detection:** Create detection rules from rule templates.

See `automation_tasks.py`, lines 27-86.

#### Enrichment Pipeline

`auto_enrich_entity()` is dispatched when entity extraction completes (line 70 in `enrichment_tasks.py`):
```python
@celery_app.task(name="app.workers.enrichment_tasks.auto_enrich_entity", soft_time_limit=120, time_limit=180)
def auto_enrich_entity(entity_type: str, entity_id: str, entity_value: str, ...):
    # ... auto-enrich from sources with trigger_mode='auto' ...
    CELERY_TASKS_TOTAL.labels(task_name="auto_enrich_entity", status="success").inc()
```

#### Report Generation

`generate_full_report()` in `report_tasks.py` (line 32) iterates through report template sections sequentially, calling AI to generate narrative prose for each empty section. It publishes SSE events (`report_section_generated`) for progress tracking.

### Distributed Coordination: Redis Locks and Vocab Versioning

**Feed Fetch Lock:** Prevents duplicate simultaneous fetches of the same feed:
```python
async def _poll_due_feeds():
    import redis as _redis
    # NX lock: SET intelfeed:feed_lock:{feed_id} "1" NX EX 300
```

**Vocab Versioning:** When new threat actors or malware are synced (`sync_cybergeist_feeds()`, line 74-76):
```python
if has_new_entities:
    refresh_autolinker_vocabulary.delay()
    rescan_recent_entries.apply_async(kwargs={"days": 7}, countdown=30)
```
This ensures that the auto-linker vocabulary (Aho-Corasick automaton) is refreshed before entries are rescanned, avoiding stale vocabulary during the refresh window.

### Telegram Listener (Real-Time Push)

**File:** `backend/app/workers/telegram_listener.py` (lines 1-80)

The Telegram listener is a **long-running non-Celery process** (runs in a dedicated Docker container) that maintains persistent Telethon MTProto connections. Instead of polling, it subscribes to Telegram channels and dispatches `fetch_feed.delay(feed_id)` on each new message.

**Key Features:**
- **Opt-in:** Only feeds with `adapter_config.realtime = true` are subscribed.
- **Coalesce:** A `_ChannelDispatcher` debounces rapid message bursts (within 1.5 seconds) into a single fetch_feed call.
- **Safety Net:** Polling remains active; if the listener dies, entries still arrive on the normal polling cadence.
- **Heartbeat:** Writes Redis key `intelfeed:telegram_listener:heartbeat` every 30 seconds. The UI can check this to show listener status.
- **Resync:** Every 5 minutes, re-polls the database for added/removed realtime feeds.

**Indirection Pattern:** Instead of parsing Telegram messages directly, the listener dispatches to the existing `fetch_feed()` polling pipeline. This reuses all dedup, sanitization, EntryMedia creation, autolink dispatch, and SSE broadcast logic. The tradeoff: slight latency overhead (~1.5 seconds for debounce + feed poll interval), but much lower risk of state divergence.

### Observability and Error Handling

**Metrics:** All tasks record Prometheus metrics via `CELERY_TASKS_TOTAL`, `CELERY_TASK_DURATION_SECONDS` (see `app/core/metrics.py`).

**Logging:** Structured logging via `structlog`:
```python
logger = structlog.get_logger("app.telegram_listener")
logger.info("dispatched_fetch", feed_id=feed_id)
```

**Dead Letter Queue:** Tasks that exceed `max_retries` are dropped to Redis (configurable); operators can inspect and manually retry.

**Error Categorization:**
- **Transient:** Network timeouts, rate limits (retry with backoff).
- **Permanent:** Invalid entry ID, feed not found (fail immediately).

See `report_tasks.py`, line 20 (`_TRANSIENT_ERROR_PATTERNS`), for transient error pattern matching.

---

## Meilisearch Integration

IntelFeed uses **Meilisearch** as a vector search + full-text search engine for entries. The system supports free-text queries, field-based filters, boolean operators, and faceted navigation.

### Index Schema and Configuration

**File:** `backend/app/services/meilisearch_client.py` (`_ensure_index`, `FILTERABLE_ATTRIBUTES`)

```python
FILTERABLE_ATTRIBUTES = [
    "id",            # the entity join constrains entries with `id IN [...]`
    "feed_id", "feed_title", "category_id", "feed_type", "published_at",
    "author", "is_read", "is_starred", "is_bookmarked", "has_notes",
    "media_type", "tags", "language",
    "word_count",    # what `words:>1500` filters on
]

def _ensure_index():
    """Create the entries index if it doesn't exist and configure it."""
    index = client.index(INDEX_NAME)  # INDEX_NAME = "entries"

    index.update_filterable_attributes(FILTERABLE_ATTRIBUTES)
    index.update_sortable_attributes(["published_at", "title", "word_count"])
    index.update_searchable_attributes(["title", "content_text", "summary", "author", "feed_title", "tags"])
    index.update_typo_tolerance({
        "enabled": True,
        "minWordSizeForTypos": {"oneTypo": 4, "twoTypos": 8},
    })
    index.update_ranking_rules(["sort", "words", "typo", "proximity", "attribute", "exactness"])
```

**Schema:**
- **Primary Key:** `id` (entry UUID)
- **Searchable Attributes:** `title`, `content_text` (first 50k chars), `summary`, `author`, `feed_title`, `tags`
- **Filterable Attributes:** Used in WHERE clauses; enables range queries on `published_at` and `word_count`, exact matches on `feed_id`, `tags`, etc. `id` is filterable because the entity join constrains the entry search with `id IN [...]`; without it Meilisearch answers 400 and `execute_entry_search` swallows the error, so every text term combined with an entity filter silently returned zero articles.
- **Sortable Attributes:** Support ordering by `published_at`, `title`, `word_count`.
- **Document Fields:**
  - `published_at` (Unix timestamp, not ISO string) for reliable sorting
  - `is_read`, `is_starred`, `is_bookmarked`, `has_notes` (user state; indexed separately from PostgreSQL)
  - `word_count`, `language`, `media_type` for filtering and display

**Not in this index:** feed categories, signal-engine reasons, article URLs, feed rating grades, mute/translation/image state, and `priority_score`. The query planner resolves those against PostgreSQL instead of re-indexing ~95k documents to carry them — see [Query Execution](#query-execution-and-search-api).

#### Entity and rule indexes

`ENTITY_INDEXES` (same file) configures one index per entity type — `entities_ttp`, `entities_cve`, `entities_actor`, `entities_malware`, `entities_country`, `entities_mitigation`, `entities_tool` — plus **`rules`**, which backs the Rule Library's list and facet rail (`GET /api/detection-rules/search`).

The `rules` index is the one whose settings carry real constraints:

- Every attribute the rail facets on must be in `filterable` — a missing value returns no distribution, silently.
- Timestamps are epoch integers so range filters and sorts compare numerically.
- `max_total_hits` is raised to **100,000**. Meilisearch caps both `totalHits` and paging depth at `maxTotalHits` (default 1,000); the library prints the total and infinite-scrolls the whole corpus, so the default under-reported the header and dead-ended the scroll.
- Facet values sort by **count**, not alphabetically. Values are truncated to `maxValuesPerFacet` (default 100) *before* the response is built, so alphabetical order dropped T1078 — the library's most common technique — while keeping T1068.

Documents are built by `entity_indexer._rule_to_doc()`, which precomputes `authored_local` ("no repo in metadata" — Meilisearch cannot filter on attribute absence), flattens JSONB `source_products` / `source_cves` that hold a mix of strings and objects, and borrows actors/malware/tools/vendors/products from the rule's source entry via the autolink junctions. Rule writes (create, update, bulk-update, delete, bulk-delete) index or remove documents inline; `sync_entity_search_indexes` heals drift every 4 hours.

### Indexing Pipeline

**Files:** `backend/app/services/meilisearch_client.py`, `backend/app/workers/maintenance.py`

#### On Entry Creation

When an entry is fetched and inserted into PostgreSQL, it's immediately indexed via `index_entry()` (line 88):
```python
def index_entry(
    entry_id: uuid.UUID, feed_id: uuid.UUID, title: str, content_text: str | None,
    ..., tags: list[str] | None = None, ...
):
    """Index an entry in Meilisearch."""
    doc = {
        "id": str(entry_id),
        "feed_id": str(feed_id),
        "title": title,
        "content_text": (content_text or "")[:50000],  # Cap at 50k chars
        "published_at": int(dt.timestamp()),  # Unix timestamp
        # ... other fields ...
    }
    index.add_documents([doc])
```

#### Batched Updates

For bulk indexing or re-indexing, the system uses batched `add_documents()` calls (typically 100-500 docs per call) to stay within Meilisearch's request size limits.

#### Cleanup on Deletion

When entries expire (retention policy) or are manually deleted, they're removed via:
```python
def delete_entries_batch(entry_ids: list[uuid.UUID]):
    """Delete entries from search index."""
    # Meilisearch DELETE /indexes/entries/documents/{id} for each entry_id
```

Called from `maintenance.py`, line 71 in `_cleanup_expired_entries()`.

#### Full Reindex on Demand

On schema changes (e.g., adding a new filterable attribute), the system supports a full reindex:
1. Create a new temporary index with updated schema.
2. Copy all entries from PostgreSQL to the temporary index.
3. Swap the old index with the new one.
4. Delete the old index.

This is triggered manually (not automatically) when database migrations add/remove searchable or filterable fields.

#### Version Bumping for Consistency

When the autolinker vocabulary is refreshed (every 30 minutes), the `refresh_autolinker_vocabulary()` task may update entity links, triggering re-indexing of entries. A version field (in Meilisearch or Redis) could track this, but currently, the system relies on the periodic `reconcile_meilisearch()` maintenance task (daily at 07:15 UTC) to detect and repair drift.

### Query Execution and Search API

**Files:** `backend/app/search/query_parser.py`, `backend/app/search/query_planner.py`, `backend/app/search/meili_builder.py`, `backend/app/api/search.py`

#### Query Language

Users write queries in a **custom language** with support for:
- **Free text:** `"APT29"` or `APT29` (implicit search in searchable fields)
- **Quoted phrases:** `"exact match"`
- **Field syntax:** `title:"APT29 campaign"`, `feed:"Talos"`, `tag:"critical"`, `cve.severity:critical`
- **Boolean operators:** `AND`, `OR`, `NOT` (case-sensitive)
- **Wildcards:** `threat_actor:*29*`
- **Range operators:** `cve.cvss:>9.0`, `date:>=2025-01-01`, `date:2025-01..2025-06`, `words:>1500`
- **Grouping:** `(APT29 OR APT28) AND Russia`

See `query_parser.py` for the grammar and [`query-language.md`](query-language.md) for the full field reference (18 entry fields, 99 entity fields).

#### Parsing and Planning

1. **Tokenize:** `tokenize(query)` breaks the query into tokens (WORD, PHRASE, LPAREN, AND, OR, NOT, EOF).
2. **Parse:** `parse_query(tokens)` builds an AST with nodes: `TextNode`, `FieldNode`, `BoolNode`, `NotNode`.
3. **Plan:** `build_execution_plan(ast)` classifies fields and builds separate execution sub-trees.
4. **Resolve:** `resolve_deferred_filters(db, plan)` answers the PostgreSQL-backed halves. It wraps `resolve_feed_filters()` and `resolve_entry_filters()` and is the supported entry point — running one without the other leaves branch placeholders unresolved and silently drops the clauses they stand for.
5. **Execute:** `execute_entry_search(plan)` sends the Meilisearch query; entity queries run separately in PostgreSQL.

#### Field Classification

**File:** `query_planner.py` (`ENTRY_FIELDS`, `ENTITY_FIELDS`)

Three lanes, not two:

| Lane | Fields | Resolved by |
|------|--------|-------------|
| Indexed entry | `title`, `content`, `author`, `feed`, `tag`, `type`, `media`, `lang`, `words`, `date`, `is:starred/read/unread/bookmarked/noted` | Meilisearch filter clauses |
| PostgreSQL entry | `category`, `signal`, `url`, `feed.reliability`, `feed.timeliness`, `feed.relevance`, `is:muted/translated/image` | `resolve_entry_filters()` |
| Entity | `cve`, `threat_actor`, `ttp`, `malware`, `country`, `tool`, `vendor`, `product`, `mitigation`, `campaign`, `ransomware_victim`, `rule`, `intel_report`, `pir`, `note` + sub-fields | `entity_builder.py` |

**`PendingEntryFilter` resolution** has two shapes:

- **Feed-scoped** (`category`, `is.muted`, `feed.*`) narrow to a set of feed IDs. There are only a few hundred feeds, so these become ordinary Meilisearch `feed_id` clauses.
- **Entry-scoped** (`signal`, `url`, `is.translated`, `is.image`) produce a set of *entry* IDs in `plan.db_entry_ids`, which the endpoint intersects with any entity join before running the query. A filter matching 17,000 entries costs one `IN` list rather than 17,000 OR clauses in a filter string.

Negation of an entry-scoped filter is subtractive only: the complement is every other entry and enumerating it is unbounded, so matches land in `plan.db_excluded_ids` and are removed from a positive set if one exists.

**Join modes:** `AND` (entity results constrain entry results) or `OR` (results are independent).

#### Meilisearch Query Execution

**File:** `meili_builder.py` (`execute_entry_search`)

```python
def execute_entry_search(
    plan: ExecutionPlan,
    entry_id_constraint: list[str] | None = None,
    limit: int = 20,
    offset: int = 0,
) -> dict:
    filters = list(plan.meili_filters)

    # Add entry ID constraint if present (from entity queries / PG entry filters)
    if entry_id_constraint is not None:
        ids = entry_id_constraint[:500]  # Cap at 500 IDs
        id_list = ", ".join(f"'{eid}'" for eid in ids)
        filters.append(f"id IN [{id_list}]")

    params = {
        "limit": limit,
        "offset": offset,
        "showMatchesPosition": True,
        "attributesToHighlight": ["title", "content_text"],
        "attributesToCrop": ["content_text"],
        "cropLength": 200,
        # Everything the search page's Entries facets offer
        "facets": ["feed_type", "feed_title", "tags", "media_type", "language"],
    }

    if filters:
        params["filter"] = " AND ".join(filters)

    result = index.search(plan.meili_query, params)

    # Execute alternative queries (from OR between text terms) and merge
    for alt_query in plan.meili_query_alternatives:
        alt_result = index.search(alt_query, alt_params)
```

**Key Details:**
- **Highlighting:** Marks matching terms in title and content with `<mark>` tags.
- **Cropping:** Truncates `content_text` to 200 chars around matches.
- **Facets:** Returns aggregated counts for `feed_type`, `feed_title`, `tags`, `media_type`, `language` — the five groups the search page's facet rail renders. `feed_title` rather than `feed_id` so the counts arrive already human-readable; the index's `maxValuesPerFacet` (5000) clears the feed count comfortably.
- **Alternatives:** If the query contains OR between text terms (e.g. `APT29 OR APT28`), Meilisearch may not rank both correctly, so the system submits alternative queries and merges results.

#### When the index is bypassed

`unified_search` reads entries straight from PostgreSQL (`_fetch_entries_by_ids`) in three cases:

1. **`sort:radar`** — orders by `priority_score`, a PostgreSQL column the index does not carry. Entries with no score are excluded outright, and the ordering matches the Priority Queue's.
2. **Nothing for the index to search** — an ID constraint exists but there is no text term and no indexed filter (an entity-only query, or a bare `signal:under_reported`).
3. **More than 800 constraining IDs** — passing tens of thousands of IDs as a Meilisearch filter string silently returned zero.

On this path counts are exact rather than estimated, and `relevance` degrades to newest-first.

#### Unified Search Endpoint

**File:** `api/search.py` (`unified_search`)

```python
@router.post("/unified", response_model=UnifiedSearchResponse)
async def unified_search(body: UnifiedSearchQuery, user=Depends(get_current_user), db=Depends(get_db)):
    plan = build_execution_plan(parse_query(body.q))

    # 1. Resolve the PostgreSQL-backed halves
    await resolve_deferred_filters(db, plan)

    # 2. Entity queries (PostgreSQL) → linked entry IDs
    if plan.has_entity_queries:
        entity_results, found = await execute_entity_queries(db, plan.entity_nodes, limit=body.entity_limit)
        if plan.join_mode == "AND":
            linked_entry_ids = found

    # 3. A PG entry filter narrows the same way an entity join does
    if plan.db_entry_ids is not None:
        linked_entry_ids = plan.db_entry_ids if linked_entry_ids is None else linked_entry_ids & plan.db_entry_ids

    # 4. Entry search — Meilisearch, or PostgreSQL when the index is bypassed
    ...

    # 5. Count entity types BEFORE trimming, so the facet rail stays honest
    entity_counts = dict(Counter(e["type"] for e in entity_results))
    entity_results = _trim_entities_per_type(entity_results, body.entity_group_limit)

    # 6. Enrich entry hits with authoritative user state from the DB
    await _enrich_hits_with_user_state(entry_hits, user.id, db)
```

`_trim_entities_per_type()` keeps the first `entity_group_limit` of *each* type. The list arrives sorted by relevance across all types, so a flat slice keeps whichever type ranks first and drops the rest entirely — which is how a plain-text query once answered with ten threat actors and nothing else.

#### Rule search

`GET /api/detection-rules/search` is a second, independent search surface over the `rules` index (`meilisearch_client.search_rules()`). It is not part of the query-language pipeline: it takes structured query params, returns disjunctive facet counts, and hydrates rows from PostgreSQL in Meilisearch's order. See [`detection-engineering.md`](detection-engineering.md#search-and-filters).

### Saved Searches and Alerting

**Files:** `models/saved_search.py`, `workers/saved_search_tasks.py`, `api/saved_search.py`

#### Data Model

```python
class SavedSearch(Base):
    id: UUID
    created_by: UUID
    name: str
    display_name: str | None
    query: str | None
    filters: dict  # JSONB for structured filters
    created_at: datetime
```

#### Periodic Refresh and Alerts

**File:** `saved_search_tasks.py`, lines 22-75

The `refresh_saved_search_counts()` task runs every 5 minutes and:
1. Fetches all saved searches.
2. For each, executes the query against Meilisearch.
3. Caches counts in Redis (TTL 10 minutes) at key `saved_search_counts:global`.
4. Optionally publishes alerts if unread count exceeds a threshold.

```python
@celery_app.task(name="app.workers.saved_search_tasks.refresh_saved_search_counts", ...)
def refresh_saved_search_counts():
    run_async(_refresh_counts())

async def _refresh_counts():
    searches = (await db.execute(select(SavedSearch))).scalars().all()
    counts: dict[str, dict[str, int]] = {}
    
    for s in searches:
        query_str = s.query or s.name or ""
        total, entry_ids = await _get_search_total_and_ids(query_str, ...)
        counts[str(s.id)] = {"unread": total, "total": total}
    
    r.set("saved_search_counts:global", json.dumps(counts), ex=600)
```

#### Campaign Saved Searches

A special mode for campaigns: saved searches can be linked to campaigns via the `CampaignSavedSearch` junction table. The `sync_campaign_saved_searches()` task (every 5 minutes) auto-adds matching entries to campaigns.

---

## Dashboards & Widgets

IntelFeed features a fully customizable dashboard system with ~20 pre-built widgets organized by category. Users create dashboards, add widgets, configure them, and arrange them using `react-grid-layout`.

### Dashboard Data Model

**File:** `models/dashboard.py`

```python
class Dashboard(Base):
    __tablename__ = "dashboards"
    id: UUID
    created_by: UUID | None
    name: str
    layout: dict  # JSONB (react-grid-layout layout)
    is_default: bool
    sort_order: int
    created_at: datetime
    
    creator = relationship("User")
    widgets = relationship("DashboardWidget", cascade="all, delete-orphan")

class DashboardWidget(Base):
    __tablename__ = "dashboard_widgets"
    id: UUID
    dashboard_id: UUID
    widget_type: str  # "feed-activity", "cve-severity", "triage-queue-stats", ...
    title: str | None
    config: dict  # JSONB (widget-specific configuration)
    position_x: int  # react-grid-layout position
    position_y: int
    width: int   # Grid units
    height: int
    
    dashboard = relationship("Dashboard")
```

### Widget Catalog

The catalog is code-defined in `frontend/src/components/widgets/registry.ts:113`
(`WIDGET_REGISTRY`). Each entry is a `type` slug, a label and description shown
in the picker, a default width/height on the 12-column grid, a React component,
and optional `configFields` (limit, time range, entity filter …). Most read a
`GET /api/widgets/<slug>` endpoint served by one of the seven widget routers
(`widgets`, `widgets_board`, `widgets_detection`, `widgets_entities`,
`widgets_ops`, `widgets_strategic`, `widgets_triage`), all mounted under the
same `/api/widgets` prefix.

**51 widgets**, alphabetically:

| Widget | Type | What it shows |
|---|---|---|
| **AI Usage** | `ai_usage` | Calls, tokens, and cost per AI provider |
| **ATT&CK Coverage Gap** | `attack_coverage_gap` | Observed TTPs with no detection rule |
| **ATT&CK Heatmap** | `attack_heatmap` | MITRE ATT&CK technique frequency |
| **Active Campaigns** | `active_campaigns` | Most active campaigns by recent entries |
| **Actively Exploited CVEs** | `kev_matches` | Recently mentioned CVEs flagged as actively exploited |
| **Actor Activity** | `actor_activity_timeline` | Sparkline of mentions per top actor |
| **Analytics Overview** | `analytics_overview` | Entity counts and event summary |
| **Automation Logs** | `automation_logs` | Recent automation execution logs with status summary |
| **CVE Severity** | `cve_severity` | CVE distribution by severity |
| **Campaign Momentum** | `campaign_momentum` | Open campaigns as activity strips — accelerating, steady, or quiet |
| **Correlation Events** | `correlation_events_feed` | Recent correlation event feed |
| **Correlation Events Browser** | `correlation_browser` | Browse, filter, and triage every correlation event |
| **Detection Coverage** | `detection_coverage` | TTP detection rule coverage |
| **Detection Format Breakdown** | `detection_format_breakdown` | Detection rules grouped by rule type |
| **Feed Activity** | `feed_activity` | Article count over time |
| **Feed Health** | `feed_health` | Failing or stale feeds with last error and fetch age |
| **Hot Correlations** | `hot_correlations` | Top co-occurring entity pairs in the window |
| **Intel Velocity** | `intel_velocity` | New entities per day by type |
| **KEV Deadlines** | `kev_deadlines` | CISA remediation due dates for KEV-listed CVEs, soonest first |
| **Latest Entries** | `latest_entries` | Most recent feed entries |
| **Morning Briefing** | `morning_briefing` | The latest AI daily summary, with entity links |
| **New Actors** | `new_actors` | Recently discovered threat actors |
| **New CVEs** | `new_cves` | Recently published CVEs with CVSS and mentions |
| **New Detections** | `new_detections` | Recently created detection rules with type, severity, and source |
| **Overview** | `overview_row` | Headline counts plus new entities of every workbench type, vs the prior window |
| **PIR Coverage** | `pir_coverage` | Intelligence requirement fulfillment status |
| **Playbook Drift** | `playbook_drift` | New techniques attributed to actors you watch |
| **Ransomware Pulse** | `ransomware_pulse` | Weekly victim disclosures stacked by ransomware group |
| **Relationship Inbox** | `relationship_inbox` | Trust-ladder counts plus claims awaiting confirm or reject |
| **Rules Needing Attention** | `rules_attention` | Detection rules with fresh intel since their last update |
| **Saved Search Hits** | `saved_search_hits` | Unread and total counts per saved search |
| **Source Reliability** | `source_reliability` | Feed source intel contribution matrix |
| **Stat Card** | `stat_card` | Single stat with trend indicator |
| **Targeted Countries** | `targeted_countries` | Top countries appearing as attack targets |
| **Targeting Grid** | `targeting_grid` | Which sectors are being hit, by region |
| **Telegram Mentions** | `telegram_mentions` | Most-mentioned Telegram channels |
| **Telemetry Gaps** | `telemetry_gaps` | Log sources you lack, ranked by how many rules they unblock |
| **Top Tags** | `top_tags` | Most-applied tags in the time window |
| **Trending Actors** | `trending_actors` | Top threat actors by article count |
| **Trending CVEs** | `trending_cves` | Most-mentioned CVEs this week |
| **Trending Malware** | `trending_malware` | Top malware families by mentions |
| **Trending Products** | `products_trending` | Top products by article mentions |
| **Trending TTPs** | `trending_ttps` | Most observed MITRE techniques |
| **Trending Vendors** | `vendors_trending` | Top vendors by article mentions |
| **Triage Flow** | `triage_flow` | Entries arriving versus entries you read, per day |
| **Triage Queue Stats** | `triage_queue_stats` | Unread, starred, and total counts |
| **Under the Radar** | `under_reported` | High-severity items with thin source coverage |
| **Unread Count** | `unread_count` | Unread entry count |
| **Watchlist Pulse** | `watchlist_pulse` | Your watched entities ranked by mention movement |
| **Weekly Recap** | `weekly_recap` | Entries, actors, CVEs, and detections vs prior window |
| **Worker Queue** | `worker_queue` | Celery task queue depth and Redis status |

A few are worth calling out because they answer a question the others don't:

- **Overview** is full-width (12 columns) and is the one widget designed to be the top row of a board — headline counts plus new entities of every workbench type, against the prior window.
- **Under the Radar** surfaces high-severity items with thin source coverage — the signal engine's `under_reported` made visible.
- **PIR Coverage** grades your feeds against your stated intelligence requirements. Uncomfortable, and the point.
- **Telemetry Gaps** ranks the log sources you don't collect by how many detection rules each one would unblock.
- **Relationship Inbox** and **Rules Needing Attention** are work queues rather than charts: claims awaiting a verdict, and rules with fresh intel since their last edit.
- **Stat Card** is the generic one — a single number with a trend indicator, configured rather than purpose-built.

Widget payload shapes are not duplicated here; each endpoint's response model is
in the OpenAPI schema at `/docs`.

### Widget Renderer and Configuration

**Frontend:** `frontend/src/components/widgets/`

Each widget component:
1. **Fetches data** via `useQuery()` from TanStack Query (with caching).
2. **Renders** based on widget type using charts (Recharts, Plotly), tables, or custom components.
3. **Accepts config** (e.g., date range, limit) via the widget's `config` JSONB.

Example widget registration (pseudo-code):
```typescript
const WIDGET_REGISTRY = {
  "feed-activity": lazy(() => import("./FeedActivityWidget")),
  "cve-severity": lazy(() => import("./CVESeverityWidget")),
  "triage-queue-stats": lazy(() => import("./TriageQueueStatsWidget")),
  // ...
};
```

The `WidgetRenderer` component:
```typescript
<Suspense fallback={<Spinner />}>
  {React.createElement(WIDGET_REGISTRY[widget.widget_type], {
    config: widget.config,
    title: widget.title,
  })}
</Suspense>
```

### StatCard and Chart Conventions

**File:** `frontend/src/components/widgets/StatCard.tsx`

The `StatCard` component displays a metric with a trend indicator:
```typescript
<StatCard
  label="Entries"
  value={entries_cur}
  trend={entries_pct}
  color="blue"
/>
```

**Chart Libraries:**
- **Recharts:** Line, bar, area charts (responsive, customizable).
- **Plotly:** Heatmaps, 3D plots, advanced visualizations (requires large bundle).
- **Custom:** Tables, timeline visualizations.

**Color Palette:** Defined via CSS variables in `index.css` (the project uses CSS Modules, not Tailwind); shared TLP/severity scales live in `frontend/src/utils/colorSchemes.ts`. Widget colors are matched to severity or category.

### Layout and Persistence

**Frontend:** `frontend/src/pages/DashboardPage.tsx:267` — a `WidthProvider(Responsive)`
grid from `react-grid-layout`:

```tsx
const ResponsiveGridLayout = WidthProvider(Responsive);
const ROW_HEIGHT = scalePx(80);   // respects the user's UI scale
const COLS = 12;                  // { lg: 12, md: 12, sm: 1 }

<ResponsiveGridLayout
  key={dashboardId}
  layouts={layouts}
  breakpoints={breakpoints}
  cols={cols}
  rowHeight={ROW_HEIGHT}
  draggableHandle={`.${styles.dragHandle}`}
  onDragStop={handleUserLayoutChange}
  onResizeStop={handleUserLayoutChange}
  isResizable={!dashboardLocked}
  isDraggable={!dashboardLocked}
  compactType="vertical"
  margin={[12, 12]}
  containerPadding={[0, 0]}
>
```

Two details worth knowing. Layout is persisted on **drag/resize stop**, not on
every `onLayoutChange` — the continuous callback fires during the drag and would
write a row per frame. And `containerPadding` is explicitly zeroed: RGL defaults
it to `margin`, which insets the grid by 12px and leaves widgets visibly
narrower than the controls bar above them.

**Persistence:** the new layout is saved to the `dashboards.layout` JSONB column.
The single-column `sm` breakpoint means the mobile stacking order is the grid's,
not a separate layout to maintain.

### Widget Picker and Configuration

**Frontend:** `frontend/src/components/widgets/WidgetPicker.tsx`, with the catalog itself in `frontend/src/components/widgets/registry.ts:113` (`WIDGET_REGISTRY`, 51 widgets)

Users can:
1. **Add widgets:** Click "Add Widget", select from the catalog, configure (e.g., date range, limit), and place on the dashboard.
2. **Remove widgets:** Click the X on a widget (hard delete via `DELETE /dashboards/{id}/widgets/{widget_id}`, returns 204).
3. **Edit config:** Click the gear icon, adjust date range or other params, save.

API endpoints:
```python
POST /dashboards/{dashboard_id}/widgets  # Create
PUT /dashboards/{dashboard_id}/widgets/{widget_id}  # Update config
DELETE /dashboards/{dashboard_id}/widgets/{widget_id}  # Delete
```

### Performance Optimizations

#### Query Batching

Some widget endpoints accept multiple filters to reduce the number of API calls. For example, a dashboard with 5 widgets shouldn't trigger 5 separate database queries; instead, widgets batch-request data.

#### Caching

- **Frontend:** TanStack Query caches data with configurable TTL (e.g., 5 minutes for feed-activity).
- **Backend:** Expensive aggregations (e.g., weekly recap trends) are cached in Redis for 10 minutes.

#### Database Indexes

Frequently-grouped columns (e.g., `Feed.is_active`, `Entry.published_at`, `TTP.technique_id`) have indexes to speed up aggregations.

#### Lazy Loading

Widget components are lazy-loaded with React's `lazy()` and `Suspense`, reducing initial dashboard bundle size.

### Multi-Dashboard and Per-User Customization

- **Per-user dashboards:** Each user can create custom dashboards.
- **Shared dashboards:** A dashboard can be marked as default, visible to all users.
- **Workspace dashboards:** Future: shared dashboards per workspace (not yet implemented).

The `is_default` flag is enforced in the API layer (not a DB constraint): when a user marks a dashboard as default, any existing default is automatically unmarked.

### Dashboard API Endpoints

**File:** `api/dashboards.py`

```python
GET /dashboards  # List all dashboards (paginated)
POST /dashboards  # Create new dashboard
GET /dashboards/{id}  # Get one dashboard with widgets
PUT /dashboards/{id}  # Update (name, is_default)
DELETE /dashboards/{id}  # Delete dashboard (cascades to widgets)

POST /dashboards/{id}/widgets  # Create widget
PUT /dashboards/{id}/widgets/{widget_id}  # Update widget (config, position)
DELETE /dashboards/{id}/widgets/{widget_id}  # Delete widget
PUT /dashboards/{id}/layout  # Persist react-grid-layout positions

PUT /dashboards/reorder  # Reorder dashboards (set sort_order)
```

---

## Diagrams

### Beat Schedule Timeline (24-hour window)

Generated from `JOB_REGISTRY` defaults; any of these can be overridden at
runtime from Engine → Jobs, which is stored in Redis and re-read at beat start.

```
00:30 ├─ check_requirement_expiry_task
01:30 ├─ run_cve_nvd_backfill
02:00 ├─ backup_database
02:05 ├─ cleanup_expired_entries
02:20 ├─ decay_observable_confidence
02:30 ├─ sync_cybergeist_feeds
02:40 ├─ prune_engine_tables
02:50 ├─ reconcile_observable_counters
03:00 ├─ kickoff_actor_profile_refresh (Monday) / kickoff_entity_merge_maintenance (Sunday)
      ├─ rescore_all_entries (Sunday) / run_mitre_attack_sync (Sunday)
03:05 ├─ reenrich_cve_nvd
03:15 ├─ cleanup_orphaned_references
03:30 ├─ rebuild_entity_profiles · run_malpedia_sync (Sunday) · run_misp_galaxy_sync (Sunday)
03:35 ├─ resolve_cve_affected
03:45 ├─ decay_relationship_confidence (Sunday) · refresh_cwe_catalog (Monday) · run_metasploit_sync (Sunday)
03:50 ├─ rebuild_rule_coverage
04:00 ├─ validate_entity_links · run_wikipedia_bulk_sync (Wednesday)
04:10 ├─ evict_image_cache
04:15 ├─ evict_tts_cache
04:20 ├─ recompute_signal_rates · rank_threat_board · rollup_targeted_sectors
      ├─ cleanup_telegram_media (Sunday)
04:25 ├─ evict_old_telegram_media
04:30 ├─ promote_watchlist_threats
04:35 ├─ fit_user_signal_weights
04:40 ├─ generate_threat_briefs
04:45 ├─ archive_correlation_events
04:50 ├─ backfill_rule_data_sources (Sunday)
05:00 ├─ run_github_poc_scan
05:30 ├─ review_hygiene_proposals · flag_stale_entities (Sunday)
      ├─ backfill_rule_attack_mappings (Sunday)
05:45 ├─ kickoff_assessment_backfill
06:00 ├─ generate_daily_summaries
06:10 ├─ narrate_story_threads
06:30 ├─ run_epss_bulk_sync · adjudicate_relationships
07:00 ├─ generate_reddit_digest
07:15 ├─ reconcile_meilisearch
12:00 └─ run_cve_nvd_refresh

Recurring:
  Every 60 s      poll_due_feeds, run_scheduled_automations
  Every 5 min     refresh_saved_search_counts, sync_campaign_saved_searches, retry_failed_indexing
  Every 10 min    poll_analysis_batches
  Every 15 min    embed_pending_entries, run_scheduled_enrichment,
                  refresh_correlation_cache, sync_campaign_sources
  Every 30 min    rebuild_story_threads, sync_ransomware_victims, refresh_autolinker_vocabulary,
                  refresh_claude_auth_status, retry_untranslated_entries, submit_analysis_batches
  Every 4 h       build_telegram_forward_relationships (:20), sync_entity_search_indexes (:45)
  Every 6 h       sync_kev_feed (:15), check_feed_health (:30),
                  rescore_recent_entries (:35), retro_sight_observables (:40)
```

The 03:00–06:00 UTC band is deliberately dense and deliberately ordered: the
enrichment and catalog syncs land first, the resolvers and rebuilds that read
them come next, and the AI jobs (assessments, hygiene review, adjudication,
briefs) run last on the single-concurrency `ai` worker, where they queue behind
one another anyway.

### Entry Ingestion Pipeline

```
feed.fetch_interval reached
          ↓
  poll_due_feeds() (Celery beat, 60s)
          ↓
  fetch_feed() [*_create_entry()*]
          ↓
  Entry record created in PostgreSQL
          ↓
  dispatch_entry_pipeline()
          ├─ [parallel] autolink_entry_task
          ├─ [parallel] scan_telegram_links_task
          └─ [parallel] extract_entry_intel_task (optional)
                      ↓
              entity extraction (CTI, CVE, TTP, IoC, etc.)
                      ↓
                  emit_extraction_complete()
          ↓
  [when all parallel tasks done]
          ↓
  entry_post_processing() [callback]
          ├─ create_cooccurrence_relationships_task
          ├─ detect_correlation_events
          └─ match_requirements_task
          ↓
  index_entry() → Meilisearch
          ↓
  emit SSE event (entry_added)
```

### Search Query Execution Flow

```
UnifiedSearchQuery
          ↓
  parse_query() → AST
          ↓
  build_execution_plan(AST) → ExecutionPlan
          ├─ classify fields (entry vs entity)
          ├─ separate into entry_nodes and entity_nodes
          └─ determine join_mode (AND / OR)
          ↓
  [if entity queries]
  execute_entity_queries(PostgreSQL) → [entry_id_1, entry_id_2, ...]
          ↓
  [if entry queries]
  execute_entry_search(Meilisearch, entry_id_constraint) → hits
          ├─ build Meilisearch filter string
          ├─ add id IN [...] constraint (if AND mode)
          └─ search() + highlight + crop
          ↓
  enrich_hits_with_user_state(PostgreSQL) → is_read, is_starred, etc.
          ↓
  UnifiedSearchResponse { hits, total, facets, parsed_filters }
```

### Dashboard Rendering Flow

```
/dashboards/{id}
          ↓
  GET /dashboards/{id} → Dashboard { id, layout, widgets: [...] }
          ↓
  GridLayout
          ├─ [for each widget]
          │   ├─ WidgetRenderer
          │   │   ├─ useQuery(`/widgets/{type}?config={...}`)
          │   │   ├─ [data cached by TanStack Query]
          │   │   └─ render chart / table / custom
          │   └─ onLayoutChange → updateDashboard({ layout: newLayout })
          └─ [user drags / resizes]
                      ↓
              PUT /dashboards/{id} { layout }
```

---

## References and Further Reading

- **Celery Documentation:** https://docs.celeryproject.org/
- **Meilisearch Docs:** https://docs.meilisearch.com/
- **React Grid Layout:** https://react-grid-layout.github.io/react-grid-layout/
- **TanStack Query:** https://tanstack.com/query/latest
- **SQLAlchemy async:** https://docs.sqlalchemy.org/en/20/orm/extensions/asyncio.html


## Pipeline Engine (engine phase 6)

The entry processing chain is registry-defined (`app/pipeline/registry.py`, same pattern as the enrichment registry): inline stages (sanitize/dedup/relevance/index, run in the fetch loop), a translate prologue (chained ahead of the chord for feeds with `auto_translate`, so autolink/extract/relevance/scoring all see the translated text; `translate_entry_task` swallows every failure so the prologue can never stall the chain), parallel chord header (autolink ∥ telegram_links ∥ extract), post-processing chord (cooccurrence ∥ correlation ∥ requirements → score), and side channels (automate, enrich). `dispatch_entry_pipeline` and `entry_post_processing` assemble Celery chords from the registry — `tests/test_pipeline_registry.py` asserts structural parity with the previous hand-built dispatch.

Stage composition is data-defined via `pipeline_plans` (global → category → feed layering, resolved in `app/pipeline/plans.py`, Redis-cached with version-bump invalidation). The legacy Feed booleans (`intel_extraction_mode`, `auto_extract_on_ingest`, `extract_detection_rules`) remain the resolution base layer until a follow-up migration drops them; the `pipeline_engine_enabled` flag toggles plan layering (off = booleans only, instant rollback).

Settings → **Engine** is the unified control surface: Pipeline tab (stage cards with 24h run counts from `entry_pipeline_runs`; per-stage config panels re-hosting Enrichment settings, one-pass AI extraction status/budget, and signal-engine tuning), Jobs tab (the former Job Schedules page + run history from `job_runs`), Plans tab (per-scope stage toggles). Old deep links (`?section=schedules|enrichment`) redirect. Engine API: `/api/engine/pipeline`, `/api/engine/plans`, `/api/engine/job-runs`, `/api/engine/extraction/status`, `/api/engine/signals/*`, `/api/engine/entries/{id}/runs`.
