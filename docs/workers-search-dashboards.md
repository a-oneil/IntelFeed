# Workers, Search, and Dashboards

This is the technical reference for three parts of the backend: the Celery workers that run background jobs, the Meilisearch search indexes, and the widget dashboards on the Workbench. It is for developers and operators. After reading it you will know every scheduled job and when it runs, which queue a task uses, how entries and rules reach the search index, how a search query runs, and how dashboard widgets are defined and saved.

## Table of Contents

1. [Worker Architecture](#worker-architecture)
2. [Meilisearch Integration](#meilisearch-integration)
3. [Dashboards & Widgets](#dashboards--widgets)
4. [Diagrams](#diagrams)
5. [Pipeline Engine](#pipeline-engine)

---

## Worker Architecture

IntelFeed runs background work with **Celery** (a Python task queue) and **Redis** (which holds the queue). This covers feed polling, enrichment, intelligence extraction, AI analysis, automation rules, reports and housekeeping.

### Celery App Configuration

`backend/app/workers/celery_app.py` sets up the app:

- **Broker and result backend** are the same Redis (`settings.redis_url`). Results expire after an hour (`result_expires=3600`) so they cannot fill Redis.
- **JSON** is the only serializer.
- **Times are UTC.**
- **Logging** goes through structlog; Celery is told not to replace the root logger (`worker_hijack_root_logger=False`).
- **The beat schedule** is built from the job registry at startup (see [Beat Schedule](#beat-schedule-and-runtime-overrides)).

### Queues and workers

There are three queues:

| Queue | Served by | Concurrency | What runs there |
|-------|-----------|-------------|-----------------|
| `celery` (default) | `celery-worker` | 4 in dev, 2 in prod | Everything not routed elsewhere |
| `ai` | `celery-worker-ai` | 1 (`CLAUDE_CODE_CONCURRENCY`, default 1) | Tasks that call an AI provider |
| `enrichment` | `celery-worker-enrichment` | 1 | `dispatch_enrichment_jobs`, the enrichment dispatcher |

The `enrichment` worker runs one dispatcher tick at a time, so ticks never overlap, and a tick waiting on a throttled source never holds a default-worker slot.

`celery-worker-ai` also drains the old `claude_code` queue name.

The `ai` worker runs one AI call at a time, whatever the provider. That paces a single Ollama GPU. It is also the only container that mounts the Claude Code CLI credentials, so CLI-provider tasks must run there.

`task_routes` sends these tasks to `ai`: `run_entry_analysis_task` (one-pass entry analysis), `adjudicate_entry_task` and `backfill_entry_adjudications` (the adjudicate stage), `refresh_actor_profile`, `process_name_normalization_batch`, `ai_enrich_gap_batch`, `narrate_story_threads`, `run_copilot_stream`, `run_claude_auth` and `refresh_claude_auth_status`. Some jobs also send their AI work there by hand with `apply_async(queue="ai")`, for example `kickoff_assessment_backfill` and `kickoff_actor_profile_refresh`.

**Any new task that calls an AI provider must be routed to `ai`.** On the default queue, a long AI call fills the worker's slots and blocks `poll_due_feeds`, which stops ingest.

### Per-Worker Async Pattern and Connection Management

`backend/app/workers/db.py` gives tasks two helpers:

- **`run_async(coro)`** runs async code on one event loop per worker process, created once and reused. This avoids "Event loop is closed" errors in Celery's prefork pool.
- **`worker_session()`** creates a fresh database engine and session for one task, and disposes the engine when the task ends. That way connections never leak between tasks.

```python
engine = create_async_engine(
    settings.database_url,
    pool_size=settings.worker_db_pool_size,        # default 3
    max_overflow=settings.worker_db_max_overflow,  # default 5
    pool_pre_ping=True,   # detect dead connections
    pool_recycle=1800,    # close connections after 30 minutes
)
```

### Task Catalog and Schedules

`JOB_REGISTRY` (`backend/app/workers/job_registry.py:44`) lists all **66** scheduled jobs. Each has a task, a description, a category, a default schedule and, where it has them, the `settings_keys` that tune it. The Engine → Jobs screen reads it and shows those settings next to the job. Every setting named there is listed in [engine-settings.md](engine-settings.md#setting--scheduled-job).

All times are UTC. "AI" means the job calls an AI provider. "(`ai` queue)" means that work runs on the `ai` worker.

#### Feed Polling

| Task | Default schedule | What it does |
|------|------------------|--------------|
| `poll_due_feeds` | Every 60 s | Find feeds that are due and queue a `fetch_feed` for each |
| `check_feed_health` | Every 6 h at :30 | Flag stale feeds and repeated fetch errors; pause feeds that have returned 4xx for longer than `feed_auto_pause_days` |

`poll_due_feeds` sets a Redis key `feed_fetch:{feed_id}` (`SET NX`, 10-minute expiry) before queueing a fetch, so a feed is never fetched twice at once.

#### Intelligence

| Task | Default schedule | What it does |
|------|------------------|--------------|
| `refresh_autolinker_vocabulary` | Every 30 min | Rebuild the entity-matching dictionary (Aho-Corasick automaton) |
| `rebuild_entity_profiles` | Daily 03:30 | Rebuild entity correlation profiles |
| `archive_correlation_events` | Daily 04:45 | Archive old correlation events |
| `check_requirement_expiry_task` | Daily 00:30 | Expire intelligence requirements past their date |
| `build_telegram_forward_relationships` | Every 4 h at :20 | Add actor-to-actor `communicates_with` links from Telegram forwards |
| `embed_pending_entries` | Every 15 min | Embed entries with no current vector, newest first. Feeds story threads and "more like this". Does nothing until `embeddings_enabled` is on |
| `rebuild_story_threads` | Every 2 h | Group embedded entries into story threads: attach, seed, fold echoes, merge split threads, prune empty ones |
| `narrate_story_threads` | Daily 06:10 | Write the summary ("spine") for threads that changed since they were last narrated. AI (`ai` queue) |
| `kickoff_assessment_backfill` | Daily 05:45 | Draft AI assessments for entities with linked articles but no description, and refresh its own drafts once enough new reporting arrives. Never overwrites text it did not write; skips CVEs, whose descriptions come from NVD. AI (`ai` queue) |
| `kickoff_actor_profile_refresh` | Monday 03:00 | Refresh the descriptions of the most active threat actors. AI (`ai` queue) |
| `rank_threat_board` | Daily 04:20 | Recompute the Threats board ranking; reopen handled threats that show new tradecraft |
| `promote_watchlist_threats` | Daily 04:30 | Pin watched actors and malware with recent activity onto the Threats board |
| `generate_threat_briefs` | Daily 04:40 | Write the two-sentence story line for each open Threats and vulnerability row. AI (default queue) |
| `submit_analysis_batches` | Every 30 min | Send pending entries to one-pass AI analysis, highest priority first, within budget |
| `poll_analysis_batches` | Every 10 min | Collect finished analysis batches: results, entity links, costs |
| `recompute_signal_rates` | Daily 04:20 | Recompute 30-day signal firing rates (the self-tuning weights) and re-scale priority scores to 0–10 |
| `fit_user_signal_weights` | Daily 04:35 | Fit each analyst's Radar weights from their own thumbs up/down. Applied only when `radar_personalization_enabled` is on |
| `rescore_recent_entries` | Every 6 h at :35 | Re-score recent entries so KEV and EPSS changes reach priority scores |
| `rescore_all_entries` | **Off by default** | Re-score every scored entry. Run it with **Run now**; the Sunday 03:00 schedule only applies if an admin turns it on |

#### Enrichment

| Task | Source | Default schedule | What it does |
|------|--------|------------------|--------------|
| `dispatch_enrichment_jobs` | | Every 30 s | Run due lookups from the enrichment job queue (`enrichment` queue). See [Enrichment Pipeline](#enrichment-pipeline) |
| `run_epss_bulk_sync` | `epss` | Daily 06:30 | Update EPSS scores (exploit likelihood) for all CVEs |
| `sync_kev_feed` | `cisa_kev` | Every 6 h at :15 | Sync the CISA Known Exploited Vulnerabilities catalog |
| `run_mitre_attack_sync` | `mitre_attack` | Sunday 03:00 | Sync MITRE ATT&CK techniques, groups and mitigations |
| `run_misp_galaxy_sync` | `misp_galaxy` | Sunday 03:30 | Refresh known actor aliases (`known_alias_map`) from the MISP Galaxy threat-actor cluster |
| `run_malpedia_sync` | `malpedia` | Saturday 01:00 | Sync malware families from Malpedia; aliases pass the junk-alias filter |
| `run_metasploit_sync` | `metasploit` | Sunday 03:45 | Map tracked CVEs to Metasploit modules and mark them weaponized |
| `refresh_cwe_catalog` | `mitre_cwe` | Monday 03:45 | Re-pull the MITRE CWE catalog and re-match unmatched NVD weakness references |
| `run_cve_nvd_refresh` | `nvd` | Daily 12:00 | Re-check NVD for CVSS changes |
| `run_cve_nvd_backfill` | `nvd` | Daily 01:30 | Fill in NVD data (CVSS, description, affected products, references) for CVEs that lack it; stops starting lookups 2 minutes before its time limit |
| `reenrich_cve_nvd` | `nvd` | Daily 03:05 | Re-fetch NVD data for CVEs still missing it |
| `run_github_poc_scan` | `github_poc` | Daily 05:00 | Search GitHub for proof-of-concept exploits; stops starting searches 2 minutes before its time limit |
| `run_wikipedia_bulk_sync` | `wikipedia` | Wednesday 04:00 | Add Wikipedia content to entities that lack it; stops 5 minutes before its time limit |
| `sync_cybergeist_feeds` | `cybergeist` | Daily 02:30 | Sync threat actor and malware lists from Cybergeist |
| `sync_ransomware_victims` | `ransomware_live` | Every 30 min | Collect ransomware leak-site victim posts as structured records |

Each source declares its jobs in its manifest ([Source Jobs](automation-ai-enrichment.md#source-jobs)). A job skips while its source is switched off (`{"skipped": "source disabled"}`), and sends its requests through its source's gateway ([Source Gateway](automation-ai-enrichment.md#source-gateway)). A refusal (rate limited, breaker open, budget spent) stops the job; it keeps what it did and records `stopped` in its stats.

When `sync_cybergeist_feeds` creates new entities, it queues `refresh_autolinker_vocabulary` and, 30 seconds later, `rescan_recent_entries` for the last 7 days. The delay lets the new dictionary load before old entries are re-scanned.

#### Maintenance

| Task | Default schedule | What it does |
|------|------------------|--------------|
| `backup_database` | Daily 02:00 | `pg_dump` with gzip |
| `cleanup_expired_entries` | Daily 02:05 | Delete entries past their feed's retention period, and remove them from search |
| `decay_observable_confidence` | Daily 02:20 | Lower confidence on aging observables (IOCs) and move them through their lifecycle |
| `prune_engine_tables` | Daily 02:40 | Delete engine bookkeeping rows (`job_runs`, …) older than 30 days |
| `prune_entity_context` | Daily 02:45 | Delete enrichment context rows (`entity_context`) that expired more than 30 days ago |
| `reconcile_observable_counters` | Daily 02:50 | Recount observable sighting and article counters, which deletes can throw off |
| `cleanup_orphaned_references` | Daily 03:15 | Remove references to deleted entities |
| `resolve_cve_affected` | Daily 03:35 | Re-match unmatched CVE affected-product (CPE) pairs to current vendors and products |
| `decay_relationship_confidence` | Sunday 03:45 | Demote co-occurrence relationships with no recent evidence from probable to possible |
| `rebuild_rule_coverage` | Daily 03:50 | Re-match detection rules to the CVEs, techniques and actors they cover (`rule_coverage`) |
| `evict_image_cache` | Daily 04:10 | Delete cached images past their TTL |
| `evict_tts_cache` | Daily 04:15 | Delete read-aloud (Piper) audio past its TTL or over the size cap |
| `rollup_targeted_sectors` | Daily 04:20 | Derive actor and malware target-sector claims from the victim sectors on their articles; rebuild the `targeted_sectors` cache |
| `cleanup_telegram_media` | Sunday 04:20 | Delete Telegram media whose entry is gone |
| `evict_old_telegram_media` | Daily 04:25 | Delete Telegram media files older than the TTL (entries are kept) |
| `evict_old_ingest_files` | Daily 04:35 | Delete original files from manual uploads older than `ingest_files_ttl_days` (entries are kept) |
| `backfill_rule_data_sources` | Sunday 04:50 | Work out detection rules' `data_sources` from their log sources, for telemetry coverage |
| `backfill_rule_attack_mappings` | Sunday 05:30 | Re-fetch GitHub-sourced rules to recover ATT&CK mappings, and fill tactics from techniques |
| `reconcile_meilisearch` | Daily 07:15 | Find and fix differences between PostgreSQL and the search index |
| `refresh_correlation_cache` | Hourly at :10 | Pre-warm the correlation cache for busy entities |
| `sync_entity_search_indexes` | Every 4 h at :45 | Re-sync entity indexes and the `rules` index |
| `retry_failed_indexing` | Every 5 min | Re-index entries that failed to index |
| `retro_sight_observables` | Every 6 h at :40 | Look for newly confirmed observables in older articles (exact match) |
| `retry_untranslated_entries` | Every 30 min | Translate entries missed while the LibreTranslate service was off (auto-translate feeds) |
| `refresh_claude_auth_status` | Every 30 min | Check the copilot's Claude Code login is still valid (`ai` queue) |

#### Automation and Saved Searches

| Task | Default schedule | What it does |
|------|------------------|--------------|
| `run_scheduled_automations` | Every 60 s | Run `on_schedule` automation rules |
| `refresh_saved_search_counts` | Every 5 min | Refresh each user's saved-search match and unread counts |
| `sync_campaign_saved_searches` | Every 5 min | Add entries matching a campaign's saved searches to the campaign |
| `sync_campaign_sources` | Every 15 min | Pull in articles for the entities, stories and queries each campaign follows |

#### Content Generation

| Task | Default schedule | What it does |
|------|------------------|--------------|
| `generate_daily_summaries` | Daily 06:00 | Write yesterday's shared daily summary shown in Triage. AI (default queue) |
| `generate_reddit_digest` | Daily 07:00 | Write a digest of top Reddit security posts. AI (default queue) |

### Beat Schedule and Runtime Overrides

`build_beat_schedule()` (`backend/app/workers/job_registry.py:621`) builds the schedule when beat starts:

1. Read overrides from the Redis key `intelfeed:job_schedule_overrides`.
2. For each job, skip it if the override disables it, or if it has `enabled_by_default: False` and no override turns it on.
3. Use the override schedule if there is one, otherwise the default.

Admins change schedules in **Settings → Engine → Jobs**. Changes are saved to that Redis key and take effect when beat next reads it (at startup).

Helpers in the same file: `schedule_to_human()` turns a schedule into text like "Every 30 minutes", and `schedule_dict_to_celery()` turns it into a Celery interval or `crontab()`.

### Task Time Limits and Retries

Tasks set these on the decorator:

- `soft_time_limit`: the task gets `SoftTimeLimitExceeded` and can clean up.
- `time_limit`: the worker kills the task.
- `max_retries` and `bind=True`: the task can retry itself.

Example from `backend/app/workers/automation_tasks.py`:

```python
@celery_app.task(
    name="app.workers.automation_tasks.run_entry_automations",
    bind=True,
    max_retries=2,
    soft_time_limit=120,
    time_limit=180,
)
@pipeline_stage("automate")
def run_entry_automations(self, entry_id: str, feed_id: str):
    ...
    except Exception as exc:
        raise self.retry(exc=exc, countdown=min(300, 2**self.request.retries * 10 + random.uniform(0, 10)))
```

The retry delay doubles each time, with some randomness, and never exceeds 5 minutes. A task that runs out of retries fails; there is no dead-letter queue.

### Task Categories and Key Workflows

#### Feed Ingestion Pipeline

1. `poll_due_feeds` finds due feeds and queues `fetch_feed`.
2. `fetch_feed` downloads the feed, sanitizes and de-duplicates entries, saves new ones and indexes them in Meilisearch.
3. For each new entry, `dispatch_entry_pipeline()` (`backend/app/workers/feed_tasks.py`) starts a Celery **chord**: a group of tasks that run in parallel, followed by a callback once all finish. The parallel tasks are autolink, observables, Telegram link scan and (if the feed has it on) extraction. Feeds with auto-translate run translation first.
4. The callback, `entry_post_processing()`, starts a second chord: co-occurrence relationships, correlation events and requirement matching in parallel, then signal scoring.

The stages come from the pipeline registry. See [Pipeline Engine](#pipeline-engine).

#### Automation Execution

`run_scheduled_automations` runs every 60 seconds and evaluates every `on_schedule` automation rule. Per-entry rules run through `run_entry_automations` as part of ingest. See [automation-ai-enrichment.md](automation-ai-enrichment.md) for triggers, conditions and actions.

#### Enrichment Pipeline

A new entity does not call its sources directly. The code that creates it (the autolinker, TTP and CVE extraction, the observables ledger, GitHub rule import) calls `enqueue()` in `backend/app/enrichment/queue.py`, which adds one `enrichment_jobs` row per enabled `trigger_mode='auto'` source that handles the entity type.

`dispatch_enrichment_jobs` (`backend/app/workers/enrichment_dispatch_tasks.py`) runs every 30 seconds on the `enrichment` queue. For up to 25 seconds it claims due rows (`FOR UPDATE SKIP LOCKED`, highest lane first, then oldest `due_at`), runs each through the pipeline for its one source, and writes the results onto the entity. A lookup the source refuses is rescheduled, not dropped. The lanes and outcomes are in [automation-ai-enrichment.md](automation-ai-enrichment.md#enrichment-job-queue).

#### Report Generation

`generate_full_report` (`backend/app/workers/report_tasks.py`) fills each empty narrative section of a report with AI text, one section at a time, and sends a `report_section_generated` server-sent event after each. A provider error on one section (matched by `_TRANSIENT_ERROR_PATTERNS`: 529, overloaded, rate limit, 502–504) moves on to the next section.

### Telegram Listener (Real-Time Push)

`backend/app/workers/telegram_listener.py` is a long-running process in its own container, not a Celery task. It keeps Telegram (Telethon) connections open and queues `fetch_feed(feed_id)` when a new message arrives, instead of waiting for the next poll.

- Only Telegram feeds with `adapter_config.realtime = true` are watched.
- Messages arriving within 1.5 seconds on one channel are combined into one fetch.
- Normal polling still runs, so entries still arrive if the listener stops.
- It writes a heartbeat to the Redis key `intelfeed:telegram_listener:heartbeat` every 30 seconds.
- Every 5 minutes it re-reads which feeds are realtime.

Reusing `fetch_feed` means de-duplication, sanitizing, media, autolinking and live updates all work the same as for polled entries.

### Observability

Tasks record Prometheus metrics `CELERY_TASKS_TOTAL` and `CELERY_TASK_DURATION_SECONDS` (`backend/app/core/metrics.py`) and log through structlog. Each scheduled run is also written to the `job_runs` table, which the Engine → Jobs screen shows as run history.

---

## Meilisearch Integration

IntelFeed uses **Meilisearch** for full-text search: fast, typo-tolerant keyword search with filters and facet counts. (Similarity search uses pgvector embeddings in PostgreSQL, not Meilisearch.)

### Index Schema and Configuration

The `entries` index is set up by `_ensure_index()` in `backend/app/services/meilisearch_client.py`:

| Setting | Value |
|---------|-------|
| Primary key | `id` (entry UUID) |
| Searchable | `title`, `content_text` (first 50,000 characters), `summary`, `author`, `feed_title`, `tags` |
| Filterable | `id`, `feed_id`, `feed_title`, `category_id`, `feed_type`, `published_at`, `author`, `is_read`, `is_starred`, `is_bookmarked`, `has_notes`, `media_type`, `tags`, `user_tags`, `language`, `word_count` |
| Sortable | `published_at`, `title`, `word_count` |
| Ranking rules | `sort`, `words`, `typo`, `proximity`, `attribute`, `exactness` |
| Typo tolerance | One typo from 4 letters, two from 8 |
| `maxValuesPerFacet` | 5,000 |
| `maxTotalHits` | 100,000 |

Notes:

- `published_at` is a Unix timestamp, so sorting and date ranges compare numbers.
- `id` is filterable because entity searches narrow the entry search with `id IN [...]`.
- `user_tags` holds personal tags as `<user_id>:<name>`. It is never searched. It is folded into the `tags` facet only for the user who owns those tags.
- `is_read`, `is_starred` and similar fields are written for one user. Search results always get each user's real state from PostgreSQL afterwards.

**Not in the index:** feed categories, signal-engine signals, URLs, feed ratings, mute, translation and image state, and `priority_score`. Searches on those are answered from PostgreSQL instead (see [Field Classification](#field-classification)).

#### Entity and rule indexes

`ENTITY_INDEXES` (same file) defines one index per entity type: `entities_cve`, `entities_ttp`, `entities_threat_actor`, `entities_malware`, `entities_country`, `entities_sector`, `entities_cwe`, `entities_mitigation`, `entities_observable` and `entities_tool`. It also defines **`rules`**, which backs the Rules Library (`GET /api/detection-rules/search`).

The `rules` index settings that matter:

- Every attribute the library's facet rail uses must be filterable, or that group silently gets no counts.
- Timestamps are numbers, so range filters and sorts work.
- `maxTotalHits` is 100,000. Meilisearch caps both the reported total and how deep you can page at this value (default 1,000).
- `maxValuesPerFacet` is 5,000 and facet values are sorted by count, so a cut-off never drops the most common values.

Rule documents are built by `entity_indexer._rule_to_doc()`. See [detection-engineering.md](detection-engineering.md#search-and-filters) for the fields it adds.

### Indexing Pipeline

- **New entries** are indexed by `index_entry()` as `fetch_feed` saves them.
- **Read, star and tag changes** update the document in place (`update_entry_state()`, `bulk_update_read_state()`, `bulk_update_entry_tags()`).
- **Deleted or expired entries** are removed with `delete_entries_batch()`; `cleanup_expired_entries` calls it.
- **Bulk loads** use `bulk_index_entries()` and `bulk_index_entities()`, which retry on failure.
- **Rules** are indexed when they are created, edited or deleted.
- **Drift** is repaired by the jobs `retry_failed_indexing` (every 5 minutes), `sync_entity_search_indexes` (every 4 hours) and `reconcile_meilisearch` (daily).

#### Full rebuild

To rebuild every index from the database, for example after restoring a dump from another environment, run this in the API container:

```bash
docker compose -f docker-compose.dev.yml exec api python scripts/maintenance/rebuild_search_indexes.py
# --user <name> bakes that user's read/star state into the entries index
# --entries-only / --entities-only rebuild one half
```

This deletes and recreates the `entries` index (`rebuild_index()`), then re-syncs the entity indexes and `rules`.

### Query Execution and Search API

Files: `backend/app/search/query_parser.py`, `query_planner.py`, `meili_builder.py`, `entity_builder.py`, and `backend/app/api/search.py`.

#### Query Language

Searches use IntelFeed's own query language: free text, `"quoted phrases"`, fields (`title:`, `feed:`, `tag:`, `cve.severity:critical`), `AND` / `OR` / `NOT`, wildcards (`threat_actor:*29*`), ranges (`cve.cvss:>9.0`, `date:>=2025-01-01`, `words:>1500`) and grouping (`(APT29 OR APT28) AND Russia`). The full field list is in [query-language.md](query-language.md).

#### Parsing and Planning

1. **Parse.** `parse_query()` tokenizes the query (`tokenize()`) and builds a syntax tree.
2. **Plan.** `build_execution_plan()` sorts each field into a lane (below) and builds the Meilisearch query and filters.
3. **Resolve.** `resolve_deferred_filters(db, plan)` answers the parts that need PostgreSQL. Always call this one function; it runs both `resolve_feed_filters()` and `resolve_entry_filters()`, and running only one silently drops clauses.
4. **Entity search.** `execute_entity_queries()` (`entity_builder.py`) finds matching entities in PostgreSQL and the entries linked to them.
5. **Entry search.** `execute_entry_search()` (`meili_builder.py`) runs the Meilisearch query.

#### Field Classification

`query_planner.py` (`ENTRY_FIELDS`, `ENTITY_FIELDS`) puts each field in one of three lanes:

| Lane | Fields | Answered by |
|------|--------|-------------|
| Indexed entry | `title`, `content`, `author`, `tag`, `type`, `media`, `lang`, `words`, `date`, `is:starred/read/unread/bookmarked/noted` | Meilisearch filters |
| PostgreSQL entry | `feed`, `category`, `feed.reliability`, `feed.timeliness`, `feed.relevance`, `is:muted` (feed-scoped); `signal`, `url`, `is:translated`, `is:image` (entry-scoped) | `resolve_feed_filters()` / `resolve_entry_filters()` |
| Entity | `cve`, `cwe`, `ttp`, `threat_actor`, `malware`, `country`, `sector`, `tool`, `vendor`, `product`, `mitigation`, `campaign`, `ransomware_victim`, `observable` (alias `ioc`), `rule`, `pir`, `intel_report`, `note`, plus their sub-fields | `entity_builder.py` |

How PostgreSQL filters are folded in:

- **Feed-scoped** filters look up a set of feed IDs. There are only a few hundred feeds, so these become ordinary Meilisearch `feed_id` filters.
- **Entry-scoped** filters produce a set of entry IDs in `plan.db_entry_ids`. The endpoint intersects it with any entity results before searching, so a filter matching 17,000 entries is one ID list, not 17,000 filter clauses.
- **Negating** an entry-scoped filter can only subtract. Its matches go in `plan.db_excluded_ids` and are removed from a positive set, because listing "every other entry" is unbounded.

Entity results either narrow the entry results (`AND`) or sit beside them (`OR`).

#### Meilisearch Query Execution

`execute_entry_search()` sends:

- the query text, with `matchingStrategy: "all"` so every term must match;
- the plan's filters, plus `id IN [...]` when entity or PostgreSQL filters narrowed the set (at most 500 IDs);
- highlighting of `title` and `content_text` with `<mark>` tags, and a 200-character crop of `content_text` around matches;
- facets for `feed_type`, `feed_title`, `tags`, `media_type` and `language`, the five groups on the search page's facet rail.

A query with `OR` between parts may become several **branches**. Each branch is searched and the results are merged.

#### When the index is bypassed

`unified_search` reads entries straight from PostgreSQL (`_fetch_entries_by_ids`) when:

1. **`sort:radar`** is used. It orders by `priority_score`, which is not in the index. Entries with no score are left out, and the order matches the Priority Queue.
2. **There is nothing for the index to search**: an ID set exists but there is no text and no indexed filter (an entity-only query, or a bare `signal:under_reported`).
3. **There are more than 500 IDs** (`MEILI_ID_FILTER_CAP`). That is the most the `id IN [...]` filter carries, so a larger set would lose its tail.

On this path counts are exact, and `relevance` sorting falls back to newest first.

#### Unified Search Endpoint

`POST /api/search/unified` (`unified_search` in `backend/app/api/search.py`):

1. Parse and plan the query.
2. Resolve PostgreSQL filters.
3. Run entity queries; in `AND` mode their linked entries become an ID set.
4. Intersect with any PostgreSQL entry IDs.
5. Search entries in Meilisearch, or PostgreSQL when bypassed.
6. Count entity results by type, then keep the top `entity_group_limit` of **each** type (`_trim_entities_per_type()`), so one type cannot crowd out the rest.
7. Fill in each hit's read, star and bookmark state for the current user (`_enrich_hits_with_user_state()`).

#### Rule search

`GET /api/detection-rules/search` is a separate search over the `rules` index (`meilisearch_client.search_rules()`). It does not use the query language. It takes ordinary query parameters, returns disjunctive facet counts, and loads rows from PostgreSQL in Meilisearch's order. See [detection-engineering.md](detection-engineering.md#search-and-filters).

### Saved Searches and Alerting

Files: `backend/app/models/saved_search.py`, `backend/app/workers/saved_search_tasks.py`, `backend/app/api/saved_searches.py`.

A `SavedSearch` has `created_by`, `name`, `display_name`, `query`, `filters` (JSONB) and `created_at`. Saved searches belong to one user.

`refresh_saved_search_counts` runs every 5 minutes. For each owner it computes match and unread counts for their saved searches, using that user's own read state, and caches them in Redis at `saved_search_counts:{user_id}` for 10 minutes. The saved-search list and the Saved Search Hits widget read that cache.

Campaigns can follow saved searches through the `CampaignSavedSearch` table. `sync_campaign_saved_searches` (every 5 minutes) adds matching entries to the campaign.

---

## Dashboards & Widgets

The dashboard is the Workbench landing page, `/workbench/dashboard`. (`/dashboards` redirects there.) Each user has their own set of boards, shown as tabs. You add widgets from a catalog, change their settings, and drag and resize them on a grid.

### Dashboard Data Model

`backend/app/models/dashboard.py`:

- **`Dashboard`** (`dashboards`): `id`, `created_by`, `name`, `layout` (JSONB), `is_default`, `sort_order`, `created_at`. Deleting a dashboard deletes its widgets.
- **`DashboardWidget`** (`dashboard_widgets`): `id`, `dashboard_id`, `widget_type` (a registry slug such as `feed_activity`), `title`, `config` (JSONB), `position_x`, `position_y`, `width`, `height`.

A widget's place on the grid is stored in its own `position_x`, `position_y`, `width` and `height` columns.

### Default boards

A user with no dashboards gets the instance's default set from `POST /dashboards/seed-defaults`: five boards named Triage, Intel, CVE, DE and Ransomware Ops (`backend/app/dashboard_defaults.py`). Seeding only runs for a user with zero dashboards, so edits are never overwritten. In public read-only mode, anonymous visitors see built-in boards locked in place.

### Widget Catalog

The catalog is code, in `WIDGET_REGISTRY` (`frontend/src/components/widgets/registry.ts:113`). Each entry has:

- `type`: the slug saved in `widget_type`. Renaming one breaks saved dashboards.
- `label` and `description`, shown in the picker.
- `defaultW` and `defaultH`, the starting size on the 12-column grid.
- `component`, the React component.
- optional `configPatch` (preset config), `configFields` (settings the user can edit, such as row limit) and `hidden`.

Most widgets read a `GET /api/widgets/<name>` endpoint. Those come from seven routers, all mounted at `/api/widgets`: `widgets`, `widgets_board`, `widgets_detection`, `widgets_entities`, `widgets_ops`, `widgets_strategic` and `widgets_triage`.

There are **51 widget types**. Five are **hidden** from the picker but still render on boards that already have them: Analytics Overview, Stat Card, Triage Queue Stats, Unread Count and Weekly Recap. That leaves 46 in the picker.

| Widget | Type | What it shows |
|---|---|---|
| **AI Usage** | `ai_usage` | Calls, tokens and cost per AI provider |
| **ATT&CK Coverage Gap** | `attack_coverage_gap` | Techniques seen in articles with no detection rule |
| **ATT&CK Heatmap** | `attack_heatmap` | How often each ATT&CK technique appears |
| **Active Campaigns** | `active_campaigns` | Campaigns with the most recent entries |
| **Actively Exploited CVEs** | `kev_matches` | Recently mentioned CVEs marked as actively exploited |
| **Actor Activity** | `actor_activity_timeline` | Mentions over time for the top actors |
| **Analytics Overview** (hidden) | `analytics_overview` | Entity counts and event summary |
| **Automation Logs** | `automation_logs` | Recent automation runs and their status |
| **CVE Severity** | `cve_severity` | CVEs by severity |
| **Campaign Momentum** | `campaign_momentum` | Open campaigns as accelerating, steady or quiet |
| **Correlation Events** | `correlation_events_feed` | Recent correlation events |
| **Correlation Events Browser** | `correlation_browser` | Browse, filter and triage every correlation event |
| **Detection Coverage** | `detection_coverage` | Detection rule coverage of techniques |
| **Detection Format Breakdown** | `detection_format_breakdown` | Detection rules by format |
| **Feed Activity** | `feed_activity` | Articles over time |
| **Feed Health** | `feed_health` | Failing or stale feeds, with last error and age |
| **Hot Correlations** | `hot_correlations` | Entity pairs that appear together most |
| **Intel Velocity** | `intel_velocity` | New entities per day, by type |
| **KEV Deadlines** | `kev_deadlines` | CISA remediation due dates for KEV CVEs, soonest first |
| **Latest Entries** | `latest_entries` | Newest entries |
| **Morning Briefing** | `morning_briefing` | The latest AI daily summary, with entity links |
| **New Actors** | `new_actors` | Recently found threat actors |
| **New CVEs** | `new_cves` | Recently published CVEs with CVSS and mentions |
| **New Detections** | `new_detections` | Recently created detection rules |
| **Overview** | `overview_row` | Headline counts and new entities of every type, compared with the previous window |
| **PIR Coverage** | `pir_coverage` | How well your intelligence requirements are being met |
| **Playbook Drift** | `playbook_drift` | New techniques linked to actors you watch |
| **Ransomware Pulse** | `ransomware_pulse` | Weekly victim posts, stacked by ransomware group |
| **Relationship Inbox** | `relationship_inbox` | Relationship claims waiting to be confirmed or rejected |
| **Rules Needing Attention** | `rules_attention` | Detection rules with new intel since their last update |
| **Saved Search Hits** | `saved_search_hits` | Unread and total counts per saved search |
| **Source Reliability** | `source_reliability` | How much intel each feed contributes |
| **Stat Card** (hidden) | `stat_card` | One number with a trend arrow |
| **Targeted Countries** | `targeted_countries` | Countries most often named as targets |
| **Targeting Grid** | `targeting_grid` | Which sectors are being hit, by region |
| **Telegram Mentions** | `telegram_mentions` | Most-mentioned Telegram channels |
| **Telemetry Gaps** | `telemetry_gaps` | Log sources you lack, ranked by how many rules they would unblock |
| **Top Tags** | `top_tags` | Most-used tags in the window |
| **Trending Actors** | `trending_actors` | Threat actors by article count |
| **Trending CVEs** | `trending_cves` | Most-mentioned CVEs |
| **Trending Malware** | `trending_malware` | Malware families by mentions |
| **Trending Products** | `products_trending` | Products by mentions |
| **Trending TTPs** | `trending_ttps` | Most-seen ATT&CK techniques |
| **Trending Vendors** | `vendors_trending` | Vendors by mentions |
| **Triage Flow** | `triage_flow` | Entries arriving versus entries read, per day |
| **Triage Queue Stats** (hidden) | `triage_queue_stats` | Unread, starred and total counts |
| **Under the Radar** | `under_reported` | High-severity items with few sources (the signal engine's `under_reported`) |
| **Unread Count** (hidden) | `unread_count` | Unread entry count |
| **Watchlist Pulse** | `watchlist_pulse` | Your watched entities, ranked by change in mentions |
| **Weekly Recap** (hidden) | `weekly_recap` | Entries, actors, CVEs and detections compared with the previous window |
| **Worker Queue** | `worker_queue` | Celery queue depth and Redis status |

**Overview** is full width (12 columns) and is meant to be a board's top row. **Relationship Inbox** and **Rules Needing Attention** are work lists rather than charts.

Each endpoint's response shape is in the OpenAPI schema at `/docs`.

### Widget Renderer and Configuration

Files are in `frontend/src/components/widgets/`.

- `WidgetRenderer.tsx` looks up the widget's definition by type, works out the board's time range (24h, 7d, 30d, 90d, 1y, all or custom), merges `configPatch` with the saved `config`, and renders the component inside an error boundary, so one broken widget shows "Widget failed to load" instead of breaking the board.
- Widget components fetch their data with TanStack Query hooks from `frontend/src/hooks/useWidgetData.ts`.
- Widgets with `configFields` get a settings gear that opens `WidgetSettingsPopover.tsx`.
- Colors come from the CSS variables in `index.css`. Shared severity and TLP scales are in `frontend/src/utils/colorSchemes.ts`.

### Layout and Persistence

`frontend/src/pages/DashboardPage.tsx` uses `react-grid-layout`:

```tsx
const ResponsiveGridLayout = WidthProvider(Responsive);
const ROW_HEIGHT = scalePx(80);   // follows the user's UI scale

<ResponsiveGridLayout
  layouts={layouts}
  breakpoints={{ lg: 1200, md: 768, sm: 0 }}
  cols={{ lg: 12, md: 12, sm: 1 }}
  rowHeight={ROW_HEIGHT}
  onDragStop={handleUserLayoutChange}
  onResizeStop={handleUserLayoutChange}
  isResizable={!dashboardLocked}
  isDraggable={!dashboardLocked}
  compactType="vertical"
  margin={[12, 12]}
  containerPadding={[0, 0]}
>
```

- The layout is saved only when a drag or resize **stops**, with `PUT /dashboards/{id}/layout`, which writes each widget's position and size. Saving on every layout change would write once per frame while dragging.
- `containerPadding` is zero so the grid lines up with the controls above it. (By default it equals `margin` and indents the grid by 12px.)
- On small screens the grid is one column, stacked in grid order.
- A **lock** setting turns off dragging and resizing, so a stray touch on a phone does not move widgets.

### Widget Picker and Configuration

`frontend/src/components/widgets/WidgetPicker.tsx` lists the visible widgets from the registry.

- **Add:** choose a widget; it is placed below the existing ones at its default size.
- **Configure:** the gear opens the widget's settings.
- **Remove:** deletes the widget row.

### Dashboard API Endpoints

`backend/app/api/dashboards.py`, under `/api/dashboards`:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/dashboards` | GET | Your dashboards with their widgets (paginated) |
| `/dashboards` | POST | Create a dashboard |
| `/dashboards/seed-defaults` | POST | Give a user with no dashboards the default boards |
| `/dashboards/reorder` | PUT | Set `sort_order` |
| `/dashboards/{id}` | GET | One dashboard with widgets |
| `/dashboards/{id}` | PUT | Rename, or set as default (unsets your other default) |
| `/dashboards/{id}` | DELETE | Delete a dashboard and its widgets |
| `/dashboards/{id}/widgets` | POST | Add a widget |
| `/dashboards/{id}/widgets/{widget_id}` | PUT | Update a widget's title, config or position |
| `/dashboards/{id}/widgets/{widget_id}` | DELETE | Remove a widget (returns 204) |
| `/dashboards/{id}/layout` | PUT | Save every widget's position and size |

Dashboards are private to their owner. `is_default` marks one of **your** dashboards as your default; setting it clears your previous default.

---

## Diagrams

### Beat Schedule Timeline (24 hours, UTC)

Built from the `JOB_REGISTRY` defaults. Admins can change any of these in Engine → Jobs.

```text
00:30 ├─ check_requirement_expiry_task
01:00 ├─ run_malpedia_sync (Sat)
01:30 ├─ run_cve_nvd_backfill
02:00 ├─ backup_database
02:05 ├─ cleanup_expired_entries
02:20 ├─ decay_observable_confidence
02:30 ├─ sync_cybergeist_feeds
02:40 ├─ prune_engine_tables
02:45 ├─ prune_entity_context
02:50 ├─ reconcile_observable_counters
03:00 ├─ kickoff_actor_profile_refresh (Mon) · run_mitre_attack_sync (Sun)
03:05 ├─ reenrich_cve_nvd
03:15 ├─ cleanup_orphaned_references
03:30 ├─ rebuild_entity_profiles · run_misp_galaxy_sync (Sun)
03:35 ├─ resolve_cve_affected
03:45 ├─ decay_relationship_confidence (Sun) · refresh_cwe_catalog (Mon) · run_metasploit_sync (Sun)
03:50 ├─ rebuild_rule_coverage
04:00 ├─ run_wikipedia_bulk_sync (Wed)
04:10 ├─ evict_image_cache
04:15 ├─ evict_tts_cache
04:20 ├─ recompute_signal_rates · rank_threat_board · rollup_targeted_sectors · cleanup_telegram_media (Sun)
04:25 ├─ evict_old_telegram_media
04:30 ├─ promote_watchlist_threats
04:35 ├─ fit_user_signal_weights · evict_old_ingest_files
04:40 ├─ generate_threat_briefs
04:45 ├─ archive_correlation_events
04:50 ├─ backfill_rule_data_sources (Sun)
05:00 ├─ run_github_poc_scan
05:30 ├─ backfill_rule_attack_mappings (Sun)
05:45 ├─ kickoff_assessment_backfill
06:00 ├─ generate_daily_summaries
06:10 ├─ narrate_story_threads
06:30 ├─ run_epss_bulk_sync
07:00 ├─ generate_reddit_digest
07:15 ├─ reconcile_meilisearch
12:00 └─ run_cve_nvd_refresh

Recurring:
  Every 30 s      dispatch_enrichment_jobs
  Every 60 s      poll_due_feeds, run_scheduled_automations
  Every 5 min     refresh_saved_search_counts, sync_campaign_saved_searches, retry_failed_indexing
  Every 10 min    poll_analysis_batches
  Every 15 min    embed_pending_entries, sync_campaign_sources
  Every 30 min    sync_ransomware_victims, refresh_autolinker_vocabulary, refresh_claude_auth_status,
                  retry_untranslated_entries, submit_analysis_batches
  Hourly (:10)    refresh_correlation_cache
  Every 2 h       rebuild_story_threads
  Every 4 h       build_telegram_forward_relationships (:20), sync_entity_search_indexes (:45)
  Every 6 h       sync_kev_feed (:15), check_feed_health (:30), rescore_recent_entries (:35),
                  retro_sight_observables (:40)

Off by default:   rescore_all_entries (Run now only)
```

The 03:00–06:00 band is ordered on purpose: data syncs run first, then the jobs that read their results, then the AI jobs.

### Entry Ingestion Pipeline

```text
poll_due_feeds (every 60 s)
  → fetch_feed
      sanitize, de-duplicate, score relevance, save Entry, index in Meilisearch
  → dispatch_entry_pipeline
      [translate first, for auto-translate feeds]
      chord, in parallel:
        autolink_entry_task
        observables_entry_task
        scan_telegram_links_task
        extract_entry_intel_task      (only if the feed has extraction on)
  → entry_post_processing (when all of the above finish)
      chord, in parallel:
        create_cooccurrence_relationships_task
        detect_correlation_events
        match_requirements_task
      → score_entry_task
  side tasks: run_entry_automations; new entities queue enrichment_jobs rows,
              run by dispatch_enrichment_jobs (enrichment queue)
  later, after AI analysis: adjudicate_entry_task (ai queue)
```

### Search Query Execution Flow

```text
POST /api/search/unified
  → parse_query() → syntax tree
  → build_execution_plan() → lanes, Meilisearch query and filters, join mode
  → resolve_deferred_filters()   (PostgreSQL: feed IDs, entry IDs)
  → execute_entity_queries()     (PostgreSQL: entities and linked entry IDs)
  → entry search
      Meilisearch execute_entry_search()  with id IN [...] when narrowed
      or PostgreSQL _fetch_entries_by_ids()  for sort:radar, ID-only, or > 500 IDs
  → trim entities per type
  → _enrich_hits_with_user_state()  (read / starred / bookmarked)
  → UnifiedSearchResponse
```

### Dashboard Rendering Flow

```text
/workbench/dashboard
  → GET /api/dashboards → your boards (tabs) with widgets
  → for each widget:
      WidgetRenderer → registry component → GET /api/widgets/<name>
  → user drags or resizes
      → on stop: PUT /api/dashboards/{id}/layout
```

---

## Pipeline Engine

The entry pipeline is defined as data in `backend/app/pipeline/registry.py`: each stage has a kind (`inline`, `pre`, `parallel`, `post`, `final`, `post_analysis`, `side`) and a task. `dispatch_entry_pipeline` and `entry_post_processing` build their chords from it. Which stages run can be set per feed, category or globally with pipeline plans (`backend/app/pipeline/plans.py`) when `pipeline_engine_enabled` is on; when it is off, the feed's own extraction settings decide. Settings → Engine shows each stage and its run counts.

The full reference, including stage kinds, plans and the Engine console, is in [engine.md](engine.md#pipeline-stage-registry).

---

## References and Further Reading

- Celery: <https://docs.celeryq.dev/>
- Meilisearch: <https://www.meilisearch.com/docs>
- React Grid Layout: <https://github.com/react-grid-layout/react-grid-layout>
- TanStack Query: <https://tanstack.com/query/latest>
