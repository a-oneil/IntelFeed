# Engine — Pipeline, Signals, and Ops Console

For contributors and operators. After reading this you will know which stages process each new article, how the priority score (0–10) is computed and tuned, and what the Settings → Engine console shows.

## Overview

"The engine" covers three connected parts:

1. **Pipeline** (`backend/app/pipeline/`): the list of processing stages each new entry goes through. The stages are defined in code (the *stage registry*). Optional *pipeline plans* switch stages on or off per feed, category or globally.
2. **Signal engine** (`backend/app/intelligence/signals.py`, `backend/app/workers/signal_tasks.py`): small, explainable facts about each entry (*signals*, such as "a CVE in this article was just added to CISA KEV") and a priority score built from them. The score drives the Radar, the Priority Queue, the chips on entry lists, and automation rules.
3. **Engine console** (`backend/app/api/engine.py` and Settings → Engine): where an admin configures the pipeline, reviews what the AI proposes, and sees per-entry and per-job run history.

The switches live in the `system_settings` database table (editable at Settings → Engine, admin only), with defaults in `backend/app/config.py`. Every engine setting is listed in [engine-settings.md](engine-settings.md). Because they are stored in the database, a change in one environment (say, dev) does not carry over to another.

| Setting | Default | What it does |
|---|---|---|
| `signal_engine_shadow` | `true` | Compute and store signals and scores (`backend/app/config.py:59`) |
| `signal_engine_surface` | `true` | Show them: Radar-ranked triage, entry-list chips, the `radar` sort, `entry_scored` SSE events (`backend/app/config.py:60`) |
| `radar_personalization_enabled` | `false` | Re-order each analyst's own Radar using weights learned from their votes (`radar_personalization_min_samples` 5, `radar_personalization_window_days` 90) |
| `pipeline_run_logging_enabled` | `true` | Write one `entry_pipeline_runs` row per stage run (`backend/app/config.py:109`) |
| `pipeline_engine_enabled` | `false` | Use pipeline plans instead of each feed's own extraction switches (`backend/app/config.py:112`) |
| `adjudication_mode` | `apply` | The `adjudicate` stage: `off`, `shadow` (file verdicts as proposals) or `apply` (apply confident verdicts, file the rest) |

Setting metadata is in `backend/app/services/system_settings.py`: `CONFIGURABLE_KEYS` (`backend/app/services/system_settings.py:26`) says which keys may be overridden and their type, `SETTING_METADATA` (`backend/app/services/system_settings.py:216`) holds labels and help text, and `_ENGINE_SECTION_GROUPS` (`backend/app/services/system_settings.py:1413`) places engine keys on console sections.

Related docs: [entries.md](entries.md) (the full entry lifecycle), [intelligence-engine.md](intelligence-engine.md) (the autolinker and correlation code the stages call), [data-model.md](data-model.md) (table schemas), [workers-search-dashboards.md](workers-search-dashboards.md) (Celery and beat schedules).

---

## Pipeline stage registry

`backend/app/pipeline/registry.py` lists every stage as a `StageDef` (`backend/app/pipeline/registry.py:28`): `name`, `kind`, the Celery `task_path` (if any), a description shown in the console, `default_enabled`, and a `config_schema` hint for the config panel.

### Stage kinds

| Kind | How it runs |
|---|---|
| `inline` | Inside the fetch loop. Listed for the console only; not a Celery task |
| `pre` | Chained before the main chord, so its output (translated text) reaches every later stage. It must never raise, or the whole chain stops |
| `parallel` | The first chord header: `autolink` ∥ `observables` ∥ `telegram_links` ∥ `extract` |
| `post` | The second chord header, after every parallel stage finishes |
| `final` | The second chord's callback: scoring |
| `post_analysis` | Runs after the entry's one-pass AI analysis lands, minutes to hours later. Never part of the chord |
| `side` | Dispatched on its own, outside the chord |

(A *chord* is a Celery group of tasks plus a callback that runs once they all finish.)

### Stage catalog

From `PIPELINE_STAGES` (`backend/app/pipeline/registry.py:38`):

| Stage | Kind | Task | Default |
|---|---|---|---|
| `sanitize` | inline | — HTML sanitizing (nh3 allowlist) and text extraction | on |
| `dedup` | inline | — GUID and cross-feed content-hash deduplication | on |
| `relevance` | inline | — keyword relevance score; gates selective autolink and the AI junk filter | on |
| `index` | inline | — Meilisearch indexing, with a retry queue for failures | on |
| `translate` | pre | `translation_tasks.translate_entry_task` | on (feeds with `auto_translate`) |
| `autolink` | parallel | `intel_feed_tasks.autolink_entry_task`. Dictionary-word matches are held for AI confirmation ([intelligence-engine.md](intelligence-engine.md)) | on |
| `observables` | parallel | `intel_feed_tasks.observables_entry_task`. Stages candidate indicators on the entry, records sightings of values already in the ledger, and parses curated `ioc_list` feeds. Regex never creates a ledger row | on |
| `telegram_links` | parallel | `telegram_link_tasks.scan_telegram_links_task` | on |
| `extract` | parallel | `intel_feed_tasks.extract_entry_intel_task`. Pattern extraction of TTP, CVE and mitigation IDs and detection rules. AI analysis runs separately | off (on for feeds with `auto_extract_on_ingest` or `extract_detection_rules`) |
| `cooccurrence` | post | `intel_feed_tasks.create_cooccurrence_relationships_task` | on |
| `correlation` | post | `automation_tasks.detect_correlation_events` | on |
| `requirements` | post | `intel_feed_tasks.match_requirements_task` | on |
| `score` | final | `signal_tasks.score_entry_task`. Scores the entry and queues the one-pass AI analysis | on |
| `adjudicate` | post_analysis | `adjudication_tasks.adjudicate_entry_task`. An AI review of everything the analysis wrote to the entry (links, new entities, relationships, observables). Verdicts are filed or applied per `adjudication_mode`; see [engine-settings.md](engine-settings.md#adjudicate-stage-post-analysis-ai-review) | on |
| `enrich` | side | `enrichment_dispatch_tasks.dispatch_enrichment_jobs`. New entities queue `enrichment_jobs` rows; this beat task runs the due ones every 30 seconds on the `enrichment` queue. See [automation-ai-enrichment.md](automation-ai-enrichment.md#enrichment-job-queue) | on |
| `automate` | side | `automation_tasks.run_entry_automations` | on |

`stages_of_kind(kind)` (`backend/app/pipeline/registry.py:163`) is how the chord builders and the API read the registry, so no task name is hard-coded elsewhere. `backend/tests/test_pipeline_registry.py` checks that the chord built from the registry has the expected shape.

---

## Pipeline plans (feed > category > global resolution)

A `PipelinePlan` row (`backend/app/models/pipeline_plan.py`) changes stages for one scope:

- `scope_type`: `global`, `category` or `feed` (the last two with a `scope_id`). One plan per scope (`uq_pipeline_plan_scope`).
- `stages`: `{stage_name: {"enabled": bool, "config": {...}}}`. Plans are **partial**: anything a plan leaves out comes from the scope below it.

How a feed's plan is resolved (`backend/app/pipeline/plans.py`):

1. **Switch.** `resolve_feed_plan()` (`backend/app/pipeline/plans.py:137`) returns `None` while `pipeline_engine_enabled` is off. The fetch code then uses the feed's own `run_extraction` switch. Turning the setting off is an instant rollback.
2. **Base.** `synthesize_from_feed()` (`backend/app/pipeline/plans.py:51`) builds a plan from the feed's columns: every stage at its registry default, except `extract`, which is on when the feed has `auto_extract_on_ingest` or `extract_detection_rules`, with `{mode, detection_rules}` from the feed. A feed whose analysis mode is `none` never gets `extract`.
3. **Overlay.** Active plans are merged in the order global → category → feed by `_merge()` (`backend/app/pipeline/plans.py:68`): `enabled` is replaced per stage and `config` is merged key by key.
4. **Cache.** The result is cached in Redis at `intelfeed:pipeline_plan:{feed_id}:{version}` for 600 seconds. Every plan write calls `bump_plan_version()` (`backend/app/pipeline/plans.py:79`), which changes `{version}` and so invalidates every cached plan. Resolution happens once per feed fetch, not per entry.

`resolve_feed_plan` is called in each ingest path in `backend/app/workers/feed_tasks.py` before entries are dispatched.

### Worked example

Feed "Vendor Blog X" has `auto_extract_on_ingest = false`, sits in category "Vendor Research", and these plans are active:

```jsonc
// global plan
{ "telegram_links": { "enabled": false } }

// category plan for "Vendor Research"
{ "extract": { "enabled": true, "config": { "mode": "full" } } }

// feed plan for "Vendor Blog X"
{ "extract": { "config": { "detection_rules": true } } }
```

1. Base from the feed: `extract` off, `{mode: "selective", detection_rules: false}`; everything else at its default.
2. Global: `telegram_links` off.
3. Category: `extract` on, config `{mode: "full", detection_rules: false}`.
4. Feed: `detection_rules` becomes `true`. The feed plan says nothing about `enabled`, so the category's `true` stays.

Result: `autolink` ∥ `observables` ∥ `extract` (full mode, with detection rules).

---

## Stage execution flow

Diagram: [diagrams/engine-pipeline-execution.md](diagrams/engine-pipeline-execution.md)

`dispatch_entry_pipeline()` (`backend/app/workers/feed_tasks.py:337`) builds each entry's Celery work from the registry:

1. **Parallel header.** One task per enabled `parallel` stage. With a plan, the plan decides; without one, everything runs except `extract`, which follows `run_extraction`. If a plan turns off every parallel stage, `autolink` is added back so the chord still has a header and the later stages still run.
2. **Translate first.** For feeds with `auto_translate` in `adapter_config`, `translate_entry_task` is chained before the chord, so every later stage sees the translated text. It never raises; it returns a status string.
3. **Post stages.** When the header finishes, `entry_post_processing` (`backend/app/workers/feed_tasks.py:295`) starts a second chord: `cooccurrence`, `correlation` and `requirements`, with `score` as its callback. Plans only affect the parallel header; post and final stages always run.
4. **Score.** `score_entry_task` runs once the co-occurrence edges, correlation events and requirement matches exist, because those are signal inputs.
5. **Side stages.** `automate` is queued from the fetch loop for each new entry. `enrich` is queued when an entity is created.
6. **AI analysis.** `score_entry_task` ends by calling `enqueue_entry_analysis` (`backend/app/services/entry_analysis.py`). It checks, in order: the global `ai_one_pass_enabled` switch, an existing request, a task assignment, the feed's AI policy, the junk gate, and echo reuse. It then writes the entry's `ai_analysis_requests` row. Feed-policy skips are recorded (`skipped_feed_ai`, `skipped_feed_none`) and re-checked by the 30-minute sweep once the feed allows AI. The analysis itself runs on the `ai` queue and writes no pipeline run, so the console's **analyze** column is drawn from that row. See [automation-ai-enrichment.md](automation-ai-enrichment.md#one-pass-entry-analysis-engine-phase-4).
7. **Adjudicate.** Wherever an analysis lands (batch results, the sequential task, echo reuse, a manual run), `enqueue_adjudication` (`backend/app/services/entry_adjudication.py`) runs after the commit. It checks the mode, the feed plan, echo, the trigger, the score floor and the hourly budget, records the decision in `ai_analysis_requests.adjudication_status`, and queues `adjudicate_entry_task` on the `ai` queue.

### Per-stage run logging

Every Celery stage task has `@pipeline_stage("<stage>")` (`backend/app/workers/pipeline_logging.py:69`) under its `@celery_app.task`. When the task finishes, it writes one `entry_pipeline_runs` row: status (`success` / `error` / `retry`), duration and a clipped error. There are no "running" rows. For `adjudicate`, the task's return value becomes the row's `detail` (verdict counts).

- A logging failure never breaks the task.
- `pipeline_run_logging_enabled` switches it off.
- It does not touch the tasks' own Prometheus counters, so nothing is counted twice.

---

## Signal scoring model

Diagram: [diagrams/engine-signal-scoring.md](diagrams/engine-signal-scoring.md)

Signals are meant to be rare. The score adds them up, and each signal type's weight depends on how often it fired over the last 30 days: a signal that fires on half of all entries adds almost nothing; one that fires on 0.5% adds a lot. (This is IDF weighting: inverse document frequency.)

### Signal catalog

16 signal types in 5 families (`SIGNAL_FAMILIES`, `backend/app/intelligence/signals.py:57`). Each signal has a strength from 0 to 1.

| Signal | Family | Fires when |
|---|---|---|
| `novel_entity` | novelty | A linked actor, malware or tool has ≤3 earlier articles or was first seen within 14 days. CVEs count by first-seen date only (`_novel_entity`, `backend/app/intelligence/signals.py:529`) |
| `entity_resurgence` | novelty | A known entity's last coverage is over 90 days old; strength grows with the gap, up to 365 days. Checked only when `novel_entity` did not fire (`_entity_resurgence`, `backend/app/intelligence/signals.py:587`) |
| `new_pairing` | novelty | A co-occurrence relationship created in the last hour has this entry as its only evidence, for actor+malware, actor+country, malware+CVE or actor+tool (`_new_pairing`, `backend/app/intelligence/signals.py:625`) |
| `scoop` | novelty | `novel_entity` fired, the entry is not an echo, and the feed's `reliability_rating` is A or B |
| `source_convergence` | coverage | ≥3 independent outlets carry the entry's [story thread](story-threads.md). For an entry in no thread: ≥3 sources (distinct domains, not feeds) share ≥2 entities within 24 hours |
| `under_reported` | coverage | A severe CVE (KEV, CVSS ≥9, EPSS ≥0.5, or weaponized) that ≤2 feeds have ever covered, counted per CVE (`_under_reported`, `backend/app/intelligence/signals.py:978`) |
| `feed_echo` | coverage | The story thread marks the entry as a re-report. For an entry in no thread: an earlier entry within 72 hours shares ≥70% of its ≥3 entities. This one **lowers** the score |
| `kev_added` | severity | A linked CVE was added to CISA KEV within 7 days of the entry's date (`_severity_signals`, `backend/app/intelligence/signals.py:892`) |
| `epss_jump` | severity | A linked CVE's EPSS score rose within the last 7 days |
| `epss_high` | severity | A linked CVE is at or above the 95th EPSS percentile |
| `weaponized_poc` | severity | A linked CVE has public PoC repos and `exploit_availability` of `weaponized` or `poc` |
| `critical_cvss` | severity | A linked CVE with CVSS ≥9 first seen in the last 90 days (so old criticals in a retrospective do not boost forever) |
| `pir_match` | interest | The entry matches an intelligence requirement; strength = matches ÷ 3, capped at 1 (`_interest_signals`, `backend/app/intelligence/signals.py:1026`) |
| `correlation_event` | interest | A correlation event was recorded; strength by highest severity (high 1.0, medium 0.6, low 0.3) |
| `detection_content` | content | The entry has extracted detection rules (`_content_signals`, `backend/app/intelligence/signals.py:1085`) |
| `research_depth` | content | ≥1500 words and (≥3 TTPs or detection rules) |

**Coverage signals use story threads first.** When the thread sweeper has placed an entry, its verdict is the answer: `role = 'echo'` is an echo, the thread's source count is the corroboration, and a *beat* (new development) is never an echo however many entities it shares. Threading runs up to 30 minutes behind ingest, so this shows up on a rescore: the sweeper queues `rescore_entries_for_threads` for every thread whose membership changed, so one more outlet rescores the whole story. Switch: Engine → Score stage → Story threads → **Score From Threads** (`thread_signals_enabled`, default on). When it is off, or for entries too short to thread, the entity-overlap check is used.

The entity-overlap checks share one query (`_feed_echo`, `backend/app/intelligence/signals.py:761`) and ignore entities linked to more than 500 articles (`MEGA_ENTITY_ARTICLE_COUNT`, `backend/app/intelligence/signals.py:113`), so "Microsoft"-sized entities do not make everything an echo. Time windows are measured from the entry's own date (`published_at`, else `fetched_at`), so a rescore gives the same answer.

### Weights: IDF, multipliers, echo

`compute_priority_score()` (`backend/app/intelligence/signals.py:144`):

```text
score = Σ strength × idf_weight(firing_rate) × family_multiplier
        (feed_echo: strength × −0.5 × family_multiplier instead)
```

- `idf_weight(rate) = log(1/rate) / log(1/0.05)`, clamped to 0.1–3.0. A 5% firing rate gives weight 1.0 (`idf_weight`, `backend/app/intelligence/signals.py:139`).
- Firing rates come from Redis (`intelfeed:signal_engine:rates`). Before the first nightly run, defaults are used (`DEFAULT_FIRING_RATES`, `backend/app/intelligence/signals.py:87`). For example `pir_match` starts at 0.43 because it fires often and must be weighted down.
- Family multipliers (`novelty`, `coverage`, `severity`, `interest`, `content`; default 1.0, admin-set, 0–2) steer whole families (`DEFAULT_FAMILY_MULTIPLIERS`, `backend/app/intelligence/signals.py:76`).
- `feed_echo` has a fixed weight (`ECHO_WEIGHT`, `backend/app/intelligence/signals.py:108`). Its job is to sink re-reports, not to get stronger as it gets rarer.

### The 0–10 scale

The sum has no upper bound, so it is stored as `Entry.priority_raw` and mapped onto 0–10 for everything people and rules see (`Entry.priority_score`, `scale_score`). The mapping ranks the sum against the last 30 days of entries that fired at least one signal:

| Score | Means |
|---|---|
| 0 | Nothing fired, or an echo cancelled what did |
| 1 | The weakest entries with any signal |
| 5 | 60th percentile |
| 8 | 90th percentile |
| 9 | 95th percentile (top 5%) |
| 10 | 99th percentile and above (top 1%) |

These anchors are `SCALE_ANCHORS` (`backend/app/intelligence/signals.py:173`). Between two anchors the score is interpolated and rounded to one decimal. The raw value at each anchor (the *cutoffs*) is recomputed nightly by `signal-rate-recompute` and cached in Redis, so a new entry gets its 0–10 score as soon as it is scored. The same nightly job re-scales stored scores from the last 90 days (`SCALE_RESCALE_DAYS`) against the new cutoffs, writing only rows that changed, 2,000 at a time. Older entries keep the scale they were last scored on. The new cutoffs reach Redis before the re-scale starts, so new and stored scores always use the same scale. Ordering uses `priority_raw`, which is never clamped or rounded.

### Persistence

`score_entry()` (`backend/app/workers/signal_tasks.py:99`) computes the signals, deletes ones that no longer fire, upserts the rest on `(entry_id, signal_type)` (`uq_entry_signals_entry_type`), and writes `priority_raw`, `priority_score` and `scored_at`. A rescore overwrites; it never appends. `entry_signals` rows are deleted with their entry.

`score_entry_task` (`backend/app/workers/signal_tasks.py:39`) does nothing unless `signal_engine_shadow` or `signal_engine_surface` is on (`_engine_enabled`, `backend/app/workers/signal_tasks.py:24`); that includes not queuing the AI analysis. When it runs, it also queues the one-pass AI analysis, queues `on_entry_scored` automation rules if any are enabled, and (surface only) broadcasts an `entry_scored` SSE event.

### Feedback loop and self-tuning (beat jobs)

Tasks in `backend/app/workers/signal_tasks.py`, scheduled through `backend/app/workers/job_registry.py`:

| Job key | Task | Schedule (UTC) | What it does |
|---|---|---|---|
| `signal-rate-recompute` | `recompute_signal_rates` | Daily 04:20 | Recomputes 30-day firing rates (entries with the signal ÷ entries *scored* in the window, so backfills do not skew it), the 0–10 cutoffs (then re-scales recent scores), the auto Radar threshold (95th percentile of `priority_score` over 7 days), and the family feedback nudges. Writes all four to Redis |
| `signal-rescore-recent` | `rescore_recent_entries` | Every 6 hours at :35 | Rescores recent entries (default 72 hours, 500 entries) so late KEV adds and EPSS jumps reach stored scores. Never-scored entries in the window go first, so a scoring failure heals itself |
| `signal-personal-weight-fit` | `fit_user_signal_weights` | Daily 04:35 | Fits each analyst's family weights from their own votes into `user_signal_weights`; drops rows whose votes aged out or fell below the minimum |
| `signal-rescore-all` | `rescore_all_entries` | Off by default; run from the Jobs view | Rescores every scored entry |
| — | `rescore_entries_for_cve` | On event | Rescores entries linked to one CVE (default 14 days, 200 entries) when its KEV, EPSS or exploit facts change (`dispatch_cve_rescore`, `backend/app/workers/signal_tasks.py:485`) |
| — | `rescore_entries_for_threads` | On event | Rescores the members of threads whose membership changed (`dispatch_thread_rescore`, `backend/app/workers/signal_tasks.py:474`) |
| — | `backfill_entry_scores` | Never scheduled | Scores entries with `scored_at IS NULL` from the last 14 days, 500 at a time (`backfill_entry_scores`, `backend/app/workers/signal_tasks.py:525`) |

**Radar feedback.** Analysts vote on Radar items (`RadarFeedbackButtons.tsx` → `PUT /api/engine/radar-feedback`; 1 = useful, −1 = noise, 0 clears), one vote per user per entry in `entry_signal_feedback`. Each vote is credited to the one family that contributed most to that entry's score. The nightly job averages votes per family and writes a nudge of `1.0 + 0.1 × mean(vote)`, read back clamped to 0.9–1.1 (`get_feedback_nudges`, `backend/app/intelligence/signals.py:419`). A family with fewer than `signal_feedback_min_samples` votes (default 20) stays at 1.0, and the nudge is rewritten every night, so a family that drops below the floor resets. Nudges multiply the admin family multipliers at score time, so votes shift the ranking by at most ±10%.

**Learned Radar weights (per analyst).** The nudge above pools everyone's votes into the shared score. `fit_user_signal_weights` keeps each analyst's votes separate and fits a personal family weight: `1 + 0.35 × mean(vote) × n/(n+8)`, clamped to 0.65–1.35 (`fit_personal_weight`, `backend/app/intelligence/signals.py:342`). The `n/(n+8)` term stops three votes from moving a family as far as thirty.

These weights apply **when reading only** (`backend/app/services/radar_personalization.py`). The Radar query adds a per-entry lift, `Σ strength × idf_weight × (w − 1)`, to the score and orders by score + exposure lift + personal lift. Because each signal's contribution is linear, that equals what the engine would have scored with the analyst's weights, with no rescoring. Personalization **re-orders** a `GET /api/entries?sort=radar` page but never changes which entries are on it: the Radar threshold still gates on the shared score. The Priority Queue (`GET /api/entries/priority-queue`) sorts on the stored score it displays; the lifts only admit extra entries (such as a stack-relevant CVE below the threshold) and decorate them.

It needs `radar_personalization_enabled` (instance-wide) and the user's own opt-in (`User.settings["radar_personalized"]`). Settings → Reading → "Your Radar" shows each family's weight and votes, a toggle, and a reset. `GET`/`PUT`/`DELETE /api/engine/my-radar` back that panel. The reader's "Why it's ranked" card adds a *Tuned for you* row naming the families that moved the entry.

**Radar threshold.** A value on the 0–10 scale. `get_radar_threshold()` (`backend/app/intelligence/signals.py:431`) returns the manual override (`intelfeed:signal_engine:threshold_override10`) if set, else the nightly auto value, else 8.0. An override left in the old raw-sum key `intelfeed:signal_engine:threshold_override` is converted on first read once real cutoffs exist. The threshold decides what the Radar shows and which entries get chips.

### Redis state

All tuning state is in Redis (key names at `backend/app/intelligence/signals.py:46-54`); Postgres holds only per-entry results. Losing these keys is safe: everything falls back to defaults and the nightly job rewrites them.

| Key | Written by | Read by |
|---|---|---|
| `intelfeed:signal_engine:rates` | `recompute_signal_rates` | `get_signal_rates()` at score time, `GET /api/engine/signals/stats` |
| `intelfeed:signal_engine:multipliers` | `PUT /api/engine/signals/settings` | `get_family_multipliers()` at score time |
| `intelfeed:signal_engine:scale_cutoffs` | `recompute_signal_rates` (after a flush, the first scoring run computes it and caches it for a day) | `get_scale_cutoffs()` at score time, Priority Queue scores |
| `intelfeed:signal_engine:threshold10` | `recompute_signal_rates` (auto, 0–10) | `get_radar_threshold()` |
| `intelfeed:signal_engine:threshold_override10` | `PUT /api/engine/signals/settings` (manual, 0–10; clear it to go back to auto) | `get_radar_threshold()`, ahead of the auto value |
| `intelfeed:signal_engine:feedback_nudge` | `recompute_signal_rates` (from votes) | `get_feedback_nudges()` at score time |

### Shadow vs surface rollout

- **Shadow** (`signal_engine_shadow`): scores are computed and stored; the UI does not change. Compare with `GET /api/entries/triage?mode=signals`.
- **Surface** (`signal_engine_surface`): triage defaults to the signal ranking, entry lists get chips and the `radar` sort, and `entry_scored` SSE fires.

Both are on by default. See [Enabling the engine](#enabling-the-engine-runbook).

---

## Triage surfacing

### Signal-mode triage queue

`GET /api/entries/triage` picks its ranking per request: `mode=legacy` or `mode=signals` wins; otherwise `signal_engine_surface` decides.

- **Legacy** (`get_triage_entries`, `backend/app/services/triage.py:71`): a live composite of PIR, correlation, automation, CVE risk, reliability and engagement.
- **Signals** (`get_triage_entries_signals`, `backend/app/services/triage.py:354`): one indexed scan over stored scores at or above the threshold, plus one batched fetch of their signals, returned as `priority_reasons`.

Per-user adjustments in signals mode, applied when reading:

- **Muted** entities hide matching entries completely.
- **Watched** entities add the watch's boost (default 1.0) to the sort value and bypass the threshold, so they show up even below the Radar line.

### Entry-list chips and radar sort

With surfacing on, the entry list (`list_entries`, `backend/app/api/entries.py:447`) loads signals for the page. Each item carries `priority_score`, up to 2 non-echo `top_signals`, and `is_echo`. Score and chips are filled only when the entry clears the threshold; `is_echo` is always set so re-reports can be dimmed. `sort=radar` orders by score with a score-based cursor and, with surfacing on, lists only entries above the threshold, matching the Priority Queue badge (`GET /api/entries/priority-unread-count`). Chips render in `frontend/src/components/SignalChip.tsx`.

### Story threads in the ranked queue

The Priority Queue (`/priority-queue`) is a second, ranked entry list: `MainLayout` in `priorityMode`, which mounts `EntryList` with `sortOverride="radar"` and `withThreads`, a docked reader, and a "Why it's ranked" card (`frontend/src/components/WhyRankedCard.tsx`). It folds **story threads** into the list as single rows.

Ranking and folding happen on the server (`build_priority_queue`, `backend/app/api/entries.py:1431`). The endpoint lists open threads with something unread, scores each one by its best **unread, non-echo** member, and merges them into the radar-ordered entries so a thread appears just before the first entry it outranks. Every member of a live thread is held back from the list as a standalone entry, including members on later pages. A thread with nothing unread is not shown.

The client only flattens the response into rows (`queueItems`, `frontend/src/utils/threads.ts:39`) and adds day dividers. The cursor carries both the entry position and the thread position, so paging never repeats a thread.

*Temporal convergence clusters* (unnamed, unsaved entity-overlap groups) are not part of the queue. `GET /api/intelligence/temporal-clusters` serves them to the copilot and the triage widget. See [story-threads.md](story-threads.md) for how threads are built.

### Automation integration

Automation rules can use signal results through three conditions in `backend/app/automation/conditions.py`: `priority_score_above` (`_eval_priority_score_above`, `backend/app/automation/conditions.py:258`; 0–10 score ≥ `config.min`), `has_signal` (`_eval_has_signal`, `backend/app/automation/conditions.py:274`) and `entity_watchlisted` (`_eval_entity_watchlisted`, `backend/app/automation/conditions.py:328`). Scoring is the last chord step, while `automate` is dispatched separately, so an `on_new_entry` rule usually sees no score yet. To react to scores, use the **`on_entry_scored`** trigger, which fires after the score is saved, on first scoring only. See [automation-ai-enrichment.md](automation-ai-enrichment.md).

### Entity "what's new" developments

Entity profiles show recent signals for that entity's entries through `GET /api/engine/entities/{type}/{id}/whats-new`, limited to eight types (novel entity, resurgence, new pairing, scoop, KEV added, EPSS jump, weaponized PoC, under-reported) from the last 14 days by default (`days`, at most 90). Visitors in public read-only mode may read it. It renders in the profile's assessment block (`frontend/src/components/entityProfile/AssessmentBlock.tsx`, via `useEntityWhatsNew` in `frontend/src/hooks/useEngine.ts`).

---

## Ops console & observability

### Settings → Engine console

The console is at `/settings?section=engine` (admin only; `/workbench/engine` redirects there, keeping the query string). `frontend/src/components/engine/EngineSection.tsx` hosts one table card (`EngineMatrix.tsx`) with six views. A `?view=` query (`entries`, `entities`, `links`, `relationships`, `review`, `feeds`) opens one directly:

- **Entries** (default): recent entries as rows and stages as columns, with ✓ / ✕ badges and peek popovers (`GET /api/engine/processing`). The **analyze** and **adjudicate** columns come from the entry's `ai_analysis_requests` row when no run exists (queued, waiting, copied from a near-duplicate, or skipped with the reason). Timing and Output lenses show how long each stage took and what it produced. A drawer (`EntryOutputs.tsx`) inspects and undoes one entry's outputs. Each stage header opens a stage panel (`StagePanel.tsx`) with recent runs, retry buttons and that stage's settings: `AnalyzeStageConfig.tsx` (the one-pass AI switch, model, budget, gates, denylist) and `ScoreStageConfig.tsx` (family multipliers, threshold override, firing rates and weights, watchlist).
- **Entities**: entities the analysis created that nobody has confirmed yet, to confirm, merge, convert or delete (`ExtractionTab.tsx`).
- **Links**: entry ↔ entity links (`AutolinkingSection.tsx` over `GET /api/entity-links`).
- **Relationships**: entity ↔ entity edges (`AutolinkingSection.tsx` over `/api/entity-relationships`).
- **Review**: everything the AI wants a person to approve (`ProposalsQueue.tsx`). Two lenses: **Proposals** (every pending proposal from both logs, one row per entity) and **History** (applied changes, with Restore). A Proposals row (`GET /api/admin/hygiene/review-groups`, newest first by default; also most proposals, oldest or highest confidence) folds every proposal about one entity: the backend files one per article, so "Linux" collects hundreds of remove-link proposals and a mis-filed malware a reclassify per mention. The row shows what each kind wants (remove links, link a held match, a type to convert to, a merge target, a veto), its buttons settle every article's copy at once (Remove links, Link, the type chips, Merge, Delete, Dismiss), and it expands to the articles behind it with per-row Apply and Dismiss. Every button, the expansion, Apply all and Dismiss all act on what the filters show, never more. Rows about something other than a catalogue entity (a relationship edge, an article's assessment) stand alone. A dismissal sticks: a type change isn't proposed again, a duplicate review's merge marks the pair not-duplicate, and an adjudicator verdict isn't filed or applied again for that article (`proposal_dismissals`). Every row carries the same "⋯" entity menu as the Entities view (`EntityRowActions.tsx`: merge into, rename, add alias, convert type, delete + never recreate), so the entity a proposal is about can be fixed without opening its profile; deleting one clears every pending proposal about it. Deleting, merging away or reclassifying an entity anywhere (profile, Review, merge endpoints, tools) closes its pending proposals and the ones that point at it (a merge proposal into a merged-away entity moves to the keeper). The queue, the pending feed and the counts all leave out proposals about an entity that is gone, and vendor links to a vendor that is gone; the nightly prune deletes any such rows left. An Apply that finds its outcome already reached (the article or edge is gone, an analyst rejected the edge) closes the proposal. Each expanded row shows the article text around the match. `POST /api/admin/hygiene/decisions` takes a reviewed batch of apply / dismiss / reclassify decisions in one call; the `list_review_groups`, `get_review_rows` and `decide_proposals` tools wrap the queue for skills. Beside the Proposed / Applied switch, **⚙ Settings** opens the adjudicate stage's panel above the table (the same panel as the adjudicate column on Entries: mode, confidence floor, reclassify consensus, circuit breaker, review scope, the duplicate review's batch and floor), and **Generate proposals** is a menu of the scans that file more rows (duplicate review, name fixes, alias trims, vendor links, TTP/CVE id fixes). The facet counts, the tab badge (`pending_total` from `GET /api/admin/hygiene/stats`) and the chips all come from the same index as the table, so they agree with it.
- **Feeds**: feed health and feed, rate-limit and image-proxy settings.

Above the table: a pulse dot (red while any entry is stuck), an ingest sparkline, the window's counts, and a **Needs you** strip of shortcuts (stage errors, duplicate candidates, entities to reclassify, adjudication verdicts). At the right end sit the time window (1h, 24h, 7d, 30d or All), the setting finder, **Clear check engine** ([Clearing the check-engine light](#clearing-the-check-engine-light)) and the **Stop engine** button ([Stopping the engine](#stopping-the-engine)). The one window covers Entries (entries ingested in it), Entities (first seen in it), Links (extracted in it) and Relationships (created in it). Feeds and Review show what stands now, so the window hides there; the duplicate-candidates chip counts all time and opens Entities on All.

Five more views open as full pages with a back button (`BrowseView`, `frontend/src/components/engine/EngineMatrix.tsx:42`): **Jobs** (schedules from `JOB_REGISTRY` plus Redis overrides in `JobSchedules.tsx`, and run history from `GET /api/engine/job-runs`), **Plans** (`PipelinePlans.tsx`), **Enrichment** (sources), **Maintenance** (`MaintenancePanel.tsx`: sweeps, resets and on-demand scanners), and **Publishing** (`PublishingPanel.tsx`: outbound observable feeds). The console keeps its open tab in the URL (`?view=`, and `?lens=history` on Review), so Back from a page it links to returns to that tab; old `?tab=` and `?section=` links are mapped onto these views (`legacyState`, `frontend/src/components/engine/EngineSection.tsx:40`). Every setting the console shows is listed in [engine-settings.md](engine-settings.md).

### Stopping the engine

The **Stop engine** button at the right of the Engine top bar stops all background work. Use it to freeze the app while you fix something, run a big cleanup, or take load off the server. **Start engine** picks everything up where it stopped, easing back to full speed over a few minutes.

While the engine is stopped:

- No feeds are polled, and the Telegram listener doesn't fetch new messages.
- No AI analysis, adjudication, summaries or other background AI runs.
- No enrichment requests leave the server. It works like the Enrichment console's **Pause all sources**, and starting the engine doesn't clear a pause you set yourself.
- No automations and no scheduled jobs run.
- Work that was already queued waits. A task that was already running finishes.

Reading, search and editing keep working, and so does AI you run yourself from a page (an entity's AI tab, AI on an entry, the copilot on Ollama). A red banner shows on the Engine pages with the number of queued tasks.

How it works: the button saves the `engine_stopped` setting in the database (`backend/app/services/engine_switch.py`). Each Celery worker reads it every 10 seconds and stops taking tasks off its queues, so queued work stays in Redis. On a start, each worker runs one task at a time at first and adds a process back every minute until it's at full size, so a backlog drains gradually instead of all hitting the database at once. Beat skips scheduled jobs while it's on, so they don't all run at once on the start. A job that was due runs at its next normal time. Both live in `backend/app/workers/engine_gate.py`. The switch is never kept in Redis, so a Redis restart or wipe can't start a stopped engine. Every task and queue is covered without extra code, including ones added later. A background process that isn't a Celery task (like the Telegram listener) has to check `is_stopped()` / `is_stopped_async()` itself.

### Clearing the check-engine light

The engine icon in the header is red while an entry is stuck at a stage and amber while stages retried in the last 24 hours. Some failures you know about and choose to leave: a feed worth keeping that errors now and then, or an entry that can't be retried. **Clear check engine**, beside **Stop engine**, turns the light green until a new error or retry comes in. It's greyed out while there is nothing to clear.

Clearing hides nothing in the console: the errors stay in the Entries view and the Needs you strip, and the light's hover card says how many older errors are still there. The clear time is kept in Redis (`engine:health_cleared_at`, set by `POST /api/engine/state/clear-health`), so a Redis wipe just turns the light back on. `GET /api/engine/pipeline` returns `new_error` and `new_retry` per stage: the counts since the clear, which the light reads.

### `entry_pipeline_runs` — per-entry stage observability

One row per stage run per entry, written by `@pipeline_stage`. Used by:

- The **entry processing popover** (`frontend/src/components/EntryPipelineStatus.tsx`) via `GET /api/engine/entries/{entry_id}/runs`: the latest run per stage, with labels from `PIPELINE_STAGE_LABELS` (`backend/app/api/engine.py:392`).
- The **stage drill-down** via `GET /api/engine/pipeline/stages/{stage}/runs`, filterable by status.
- The **Entries view** via `GET /api/engine/processing`.
- **Retry**: `POST /api/engine/entries/{entry_id}/stages/{stage}/retry` re-sends the stage's task with the entry id. Only stages in `RETRYABLE_STAGE_TASKS` (`backend/app/api/engine.py:409`) qualify. `automate` (needs a feed id) and `translate` (needs a target language) are excluded. A manual `adjudicate` retry skips the enqueue gates and checks only the mode. `POST /api/engine/pipeline/retry-errors` does the same for every stage still stuck on an error at once (optionally one stage, scoped to the ingest window); the Entries view shows it as **retry all** next to the error filter. An entry whose stage has since re-run green is left alone.

### `job_runs` — scheduled-job history

Celery signal handlers in `backend/app/workers/task_tracking.py` (`task_prerun`, `task_postrun`, `task_failure`, `task_retry`) record runs of `JOB_REGISTRY` tasks only. Per-entry pipeline tasks would add about 100,000 rows a day and are already in `entry_pipeline_runs`. Each row has status, duration, error, and a size-limited `detail` with the args and result. The handlers never let a tracking error break a task.

### Retention: `prune_engine_tables`

`prune_engine_tables` (`backend/app/workers/maintenance.py:885`; job `prune-engine-tables`, daily 02:40 UTC) deletes rows older than `engine_run_retention_days` (default 30) from `entry_pipeline_runs`, `job_runs`, non-pending `ai_analysis_requests` and `ai_batch_jobs`, and deletes resolved `pending_autolink_matches`. Unresolved held matches expire after 14 days (their article never got an analysis). It also expires old link-validator proposals that nothing re-judges (`expire_legacy_link_proposals`, `backend/app/services/proposal_dismissals.py`). `entry_signals` is never pruned; signals live as long as their entry.

---

## API endpoints

The engine router is mounted at `/api/engine`. Every route needs a signed-in user except `whats-new`, which public read-only visitors may also read. Routes that change something, plus `/processing`, need an admin (`_require_admin`, `backend/app/api/engine.py:15`).

| Method & path | Purpose |
|---|---|
| `GET /signals/stats` | Firing rates, weights, families, multipliers, threshold, and a health block (flags, unscored recent entries, last job runs, vote counts against the minimum, current nudges) |
| `PUT /signals/settings` | Admin: family multipliers (0–2) and threshold override. A multiplier change rescores the last 168 hours (up to 2,000 entries) |
| `GET /entities/{type}/{id}/whats-new` | Recent signals for an entity's entries |
| `GET /extraction/status` | One-pass AI health: queue by status, today's spend against the budget, last batch |
| `GET /pipeline` | Stage registry, 24-hour run counts, engine flags |
| `GET /processing` | Admin: data for the Entries view |
| `GET /pipeline/stages/{stage}/runs` | Recent runs of one stage (limit ≤200, optional status filter) |
| `GET /entries/{entry_id}/runs` | Latest run per stage for one entry |
| `GET /entries/{entry_id}/adjudication` | What the adjudicate stage decided for one entry |
| `POST /entries/{entry_id}/stages/{stage}/retry` | Admin: re-run one retryable stage |
| `GET /plans` | List pipeline plans |
| `PUT /plans` | Admin: create or update a plan by scope (checks stage names, bumps the plan version) |
| `DELETE /plans/{plan_id}` | Admin: delete a plan. Global plans cannot be deleted |
| `GET /job-runs` | Recent job runs, optional `job_key` filter (limit ≤500) |
| `GET /state` | Whether the engine is stopped, and how many tasks wait on each queue |
| `PUT /state` | Admin: stop or start the engine (`{"stopped": true}`). See [Stopping the engine](#stopping-the-engine) |
| `PUT /radar-feedback` | Vote on a Radar item (1 / −1 / 0 clears) |
| `GET`/`PUT`/`DELETE /my-radar` | Your learned Radar weights: read, opt in or out, reset |
| `GET`/`POST`/`DELETE /autolink/fp-names` | Admin writes: the false-positive name list (`autolinker_false_positive_names`). Vendors, products, tools and mitigations ignore it |
| `GET`/`POST`/`DELETE /autolink/blocked-names` | Admin writes: hard blocks (`autolinker_blocked_surface_forms`), enforced for every entity type |

A second router at `/api/engine/extraction` (`backend/app/api/extraction.py`) backs the Entities view: `GET /stats`, `GET /entities`, `POST /confirm`, `POST /not-duplicate`, `POST /delete`, and `GET`/`POST`/`DELETE /denylist`.

Related endpoints elsewhere:

- `GET /api/entries/triage?mode=legacy|signals`: the triage queue.
- `GET /api/entries?sort=radar`: entries by priority, with chips.
- `GET /api/entries/priority-queue`: the Priority Queue, with threads folded in.
- `GET /api/entity-links` (plus `/stats`, unlink, bulk unlink): the Links view (`backend/app/api/entity_links.py`).
- `GET /api/intelligence/temporal-clusters`: temporal clusters for the convergence widgets.
- Job schedule editing lives on the jobs router; see [workers-search-dashboards.md](workers-search-dashboards.md).

Frontend hooks for all of these: `frontend/src/hooks/useEngine.ts`.

---

## Key tables

Full schemas are in [data-model.md](data-model.md).

| Table | Model | Role |
|---|---|---|
| `entry_signals` | `backend/app/models/entry_signal.py` | One row per (entry, signal type): strength 0–1, explanation, evidence. Upserted on rescore; deleted with the entry |
| `entry_signal_feedback` | `backend/app/models/entry_signal_feedback.py` | One Radar vote per user per entry (±1) |
| `pipeline_plans` | `backend/app/models/pipeline_plan.py` | Stage plans; one per (scope_type, scope_id) |
| `entry_pipeline_runs` | `backend/app/models/entry_pipeline_run.py` | One row per stage run; pruned after the retention period |
| `job_runs` | `backend/app/models/job_run.py` | Scheduled-job runs; pruned after the retention period |

`entries` also has `priority_score` (0–10, indexed, NULL = never scored), `priority_raw` (the sum it is scaled from, indexed, used for ordering) and `scored_at`.

---

## Enabling the engine (runbook)

On a fresh install `signal_engine_shadow` and `signal_engine_surface` are both on, so new entries are scored and shown from the start. These steps are for an install that has them off (or wants to check the ranking before showing it). Settings are per environment.

1. **Shadow first.** Turn on `signal_engine_shadow` (Settings → Engine → score stage) and leave surface off. New entries are scored; the UI does not change.
2. **Backfill.** Run `backfill_entry_scores` by hand (default: last 14 days, 500 per batch). It only scores entries with `scored_at IS NULL`, and it does nothing if both flags are off. The 6-hourly rescore also picks up unscored entries, but only in its 72-hour window.
3. **Let the weights settle.** Run (or wait for) `signal-rate-recompute`, so the weights, cutoffs and threshold reflect your real data instead of the defaults.
4. **Check.** Compare `GET /api/entries/triage?mode=signals` with the legacy ranking for about a week. Adjust family multipliers on the score stage card if one family dominates.
5. **Surface.** Turn on `signal_engine_surface`.
6. **Pipeline plans** are separate. Turn on `pipeline_engine_enabled` when you want plans. Turning it off returns to the feed switches at once, because those switches are still the base every plan starts from.

## Operational notes

- **Plan edits outside the API wait for the cache.** The API bumps the plan version on every write. A direct database edit to `pipeline_plans` without `bump_plan_version()` takes up to 600 seconds to apply.
- **Global plans cannot be deleted** through the API. Deactivate or empty them instead.
- **Turning off run logging** stops new `entry_pipeline_runs` rows; existing rows stay until they are pruned.
- **Retry re-runs one stage only.** Stages are idempotent (they upsert), so a retry is safe, but it does not re-trigger the stages after it.
- **`feed_echo` never hides anything.** It lowers the score and sets `is_echo`; dimming is a display choice, not a filter.
- **A failed signal check drops only that signal.** Each check is wrapped (`_guarded`, `backend/app/intelligence/signals.py:1114`): an exception logs a warning, increments `intelfeed_signal_probe_failures_total{probe}`, and the entry is scored without that signal. `intelfeed_entry_signals_fired_total{signal_type}` counts firings. `_collect_links` is not wrapped, because every signal needs it; its failure fails and retries the task.

---

## Tests

- `backend/tests/test_pipeline_registry.py`: the chord built from the registry, plan gating, the forced-autolink fallback, the translate prologue, plan resolution, and the plans and pipeline endpoints.
- `backend/tests/test_signal_engine.py`: each signal, the IDF and multiplier math, persistence and upserts, signals-mode triage with watch and mute, entry-list chips, `@pipeline_stage`, the runs and retry endpoints, `job_runs`, the automation conditions, and Radar feedback.
- `backend/tests/test_triage.py`: legacy triage scoring.

Run them from `backend/` in the host venv, or in the api container:

```bash
# host venv, from backend/
pytest tests/test_pipeline_registry.py tests/test_signal_engine.py -x -q

# or in the dev api container, from the repo root
docker compose -f docker-compose.dev.yml exec api pytest tests/test_pipeline_registry.py tests/test_signal_engine.py -x -q
```
