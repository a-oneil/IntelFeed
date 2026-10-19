# Engine — Pipeline, Signals, and Ops Console

## Overview

"The engine" is the umbrella for three related subsystems built out during the 2026 engine plan (`planning/platform-review-and-engine-vision.md`, phases 1–6):

1. **Pipeline engine** (`backend/app/pipeline/`) — the entry processing chain expressed as data: a code-defined **stage registry** plus data-defined **pipeline plans** (feed > category > global) that decide which stages run for a feed and with what config.
2. **Signal engine** (`backend/app/intelligence/signals.py`, `backend/app/workers/signal_tasks.py`) — explainable per-entry signals and an IDF-weighted priority score that powers the Radar/triage ranking, entry-list chips, and a bounded analyst feedback loop.
3. **Engine console** (`backend/app/api/engine.py` + Settings → Engine in the frontend) — a single-surface "living table" for pipeline configuration, edge/entity management, scheduled-job run history, and per-entry stage observability backed by the `job_runs` and `entry_pipeline_runs` tables.

All three are behind runtime flags that live in the **`system_settings` DB table** (editable at Settings → Engine, admin-only — every one of them is catalogued in [engine-settings.md](engine-settings.md)), resolved through the standard config override chain (`backend/app/config.py` defaults → DB override via `get_setting`). The `.env`/`config.py` defaults are all off/safe, so a fresh deploy runs the legacy behavior until flags are flipped in the UI:

| Flag | Default | Effect |
|---|---|---|
| `signal_engine_shadow` | `false` | Compute + store signals and priority scores; no UI change (`backend/app/config.py:48`) |
| `signal_engine_surface` | `false` | Surface scores: entry-list chips, Radar-ranked triage, SSE `entry_scored` events (`backend/app/config.py:49`) |
| `radar_personalization_enabled` | `false` | Apply each analyst's learned family weights as a read-time lift on their own Radar ordering (`radar_personalization_min_samples` = 5, `radar_personalization_window_days` = 90) |
| `pipeline_run_logging_enabled` | `true` | Kill switch for per-entry stage run logging (`backend/app/config.py:77`) |
| `pipeline_engine_enabled` | `false` | Stage composition from pipeline plans instead of legacy feed booleans (`backend/app/config.py:80`) |

Setting metadata (types, labels, help text, console groups) is registered in `backend/app/services/system_settings.py`: `CONFIGURABLE_KEYS` (`system_settings.py:19`) declares which keys are DB-overridable and their expected type, `SETTING_METADATA` (`system_settings.py:186`) carries the label/description/group shown in the UI, and `_ENGINE_SECTION_GROUPS` (`backend/app/services/system_settings.py:1195`) re-groups the engine-owned keys onto Engine console sections. Every one of them is catalogued in [engine-settings.md](engine-settings.md). Because these are DB-backed, toggling them in a dev stack does **not** carry to production — they must be re-enabled per environment.

Related docs: [entries.md](entries.md) (full entry lifecycle), [intelligence-engine.md](intelligence-engine.md) (autolinker/correlation internals the pipeline stages call into), [data-model.md](data-model.md) (table schemas), [workers-search-dashboards.md](workers-search-dashboards.md) (Celery layer and beat schedules).

---

## Pipeline stage registry

`backend/app/pipeline/registry.py` defines the entry processing chain as data. Each stage is a frozen `StageDef` (`registry.py:25`) with a `name`, a `kind`, an optional Celery `task_path`, a description (shown on the Engine UI stage cards), a `default_enabled` flag, and a jsonschema-ish `config_schema` hint for the config panel.

### Stage kinds

Documented in the module docstring (`registry.py:1-19`):

| Kind | Execution | Notes |
|---|---|---|
| `inline` | Synchronously inside the fetch loop | Documented for the Engine UI only; never dispatched as Celery tasks |
| `pre` | Chained ahead of the chord | Output (e.g. translated text) visible to every later stage; must never raise or the whole chain dies |
| `parallel` | First chord header, after entry creation | `autolink` ∥ `observables` ∥ `telegram_links` ∥ `extract` |
| `post` | Second chord header | Runs after all parallel stages complete |
| `final` | Second chord callback | Signal scoring — the terminal chord stage |
| `post_analysis` | Dispatched from wherever the one-pass AI analysis lands, minutes to hours after `score` | `adjudicate` — never part of the chord; the registry row gives it a matrix column, a plan chip, run logging |
| `side` | Dispatched independently of the chord | Automation, enrichment |

### Stage catalog

The full registry (`registry.py:35-144`):

| Stage | Kind | Task | Default |
|---|---|---|---|
| `sanitize` | inline | — (nh3 allowlist + text extraction during fetch) | on |
| `dedup` | inline | — (GUID + cross-feed content-hash) | on |
| `relevance` | inline | — (keyword score; gates selective autolink + AI junk filter) | on |
| `index` | inline | — (Meilisearch, with failed-index retry queue) | on |
| `translate` | pre | `translation_tasks.translate_entry_task` | on |
| `autolink` | parallel | `intel_feed_tasks.autolink_entry_task` (dictionary-word matches go to the pending tier — see [intelligence-engine.md](intelligence-engine.md)) | on |
| `observables` | parallel | `intel_feed_tasks.observables_entry_task` — stages entry-local candidates (refang + precision regex), sights known ledger values, parses curated `ioc_list` bodies. Regex never creates a ledger row | on |
| `telegram_links` | parallel | `telegram_link_tasks.scan_telegram_links_task` | on |
| `extract` | parallel | `intel_feed_tasks.extract_entry_intel_task` — regex intel extraction (TTP/CVE/mitigation IDs, detection rules); AI analysis runs via the batch queue | **off** (historical: only when `feed.auto_extract_on_ingest`) |
| `cooccurrence` | post | `intel_feed_tasks.create_cooccurrence_relationships_task` | on |
| `correlation` | post | `automation_tasks.detect_correlation_events` | on |
| `requirements` | post | `intel_feed_tasks.match_requirements_task` | on |
| `score` | final | `signal_tasks.score_entry_task` — signal scoring **and** the one-pass AI analysis enqueue | on |
| `adjudicate` | post_analysis | `adjudication_tasks.adjudicate_entry_task` — AI review of everything the analysis wrote to the entry (links of every source, minted entities with nearest catalogue names, asserted edges, AI observables); verdicts filed as proposals or applied per `adjudication_mode`. See [engine-settings.md](engine-settings.md#adjudicate-stage-post-analysis-ai-review) | on (mode `off` by default — the mode is the master switch because plans are off in prod) |
| `enrich` | side | `enrichment_tasks.auto_enrich_entity` | on |
| `automate` | side | `automation_tasks.run_entry_automations` | on |

`stages_of_kind(kind)` (`registry.py:146`) is the only accessor; the chord builders and the Engine API both iterate the registry rather than hard-coding task names. `tests/test_pipeline_registry.py` asserts the chord built from the registry is structurally identical to the previous hand-built dispatch.

---

## Pipeline plans (feed > category > global resolution)

`PipelinePlan` rows (`backend/app/models/pipeline_plan.py`) hold data-defined stage composition per scope:

- `scope_type`: `global` | `category` | `feed`, with `scope_id` for the latter two; one plan per scope (`uq_pipeline_plan_scope`).
- `stages`: JSONB `{stage_name: {"enabled": bool, "config": {...}}}` — **partial**. Anything unspecified falls through to the next scope down and ultimately to values synthesized from the legacy `Feed` booleans.

Resolution lives in `backend/app/pipeline/plans.py`:

1. **Flag gate** — `resolve_feed_plan()` (`backend/app/pipeline/plans.py:116`) returns `None` when `pipeline_engine_enabled` is off; callers then use the legacy `run_extraction` boolean path. This is the instant-rollback lever.
2. **Base layer** — `synthesize_from_feed()` (`plans.py:28`) produces a plan from the feed's own columns: every stage at its registry default, except `extract`, which is enabled iff `feed.auto_extract_on_ingest` or `feed.extract_detection_rules`, with `{mode, detection_rules}` config from the feed columns. The legacy booleans stay authoritative until a follow-up migration drops them; synthesizing at resolve time (not snapshotting) avoids drift.
3. **Overlay** — active `PipelinePlan` rows for the feed's scopes are merged in order `global → category → feed` (`plans.py:104-110`); `_merge()` (`plans.py:47`) overrides `enabled` per stage and dict-merges `config`.
4. **Cache** — resolutions are cached in Redis per feed under `intelfeed:pipeline_plan:{feed_id}:{version}` with a 600s TTL (`plans.py:23-25`). Any plan write bumps `intelfeed:pipeline_plan:version` via `bump_plan_version()` (`plans.py:58`) — the same version-key invalidation pattern as the autolinker vocabulary. Resolution happens once per feed fetch, not per entry.

`resolve_feed_plan` is called at each ingest path in `backend/app/workers/feed_tasks.py` (`:620`, `:1092`, `:1221`, `:2002`) before entries are dispatched.

### Worked example

Feed "Vendor Blog X" has `auto_extract_on_ingest = false`, sits in category "Vendor Research", and these active plans exist:

```jsonc
// global plan
{ "telegram_links": { "enabled": false } }

// category plan for "Vendor Research"
{ "extract": { "enabled": true, "config": { "mode": "full" } } }

// feed plan for "Vendor Blog X"
{ "extract": { "config": { "detection_rules": true } } }
```

Resolution:

1. Synthesis from the feed booleans: `extract` disabled with `{mode: "selective", detection_rules: false}`; everything else at registry defaults.
2. Global overlay: `telegram_links` → disabled.
3. Category overlay: `extract` → enabled, config merged to `{mode: "full", detection_rules: false}`.
4. Feed overlay: `extract.config.detection_rules` → `true` (the `enabled` key is absent, so the category's `true` stands).

Final parallel header for this feed's entries: `autolink` ∥ `observables` ∥ `extract` (full mode, with detection rules). Partial overlays mean a feed plan can tweak one config key without restating the stage's enablement.

---

## Stage execution flow

Diagram: [diagrams/engine-pipeline-execution.md](diagrams/engine-pipeline-execution.md)

`dispatch_entry_pipeline()` (`backend/app/workers/feed_tasks.py:117`) builds the per-entry Celery structure from the registry:

1. **Parallel header** — one immutable signature per enabled `parallel` stage. With a resolved plan, `plan[stage]["enabled"]` decides; without one (legacy), everything runs except `extract`, which follows `run_extraction`. If the plan disables *all* parallel stages, `autolink` is forced back in (`feed_tasks.py:148-153`) so the chord always has a header and downstream stages still fire.
2. **Translate prologue** — for feeds with `auto_translate` in `adapter_config`, the `translate` stage is `chain`ed ahead of the chord (`feed_tasks.py:157-166`) so autolink/extract/relevance/scoring all see translated text. `translate_entry_task` swallows every failure and returns a status string — a raised prologue would stop the chain and silently skip the whole pipeline.
3. **First callback** — `entry_post_processing` (`feed_tasks.py:75`) runs when the header completes. It builds a **second chord**: all `post` stages (`cooccurrence`, `correlation`, `requirements`) as the header, with the single `final` stage (`score`) as callback. Note: plan gating applies to the parallel header only — post/final stages always run (scoring no-ops on its own flag).
4. **Final callback** — `score_entry_task` runs once co-occurrence edges, correlation events, and requirement matches all exist, because those are the signal engine's inputs. It accepts positional args since Celery passes the chord header results as the first argument (`backend/app/workers/signal_tasks.py:39-44`).
5. **Side dispatches** — `automate` and `enrich` are sent independently of the chord (automation per entry from the fetch loop; enrichment triggered by entity creation).
6. **After the analysis lands** — `services/entry_adjudication.enqueue_adjudication` runs at each of the one-pass analysis landing sites (batch ingest, sequential task, echo reuse, manual run) right after their commit, walks the gates (mode → feed plan → echo → trigger → score floor → hourly budget), records the decision on `ai_analysis_requests.adjudication_status`, and dispatches `adjudicate_entry_task` on the `ai` queue. The task's return dict becomes the run's `detail` (verdict counts) via `@pipeline_stage`, which the matrix's Output lens renders.

### Per-stage run logging

Every non-inline stage task is wrapped with `@pipeline_stage("<stage>")` from `backend/app/workers/pipeline_logging.py:61`, applied *below* `@celery_app.task`. On completion it writes one terminal `entry_pipeline_runs` row (`success` / `error` / `retry`, duration, clipped error) — no "running" rows. Properties:

- **Never raises** — logging failure must not break a task (`pipeline_logging.py:35-59`).
- **Kill switch** — gated by `pipeline_run_logging_enabled` checked inside the write.
- **Metrics untouched** — the decorator deliberately does not subsume the tasks' existing Prometheus counters; doing both would double-count `CELERY_TASKS_TOTAL` (deviation from the original plan, noted in the module docstring).
- Entry id extraction handles both `entry_id=` kwargs and positional UUIDs (skipping `self` on bound tasks).

---

## Signal scoring model

Diagram: [diagrams/engine-signal-scoring.md](diagrams/engine-signal-scoring.md)

`backend/app/intelligence/signals.py` computes **explainable, rare-by-construction signals** per entry; the priority score is a weighted sum where each signal type's weight self-tunes to its 30-day firing rate (IDF-style). A signal firing on half the river contributes almost nothing; one firing on 0.5% of entries contributes a lot.

### Signal catalog

16 signal types across 5 families (`SIGNAL_FAMILIES`, `signals.py:51-68`); raw scores are 0..1:

| Signal | Family | Fires when (implementation) |
|---|---|---|
| `novel_entity` | novelty | Linked actor/malware/tool has ≤3 prior articles or `first_seen_at` within 14 days; CVEs by first-seen recency only (`_novel_entity`, `backend/app/intelligence/signals.py:509`) |
| `entity_resurgence` | novelty | Known entity's previous coverage is >90 days old; score scales with gap up to 365d (`_entity_resurgence`, `backend/app/intelligence/signals.py:567`); only checked when `novel_entity` didn't fire |
| `new_pairing` | novelty | A co-occurrence `EntityRelationship` created in the last hour has this entry as its *only* evidence, for interesting type pairs (actor+malware, actor+country, malware+CVE, actor+tool) (`_new_pairing`, `backend/app/intelligence/signals.py:605`) |
| `scoop` | novelty | `novel_entity` fired, no echo, and the feed's `reliability_rating` is A or B (`signals.py:1030-1038`) |
| `source_convergence` | coverage | ≥3 independent outlets on this entry's [story thread](story-threads.md); for an entry no thread holds, ≥3 sources (distinct domains, not feeds) sharing ≥2 entities within 24h |
| `under_reported` | coverage | Severe CVE (KEV, CVSS ≥9, EPSS ≥0.5, or weaponized) that ≤2 feeds have *ever* covered — counted per CVE via the `EntryCVE` junction (`_under_reported`, `backend/app/intelligence/signals.py:958`) |
| `feed_echo` | coverage | The entry's story thread folded it as a re-report; for an entry no thread holds, an **earlier** entry within 72h sharing ≥70% of its ≥3 entities — negative signal |
| `kev_added` | severity | Linked CVE added to CISA KEV within 7 days (`_severity_signals`, `backend/app/intelligence/signals.py:872`) |
| `epss_jump` | severity | Linked CVE's EPSS score actually rose (`epss_previous_score` → `epss_score`) within the last 7 days (`signals.py:769`) |
| `epss_high` | severity | Linked CVE at ≥95th EPSS percentile (`signals.py:785`) |
| `weaponized_poc` | severity | Linked CVE has GitHub PoC repos and `exploit_availability` in (weaponized, poc) (`signals.py:751`) |
| `critical_cvss` | severity | Linked CVE with CVSS ≥9 first seen within the last 90 days — recency-gated so old criticals in retrospectives don't boost forever (`signals.py:805`) |
| `pir_match` | interest | `RequirementMatch` rows exist; score = count/3 capped at 1 (`_interest_signals`, `backend/app/intelligence/signals.py:1006`) |
| `correlation_event` | interest | `CorrelationEventRecord` rows exist; score by max severity (high 1.0 / medium 0.6 / low 0.3) (`signals.py:912`) |
| `detection_content` | content | Entry has extracted `DetectionRule` rows (`_content_signals`, `backend/app/intelligence/signals.py:1065`) |
| `research_depth` | content | ≥1500 words and (≥3 TTPs or detection rules) (`signals.py:938`) |

**Both coverage signals prefer the story thread.** Shared entities inside a
72-hour window were always a proxy for the question a thread answers directly —
is this the same story, and how many outlets carried it. The proxy misses every
re-report of a story with nothing extractable in it, and fires on two genuinely
different stories that happen to share an actor and a CVE. So when the sweeper
has placed an entry, its verdict is the signal: `role = 'echo'` is the echo,
`source_count` is the corroboration, and a *beat* is explicitly not an echo no
matter how many entities it shares with earlier coverage. Threading runs up to
30 minutes behind ingest, so this lands on a rescore
(`rescore_entries_for_threads`, dispatched by the sweeper for every thread whose
membership changed — one more outlet re-scores the whole story, not just the
newcomer). Switchable at Engine → Score stage → Story threads →
**Score From Threads**; off, or for the 44% of the corpus too short to thread,
the entity probe below is still the answer.

The entity-overlap probes share one junction-union query (`_feed_echo`, `backend/app/intelligence/signals.py:741`) and exclude **mega-entities** (>500 linked articles, `MEGA_ENTITY_ARTICLE_COUNT`, `signals.py:107`) so "Microsoft"-scale entities neither make everything an echo nor blow up the scan. This is the only fan-out query; everything else is index-backed. Time-window signals anchor on the entry's own timeline (`published_at`, else `fetched_at`) so re-scores and backfills reproduce the same facts.

### Weights: IDF, multipliers, echo

`compute_priority_score()` (`signals.py:138`):

```
score = Σ  raw_score × idf_weight(firing_rate) × family_multiplier
       (feed_echo instead uses a fixed weight of −0.5 × multiplier)
```

- `idf_weight(rate) = log(1/rate) / log(1/0.05)`, clamped to [0.1, 3.0] — a 5% firing rate maps to weight 1.0 (`idf_weight`, `signals.py:133`).
- Firing rates come from Redis (`intelfeed:signal_engine:rates`), falling back to conservative cold-start defaults (`DEFAULT_FIRING_RATES`, `signals.py:81` — e.g. `pir_match` starts at 0.43 because it fires on ~43% of prod entries and must be down-weighted).
- Family multipliers (`novelty`/`coverage`/`severity`/`interest`/`content`, all default 1.0) are global, admin-set, clamped 0–2 — coarse steering on top of the self-tuning weights (`DEFAULT_FAMILY_MULTIPLIERS`, `signals.py:70`).
- `feed_echo` is excluded from IDF: its job is to sink re-reported stories, not to get rarer-therefore-stronger (`ECHO_WEIGHT`, `signals.py:102`).

### The 0–10 scale

The weighted sum is unbounded, so it is stored as `Entry.priority_raw` and placed on a 0–10 scale for everything people and rules read (`Entry.priority_score`, `scale_score` in `signals.py`). The scale ranks the sum against the trailing 30 days of entries that fired at least one signal:

| Score | Means |
|---|---|
| 0 | Nothing fired, or an echo cancelled out what did |
| 1 | The weakest signal-bearing entries |
| 5 | The 60th percentile |
| 8 | The 90th percentile |
| 9 | The 95th percentile (top 5%) |
| 10 | The 99th percentile and above (top 1%) |

Anchors sit on the whole numbers (`SCALE_ANCHORS`); between two anchors the score interpolates linearly in raw units and rounds to one decimal. The raw value at each anchor (the *cutoffs*) is recomputed nightly by `signal-rate-recompute` and cached in Redis. Scoring converts immediately using the cached cutoffs, so a new entry has its 0–10 score as soon as it is scored. The nightly job also re-scales the stored scores of entries scored in the last 90 days (`SCALE_RESCALE_DAYS`) against the new cutoffs, writing only rows whose value changed, in batches of 2,000 so it never holds locks on `entries` for long. Within that window a 7 today and a 7 last month sit at the same rank; older entries keep the scale they were last scored on. The cutoffs reach Redis before the re-scale starts, so new scoring and the stored scores never run on two different scales.

### Persistence

`score_entry()` (`backend/app/workers/signal_tasks.py:99`) computes hits, deletes signals that no longer fire, upserts the rest on `(entry_id, signal_type)` (`uq_entry_signals_entry_type`), and writes `Entry.priority_raw`, `Entry.priority_score` (the 0–10 scale) and `Entry.scored_at`. Re-scoring overwrites, never appends. `entry_signals` rows cascade-delete with their entry.

The task wrapper `score_entry_task` (`signal_tasks.py:39`) no-ops unless `signal_engine_shadow` **or** `signal_engine_surface` is on (`_engine_enabled`, `signal_tasks.py:24`), then also enqueues the entry for one-pass AI analysis (`enqueue_entry_analysis`), dispatches `on_entry_scored` automation rules when any are enabled, and — surface flag only — broadcasts an `entry_scored` SSE event (`signal_tasks.py:56-95`).

### Feedback loop and self-tuning (beat jobs)

Scheduled/dispatchable tasks in `backend/app/workers/signal_tasks.py`, registered in `backend/app/workers/job_registry.py`:

| Job key | Task | Schedule | What it does |
|---|---|---|---|
| `signal-rate-recompute` | `recompute_signal_rates` (`signal_tasks.py:167`) | daily 04:20 UTC (`job_registry.py:630`) | Recomputes 30-day firing rates (distinct entries with signal ÷ entries **scored** in window — not entries fetched, so backfills don't skew the denominator), the 0–10 scale's cutoffs (then re-scales the last 90 days' stored scores that moved), the auto Radar threshold (p95 of the 0–10 `priority_score` over 7 days), and per-family feedback nudges; writes all four to Redis |
| `signal-rescore-recent` | `rescore_recent_entries` (`backend/app/workers/signal_tasks.py:329`) | every 6h at :35 (`job_registry.py:648`) | Re-scores recent entries (default 72h/500) so late severity changes — KEV adds, EPSS jumps — propagate into stored scores. Also sweeps up never-scored entries in the window (unscored first when the limit truncates), so scoring failures self-heal instead of leaving entries permanently off Radar |
| — | `rescore_entries_for_cve` (`backend/app/workers/signal_tasks.py:354`) | event-dispatched | Re-scores entries linked to one CVE (default 14d/200) when that CVE's severity facts change — dispatched via `dispatch_cve_rescore()` (`backend/app/workers/signal_tasks.py:480`) from CVE enrichment events, so KEV/EPSS/exploit changes propagate without waiting for the 6-hourly sweep |
| `signal-personal-weight-fit` | `fit_user_signal_weights` | daily 04:35 UTC | Fits per-analyst family weights from each user's own thumbs into `user_signal_weights`, and drops rows whose evidence aged out of the window or fell below the floor |
| — | `backfill_entry_scores` (`backend/app/workers/signal_tasks.py:520`) | never scheduled | One-shot manual dispatch after enabling shadow mode, so there is historical data to evaluate |

**Radar feedback**: analysts thumb Radar items (`RadarFeedbackButtons.tsx` → `PUT /api/engine/radar-feedback`, verdict 1 = useful / −1 = noise / 0 clears), stored one-per-user-per-entry in `entry_signal_feedback`. The nightly job joins feedback to the signals on those entries, averages verdicts per family, and writes a **bounded nudge** `1.0 + 0.1 × mean(verdict)`; reads re-clamp to 0.9–1.1 (`get_feedback_nudges`, `backend/app/intelligence/signals.py:414`). Families with fewer than `signal_feedback_min_samples` verdicts in the window (default 20, Settings → Engine → score stage) keep a neutral 1.0 — a handful of votes can't swing scoring — and the nudge key is rewritten every night, so families that fall below the floor reset instead of keeping a stale nudge. Nudges multiply the admin family multipliers at score time (`signal_tasks.py:123-125`) — analyst feedback can shade the ranking by ±10%, never dominate it.

**Learned Radar weights (per analyst)**: the nudge above is *global* — every analyst's thumbs pooled into one multiplier baked into the shared `Entry.priority_score`. `fit_user_signal_weights` keeps the same votes separated per user and fits a personal family weight from each analyst's own verdicts: `1 + 0.35 × mean(verdict) × n/(n+8)`, clamped to 0.65–1.35 (`fit_personal_weight`, `signals.py`). The shrinkage term is what stops three enthusiastic thumbs moving a family as far as thirty do, and attribution reuses `attribute_feedback_votes` verbatim, so a vote credits exactly one family — the signal that contributed most to that entry's score.

Weights apply at **read time only**, mirroring My Stack exposure (`backend/app/services/radar_personalization.py`): the Radar query joins a `(entry_id, lift)` subquery over `entry_signals` where `lift = Σ score × idf_weight × (w−1)`, and orders by score + `exposure_lift` + `personal_lift`. Because the per-signal contribution is linear, that sum is exactly what the engine would have scored with the analyst's multipliers — no re-scoring, and switching it off drops the term. Personalisation **re-orders** a `GET /api/entries?sort=radar` page and deliberately does not change its membership: the radar threshold still gates on the global score, so a learned weight can never hide an entry the badge counted. The Priority Queue (`GET /api/entries/priority-queue`) does not apply either read-time lift to its order: it sorts on the stored score its rows display, and the lifts only admit entries (a stack-relevant CVE below the threshold) and decorate them.

Gated by `radar_personalization_enabled` (instance-wide, Settings → Engine → score stage) plus a per-user opt-in in `User.settings["radar_personalized"]`. Settings → Reading → "Your Radar" shows each family's weight, the votes behind it, and both exits: the toggle (back to the house ranking) and a reset that discards the fitted rows. `GET/PUT/DELETE /api/engine/my-radar` back that panel; the reader's "Why it's ranked" card gains a *Tuned for you* row naming the families that moved the entry. When the ordering key is a computed lift, the list query selects it and the cursor carries that exact value — rebuilding it in Python drifts from what Postgres compared and lands rows on two pages.

**Radar threshold**: a value on the 0–10 scale. `get_radar_threshold()` returns the manual override (`intelfeed:signal_engine:threshold_override10`) if set, else the auto p95 written nightly, else the 8.0 default. An override left in the raw-sum key `intelfeed:signal_engine:threshold_override` is converted to the scale on first read. The threshold gates what the Radar shows and which entries get chips.

### Redis state

All mutable tuning state is in Redis (constants at `signals.py:44-48`); Postgres holds only the per-entry outputs. Losing these keys is safe — everything falls back to defaults and the nightly job rewrites them:

| Key | Written by | Read by |
|---|---|---|
| `intelfeed:signal_engine:rates` | `recompute_signal_rates` (nightly) | `get_signal_rates()` at score time, `GET /engine/signals/stats` |
| `intelfeed:signal_engine:multipliers` | `PUT /engine/signals/settings` | `get_family_multipliers()` at score time |
| `intelfeed:signal_engine:scale_cutoffs` | `recompute_signal_rates` (nightly; after a flush, the first scoring run computes it from Postgres and caches it for a day) | `get_scale_cutoffs()` at score time, Priority Queue row scores |
| `intelfeed:signal_engine:threshold10` | `recompute_signal_rates` (auto p95, 0–10) | `get_radar_threshold()` — triage, entry chips |
| `intelfeed:signal_engine:threshold_override10` | `PUT /engine/signals/settings` (manual, 0–10; delete to return to auto) | `get_radar_threshold()` — beats the auto value |
| `intelfeed:signal_engine:feedback_nudge` | `recompute_signal_rates` (from thumbs) | `get_feedback_nudges()` at score time |

### Shadow vs surface rollout

- **Shadow** (`signal_engine_shadow`): scoring runs and persists, nothing changes in the UI. Validate via `GET /entries/triage?mode=signals` against the legacy composite for a week (per the setting's own help text, `system_settings.py:458-466`).
- **Surface** (`signal_engine_surface`): triage defaults to the signal ranking, entry lists gain priority chips and the `radar` sort, `entry_scored` SSE fires. Both flags live in the `system_settings` DB table — production must be flipped in its own Settings UI.

---

## Triage surfacing

### Signal-mode triage queue

`GET /api/entries/triage` (`backend/app/api/entries.py:171`) picks its path per request: explicit `mode=legacy|signals` wins; otherwise `signal_engine_surface` decides. The legacy path is the live multi-subquery composite (`get_triage_entries`, `backend/app/services/triage.py:72` — PIR/correlation/automation/CVE-risk/reliability/engagement weights). The signal path (`get_triage_entries_signals`, `triage.py:356`) is one indexed scan over stored `Entry.priority_score ≥ threshold` plus one batched `entry_signals` fetch, returning the same response shape with signal explanations as `priority_reasons`.

Per-user, read-time adjustments on top of the global score (inside `get_triage_entries_signals`):

- **Muted** entity watches filter matching entries out entirely.
- **Watched** entities add +1.0 to the effective sort score and bypass the threshold, so watched-entity entries surface even below the Radar line. (This is the "watchlist" signal noted in the `entry_signals` model comment — read-time only, never stored.)

### Entry-list chips and radar sort

When surfaced, the entry list endpoint (`list_entries`, `backend/app/api/entries.py:447`) batch-loads signals for the page and each `EntryResponse` carries `priority_score`, up to 2 non-echo `top_signals`, and `is_echo` (`backend/app/schemas/entry.py:44-47`). Score and chips are only populated when the entry clears the Radar threshold; `is_echo` is always set so echoed re-reports can be visually de-emphasized. `sort=radar` orders by `priority_score` desc with a score-based cursor, and — when surfacing is on — restricts the list to entries clearing the Radar threshold, mirroring the Priority Queue badge count (`api/entries.py:876-892`; badge count itself from `GET /api/entries/priority-unread-count`, `:1263`). Rendering: `frontend/src/components/SignalChip.tsx`.

### Story threads in the ranked queue

The Priority Queue is a second, ranked entry list: `/priority-queue` renders `MainLayout` in `priorityMode`, which mounts `EntryList` with `sortOverride="radar"` and `withThreads`, a docked reader, and a Why-ranked card (`frontend/src/components/WhyRankedCard.tsx`) explaining the entry's signals. It folds **story threads** into the ranked list as inline rows (`GET /api/threads`).

The ranking and the folding are **server-side** (`build_priority_queue`, `backend/app/api/entries.py:1377`): the endpoint lists open threads with something unread, scores each one, and two-pointer-merges them into the radar-ordered entry page so a thread slots in ahead of the first entry it outranks. A thread ranks by the score of its best **unread, non-echo** member (`top_score`, `story_threads.py:1003`), and its badge shows that score. Every member of a live thread is withheld from the queue as a standalone entry, including members on pages not yet fetched — a thread always scores at or above its best unread member, so the row is reached before the articles it stands for. A thread with nothing unread does not render at all: the queue answers "read this next", and a story you have finished has no answer to give.

The client only flattens the response into display rows (`queueItems`, `frontend/src/utils/threads.ts:49`) and adds day dividers; it does no ranking of its own. Pagination carries a composite cursor holding both the entry cursor and the thread sort key, so a page that emitted no thread row still resumes thread progress instead of re-emitting threads already shown.

**Temporal convergence clusters** — per-request entity-overlap groups with no name, no spine and no persistence — are not part of the queue. `GET /api/intelligence/temporal-clusters` and its registry tool serve the copilot and the triage widget; nothing in the reading UI calls them. See [story-threads.md](story-threads.md) for how a thread is built and tuned.

### Automation integration

Automation rules can react to signal outputs via entry conditions in `backend/app/automation/conditions.py` (engine phase 7): `priority_score_above` (`conditions.py:258` — stored `Entry.priority_score`, on the 0–10 scale, ≥ `config.min`), `has_signal` (`conditions.py:274` — entry carries any/specific `entry_signals` types), and `entity_watchlisted` (`conditions.py:328` — entry links an entity on the rule creator's watchlist). Because scoring is the *final* chord callback while `automate` is a *side* dispatch, `on_new_entry` rules see `priority_score` only if the entry was already scored. For score reactions use the **`on_entry_scored` trigger**: `score_entry_task` dispatches `run_scored_entry_automations` after signals + score are persisted (guarded by a cheap enabled-rule existence check), so `priority_score_above`/`has_signal` conditions evaluate against real values. It fires on initial pipeline scoring only — rescores and backfills don't re-fire rules. See [automation-ai-enrichment.md](automation-ai-enrichment.md) for the rule engine itself.

### Entity "what's new" developments

Entity profile pages show recent novelty/severity signals for entries linked to that entity via `GET /api/engine/entities/{type}/{id}/whats-new` (`api/engine.py:168`) — filtered to the 8 "interesting" types (novel/resurgence/pairing/scoop/KEV/EPSS-jump/PoC/under-reported), most recent within ≤90 days. Rendered as the recent-developments list inside the profile Overview tab's assessment block (`frontend/src/components/entityProfile/AssessmentBlock.tsx`, fed by `useEntityWhatsNew` in `frontend/src/hooks/useEngine.ts`).

---

## Ops console & observability

### Settings → Engine console

The Engine console lives at `/settings?section=engine` (Settings > Administration > Engine, admin-only — the section only renders for admins; `/workbench/engine` redirects here, query string preserved). `frontend/src/components/engine/EngineSection.tsx` hosts a **single-surface console** (`EngineMatrix.tsx`): everything lives in one "living table" card whose view tabs switch what the table shows —

- **Entries** (default) — the processing matrix from `GET /api/engine/processing`: recent entries as rows, pipeline stages as columns with ✓/✕ badges and peek popovers, plus a per-entry pipeline table with **Timing and Output lenses** (the Output lens shows what each stage actually produced for the entry — links created, rules extracted, signals fired) and a drawer output manager (`EntryOutputs.tsx`) for inspecting and unwinding a single entry's outputs. Stage column headers expand into in-card stage panels (`StagePanel.tsx`) with recent-runs drill-down, retry buttons, and per-stage settings (`ExtractStageConfig.tsx`; `ScoreStageConfig.tsx` — family multiplier sliders, threshold override, per-signal firing-rate/effective-weight readout, watchlist management; enrichment/autolink hygiene/correlation tuning via `WorkbenchAdminPanel.tsx`).
- **Links** — entry↔entity edge management over `GET /api/entity-links` (`AutolinkingSection.tsx`), with a proposals queue (`ProposalsQueue.tsx`) for pending-tier autolink matches.
- **Relationships** — entity↔entity edge management (`AutolinkingSection.tsx` in relationships view, over `/api/entity-relationships`).
- **Entities** — AI-created entity management (`ExtractionTab.tsx` over `/api/engine/extraction`: provenance stats, filter/merge/delete/confirm) plus its proposals queue.
- **Feeds** — feed health plus feed/rate-limiting/image-proxy settings.

Four things open as separate **browse views** with a back button (`BrowseView`, `EngineMatrix.tsx:39`): **Jobs** (schedule editor `frontend/src/components/JobSchedules.tsx`, backed by the `JOB_REGISTRY` + Redis schedule overrides, and run history from `GET /api/engine/job-runs`), **Plans** (`PipelinePlans.tsx` for global/category/feed plan CRUD plus the plan-engine switches), **Maintenance** (`MaintenancePanel.tsx` — global sweeps, destructive resets and the on-demand hygiene scanners), and **Publishing** (`PublishingPanel.tsx` — the outbound observable feeds and their token/confidence/age gates).

Enrichment, Job Schedules, Feed Health, and Workbench settings all live inside the console. Bookmarked `?tab=` and `?section=` deep links are remapped onto console states (`legacyState`, `EngineSection.tsx:30-53`). Every setting the console exposes is catalogued in [engine-settings.md](engine-settings.md).

### `entry_pipeline_runs` — per-entry stage observability

Written by `@pipeline_stage` (see above); one terminal row per stage execution per entry. Powers:

- The **entry processing popover** (`frontend/src/components/EntryPipelineStatus.tsx`) via `GET /api/engine/entries/{entry_id}/runs` (`api/engine.py:418`), which returns the *latest* run per stage with human labels (`PIPELINE_STAGE_LABELS`, `api/engine.py:391`).
- The **stage drill-down** behind each stage's ✓/✕ badges via `GET /api/engine/pipeline/stages/{stage}/runs` (`api/engine.py:466`), filterable by status.
- The **Engine console entries matrix** via `GET /api/engine/processing` (`api/engine.py:631`) — recent entries with per-stage status, timing, and per-entry output counts.
- **Per-stage retry**: `POST /api/engine/entries/{entry_id}/stages/{stage}/retry` (`api/engine.py:512`) re-dispatches the stage's task with a bare `entry_id`. Only stages in `RETRYABLE_STAGE_TASKS` (`api/engine.py:406`) qualify — `automate` (needs `feed_id`) and `translate` (needs target language) are excluded.

### `job_runs` — scheduled-job history

Written by Celery signal handlers in `backend/app/workers/task_tracking.py` (`task_prerun`/`task_postrun`/`task_failure`/`task_retry`), **filtered to `JOB_REGISTRY` tasks only** — per-entry pipeline tasks would produce ~100k rows/day and are covered by `entry_pipeline_runs` instead. Each row records status, precise duration, error, and a clipped `detail` JSONB of args/kwargs/result (`_task_detail`, depth- and size-bounded) so the Jobs tab can show what a run actually did. Every handler swallows its own errors: run tracking must never break a task.

### Retention: `prune_engine_tables`

`backend/app/workers/maintenance.py:938` (job key `prune-engine-tables`, daily 02:40 UTC — `job_registry.py:699`) deletes engine bookkeeping older than **30 days**: `entry_pipeline_runs`, `job_runs`, non-pending `ai_analysis_requests`, `ai_batch_jobs`, and resolved `pending_autolink_matches` (unresolved pending matches expire at 14 days — no AI pass ever came, so the hold just lapses). `entry_signals` is not pruned — signals stay for the life of the entry and cascade-delete with it.

---

## API endpoints

The engine router mounts at `/api/engine` (`backend/app/main.py:801`). All endpoints require auth; mutating ones require admin (`_require_admin`, `api/engine.py:15`).

| Method & path | Purpose | Ref |
|---|---|---|
| `GET /api/engine/signals/stats` | Firing rates, effective IDF weights, families, multipliers, threshold (+is_auto), plus a `health` block: flag state, unscored-recent count (72h), last rate-recompute/rescore job runs, per-family feedback counts vs the min-sample floor, current nudges | `api/engine.py:36` |
| `PUT /api/engine/signals/settings` | Admin: family multipliers (clamped 0–2) and/or threshold override; multiplier changes trigger `rescore_recent_entries(hours=168, limit=2000)` | `api/engine.py:130` |
| `GET /api/engine/entities/{type}/{id}/whats-new` | Recent novelty/severity signals for an entity's entries | `api/engine.py:168` |
| `GET /api/engine/extraction/status` | One-pass AI extraction health: queue depth by status, today's spend vs budget, last batch | `api/engine.py:339` |
| `GET /api/engine/pipeline` | Stage registry + 24h run counts + engine flag state | `api/engine.py:534` |
| `GET /api/engine/processing` | Entries-matrix data: recent entries × stages with status, timing, and output counts | `api/engine.py:631` |
| `GET /api/engine/pipeline/stages/{stage}/runs` | Recent runs for one stage with entry titles (limit ≤200, optional status filter) | `api/engine.py:466` |
| `GET /api/engine/entries/{entry_id}/runs` | Latest run per stage for one entry (processing popover) | `api/engine.py:418` |
| `POST /api/engine/entries/{entry_id}/stages/{stage}/retry` | Re-dispatch one retryable stage task | `api/engine.py:512` |
| `GET /api/engine/plans` | List pipeline plans (all scopes) | `api/engine.py:1046` |
| `PUT /api/engine/plans` | Admin: upsert a plan by scope (validates stage names; bumps plan version) | `api/engine.py:1096` |
| `DELETE /api/engine/plans/{plan_id}` | Admin: delete a non-global plan (global plans cannot be deleted) | `api/engine.py:1146` |
| `GET /api/engine/job-runs` | Recent scheduled-job runs, optional `job_key` filter (limit ≤500) | `api/engine.py:1175` |
| `PUT /api/engine/radar-feedback` | Thumbs on a Radar item (1/−1/0-clears), one per user per entry | `api/engine.py:1217` |
| `GET/PUT/DELETE /api/engine/my-radar` | Per-analyst learned Radar weights: read the fitted family weights and vote counts, opt in/out, or discard the fitted rows | `api/engine.py:1267`, `:1366`, `:1386` |
| `GET/POST/DELETE /api/engine/autolink/fp-names` | The curated false-positive vocabulary (`autolinker_false_positive_names`) as rows — vendors/products/tools/mitigations bypass it | `api/engine.py:1427`, `:1444`, `:1465` |
| `GET/POST/DELETE /api/engine/autolink/blocked-names` | Analyst hard blocks (`autolinker_blocked_surface_forms`) — enforced for **every** entity type | `api/engine.py:1497`, `:1514`, `:1535` |

A sibling router mounts at `/api/engine/extraction` (`backend/app/api/extraction.py`, `main.py:831`) for the console's Entities view: `GET /stats` (provenance/source breakdowns), `GET /entities` (filterable list of AI-created entities), `POST /confirm` (bulk analyst confirmation).

Related endpoints on other routers:

- `GET /api/entries/triage?mode=legacy|signals` — triage queue, mode-switched (`api/entries.py:171`)
- `GET /api/entries?sort=radar` — priority-ordered entry list with signal chips (`api/entries.py:447`)
- `GET /api/entries/priority-queue` — the Priority Queue: the radar-ranked unread list with open story threads folded in as single rows, assembled server-side (`build_priority_queue`, `backend/app/api/entries.py:1377`)
- `GET /api/entity-links` (+ `/stats`, unlink, bulk-unlink) — entry↔entity edge management for the console's Links view (`backend/app/api/entity_links.py`)
- `GET /api/intelligence/temporal-clusters` — cross-feed temporal clusters, used by the convergence widgets (`api/correlation.py:388`)
- Job schedule CRUD (Jobs browse-view editor) lives on the jobs router backed by `job_registry.py` — see [workers-search-dashboards.md](workers-search-dashboards.md)

Frontend data hooks for all of the above: `frontend/src/hooks/useEngine.ts`.

---

## Key tables

Schemas, indexes, and JSONB layouts are documented in [data-model.md](data-model.md) (signal engine & observability section); summary only:

| Table | Model | Role |
|---|---|---|
| `entry_signals` | `backend/app/models/entry_signal.py` | One row per (entry, signal_type); raw score 0..1, explanation, evidence payload. Upserted on re-score; cascade-deletes with entry |
| `entry_signal_feedback` | `backend/app/models/entry_signal_feedback.py` | One Radar verdict per user per entry (±1); feeds nightly family nudges |
| `pipeline_plans` | `backend/app/models/pipeline_plan.py` | Data-defined stage composition; unique per (scope_type, scope_id) |
| `entry_pipeline_runs` | `backend/app/models/entry_pipeline_run.py` | Terminal per-stage execution records; 30-day retention |
| `job_runs` | `backend/app/models/job_run.py` | Scheduled-task execution records with clipped detail; 30-day retention |

Plus three columns on `entries`: `priority_score` (0–10, indexed, nullable — null means never scored), `priority_raw` (the weighted sum it is scaled from, indexed; the ordering key) and `scored_at`.

---

## Enabling the engine (runbook)

All flags are DB-backed per environment — flipping them in dev does nothing for prod.

1. **Shadow first.** Enable `signal_engine_shadow` (Settings → Engine → score stage). New entries start getting scored as their pipelines complete; nothing changes in the UI.
2. **Backfill history.** Manually dispatch `backfill_entry_scores` (default: 14 days, batches of 500) so shadow mode has data to evaluate — it is never beat-scheduled and skips itself if both flags are off (`backend/app/workers/signal_tasks.py:520`). It only scores entries with `scored_at IS NULL`; the 6-hourly rescore sweeps unscored entries too but only inside its 72h window, so without the backfill, older history stays unscored.
3. **Let the weights settle.** Run (or wait for) `signal-rate-recompute` so IDF weights, the 0–10 scale's cutoffs and the auto p95 threshold reflect the actual river instead of the cold-start defaults.
4. **Validate.** Compare `GET /api/entries/triage?mode=signals` against the default legacy ranking for about a week; tune family multipliers on the score stage card if a family dominates.
5. **Surface.** Enable `signal_engine_surface` — triage flips to the signal ranking, entry lists gain chips and `sort=radar`, `entry_scored` SSE starts.
6. **Pipeline plans (independent).** Enable `pipeline_engine_enabled` whenever plan-driven composition is wanted; turning it off is an instant, lossless rollback to the feed booleans because the booleans are still the synthesis base, not a migrated-away snapshot.

## Operational notes

- **Plan edits outside the API don't propagate immediately.** Cached resolutions live up to 600s keyed on the version counter; the API bumps it on every write, but a direct DB edit to `pipeline_plans` without `bump_plan_version()` waits out the TTL.
- **Global plans can't be deleted** via the API (`delete_plan`, `backend/app/api/engine.py:1389`) — deactivate or empty them instead.
- **Run logging is write-path-only.** Disabling `pipeline_run_logging_enabled` stops new `entry_pipeline_runs` rows but the ops console keeps serving existing ones until retention prunes them.
- **Retry re-runs the whole stage.** The retry endpoint just re-sends the task with the entry id; stages are idempotent (junction upserts, signal upserts), so this is safe, but it does not resume the chord — downstream stages are not re-triggered.
- **Rate recompute denominator** is entries *scored* in the 30-day window, not entries fetched (`signal_tasks.py:192-196`) — so a large backfill shifts rates only in proportion to what it scored, not what it skimmed past.
- **`feed_echo` never hides anything.** It subtracts from the score and sets `is_echo` on list items; suppression is a rendering decision (dimmed rows), not a filter.
- **Failed probes omit their signal, visibly.** Async signal probes are individually guarded (`_guarded`, `signals.py`): a probe that raises logs a warning, increments `intelfeed_signal_probe_failures_total{probe}`, and the entry scores without that signal instead of failing the whole task. `intelfeed_entry_signals_fired_total{signal_type}` counts firings for drift-watching. `_collect_links` stays unguarded — everything depends on it, so its failure still fails (and retries) the task.

---

## Tests

- **`backend/tests/test_pipeline_registry.py`** (11 tests) — the structural safety net for the registry refactor: asserts `dispatch_entry_pipeline` builds a chord identical to the previous hand-built dispatch with and without extraction, plan overrides gate the header, a plan can never empty the header (the forced-autolink fallback), the translate prologue chains correctly, the post-processing chord shape, synthesis + scope-layered resolution, and the plans/pipeline API endpoints.
- **`backend/tests/test_signal_engine.py`** (41 tests) — per-signal firing behavior (novelty, echo/convergence, severity/under-reported, PIR, research depth), IDF math and multiplier/echo weighting, score persistence + upsert, signals-mode triage shape and watch/mute effects, surfaced entry-list chips, the `@pipeline_stage` decorator and runs/retry endpoints, `job_runs` recording and detail clipping, signal automation conditions, and Radar feedback.
- **`backend/tests/test_triage.py`** — legacy composite triage scoring.

Run them from `backend/` against the host venv, or via the docker api container:

```bash
cd backend && pytest tests/test_pipeline_registry.py tests/test_signal_engine.py -x -q
# or
docker compose -f docker-compose.dev.yml exec api pytest tests/test_pipeline_registry.py tests/test_signal_engine.py -x -q
```
