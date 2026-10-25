# Engine Settings Reference

Every runtime setting IntelFeed exposes, what it actually does, and where in the
UI it lives. This is the companion to [engine.md](engine.md), which explains the
subsystems these settings steer; here the unit of organisation is the **knob**.

IntelFeed has **186 settings** in total:

- **138** are DB-overridable and editable in the UI (`CONFIGURABLE_KEYS`, `backend/app/services/system_settings.py:19`).
  One of them exists only in the database, with no `Settings` field behind it — see [How a setting resolves](#how-a-setting-resolves).
- **48** are env-only — infrastructure, secrets and build stamps — see [Env-only settings](#env-only-settings) at the end.
- Five are **secrets** (encrypted at rest, masked in API responses): `github_token`,
  `nvd_api_key`, `observables_publish_token`, `registration_invite_code`, `sentry_dsn`
  (`SECRET_KEYS`, `system_settings.py:14`).

---

## How a setting resolves

Everything goes through `settings.get(key)` (`backend/app/config.py:448`), never
`settings.key` directly, for any key that should be runtime-editable:

1. **DB override** — if the key is in `CONFIGURABLE_KEYS` and the `system_settings`
   table holds a row for it, that value wins (`get_setting_cached`).
2. **Env / `.env`** — otherwise the pydantic `Settings` field default, which `.env`
   or a real environment variable can override at process start.
3. **Code default** — the literal in `config.py`.

The code defaults are the values the reference production instance settled on
after months of tuning, so a fresh install behaves like a tuned one without
anyone touching the Engine console. The instance-specific knobs are the
exceptions: content budgets that depend on the AI host's memory
(`ai_analysis_content_max_chars`), anything that exposes data outward
(`public_rss_enabled`, `observables_publish_enabled`), the per-instance
curation lists (`autolinker_false_positive_names`,
`autolinker_blocked_surface_forms`), and every secret and URL.

An override that equals the shipped default is dead weight — it pins the
install to a stale copy when the default moves again.
`scripts/maintenance/prune_setting_overrides.py --dry-run` lists those, plus
keys no setting reads any more and job overrides for jobs that no longer
exist; without the flag it removes them.

One key exists **only** in the DB and has no env default at all:
`registration_invite_code`. Reading it before anyone sets it returns `None`.

Reading `settings.key` as an attribute bypasses the override, which is how
several knobs were editable in the UI yet inert (`correlation_cache_ttl_seconds`,
`rate_limit_default_interval`, the `image_proxy_*` keys, `backup_retention_days`,
`sentry_*`, and `user_agent` outside feed polling). Every runtime-editable key
now resolves through `settings.get()`; the API warms the cache at startup and
Celery tasks call `warm_settings_cache()` before reading knobs.

**Caching.** Resolved values are cached in-process for 5 seconds
(`_CACHE_TTL`, `system_settings.py`). A `PATCH` on one API worker therefore
reaches the Celery workers within ~5s — but Celery tasks already in flight keep
the value they read at start. Nothing needs a restart.

**Per-environment.** These live in the database, so flipping a flag in dev does
nothing for production. Every rollout is a per-environment action in that
environment's own Settings UI.

### Where the metadata comes from

| Structure | File | Role |
|---|---|---|
| `CONFIGURABLE_KEYS` | `system_settings.py:19` | Which keys are DB-overridable, and the type each value is coerced to |
| `SETTING_METADATA` | `system_settings.py:186` | Label, description and group shown in the UI |
| `_ENGINE_SECTION_GROUPS` | `backend/app/services/system_settings.py:1223` | Re-groups engine-owned keys onto Engine console sections, overwriting the `group` above |
| `SECRET_KEYS` | `system_settings.py:14` | Encrypted at rest, masked on read |
| `GROUP_DEST` | `frontend/src/components/engine/engineSettingsIndex.ts:26` | Group → which console surface renders it; powers the Engine settings search |
| `KEY_DEST` | `frontend/src/components/engine/engineSettingsIndex.ts:68` | Key-level exceptions to `GROUP_DEST` |

Adding a setting means touching all of `config.py` (default), `CONFIGURABLE_KEYS`
(type), `SETTING_METADATA` (label/description/group), and — if a scheduled job
reads it — that job's `settings_keys` in `backend/app/workers/job_registry.py`.
A `settings.get()` on a key missing from `CONFIGURABLE_KEYS` silently returns the
env default forever; the UI can never change it.

### Finding a setting

Settings → Engine has a search box (`EngineSettingsSearch.tsx`) that matches on
key, label and description across every group and deep-links to the surface that
renders it. The mapping it uses is the same `GROUP_DEST` table this document is
organised around.

---

## Autolink stage

Settings → Engine → *autolink* stage panel. These steer the Aho-Corasick
dictionary scan in `backend/app/intelligence/autolinker.py`; see
[intelligence-engine.md](intelligence-engine.md) for the algorithm.

| Setting | Type / default | What it does |
|---|---|---|
| `autolinker_min_name_length` | int, `3` | Names shorter than this are never added to the automaton. The floor that keeps two- and three-letter aliases out of the scan entirely. |
| `autolinker_ambiguous_name_max_length` | int, `10` | Single-word, alpha-only names up to this length must appear **capitalised** in the source text to match — the rule that lets "Royal" the actor match *Royal ransomware* but not *the royal family*. |
| `autolinker_ambiguous_max_occurrences` | int, `3` | An ambiguous name appearing more than this many times in one article is skipped for that article. High repetition reads as ordinary English usage, not a named-entity reference. |
| `autolinker_false_positive_names` | csv, ~150 names | The curated FP vocabulary: generic animal/nature words, malware category words, OS/vendor brand words, Windows built-ins, and known-bad Malpedia aliases. **Only applies to actor / malware / country matching** — vendors, products, tools and mitigations deliberately bypass it, since their real names *are* common brand words (Norton the vendor still matches). Editable as rows via `GET/POST/DELETE /api/engine/autolink/fp-names`. |
| `autolinker_blocked_surface_forms` | csv, empty | Analyst hard blocks, written by the reader's *Wrong? → never match this word* action. Unlike the list above, these are enforced for **every** entity type — an analyst saying "stop matching this" has to actually stop it. Managed from the reader popover and Engine → Autolink. |
| `autolink_pending_tier_enabled` | bool, `true` | Actor/malware/tool/country matches whose only surface forms are common English dictionary words are held in `pending_autolink_matches` rather than linked outright; the one-pass AI analysis promotes or rejects them. Unconfirmed matches never become links. Off restores instant linking for dictionary-word names. |

Vocabulary changes take effect when the autolinker's Redis-versioned vocabulary is
rebuilt — `refresh-autolinker-vocabulary` runs every 30 minutes, and the API
bumps the version on writes made through it.

---

## Observables stage

Settings → Engine → *observables* stage panel, except the publish knobs, which
render on the **Publishing** browse screen. Backing module:
`backend/app/intelligence/observables.py`.

The hard rule this stage is built around: **regex never creates a ledger row.**
Pattern scanning only stages entry-local *candidates*; rows come from judgment
doors (the one-pass AI `iocs` array, TTP observable upserts, curated `ioc_list`
feeds, analyst promotion), and known values are then sighted by exact match.

| Setting | Type / default | What it does |
|---|---|---|
| `observables_candidate_max` | int, `200` | Cap on candidates staged per entry by the refang+regex scan. Candidates are nominations attached to the entry, never ledger rows. |
| `observables_analysis_tail_reserve` | float, `0.4` | Share of the one-pass analysis text budget reserved for the article's **indicator appendix** when the body exceeds `ai_analysis_content_max_chars`. Research write-ups put their IOC tables and command blocks at the end; the window keeps the head and appends the IOC section (found by heading or table header, hash dumps compressed) after a marker line. `0` disables it and the model sees only the head. |
| `observables_codeblock_skip_categories` | csv, `Security Advisories,Government / CERT` | Feed categories whose entries never nominate host-kind candidates from `<pre>` blocks — bulletins are preformatted prose, not commands. Rule-repository entries (any GitHub `content_type`) are always skipped. |
| `observables_publisher_ioc_enabled` | bool, `true` | Fetch and capture the indicator file an article links to when it lives in an allow-listed publisher repository (Cisco Talos IOCs, Bitdefender malware-ioc, Datadog indicators-of-compromise). Roles come from the publisher's own labels; rows are sighted on the article. |
| `observables_publisher_ioc_max_values` | int, `2000` | Cap on indicators taken from one article IOC table. |
| `observables_ai_capture_kinds` | csv, network + hash kinds + `script` | In `capture` mode, only these kinds become ledger rows from the one-pass AI; every other kind it reports is still staged as a promotable candidate (with its role, evidence and confidence). Add the host kinds — `cmdline`, `path`, `registry`, `scheduled_task`, `service_name`, `mutex`, `named_pipe`, `user_agent`, `http_header` — once the extraction fixture (`scripts/dev/eval_observable_extraction.py`) shows they are precise. |
| `observables_ai_capture_mode` | `shadow` \| `capture`, default `capture` | `shadow`: indicators the one-pass AI confirms land on the entry as *promotable candidates* — you eyeball the judge before trusting it. `capture`: confirmations become ledger rows directly. |
| `observables_decay_enabled` | bool, `true` | Nightly per-kind confidence decay for network observables — IP 30d half-life, URL 60d, domain 90d; hashes and host artifacts never decay. A new sighting resets the clock. Job: `decay-observable-confidence`, daily 02:20 UTC. |

### Publishing (Engine → Publishing browse screen)

Outbound observable feeds: EDL blocklists, SIEM lookup CSVs, and the TAXII 2.1
collection (`backend/app/api/publish.py`). The router is mounted **without** the
app auth dependency — these endpoints authenticate their own pullers by token.

| Setting | Type / default | What it does |
|---|---|---|
| `observables_publish_enabled` | bool, `false` | Master switch. Off, every publish endpoint returns 404 — not 403, so a scanner learns nothing. |
| `observables_publish_token` | secret csv, empty | Consumer tokens as `name:secret` pairs (a bare secret also works). Each puller gets its own revocable token and pulls are attributed to its name. Accepted as `Authorization: Bearer` or `?token=`. |
| `observables_publish_min_confidence` | float, `0.6` | Minimum *current* (post-decay) confidence for a value to appear in any feed. Raising this is the fastest way to tighten an over-broad blocklist. |
| `observables_publish_max_age_days` | int, `90` | Values last sighted longer ago than this drop out of the feeds. |
| `observables_publish_never_suffixes` | csv, empty | Domain suffixes excluded from every outbound feed — your own domains, partners, anything you must never blocklist. This is a **publish filter, not a capture rule**: the rows stay in the ledger. Shared CDN/hosting suffixes (cloudfront, `workers.dev`, …) are always excluded regardless. |

---

## Extract stage

Settings → Engine → *extract* stage panel. Pattern matching only — the stage
pulls CVE, ATT&CK technique and mitigation IDs out of the text at ingest and
never calls a model — so only the two pattern knobs of the `extraction` group
render here. The AI read, and everything that tunes it, lives on the
[Analyze stage](#analyze-stage).

| Setting | Type / default | What it does |
|---|---|---|
| `attack_ics_context_keywords` | csv | ICS-matrix ATT&CK techniques (`T0xxx`) are linked only when the entry text word-boundary-matches one of these. Without it, IT articles pick up ICS techniques on ID collisions. Read by `backend/app/intelligence/attack_catalog.py`. |
| `cve_epss_high_risk_threshold` | float, `0.1` | EPSS score at or above which a CVE is tiered **high** risk. Drives CVE risk tiers, triage scoring and opportunity badges (`backend/app/intelligence/cve.py`). |

---

## Analyze stage

Settings → Engine → *analyze* stage panel (`AnalyzeStageConfig.tsx`). Two groups
render here: the one-pass AI analysis knobs (`ai`) and the entity-creation
guardrails its output passes through (the rest of `extraction`), plus the
`entry_analysis` model assignment, its max-output-tokens override, and the
entity-name denylist.

### One-pass AI analysis

One consolidated `entry_analysis` call per entry replaces the old per-task
extraction fan-out. Requested when scoring finishes, batched hourly and budget-capped;
`backend/app/services/entry_analysis.py` + `backend/app/workers/ai_batch_tasks.py`.
Job: `ai-analysis-batch-submit` (every 30 min) and `ai-analysis-batch-poll`
(every 10 min).

| Setting | Type / default | What it does |
|---|---|---|
| `ai_one_pass_enabled` | bool, `true` | Master switch. Requires an enabled `entry_analysis` AI task assignment — the flag alone does nothing. |
| `ai_daily_budget_usd` | float, `2.0` | Hard daily spend cap. On reaching it, pending entries wait; the next run takes the highest-priority ones first. |
| `ai_analysis_relevance_threshold` | float, `0.15` | Junk gate: entries scoring below this on the keyword relevance pass skip AI analysis entirely. The question it answers is "is there anything here to extract", not "is this important". |
| `ai_batch_max_requests` | int, `500` | Maximum entries per batch submission. |
| `ai_analysis_content_max_chars` | int, `12000` | Characters of article body sent per entry. Bodies over the cap are windowed as head + indicator appendix (see `observables_analysis_tail_reserve`) so a long write-up's IOC section is never cut; narrative past the head is. |
| `ai_use_batches` | bool, `true` | Use the Anthropic Message Batches API (50% discount) when the provider supports it. Otherwise sequential calls with prompt caching. |
| `ai_est_cost_per_request` | float, `0.0024` | Per-entry cost estimate used to size a batch against the daily budget. Set near zero for local providers (Ollama), where the budget is meaningless. |
| `ai_tool_evidence_required` | bool, `true` | Only store an extracted **tool** when the model names who wielded it *and* quotes the sentence showing its use. This is the evidence door that stopped tool extraction turning every mention of `certutil` into an entity. Turn off only if tool extraction stops finding anything at all. |

### Entity creation guardrails

`backend/app/intelligence/entity_resolution.py` — the gates between an AI-extracted
name and a new row in an entity table.

| Setting | Type / default | What it does |
|---|---|---|
| `entity_resolution_normalized_match` | bool, `true` | Match incoming names against existing profiles *after* normalisation (case, punctuation, spacing, leetspeak folding) so `Cl0p` resolves to `Clop` and `Silver Fox` to `SilverFox` instead of creating a duplicate. Only prevents duplicate creation, so it is safe on. |
| `entity_creation_gates` | `off` \| `shadow` \| `on`, default `on` | The generic-name / denylist / cross-type / alias-quality gates. `shadow` logs every would-block decision to the maintenance log but still creates — the right setting for watching what enforcement *would* do. `on` enforces. Manual creation always succeeds but is logged as an override. |

---

## Score stage

Settings → Engine → *score* stage panel. Two groups: signal scoring (`scoring`)
and story threads (`threads`). The scoring model itself is documented in
[engine.md](engine.md#signal-scoring-model); the thread clustering in
[story-threads.md](story-threads.md).

### Signal engine and Radar

| Setting | Type / default | What it does |
|---|---|---|
| `signal_engine_shadow` | bool, `true` | Compute and persist `entry_signals` + `Entry.priority_score`. Nothing changes in the UI. This is stage one of the rollout. |
| `signal_engine_surface` | bool, `true` | Surface the scores: entry-list priority chips, the `radar` sort, signal-ranked triage, and the `entry_scored` SSE event. |
| `signal_feedback_min_samples` | int, `20` | A signal family needs at least this many Radar verdicts in the 30-day window before its **global** feedback nudge applies. Below the floor the family keeps a neutral 1.0 — a handful of votes can't swing scoring. |
| `radar_personalization_enabled` | bool, `false` | Instance-wide switch for per-analyst learned weights, applied as a **read-time lift** on each analyst's own `sort=radar` entry ordering. The stored score stays global; personalisation re-orders that list and never changes its membership, because the radar threshold still gates on the global score. The Priority Queue sorts on the stored score its rows display and does not apply the lift. Also needs a per-user opt-in (`User.settings["radar_personalized"]`). |
| `radar_personalization_min_samples` | int, `5` | Minimum verdicts *one* analyst must cast in a family before that family gets a personal weight. |
| `radar_personalization_window_days` | int, `90` | Lookback for the nightly per-user fit. Longer than the global 30-day nudge window because one analyst votes far less often than all of them together. |
| `my_stack_exposure_enabled` | bool, `true` | Vendor Watch: float CVEs affecting followed vendors/products in the Priority Queue and power the Vendor Watch board with detection-library coverage. Read-time and per-user, reusing the entity watchlist — no rescore. **Requires `signal_engine_surface`.** |
| `exposure_attack_visibility_enabled` | bool, `true` | On the Vendor Watch board, for vulns with no detection rule, estimate detectability by mapping the CVE's co-occurring ATT&CK techniques to their data sources and on to configured telemetry. Explicitly lower confidence than rule-backed coverage — the CVE→technique link is article co-occurrence, not a curated mapping. |

Jobs: `signal-rate-recompute` (daily 04:20 UTC),
`signal-personal-weight-fit` (daily 04:35 UTC), `signal-rescore-recent`
(every 6h at :35), `signal-rescore-all` (Mondays 03:00 UTC).

Family multipliers and the Radar threshold override are **not** settings rows —
they live in Redis and are edited through `PUT /api/engine/signals/settings`
(the score stage card's sliders). See [engine.md](engine.md#redis-state).

### Embeddings

Configured on their own rather than through an AI task assignment: the sweeper is
a bulk, non-generative job that must keep running when every generative provider
is paused. Job: `embed-entries`, every 15 minutes.

| Setting | Type / default | What it does |
|---|---|---|
| `embeddings_enabled` | bool, `true` | Master switch for entry embeddings. Story threads, evidence structure, and thread-based signals are all dormant without it. Needs an Ollama provider (serving `embedding_model`) or an explicit `embedding_base_url`; with neither, the sweep logs one line and skips. |
| `embedding_model` | str, `nomic-embed-text` | Ollama model used. Must output **768 dimensions** — the pgvector column is fixed at that width. |
| `embedding_base_url` | str, empty | Ollama host for embeddings. Blank falls back to the Ollama provider row's `base_url`, then `OLLAMA_BASE_URL`. |
| `embedding_batch_size` | int, `32` | Texts per embedding request. |
| `embedding_backfill_limit` | int, `2000` | Entries embedded per sweeper run. |

### Story threads

Clustering thresholds. Every one is a tuning knob against live data —
`backend/app/intelligence/story_threads.py`. Job: `story-threads` every 30
minutes; `narrate-story-threads` daily at 06:10 UTC.

| Setting | Type / default | What it does |
|---|---|---|
| `thread_window_days` | int, `21` | How far back an entry can still be pulled into a thread. |
| `thread_dormancy_days` | int, `14` | Silence after which a thread stops accepting new articles. |
| `thread_gap_days` | int, `5` | Maximum quiet days between an article and the last article of the thread it joins. Stops a revived old story swallowing unrelated new coverage. |
| `thread_min_body_chars` | int, `400` | Below this an entry is a bulletin row, not an article, and is never threaded. About 44% of the corpus falls here. |
| `thread_join_similarity` | float, `0.84` | Cosine to the thread when the article shares an extracted entity with it. |
| `thread_join_similarity_no_entity` | float, `0.90` | The higher bar required when no entity is shared. |
| `thread_seed_similarity` | float, `0.84` | Cosine between two unthreaded articles needed to start a new thread. |
| `thread_duplicate_similarity` | float, `0.90` | At or above this an article is an **echo** — a re-report folded into the thread rather than a beat. |
| `thread_merge_similarity` | float, `0.92` | Centroid similarity at which two overlapping threads are judged the same story and folded into one. |
| `thread_sweep_limit` | int, `1500` | Entries examined per sweep. **Must stay comfortably above the number of articles published inside the gap window** — otherwise re-checks crowd out the newest arrivals and today's pile never gets threaded. |
| `thread_min_entries` | int, `3` | Articles required before a cluster becomes a thread. A pile of two is not a story. |
| `thread_min_sources` | int, `2` | Distinct source **domains** (not feed rows) required before a cluster becomes a thread. |
| `thread_narrate_limit` | int, `10` | Threads given an AI-written spine per nightly run. |
| `thread_signals_enabled` | bool, `true` | Let thread membership answer the `feed_echo` and `source_convergence` signals — a re-report is one the thread folded, corroboration is the thread's outlet count. Off falls back to the entity-overlap probe everywhere, which is also what short, unthreadable entries always get. |

---

## Correlation stage

Settings → Engine → *correlation* stage panel (the `intelligence` group).
These govern entity↔entity relationship strength, confidence and display —
`backend/app/intelligence/correlation.py`. See
[intelligence-engine.md](intelligence-engine.md) for the model.

### Strength composition

Strength is a weighted composite of corroboration, closeness and recency. The
three weights are meant to sum to 1.0.

| Setting | Type / default | What it does |
|---|---|---|
| `relationship_weight_corroboration` | float, `0.45` | Share of strength driven by how many independent articles assert the edge. |
| `relationship_weight_closeness` | float, `0.40` | Share driven by in-article proximity. |
| `relationship_weight_recency` | float, `0.15` | Share driven by how recent the evidence is. |
| `relationship_corroboration_saturation` | int, `8` | Independent-reporting count at which the corroboration component maxes out. Past this, more articles stop adding strength. |
| `relationship_recency_half_life_days` | int, `90` | Days after which the recency component halves. Doubles as the staleness window the weekly `relationship-confidence-decay` job demotes on. |
| `relationship_reliability_high_multiplier` | float, `1.15` | Evidence weight for articles from admiralty A/B feeds. `1.0` disables the boost. |
| `relationship_reliability_low_multiplier` | float, `0.85` | Evidence weight for D/E feeds. C, F ("cannot be judged") and unrated feeds are neutral at 1.0. |

### Proximity scoring

Paragraph distance between two entity mentions, decayed.
Formula: `1 / (1 + decay_rate × distance)`.

| Setting | Type / default | What it does |
|---|---|---|
| `proximity_default_score` | float, `0.3` | Score assigned to pairs with no paragraph data to measure. |
| `proximity_decay_rate` | float, `1.0` | How fast the score drops with paragraph distance. Higher is stricter. |
| `proximity_strong_threshold` | float, `0.7` | Minimum proximity to label a relationship **strong**. |
| `proximity_moderate_threshold` | float, `0.3` | Minimum to label it **moderate**; below is **weak**. |

### Trust, specificity and display

| Setting | Type / default | What it does |
|---|---|---|
| `relationship_evidence_promote_count` | int, `3` | Independent pieces of evidence needed to promote an edge to the next confidence tier. |
| `relationship_min_confidence` | `possible` \| `probable` \| `confirmed`, default `possible` | Trust floor for display surfaces (profiles, graphs, timelines). `possible` shows the full ladder including dashed signal rows; `probable` hides engine inferences awaiting corroboration; `confirmed` shows only corroborated claims (MITRE import, AI-adjudicated, analyst-pinned). **Engine management views always show everything** regardless. |
| `relationship_min_tier_default` | `all` \| `moderate` \| `strong`, default `all` | Platform-wide default evidence-tier floor for pivot "related" lists. Per-view filters can narrow further. |
| `relationship_specificity_weight` | float, `0.5` | How much strength is damped by counterpart ubiquity (IDF). `0` disables; `1` fully scales strength by specificity, sinking corpus-wide entities (reporting vendors, OS names) to the bottom of related lists. |
| `relationship_reporting_source_specificity` | float, `0.45` | Vendors/products below this specificity are treated as *reporting sources* and folded into a collapsed group on profile relationship views. |
| `graph_max_neighbors_per_node` | int, `30` | Cap on neighbours expanded per node when building an entity graph. |
| `graph_max_claim_edges` | int, `300` | Cap on typed relationship edges per graph, trust-ranked — protects against degenerate hubs. |
| `correlation_cache_ttl_seconds` | int, `3600` | Seconds correlation-engine results stay cached (`correlation_cache.py`). The `refresh-correlation-cache` job re-warms it hourly (at :10), matching the TTL. |

### Evidence structure

| Setting | Type / default | What it does |
|---|---|---|
| `relationship_evidence_structure` | bool, `true` | Cluster each edge's evidence articles into **stories** via the entry embeddings, so relationship views can say "recurring across N incidents" instead of treating scattered roundup co-mentions as corroboration. Also adds a story floor to co-occurrence promotion and orders the adjudication queue. **Requires embeddings coverage.** |
| `relationship_story_threshold` | float, `0.75` | Single-link join threshold for that clustering. Validated empirically: 0.70 chains digests into incidents, 0.75 keeps them separate. |

---

## Enrich stage

Settings → Engine → *enrich* stage panel (`enrichment` + `api_keys`). The
enrichment adapter pipeline itself is in
[automation-ai-enrichment.md](automation-ai-enrichment.md).

| Setting | Type / default | What it does |
|---|---|---|
| `nvd_api_key` | secret, empty | NIST NVD API key. Raises the rate limit from 5 requests/30s to 50/30s — the difference between a CVE backfill taking days and taking hours. |
| `github_token` | secret, empty | Shared GitHub PAT for repo monitoring and PoC search (5,000 req/hr). No scopes needed for public repos. |
| `cve_reenrich_batch_size` | int, `150` | CVEs re-fetched from NVD per `reenrich-cve-nvd` run (bulk-imported rows and ones awaiting analysis). |
| `github_poc_batch_limit` | int, `0` | CVEs searched per `github-poc-scan` run. `0` = auto: 300 with a token, 40 without — unauthenticated search 403s after roughly 10 requests/minute. |
| `github_poc_rescan_days` | int, `30` | Days before an already-scanned CVE is eligible for another PoC search. |

---

## Translate stage

| Setting | Type / default | What it does |
|---|---|---|
| `translation_default_target` | str, `en` | Language code translated into when a feed does not set its own target in `adapter_config`. |

The LibreTranslate endpoint, key and timeout are env-only.

---

## Feeds view

Settings → Engine → **Feeds** table view (`feeds`, `rate_limiting`,
`image_proxy`, `feed_value`).

| Setting | Type / default | What it does |
|---|---|---|
| `default_feed_fetch_interval` | int, `30` min | Default interval between fetches for a feed that doesn't set its own. |
| `feed_auto_pause_days` | int, `30` | The `check-feed-health` job pauses an active feed once every fetch has answered **HTTP 4xx** for this many days in a row (`Feed.error_since` marks the streak start; a clean fetch clears it). Only client errors count — a 5xx, a timeout or an HTML page at the feed URL never pauses anything — and the clock is the streak, not the last post, so a seldom-posting blog that still answers 200 is never paused for being quiet. Paused feeds are listed as **Dead** on the Feeds view (`auto_paused_at`), apart from feeds switched off by hand, and `POST /api/feeds/{id}/resume` (admin) re-activates one and clears the streak. `0` disables. |
| `user_agent` | str, browser-like | `User-Agent` sent when fetching feeds. The browser-like default exists because many sites (CISA/gov, Cloudflare-fronted blogs) return 403 to obvious bot agents. |
| `rate_limit_default_interval` | float, `2.0` s | Default seconds between requests to the same domain. Per-domain overrides are env-only (`rate_limit_overrides`). |
| `per_user_subscriptions_enabled` | bool, `true` | Each analyst manages their own feed list and mutes over the shared pool. Off is a single shared list where a mute affects everyone. While the flag is off, a mute is written to the shared `Feed.is_muted` only, not to anyone's subscription, so a feed muted while the flag is off reappears for everyone when it is turned on. |
| `image_proxy_enabled` | bool, `true` | Proxy external images through IntelFeed so reading an article doesn't beacon to the publisher. |
| `image_proxy_cache_ttl_days` | int, `30` | Days a proxied image stays cached (`evict-image-cache`, daily 04:10 UTC). |
| `image_proxy_max_size_bytes` | int, `10 MB` | Largest image the proxy will fetch. |

### Feed intel-value weights

How much each behaviour counts toward a feed's intel-value score
(`backend/app/intelligence/source_analytics.py`). The five weights are
**normalised to sum 1.0 at compute time**, so you can set relative values
without doing the arithmetic.

| Setting | Default | Counts |
|---|---|---|
| `feed_value_weight_entity_yield` | `0.25` | Entities per article |
| `feed_value_weight_entity_intro` | `0.25` | Entities this feed discovered first |
| `feed_value_weight_correlation` | `0.20` | Correlation events produced |
| `feed_value_weight_detection` | `0.15` | Detection rules generated |
| `feed_value_weight_pir` | `0.15` | PIR (intelligence requirement) matches |

---

## Plans browse screen

Settings → Engine → **Plans**. See
[engine.md](engine.md#pipeline-plans-feed--category--global-resolution).

| Setting | Type / default | What it does |
|---|---|---|
| `pipeline_engine_enabled` | bool, `false` | Stage composition comes from `PipelinePlan` rows layered over the feed booleans. Off = feed booleans only. Turning it off is an instant, lossless rollback, because the booleans remain the synthesis base rather than a migrated-away snapshot. |
| `pipeline_run_logging_enabled` | bool, `true` | Kill switch for per-entry `entry_pipeline_runs` rows. Write-path only — disabling stops new rows but the ops console keeps serving existing ones until retention prunes them. |

---

## Maintenance browse screen

Settings → Engine → **Maintenance** (`maintenance` + `retention`). This is where
the AI-driven cleanup jobs and every destructive-ish sweep are configured.

### Adjudicate stage (post-analysis AI review)

After an entry's one-pass analysis lands, a second, smaller AI call re-reads the
article next to a manifest of everything the analysis wrote to it — entity
links of every source, entities it minted (with their nearest catalogue names
pre-fetched), pending-tier promotions, relationship claims, AI observables —
and returns a verdict — remove, reclassify, veto, merge, demote or drop — for
each item it would change. Items it leaves out are kept, so a clean review
returns an empty list: at the manifest caps below, one line per item would not
fit in the task's 4096 output tokens, and a truncated response is a parse
error that throws the whole review away. A manifest holds at most 60 entity links, 10 relationship
claims and 25 observables; when an article has more links than that, the ones
only this review can judge come first — entities it minted, then pending-tier
promotions, then AI assertions, then the autolinker's bulk — the prompt says
the list is partial, and the run's `detail.uncapped_links` records the
remainder. Relationship claims over the cap work the same way (claims born
here — this entry their only evidence — come first, since no later article
will review them; `detail.uncapped_edges`); the manifest only ever holds
machine-asserted edges whose verdict is still open. `backend/app/services/entry_adjudication.py`,
`backend/app/workers/adjudication_tasks.py`; stage `adjudicate` (kind
`post_analysis`), task `adjudicate_entry_task` on the `ai` Celery queue,
dispatched from the analysis landing path (`enqueue_adjudication`), not
scheduled. This is the day-to-day cleanup path: every link, minted entity,
asserted edge and captured observable is judged once, at ingest. The AI task
behind it is `entry_adjudication` (Settings → AI Configuration → Prompts).

| Setting | Type / default | What it does |
|---|---|---|
| `adjudication_mode` | `off` \| `shadow` \| `apply`, default `apply` | The master switch (pipeline plans only subtract feeds). `shadow` files every verdict as a proposal on Review › Proposals and touches nothing. `apply` acts on verdicts at or above the confidence floor at ingest, through the same code the queue's Apply buttons use; lower ones still become proposals. The Proposed/Applied switch on Review › Proposals writes `shadow` / `apply`; `off` is set from the Adjudicate stage panel. |
| `adjudication_trigger` | `all` \| `created`, default `all` | `all` reviews every analysed entry (~100–500/day). `created` reviews only entries whose analysis minted an entity, wrote an AI junction row (actor/malware/tool/country/sector), asserted a TTP or a relationship, promoted a pending match or captured an observable (~20–50/day) — the fallback when reviews cannot keep up with ingest. |
| `adjudication_max_per_hour` | int, `0` | Reviews started per hour; `0` (the default) = no ceiling. The AI worker runs one call at a time, so with no ceiling the worker itself is the only pacing. Set a number for two reasons only: to hold down spend on a metered provider, and to stop a review backlog queueing ahead of the one-pass analysis, which shares that worker. Over-budget entries wait for the resweep. While a ceiling is set, the backfill may use at most half of each hour's budget; live entries get the rest. With no ceiling the backfill has no share, so dispatch it in batches via its own `limit`. |
| `adjudication_min_priority_score` | float, `0` | Skip entries below this priority score, on the 0–10 scale (`0` = off). Keep it at 0: CVE/NVD entries are the main source of junk tool entities and score low, so a floor would exempt exactly those. |
| `adjudication_apply_min_confidence` | `high` \| `medium` \| `low`, default `high` | In apply mode, verdicts below this confidence are filed as proposals instead of applied. |
| `adjudication_circuit_breaker_pct` | float, `0.5` | If more than this share of an entry's items come back destructive (remove + veto + demote + drop), the whole run is downgraded to proposals. A rolling mean over the last 50 **apply** runs above the same threshold (once 10 samples exist) pauses dispatch for an hour, logs a warning, and surfaces as `adjudication_breaker_until` in the hygiene stats and a chip in the Engine needs-you row. Shadow runs are not sampled: the breaker stops damage, and a shadow run makes no changes. |
| `adjudication_content_max_chars` | int, `8000` | Article text in the review prompt (head + indicator tail, the extraction window). |
| `adjudication_scope` | csv, `links,entities,relationships,observables` | Manifest sections the reviewer sees. `links` puts every entity link on the article under review; `entities` adds the catalogue lookup that makes `veto` and `merge` answerable, and on its own narrows the review to what this article minted. `assessment` is opt-in and only ever logged. |

**Gates**, first hit wins, each recorded on `ai_analysis_requests.adjudication_status`:
mode (`skipped_off`) → feed plan, only when pipeline plans are on
(`skipped_plan`) → echo-reused analysis (`skipped_echo`) → trigger
(`skipped_nothing_new`) → score floor (`skipped_score`) → hourly budget
(`skipped_budget`). A provider quota pause parks the row as `skipped_paused`.
Rows that pass go `pending` (stamping `adjudication_queued_at`) and end
`completed`, or `failed` once the task's Celery retries are exhausted. The task
itself re-checks only the master switch; a manual retry from the matrix
bypasses the other gates and re-queues the row.

**The resweep** (`resweep_adjudications`, run from
`submit_analysis_batches`, so every 30 minutes — the budget it drains
against is the hourly one) re-enqueues, newest first: completed analyses with
no decision after two hours, `skipped_budget` / `skipped_paused` rows every
hour, and `pending` rows queued more than six hours ago with no run (a lost
task). It does nothing while the `ai` queue holds more than
`RESWEEP_QUEUE_CEILING` (200) tasks: a deep queue is reviews waiting their
turn, not lost ones, and the entry analyses behind them need the worker more
than a history walk does. A task that finds its row already `completed`
(a duplicate dispatch) returns `skipped: already_reviewed` without calling
the model.

**What never changes, in any mode:** edges an analyst rejected, and links of a
validator junction type (actor, malware, vendor, product, country) that an
analyst restored within the last 90 days — flagged to the reviewer, never
applied. The guard reads the link log, which is the only place a restore is
recorded per entry per link, so tool, sector and TTP links are reviewed again
like any other row. Veto deletes an entity only when this entry created it and nothing
else holds it (no other article, edge or claim); otherwise it only unlinks.
Promotion of a relationship edge to *confirmed* is a counter on the edge
(`reviewer_kept_entry_ids`): a keep in apply mode from a new entry appends it,
and at `relationship_evidence_promote_count` distinct entries the edge is
promoted. A keep only counts when the reviewer **named that edge** and did so
at or above the confidence floor — it is the one verdict that raises trust
rather than lowering it, so silence is not agreement. Since the prompt
otherwise asks for changes only, it carves edges out and requires a verdict on
every one of them (at most ten per article). Stale entities (one article at most, no edge, 90 days idle) are a
live `stale` filter on Review › New entities.

**Queue.** Review › Proposals has a domain facet (what applying the row changes: links / entities / relationships), an origin facet (`adjudicator` | `legacy`),
per-row Apply / Dismiss / Restore, bulk **Apply all**
(`POST /api/admin/hygiene/adjudication/apply-all`) and **Dismiss all** scoped
by origin. A restore writes its own `adjudication_restored` audit line rather
than reusing the verdict's code, so an undo reads as history: it stays out of
the pending count, out of Apply all, and offers no buttons of its own. When a review completes it deletes the legacy pending rows it showed
the model as earlier suggestions (merge-engine and stale-sweep proposals about
entities this entry minted, validator rows on this entry). Legacy proposals no
entry can carry are listed by `GET /api/admin/hygiene/feed?orphaned=true` for
manual disposition; nothing automatic touches them.

**Backfill.** `celery -A app.workers.celery_app call
app.workers.adjudication_tasks.backfill_entry_adjudications` (kwargs `limit`,
`since_days`) marks older analysed entries pending through the same gates; the
sweep drains them within the backfill's half of the hourly budget.

### Entity assessments

Drafts and refreshes the AI-written description paragraph on entity profiles.
`backend/app/workers/entity_maintenance_tasks.py`; job
`backfill-entity-assessments`, daily 05:45 UTC.

| Setting | Type / default | What it does |
|---|---|---|
| `assessment_backfill_batch_size` | int, `50` | Entities dispatched per daily run. They queue serially on the single-concurrency AI worker, so the batch paces itself — raise to drain a backlog, lower to leave more of the worker's time for ingest extraction. |
| `assessment_backfill_min_articles` | int, `1` | Fewest linked entries before an entity is worth summarising. Raise it to spend the daily budget on better-covered entities first. |
| `assessment_backfill_retry_days` | int, `7` | Don't re-attempt an entity within this window. Without it the highest-article-count entities are re-picked every run and starve the rest of the queue. |
| `assessment_refresh_enabled` | bool, `true` | Also re-write assessments that have gone **stale**, not just missing ones — otherwise an entity assessed once keeps a paragraph describing the month it was written in. Only touches text this writer produced; analyst and enrichment descriptions are never overwritten. |
| `assessment_refresh_min_new_articles` | int, `10` | New linked articles since the assessment was written before it counts as stale. The writer reads the 20 most recent articles, so 10 means half its input has turned over. |
| `assessment_refresh_batch_size` | int, `10` | Stale refreshes per run, budgeted **separately** from the backfill so a long refresh queue can never crowd out an entity that has no assessment at all. |

### Actor profile refresh

Weekly AI rewrite of the most-active threat actor profiles. Job
`actor-profile-refresh`, Mondays 03:00 UTC.

| Setting | Type / default | What it does |
|---|---|---|
| `actor_refresh_top_n_per_run` | int, `20` | Actors refreshed per run. |
| `actor_refresh_min_age_days` | int, `60` | Skip actors refreshed more recently than this. |
| `actor_refresh_activity_window_days` | int, `90` | Lookback used to rank "most active". |
| `actor_refresh_sample_n` | int, `20` | Recent headlines sampled into each refresh prompt. |

### Narrative themes and actor refresh mode

| Setting | Type / default | What it does |
|---|---|---|
| `entity_maintenance_mode` | `shadow` \| `apply`, default `shadow` | The weekly actor profile refresh: `shadow` files the rewritten description as a proposal, `apply` writes it (the description history is the undo). |
| `narrative_themes_enabled` | bool, `true` | Parse the daily briefing's own `### Theme` grouping back out of its cached markdown and record which articles it placed together. Free — no AI call, no embeddings — and useful as a standalone record before the gate below is on. |
| `narrative_theme_gating` | bool, `false` | Let that grouping **veto** a co-occurrence promotion: a pair whose evidence all sits under one heading on one day is a single reporting wave, not corroboration. Leave off until a couple of weeks of themes have accumulated — with no parsed coverage the gate has no opinion and changes nothing. |

### Detection-rule maintenance

| Setting | Type / default | What it does |
|---|---|---|
| `rule_attack_backfill_limit` | int, `1500` | Detection rules re-fetched per ATT&CK-mapping backfill run. Job `backfill-rule-attack-mappings`, Sundays 05:30 UTC. |

### Retention

| Setting | Type / default | What it does |
|---|---|---|
| `engine_run_retention_days` | int, `30` | Days of engine bookkeeping kept: `job_runs`, `entry_pipeline_runs`, non-pending `ai_analysis_requests`, `ai_batch_jobs`, resolved `pending_autolink_matches`. `entry_signals` is **not** pruned — signals live as long as their entry. Job `prune-engine-tables`, daily 02:40 UTC. |
| `telegram_media_ttl_days` | int, `30` | Delete downloaded Telegram media files older than this. Entries and extracted intel are kept. Job `evict-old-telegram-media`, daily 04:25 UTC. |
| `tts_cache_ttl_days` | int, `30` | Evict cached Piper audio not played within this window (per-row TTLs, e.g. the 24h share pre-gen, still win). |
| `tts_cache_max_bytes` | int, `2 GB` | LRU size cap for cached read-aloud audio; oldest-played files are evicted first. Disk is the binding constraint, not the TTL. Job `evict-tts-cache`, daily 04:15 UTC. |

---

## Outside the Engine console

These are DB-overridable like everything above, but render on ordinary Settings
sections rather than the Engine console.

### Settings → Users

| Setting | Type / default | What it does |
|---|---|---|
| `registration_enabled` | bool, `true` | Whether `POST /api/auth/register` accepts new accounts. The first account created becomes the admin. |
| `registration_invite_code` | secret, generated | When set, registration also requires this code. One is generated the moment the first account (the admin) registers, so an install is never open to strangers by accident; clear it under Settings → Users to reopen registration. |

### Settings → System

| Setting | Type / default | What it does |
|---|---|---|
| `sentry_dsn` | secret, empty | Sentry DSN. Empty disables Sentry entirely. Read once at API startup (after the settings cache is warmed), so a change needs a restart. |
| `sentry_traces_sample_rate` | float, `0.1` | Performance trace sampling. Read at startup, with the DSN. |
| `sentry_profiles_sample_rate` | float, `0.1` | Profiling sampling. Read at startup, with the DSN. |
| `backup_retention_days` | int, `7` | Days of `pg_dump` backups kept. Job `backup-database`, daily 02:00 UTC. |

### Settings → AI Configuration → User keys

The `ai` group's personal-key policy. The whole feature sits behind the first
switch; with it off the others are inert and every AI call runs exactly as if
they did not exist. The lookup they govern is described in
[automation-ai-enrichment.md](automation-ai-enrichment.md#personal-keys--the-lookup).

| Setting | Type / default | What it does |
|---|---|---|
| `allow_user_ai_providers` | bool, `false` | Let people add their own AI keys; the tasks they start run on them and fall back to the instance's providers when the key is missing, failing or over its cap. |
| `require_user_ai_provider` | bool, `false` | With personal keys on: refuse an interactive task instead of falling back. Ignored while personal keys are off. |
| `user_ai_provider_types` | str, `claude,openai_compatible` | Comma-separated types a person may register (`ollama` may be added; `claude_code` never qualifies). Re-checked on every call, so removing a type stops keys already saved. |
| `user_ai_allow_private_endpoints` | bool, `false` | Let a personal key point at a private address, such as a LAN Ollama. The server resolves the hostname on save and on every call. |
| `user_ai_daily_request_cap` | int, `300` | Requests one person may make on their own keys per UTC day. Counts calls, since Ollama and unpriced models report $0. `0` = unlimited. |
| `site_ai_user_daily_requests` | int, `0` | Requests one person may make per UTC day on the *instance's* providers for the tasks they start (copilot, rule help, summaries, reports). Background work, automation rules and share links are not counted; failed calls are. `0` = unlimited. |
| `share_ai_daily_requests` | int, `20` | AI questions and tasks one share link may run per UTC day, across both share routes. Share traffic always uses the instance's providers. `0` = unlimited. |

### Settings → Feeds (public RSS)

| Setting | Type / default | What it does |
|---|---|---|
| `public_rss_enabled` | bool, `false` | Re-publish aggregated entries over a token-gated RSS URL. Only active feeds that are not muted are included (the instance-wide mute, not a reader's own). |
| `public_rss_per_feed_limit` | int, `100` | Items per feed in the published output. |
| `public_rss_full_content` | bool, `true` | Include full article content rather than summaries. |

### Content generation (no console surface)

The `content` group has no entry in the console's `GROUP_DEST` map, so the
Engine settings search will not deep-link to it; edit these from Settings →
System.

| Setting | Type / default | What it does |
|---|---|---|
| `threat_brief_limit` | int, `30` | Open Threats-board rows given an AI story line per nightly run. Job `generate-threat-briefs`, daily 04:40 UTC. |
| `reddit_digest_min_entries` | int, `3` | Skip the daily Reddit digest when fewer than this many qualifying posts were collected. |
| `reddit_digest_max_entries` | int, `20` | Cap on posts fed into the digest prompt. Job `generate-reddit-digest`, daily 07:00 UTC. |

---

## Setting → scheduled job

The `settings_keys` field on each `JOB_REGISTRY` entry
(`backend/app/workers/job_registry.py`) links a job to the settings that govern
it, so the Jobs browse screen can show them inline. Jobs not listed here read no
settings.

| Job key | Schedule (UTC) | Settings |
|---|---|---|
| `poll-feeds` | every 60 s | `default_feed_fetch_interval`, `user_agent` |
| `check-feed-health` | every 6 h at :30 | `feed_auto_pause_days` |
| `embed-entries` | every 15 min | `embeddings_enabled`, `embedding_model`, `embedding_base_url`, `embedding_batch_size`, `embedding_backfill_limit` |
| `story-threads` | every 2 h | all `thread_*` except `thread_narrate_limit`, `thread_signals_enabled` |
| `narrate-story-threads` | 06:10 | `thread_narrate_limit` |
| `ai-analysis-batch-submit` | every 30 min | all `ai_*` |
| `signal-rate-recompute` | 04:20 | `signal_feedback_min_samples` |
| `signal-personal-weight-fit` | 04:35 | `radar_personalization_*` |
| `signal-rescore-recent` | every 6 h at :35 | `signal_engine_shadow`, `signal_engine_surface` |
| `signal-rescore-all` | Mon 03:00 | `signal_engine_shadow`, `signal_engine_surface` |
| `backfill-entity-assessments` | 05:45 | all `assessment_*` |
| `actor-profile-refresh` | Mon 03:00 | all `actor_refresh_*`, `entity_maintenance_mode` |
| `relationship-confidence-decay` | Sun 03:45 | `relationship_recency_half_life_days` |
| `generate-daily-summaries` | 06:00 | `narrative_themes_enabled` |
| `generate-threat-briefs` | 04:40 | `threat_brief_limit` |
| `generate-reddit-digest` | 07:00 | `reddit_digest_min_entries`, `reddit_digest_max_entries` |
| `decay-observable-confidence` | 02:20 | `observables_decay_enabled` |
| `reenrich-cve-nvd` | 03:05 | `cve_reenrich_batch_size` |
| `github-poc-scan` | 05:00 | `github_poc_batch_limit`, `github_poc_rescan_days` |
| `backfill-rule-attack-mappings` | Sun 05:30 | `rule_attack_backfill_limit` |
| `refresh-correlation-cache` | hourly at :10 | `correlation_cache_ttl_seconds` |
| `retry-untranslated-entries` | every 30 min | `translation_default_target` |
| `evict-image-cache` | 04:10 | `image_proxy_cache_ttl_days`, `image_proxy_max_size_bytes` |
| `evict-tts-cache` | 04:15 | `tts_cache_ttl_days`, `tts_cache_max_bytes` |
| `evict-old-telegram-media` | 04:25 | `telegram_media_ttl_days` |
| `prune-engine-tables` | 02:40 | `engine_run_retention_days` |
| `backup-database` | 02:00 | `backup_retention_days` |

The full 70-job registry, including the jobs with no settings, is documented in
[workers-search-dashboards.md](workers-search-dashboards.md).

---

## Env-only settings

These 48 are **not** in `CONFIGURABLE_KEYS` — they come from the environment or
`.env` and take a process restart to change. Infrastructure and secrets that
should not be editable from a web UI.

| Area | Keys |
|---|---|
| Environment | `env` |
| Build stamp | `app_version`, `git_sha`, `build_time` — baked into the image by `scripts/ops/version.sh` and compose build args, not set in `.env`; they feed the version string in the app footer |
| Postgres | `postgres_host`, `postgres_port`, `postgres_db`, `postgres_user`, `postgres_password`, `postgres_ssl`, `db_pool_size`, `db_max_overflow`, `worker_db_pool_size`, `worker_db_max_overflow` |
| Redis / Meilisearch | `redis_url`, `meili_url`, `meili_master_key`, `meili_timeout` |
| Auth & crypto | `secret_key`, `access_token_expire_minutes`, `refresh_token_expire_days`, `encryption_key`, `encryption_key_previous` |
| Networking | `cors_origins`, `public_base_url`, `rate_limit_overrides`, `webhook_allow_private_networks` |
| Storage paths | `image_proxy_cache_dir`, `tts_media_dir`, `telegram_media_dir`, `telegram_session_path` |
| GitHub repo adapter | `github_repo_max_file_size_kb`, `github_repo_default_interval_minutes` |
| Telegram | `telegram_api_id`, `telegram_api_hash`, `telegram_max_media_size_mb`, `telegram_flood_sleep_threshold`, `telegram_ocr_enabled`, `telegram_ocr_min_chars` |
| Translation sidecar | `libretranslate_url`, `libretranslate_api_key`, `translation_timeout_seconds` |
| TTS sidecar | `tts_enabled`, `piper_url`, `piper_voice`, `piper_timeout_seconds`, `tts_max_text_chars` |
| Copilot | `copilot_worker_dispatch` |

`postgres_password`, `meili_master_key`, `secret_key` and `encryption_key` are
validated at startup: the literal `changeme` warns in development and **raises**
in production (`_reject_insecure_defaults`, `backend/app/config.py:457`). `encryption_key`
must additionally be a valid 32-byte URL-safe base64 Fernet key.

---

## Related docs

- [engine.md](engine.md) — the pipeline, signal and console subsystems these settings steer
- [story-threads.md](story-threads.md) — what the `thread_*` knobs are actually clustering
- [intelligence-engine.md](intelligence-engine.md) — autolinker and correlation internals
- [workers-search-dashboards.md](workers-search-dashboards.md) — the full job registry and beat schedule
- [operations.md](operations.md) — deployment, `.env` handling, and backup/restore
