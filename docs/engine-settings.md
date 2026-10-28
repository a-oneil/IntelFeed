# Engine Settings Reference

This is the list of every IntelFeed setting: what it does, its default, and where you change it. It is for admins tuning an instance and for developers adding a setting. [engine.md](engine.md) explains the systems these settings control.

IntelFeed has **208 settings**:

- **157** can be changed in the web UI. They are listed in `CONFIGURABLE_KEYS` (`backend/app/services/system_settings.py:26`). One of them, `registration_invite_code`, lives only in the database.
- **51** come only from the environment (`.env`). See [Env-only settings](#env-only-settings).
- Six are **secrets**. They are encrypted in the database and never sent back to the browser: `github_token`, `nvd_api_key`, `observables_publish_token`, `registration_invite_code`, `sentry_dsn`, `smtp_password` (`SECRET_KEYS`, `system_settings.py:14`).

---

## How a setting resolves

Code reads a setting with `settings.get(key)` (`backend/app/config.py:509`). The value comes from the first of these that has one:

1. **Database.** If the key is in `CONFIGURABLE_KEYS` and the `system_settings` table holds a value, that value wins.
2. **Environment.** A value in `.env` or a real environment variable, read when the process starts.
3. **Code default.** The value written in `config.py`.

Reading `settings.key` as a plain attribute skips the database, so a UI change would do nothing. Always use `settings.get()` for a setting that should be editable.

The code defaults are the values the reference instance uses after tuning, so a fresh install starts out tuned. You still need to set the things that depend on your instance: the AI text budget (`ai_analysis_content_max_chars`, which depends on your AI host's memory), anything that publishes data outward (`public_rss_enabled`, `observables_publish_enabled`), your own name lists (`autolinker_false_positive_names`, `autolinker_blocked_surface_forms`), secrets, and URLs.

A database value that equals the default does nothing useful, and it stops you getting a better default later. `scripts/maintenance/prune_setting_overrides.py --dry-run` lists those, plus values for keys nothing reads and overrides for jobs that don't exist. Run it without `--dry-run` to delete them.

**Caching.** The API re-reads the settings table at most every 5 seconds (`_CACHE_TTL`). A Celery task reads fresh values when it starts (`warm_settings_cache()`). A task that is already running keeps the values it started with. No restart is needed.

**Each environment is separate.** Settings live in each instance's database, so a change in dev does not reach production. Change production in production's own Settings UI.

### Where the metadata comes from

| Structure | File | Role |
|---|---|---|
| `CONFIGURABLE_KEYS` | `backend/app/services/system_settings.py:26` | Which keys the UI can edit, and each value's type |
| `SETTING_METADATA` | `backend/app/services/system_settings.py:208` | Label, description and group shown in the UI |
| `_ENGINE_SECTION_GROUPS` | `backend/app/services/system_settings.py:1319` | Moves engine keys into the group of the Engine panel that owns them |
| `SECRET_KEYS` | `system_settings.py:14` | Encrypted in the database, hidden on read |
| `GROUP_DEST` | `frontend/src/components/engine/engineSettingsIndex.ts:26` | Which Engine screen shows each group; drives the Engine settings search |
| `KEY_DEST` | `frontend/src/components/engine/engineSettingsIndex.ts:67` | Single keys that live somewhere other than their group's screen |

To add a setting, add it to `config.py` (default), `CONFIGURABLE_KEYS` (type) and `SETTING_METADATA` (label, description, group). If a scheduled job reads it, also add it to that job's `settings_keys` in `backend/app/workers/job_registry.py`. A key missing from `CONFIGURABLE_KEYS` always returns the env default, and the UI can never change it.

### Finding a setting

Settings → Engine has a search box (`EngineSettingsSearch.tsx`). It matches key, label and description, and links to the screen that shows the setting.

---

## Autolink stage

Settings → Engine → *autolink* stage panel. These control the dictionary scan that links known entity names in articles (`backend/app/intelligence/autolinker.py`). See [intelligence-engine.md](intelligence-engine.md) for how it works.

| Setting | Type / default | What it does |
|---|---|---|
| `autolinker_min_name_length` | int, `3` | Names shorter than this are never matched. |
| `autolinker_ambiguous_name_max_length` | int, `10` | A one-word, letters-only name up to this length must appear **capitalised** to match. So "Royal" the actor matches *Royal ransomware* but not *the royal family*. |
| `autolinker_ambiguous_max_occurrences` | int, `3` | If such a name appears more than this many times in one article, it is skipped there. Heavy repetition usually means an ordinary word. |
| `autolinker_false_positive_names` | csv, about 120 names | Names never matched: common words, malware category words, brand words, Windows built-ins and known bad aliases. Applies **only to actor, malware and country** matches, because vendor, product, tool and mitigation names often are brand words. Edited as a table on the panel, or via `GET/POST/DELETE /api/engine/autolink/fp-names`. |
| `autolinker_blocked_surface_forms` | csv, empty | Words an analyst blocked with the reader's *Wrong? → never match this word*. Applies to **every** entity type. Managed from the reader and the autolink panel. |
| `autolink_pending_tier_enabled` | bool, `true` | Actor, malware, tool and country matches whose only matched words are ordinary dictionary words are held for the AI to confirm, not linked at once. If the feed has AI analysis off, nothing could confirm them, so they are dropped. Off links them straight away. |

The autolinker rebuilds its word list every 30 minutes (job `refresh-autolinker-vocabulary`). Changes made through the API also trigger a rebuild.

---

## Observables stage

Settings → Engine → *observables* stage panel. The publish settings are on the **Publishing** screen. Code: `backend/app/intelligence/observables.py`.

An observable is an indicator of compromise (IOC), such as an IP address, domain or file hash. The main rule: **pattern matching never creates an observable.** Regex only marks *candidates* on the article. Observables are created by a judgment: the AI analysis, a TTP record, a curated IOC-list feed, or an analyst. After that, known values are matched exactly in new articles.

| Setting | Type / default | What it does |
|---|---|---|
| `observables_candidate_max` | int, `200` | Most candidates marked on one article. |
| `observables_analysis_tail_reserve` | float, `0.4` | When an article is longer than `ai_analysis_content_max_chars`, this share of the AI's text budget is kept for the article's indicator section (usually at the end). `0` turns it off, and the AI sees only the start. |
| `observables_codeblock_skip_categories` | csv, `Security Advisories,Government / CERT` | Feed categories whose code blocks never produce host-type candidates, because bulletins use code blocks for plain text. Detection-rule repositories are always skipped. |
| `observables_publisher_ioc_enabled` | bool, `true` | When an article links to an IOC file in a known publisher repository (Cisco Talos, Bitdefender, Datadog), fetch it and record its indicators on the article. |
| `observables_publisher_ioc_max_values` | int, `2000` | Most indicators taken from one IOC file. |
| `observables_ai_capture_kinds` | csv, `ipv4,ipv6,domain,url,uri_path,email,ja3,ja4,cert_fingerprint,md5,sha1,sha256,script` | In `capture` mode, only these kinds become observables directly. Other kinds the AI reports stay as candidates an analyst can promote. Add host kinds (`cmdline`, `path`, `registry`, `scheduled_task`, `service_name`, `mutex`, `named_pipe`, `user_agent`, `http_header`) once `scripts/dev/eval_observable_extraction.py` shows they are accurate. |
| `observables_ai_capture_mode` | `shadow` \| `capture`, default `capture` | `shadow`: indicators the AI confirms stay as candidates for review. `capture`: they become observables directly. |
| `observables_decay_enabled` | bool, `true` | Lowers confidence in network indicators over time: half-life 30 days for IPs, 60 for URLs, 90 for domains. Hashes and host artifacts never decay. A new sighting resets the clock. Job `decay-observable-confidence`, daily 02:20 UTC. |

### Publishing (Engine → Publishing browse screen)

Feeds of observables for other tools to pull: blocklists, SIEM lookup CSVs and a TAXII 2.1 collection (`backend/app/api/publish.py`). These endpoints check their own tokens instead of user logins.

| Setting | Type / default | What it does |
|---|---|---|
| `observables_publish_enabled` | bool, `false` | Master switch. When off, every publish endpoint returns 404. |
| `observables_publish_token` | secret csv, empty | Consumer tokens as `name:secret` pairs (a bare secret also works). Give each consumer its own token so you can revoke it. Send as `Authorization: Bearer` or `?token=`. |
| `observables_publish_min_confidence` | float, `0.6` | Lowest current confidence (after decay) a value needs to be published. Raise it to shrink a blocklist. |
| `observables_publish_max_age_days` | int, `90` | Values not seen for longer than this are left out. |
| `observables_publish_never_suffixes` | csv, empty | Domain suffixes never published, such as your own domains. They stay in the database. Shared CDN and hosting domains are always left out. This one also shows on the observables stage panel. |

---

## Extract stage

Settings → Engine → *extract* stage panel. This stage uses pattern matching only, with no AI. It pulls CVE, ATT&CK technique and mitigation IDs out of the text. AI settings are on the [Analyze stage](#analyze-stage).

| Setting | Type / default | What it does |
|---|---|---|
| `attack_ics_context_keywords` | csv, ICS words (`ics,ot,scada,plc,…`) | ATT&CK ICS techniques (`T0xxx`) are linked only when the article contains one of these words. This stops IT articles picking up ICS IDs by accident. Read by `backend/app/intelligence/attack_catalog.py`. |
| `cve_epss_high_risk_threshold` | float, `0.1` | EPSS score at or above which a CVE counts as **high** risk. Used for CVE risk tiers, triage scoring and badges (`backend/app/intelligence/cve.py`). |

---

## Analyze stage

Settings → Engine → *analyze* stage panel (`AnalyzeStageConfig.tsx`). This holds the AI analysis settings (group `ai`, minus the personal-key settings) and the entity creation checks (group `extraction`, minus the two above). The panel also sets the model and output-token limit for the `entry_analysis` AI task, and the list of names the AI may never create.

### One-pass AI analysis

Each article gets one AI call, `entry_analysis`, that extracts everything at once. It is requested when scoring finishes and sent in batches under a daily budget. Code: `backend/app/services/entry_analysis.py` and `backend/app/workers/ai_batch_tasks.py`. Jobs: `ai-analysis-batch-submit` (every 30 minutes) and `ai-analysis-batch-poll` (every 10 minutes).

| Setting | Type / default | What it does |
|---|---|---|
| `ai_one_pass_enabled` | bool, `true` | Master switch. It also needs an enabled `entry_analysis` task assignment (Settings → AI Configuration). |
| `ai_daily_budget_usd` | float, `2.0` | Daily spending cap. When it is reached, articles wait. The next run takes the highest-priority ones first. |
| `ai_analysis_relevance_threshold` | float, `0.15` | Articles scoring below this on the keyword relevance check skip AI analysis. On `selective` feeds they also skip autolinking. It asks "is there anything to extract", not "is this important". |
| `ai_batch_max_requests` | int, `500` | Most articles per batch. |
| `ai_analysis_content_max_chars` | int, `12000` | Characters of article text sent to the AI. Longer articles send the start plus the indicator section (see `observables_analysis_tail_reserve`). |
| `ai_use_batches` | bool, `true` | Use the Anthropic Message Batches API (half price) when the provider is Anthropic. Other providers get one call per article. |
| `ai_est_cost_per_request` | float, `0.0024` | Estimated cost per article, used to fit a batch inside the daily budget. Set it near zero for local models such as Ollama. |
| `ai_tool_evidence_required` | bool, `true` | Only save an extracted **tool** when the AI names who used it and quotes the sentence that shows it. This stops every mention of a tool like `certutil` becoming an entity. |

### Entity creation guardrails

`backend/app/intelligence/entity_resolution.py`. These checks run before an AI-extracted name becomes a new entity.

| Setting | Type / default | What it does |
|---|---|---|
| `entity_resolution_normalized_match` | bool, `true` | Match new names to existing entities after ignoring case, punctuation, spacing and number-for-letter swaps. So `Cl0p` matches `Clop` instead of making a duplicate. |
| `entity_creation_gates` | `off` \| `shadow` \| `on`, default `on` | Checks for generic names, the deny list, the wrong entity type and bad aliases. `shadow` logs what would be blocked but still creates. `on` blocks. Manual creation always works but is logged. |

---

## Score stage

Settings → Engine → *score* stage panel. It has two groups: signal scoring (`scoring`) and story threads (`threads`). The scoring model is in [engine.md](engine.md#signal-scoring-model); thread clustering is in [story-threads.md](story-threads.md).

### Signal engine and Radar

Radar is the ranked view of articles (the `radar` sort and the Priority Queue). Analysts vote on whether an article deserved its rank, and those votes tune the scoring.

| Setting | Type / default | What it does |
|---|---|---|
| `signal_engine_shadow` | bool, `true` | Compute and store each article's signals and `priority_score`. Changes nothing in the UI by itself. |
| `signal_engine_surface` | bool, `true` | Show the scores: priority chips, the `radar` sort, ranked triage and the `entry_scored` live event. |
| `signal_feedback_min_samples` | int, `20` | Votes a signal family needs in 30 days before votes adjust its weight for everyone. Below this its weight stays 1.0. |
| `radar_personalization_enabled` | bool, `false` | Let each analyst's own votes re-order their own `radar` list. The stored score stays the same for everyone, so this changes order, never which articles appear. The Priority Queue does not use it. Each user must also opt in (`User.settings["radar_personalized"]`). |
| `radar_personalization_min_samples` | int, `5` | Votes one analyst needs in a family before it gets a personal weight. |
| `radar_personalization_window_days` | int, `90` | How far back the nightly per-user fit looks. |
| `my_stack_exposure_enabled` | bool, `true` | Show CVEs that affect vendors and products you follow in the Priority Queue, and power the Threats page's Vulnerabilities tab. **Needs `signal_engine_surface`.** |
| `exposure_attack_visibility_enabled` | bool, `true` | On the Vulnerabilities tab, for a CVE with no detection rule, estimate whether your telemetry could see it, using the ATT&CK techniques that appear alongside it in articles. This is a weaker signal than a real rule. |

Jobs: `signal-rate-recompute` (daily 04:20 UTC), `signal-personal-weight-fit` (daily 04:35 UTC), `signal-rescore-recent` (every 6 hours at :35), `signal-rescore-all` (Sundays 03:00 UTC).

Signal family weights and the Radar threshold are not settings rows. They live in Redis and are changed with the sliders on the score stage card (`PUT /api/engine/signals/settings`). See [engine.md](engine.md#redis-state).

### Embeddings

An embedding is a list of numbers that captures what an article is about, so similar articles can be found. These settings sit outside the AI task assignments so embedding keeps running when chat models are paused. Job: `embed-entries`, every 15 minutes.

| Setting | Type / default | What it does |
|---|---|---|
| `embeddings_enabled` | bool, `true` | Master switch. Story threads, evidence stories and thread-based signals need it. It needs an Ollama provider serving `embedding_model`, or `embedding_base_url`. Without either, the job logs a line and skips. |
| `embedding_model` | str, `nomic-embed-text` | Ollama model to use. It must output **768 numbers**, because the database column has that fixed size. |
| `embedding_base_url` | str, empty | Ollama server for embeddings. Blank uses the Ollama provider's URL, then `OLLAMA_BASE_URL`. |
| `embedding_batch_size` | int, `32` | Texts per request. |
| `embedding_backfill_limit` | int, `2000` | Articles embedded per run. |

### Story threads

A story thread groups articles about the same unfolding story. Code: `backend/app/intelligence/story_threads.py`. Jobs: `story-threads` every 2 hours; `narrate-story-threads` daily at 06:10 UTC.

| Setting | Type / default | What it does |
|---|---|---|
| `thread_window_days` | int, `21` | How old an article can be and still join a thread. |
| `thread_dormancy_days` | int, `14` | Days of silence after which a thread stops taking new articles. |
| `thread_gap_days` | int, `5` | Most quiet days allowed between an article and the thread's latest article. Stops an old story absorbing new, unrelated news. |
| `thread_min_body_chars` | int, `400` | Shorter articles are treated as bulletins and never threaded. |
| `thread_join_similarity` | float, `0.84` | Similarity needed to join a thread when the article shares an entity with it. |
| `thread_join_similarity_no_entity` | float, `0.90` | Higher similarity needed when no entity is shared. |
| `thread_seed_similarity` | float, `0.84` | Similarity between two loose articles needed to start a thread. |
| `thread_duplicate_similarity` | float, `0.90` | At or above this, an article is an **echo** (a re-report), not a new development. |
| `thread_merge_similarity` | float, `0.92` | Similarity at which two overlapping threads are merged. |
| `thread_sweep_limit` | int, `1500` | Articles checked per run. Keep it well above the number of articles published within `thread_gap_days`, or new articles never get threaded. |
| `thread_min_entries` | int, `3` | Articles needed before a group becomes a thread. |
| `thread_min_sources` | int, `2` | Distinct source **domains** needed before a group becomes a thread. |
| `thread_narrate_limit` | int, `10` | Threads given an AI-written summary per nightly run. |
| `thread_signals_enabled` | bool, `true` | Use thread membership for the `feed_echo` and `source_convergence` signals. Off uses shared-entity overlap instead. |

---

## Correlation stage

Settings → Engine → *correlation* stage panel (group `intelligence`). These control how strong a link between two entities looks, how much it is trusted, and what is shown. Code: `backend/app/intelligence/correlation.py`. See [intelligence-engine.md](intelligence-engine.md).

### Strength composition

Strength mixes three parts. Their weights should add up to 1.0.

| Setting | Type / default | What it does |
|---|---|---|
| `relationship_weight_corroboration` | float, `0.45` | Weight for how many separate articles support the link. |
| `relationship_weight_closeness` | float, `0.40` | Weight for how close together the two entities appear in articles. |
| `relationship_weight_recency` | float, `0.15` | Weight for how recent the evidence is. |
| `relationship_corroboration_saturation` | int, `8` | Number of articles at which corroboration is maxed out. |
| `relationship_recency_half_life_days` | int, `90` | Days for the recency part to halve. The weekly `relationship-confidence-decay` job also uses it as the staleness window. |
| `relationship_reliability_high_multiplier` | float, `1.15` | Extra weight for evidence from feeds rated A or B. `1.0` turns it off. |
| `relationship_reliability_low_multiplier` | float, `0.85` | Weight for evidence from feeds rated D or E. C, F and unrated feeds count as 1.0. |

### Proximity scoring

How close two entity mentions are, by paragraph. Formula: `1 / (1 + decay_rate × distance)`.

| Setting | Type / default | What it does |
|---|---|---|
| `proximity_default_score` | float, `0.3` | Score used when there is no paragraph data. |
| `proximity_decay_rate` | float, `1.0` | How fast the score falls with distance. Higher is stricter. |
| `proximity_strong_threshold` | float, `0.7` | Lowest score labelled **strong**. |
| `proximity_moderate_threshold` | float, `0.3` | Lowest score labelled **moderate**. Below this is **weak**. |

### Trust, specificity and display

| Setting | Type / default | What it does |
|---|---|---|
| `relationship_evidence_promote_count` | int, `3` | Separate pieces of evidence needed to raise a link one confidence level. |
| `relationship_min_confidence` | `possible` \| `probable` \| `confirmed`, default `possible` | Lowest confidence shown on profiles, graphs and timelines. `probable` hides unconfirmed guesses; `confirmed` shows only confirmed links (MITRE import, AI review, analyst). Engine admin screens always show everything. |
| `relationship_min_tier_default` | `all` \| `moderate` \| `strong`, default `all` | Default lowest strength tier in "related" lists. Each view can narrow it. |
| `relationship_specificity_weight` | float, `0.5` | How much a very common entity (one that appears everywhere, like a big vendor) is pushed down related lists. `0` off, `1` full. |
| `relationship_reporting_source_specificity` | float, `0.45` | Vendors and products below this specificity are treated as *reporting sources* (the company that wrote the report) and grouped separately on profiles. |
| `graph_max_neighbors_per_node` | int, `30` | Most neighbours shown per node in an entity graph. |
| `graph_max_claim_edges` | int, `300` | Most relationship edges in one graph, most trusted first. |
| `correlation_cache_ttl_seconds` | int, `3600` | Seconds correlation results stay cached (`correlation_cache.py`). The `refresh-correlation-cache` job refills it hourly at :10. |

### Evidence structure

| Setting | Type / default | What it does |
|---|---|---|
| `relationship_evidence_structure` | bool, `true` | Group each link's evidence articles into **stories** using embeddings, so a link can say "seen across N incidents" instead of counting every roundup. Also used when promoting links and ordering the AI review queue. **Needs embeddings.** |
| `relationship_story_threshold` | float, `0.75` | Similarity needed to put two evidence articles in the same story. 0.70 merges digests into incidents; 0.75 keeps them apart. |

---

## Enrich stage

Settings → Engine → **Enrichment**, under **Settings** at the bottom of the page (groups `enrichment` and `api_keys`); the *enrich* stage opens the same page. The page lists every source with its status and what it fills; expanding a row shows its limits, outputs (fill rates, backfill) and jobs. Enrichment adds facts from outside sources (NVD, GitHub and others) to entities. See [automation-ai-enrichment.md](automation-ai-enrichment.md).

| Setting | Type / default | What it does |
|---|---|---|
| `nvd_api_key` | secret, empty | NIST NVD API key. Raises the limit from 5 to 50 requests per 30 seconds, so a CVE backfill takes hours, not days. |
| `github_token` | secret, empty | GitHub token for repo feeds and exploit (PoC) search. No scopes needed for public repos. |
| `cve_reenrich_batch_size` | int, `150` | CVEs re-fetched from NVD per `reenrich-cve-nvd` run. |
| `github_poc_batch_limit` | int, `0` | CVEs searched per `github-poc-scan` run. `0` means 300 with a token, 40 without (GitHub blocks unauthenticated search quickly). |
| `github_poc_rescan_days` | int, `30` | Days before a CVE is searched again. |
| `enrichment_paused` | bool, `false` | Refuses every request to outside sources; queued lookups wait and scheduled jobs stop. The page's **Pause enrichment** button sets it. |

---

## Translate stage

| Setting | Type / default | What it does |
|---|---|---|
| `translation_default_target` | str, `en` | Language to translate into when a feed doesn't set its own. |

The LibreTranslate URL, key and timeout are env-only.

---

## Feeds view

Settings → Engine → **Feeds** view (groups `feeds`, `rate_limiting`, `image_proxy`, `feed_value`).

| Setting | Type / default | What it does |
|---|---|---|
| `default_feed_fetch_interval` | int, `30` min | Minutes between fetches for a feed that doesn't set its own. |
| `feed_auto_pause_days` | int, `30` | Pause a feed after every fetch has returned **HTTP 4xx** for this many days in a row. Server errors, timeouts and quiet feeds never count. While failing, the fetch interval doubles after each failure, up to 24 hours. Paused feeds show as **Dead** on the Feeds view with the reason. An admin can resume one with `POST /api/feeds/{id}/resume`. Checked by `check-feed-health` every 6 hours. `0` turns it off. |
| `user_agent` | str, browser-like | `User-Agent` sent when fetching feeds. It looks like a browser because many sites block obvious bots. |
| `rate_limit_default_interval` | float, `2.0` s | Seconds between requests to the same site. Per-site values are env-only (`rate_limit_overrides`). |
| `per_user_subscriptions_enabled` | bool, `true` | Each analyst picks their own feeds and mutes from the shared pool. Off means one shared list where a mute affects everyone. Mutes made while it is off are stored on the shared feed only, so they disappear for everyone when it is turned on. |
| `ingest_max_file_mb` | int, `50` | Largest file for manual upload, including each file inside a `.zip`. A bigger file is marked `too_large`. |
| `ingest_max_batch_items` | int, `200` | Most items in one upload batch, counting files from a `.zip` or GitHub repository. |
| `ingest_zip_max_members` | int, `100` | Most files taken from one `.zip`. A larger archive is refused as `unsupported`. |
| `image_proxy_enabled` | bool, `true` | Load article images through IntelFeed, so the publisher can't see who is reading. |
| `image_proxy_cache_ttl_days` | int, `30` | Days a proxied image stays cached (`evict-image-cache`, daily 04:10 UTC). |
| `image_proxy_max_size_bytes` | int, `10 MB` | Largest image the proxy will fetch. |

`ingest_files_dir` (default `/app/data/ingest_files`) is env-only. It is the folder, shared by api and celery-worker, that holds uploaded originals.

### Feed intel-value weights

How much each behaviour counts toward a feed's intel-value score (`backend/app/intelligence/source_analytics.py`). The weights are scaled to add up to 1.0 when the score is computed, so you only need to set them relative to each other.

| Setting | Default | Counts |
|---|---|---|
| `feed_value_weight_entity_yield` | `0.25` | Entities per article |
| `feed_value_weight_entity_intro` | `0.25` | Entities this feed reported first |
| `feed_value_weight_correlation` | `0.20` | Correlation events |
| `feed_value_weight_detection` | `0.15` | Detection rules |
| `feed_value_weight_pir` | `0.15` | Intelligence requirement (PIR) matches |

---

## Plans browse screen

Settings → Engine → **Plans**. A pipeline plan turns processing stages on or off per feed, per category, or for everything. See [engine.md](engine.md#pipeline-plans-feed--category--global-resolution).

| Setting | Type / default | What it does |
|---|---|---|
| `pipeline_engine_enabled` | bool, `false` | Use `PipelinePlan` rows on top of each feed's own switches. Off uses the feed switches only. Turning it off is a safe, instant rollback. |
| `pipeline_run_logging_enabled` | bool, `true` | Record one `entry_pipeline_runs` row per stage per article. Off stops new rows; old ones stay until retention removes them. |

---

## Maintenance browse screen

Settings → Engine → **Maintenance** (groups `maintenance` and `retention`). This holds the AI cleanup jobs and the clean-up sweeps.

### Adjudicate stage (post-analysis AI review)

After an article's AI analysis is saved, a second, smaller AI call reviews it. It re-reads the article next to a list of everything the analysis wrote: entity links, new entities (with similar existing names), held matches, relationships and observables. For each item it wants to change, it returns a verdict: remove, reclassify, veto, merge, demote or drop. Items it leaves out are kept, so a clean review returns an empty list.

The list sent to the AI holds at most 60 entity links, 10 relationships and 25 observables. When there are more, the items only this review can judge go first: new entities, then held matches, then AI claims, then plain autolink matches. The rest are recorded in the run's `detail.uncapped_links` and `detail.uncapped_edges`.

Code: `backend/app/services/entry_adjudication.py` and `backend/app/workers/adjudication_tasks.py`. Stage `adjudicate` (kind `post_analysis`), task `adjudicate_entry_task` on the `ai` queue. It starts when an analysis is saved, not on a schedule. Its AI task is `entry_adjudication` (Settings → AI Configuration → Prompts).

| Setting | Type / default | What it does |
|---|---|---|
| `adjudication_mode` | `off` \| `shadow` \| `apply`, default `apply` | Master switch. `shadow` files every verdict as a proposal on Review › Proposals and changes nothing. `apply` acts on verdicts at or above the confidence floor; weaker ones become proposals. The Proposed/Applied switch on Review › Proposals sets `shadow` or `apply`; `off` is set on the Adjudicate stage panel. Pipeline plans can only turn it off for some feeds. |
| `adjudication_trigger` | `all` \| `created`, default `all` | `all` reviews every analysed article. `created` reviews only articles whose analysis created or claimed something (an entity, an AI link, a TTP, a relationship, a promoted match or an observable). Use `created` if reviews can't keep up. |
| `adjudication_max_per_hour` | int, `0` | Most reviews started per hour. `0` means no limit; the single AI worker is then the only pacing. Set a limit to cap spend on a paid provider, or to stop reviews delaying article analysis on the same worker. With a limit, the backfill gets at most half of each hour's budget. |
| `adjudication_min_priority_score` | float, `0` | Skip articles below this priority score (0–10). Keep it at 0: low-scoring CVE articles are the main source of junk tool entities. |
| `adjudication_apply_min_confidence` | `high` \| `medium` \| `low`, default `high` | In apply mode, verdicts below this are filed as proposals instead. |
| `adjudication_circuit_breaker_pct` | float, `0.5` | If more than this share of one article's items get a destructive verdict, the whole run becomes proposals. If the average over the last 50 apply runs goes above it (with at least 10 runs), reviews pause for an hour and a warning chip shows in the Engine console. |
| `adjudication_content_max_chars` | int, `8000` | Article characters in the review prompt. |
| `adjudication_scope` | csv, `links,entities,relationships,observables` | Which sections the reviewer sees. `entities` adds the lookup of existing names needed for `veto` and `merge`. `assessment` can be added but is only logged. |

**Skip checks.** Each is recorded in `ai_analysis_requests.adjudication_status`, and the first one that applies wins:

| Status | Why it skipped |
|---|---|
| `skipped_off` | `adjudication_mode` is off |
| `skipped_plan` | The feed's pipeline plan turns it off (only when plans are on) |
| `skipped_echo` | The analysis was copied from a near-duplicate article |
| `skipped_nothing_new` | `adjudication_trigger` is `created` and nothing was created |
| `skipped_score` | Below `adjudication_min_priority_score` |
| `skipped_budget` | Over `adjudication_max_per_hour` |
| `skipped_paused` | The AI provider hit its quota |

Rows that pass become `pending`, then `completed`, or `failed` once retries run out. A manual retry from the Engine table skips every check except the master switch.

**Resweep.** Every 30 minutes (inside `submit_analysis_batches`), `resweep_adjudications` re-queues, newest first: analyses with no review after two hours, `skipped_budget` and `skipped_paused` rows, and `pending` rows stuck for six hours. It does nothing while the `ai` queue holds more than 200 tasks (`RESWEEP_QUEUE_CEILING`). A duplicate task for a finished review exits without calling the AI.

**What the reviewer never changes:** links an analyst rejected, and actor, malware, vendor, product or country links an analyst restored in the last 90 days. Veto deletes an entity only if this article created it and nothing else uses it; otherwise it just removes the link. A relationship becomes *confirmed* only after the reviewer explicitly keeps it, at or above the confidence floor, on `relationship_evidence_promote_count` different articles (`reviewer_kept_entry_ids`). Silence does not count as agreement.

**Queue.** Review › Proposals filters by what applying would change (links, entities, relationships) and by origin (`adjudicator` or `legacy`). Each row has Apply, Dismiss and Restore. **Apply all** (`POST /api/admin/hygiene/adjudication/apply-all`) and **Dismiss all** act on one origin. A restore is logged as `adjudication_restored`. Stale entities (one article at most, no links, idle 90 days) are a `stale` filter on Review › New entities. `GET /api/admin/hygiene/feed?orphaned=true` lists old proposals with no article, for manual clean-up.

**Backfill.** To review older articles, run this inside the api or celery-worker container:

```bash
celery -A app.workers.celery_app call app.workers.adjudication_tasks.backfill_entry_adjudications
```

It takes `limit` and `since_days` kwargs, passes rows through the same checks, and the resweep drains them.

### Entity assessments

Writes and refreshes the AI summary paragraph on entity profiles. Code: `backend/app/workers/entity_maintenance_tasks.py`. Job `backfill-entity-assessments`, daily 05:45 UTC.

| Setting | Type / default | What it does |
|---|---|---|
| `assessment_backfill_batch_size` | int, `50` | Entities queued per run. They run one at a time on the AI worker. |
| `assessment_backfill_min_articles` | int, `1` | Fewest linked articles an entity needs to get a summary. |
| `assessment_backfill_retry_days` | int, `7` | Don't retry an entity within this many days, so the busiest entities don't hog every run. |
| `assessment_refresh_enabled` | bool, `true` | Also rewrite summaries that are out of date. Only rewrites summaries this job wrote; analyst text is never touched. |
| `assessment_refresh_min_new_articles` | int, `10` | New articles since the summary was written before it counts as out of date. |
| `assessment_refresh_batch_size` | int, `10` | Refreshes per run, counted separately so refreshes never crowd out entities with no summary. |

### Actor profile refresh

Weekly AI rewrite of the most active threat actor profiles. Job `actor-profile-refresh`, Mondays 03:00 UTC.

| Setting | Type / default | What it does |
|---|---|---|
| `actor_refresh_top_n_per_run` | int, `20` | Actors refreshed per run. |
| `actor_refresh_min_age_days` | int, `60` | Skip actors refreshed more recently than this. |
| `actor_refresh_activity_window_days` | int, `90` | Days of activity used to pick the most active actors. |
| `actor_refresh_sample_n` | int, `20` | Recent headlines included in each prompt. |

### Narrative themes and actor refresh mode

| Setting | Type / default | What it does |
|---|---|---|
| `entity_maintenance_mode` | `shadow` \| `apply`, default `shadow` | For the weekly actor refresh: `shadow` files the new description as a proposal; `apply` writes it (the description history lets you undo). |
| `narrative_themes_enabled` | bool, `true` | Read the `### Theme` headings back out of the daily briefing and record which articles it grouped together. No extra AI call. |
| `narrative_theme_gating` | bool, `false` | If all the evidence for a link sits under one theme heading on one day, treat it as one news wave and don't promote the link. Leave off until a couple of weeks of themes have been recorded. |

### Detection-rule maintenance

| Setting | Type / default | What it does |
|---|---|---|
| `rule_attack_backfill_limit` | int, `1500` | Detection rules re-checked per ATT&CK-mapping run. Job `backfill-rule-attack-mappings`, Sundays 05:30 UTC. |

### Retention

| Setting | Type / default | What it does |
|---|---|---|
| `engine_run_retention_days` | int, `30` | Days of engine records kept: `job_runs`, `entry_pipeline_runs`, finished `ai_analysis_requests`, `ai_batch_jobs` and resolved `pending_autolink_matches`. Article signals are kept as long as the article. Job `prune-engine-tables`, daily 02:40 UTC. |
| `telegram_media_ttl_days` | int, `30` | Delete downloaded Telegram media older than this. Articles and their intel stay. Job `evict-old-telegram-media`, daily 04:25 UTC. |
| `ingest_files_ttl_days` | int, `180` | Delete uploaded original files older than this; `0` keeps them. Articles stay, and the reader says the file was removed. Job `evict-old-ingest-files`, daily 04:35 UTC. |
| `tts_cache_ttl_days` | int, `30` | Delete read-aloud audio not played within this many days. A shorter per-file limit (such as 24 hours for share links) still applies. |
| `tts_cache_max_bytes` | int, `2 GB` | Size cap for read-aloud audio; the least recently played files go first. Job `evict-tts-cache`, daily 04:15 UTC. |

---

## Outside the Engine console

These are editable in the UI too, but live on other Settings pages.

### Settings → Users

| Setting | Type / default | What it does |
|---|---|---|
| `registration_enabled` | bool, `true` | Whether `POST /api/auth/register` accepts new accounts. The first account becomes the admin. |
| `registration_invite_code` | secret, generated | When set, new accounts need this code. One is created when the first account registers, so a new instance is not open to anyone. Clear it here to allow open sign-up. |
| `public_read_only_enabled` | bool, `false` | Let anyone browse without an account: articles, entity profiles, story threads and the default dashboards. Visitors can't change anything, run AI, or see private pages. See [public-read-only-mode.md](public-read-only-mode.md). |

### Settings → System

| Setting | Type / default | What it does |
|---|---|---|
| `smtp_host` | str, empty | Mail server the `send_email` automation action sends through. Empty turns email off, and the action reports an error. |
| `smtp_port` | int, `587` | Usually 587 for STARTTLS, 465 for TLS. |
| `smtp_security` | `starttls` / `tls`, `starttls` | `starttls` connects plain, then upgrades. `tls` is encrypted from the start. There is no unencrypted option; any other value makes every send fail. |
| `smtp_username` | str, empty | Login for the mail server. Empty sends without logging in. |
| `smtp_password` | secret, empty | Password or app password for that login. |
| `smtp_from_address` | str, empty | Sender on every email, for example `IntelFeed <alerts@example.com>`. Email is off until this is set too. The **Send Test Email** row at the end of the section uses the saved settings. |
| `smtp_max_per_hour` | int, `30` | Most emails sent per clock hour across every rule, test emails included, so a busy rule doesn't trip the mail provider's limits. Extra emails aren't sent and show as errors in the rule's run log. Counted in Redis; if Redis is down, mail goes out uncounted. `0` = no limit. |
| `sentry_dsn` | secret, empty | Sentry error-reporting address. Empty turns Sentry off. Read when the API starts, so a change needs a restart. |
| `sentry_traces_sample_rate` | float, `0.1` | Share of requests traced. Read at startup. |
| `sentry_profiles_sample_rate` | float, `0.1` | Share of requests profiled. Read at startup. |
| `backup_retention_days` | int, `7` | Days of database backups kept. Job `backup-database`, daily 02:00 UTC. |

### Settings → AI Configuration → User keys

Rules for people using their own AI keys. Everything here depends on the first switch: with it off, the rest do nothing. See [automation-ai-enrichment.md](automation-ai-enrichment.md#personal-keys--the-lookup).

| Setting | Type / default | What it does |
|---|---|---|
| `allow_user_ai_providers` | bool, `false` | Let people add their own AI keys. Tasks they start use their key, and fall back to the instance's providers if the key is missing, failing or over its cap. |
| `require_user_ai_provider` | bool, `false` | With personal keys on: refuse a task instead of falling back. |
| `user_ai_provider_types` | str, `claude,openai_compatible` | Provider types a person may add (`ollama` can be added; `claude_code` never). Checked on every call, so removing a type stops existing keys. |
| `user_ai_allow_private_endpoints` | bool, `false` | Let a personal key point at a private address, such as Ollama on your LAN. The address is checked on save and on every call. |
| `user_ai_daily_request_cap` | int, `300` | Requests one person may make on their own keys per UTC day. `0` = no limit. |
| `site_ai_user_daily_requests` | int, `0` | Requests one person may make per UTC day on the instance's providers, for tasks they start (copilot, rule help, summaries, reports). Background work, automation and share links don't count. `0` = no limit. |
| `share_ai_daily_requests` | int, `20` | AI requests one share link may make per UTC day. Always uses the instance's providers. `0` = no limit. |

### Settings → Feeds & Export (public RSS)

| Setting | Type / default | What it does |
|---|---|---|
| `public_rss_enabled` | bool, `false` | Publish collected articles at an RSS address that needs a token. Only active, unmuted feeds are included (the instance-wide mute, not a reader's own). |
| `public_rss_per_feed_limit` | int, `100` | Items per feed in the output. |
| `public_rss_full_content` | bool, `true` | Include the full article instead of a summary. |

### Content generation (Engine → Jobs)

The `content` group has no screen of its own, and the Engine settings search does not find it. Edit these on Settings → Engine → **Jobs**, under the job that uses each one.

| Setting | Type / default | What it does |
|---|---|---|
| `threat_brief_limit` | int, `30` | Threats-board rows given an AI summary per nightly run. Job `generate-threat-briefs`, daily 04:40 UTC. |
| `reddit_digest_min_entries` | int, `3` | Skip the daily Reddit digest if fewer posts than this were collected. |
| `reddit_digest_max_entries` | int, `20` | Most posts in the digest. Job `generate-reddit-digest`, daily 07:00 UTC. |

---

## Setting → scheduled job

Each job in `JOB_REGISTRY` (`backend/app/workers/job_registry.py`) lists the settings it reads in `settings_keys`. The Jobs screen shows those settings next to the job. Jobs not listed here read no settings. Times are UTC.

| Job key | Schedule (UTC) | Settings |
|---|---|---|
| `poll-feeds` | every 60 s | `default_feed_fetch_interval`, `user_agent` |
| `check-feed-health` | every 6 h at :30 | `feed_auto_pause_days` |
| `embed-entries` | every 15 min | `embeddings_enabled`, `embedding_model`, `embedding_base_url`, `embedding_batch_size`, `embedding_backfill_limit` |
| `story-threads` | every 2 h | every `thread_*` except `thread_narrate_limit` and `thread_signals_enabled` |
| `narrate-story-threads` | 06:10 | `thread_narrate_limit` |
| `ai-analysis-batch-submit` | every 30 min | `ai_one_pass_enabled`, `ai_use_batches`, `ai_daily_budget_usd`, `ai_batch_max_requests`, `ai_est_cost_per_request`, `ai_analysis_relevance_threshold`, `ai_analysis_content_max_chars` |
| `signal-rate-recompute` | 04:20 | `signal_feedback_min_samples` |
| `signal-personal-weight-fit` | 04:35 | `radar_personalization_enabled`, `radar_personalization_min_samples`, `radar_personalization_window_days` |
| `signal-rescore-recent` | every 6 h at :35 | `signal_engine_shadow`, `signal_engine_surface` |
| `signal-rescore-all` | Sun 03:00 | `signal_engine_shadow`, `signal_engine_surface` |
| `backfill-entity-assessments` | 05:45 | every `assessment_*` |
| `actor-profile-refresh` | Mon 03:00 | every `actor_refresh_*` |
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
| `evict-old-ingest-files` | 04:35 | `ingest_files_ttl_days` |
| `prune-engine-tables` | 02:40 | `engine_run_retention_days` |
| `backup-database` | 02:00 | `backup_retention_days` |

`entity_maintenance_mode` is read by `actor-profile-refresh` but is not in its `settings_keys`, so the Jobs screen doesn't show it there. Edit it on the Maintenance screen.

All 67 jobs, including those with no settings, are in [workers-search-dashboards.md](workers-search-dashboards.md).

---

## Env-only settings

These 51 are not in `CONFIGURABLE_KEYS`. They come from the environment or `.env`, and a change needs a restart. They are infrastructure and secrets that should not be editable from a web page.

| Area | Keys |
|---|---|
| Environment | `env` |
| Build stamp | `app_version`, `git_sha`, `build_time`. Set when the image is built (`scripts/ops/version.sh` and compose build args), not in `.env`. Shown in the app footer. |
| Postgres | `postgres_host`, `postgres_port`, `postgres_db`, `postgres_user`, `postgres_password`, `postgres_ssl`, `db_pool_size`, `db_max_overflow`, `worker_db_pool_size`, `worker_db_max_overflow` |
| Redis / Meilisearch | `redis_url`, `meili_url`, `meili_master_key`, `meili_timeout` |
| Auth & crypto | `secret_key`, `access_token_expire_minutes`, `refresh_token_expire_days`, `encryption_key`, `encryption_key_previous` |
| Networking | `cors_origins`, `public_base_url`, `rate_limit_overrides`, `webhook_allow_private_networks`, `outbound_allow_private_networks`, `trusted_client_ip_header` |
| Storage paths | `image_proxy_cache_dir`, `tts_media_dir`, `telegram_media_dir`, `telegram_session_path`, `ingest_files_dir` |
| GitHub repo adapter | `github_repo_max_file_size_kb`, `github_repo_default_interval_minutes` |
| Telegram | `telegram_api_id`, `telegram_api_hash`, `telegram_max_media_size_mb`, `telegram_flood_sleep_threshold`, `telegram_ocr_enabled`, `telegram_ocr_min_chars` |
| Translation sidecar | `libretranslate_url`, `libretranslate_api_key`, `translation_timeout_seconds` |
| TTS sidecar | `tts_enabled`, `piper_url`, `piper_voice`, `piper_timeout_seconds`, `tts_max_text_chars` |
| Copilot | `copilot_worker_dispatch` |

Three networking keys need a word:

- `outbound_allow_private_networks` (default `false`): lets feeds, article fetches, uploads by URL and the image proxy reach private network addresses. Turn it on only if you read feeds from your own LAN. Loopback and cloud-metadata addresses are always refused.
- `webhook_allow_private_networks` (default `true`): the same rule for automation webhooks.
- `trusted_client_ip_header` (default empty): the header your edge proxy uses for the visitor's real IP, such as `CF-Connecting-IP` behind Cloudflare. Set it only when the server accepts traffic from that proxy alone. Empty uses the first `X-Forwarded-For` address.

`postgres_password`, `meili_master_key`, `secret_key` and `encryption_key` are checked at startup. The value `changeme` gives a warning in development and **stops startup** in production (`_reject_insecure_defaults`, `backend/app/config.py:480`). `encryption_key` must also be a valid Fernet key (32 bytes, URL-safe base64).

---

## Related docs

- [engine.md](engine.md): the pipeline, signals and console these settings control
- [story-threads.md](story-threads.md): what the `thread_*` settings cluster
- [intelligence-engine.md](intelligence-engine.md): autolinker and correlation internals
- [workers-search-dashboards.md](workers-search-dashboards.md): every scheduled job
- [operations.md](operations.md): deployment, `.env` and backups
