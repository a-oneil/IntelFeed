# Architecture

Comprehensive documentation of how IntelFeed works — from RSS ingestion through intelligence extraction, entity profiling, correlation, and detection engineering.

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Entry Lifecycle: From Feed to Intelligence](#2-entry-lifecycle-from-feed-to-intelligence)
3. [Entity Types and Data Models](#3-entity-types-and-data-models)
4. [The Autolinker: Aho-Corasick Entity Recognition](#4-the-autolinker-aho-corasick-entity-recognition)
5. [Intelligence Extraction Pipeline](#5-intelligence-extraction-pipeline)
6. [Enrichment Pipeline](#6-enrichment-pipeline)
7. [Correlation Engine](#7-correlation-engine)
8. [Detection Engineering](#8-detection-engineering)
9. [Campaigns](#9-campaigns)
10. [Automation Engine](#10-automation-engine)
11. [Frontend Architecture](#11-frontend-architecture)
12. [Dashboard and Priority Queue](#12-dashboard-and-priority-queue)
13. [Widgets and Dashboards](#13-widgets-and-dashboards)
14. [Entity Profile Pages](#14-entity-profile-pages)
15. [API Layer](#15-api-layer)
16. [Configuration and Settings](#16-configuration-and-settings)

---

## 1. System Overview

IntelFeed is a self-hosted threat intelligence platform built on an RSS aggregator foundation. It consumes security feeds from many source types (RSS, Atom, YouTube, podcasts, Reddit, GitHub, NVD, Mastodon, Bluesky, Telegram, generic web scraping), extracts threat intelligence entities (TTPs, CVEs, threat actors, malware families, vendors, products, countries, mitigations, tools), correlates them across articles, and supports detection engineering workflows.

### Core Data Flow

```
Feed Sources → Polling → Parsing → Deduplication → Content Processing → Persistence
    ↓
Task Fan-out → Autolinking → Intelligence Extraction → Enrichment → Correlation
    ↓
Entity Profiles ← Pivot Queries ← Co-occurrence ← Proximity Scoring
    ↓
Detection Rules ← Campaign Tracking ← Automation ← Intelligence Requirements
```

### Service Architecture

| Service | Port | Role |
|---------|------|------|
| PostgreSQL | 5433 | Primary database (async via asyncpg) |
| Redis | 6380 | Task queue, caching, distributed locks, autolinker vocabulary versioning |
| FastAPI (api) | 8000 | REST API + auto-migrations on startup |
| Celery Worker | — | Async task execution (feed fetch, extraction, enrichment, correlation) |
| Celery Beat | — | Scheduled task orchestration (70 jobs registered in `JOB_REGISTRY`, `backend/app/workers/job_registry.py`) |
| Meilisearch | 7700 | Full-text search indexing |
| Vite (frontend) | 3001 | React 18 SPA |

---

## 2. Entry Lifecycle: From Feed to Intelligence

An entry goes through several distinct stages from the moment a feed is polled to the point where intelligence is fully correlated. Stages 1–5 happen synchronously inside the `fetch_feed` worker; stage 6 dispatches a Celery chord whose graph drives the rest.

### Stage 1: Feed Polling

Celery Beat runs `poll_due_feeds` every 60 seconds. It queries feeds where:

- `is_active = TRUE`
- `last_fetched_at + fetch_interval_minutes <= NOW()`
- Ordered by `last_fetched_at ASC NULLS FIRST` (unfetched feeds first)
- Limited to 50 feeds per poll cycle

Each feed gets a Redis NX lock (`feed_fetch:{id}`, TTL 10 minutes) to prevent duplicate fetches across distributed workers. If the lock is already held, the feed is skipped.

### Stage 2: Feed Fetch

The `fetch_feed(feed_id)` Celery task dispatches to the appropriate adapter based on `feed.feed_type`:

| Feed Type | Adapter | Mechanism |
|-----------|---------|-----------|
| rss, atom | HTTP GET | Standard RSS/Atom parsing with `If-None-Match`/`If-Modified-Since` headers |
| youtube | HTTP GET | YouTube RSS feed with optional Shorts exclusion |
| podcast | HTTP GET | RSS with `<enclosure>` media extraction |
| reddit | Reddit API | Subreddit/user post fetching |
| github_releases / github_advisories / github_repo | GitHub API | Releases, security advisories, or repo file/commit watching |
| nvd | NVD API 2.0 | CVE advisory fetching |
| mastodon | Mastodon API | Toots/posts from security researchers |
| bluesky | AT Protocol XRPC | Author timeline, custom feed, or search query ingest |
| telegram | MTProto (Telethon) | Channel/group messages via persistent listener (`telegram_listener.py`) |
| web_scraper | HTTP GET + readability | Generic article scraping for sites without RSS |

HTTP responses are handled as:
- **304 Not Modified** → Update `last_fetched_at`, return early
- **4xx/5xx** → Increment `error_count`, log `last_error`, retry (max 3)
- **200 OK** → Parse entries via `adapter.parse_entries()` → `(feed_meta, ParsedEntry[])`

### Stage 3: Deduplication

Each parsed entry is checked against the database:

1. **Exclude-title filter** — If the entry's title contains one of the feed's `exclude_title_patterns` (plain phrases, case-insensitive), it is dropped before anything is stored. Applies to every adapter.
2. **GUID check** — `(feed_id, guid)` unique constraint. If the entry's GUID already exists for this feed, skip it.
3. **YouTube Shorts filter** — If the feed has `exclude_shorts` enabled and the entry is a YouTube Short, skip it.
4. **Content hash** — SHA-256 of `content_text` is computed for cross-feed deduplication.

### Stage 4: Content Processing

For entries that pass dedup:

1. **Full-text extraction** — If `content_text` is under 500 characters (common for RSS feeds that only include summaries), fetch the full article from the entry URL and extract `og:image`.
2. **HTML sanitization** — `sanitize_html()` strips scripts, iframes, dangerous attributes, and event handlers. Images are proxied through the backend.
3. **Metrics** — Compute `word_count` and SHA-256 `content_hash`.
4. **Image extraction** — Priority: content HTML img → summary img → og:image → parsed metadata.
5. **Media processing** — For podcasts/YouTube: create `EntryMedia` record, fetch transcript (YouTube Transcript API or podcast `transcript_url`), append transcript to `content_text`.

### Stage 5: Persistence

The Entry record is created with:

| Field | Description |
|-------|-------------|
| `id` | UUID primary key |
| `feed_id` | FK to Feed (CASCADE) |
| `guid` | Feed-specific unique identifier (up to 2000 chars) |
| `url` | Source article URL |
| `title` | Article title (up to 2000 chars) |
| `content_html` | Sanitized HTML |
| `content_text` | Plain text version |
| `summary` | Short summary |
| `published_at` | Publication timestamp |
| `fetched_at` | When IntelFeed fetched it |
| `word_count` | Computed word count |
| `content_hash` | SHA-256 for dedup |
| `image_url` | Lead image URL |
| `extracted_urls` | JSONB list of URLs found in content |
| `language` | Detected language code |
| `metadata_` | JSONB bag for adapter-specific data |

After `db.flush()` (to get the `entry.id`), the entry is indexed in Meilisearch with searchable fields (title, content, summary, author) and filterable fields (feed, type, date, tags, language).

SSE events (`feed_fetched`, `entry_new`) are published to subscribed users for real-time UI updates.

### Stage 6: Task Fan-out

For each new `entry_id`, `dispatch_entry_pipeline()` (`backend/app/workers/feed_tasks.py`) builds a Celery **chord**. Stage composition is not hardcoded: stages are declared as data in the pipeline registry (`backend/app/pipeline/registry.py`), each with a kind, and can be enabled/disabled per feed via resolved `PipelinePlan` rows (feed > category > global):

| Kind | Stages | Role |
|------|--------|------|
| `inline` | sanitize, dedup, relevance, index | Run synchronously inside the fetch loop |
| `pre` | translate | Chained ahead of the chord (feeds with `auto_translate`) so every later stage sees translated text; never raises |
| `parallel` | autolink, telegram_links, extract | Chord header — Aho-Corasick linking, Telegram URL/mention extraction, regex intel extraction (`extract` defaults off; gated by `feed.auto_extract_on_ingest` in the plan base layer) |
| `post` | cooccurrence, correlation, requirements | Fan-out from the `entry_post_processing` callback — `EntityRelationship` edges, correlation events, PIR matching |
| `final` | signal scoring | Second chord callback |
| `side` | automation, enrichment | Dispatched independently of the chord |

See the [entry pipeline diagram](diagrams/architecture-entry-pipeline.md) for the full flow.

Independently, the fetch task fires `run_entry_automations(eid, feed_id)` directly (not part of the chord) and a per-feed `_check_keyword_alerts()` pass over the new entry batch.

The chord shape ensures correlation/cooccurrence work runs *exactly* when its inputs are ready, regardless of how long autolinking and extraction take on a given entry.

### Stages 7-12

The remaining stages (Autolinking, Intelligence Extraction, Enrichment, Correlation, Automation, Requirements) are covered in their own sections below.

---

## 3. Entity Types and Data Models

IntelFeed's canonical entity-type vocabulary is **12 slugs**, in `backend/app/entity_types.py` (`ALL`) — the single source of truth for every layer (API, autolinker, correlation, search, AI schemas, DB `entity_type` columns):

- **10 correlatable types**, linked to entries via junction tables and pivotable against each other: `threat_actor`, `malware`, `cve`, `cwe`, `ttp`, `country`, `mitigation`, `tool`, `vendor`, `product`. (Note the one place the slug and the storage name diverge: `malware` is backed by the `malware_families` table and the `MalwareFamily` class.)
- **`ransomware_victim`** backs the ransomware victim tracker (`RansomwareVictim` / `VictimDisclosure`, `/api/ransomware`, behind `ransomware_tracker_enabled`) but does not participate in correlation pivots.
- **`observable`** is the IOC ledger — see the note below; identity is `(kind, value)` rather than a name.

Higher-level constructs — Campaign, DetectionRule, IntelligenceRequirement, StoryThread — are object kinds, not entity types, and are deliberately not in the vocabulary.

### Field-Value Vocabularies

`entity_types.py` names the entity *kinds*; a parallel set of modules names the values that a handful of entity *fields* may hold, because the search grammar treats each of them as a facet:

| Module | Column(s) | Canonical form |
| --- | --- | --- |
| `intelligence/tactics.py` | `DetectionRule.mitre_tactics`, `TTP.tactic` | ATT&CK's own `kill_chain_phases.phase_name` slug (`defense-evasion`) |
| `intelligence/platforms.py` | `Tool.platforms` | ATT&CK enterprise platform labels (`Windows`, `IaaS`) |
| `intelligence/sectors.py` | the `sectors` entity table (seeded), `EntrySector.sector`, `*.targeted_sectors` (a cache of junction labels) | slug + display label (`critical-infrastructure` / `Critical Infrastructure`); the module is also the seed source for the entity rows |
| `intelligence/actor_attributes.py` | `ThreatActor.motivation`, `.country` | five motivations; country names resolved against the countries table |

Each is enforced by a SQLAlchemy `@validates` hook on the model rather than at the call sites, because these columns have five or six writers apiece (AI extraction, rule imports, the tool registry, the profile editor, maintenance jobs) and normalizing at any one of them only lasts until the next writer is added. The hooks **fold** rather than reject: an unrecognized value keeps its wording with the spelling settled, so a new ATT&CK release or an analyst's phrasing survives while case variants stop splitting the facet. Only placeholders (`Unknown`, `n/a`) are dropped.

Two related pieces complete it. The AI task schemas in `ai/prompts/defaults.py` carry these vocabularies as JSON-Schema `enum`s, which Ollama compiles into a decode-time grammar constraint, so extraction cannot invent a value in the first place. And for columns whose values are genuinely open — rule tags, log-source names, both published by upstream rule repos — nothing is rewritten at all; `api/search.py` folds case when it *builds the suggestions*, which keeps vendor data as published and cannot drift back. `scripts/maintenance/normalize_vocabularies.py` is the one-shot catch-up for rows predating the hooks.

> **Note on IOCs:** observables (the IOC ledger) are a first-class entity type as of 2026-09: `observables` + `entry_observables` with a `(kind, value)` identity — the successor to the v1 IOC tables dropped in `060_remove_ioc_tables`. The v2 rule that makes it viable: **regex never creates a ledger row.** Pattern scanning only stages candidates on the entry (`entries.observable_candidates`); rows come from judgment doors — the one-pass `entry_analysis` `iocs` array, `EntryTTP.observable_value` upserts, curated `ioc_list` feed bodies, and analyst promotion — and the observables pipeline stage then sights known values by exact match. See `app/intelligence/observables.py`.

### Junction Table Pattern

Every entity-to-entry relationship follows the same structure:

```
┌─────────────────────────────────────────┐
│ Entry{EntityType} (junction table)       │
├─────────────────────────────────────────┤
│ entry_id         UUID  (composite PK)   │
│ {entity}_id      UUID  (composite PK)   │
│ confidence       str   (high/medium/low)│
│ source           str   (auto_link/regex/ai)│
│ matched_names    str[] (forms that matched)│
│ extracted_at     datetime               │
│ paragraph_indices  int[]  (positions)   │
└─────────────────────────────────────────┘
```

The `paragraph_indices` field records which paragraphs in the entry text mention this entity. This enables **proximity scoring** — if two entities appear in the same paragraph, they're more strongly related than if they appear in distant paragraphs.

### 3.1 Threat Actor

**Model:** `ThreatActor` — Unique on `name`

| Field | Type | Description |
|-------|------|-------------|
| `name` | str (255) | Canonical name (e.g., "APT29", "Lazarus Group") |
| `aliases` | Text[] | Alternative names (e.g., ["Cozy Bear", "The Dukes"]) |
| `description` | Text | Rich text description (user-editable) |
| `mitre_id` | str (20) | MITRE ATT&CK group ID (e.g., "G0016") |
| `country` | str (100) | Legacy text country field |
| `origin_country_id` | UUID FK | Link to Country entity |
| `motivation` | str (100) | e.g., "state-sponsored", "financially motivated" |
| `associated_ttps` | JSONB | Cached TTP list |
| `targeted_sectors` | Text[] | e.g., ["financial", "healthcare", "government"] |
| `first_seen_at` / `last_seen_at` | DateTime | Activity window |
| `article_count` | int | Number of entries mentioning this actor |

**Junction:** `EntryThreatActor` — Links entries to actors with confidence, source, matched_names, paragraph_indices.

**Additional junction:** `ThreatActorTargetCountry` — Many-to-many with Country (which countries does this actor target).

**Data sources:** Autolinker (name/alias matching), AI extraction, MITRE ATT&CK weekly sync, manual user entry.

### 3.2 Malware Family

**Model:** `MalwareFamily` — Unique on `name`

| Field | Type | Description |
|-------|------|-------------|
| `name` | str (255) | Canonical name (e.g., "Cobalt Strike", "Emotet") |
| `aliases` | Text[] | Alternative names |
| `description` | Text | Rich text description |
| `malware_type` | str (50) | "trojan", "ransomware", "worm", "backdoor", "rat", etc. |
| `malpedia_url` | Text | Link to Malpedia entry |
| `associated_actors` | JSONB | Cached actor list |
| `article_count` | int | Mention count |

**Junction:** `EntryMalware` — Same pattern as EntryThreatActor.

**Data sources:** Autolinker, Malpedia weekly sync, AI extraction.

### 3.3 CVE (Common Vulnerabilities and Exposures)

**Model:** `CVE` — Unique on `cve_id`

| Field | Type | Description |
|-------|------|-------------|
| `cve_id` | str (20) | e.g., "CVE-2024-1234" |
| `cvss_score` | Numeric(3,1) | CVSS v3 score (0.0 – 10.0) |
| `severity` | str (20) | "critical", "high", "medium", "low" |
| `description` | Text | From NVD + user edits |
| `affected_products` | JSONB | Product names/versions from CPE |
| `exploit_availability` | str (25) | "none" → "poc" → "weaponized" → "active_exploitation" |
| `github_poc_count` | int | Count of public PoC exploits |
| `github_poc_urls` | Text[] | URLs to GitHub PoC repos |
| `metasploit_module` | str (255) | Metasploit module name if available |
| `epss_score` | float | EPSS probability (0-1) |
| `epss_percentile` | float | EPSS percentile ranking |
| `is_kev` / `kev_date_added` / `kev_due_date` | bool / DateTime | CISA KEV listing status, synced from the KEV enrichment adapter |
| `nvd_data` | JSONB | Raw NVD API response |
| `references_` | JSONB | Reference URLs |
| `timeline` | JSONB | Historical events |

**Junction:** `EntryCVE` — Links entries to CVEs with `extracted_at` and `paragraph_indices`.

**Data sources:** Regex extraction (`CVE-YYYY-NNNN+`), NVD API 2.0 enrichment, EPSS bulk sync (every 6 hours), GitHub PoC scanner (daily), AI extraction.

### 3.4 TTP (Tactic, Technique, Procedure)

**Model:** `TTP` — Unique on `technique_id`

| Field | Type | Description |
|-------|------|-------------|
| `technique_id` | str (20) | MITRE ATT&CK ID (e.g., "T1059", "T1059.001") |
| `technique_name` | str (255) | Human-readable name |
| `tactic` | str (100) | ATT&CK tactic (e.g., "initial-access", "execution") |
| `description` | Text | From MITRE + user edits |
| `platforms` | JSONB | ["Windows", "Linux", "macOS", ...] |
| `data_sources` | JSONB | Required telemetry, channel-level (e.g., `WinEventLog:Sysmon`, `auditd:SYSCALL`). ATT&CK v17 retired `x_mitre_data_sources`; these come from the detection-strategy → analytic → log-source chain |
| `detection` | Text | MITRE detection guidance |
| `mitre_url` | Text | Link to ATT&CK page |
| `is_subtechnique` | bool | Whether this is a sub-technique (T1059.001 vs T1059) |
| `article_count` | int | Mention count |

**Junction:** `EntryTTP` — Includes `confidence`, `source_text`, `paragraph_indices`.

**Additional model:** `TTPMitigation` — Links TTPs to Mitigations (MITRE mitigation IDs like "M1036").

**Data sources:** Autolinker (regex `T\d{4}(?:\.\d{3})?`), MITRE ATT&CK weekly sync (full framework import), AI extraction from behavioral descriptions.

### 3.5 Country

**Model:** `Country` — Unique on `name`

| Field | Type | Description |
|-------|------|-------------|
| `name` | str (255) | Country name |
| `iso_code` | str (3) | ISO 3166-1 code |
| `aliases` | Text[] | Demonyms and alternative names |
| `region` | str (100) | Geographic region |
| `article_count` | int | Mention count |

**Junction:** `EntryCountry` — Includes a unique `role` field:
- `"origin"` — The attack originated from this country
- `"target"` — This country was targeted
- `"infrastructure"` — Infrastructure located in this country
- `"mentioned"` — Country mentioned without clear role

**Additional junctions:**
- `ThreatActorTargetCountry` — Which actors target which countries
- `CampaignCountry` — Campaign geographic scope (role: "origin" or "target")

**Data sources:** UN country seed script (`seed_countries.py`), demonym/alias script (`add_country_aliases.py`), autolinker (name/alias matching), AI extraction with role detection.

### 3.6 Mitigation, Tool, Vendor, Product

Four additional first-class entities round out the correlation graph:

- **`Mitigation`** — MITRE ATT&CK mitigations (e.g., `M1036`). Junction: `EntryMitigation`. Linked to TTPs via `TTPMitigation`.
- **`Tool`** — Red-team / offensive and dual-use tooling (e.g., Mimikatz, Metasploit modules). Junction: `EntryTool`. Distinct from MalwareFamily — these are dual-use security tools rather than malware families.
- **`Vendor`** — Software/hardware vendors that ship vulnerable products (e.g., Microsoft, Fortinet, Citrix). Junction: `EntryVendor`. Important for supply-chain and CVE-impact tracking.
- **`Product`** — Specific products tied to a vendor (e.g., Exchange Server, FortiOS). Junction: `EntryProduct`. Each `Product` has a FK to its `Vendor`. `selectinload(Product.vendor)` is used wherever products are surfaced.

All four are autolinkable, appear in `ENTITY_CONFIG` for correlation pivots, have `/workbench/{slug}/{id}` profile pages, and are eligible targets for autolinker matching, AI extraction, and campaign membership.

### 3.7 Campaign

**Model:** `Campaign` — User-created intelligence collections

| Field | Type | Description |
|-------|------|-------------|
| `name` | str (255) | Campaign name |
| `description` | Text | Rich description |
| `status` | str | "active", "closed", "archived" |
| `tlp_marking` | str | Traffic Light Protocol: "TLP:WHITE", "TLP:GREEN", "TLP:AMBER", "TLP:RED" |
| `start_date` / `end_date` | Date | Campaign timeframe |
| `tags` | Text[] | User-defined tags |

**Related models:**
- `CampaignEntry` — Links entries to campaigns (who added, when)
- `CampaignEntity` — Links entities with role: "primary", "secondary", "related"
- `CampaignCountry` — Geographic scope

Campaigns aggregate entities from multiple entries into a coherent investigation workspace. They support AI-suggested entities, MITRE ATT&CK coverage heatmaps, and detection gap analysis.

### 3.8 Detection Rule

**Model:** `DetectionRule` — Links to source entry

| Field | Description |
|-------|-------------|
| `entry_id` | Source entry (FK) |
| `rule_type` | "sigma", "splunk_spl", "crowdstrike_ql", "elastic_ql", "kql", "snort_suricata", "yara", "nuclei", "panther" |
| `title` | Rule title |
| `rule_content` | Full rule text |
| `severity` | Rule severity |
| `tags` | Rule tags |
| `mitre_tactics` | Mapped ATT&CK tactics |
| `log_sources` | Required log sources |

**Versioning:** `DetectionRuleVersion` tracks all edits for audit trail and rollback.

---

## 4. The Autolinker: Aho-Corasick Entity Recognition

The autolinker is IntelFeed's primary entity recognition system. It runs on every ingested entry (based on feed configuration) and performs O(n) multi-pattern matching against all known entities.

### How the Vocabulary is Built

The `EntityVocabulary` is an Aho-Corasick automaton (via the `pyahocorasick` library) containing all known entity names and aliases:

```
Vocabulary entries:
  ThreatActor "APT29"              → VocabEntry(entity_type="threat_actor", canonical_name="APT29", is_alias=False)
  ThreatActor "Cozy Bear"          → VocabEntry(entity_type="threat_actor", canonical_name="APT29", is_alias=True)
  MalwareFamily "Cobalt Strike"    → VocabEntry(entity_type="malware", canonical_name="Cobalt Strike", is_alias=False)
  Country "United States"          → VocabEntry(entity_type="country", canonical_name="United States", is_alias=False)
  Country "American"               → VocabEntry(entity_type="country", canonical_name="United States", is_alias=True)
```

The vocabulary is rebuilt every 30 minutes and version-stamped in Redis for cross-worker synchronization. When a worker's local vocabulary version differs from Redis, it triggers a rebuild.

### Ambiguity Detection

Short, common-word entity names are flagged as **ambiguous**. An entity name is ambiguous if:
- Its length ≤ `autolinker_ambiguous_name_max_length` (configurable)
- It contains no spaces, hyphens, or underscores
- It's purely alphabetic (no digits)

Ambiguous names (e.g., "Maze", "Agent") require uppercase-first matching in the original text to avoid false positives from common English words.

### The Scanning Process

For each entry, the autolinker:

1. **Checks feed extraction mode:**
   - `"none"` or `"manual"` → Skip entirely
   - `"selective"` → Run `score_relevance()` against security keyword list; skip if below threshold
   - `"full"` → Proceed to scan

2. **Splits text into paragraphs:**
   ```
   [(0, title), (1, summary), (2, paragraph_1), (3, paragraph_2), ...]
   ```

3. **Phase 1 — Aho-Corasick dictionary scan:**
   - O(n) scan of all text against the automaton
   - For each match: verify word boundaries (not mid-word)
   - If ambiguous: verify uppercase-first in original text
   - Check max_occurrences threshold (very frequent matches are likely false positives)
   - Result: `{entity_type, entity_id} → {confidence, source, surface_form, paragraph_indices[]}`

4. **Phase 2 — Regex scan for structured IDs:**
   - `CVE-\d{4}-\d{4,}` → CVE entities
   - `T\d{4}(?:\.\d{3})?` → TTP (MITRE ATT&CK technique IDs)

5. **Store results** via `store_autolink_matches()`:
   - Creates junction records (`EntryThreatActor`, `EntryMalware`, `EntryCountry`, `EntryCVE`, `EntryTTP`, `EntryTool`, `EntryVendor`, `EntryProduct`, `EntryMitigation`)
   - Uses `ON CONFLICT DO NOTHING` for idempotency
   - Updates entity stats: `article_count++`, `last_seen_at = now`
   - **Pending tier:** dictionary-word matches (common-English entity names) can be held as `PendingAutolinkMatch` rows for AI confirmation instead of linking immediately — enabled when both `autolink_pending_tier_enabled` and `ai_one_pass_enabled` are on

### Confidence Weighting

Confidence is determined by match quality and feed reliability:

**Match quality:**
- Canonical name match → `"high"`
- Alias match → `"medium"`

**Feed reliability weight** (from `Feed.reliability_rating`):

| Rating | Weight | Resulting confidence |
|--------|--------|---------------------|
| A | 1.0 | high stays high, medium stays medium |
| B | 0.85 | high stays high, medium stays medium |
| C | 0.7 | high → medium, medium → low |
| D | 0.5 | high → medium, medium → low |
| E | 0.3 | high → low, medium → low |
| F | 0.15 | high → low, medium → low |

Unrated feeds default to weight 0.5 (`_reliability_to_weight()` in `backend/app/workers/intel_feed_tasks.py`).

The formula: confidence × weight → if ≥ 0.7 then "high", if ≥ 0.4 then "medium", else "low".

### False Positive Filtering

Configurable via system settings:
- `autolinker_false_positive_names` — Comma-separated blocklist (e.g., "ai,ir,http")
- `autolinker_min_name_length` — Minimum characters to index (default 4)
- `autolinker_ambiguous_name_max_length` — Threshold for ambiguity check
- `autolinker_ambiguous_max_occurrences` — Frequency limit (names appearing too often are likely common words)

**Junk-alias filtering:** `is_junk_alias()` / `filter_aliases()` (`backend/app/intelligence/autolinker.py`) drop low-quality aliases (too short, on the FP list, or binary-name-shaped) both when building the vocabulary and at alias ingestion time (AI extraction, Malpedia sync) — so a bad alias on one entity can't silently link thousands of entries.

**Cross-type reclassify tombstones:** when an entity is reclassified to a different type (e.g., a "malware" that was actually a tool), an `EntityReclassifyTombstone` row records the old identity so the autolinker and extraction pipelines don't resurrect the entity under its original type.

---

## 5. Intelligence Extraction Pipeline

Beyond autolinking (which is fast, dictionary-based matching), IntelFeed has a deeper extraction layer that uses regex patterns and optionally AI to extract structured intelligence. The entry point is `extract_entry_intel_task(eid)`, which is dispatched as part of the chord prerequisite group when `feed.auto_extract_on_ingest` is true.

### TTP Extraction

- **Regex:** `T\d{4}(?:\.\d{3})?` — Matches MITRE ATT&CK technique IDs
- **Catalog validation:** matches are checked against the hydrated ATT&CK catalog (`_filter_ttp_matches`) — unknown technique IDs are dropped, revoked ones remapped to their replacement, and ICS-matrix techniques dropped unless the entry context looks ICS/OT related
- **AI:** Extracts TTPs from behavioral descriptions (e.g., "the malware uses process injection" → T1055)
- New TTPs trigger `auto_enrich_entity()` for MITRE metadata fetch

### CVE Extraction

- **Regex:** `CVE-\d{4}-\d{4,}` — Standard CVE ID format
- New CVEs trigger NVD API 2.0 lookup for CVSS, severity, description, CPEs, references
- Existing CVEs just create the `EntryCVE` junction link

### Detection Rule Extraction

When `feed.extract_detection_rules = True`, entry content is scanned for embedded detection rules:

| Format | Detection Method |
|--------|-----------------|
| SIGMA | YAML structure with `detection:` key |
| Splunk SPL | SPL query in a code block, or a text line starting `index=` / `search` / `\| tstats` |
| KQL | Defender XDR / Sentinel query in a code block (`DeviceProcessEvents \| where …`), or an Elastic TOML rule with `language = "kuery"` |
| Elastic QL | EQL (`process where …`, `sequence by …`) or ES\|QL (`FROM logs-* \| …`) in a code block, or an Elastic TOML rule |
| YARA | `rule name { meta: ... strings: ... condition: ... }` |
| Snort/Suricata | Alert rule patterns (stored as `snort_suricata`) |

Each extracted rule is validated with `validate_rule(rule_type, rule_content)` before storage.

### GitHub Entry Special Handling

Entries from GitHub feeds with `content_type` metadata (e.g., `sigma_rule`) bypass normal extraction and go directly to `process_github_entry()` for direct rule import.

---

## 6. Enrichment Pipeline

Enrichment adds external context to extracted entities.

### Automatic Enrichment

When a **new** entity is extracted, `auto_enrich_entity(entity_type, entity_id, entity_value)` is dispatched. It:

1. Queries `EnrichmentSource` records where `trigger_mode='auto'` and `entity_type` matches
2. Executes the appropriate adapter (`backend/app/enrichment/adapters/`): NVD, EPSS, CISA KEV, MITRE ATT&CK, Malpedia, GitHub PoC, Wikipedia, CVEDetails, OSV, VulnCheck
3. Stores results in the entity's `enrichment` JSONB field
4. For CVEs: updates `exploit_availability`, KEV status, and EPSS scores from the verdict payload

> **Note:** the IOC-focused adapters (VirusTotal, AbuseIPDB, Shodan, AlienVault OTX, GreyNoise, ThreatFox, URLhaus, MalwareBazaar, URLscan) were removed along with the IOC subsystem — enrichment now targets the first-class entity types only.

### Scheduled Enrichment

Celery Beat runs periodic bulk enrichment:

| Schedule | Task | Description |
|----------|------|-------------|
| Every 6 hours | EPSS bulk sync | Updates `epss_score` and `epss_percentile` for all CVEs |
| Weekly | MITRE ATT&CK sync | Full framework import — TTPs, platforms, data sources, mitigations |
| Weekly | Malpedia sync | Malware family descriptions, aliases, Malpedia URLs |
| Daily | GitHub PoC scan | Scans GitHub for public exploit PoCs, updates `github_poc_count`/`github_poc_urls` |

### Enrichment Sources

Each `EnrichmentSource` has:
- `entity_type` — Which entities it enriches (cve, ttp, threat_actor, malware, vendor, product, country, etc.)
- `trigger_mode` — "auto" (on extraction), "scheduled" (periodic), "manual" (user-triggered)
- `adapter_config` — API keys, rate limits, etc.
- Health tracking: `last_success_at`, `last_error`, `error_count`

---

## 7. Correlation Engine

The correlation engine (`backend/app/intelligence/correlation.py`) connects entities across entries through co-occurrence analysis and proximity scoring.

### Entity Configuration

The engine supports 12 entity types, each mapped to its model, junction table, and foreign key (`backend/app/intelligence/correlation.py`):

```python
ENTITY_CONFIG = {
    "ttp":           (TTP, EntryTTP, EntryTTP.ttp_id),
    "cve":           (CVE, EntryCVE, EntryCVE.cve_id),
    "cwe":           (CWE, EntryCWE, EntryCWE.cwe_id),
    "threat_actor":  (ThreatActor, EntryThreatActor, EntryThreatActor.threat_actor_id),
    "malware":       (MalwareFamily, EntryMalware, EntryMalware.malware_family_id),
    "country":       (Country, EntryCountry, EntryCountry.country_id),
    "mitigation":    (Mitigation, EntryMitigation, EntryMitigation.mitigation_id),
    "tool":          (Tool, EntryTool, EntryTool.tool_id),
    "vendor":        (Vendor, EntryVendor, EntryVendor.vendor_id),
    "product":       (Product, EntryProduct, EntryProduct.product_id),
    "observable":    (Observable, EntryObservable, EntryObservable.observable_id),
    "sector":        (Sector, EntrySector, EntrySector.sector_id),
}
```

A **campaign** can be pivoted *from* but is not in `ENTITY_CONFIG`: it is a curated membership list, not something extracted from an article, so it never appears as a related type (`PIVOT_SOURCE_TYPES = VALID_ENTITY_TYPES | {"campaign"}`).

### Pivot Queries

`pivot_from_entity(db, entity_type, entity_id)` answers: "What other entities are related to this one?"

1. Find all entries linked to the source entity (via junction table)
2. For each related entity type, find all entities linked to those same entries
3. Count co-occurrences and compute proximity scores
4. Compute a composite **relationship strength** per related entity — corroboration (distinct evidence entries, weighted by feed reliability), closeness (proximity), and recency — exposed as a `strength` score plus a tier (the same tiers the UI badges read)
5. Return sorted by strength (falling back to co-occurrence count); `sort` also accepts `recent` and `articles`

### Proximity Scoring

When two entities appear in the same entry, their relationship strength is scored by paragraph distance:

```
proximity_score = 1.0 / (1 + decay_rate × min_distance)
```

Where `min_distance` is the minimum paragraph distance between the two entities' `paragraph_indices`. If they share the same paragraph, distance = 0, score = 1.0. If they're 3 paragraphs apart with decay_rate = 1.0, score = 0.25.

When paragraph indices are unavailable, a default proximity score (0.3) is used.

### Entity Graph

`build_entity_graph(db, entity_type, entity_id)` generates a node-link graph for visualization:

- **Nodes:** The source entity + all related entities (configurable depth)
- **Edges:** Co-occurrence links weighted by proximity score
- **Cached:** Redis with 1-hour TTL

### Correlation Events

When new entries are processed, `detect_correlation_events(entry_id)` runs the emitters in `backend/app/intelligence/correlation_events.py`. The full list of emitted `event_type` values:

| Severity | Event Type | Trigger |
|----------|-----------|---------|
| HIGH | `coverage_gap` | TTP/CVE with no associated detection rule |
| HIGH | `exploit_status_change` | CVE exploit status escalated |
| HIGH | `kev_addition` | CVE newly listed in CISA KEV |
| HIGH | `new_exploit_discovered` | First public PoC for a known CVE |
| HIGH | `cve_score_change` | CVSS / EPSS scoring shift past a tier threshold |
| MEDIUM | `trending_entity` | Entity mentioned >N times in 24 hours |
| MEDIUM | `campaign_match` | Entry matches campaign criteria |
| MEDIUM | `requirement_match` | Entry satisfies an active intelligence requirement |
| MEDIUM | `new_ttp_for_known_actor` | New TTP for tracked actor |
| MEDIUM | `new_ttp_for_known_malware` | New TTP for tracked malware family |
| MEDIUM | `new_malware_for_known_actor` | New malware for tracked actor |
| MEDIUM | `feed_error` | Feed has accumulated repeated fetch errors |
| LOW | `feed_stale` | Feed has not produced entries within its expected window |
| LOW | `actor_malware_cooccurrence` | Actor and malware mentioned together |
| LOW | `new_intel_for_rule` | New intel relevant to existing detection rule |

Severities are tunable per event type via system settings.

### Typed Relationships and Co-occurrence

`EntityRelationship` (`backend/app/models/entity_relationship.py`) is a typed, directed edge between any two entities:

- `relationship_type` — semantic verb: `uses`, `exploits`, `targets`, `attributed_to`, `variant_of`, `communicates_with`, `delivers`, `drops`, `hosts`, `related_to`
- `confidence` — `confirmed` / `probable` / `possible`
- `source` — `co_occurrence`, `auto_extracted`, `analyst_confirmed`, `analyst_created`, `analyst_rejected` (hidden and never resurrected by co-occurrence), `external_feed`
- `evidence_entry_ids[]` — the entries backing the edge

`create_cooccurrence_relationships(entry_id)` builds this graph automatically:

- For each cross-type pair of entities in an entry (same-type pairs are skipped), compute a proximity score and map it to a confidence
- `_directed_pair()` picks a semantic verb and direction for the type pair (e.g., actor→malware = `uses`); unmapped pairs only get a generic `related_to` edge when the co-mention is exceptionally close
- Existing edges accumulate evidence: the entry is appended to `evidence_entry_ids`, and `co_occurrence`-sourced edges are promoted from `possible` to `probable` on one very close co-mention or after `relationship_evidence_promote_count` distinct evidence entries
- Analyst-rejected edges are never recreated or updated by co-occurrence

Analysts browse, confirm, reject, and create these edges through the relationship browser (`backend/app/api/entity_relationships.py`), and the same edges drive the typed entity graph.

---

## 8. Detection Engineering

IntelFeed integrates detection engineering throughout the platform.

### Rule Formats

9 detection rule formats are supported:

| Format | Use Case |
|--------|----------|
| SIGMA | Vendor-agnostic detection rules (YAML) |
| Splunk SPL | Splunk queries |
| CrowdStrike QL | CrowdStrike Falcon queries |
| Elastic QL | Elasticsearch queries |
| KQL | Kibana Query Language |
| YARA | File/memory pattern matching |
| Snort/Suricata | Network detection rules |
| Nuclei | Web vulnerability scanning templates |
| Panther | Cloud-native detection rules |

### Rule Lifecycle

1. **Extraction** — Rules extracted from feed content (blog posts, GitHub repos, advisories)
2. **Validation** — Syntax validation per format
3. **Feasibility Check** — Can this rule be implemented given available telemetry? (`POST /api/telemetry-sources/check-feasibility`, evaluated against the user's configured `TelemetrySource` records)
4. **Storage** — `DetectionRule` record linked to source entry
5. **Versioning** — All edits tracked in `DetectionRuleVersion` for audit trail and rollback
6. **Metadata Extraction** — ATT&CK mapping, log source requirements, severity assessment

### Detection Gap Analysis

Available at campaign and entity levels:
- Identifies TTPs and CVEs that lack associated detection rules
- Highlights coverage gaps in the MITRE ATT&CK matrix — a full ATT&CK matrix view is served by `/api/attack/matrix` (`backend/app/api/attack.py`), backed by the imported ATT&CK catalog, with per-technique rule counts and recent-mention activity
- Coverage is **telemetry-aware**: gaps are weighed against which telemetry sources the user actually has configured, not just whether a rule exists
- Feeds into correlation events (`coverage_gap` = HIGH severity)

---

## 9. Campaigns

Campaigns are user-created intelligence collections that aggregate entities and entries into a coherent investigation.

### Campaign Structure

A campaign contains:
- **Entries** — Source articles (via `CampaignEntry`)
- **Entities** — Threat actors, malware, CVEs, TTPs, vendors, products with roles:
  - `"primary"` — Core to the campaign
  - `"secondary"` — Supporting context
  - `"related"` — Peripheral connection
- **Countries** — Geographic scope (origin/target via `CampaignCountry`)
- **Saved Searches** — Reusable search queries
- **TLP Marking** — Traffic Light Protocol for sharing classification

### Campaign Profile Tabs

| Tab | Content |
|-----|---------|
| Overview | Description, top entities, key stats, geographic scope |
| Timeline | Chronological entity additions and correlation events |
| Entities | All linked entities by type (including vendors/products) with role badges |
| ATT&CK | MITRE matrix heatmap of campaign TTPs |
| Detection Gaps | Techniques/CVEs without detection rules |
| Searches | Saved searches attached to the campaign |
| Suggestions | AI-recommended entities to add |
| Notes | Analyst notes |
| Comments | Discussion thread |

---

## 10. Automation Engine

The automation engine evaluates rules against new entries and correlation events.

### Entry Automation

When `run_entry_automations(entry_id, feed_id)` fires (T+0s after entry creation):

1. Query `AutomationRule` records where `trigger = "on_ingest"`
2. Evaluate conditions:
   - Feed ID filter (only specific feeds)
   - Keywords in title/content
   - Entity filters (must contain specific entity types)
   - Severity / role / TLP filters
3. Execute matching actions (`VALID_ACTION_TYPES`, `backend/app/schemas/automation.py`):
   - Add/remove tags; star, bookmark, or hide the entry; mark read/priority
   - Create note
   - Run webhook (reusable presets managed via `/api/webhook-presets`) or send notification
   - Run AI task
   - Extract intel (TTPs, CVEs, actors, malware) or generate detection rules
   - Add to campaign, create intel report, export, or chain another rule

### Correlation Automation

When correlation events are generated, `run_automations_for_correlation_event()` evaluates rules with `trigger = "on_correlation_event"`.

### Intelligence Requirements

`match_entry_against_requirements(entry_id)` checks active intelligence requirements (PIRs — Priority Intelligence Requirements):
- Matches against keyword filters **and** the requirement's `linked_entities` (threat actors, malware, CVEs, TTPs) — an entry that autolinks to a linked entity matches even without keyword hits
- Creates `RequirementMatch` records for tracking (`match_type`: keyword, entity, or manual)
- May trigger additional correlation events

---

## 11. Frontend Architecture

### Three-Panel Layout (MainLayout)

The primary interface is a three-panel feed reader:

```
┌─────────┬──────────────┬──────────────┐
│ Sidebar │  Entry List  │   Reader     │
│         │              │              │
│ Feeds   │ Virtualized  │ Entry HTML   │
│ Folders │ infinite     │ + metadata   │
│ Tags    │ scroll       │ + workbench  │
│ Search  │              │ + notes      │
│         │ Intel badges │ + entities   │
└─────────┴──────────────┴──────────────┘
```

- **Sidebar** — Feed tree, folders, categories, saved searches, tags
- **Entry List** — `EntryList` component with `@tanstack/react-virtual` for virtualized rendering. Each row shows `EntryIntelBadges` (TTP/CVE/actor/malware/rule/note counts), feed type icon, read/star/bookmark state.
- **Reader** — `EntryReader` renders sanitized HTML with inline entity highlighting (`InlineEntityHighlighter`), side panels for notes/tags/workbench/glossary, keyboard shortcuts.

### State Management

**Five Zustand stores** in `frontend/src/stores/` (all persisted to localStorage):

1. **`authStore`** — JWT tokens, user identity, token refresh
2. **`uiStore`** — All layout state:
   - `selectedEntryId`, `readerOpen`, `activePanel`
   - `activeReaderPanel` — "note" | "tag" | "workbench" | "glossary" | "create_entity" | "add_alias" | "link_entity" | null
   - Panel widths and collapse state (resizable)
   - `selectedEntryIds` (Set) for bulk operations
   - `viewMode` — "compact" | "expanded" | "magazine"
   - `sortOrder`, `showUnreadOnly`, `markReadOnScroll`
   - `tables` — per-DataTable columns/filters/sort. Column layouts additionally sync to the server-side `table_layouts` user setting via `useTableLayoutSync`, so they follow the analyst between desktop and mobile
3. **`intelStore`** — Intelligence workspace state:
   - `activeSection` — Current workbench section
   - `selectedEntityType` / `selectedEntityId`
   - `enrichmentQueue` — Track in-progress enrichment tasks
   - `recentPivots` — Navigation history (last 20 pivoted entities)
   - `autoExtractOnOpen`, `autoOpenIntelPanel`
   - `preferredRuleFormats` — User's preferred detection rule formats
4. **`triageViewStore`** — Local mirror of the triage view (widget layout, collapsed state, global time range). The authoritative copy lives in the server-side `triage_view` user setting; the store gives the page a synchronous handle and survives reloads while an auto-save is in flight
5. **`playerStore`** — Audio/podcast playback state

### Data Fetching

All server state is managed via **TanStack Query v5**:

- `useInfiniteQuery` for paginated entry lists (cursor-based, 50 per page)
- `useMutation` with cache invalidation for write operations
- `staleTime: 30s`, `retry: 1`, `refetchOnWindowFocus: false`
- `useEntryIntelBadges(entryIds)` — Batch fetch intel counts for up to 100 entries

### Key Hook Families

**Entry hooks:** `useEntries`, `useEntry`, `useMarkRead`, `useToggleStar`, `useToggleBookmark`, `useMarkAllRead`, `useBulkAction`

**Entity extraction hooks (per-entry):** `useEntryTTPs`, `useEntryCVEs`, `useEntryThreatActors`, `useEntryMalware`, `useEntryCountries`, `useEntryVendors`, `useEntryProducts`

**On-demand extraction hooks:** `useExtractTTPs`, `useExtractCVEs`, `useExtractThreatActors`, `useExtractMalware`, `useExtractCountries`, `useExtractVendorsProducts`

**Entity CRUD hooks:** `useCreate{Entity}`, `useUpdate{Entity}`, `useDelete{Entity}`, `useFindDuplicates`, `useMergeEntities`, `useConvertEntity`

**Correlation hooks:** `usePivot`, `useEntityGraph`, `useEntityTimeline`, `useEntitySearch`

**Campaign hooks:** `useCampaign`, `useCampaignTimeline`, `useCampaignEntities`, `useCampaignAttackLayer`, `useCampaignDetectionGaps`, `useCampaignSuggestions`

**Detection rule hooks:** `useDetectionRule`, `useCreateDetectionRule`, `useValidateRule`, `useCheckFeasibility`, `useDetectionRuleVersions`

### Inline Entity Highlighting

`InlineEntityHighlighter` scans rendered entry HTML for known entities (actors, malware, CVEs, TTPs, countries, vendors, products) and wraps them with interactive highlights:
- Hover shows `EntityPopover` with quick profile view
- Click navigates to entity profile in workbench
- Supports inline creation/linking of new entities from selected text

### Entry Insights

`useEntryInsights` provides per-entry intelligence summary:
- Entity overlap with other entries
- Detection gaps (TTPs without rules)
- Campaign matches
- PIR matches
- Critical CVE alerts

### AI Copilot Dock

`CopilotDockPanel` mounts globally in `App.tsx` for authenticated users — a dockable chat panel over the copilot API (`backend/app/api/copilot.py`), which runs a streaming, tool-calling, read-only session against the platform (allowed tools: Bash, Read, Skill). Tool invocations stream into the transcript as expandable traces, and a small set of vetted actions (create campaign, add note) can be applied from responses. Conversations can be shared read-only at `/shared/copilot/:token` (`SharedCopilotPage`). Each copilot turn records an `AIResult` row (`target_type="conversation"`) with token usage and the CLI-reported `total_cost_usd`, so copilot usage appears in the AI cost dashboard — though under the flat-rate Claude sign-in the dollar figures are notional (API-rate equivalents); real capacity is bounded by the plan quota.

---

## 12. Dashboard and Priority Queue

The workbench landing page — the **Dashboard** (`/workbench/dashboard`, `frontend/src/pages/DashboardPage.tsx`) — is the operational "what is happening right now" view. It is the first item in the workbench nav and the page `/workbench` redirects to. The entity/section browser lives at `/workbench/explore`. `/triage`, `/dashboards`, and `/atlas` all redirect to `/workbench/dashboard`.

The page is organized as a correlation-events browser plus a stack of widgets backed by `triageViewStore`. The **Priority Queue** — entries ranked by intelligence signals, with open story threads folded in as single rows — is a second, ranked entry list: `/priority-queue` renders `MainLayout` in `priorityMode` (`frontend/src/pages/MainLayout.tsx`), which mounts `EntryList` with `sortOverride="radar"` and `withThreads`, a docked reader, and a Why-ranked card (`WhyRankedCard.tsx`) explaining the entry's signals. The ranking and thread folding are assembled server-side by `GET /api/entries/priority-queue` (`build_priority_queue`, `backend/app/api/entries.py:1431`); the client only flattens the rows for display (`frontend/src/utils/threads.ts`). It is reachable from a chip under the Unread-articles hero in the feed sidebar.

The triage stream is broken up by **daily-divider summaries** — AI-generated per-day recaps that are shared across all users. A beat job (`generate-daily-summaries`, daily at 6 AM, `backend/app/workers/daily_summary_tasks.py`) pre-generates yesterday's summary so it renders instantly.

### Telegram Mentions

`TelegramMentionsPanel` and the dashboard-tier `TelegramMentionsWidget` surface activity ingested by the Telegram adapter. The `TelegramMention` model stores per-message channel/user mentions and forwards. A scheduled job (`build-telegram-forward-relationships`, in `telegram_link_tasks.py`) walks recent mentions and builds `EntityRelationship` edges so that a Telegram-only social graph is queryable through the same correlation APIs as the rest of the platform.

---

## 13. Widgets and Dashboards

The widgets system is the dominant frontend pattern for surfacing intelligence summaries. Widgets live in `frontend/src/components/widgets/` and are registered in `registry.ts`. `WidgetRenderer` resolves an entry from the registry by `type`; `WidgetPicker` lets the user add new widgets to the Dashboard.

Widgets fall into roughly five families:

| Family | Examples |
|--------|----------|
| Operational | `CorrelationEventsWidget`, `HotCorrelationsWidget`, `TriageQueueStatsWidget`, `FeedHealthWidget`, `AutomationLogsWidget`, `WorkerQueueWidget` |
| Intelligence | `NewActorsWidget`, `NewCVEsWidget`, `TrendingEntitiesWidget`, `VendorsTrendingWidget`, `ProductsTrendingWidget`, `TrendingCVEs`, `ActorActivityTimelineWidget` |
| Telemetry / OSINT | `TelegramMentionsWidget`, `TargetedCountriesWidget`, `SourceReliabilityWidget`, `PIRCoverageWidget` |
| Detection | `DetectionCoverageWidget`, `DetectionFormatBreakdownWidget`, `AttackCoverageGapWidget`, `AttackHeatmap`, `KEVMatchesWidget`, `NewDetectionsWidget` |
| Analytics / Recap | `IntelVelocityWidget`, `AIUsageWidget`, `WeeklyRecapWidget`, `SavedSearchHitsWidget`, `ActiveCampaignsWidget`, `LatestEntries`, `OverviewWidget`, `CVESeverityChart`, `FeedActivityChart`, `TopTagsWidget`, `StatCard` |

Widgets pull their data via dedicated TanStack Query hooks (e.g. `useWidgetData`, `useAnalytics`, `useCorrelation`). The Dashboard is the single widget host, composing them in a `react-grid-layout` canvas.

A widget is roughly four pieces: a registry entry (icon, label, default size), a renderer component, a query hook, and an optional settings panel surfaced via `WidgetPicker`.

**The grid starts locked.** `uiStore.dashboardLocked` (toggled from the Dashboard toolbar, persisted per device) turns off `isDraggable`/`isResizable` on the `react-grid-layout` canvas, and it defaults *on* for every viewport — rearranging a board is a deliberate act, so it takes an explicit unlock. Adding, configuring, and removing widgets stay available while locked; only drag and resize are gated. The default matters most on a phone: under 768px the `sm` breakpoint drops `cols` to 1, react-grid-layout clamps every widget to `w=1, x=0` to fit, and `onDragStop`/`onResizeStop` then persists that flattened one-column layout over the 12-column board for every screen. Locked, nothing can be written back; unlocking on a phone re-arms the hazard deliberately.

**Boards are per-user, seeded from a default set.** Every dashboard belongs to the user who created it; `/api/dashboards` only ever lists and mutates the caller's own. A user with no boards gets the instance defaults — five `__triage__/` tabs declared in `backend/app/dashboard_defaults.py` — via `POST /api/dashboards/seed-defaults`, which the Dashboard page fires once. Seeding is idempotent and never touches a user who already owns a board, so a renamed, rearranged, or deleted tab stays that way. Re-capture the defaults from a curated instance with `GET /api/dashboards` and regenerate that module.

> **Note:** correlation events surface through `CorrelationEventsWidget`; feed-health-only events go through a slimmer notification path.

---

## 14. Entity Profile Pages

All entity types share a single config-driven page component (`frontend/src/pages/EntityProfilePage.tsx`). Per-type behavior — identity fields, stats, tabs, actions — is declared in `frontend/src/components/entityProfile/entityProfileConfig.tsx` rather than branched in code. Shared building blocks live in `components/entityProfile/` (`ProfileHeader`, `IdentityFields`, `StatGrid`, `ProfileTabs`, `ActivityFeed`, `AssessmentBlock`, `EssentialReading`, `KnownAssociates`, `MentionsTimeline`, `SignalBadges`, `SinceLastVisitRibbon`, tab bodies in `tabs/`).

### Routing

Entity profiles are accessed at `/workbench/{entity_type}/{id}`:
- `/workbench/actor/:id`
- `/workbench/malware/:id`
- `/workbench/cve/:id`
- `/workbench/ttp/:id`
- `/workbench/country/:id`
- `/workbench/tool/:id`
- `/workbench/mitigation/:id`
- `/workbench/vendor/:id`
- `/workbench/product/:id`
- `/workbench/campaign/:id`
- `/workbench/rule/:id`
- `/workbench/report/:id` and `/workbench/report/new`

### Common Profile Structure

Every entity profile has:

1. **Header** — Name, type badge, key identifiers, article count, first/last seen dates
2. **Metadata panel** — Type-specific fields (editable inline), driven by the config's identity-field declarations
3. **Description** — Rich text, editable
4. **Related entities** — Fetched via `usePivot(entityType, entityId)`, showing co-occurrence counts, proximity, and relationship strength tiers
5. **Entity Graph** — Interactive typed-relationship visualization (`EntityGraph`, a custom SVG renderer with its own layout engine in `entityGraphLayout.ts`)
6. **Tabs** (per-type list from `entityProfileConfig`, bodies in `tabs/`):
   - **Overview** — Activity feed of linked entries plus type-specific panels (assessment block, recent-developments strip fed by `/api/engine/entities/{type}/{id}/whats-new`)
   - **Relationships** — Typed relationship browser (`RelationshipsTab`): confirm/reject/create edges, evidence entries, strength badges
   - **Detection / ATT&CK / Detection Gaps** — Associated rules and coverage, ATT&CK matrix heatmap, coverage-gap analysis (per-type)
   - **Vulnerabilities** — Vendor/product profiles: CVEs affecting the product (via the `cve_affected` table)
   - **Geography** — Country profiles only: role breakdown and map
   - **AI** — AI analysis actions for the entity (`AIAnalysisSection` in entity mode)
   - **Notes** — Analyst notes and comments

### Type-Specific Displays

**Threat Actor:**
- Country of origin, motivation, targeted sectors
- MITRE group ID link
- Aliases management
- Target countries list

**Malware Family:**
- Malware type badge (trojan, ransomware, etc.)
- Malpedia link
- Associated actors (cached JSONB)

**CVE:**
- Severity badge (color-coded by CVSS)
- CVSS score, EPSS score/percentile
- Exploit status progression: none → poc → weaponized → active_exploitation
- KEV badge (CISA Known Exploited Vulnerabilities)
- GitHub PoC count and links
- Affected products (CPE list)

**Vendor / Product:**
- Vendor name, normalized aliases, article count
- Product profile shows its parent vendor (eager-loaded via `selectinload(Product.vendor)`) and the CVE list referencing this product/version
- Common pivots: targeted CVEs, related actors (who exploits this product), associated malware

**TTP:**
- MITRE ATT&CK technique ID and tactic
- Platforms and data sources
- Detection guidance
- Linked mitigations (via `TTPMitigation`)

**Country:**
- ISO code, region
- Role breakdown: origin count, target count, infrastructure count, mentioned count
- Origin actors (ThreatActors with `origin_country_id = this`)
- Targeting actors (via `ThreatActorTargetCountry`)
- Linked campaigns
- Related countries (by co-occurrence)

**Campaign:** (dedicated page `CampaignProfilePage.tsx`)
- Status, TLP marking, date range
- Entity tabs: actors, malware, CVEs, TTPs, vendors, products with role badges
- ATT&CK heatmap
- Detection gap analysis
- AI suggestions
- Country involvement

### Workbench Page

The workbench (`WorkbenchPage.tsx`) is the central intelligence workspace:

**Sidebar sections (collapsible):**
- **Detection:** ATT&CK Matrix, Rules Library, Telemetry Sources, Vendor Watch (links to `/workbench/exposure`)
- **Entities:** Countries, CVEs, Malware, Mitigations, Products, Threat Actors, Tools, TTPs, Vendors
- **Intelligence:** Campaigns, Glossary, Ransomware (victim tracker), Reports, Requirements (PIRs), Telegram Mentions

Features: cross-entity search, column customization, duplicate detection/merge, bulk operations. (The standalone rules-library page was folded into the workbench; `/workbench/rules` redirects here. Merge/reclassification advisories surface through the admin hygiene feed, `backend/app/api/hygiene.py`.)

---

## 15. API Layer

### Key Endpoint Groups

**Entries** (`/api/entries/`):
- `GET /triage` — Priority-scored entry queue
- `GET /entries` — Paginated list with filters (feed, read state, starred, bookmarked, content_type)
- `GET /entries/{id}` — Full entry detail
- `GET /entries/{id}/intel-badges` — Batch intel counts (up to 100 entries)

**Intelligence** (`/api/intelligence/`):
- `POST /entries/{id}/extract-ttps` — Extract TTPs
- `POST /entries/{id}/extract-cves` — Extract CVEs
- `POST /entries/{id}/extract-threat-actors` — Extract actors
- `POST /entries/{id}/extract-malware` — Extract malware families
- `POST /entries/{id}/extract-countries` — Extract countries
- `POST /entries/{id}/extract-vendors-products` — Extract vendor/product references

**Correlation** (also under `/api/intelligence/`):
- `GET /pivot/{entity_type}/{entity_id}` — Pivot query
- `GET /graph/{entity_type}/{entity_id}` — Entity graph
- `GET /timeline/{entity_type}/{entity_id}` — Temporal view
- `POST /detection-summary` — Detection coverage summary
- Correlation events are served through the widget endpoints (`GET /api/widgets/correlation-events`)

**Entity Profiles** (`/api/entities/`):
- CRUD for all entity types
- Entity merge (consolidate duplicates) and cross-type reclassification
- Alias management
- Backlink task dispatch

**Entity Relationships** — typed relationship browser: list/filter edges, confirm/reject, create analyst edges (`backend/app/api/entity_relationships.py`)

**Entity Links** (`/api/entity-links`) — entry↔entity edge management (union across the seven junction tables): list, stats, unlink, bulk-unlink (`backend/app/api/entity_links.py`); powers the Engine console's Links view

**Engine** (`/api/engine`) — pipeline/signal ops console: stage registry + run counts, per-entry stage runs and retries, signal stats/settings, pipeline plans, job runs, Radar feedback (`backend/app/api/engine.py`); `/api/engine/extraction` (from `backend/app/api/extraction.py`) manages AI-created entities (stats, list, confirm)

**Ransomware** (`/api/ransomware`) — leak-site victim tracker (victims, disclosures, landscape stats), behind the `ransomware_tracker_enabled` setting

**Documentation** (`/api/documentation`) — serves this documentation set to the in-app docs route (`/documentation` in the SPA, `backend/app/api/documentation.py`). Pages are discovered by walking `docs/` on each request: the title is the file's own H1 and the sidebar section is the directory it sits in, so adding a doc needs no code change

**Copilot** (`/api/ai/copilot`) — streaming, tool-calling, read-only AI chat with shareable conversations

**Detection Rules** (`/api/detection-rules/`):
- CRUD for rules
- Syntax validation
- Feasibility checking
- Version history and rollback

**Export** — CSV, Markdown, MISP formats for all entity types.

### Common Patterns

- **Authentication:** JWT with `get_current_user` dependency injection
- **Pagination:** Offset/limit or cursor tokens, wrapped in `PaginatedResponse[T]`
- **Eager loading:** `selectinload()` for relationships
- **Error handling:** `AppError` with structured `{code, message, details}` responses
- **Caching:** Redis cache-through for pivot queries and entity graphs (`correlation_cache_ttl_seconds`, default 1 hour)

---

## 16. Configuration and Settings

### Config Override Chain

Settings are resolved in order:
1. **`system_settings` DB table** — editable in the web UI: engine-owned keys at Settings → Engine (grouped onto the stage/view/browse surface that owns them), the rest at Settings → System
2. **`.env` file** — environment variables
3. **Defaults in `config.py`** — Pydantic settings defaults

The `settings.get(key)` method checks the DB table first, then falls back to the env default. 142 of the 187 settings are DB-overridable, so most configuration changes need no restart; the remaining 45 are infrastructure and secrets. Values are cached in-process for 5 seconds, so a change propagates to the Celery workers within about that.

**Every setting is catalogued in [engine-settings.md](engine-settings.md)** — what it does, its default, and which console surface edits it. The lists below are orientation only.

### Key Configuration Areas

**Feed behavior:**
- `intel_extraction_mode` — `full` | `selective` | `manual` | `none`. The UI also shows a fifth *derived* level, **known entities only** (`known_only`, `frontend/src/components/IntelLevelBadge.tsx:27`): a feed on `full` or `selective` with `auto_extract_on_ingest` off, i.e. autolink against the existing dictionary with no new-entity extraction. It is a display of two columns, not a stored mode.
- `auto_extract_on_ingest` — Trigger regex extraction on new entries
- `extract_detection_rules` — Scan for embedded detection rules
- `reliability_rating` — A through F, affects confidence weighting

**Autolinker tuning:**
- `autolinker_min_name_length` — Minimum entity name length to index
- `autolinker_ambiguous_name_max_length` — Threshold for ambiguity detection
- `autolinker_ambiguous_max_occurrences` — Frequency limit for ambiguous names
- `autolinker_false_positive_names` — Comma-separated blocklist

**Correlation tuning:**
- `proximity_default_score` — Fallback when paragraph indices unavailable (default 0.3)
- `proximity_decay_rate` — How fast proximity score decays with distance (default 1.0)

**AI providers:**
- Model-agnostic: Ollama, Claude API, Claude Code CLI, OpenAI-compatible endpoints (OpenAI, LM Studio, vLLM, llama.cpp, LiteLLM, OpenRouter, Groq)
- Models assigned to specific tasks (extraction, summarization, rule generation)
- All configurable via Settings > AI Configuration in the web UI (providers, prompts, task assignments, and cost tracking)

**Enrichment sources:**
- Per-source: API keys, rate limits, trigger mode (auto/scheduled/manual)
- Health tracking per source
