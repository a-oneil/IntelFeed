# Intelligence Engine

For contributors and operators who need to know how an article becomes linked, correlated intelligence — and why something did or didn't link. It walks an entry through the autolinker, the extraction layers, the observables ledger, correlation, detection-rule extraction and the TTP and CVE pipelines, with the settings that steer each.

**Contents**

- [Overview](#overview)
- [Architecture Overview](#architecture-overview)
- [Entry-to-Intelligence Pipeline](#entry-to-intelligence-pipeline)
  - [Phase 1: Entry Arrival & Text Normalization](#phase-1-entry-arrival--text-normalization)
  - [Phase 2: Autolinker Scan (Layer 0)](#phase-2-autolinker-scan-layer-0)
  - [Phase 3: Junction Record Storage](#phase-3-junction-record-storage)
  - [Phase 4 (Optional): Secondary Extraction Layers](#phase-4-optional-secondary-extraction-layers)
- [Autolinker Deep Dive](#autolinker-deep-dive)
  - [False Positive Filtering](#false-positive-filtering)
  - [Pending Tier: Dictionary-Word Matches](#pending-tier-dictionary-word-matches)
  - [Junk Alias Filtering at Import](#junk-alias-filtering-at-import)
  - [Cross-Type Resurrection Guard](#cross-type-resurrection-guard)
  - [Vocabulary Performance](#vocabulary-performance)
  - [False Positive Feedback Loop](#false-positive-feedback-loop)
- [Entity Hygiene Console](#entity-hygiene-console)
  - [Unified Feed & Stats](#unified-feed--stats)
  - [Reclassification Suggestions](#reclassification-suggestions)
  - [Orphans, Cascade Preview & Scanners](#orphans-cascade-preview--scanners)
  - [Tombstone Management](#tombstone-management)
- [Observables — the IOC ledger](#observables--the-ioc-ledger)
  - [The contract: regex never creates a row](#the-contract-regex-never-creates-a-row)
  - [Candidate policy is precision-first by construction](#candidate-policy-is-precision-first-by-construction)
  - [The judgment doors](#the-judgment-doors)
  - [Validation gates](#validation-gates)
  - [Lifecycle](#lifecycle)
  - [Where it surfaces](#where-it-surfaces)
- [Entity Types & Resolution](#entity-types--resolution)
  - [Uniqueness Keys](#uniqueness-keys)
  - [Enrichment Sources](#enrichment-sources)
- [Correlation Engine](#correlation-engine)
  - [Timeline Construction](#timeline-construction)
- [Retention & Archival](#retention--archival)
- [Detection Rule Extraction](#detection-rule-extraction)
- [TTP & MITRE ATT&CK Integration](#ttp--mitre-attck-integration)
  - [TTP Extraction Layers](#ttp-extraction-layers)
  - [TTP Storage & Enrichment](#ttp-storage--enrichment)
  - [MITRE ATT&CK Sync](#mitre-attck-sync)
- [CVE Pipeline](#cve-pipeline)
  - [CVE Extraction & NVD Enrichment](#cve-extraction--nvd-enrichment)
  - [EPSS & Exploit Tracking](#epss--exploit-tracking)
  - [CVE Scoring & Priority](#cve-scoring--priority)
- [Glossary & Inline Highlighting](#glossary--inline-highlighting)
- [Reporting & Export](#reporting--export)
  - [Report Templates](#report-templates)
  - [Intel profiles and exposure reports](#intel-profiles-and-exposure-reports)
  - [Report Generation](#report-generation)
  - [Export Formats](#export-formats)
- [Real-Time Intelligence Events](#real-time-intelligence-events)
  - [Event Publishing](#event-publishing)
  - [Webhook Integration](#webhook-integration)
- [Performance & Scaling](#performance--scaling)
  - [Autolinker Performance](#autolinker-performance)
  - [Correlation Engine Performance](#correlation-engine-performance)
  - [Database Indexes](#database-indexes)
  - [Scaling Strategies](#scaling-strategies)
- [Configuration](#configuration)
- [Sequence Diagrams](#sequence-diagrams)
  - [Entry Ingest to Event Emission](#entry-ingest-to-event-emission)
  - [Pivot Query (Find Actor for CVE)](#pivot-query-find-actor-for-cve)
- [Troubleshooting & Debugging](#troubleshooting--debugging)
  - [Vocabulary Build Issues](#vocabulary-build-issues)
  - [Correlation Events Not Firing](#correlation-events-not-firing)
  - [CVE Enrichment Delays](#cve-enrichment-delays)
- [Future Enhancements](#future-enhancements)
- [References](#references)
- [Per-feed pipeline switches](#per-feed-pipeline-switches)
  - [The two pipelines](#the-two-pipelines)
  - [Confidence weighting and reliability rating](#confidence-weighting-and-reliability-rating)
  - [Choosing a mode — quick decision guide](#choosing-a-mode--quick-decision-guide)
  - [Operational notes](#operational-notes)
  - [None of this uses AI](#none-of-this-uses-ai)
- [Signal Engine (engine phase 2)](#signal-engine-engine-phase-2)
  - [Surfacing (engine phase 3)](#surfacing-engine-phase-3)

## Overview

The IntelFeed Intelligence Engine is a multi-stage extraction, linking, and correlation system that transforms raw threat intelligence feed entries into actionable, interconnected threat data. It operates as a high-throughput pipeline designed for distributed processing, zero-downtime updates, and real-time intelligence insights.

The engine sits at the core of IntelFeed's intelligence operations, providing:
- **Instant entity linking** via Aho-Corasick dictionary scanning (Layer 0)
- **Structured intelligence extraction** (TTPs, CVEs, CWEs, threat actors, malware, tools, mitigations)
- **An IOC ledger** (observables) where rows come from judgment doors, never from a regex match
- **Cross-entity correlation** with proximity-aware scoring
- **Detection rule extraction** from entry content (SIGMA, Elastic TOML, YARA, Snort/Suricata, and SPL / KQL / EQL / ES|QL queries in code blocks)
- **Retention & archival** of read correlation events
- **Real-time intelligence event generation** for anomalies, coverage gaps, and trending entities

---

## Architecture Overview

```
Entry Ingestion
    ↓
[Paragraph Splitting] (title, summary, content → indexed chunks)
    ↓
Layer 0: Autolinker (Aho-Corasick scan for known entities)
    ├→ Threat Actors (name + aliases)
    ├→ Malware Families (name + aliases)
    ├→ Countries
    ├→ Vendors / Products
    ├→ Tools / Mitigations
    ├→ CVEs (regex: CVE-YYYY-NNNN+)
    └→ TTPs (regex: T####(.###)?)
    ↓
Store Junction Records (EntryThreatActor, EntryCVE, EntryTTP, etc.)
    │   dictionary-word matches → pending_autolink_matches (held for AI confirmation)
    ↓
Observables stage (parallel): stage entry-local candidates, sight known
    ledger values by exact match — regex never creates a ledger row
    ↓
Layers 1+ (Optional: one-pass AI analysis via the batch queue, regex TTP/CVE/
    mitigation extraction, detection-rule extraction)
    ↓
Correlation Event Detection
    ├→ new_ttp_for_known_actor
    ├→ new_ttp_for_known_malware
    ├→ coverage_gap (TTP with no detection rules)
    ├→ actor_malware_cooccurrence
    ├→ campaign_match
    ├→ requirement_match
    └→ ... (15 event types total)
    ↓
Real-time Event Publishing (SSE, webhooks, correlation_event table)
```

---

## Entry-to-Intelligence Pipeline

### Phase 1: Entry Arrival & Text Normalization

When an entry enters IntelFeed, it is processed through:

```python
# autolinker.py:227 — Paragraph Splitting
paragraphs = split_into_paragraphs(title, summary, content_text)
# → [(0, title), (1, summary), (2, para_1), (3, para_2), ...]
```

**Purpose:** Paragraph indices are critical for proximity scoring in correlation. They allow the engine to measure "closeness" between entities — e.g., "APT29 and CVE-2024-12345 appear in the same paragraph (high signal)".

**Metrics:**
- Title = paragraph 0
- Summary = paragraph 1
- Content split on `\n\n` = paragraphs 2+

### Phase 2: Autolinker Scan (Layer 0)

The autolinker uses an **Aho-Corasick automaton** to scan entry text against a live vocabulary of known entities.

#### Vocabulary Build (`autolinker.py:250-410`)

On startup or after database mutations, the vocabulary is built from:
```python
EntityVocabulary.build_from_entities(
    actors=[ThreatActor],
    malware_families=[MalwareFamily],
    countries=[Country],
    vendors=[Vendor],
    products=[Product],
    tools=[Tool],
    mitigations=[Mitigation],  # canonical name only (no aliases column)
)
```

For each entity:
- **Canonical name** (the primary label)
- **Aliases** (alternative names, lower-confidence matches)
- **Surface forms** (all names + aliases to scan for)

Example:
```
ThreatActor(name="APT29", aliases=["Cozy Bear", "The Dukes"])
  → Add surface forms: "apt29", "cozy bear", "the dukes"
```

#### Scan Process (`autolinker.py:420-565`)

For each paragraph:

1. **Aho-Corasick match** on lowercased text against all surface forms
2. **Word-boundary validation** (prevent "APT" matching "RAPT" mid-word)
3. **Ambiguous name filtering:**
   - Short alpha-only terms (≤10 chars by default) require uppercase first char in original text
   - Prevents false positives on common words like "fox" in "Firefox"
   - Configurable via `autolinker_ambiguous_name_max_length` (default 10) and `autolinker_ambiguous_max_occurrences` (default 3) — DB-overridable at Settings → Engine → autolink stage, see [Configuration](#configuration)

4. **Confidence scoring:**
   - Canonical names → "high" confidence
   - Aliases → "medium" confidence
   - Weighted by source's `confidence_weight` (e.g., 0.8 for lower-tier feeds)

5. **Structured identifier extraction:**
   - CVE pattern: `CVE-\d{4}-\d{4,}`
   - TTP pattern: `T\d{4}(?:\.\d{3})?` (technique IDs + subtechniques)

#### Redis Vocabulary Versioning (`autolinker.py:1091-1159`)

For distributed workers (Celery nodes):

```python
VOCAB_VERSION_KEY = "intelfeed:autolinker:vocab_version"

# On refresh:
await r.set(VOCAB_VERSION_KEY, vocab.version)  # UTC timestamp

# On scan:
redis_version = await r.get(VOCAB_VERSION_KEY)
if redis_version == _vocab_version:
    return  # Already up to date
refresh_vocabulary(db)  # Otherwise rebuild
```

Workers check Redis before every scan; if versions mismatch, vocabulary is reloaded. This enables zero-downtime updates across a cluster.

### Phase 3: Junction Record Storage

Matches are persisted as **junction records** linking entries to entities:

```python
# autolinker.py:638 — store_autolink_matches()

# For threat actors:
EntryThreatActor(
    entry_id, threat_actor_id,
    confidence="high|medium|low",  # Weighted by source
    source="auto_link",
    matched_names=["APT29", "Cozy Bear"],  # Variants found
    paragraph_indices=[0, 3, 7],  # Where they appear
)

# For CVEs:
EntryCVE(entry_id, cve_id, paragraph_indices=[...])

# For TTPs:
EntryTTP(
    entry_id, ttp_id,
    source_text="auto_link:T1234",  # Source of extraction
    paragraph_indices=[...]
)
```

**Key design:**
- `paragraph_indices` enables proximity scoring; backfilled if NULL
- `confidence` from match type + source weight
- `source="auto_link"` distinguishes from AI/regex sources
- `on_conflict_do_nothing()` prevents race conditions under concurrency

Entity stats are updated:
```python
actor.article_count += 1
actor.last_seen_at = datetime.now(timezone.utc)
```

### Phase 4 (Optional): Secondary Extraction Layers

After autolinker, optional pipelines run:

- **Regex IOC extraction:** Extract IPs, domains, file hashes
- **AI extraction** (`backend/app/ai/`): Structured entity extraction via LLM
- **TTP extraction** (`intelligence/ttp.py`): Layer 1 (regex T####) + Layer 2 (AI)
- **CVE enrichment** (`intelligence/cve.py`): NVD API fetch for CVSS, EPSS, affected products

---

## Autolinker Deep Dive

### False Positive Filtering

The autolinker has **three layers** of false positive protection:

1. **Configuration blacklist** (`autolinker_false_positive_names`)
   - CSV-configured common words to ignore: "data", "report", "system", etc.
   - Also covers Windows built-in tools/LOLBins and common-word aliases that leak in from Malpedia `alt_names` and AI extraction ("page", "free", "watchdog", "norton", "banking trojans", …), which otherwise generate mass false-positive links
   - Checked at vocabulary build time (line 320). Vendor, Product, Tool, and Mitigation names deliberately **bypass** this list (`skip_fp_filter`), so real vendor names that collide with denylisted words (e.g. Norton the vendor) still match

2. **Ambiguous name rules** (`_is_ambiguous_surface_form`, line 180)
   - Single alpha-only words ≤ 10 chars (default) require uppercase-first in original text
   - "fox" must appear as "Fox" (proper noun), not lowercase
   - Configurable threshold: `autolinker_ambiguous_name_max_length`

3. **Frequency-based filtering** (`scan_text`, lines 362-488)
   - Ambiguous names exceeding `autolinker_ambiguous_max_occurrences` (default 3) are rejected
   - Prevents trivial matches on common terms

### Pending Tier: Dictionary-Word Matches

The capitalization guard cannot disambiguate entity mentions from ordinary proper-noun
compounds — "Royal Navy" links Royal-the-ransomware, "© N2K Networks, Inc." links INC.
A fourth protection layer holds these matches for contextual confirmation instead of
linking instantly:

- **Classification** (`is_common_english_word`, `autolinker.py`): single-token alpha-only
  surface forms are checked against a bundled ~31k common-English-words list
  (`app/intelligence/data/common_english_words.txt`, google-10000-english ∪ top-30k
  OpenSubtitles frequency list). Dictionary words ("royal", "inc", "hive", "medusa",
  "turkey") mark the vocab entry `is_provisional`; coined names ("Emotet", "LockBit")
  stay instant. Applies to actor/malware/tool/country only — vendor/product have no AI
  payload to reconcile against and keep instant linking. Countries use their own short
  list instead (`AMBIGUOUS_COUNTRY_WORDS`: Turkey, Jordan, Chad, Georgia, China…), since
  the subtitle-frequency list also carries proper nouns like "canada" and "germany".
  Analysts resolve held matches by hand in Engine → Review → Held links
  (`GET /api/entity-links/pending`, `POST /api/entity-links/pending/resolve`).
- **Diversion** (`store_autolink_matches`): matches whose surface forms are all
  provisional are written to `pending_autolink_matches` instead of junction tables —
  invisible to correlation, signals, counts, and the UI. A single non-provisional form
  (e.g. the "Royal Ransomware" alias) rescues the match into an instant link.
- **Reconcile** (`intelligence/autolink_reconcile.py`, called from
  `store_entry_analysis`): when the one-pass AI analysis lands, pending entities whose
  name/aliases appear in the AI's extracted entities are **promoted** through the normal
  store path (identical confidence weighting and `article_count` bumps; actor/malware/tool
  payload slots are matched jointly since the AI files ransomware brands inconsistently).
  Unconfirmed entities are **rejected** with a `FalsePositiveRecord`
  (`extraction_source="ai_reconcile"`).
- **Feed policy** (`services/ai_eligibility.py`): AI queueing and the diversion step share
  one check, `entry_will_get_ai_analysis` — the instance `ai_one_pass_enabled` switch, the
  feed's `ai_analysis_enabled`, and an extraction mode other than `none`. On an entry that
  fails it, nothing would ever confirm a held match, so provisional matches are **dropped**:
  not held, not linked. On a feed with AI off, common-word names aren't tagged. Drops are
  counted in daily Redis keys (`autolink:pending_dropped_ai_off:<YYYYMMDD>`) and the
  Autolinking tab of the Engine view shows the 30-day total
  (`pending_dropped_ai_off` on `GET /api/entity-links/stats`).
- **Expiry**: entries that never get an AI pass for per-entry reasons (junk-gated, budget)
  leave rows unresolved; `prune_engine_tables` deletes unresolved rows after 14 days and
  resolved rows after 30. `scripts/maintenance/resolve_pending_ai_off.py` resolves open
  rows on entries whose feed fails the feed-policy check (`resolution = 'dropped_ai_off'`).

Gated by `autolink_pending_tier_enabled` (Settings → Engine → autolink stage, default on) — and
auto-disabled when `ai_one_pass_enabled` is off, since without the reconciler there is
no promotion path and dictionary-word entities would never link at all. Known gap:
`link_entity_to_existing_entries` (manual entity creation backfill) bypasses the tier.

### Junk Alias Filtering at Import

The FP word set is also enforced at **ingestion time**, so junk aliases never enter the `aliases` arrays in the first place (`autolinker.py:61-120`):

- **`is_junk_alias(alias, canonical_name)`** — rejects empty/short forms (below `autolinker_min_name_length`), exact duplicates of the entity's own name, and any surface form in the FP name set. Intended for actor/malware aliases; vendor/product names bypass it.
- **`filter_aliases(aliases, canonical_name)`** — drops junk aliases and de-duplicates case-insensitively while preserving order.

Callers:
- **AI extraction** (`intelligence/enrichment.py`, `store_threat_actors` / `store_malware`) checks `is_junk_alias()` before merging newly extracted aliases into an existing entity.
- **Malpedia sync** (`workers/enrichment_tasks.py`, `_run_malpedia_sync`) passes Malpedia `alt_names` through `filter_aliases()` before storing them.

### Cross-Type Resurrection Guard

Same-type entity merges survive re-import because the loser's name lands in the survivor's `aliases` array (`intelligence/entity_dedup.py`). Cross-type folds (e.g. the "Akira" malware family folded into the "Akira" threat actor) would otherwise resurrect within hours, because each importer only searches its own table. Two mechanisms close that gap:

1. **Reclassify tombstones** — `EntityReclassifyTombstone` (`models/entity_maintenance.py`) records one row per folded name/alias: `(source_type, normalized_name) → (target_type, target_id)`. A cross-type reclassify in `api/entity_merge.py` writes these. Automated creation paths — AI extraction (`intelligence/enrichment.py`) and the Cybergeist sync (`intelligence/external_feeds.py`) — now route through `resolve_entity_creation()` (`intelligence/entity_resolution.py`), which calls `find_reclassify_tombstone()` (`intelligence/entity_dedup.py`) before creating an entity; on a hit creation is skipped and the entry is instead linked to the surviving canonical entity via `link_entry_to_entity()` (idempotent junction insert that bumps `article_count`/`last_seen_at` only on new rows). Set `active=False` on a tombstone to intentionally re-allow a split. Legitimately-distinct same-name entities (Jupyter product vs Jupyter stealer) never get a tombstone.
2. **FP entity-name filter** — `is_fp_entity_name()` (`backend/app/intelligence/autolinker.py:101`) guards the same automated creation paths against spawning junk profiles: it rejects the configurable FP name set plus bare system-binary/LOLBin filenames (`svchost.exe`, `*.dll`, `*.sys`, …). Manual creation is not gated — a human deliberately adding an entity is trusted.

The resolver adds further gates on top (an `entity_name_denylist` table, normalized/alias-index exact matching, and held-for-review candidate matches), controlled by `entity_creation_gates` (`off` / `shadow` / `on`, default `shadow` — shadow logs the would-block decision to `EntityMaintenanceLog` and still creates). Every resolution decision is written to `EntityMaintenanceLog` (`resolution_*` actions) so it surfaces in the hygiene feed.

Tools carry two more guards that hold for every automated source whatever `entity_creation_gates` says. A concept word in `TOOL_CONCEPT_NAMES` (`intelligence/entity_resolution.py`: hash algorithms, vulnerability classes such as SQL injection, protocols such as WebSocket, and generic words such as payload or debug) is blocked (`generic_name:concept_term`). A name already on file as a product or vendor (canonical name or alias, via `entity_alias_index`) is held as `product_or_vendor_name`, and the entry links to that product or vendor instead; `DUAL_USE_TOOL_NAMES` (AnyDesk, rclone, ngrok and the like) is exempt. A feed with `extract_tools` off calls the resolver with `link_only=True`: every matcher still runs, so known tools link, and a name that would have created a row is blocked as `creation_disabled`. `scripts/maintenance/clean_tool_catalog.py` moves platform and product rows out of the tool catalog and deletes concept rows onto the do-not-recreate list.

See diagram: [Entity creation guards](diagrams/intelligence-engine-entity-creation-guards.md)

**Example scenario:**
```
Text: "The fox (Malware Family) was seen..."
actor.name = "Fox", aliases = ["fox"]
Surface form "fox" is ambiguous (4 chars, alpha-only)
  → Match "fox" (lowercase) → rejected (not uppercase)
  → Match "Fox" (uppercase) → accepted
Result: Entry linked to actor despite ambiguity
```

### Vocabulary Performance

- **Space:** Automaton size depends on entity count; typically 10K–100K entities = <100 MB
- **Time:** Aho-Corasick scan is O(n + m + z) where n = text length, m = alphabet size, z = match count
  - Typical entry (10 KB): <100 ms scan on modern CPU
- **Concurrency:** No locking; read-only after build. Workers can scan in parallel.

### False Positive Feedback Loop

The `FalsePositiveRecord` model (`models/false_positive_record.py:13`) tracks analyst feedback:

```python
FalsePositiveRecord(
    entity_type="threat_actor",
    entity_id=uuid.UUID(...),
    entity_value="APT29",  # The incorrectly matched name
    source_entry_id=entry_id,
    reason="Not threat actor, generic term in this context",
    marked_by=user_id,
    extraction_source="auto_link",  # Which layer flagged it
    created_at=datetime.now(utc),
)
```

Future enhancements could:
- Feed FP records into model retraining for AI extraction
- Dynamically adjust `autolinker_false_positive_names`
- Weight down ambiguous-name confidence on re-extraction

---

## Entity Hygiene Console

The dedup/tombstone/FP machinery above is operated day-to-day from a single admin surface backed by `api/hygiene.py` (~3,200 lines, all routes under `/api/admin/hygiene/*`, admin-only except cascade preview).

**Where it lives in the UI:** Workbench → **Engine** is a single-surface console (`frontend/src/components/engine/EngineMatrix.tsx`). Hygiene surfaces as the **Proposals** lens on the console's Links and Review view-tabs (`frontend/src/components/engine/ProposalsQueue.tsx` — queue of pending adjudicator and scanner proposals with an origin facet, inline Apply / Dismiss, bulk Apply all / Dismiss all, and a History view with Restore) plus a **Maintenance** drawer (`MaintenancePanel.tsx` — orphan prune, full re-extract, proximity backfill, destructive resets). Bookmarked `?section=workbench` and `?tab=` deep links redirect into the console.

### Unified Feed & Stats

- `GET /api/admin/hygiene/feed` — chronological merge of `entity_link_validation_log` + `entity_maintenance_log`, normalized into one row shape with per-row actions and filter chips (proposed vs applied). `origin=adjudicator|legacy` splits the adjudicate stage's rows from the scanners'; `orphaned=true` lists pending legacy proposals no entry can carry (entry gone, or merge/stale rows whose entity is gone) for manual disposition. `DELETE /api/admin/hygiene/feed/{source}/{row_id}` dismisses a row; `POST /api/admin/hygiene/dismiss-proposals` dismisses every pending proposal of one origin.
- `GET /api/admin/hygiene/stats` — combined counters (applied 24h/7d, pending proposals, orphan count) across both logs, plus `adjudication_mode`, `adjudication_pending` and `adjudication_breaker_until`.
- `POST /api/admin/hygiene/adjudication/{log_id}/apply` / `.../restore` — act on or undo one adjudicator row in `entity_maintenance_log`; `POST /api/admin/hygiene/adjudication/apply-all` applies every pending adjudicator proposal.
- `POST /api/admin/hygiene/link-log/{log_id}/restore` / `.../apply-removal` — undo or act on one `entity_link_validation_log` row (restores re-create the junction row from the snapshot and count as analyst restores).

### The adjudicate stage (`services/entry_adjudication.py`)

Day-to-day cleanup happens once per entry, at ingest. After an entry's one-pass analysis lands, the `adjudicate` pipeline stage (kind `post_analysis`, `adjudicate_entry_task` on the `ai` queue, dispatched by `enqueue_adjudication`) runs one more AI call on that entry: the article text plus a manifest of everything the analysis wrote — entity links of every source (with article counts, ages, the pending-tier flag and the analyst-restored flag), entities the entry minted (with their nearest catalogue names pre-fetched through the resolver's own matchers, so a merge can only target a name the model was shown), relationship claims with their evidence sentence, and AI observables. The reviewer returns a verdict — remove, reclassify, veto, merge, demote or drop — only for the items it would change; anything it omits is kept, which keeps a long article's response inside the task's output budget. In `shadow` the verdicts become rows in the two proposal logs the Review › Proposals reads (`shadow_remove` / `needs_reclassification` for links, `adjudication_*` actions in `entity_maintenance_log` for the rest); in `apply` the high-confidence ones are acted on through the same primitives the queue's Apply buttons use, and every applied change writes the audit row that is also its undo. Per-entry and rolling circuit breakers downgrade a destructive run to proposals; the rolling one also pauses dispatch for an hour (`adjudication_breaker_until`, shown as a chip in the Engine needs-you row). Edges an analyst touched (confirmed, created, rejected), external-feed edges, and edges whose verdict is already settled (`corroborated` / `coincidental`) are never in the manifest and never changed in any mode, and neither is a validator-junction link (actor, malware, vendor, product, country) an analyst restored within 90 days — that guard reads the link log, the one place a restore is recorded per entry per link, so tool, sector and TTP links carry no such shield.

The pieces of the job: duplicates are caught at creation (a minted entity's nearest catalogue names ride along in the manifest, so `merge` can only target one of them, and `veto` deletes an entity only when this entry created it and nothing else holds it); relationship edges are demoted at birth (`coincidental`, sticky) or promoted by a keep-counter on the edge (`reviewer_kept_entry_ids`, confirmed at `relationship_evidence_promote_count` distinct entries); stale entities are a live `stale` filter on the Review view (one article at most, no edge, 90 days idle); and `backfill_entry_adjudications` (manual: `celery -A app.workers.celery_app call app.workers.adjudication_tasks.backfill_entry_adjudications`, kwargs `limit`, `since_days`) walks older analysed entries through the same gates within half of each hour's budget. Scanner proposals (name normalization, alias collisions) still come from the on-demand scanners below and sit in the same queue under origin `legacy`. See [engine.md](engine.md) and [engine-settings.md](engine-settings.md#adjudicate-stage-post-analysis-ai-review).

### Reclassification Suggestions

The reviewer can file `needs_reclassification` advisories (with a `suggested_entity_type`) instead of remove/keep verdicts. `POST /api/admin/hygiene/apply-reclassify-advisories` promotes them: advisories are deduped by `(entity_type, entity_id, suggested_type)`, matched to an existing same-name target (or a new one is created), and pushed through `perform_reclassify()` (`api/entity_merge.py`) in shadow or apply mode. Apply mode clears the consumed advisory rows; stale advisories for already-deleted entities are cleared too.

### Merge Suggestions (`intelligence/merge_suggestions.py`)

Ranked duplicate-pair suggestions per entity type, scoring normalized-name similarity (generic-suffix stripping, token containment), alias overlap, shared entity relationships, and co-mention frequency. Served at `GET /api/entities/{entity_type}/merge-suggestions`; pairs the analyst dismisses are persisted in **`entity_merge_suggestion_dismissals`** (unique per pair) and never re-suggested. Cross-type tool-vs-malware name collisions ("Pegasus" tool vs "Pegasus" malware) are flagged as possible cross-type duplicates but never offered auto-merge — those need reclassify, not merge.

### Orphans, Cascade Preview & Scanners

- `GET /api/admin/hygiene/orphans` / `POST .../orphans/prune` — entities with `article_count == 0`, pruned one at a time or in bulk.
- `GET /api/entities/{type}/{id}/cascade-preview` — read-only blast-radius preview (junction rows, relationships, notes, campaign links) before deleting an entity; available to any authenticated user.
- On-demand scanners with shadow/apply flows: enrichment gaps (`/enrichment-gaps` + AI-backed `/enrichment-gaps/enrich`), name normalization, alias-collision scan, vendor-autolink scan, and TTP/CVE ID hygiene (malformed/withdrawn IDs).

### Tombstone Management

There are no dedicated tombstone endpoints. Cross-type reclassifies — including bulk advisory promotion above — write `EntityReclassifyTombstone` rows via `api/entity_merge.py` (see [Cross-Type Resurrection Guard](#cross-type-resurrection-guard)). To intentionally re-allow a split, set `active = False` on the tombstone row directly in the DB; there is currently no UI for it.

---

## Observables — the IOC ledger

`backend/app/intelligence/observables.py`. Observables became a first-class
entity type in 2026-09, replacing the v1 IOC tables dropped in
`060_remove_ioc_tables`. Identity is `(kind, value)`; schema in
[data-model.md](data-model.md#observable--the-ioc-ledger); settings in
[engine-settings.md](engine-settings.md#observables-stage).

### The contract: regex never creates a row

IOC v1 failed by discovering indicators with patterns, which meant every
`microsoft.com` in prose and every version string that looked like a hash became
a row. v2 inverts it. **Nothing in this module creates an observable from a
regex match.** There are two distinct things a scan can produce:

- **Candidates** — entry-local *nominations*, written to
  `entries.observable_candidates` by `scan_candidates()`
  (`observables.py:271`). They are attached to the entry and shown in the
  reader as promotable suggestions. They are not ledger rows and never become
  ones on their own. Capped by `observables_candidate_max` (default 200).
- **Sightings** — `sight_known_values()` (`backend/app/intelligence/observables.py:1001`) exact-matches
  scanned tokens against values a **door** already created. Sighting a known-bad
  string is precise; discovering strings by regex is what killed v1.

### Candidate policy is precision-first by construction

| Family | Becomes a candidate when |
|---|---|
| Hashes, public IPs | Always — unambiguous, octet-validated, reserved/benign ranges gated out (`_valid_public_ip`, `backend/app/intelligence/observables.py:250`) |
| Domains, URLs, emails | **Only when the author defanged them** (`evil[.]com`, `hxxps://`). An author who defangs is telling you it is an indicator, so `microsoft.com` in prose nominates nothing |
| Host artifacts (cmdline, registry, path, mutex, …) | Never from prose. `<pre>`/`<code>` blocks may nominate a *candidate* (`scan_code_block_candidates`) only when the block is mostly command-shaped and the line opens with a shell prompt or a known executor; bulletin feeds and rule-repository files never nominate. Rows arrive through the AI door, the TTP observable door or an analyst |

Refanging (`refang()`, `observables.py:64`) normalises `hxxp`, `[.]`, `(dot)`,
`[:]`, `[@]` and friends on the way in, and `is_defanged()` records that the
author did so — the defanged surface form is kept on the sighting
(`entry_observables.surface_form` / `was_defanged`), not on the ledger row.

### The judgment doors

A ledger row exists because something with judgment put it there. Each door has
its own base confidence:

| Door (`created_via`) | Base | What it is |
|---|---|---|
| `manual` | 1.0 | An analyst promoted a candidate or created the row |
| `ioc_list` | 0.85 | A curated indicator-list feed body, parsed by `parse_ioc_list_body()` (`backend/app/intelligence/observables.py:709`). Path-gated by `ioc_list_path_allowed()` (`backend/app/intelligence/observables.py:658`), which refuses `whitelist` / `allowlist` / `benign` / `unverified` files and C2-Tracker's aggregate `all.txt` — the per-tool files carry the real provenance, and an everything-list is not a judgment. `ioc_list_path_tag()` reads the infra tag a path implies |
| `ttp_observable` | 0.85 | An `EntryTTP.observable_value` upsert — this is how host artifacts get in, carrying their technique via `entry_observables.ttp_id` |
| `publisher_ioc` | 0.9 | The indicator file a write-up links to — Cisco Talos `IOCs` (`.txt` + STIX `.json` with MISP-category roles), Bitdefender `malware-ioc` CSV, Datadog `indicators-of-compromise` CSV — fetched from an allow-list of repositories only, parsed with the publisher's own format, sighted on the **article** (`entry_observables.source = publisher`). `intelligence/publisher_iocs.py`; `observables_publisher_ioc_enabled` |
| `ai_extraction` | 0.8 | The one-pass `entry_analysis` `iocs` array — network, hash **and host kinds** (cmdline, path, registry, scheduled_task, service_name, mutex, named_pipe, user_agent, http_header), each with a role (network: c2/delivery/payload/…; host: the tactic) and an optional `technique_id` that becomes the sighting's `ttp_id`. Gated by `observables_ai_capture_mode` (`shadow` stages them as promotable candidates carrying the judgment; `capture` writes rows) and, in capture, by the per-kind list `observables_ai_capture_kinds`. Every value passes `validate_kind_value`, which vetoes generic discovery commands, OS-binary paths, bare well-known registry keys, placeholders and key-shaped "hashes" |

Author-defanged input adds `DEFANG_BONUS` (+0.1). There is intentionally no
`created_via` value meaning "regex".

### Validation gates

Values still have to be plausible for their kind before a door can write them —
`validate_kind_value()` (`backend/app/intelligence/observables.py:1240`) and the per-kind plausibility
checks (`_plausible_cmdline`, `_plausible_path_atom`, `_plausible_user_agent`,
`_plausible_domain`). These exist because an AI asked for IOCs will happily
return a sentence as a command line.

`is_shared_infra()` (`backend/app/intelligence/observables.py:652`) tags dual-use infrastructure —
shared hosting, CDNs, URL shorteners — into `infra_tag` rather than dropping it.
The intel is real; it just must not reach a blocklist. Publishing excludes
tagged rows; the profile still shows them.

### Lifecycle

Confidence decays per kind (see
[data-model.md](data-model.md#observable--the-ioc-ledger)) and `status_for()`
(`observables.py:753`) derives `active` / `aging` / `expired` from the current
value. `retro_sight_observable()` (`backend/app/intelligence/observables.py:1945`) back-fills sightings
for a newly created row against recent entries, so promoting a candidate does
not lose the history it already had. Nightly jobs:
`decay-observable-confidence` (02:20 UTC),
`reconcile-observable-counters` (02:50 UTC, repairs the O(1) counters), and
`retro-sight-observables` (every 6h at :40).

### Where it surfaces

The observables browser and profile pages, the reader's candidate queue,
unified search, the `observables` pipeline stage column in the Engine console,
and the outbound feeds (`/api/publish/edl/…`, `/api/publish/lookup/…`, and the
TAXII 2.1 collection under `/api/taxii2/`) — see
[engine-settings.md](engine-settings.md#publishing-engine--publishing-browse-screen)
for the publish gates. Registry tools: `get_observable`, `search_observables`.

---

## Entity Types & Resolution

### Uniqueness Keys

Each entity type has a unique identifying key:

| Entity Type | Unique Key | Resolution |
|-------------|-----------|------------|
| ThreatActor | `name` | Case-insensitive, unique in DB |
| MalwareFamily | `name` | Case-insensitive, unique in DB |
| CVE | `cve_id` (e.g. "CVE-2024-12345") | Regex extracted, upserted on demand |
| TTP | `technique_id` (e.g. "T1234.001") | Regex extracted, must exist in DB |
| Country | `name` (e.g. "China", "Russia") | Aliases supported |
| Vendor | `name` | Unique in DB |
| Product | `name` | Associated with vendor_id |
| Tool | `name` | Attack/dual-use tooling (Mimikatz, etc.) |
| Mitigation | `mitre_id` or `name` | MITRE security controls |
| CWE | `cwe_id` (e.g. "CWE-79") | Seeded from the MITRE catalog; `parent_cwe_id` walks the abstraction ladder |
| Observable | `(kind, value)` | The IOC ledger — created only by a judgment door, never a regex match |

### Enrichment Sources

Entities are enriched from multiple sources:

**ThreatActor:**
- Manual MITRE ATT&CK mapping (`mitre_id`)
- Wikipedia profiles (`wikipedia_url`, `wikipedia_content`, `wikipedia_image_url`)
- Origin country (`origin_country_id`)
- Target sectors (`threat_actor_target_sectors` claim rows; `targeted_sectors` is the label cache they rebuild)
- Associated TTPs (`associated_ttps`: JSONB array)

**MalwareFamily:**
- Malpedia integration (`malpedia_url`)
- Type classification (`malware_type`: trojan, ransomware, worm, etc.)
- Associated actors (`associated_actors`: JSONB)

**CVE:**
- NVD enrichment: CVSS v3.1 score, severity, affected products
- EPSS scoring: Probability of exploitation (`epss_score`, `epss_percentile`)
- Exploit tracking: POC count, Metasploit modules, KEV badge status
- Timeline events (initial discovery → weaponization → active exploitation)

**TTP:**
- MITRE ATT&CK framework: ID, name, tactic, platforms, data sources
- Detection guidance (`detection` field from MITRE)
- Sub-technique relationships

---

## Correlation Engine

The correlation engine runs **after** entity extraction and creates second-order insights by analyzing entity co-occurrence and relationships.

### Correlation Event Detection (`correlation_events.py`)

After a new entry is processed, `correlate_new_entities(db, entry_id)` checks for patterns:

#### 1. New TTP for Known Actor
```
IF entry.contains(NEW_TTP) AND entry.contains(KNOWN_ACTOR)
    THEN event("new_ttp_for_known_actor")
```
- **Known actor:** `article_count > 1` (existed before this entry)
- **New TTP:** `article_count == 1` (first seen in this entry)

#### 2. New TTP for Known Malware
```
IF entry.contains(NEW_TTP) AND entry.contains(KNOWN_MALWARE)
    THEN event("new_ttp_for_known_malware")
```

#### 3. New Malware for Known Actor
```
IF entry.contains(NEW_MALWARE) AND entry.contains(KNOWN_ACTOR)
    THEN event("new_malware_for_known_actor")
```

#### 4. Actor-Malware Co-occurrence
```
IF entry.contains(KNOWN_ACTOR) AND entry.contains(KNOWN_MALWARE)
    THEN event("actor_malware_cooccurrence")
```

#### 5. Coverage Gap
```
FOR each TTP in entry:
    IF count(DetectionRule where rule.source_ttps contains TTP) == 0
        THEN event("coverage_gap")
```
- Alerts detection engineers to missing rules for observed techniques

#### 6. New Intel for Rule
```
FOR each TTP in entry:
    IF exists(published DetectionRule covering TTP)
        THEN event("new_intel_for_rule")
```
- Notifies rule owners of new activity matching their rules

### Deduplication (`correlation_events.py:88-114`)

Within 24 hours, duplicate events (same type + source entity) are collapsed:

```python
async def _deduplicate_event(db, event):
    cutoff = datetime.now(UTC) - timedelta(hours=24)
    existing = await db.execute(
        select(CorrelationEventRecord)
        .where(
            CorrelationEventRecord.event_type == event.event_type,
            CorrelationEventRecord.source_entity_id == event.source_entity_id,
            CorrelationEventRecord.created_at > cutoff,
        )
    )
    if existing:
        increment(existing.occurrence_count)
        return True  # Deduplicated
    return False
```

### Pivot Queries (`correlation.py`)

The correlation engine supports **pivot queries** to find all entities related to a given entity:

```python
# Find all threat actors that appear in the same entries as CVE-2024-12345
async def pivot_query(
    db: AsyncSession,
    source_entity_type: str = "cve",
    source_entity_id: uuid.UUID,
    target_entity_type: str = "threat_actor",
) -> list[dict]:
    # 1. Get all entries linked to source entity
    entry_ids = await _get_entry_ids_for_entity(db, source_entity_type, source_entity_id)
    
    # 2. Find all target entities in those entries
    related = await _get_related_entities(db, target_entity_type, entry_ids)
    
    # 3. Enrich with proximity scores
    #    (paragraph distance decay) and co-occurrence counts
    return related
```

**Output:**
```json
{
  "id": "...",
  "type": "threat_actor",
  "name": "APT29",
  "co_occurrence_count": 5,
  "proximity_score": 0.67,
  "proximity_entries": [
    {
      "entry_id": "...",
      "score": 0.8,
      "title": "APT29 exploits CVE-2024-12345 in campaign"
    },
    ...
  ]
}
```

### Proximity Scoring (`correlation.py:166-185`)

When two entities appear in the same entry, their **proximity score** reflects how close they are:

```python
def _compute_proximity_score(
    source_indices: list[int] | None,
    target_indices: list[int] | None,
) -> float:
    """Score based on minimum paragraph distance.
    
    Formula: 1.0 / (1 + decay_rate × min_distance)
    
    Example:
      - Same paragraph: 1.0 / (1 + 1.0 × 0) = 1.0 (perfect signal)
      - 1 paragraph apart: 1.0 / (1 + 1.0 × 1) = 0.5
      - 5 paragraphs apart: 1.0 / (1 + 1.0 × 5) = 0.167 (weak signal)
    """
    if not source_indices or not target_indices:
        return default_score  # 0.3 if no paragraph data
    
    min_dist = min(abs(a - b) for a in source_indices for b in target_indices)
    return 1.0 / (1 + decay_rate * min_dist)
```

**Configuration:**
- `proximity_default_score`: 0.3 (default when no paragraph data)
- `proximity_decay_rate`: 1.0 (aggressiveness of decay)
- `proximity_moderate_threshold`: 0.3 (filtering weak links)

### Timeline Construction

Entities maintain a **timeline** of their activity:

```python
# models/cve.py:25
timeline: Mapped[list] = mapped_column(JSONB, default=list)
# [
#   {"date": "2024-01-15", "event": "disclosure"},
#   {"date": "2024-02-03", "event": "poc_published"},
#   {"date": "2024-02-10", "event": "active_exploitation"},
# ]
```

Timelines are built by:
1. Collecting `first_seen_at`, `last_seen_at` from entities
2. Enriching with external data (NVD timeline, KEV badge status)
3. Ordering by date for dashboard visualization

---

## Retention & Archival

Entity-level confidence is assigned at link time by the autolinker's `_weighted_confidence()` (see the Autolinker section); there is no time-based confidence decay on entry↔entity links. (Typed *entity relationships* are the exception: the weekly `decay_relationship_confidence` beat task demotes stale co-occurrence rows from `probable` back to `possible`; analyst-touched rows are never demoted.)

Old entities and correlation events are archived based on retention policy:

```python
# correlation_events.py:553
async def archive_old_events(db, retention_days=90):
    """Delete read events older than 90 days."""
    cutoff = datetime.now(UTC) - timedelta(days=retention_days)
    await db.execute(
        delete(CorrelationEventRecord)
        .where(
            CorrelationEventRecord.created_at < cutoff,
            CorrelationEventRecord.is_read.is_(True),  # Only read (not actionable)
        )
    )
```

---

## Detection Rule Extraction

The rule extraction engine stores **6 rule types** (`yara`, `sigma`, `elastic_ql`, `kql`, `snort_suricata`, `splunk_spl`) found in entry content: YARA, Sigma, Elastic TOML rule files, Snort/Suricata, and the query languages SPL, KQL, EQL and ES|QL (EQL and ES|QL are stored as `elastic_ql`). CrowdStrike QL and other formats are supported for authoring/import in the rule library, but are not detected by the ingest extractor.

```python
# rule_extraction.py:32-87
def extract_rules_from_content(text, source_url=None, *, html=None, article_title=None) -> list[dict]:
    text = html.unescape(text)              # &gt; &lt; &amp; -> > < &
    code_blocks = _code_blocks(text, html)  # fences + <pre>/<code> from the article HTML
    rules = []
    rules.extend(_extract_yara_rules(text))
    rules.extend(_extract_elastic_toml_rules(text))
    rules.extend(_extract_sigma_rules(text, code_blocks))
    rules.extend(_extract_snort_suricata_rules(text))
    rules.extend(_extract_query_rules(text, code_blocks))   # SPL, KQL, EQL, ES|QL

    # Drop repeats (whitespace-blind), validate, then title the queries
    ...
    _number_query_titles(validated, article_title)
    return validated
```

Callers pass the entry's sanitized `content_html` as `html` and its title as `article_title`. The plain `content_text` has every `<pre>` block flattened into prose, so code blocks are read from the HTML; HTML entities are decoded in both, so a saved query runs as written.

### YARA Rules (`rule_extraction.py:139-202`)

**Extraction logic:**
1. Regex match `rule <name> { ... }`
2. Find balanced closing brace
3. Extract metadata section (title, severity, tags)
4. Validate `condition:` exists

**Storage:**
```python
DetectionRule(
    rule_type="yara",
    title="Detect malware family X",
    rule_content=full_yara_text,
    severity="high|medium|low|unknown",
    tags=["malware_family_x", "auto-extracted"],
    is_draft=True,  # Manual review before publishing
    mitre_tactics=["Execution"],  # From metadata
    source_ttps=["T1234"],  # Linked TTPs from entry
    source_cves=["CVE-2024-12345"],  # Linked CVEs
)
```

### SIGMA Rules (`rule_extraction.py:299-369`)

**Format:** YAML with required fields: `title`, `detection`, `logsource`

**Extraction:**
1. Find YAML blocks (fenced code blocks or raw YAML)
2. Parse with `yaml.safe_load_all()` (supports multi-document)
3. Extract MITRE tactics from tags: `attack.execution` → "Execution"
4. Serialize back to YAML for storage

### Elastic TOML Rules (`rule_extraction.py:205-296`)

**Format:** TOML with `[rule]` section

**Key fields extracted:**
- `query` (EQL, KQL, or ESL)
- `language` (eql, esql, kql)
- `severity`
- `threat.tactic.name` → MITRE tactic
- `threat.technique.id` → MITRE technique

### Query languages: SPL, KQL, EQL, ES|QL (`rule_extraction.py:445-616`)

**Code blocks only.** A query is taken from a Markdown fence or an HTML `<pre>`/`<code>` block, never from prose, so a sentence that says "where" never becomes a rule. A fence tag or `language-*` class (`kql`, `kusto`, `eql`, `esql`, `spl`, `splunk`) is a hint; the block still has to have the language's shape. The one exception is the inline SPL scan: a line of text starting `index=`, `search ` or `| tstats`, at least 30 characters long.

**Shapes:**
- **SPL:** `index=` + `|` (pipe); `search ` + `|`; `| tstats`; or `| stats`, `| where`, `| eval`… plus `index=`, `sourcetype=` or `source=`
- **KQL:** a table name followed by a pipe (`DeviceProcessEvents | where …`) and a tabular operator (`| where`, `| summarize`, `| project`, `| extend`, `| join`…). The table must be a known Defender XDR / Sentinel table, or the query must use syntax SPL never has (`| summarize`, `| project`, `ago(`, `=~`, `has`, `==`). A query that opens with `let` or `union` must name a known table. `index=` / `sourcetype=` rule it out.
- **EQL:** `<category> where …` (`process`, `file`, `network`, `registry`, `any`…), `sequence [by …] [with maxspan=…] [`, or `join … [` — stored as `elastic_ql`
- **ES|QL:** `FROM <index pattern>` followed by `| WHERE`, `| STATS`, `| EVAL`, `| KEEP`… — stored as `elastic_ql`

Leading `//` comment lines are dropped from KQL/EQL/ES|QL queries; the validator ignores `//` and `/* */` comments when it checks quote balance.

**Titles.** Queries carry no name of their own. Each is titled from the article: `"<article title> — KQL query 2"`, numbered per language in article order, so titles are distinct within an article and stable when it is processed again.

**Examples:**
```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "rundll32.exe"
| summarize count() by DeviceName
```
```eql
sequence by host.id with maxspan=1m
  [file where event.action == "creation"]
  [process where process.name == "rundll32.exe"]
```

### Snort/Suricata Rules (`rule_extraction.py:372-402`)

**Format:** Single-line rules with `msg` field

**Regex match:**
```
^(alert|log|pass|drop) (tcp|udp|icmp|ip) ... (...)$
```

**Title extraction:**
```
msg:"Detect SQL Injection Attempt"
```

### Rule Storage (`rule_extraction.py:619-718`)

Extracted rules are stored with **deduplication and linking.** Dedup is on the rule body, never on the title alone, so two articles' queries never overwrite each other:

```python
async def store_extracted_rules(db, entry_id, user_id, rules):
    for rule_data in rules:
        # Same body already stored (by this user, or auto-extracted by anyone) -> skip
        existing = select(DetectionRule.id).where(
            DetectionRule.rule_content == rule_data["rule_content"],
            or_(DetectionRule.created_by == user_id, DetectionRule.tags.contains(["auto-extracted"])),
        )
        if existing:
            continue

        # Same entry + title + type, new body: the rule was edited upstream
        # and the article processed again -> replace the content in place
        existing_by_title = select(DetectionRule).where(
            DetectionRule.created_by == user_id,
            DetectionRule.entry_id == entry_id,
            DetectionRule.title == rule_data["title"],
            DetectionRule.rule_type == rule_data["rule_type"],
            DetectionRule.tags.contains(["auto-extracted"]),
        )
        if existing_by_title:
            existing_by_title.rule_content = rule_data["rule_content"]
            continue

        # New rule
        db.add(DetectionRule(...))
```

Processing the same article again stores nothing new.

**Link to source entities:**
```python
# Merge entry-level entities with rule-level entities
rule_ttps = list(set(entry_ttp_ids + (rule_data.get("mitre_techniques") or [])))
rule_cves = list(set(entry_cve_ids + (rule_data.get("cve_ids") or [])))

detection_rule.source_ttps = rule_ttps
detection_rule.source_cves = rule_cves
```

---

## TTP & MITRE ATT&CK Integration

### TTP Extraction Layers

TTP extraction is **multi-stage:**

**Layer 1 — Regex (Free)**
```python
# intelligence/ttp.py:19-80
TTP_PATTERN = re.compile(r"\bT\d{4}(?:\.(?!000\b)\d{3})?\b")
# Matches: T1234, T1234.001, T1234.999 (rejects the invalid .000 subtechnique)

def extract_ttp_ids_regex(text: str) -> list[dict]:
    matches = TTP_PATTERN.findall(text)
    return [
        {
            "technique_id": tid,
            "technique_name": tid,  # Placeholder
            "confidence": "medium",
            "source": "regex",
        }
        for tid in matches
    ]
```

**Layer 2 — AI (Optional)**
```python
# intelligence/ttp.py:83
async def extract_ttps(db, user_id, entry_id, entry_data, use_ai=True):
    # Layer 1: Always run
    regex_ttps = extract_ttp_ids_regex(text)
    
    # Layer 2: Optional (if AI enabled + configured)
    ai_ttps = []
    if use_ai:
        result = await run_task(
            task_name="ttp_mapping",
            variables={"entry": entry_data, ...}
        )
        # AI returns richer data:
        # {
        #   "technique_id": "T1234",
        #   "technique_name": "Command and Scripting Interpreter",
        #   "tactic": "Execution",
        #   "confidence": "high",
        # }
        ai_ttps = result.get("ttps", [])
    
    # Merge: AI takes precedence
    merged = {t["technique_id"]: t for t in regex_ttps}
    for t in ai_ttps:
        merged[t["technique_id"]] = t  # Override regex with AI
    
    return list(merged.values())
```

### TTP Storage & Enrichment

```python
# intelligence/ttp.py:146
async def store_ttps(db, entry_id, ttps):
    for ttp_data in ttps:
        tid = ttp_data["technique_id"]
        
        # Check if TTP exists
        existing = await db.execute(select(TTP).where(TTP.technique_id == tid))
        if existing:
            # Update: enrich with new data
            existing.last_seen_at = datetime.now(utc)
            existing.article_count += 1
            if ttp_data.get("technique_name") and not existing.description:
                existing.description = ttp_data["technique_name"]
            if ttp_data.get("tactic"):
                existing.tactic = ttp_data["tactic"]
        else:
            # Create new TTP
            ttp = TTP(
                technique_id=tid,
                technique_name=ttp_data.get("technique_name", tid),
                tactic=ttp_data.get("tactic"),
                description=ttp_data.get("description"),
            )
            db.add(ttp)
        
        # Link to entry
        await db.execute(
            pg_insert(EntryTTP).values(
                entry_id=entry_id,
                ttp_id=ttp.id,
                confidence=ttp_data.get("confidence"),
            ).on_conflict_do_nothing()
        )
```

### MITRE ATT&CK Sync

IntelFeed syncs TTPs from MITRE ATT&CK framework:

```python
# api/attack.py (pseudo-code)

async def sync_mitre_ttps(db):
    """Fetch TTPs from MITRE ATT&CK public API or offline dataset."""
    techniques = await fetch_mitre_techniques()
    # [
    #   {
    #     "technique_id": "T1234",
    #     "technique_name": "Command and Scripting Interpreter",
    #     "tactic": "Execution",
    #     "platforms": ["Windows", "macOS", "Linux"],
    #     "data_sources": ["Process Execution"],
    #     "detection": "Monitor for...",
    #   },
    #   ...
    # ]
    
    for tech in techniques:
        existing = await db.execute(
            select(TTP).where(TTP.technique_id == tech["technique_id"])
        )
        if not existing:
            db.add(TTP(**tech))
        else:
            # Update rich metadata
            for key in ["technique_name", "tactic", "platforms", ...]:
                setattr(existing, key, tech.get(key))
    
    await db.commit()
```

---

## CVE Pipeline

### CVE Extraction & NVD Enrichment

**Extraction step:**
```python
# intelligence/cve.py:22-48
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")

def extract_cve_ids(text: str) -> list[str]:
    return list(set(CVE_PATTERN.findall(text)))
```

**NVD Enrichment:**
```python
# intelligence/cve.py:50
async def enrich_from_nvd(cve_id: str) -> dict | None:
    """Fetch CVE details from NVD API 2.0."""
    headers = {}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key
    
    for attempt in range(NVD_MAX_RETRIES):
        try:
            resp = await client.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"cveId": cve_id},
                headers=headers,
            )
            
            if resp.status_code == 429:  # Rate limited
                await asyncio.sleep(2 ** (attempt + 1))
                continue
            
            cve_data = resp.json()["vulnerabilities"][0]["cve"]
            
            return {
                "cvss_score": extract_cvss_v3_1_score(cve_data),
                "severity": extract_cvss_severity(cve_data),
                "description": extract_description(cve_data),
                "affected_products": extract_cpe_products(cve_data),
                "references": extract_references(cve_data),
                "nvd_data": cve_data,  # Full NVD response
            }
        except Exception as e:
            logger.warning(f"NVD enrichment failed for {cve_id}: {e}")
```

### EPSS & Exploit Tracking

The CVE model stores:

```python
# models/cve.py:31-38
epss_score: float | None  # 0.0–1.0
epss_percentile: float | None  # Percentile among all CVEs
epss_updated_at: datetime  # When score last updated
exploit_availability: str  # "none", "poc", "weaponized", "active_exploitation"
github_poc_count: int  # Number of POCs on GitHub
github_poc_urls: list[str]  # Direct links
metasploit_module: str | None  # If weaponized in Metasploit
```

These are populated via:
- **EPSS API:** Fetched periodically (daily/weekly)
- **KEV catalog:** CISA Known Exploited Vulnerabilities
- **GitHub POC scanner:** Scans for public exploits
- **Metasploit:** Checks for available modules

### CVE Scoring & Priority

```python
# intelligence/cve.py:241 (simplified)
def calculate_cve_priority(
    cvss_score: float | None,
    epss_score: float | None,
    exploit_status: str | None,
) -> str:
    """Priority: CRITICAL, HIGH, MEDIUM, LOW."""
    if exploit_status == "active_exploitation":
        return "CRITICAL"
    if cvss_score >= 9.0 or epss_score >= 0.5:
        return "HIGH"
    if cvss_score >= 7.0:
        return "MEDIUM"
    return "LOW"
```

---

## Glossary & Inline Highlighting

The glossary system (`models/glossary_term.py`) supports **inline term highlighting** in entry content:

```python
class GlossaryTerm(Base):
    __tablename__ = "glossary_terms"
    
    id: UUID
    is_system: bool  # System terms vs. user-defined
    name: str  # Unique term
    category: str  # E.g., "Detection", "Threat Intelligence", "Compliance"
    maturity: str  # E.g., "draft", "stable"
    description: str  # Short definition
    long_description: str | None  # Detailed explanation
    technologies: list  # Related tech areas
    search_terms: list  # Aliases for matching
```

**Highlighting flow:**
1. Entry is displayed in frontend
2. Frontend calls API to fetch glossary terms
3. Frontend highlights matches of `name` + `search_terms` in entry text
4. Hovering reveals `description` tooltip; clicking opens full term details

**Example:**
```
Entry text: "...using DLL injection to elevate privileges..."
Glossary term: GlossaryTerm(
    name="DLL Injection",
    search_terms=["dll injection", "dynamic library injection"],
    description="Technique to execute code within a process...",
)
Result: "DLL injection" is highlighted; tooltip on hover
```

---

## Reporting & Export

### Report Templates

IntelFeed ships 6 built-in report templates (`REPORT_TEMPLATES`, `reporting.py:18-103`):

| Template (key) | Purpose | Sections |
|----------|---------|----------|
| **Flash Alert** (`flash_alert`) | Rapid notification | summary, key_findings, iocs, recommended_actions, references |
| **Threat Actor Profile** (`actor_profile`) | Comprehensive profile | overview, aliases_attribution, ttps, target_sectors, infrastructure, iocs, timeline, references |
| **Campaign Tracker** (`campaign_tracker`) | Active campaign tracking | executive_summary, campaign_overview, attack_chain, iocs, ttps, affected_systems, timeline, recommendations |
| **Threat Landscape** (`landscape_report`) | Periodic overview | executive_summary, key_trends, notable_threats, vulnerability_highlights, sector_impact, outlook, appendix |
| **Threat Exposure** (`exposure_report`) | Exposure profile for a saved scope | executive_summary, scope, threat_surface, ttps, iocs, outlook, references |
| **Detection Report** (`detection_report`) | Detection engineering | executive_summary, attack_chain, ttps, detection_opportunities, coverage_gaps, iocs, log_source_requirements, recommended_actions, references |

The `iocs` data section is the **observables ledger** — judged rows sighted in
the report's sources, defanged, with their attribution claims. The section names
match the builtin `report_templates` DB rows seeded in migration `050`, which
carried these sections for months while nothing filled them.

Each family has its own tailored section-generation AI task
(`REPORT_SECTION_TASKS`, `reporting.py:108-115`) — `report_section_exposure`,
`report_section_flash_alert`, `report_section_actor_profile`,
`report_section_campaign_tracker`, `report_section_landscape`,
`report_section_detection` — seeded from `backend/app/ai/prompts/defaults.py`
and editable at Settings → AI → Prompts. A detection report and a flash alert
are not the same writing job, and one shared prompt produced the average of the
two.

### Intel profiles and exposure reports

An **intel profile** (`intel_profiles`, `backend/app/api/intel_profiles.py`) is
a named, reusable report scope: regions (country ids) × verticals (canonical
sector slugs) × a lookback window. The platform is enterprise-agnostic —
nothing here is "our org" or "the company". Analysts keep one profile per scope
they report against: a customer, a client portfolio, a watch area.

`backend/app/intelligence/threat_surface.py` is the read-model behind the
exposure builder. Given a profile's scope it finds the actors and malware
families the corpus says are active against it, each carrying **why it
matched**, from three independent sources:

| Source | Evidence |
|---|---|
| Co-occurrence | Entries in the window linking the entity *and* a scope country or scope sector (`entry_countries` / `entry_sectors`) |
| Claims | `threat_actor_target_countries` rows and the target-sector junctions (`threat_actor_target_sectors` / `malware_target_sectors`, any source) |
| Victims | Ransomware victim disclosures by that group in scope countries/sectors inside the window |

Candidates matching on only one dimension still surface — ranked lower, with
the gap stated. The analyst decides, not the query. Nothing in the module
writes; the keep/drop decisions land in `intel_profiles.curation`, so a rebuild
doesn't re-ask what was already rejected.

Endpoints: `GET/POST/PUT/DELETE /api/intel-profiles`,
`GET /api/intel-profiles/{id}/surface` (the matched surface for a saved
profile), `POST /api/intel-profiles/surface-preview` (an unsaved scope),
`GET /api/intel-profiles/sector-vocabulary`, and
`POST /api/intel-reports/generate-exposure` to turn a curated surface into a
report. Frontend: `ExposureBuilderPage.tsx` and `ReportBuilderPage.tsx`, with
`SendToReportModal.tsx` as the send-to-report entry point from entry lists and
entity profiles.

### Report Generation

```python
# reporting.py:310-492 (outline)
async def generate_report_content(
    template_type: str,  # "flash_alert", "actor_profile", etc.
    entry_ids: list[uuid.UUID],
    entity_ids: dict,  # {"ttps": [...], "actors": [...], ...}
    db: AsyncSession,
) -> dict:
    """Generate report structure from template + linked entities."""
    template = REPORT_TEMPLATES[template_type]
    
    # Fetch entries and entities
    entries = await db.execute(select(Entry).where(Entry.id.in_(entry_ids)))
    ttps = await db.execute(select(TTP).where(...))
    cves = await db.execute(select(CVE).where(...))
    actors = await db.execute(select(ThreatActor).where(...))
    malware = await db.execute(select(MalwareFamily).where(...))
    
    # Build report structure
    report = {
        "title": "Report Title",
        "sections": {
            "executive_summary": "Auto-generated summary from entities...",
            "attack_chain": "Diagram of actor → malware → TTP → detection...",
            "ttps": [
                {
                    "technique_id": "T1234",
                    "technique_name": "...",
                    "detection_coverage": "high|medium|low",
                    "detection_rules": [DetectionRule, ...],
                }
            ],
            ...
        },
        "metadata": {
            "generated_at": datetime.now(utc).isoformat(),
            "template": template_type,
            "entities_analyzed": len(entity_ids),
        }
    }
    
    return report
```

### Export Formats

**CSV Export:**
- Entities (threat actors, malware, CVEs, TTPs)
- Entry-entity links with confidence and paragraph indices
- Correlation events with severity and timestamps

**Markdown Export:**
- Report sections formatted with headings, tables, links
- Entity profiles with descriptions and enrichment data
- Timeline diagrams in text format

**MISP/STIX Export:**
- STIX 2.1 bundles of observed entities
- Relationships preserved with score/confidence
- Exportable to threat intel platforms (MISP, OpenCTI, etc.)

---

## Real-Time Intelligence Events

### Event Severity Mapping (`correlation_events.py:18-34`)

```python
EVENT_SEVERITY = {
    "coverage_gap": "high",  # TTP observed, no detection rule
    "trending_entity": "medium",  # Entity mentions spike
    "campaign_match": "medium",  # Entry matches active campaign
    "requirement_match": "medium",  # Entry matches intel requirement
    "new_intel_for_rule": "low",  # New article about covered TTP
    "new_ttp_for_known_actor": "medium",  # Actor behavior expanding
    "new_ttp_for_known_malware": "medium",  # Malware capability expanding
    "new_malware_for_known_actor": "medium",  # Actor using new malware
    "actor_malware_cooccurrence": "low",  # Ongoing activity
    "feed_stale": "low",  # Feed not producing entries
    "feed_error": "medium",  # Feed fetch failures
    "exploit_status_change": "high",  # CVE moves to active exploitation
    "cve_score_change": "high",  # CVE CVSS/EPSS score significant change
    "new_exploit_discovered": "high",  # New public POC for CVE
    "kev_addition": "high",  # CVE added to CISA KEV catalog
}
```

### Event Publishing

Events are published **immediately** via:

```python
# correlation_events.py:325
from app.api.events import publish_event

publish_event("broadcast", "correlation_event", event.to_dict())
```

Subscribers (frontend, webhooks, external systems) receive:

```json
{
  "event_type": "new_ttp_for_known_actor",
  "severity": "medium",
  "source_entity_type": "ttp",
  "source_entity_id": "...",
  "source_entity_label": "T1234 Command and Scripting Interpreter",
  "related_entity_type": "threat_actor",
  "related_entity_id": "...",
  "related_entity_label": "APT29",
  "context": "New TTP T1234 found in article mentioning known actor APT29",
  "created_at": "2024-05-03T14:22:00Z",
}
```

### Webhook Integration

High-severity events can trigger webhooks to:
- Slack: Instant notifications in security channels
- PagerDuty: Incident creation for critical events
- Splunk: Forward for correlation with SIEM data
- Custom systems: Via HTTP POST to registered endpoints

---

## Performance & Scaling

### Autolinker Performance

| Metric | Typical Value |
|--------|---------------|
| Vocabulary build | ~100 ms (10K entities) |
| Scan per entry | <100 ms (10 KB text) |
| Scan throughput | 100+ entries/sec single worker |
| Vocabulary size (memory) | ~50 MB (10K entities) |

### Correlation Engine Performance

| Operation | Time |
|-----------|------|
| Pivot query (10K entries) | <500 ms |
| Proximity scoring | O(n × m) where n, m = co-occurrence counts |
| Event deduplication | <10 ms (24-hour window) |

### Database Indexes

Critical indexes for performance:

```sql
-- Junction tables
CREATE INDEX idx_entry_threat_actor_on_actor_id 
  ON entry_threat_actors(threat_actor_id);
CREATE INDEX idx_entry_threat_actor_on_entry_id 
  ON entry_threat_actors(entry_id);

-- Entity tables
CREATE INDEX idx_threat_actor_name ON threat_actors(name);
CREATE INDEX idx_malware_family_name ON malware_families(name);
CREATE INDEX idx_cve_cve_id ON cves(cve_id);
CREATE INDEX idx_ttp_technique_id ON ttps(technique_id);

-- Correlation events
CREATE INDEX idx_correlation_event_source_entity 
  ON correlation_events(source_entity_type, source_entity_id);
CREATE INDEX idx_correlation_event_created_at 
  ON correlation_events(created_at DESC);
```

### Scaling Strategies

1. **Read-only replica for Meilisearch sync:** Prevents write lock contention
2. **Async processing:** Heavy enrichment tasks (NVD, EPSS, GitHub POC) run asynchronously via Celery
3. **Batch commits:** `autolink_batch()` commits every 100 entries to control transaction size
4. **Redis caching:** Vocabulary version, entity correlation caches, event deduplication windows
5. **Distributed workers:** Vocabulary versioning via Redis allows horizontal scaling

---

## Configuration

### Settings (`app/config.py`)

Key intelligence engine settings:

```python
# Autolinker (config.py:180-214) — DB-overridable
autolinker_min_name_length: int = 4        # Skip names shorter than this
autolinker_false_positive_names: str = "..."  # Curated CSV denylist (common words,
                                              # Windows/LOLBin tools, junk aliases).
                                              # Actor/malware/country only — vendor,
                                              # product, tool and mitigation bypass it.
autolinker_blocked_surface_forms: str = ""    # Analyst hard blocks, enforced for EVERY type
autolinker_ambiguous_name_max_length: int = 10  # Short alpha-only terms need capitalization
autolinker_ambiguous_max_occurrences: int = 3   # Frequency threshold for ambiguous names
autolink_pending_tier_enabled: bool = True      # Hold dictionary-word matches for AI confirmation

# Proximity scoring (config.py:281-285) — DB-overridable
proximity_default_score: float = 0.3       # No paragraph data
proximity_decay_rate: float = 1.0          # Aggressiveness
proximity_strong_threshold: float = 0.7    # "Strong" relationship cutoff
proximity_moderate_threshold: float = 0.3  # Filtering weak links

# CVE enrichment
nvd_api_key: str = ""  # NVD API key (higher rate limits when set)
```

**Override behavior:** every one is read via `settings.get(...)` at runtime — proximity in `correlation.py:177-178,290-291`, the autolinker keys in `autolinker.py:46,50,63,204,448` — which checks the `system_settings` DB table before falling back to the `.env` default. All of them are editable at runtime from Settings → Engine.

**Full catalogue:** [engine-settings.md](engine-settings.md) documents all 146 DB-overridable settings, including the relationship strength/specificity knobs and the entity-creation gates this doc's sections describe.

Correlation-event retention (90 days) and the dedupe window (24 h) are hardcoded function defaults in `correlation_events.py`, not config keys.

---

## Sequence Diagrams

### Entry Ingest to Event Emission

```
Entry Received
    ↓
[1. Split into paragraphs]
    ↓
[2. Build vocabulary (if stale)]
    ↓
[3. Aho-Corasick scan]
    → Match threat actors → Store EntryThreatActor
    → Match malware → Store EntryMalware
    → Match CVEs (regex) → Upsert CVE → Store EntryCVE
    → Match TTPs (regex) → Store EntryTTP
    → Match countries, vendors, products → Store links
    ↓
[4. Correlation event detection]
    → Check: new TTP for actor?
    → Check: new malware for actor?
    → Check: coverage gap (TTP with no rule)?
    → Check: campaign match?
    ↓
[5. Publish events]
    → SSE broadcast
    → Webhook dispatch
    → CorrelationEventRecord persist
    ↓
Event in Dashboard
```

### Pivot Query (Find Actor for CVE)

```
User: "Show all threat actors exploiting CVE-2024-12345"
    ↓
API call: GET /intelligence/pivot?source=cve&source_id=X&target=threat_actor
    ↓
[1. Get entry IDs linked to CVE]
    SELECT DISTINCT entry_id FROM entry_cves WHERE cve_id = X
    → [entry1, entry2, ..., entry10]
    ↓
[2. Get threat actors in those entries]
    SELECT threat_actor, COUNT(*) as co_count
    FROM entry_threat_actors
    WHERE entry_id IN (entry1...entry10)
    GROUP BY threat_actor
    → [APT29 (5x), Lazarus (3x), ...]
    ↓
[3. For each actor, compute proximity scores]
    FOR each (entry_id, threat_actor_id) pair:
        SELECT paragraph_indices FROM entry_threat_actors
        SELECT paragraph_indices FROM entry_cves
        Compute proximity = 1.0 / (1 + decay × distance)
    ↓
[4. Fetch entry titles for top proximity pairs]
    SELECT title FROM entries WHERE id IN (...)
    ↓
Return:
{
  "id": "APT29-uuid",
  "type": "threat_actor",
  "name": "APT29",
  "co_occurrence_count": 5,
  "proximity_score": 0.67,
  "proximity_entries": [
    {"entry_id": "...", "title": "APT29 exploits CVE-2024-12345", "score": 0.8},
    ...
  ]
}
```

---

## Troubleshooting & Debugging

### Vocabulary Build Issues

**Problem:** Autolinker not matching known entities

**Diagnosis:**
```python
# Check vocabulary is built
print(_vocabulary.built)  # Should be True
print(_vocabulary.entry_count)  # Should > 0

# Manually rebuild
from app.intelligence.autolinker import refresh_vocabulary
count = await refresh_vocabulary(db)
print(f"Built vocabulary with {count} surface forms")
```

**Common causes:**
- Entity name is <4 chars (below `autolinker_min_name_length`)
- Entity name is in false positive list
- Entity is ambiguous and appears lowercase (or frequency > threshold)

### Correlation Events Not Firing

**Problem:** No events generated despite new TTPs/actors

**Diagnosis:**
```python
# Check if entry was processed
entry = await db.get(Entry, entry_id)
print(entry.entry_threat_actors)  # Should have links
print(entry.entry_ttps)  # Should have links

# Check event deduplication
from app.models.correlation_event import CorrelationEventRecord
events = await db.execute(
    select(CorrelationEventRecord)
    .where(CorrelationEventRecord.entry_id == entry_id)
)
print(events.scalars().all())
```

**Common causes:**
- Deduplication within 24-hour window
- Entities are "new" (article_count = 1), failing `known_*` check
- TTPs have coverage (rule exists), so no `coverage_gap` event

### CVE Enrichment Delays

**Problem:** CVSS/EPSS scores not populating

**Diagnosis:**
```python
# Check if enrichment task is running
from app.workers import celery_app
cve_tasks = celery_app.inspect().active_queues()  # Celery queue status

# Manually trigger enrichment
from app.intelligence.cve import enrich_from_nvd
data = await enrich_from_nvd("CVE-2024-12345")
print(data)  # Should have cvss_score, severity, etc.
```

**Common causes:**
- NVD API rate limited (retry with backoff)
- API key not configured (`settings.nvd_api_key`)
- Network timeout (NVD service unavailable)

---

## Future Enhancements

1. **Temporal reasoning:** Detect "campaign ramp-up" (actor activity spike over time)
2. **Graph neural networks:** Learn implicit relationships between entities
3. **Multi-source fusion:** Weight entities by feed reliability
4. **Confidence calibration:** Learn decay rates from actual analyst feedback
5. **Federated extraction:** Allow partner organizations to contribute entities
6. **Zero-day correlation:** Detect potential zero-day patterns from anomalous TTPs
7. **Supply chain tracking:** Model dependencies and cascade failures
8. **Autonomous threat hunting:** Automatically generate hypotheses from high-scoring correlations

---

## References

- **Autolinker implementation:** `/backend/app/intelligence/autolinker.py` (~1455 lines)
- **Correlation engine:** `/backend/app/intelligence/correlation.py` (~2435 lines)
- **Detection rule extraction:** `/backend/app/intelligence/rule_extraction.py` (~720 lines)
- **Correlation events:** `/backend/app/intelligence/correlation_events.py` (~605 lines)
- **CVE intelligence:** `/backend/app/intelligence/cve.py` (~430 lines)
- **TTP extraction:** `/backend/app/intelligence/ttp.py` (~300 lines)
- **Reporting:** `/backend/app/intelligence/reporting.py` (~585 lines)
- **Entity dedup & tombstones:** `/backend/app/intelligence/entity_dedup.py`
- **Maintenance tasks:** `/backend/app/workers/maintenance.py`
- **Entity models:** `/backend/app/models/{threat_actor,malware_family,cve,ttp,glossary_term,entity_maintenance}.py`

---

**Document updated:** 2026-08-28  
**IntelFeed version:** Latest  
**Scope:** Core intelligence extraction, linking, correlation, and export  

For architecture overview (non-engine-specific), see `/docs/architecture.md` sections 4–9.

---

## Per-feed pipeline switches

Each feed carries a set of switches that decide what the ingest pipeline does with its articles. They are edited per-feed in the Edit Feed modal's **Pipeline** pane and per-category in the Edit Category modal, and each one maps to a column on the Feed model:

| Switch | Field | Governs |
|---|---|---|
| Process this feed | `intel_extraction_mode` = `none` or not | Everything below. `none` opts out of all extraction. |
| Autolink known entities | `intel_extraction_mode` = `manual` (off) vs `selective` / `full` (on) | The deterministic dictionary scan. |
| ↳ Only security-relevant articles | `selective` (on) vs `full` (off) | Whether autolinking applies a keyword relevance pre-filter. |
| AI analysis (one pass) | `ai_analysis_enabled` | The one-pass `entry_analysis` call. With AI off, common-word names aren't tagged: the autolinker drops dictionary-word matches it would otherwise hold for the AI (see [Pending Tier](#pending-tier-dictionary-word-matches)). |
| Regex enrichment | `auto_extract_on_ingest` | The standalone CVE/NVD, TTP and mitigation pass. |
| Detection rule extraction | `extract_detection_rules` | Sigma/YARA/SPL/Elastic parsing from article bodies. |
| ↳ Create tool entities | `extract_tools` | Whether that AI pass may mint new Tool rows. Off, the AI still links tools already in the catalog, and autolink tags them as usual. Advisory-type articles skip AI tools whatever the switch says. Does nothing when the AI is off. |

The observables ledger scan has no switch of its own, but it is not unconditional either: `_scan_entry_observables` skips any feed whose `intel_extraction_mode` is `none`, so "do not analyse this feed" really does mean nothing is extracted — the curated `ioc_list` door would otherwise keep creating ledger rows from a feed the operator had switched off. That check sits in the task rather than at dispatch, exactly as `_autolink_entry`'s does, which also means a feed set to `none` outranks a pipeline plan that enables the stage. Everything else about it is tuned by the global `observables_*` settings.

> **This section used to describe a five-way preset** — "Full", "Selective", "Known entities only", "Manual", "None" — mapped onto `intel_extraction_mode` + `auto_extract_on_ingest`. Three of those labels had stopped being true. The one-pass AI analysis, which does most of the extraction today, gates only on `intel_extraction_mode == "none"` and ignores `auto_extract_on_ingest` entirely, so a feed set to "Known entities only — match against existing database" or "Manual — only when triggered" still had the AI read every article and create entities. The preset is gone; the switches above are what actually exists. See `frontend/src/components/feedModal/pipelineStages.ts`.

**The AI pass is the main extraction path, and it has its own switch.** `enqueue_entry_analysis` (`services/entry_analysis.py`) refuses to queue an entry when the global `ai_one_pass_enabled` is off, when the feed's `intel_extraction_mode` is `none`, or when the feed's `ai_analysis_enabled` is false. That last field exists because turning the AI off for one noisy source used to require `mode=none`, which also switches off its autolinking and extraction — there was no setting for "keep matching this against my catalog, just don't let the AI invent entities from it".

The sections below describe the **deterministic** layer in detail: what each `intel_extraction_mode` value does to the autolinker and the regex passes. They are accurate about that layer and say nothing about the AI pass, which runs independently of everything except the three gates above.

### The two pipelines

Two distinct extraction pipelines run on each new entry:

**Pipeline A — the autolinker** (`backend/app/intelligence/autolinker.py`). Dictionary-based entity linking. Loads a vocabulary of every ThreatActor, MalwareFamily, Country, Vendor, Product, Tool, and Mitigation already in the database (canonical names + aliases) into an Aho-Corasick automaton, scans entry title/summary/content paragraph-by-paragraph, and creates `EntryThreatActor`, `EntryMalware`, `EntryCountry`, `EntryVendor`, `EntryProduct`, `EntryTool`, `EntryMitigation` junction rows. As a side effect of the same scan, regex matches for CVE IDs (`CVE-YYYY-NNNN`) and MITRE ATT&CK technique IDs (`T1234[.NNN]`) also create `EntryCVE` and `EntryTTP` links. CVEs are the one entity the autolinker creates rather than only links: a CVE ID not seen before becomes a stub row (`created_via = "auto_link"`, `created_from_entry_id` set) and is queued for enrichment, unless the ID is on the analyst do-not-recreate list (`is_name_denied`, the same check the extract path uses). TTPs only link if the technique is already in the MITRE catalog. Entry point: `_autolink_entry` (`workers/intel_feed_tasks.py:202`). Gated by `intel_extraction_mode`.

**Pipeline B — heavy enrichment** (`_extract_entry_intel`, `backend/app/workers/intel_feed_tasks.py:469`). Standalone regex pass + external lookups:

- CVE extraction with NVD enrichment — pulls CVSS scores, descriptions, affected products from the NVD API
- TTP regex extraction — same `T1234` pattern, but a dedicated standalone pass
- Mitigation extraction — MITRE M-IDs
- GitHub rule import — for `github_repo` entries with a `content_type`, runs the dedicated `process_github_entry` pipeline that parses SIGMA/YARA/Splunk/etc. rules

Dispatched when `auto_extract_on_ingest` or `extract_detection_rules` is on and the feed's mode is not `none`; the CVE/TTP/mitigation passes then check `auto_extract_on_ingest` themselves, and GitHub-typed entries (`content_type` set) take the import pipeline whichever flag dispatched it. Every ingest dispatch reads one gate, `feed_runs_extraction` (`pipeline/plans.py`), and `_extract_entry_intel` re-checks mode `none` itself, so a pipeline plan that enables the stage, a forced dispatch or the Engine's re-run never reaches past it.

A third optional layer — `extract_detection_rules` — runs `extract_rules_from_content` to pull SIGMA/YARA/SPL/Elastic/Snort rules from non-GitHub article bodies. Independent of `auto_extract_on_ingest` and of the autolink modes; off when the mode is `none`.

### `full` — autolink every article

Backend: `mode=full, extract=true`. Every new entry gets the autolinker, regex CVE extraction with NVD enrichment, regex TTP extraction, regex mitigation extraction, and (if `extract_detection_rules=true`) detection rule extraction. The relevance filter is skipped for autolinking — everything is tagged. (The AI junk gate, which uses the same score, still applies.)

Maximum recall, maximum cost. New CVEs referenced in the article spawn stub rows hydrated with NVD metadata; known threat actors, malware, vendors, and products get linked; TTPs and mitigations get pulled out by regex.

Cost considerations: NVD API calls are rate-limited (5 req / 30 sec without an API key, 50 req / 30 sec with one); the autolinker is cheap once the vocab is built (single Aho-Corasick pass per entry) but CPU scales with corpus size; junction-table writes from high-volume full-mode feeds are the biggest contributors to `EntryCVE` / `EntryThreatActor` row counts.

**Use for:** high-signal sources where every entry is virtually guaranteed to be threat intel (NVD, vendor PSIRT advisories, CISA alerts, Talos/Mandiant/CrowdStrike research, MITRE ATT&CK updates), reliability-A/B feeds, curated incident-tracking feeds. **Avoid for:** general news aggregators mixing commentary and marketing, Reddit/Bluesky/Mastodon feeds with a high noise floor, YouTube channels with noisy transcripts.

### `selective` — autolink security-relevant articles (default)

Backend: `mode=selective, extract=true`. The relevance filter (`backend/app/intelligence/relevance_filter.py`) scores the article — title, summary and content, plus the translation when there is one — before autolinking. Below `ai_analysis_relevance_threshold` (default 0.15, Settings → Engine) the autolinker skips the entry; the entry itself is still ingested and visible in the reader. Only autolinking reads this gate: regex CVE/TTP/mitigation extraction (when `auto_extract_on_ingest` is on), detection rule extraction and the observables stage run whatever the score. The same score and threshold drive the AI junk gate on every mode, so the one setting decides both what gets tagged here and what the AI reads.

The relevance filter is a cheap lexical scorer (no AI, no DB). Keywords match at the start of a word, so "exploited" counts for "exploit" but "laptop" does not count for "APT" and "percent" does not count for "RCE". Keywords of four letters or fewer must be the whole word, allowing a plural *s* or trailing digits ("APT29", "IOCs"; not "aptly", "pocket" or "Siemens"). It sums weighted hits across five keyword categories:

| Category | Weight | Examples |
|---|---|---|
| Vulnerability | 0.30 | "vulnerability", "CVE-", "RCE", "zero-day", "CVSS", "PoC", "advisory" |
| Malware | 0.30 | "malicious", "ransomware", "trojan", "Cobalt Strike", "C2 server", "shellcode", "stealer" |
| Incident | 0.25 | "breach", "hacked", "compromise", "intrusion", "phishing", "lateral movement", "supply chain" |
| Threat actor | 0.35 | "APT", "nation-state", "espionage", "hacktivist", "financially motivated" |
| Detection | 0.20 | "Sigma", "YARA", "IOC", "MITRE ATT&CK", "Splunk", "SIEM", "threat hunting" |

Per-category contributions use diminishing returns (1 hit = 80% of the weight, 2 or more = the full weight). Structured-pattern bonuses are added on top: CVE pattern in text +0.4, TTP pattern (`T1234`) +0.3, IOC-like pattern (IPv4, hash, defanged URL) +0.2, title contains any security keyword +0.15. Final score capped at 1.0. At the default 0.15 a single keyword in any category clears it, so the filter drops articles with no security vocabulary at all — product launches, earnings, release notes, politics — and keeps anything borderline. Raising the threshold tightens autolinking on selective feeds and the AI junk gate together. `scripts/maintenance/measure_relevance_filter.py` prints, per feed, how many recent entries fall under a given threshold, with sample titles.

**Use for:** general security blogs (Krebs, Bleeping Computer, The Record, DarkReading, The Hacker News), social sources where some posts are intel and others aren't, vendor blogs mixing security content with marketing — the default choice for anything you're not sure about. **Avoid for:** non-English feeds unlikely to hit English keywords (the keywords are English: turn on `auto_translate` so the filter scores the translation, or use full) and sources where every entry is intel by definition (use full).

If the relevance filter rejects an entry, it is skipped by the autolinker here and by the AI one-pass analysis (the junk gate, on any mode). A CVE ID alone adds 0.4 and an ATT&CK ID 0.3, so an article that names one always clears the default threshold.

### `full` with `auto_extract_on_ingest=false` — catalog matching without NVD cost

Backend: `mode=full, extract=false`. The autolinker runs unconditionally (no relevance gate, since mode is `full`); the standalone CVE-with-NVD, TTP, and mitigation passes are skipped (gated by `auto_extract`); detection rule extraction (if enabled) still runs. Note: the autolinker's internal CVE/TTP regex still fires as part of `scan_text`, so CVE stubs get created (outside the do-not-recreate list) and existing TTPs get linked — but without inline NVD hydration.

The autolinker matches against entities already in your database: threat actors and malware you've created or seeded, countries (seeded automatically), vendors/products, TTPs (the MITRE catalog must already be seeded), and CVEs (auto-created as skeletal stubs — just the ID, no description/CVSS/affected products — then queued for auto-enrichment and picked up by the nightly NVD sweeps `run_cve_nvd_backfill` and `reenrich_cve_nvd`). Both sweeps share one retry budget stamped into `nvd_data` (`_enrich_attempts`, `_enrich_last_attempt`): an ID NVD has no record of is looked up at most three times, a week apart, so junk IDs pulled out of prose stop costing NVD quota.

What you lose vs. selective/full: new CVE references don't trigger NVD lookups (bare CVE detail pages), M-IDs aren't linked, and the standalone TTP pass doesn't run (essentially redundant work being skipped, since the autolinker's own regex picks up TTP IDs). What you keep: full entity correlation against your curated catalog, retroactive backlinking when new entities are created later (`link_entity_to_existing_entries`, `backend/app/intelligence/autolinker.py:1351`), and optional detection rule extraction.

**Use for:** high-volume feeds where you want catalog correlation without per-mention NVD cost (Telegram channels, Bluesky firehoses, r/netsec), "alarm sources" where you only care whether a known entity is mentioned, reliability-D/F sources you don't trust enough to enrich from, and feeds where the relevance filter drops content you care about. **Avoid for:** likely sources of new CVEs (NVD itself, vendor PSIRT) and feeds where you want to discover new TTPs/mitigations — use full or selective.

### `manual` — no autolinking

Backend: `mode=manual`. The autolinker is skipped. The standalone CVE/TTP/mitigation pass still runs if `auto_extract_on_ingest=true`, and detection rule extraction if `extract_detection_rules=true`: both follow their own flags in this mode.

Entries from this feed are ingested normally — sanitized HTML, title/summary/content text, Meilisearch indexing, translation — they just aren't matched against your catalog at ingest. Manual does not stop the AI: if `ai_analysis_enabled` is on, the one-pass analysis still reads each article, tags it and can create entities, and the observables scan still runs. You can still run extraction on demand: the intelligence workspace has actions to autolink a single entry, and bulk rescan tools (scripts + admin endpoints) can target specific entries or feeds regardless of mode. New entities and aliases added later don't retroactively link to manual-mode entries: the retroactive backlink skips feeds set to manual or none.

**Use for:** noisy feeds you read for situational awareness but don't want polluting the entity graph, untrusted/unrated sources, feeds with persistent false-positive matches, personal feeds. If you genuinely never want anything from a feed, prefer `none`; if you actually want most entries processed, `selective` is the right call.

### `none` — process nothing

Backend: `mode=none`, whatever `auto_extract_on_ingest` and `extract_detection_rules` say. The only mode that opts out of every extraction pipeline: no autolinking, no AI analysis, no observables scan, no regex CVE/NVD, TTP or mitigation pass, no detection rule extraction and no GitHub rule import. Dispatch leaves the extract stage out (`feed_runs_extraction`, `pipeline/plans.py`), and `_extract_entry_intel`, `_autolink_entry` and `_scan_entry_observables` each check the mode themselves, so a pipeline plan cannot switch them back on; the bulk rescan skips these feeds too. Nothing is tagged and no entity, CVE, indicator or rule is created from the feed's articles.

What still happens: entries are ingested, sanitized, indexed and translated, get a priority score from the signal engine, are embedded and clustered into story threads (when embeddings are on), are matched against intelligence requirements, and run through automation rules. None of those read the mode.

**Use for:** feeds you want to read but keep entirely out of the intel system (personal blogs, hobby content), test/staging feeds, or temporarily quieting a feed while you fix a noisy entity catalog. Note: if you want detection rules extracted you need at least `manual` mode with `extract_detection_rules=true`, and if you want entries searchable by entity name you need autolinking (use `manual` + on-demand autolink, or another mode).

### Confidence weighting and reliability rating

Independent of mode, every autolink junction record gets a confidence value (high/medium/low) computed by `_weighted_confidence` (`backend/app/intelligence/autolinker.py:629`): a canonical name match starts at high (0.9), an alias match at medium (0.5), multiplied by `source_confidence_weight` derived from the feed's reliability rating (A–F), then bucketed (≥0.7 → high, ≥0.4 → medium, else low). An A-grade feed's canonical match for "APT29" stays high; an F-grade feed's alias match for "Cozy Bear" gets downgraded to low. This rolls into correlation scoring downstream — mode and reliability rating work together, so full mode on a graded-F feed still produces useful but appropriately-weighted links.

### Choosing a mode — quick decision guide

| Scenario | Suggested mode |
|---|---|
| NVD, CISA, vendor PSIRT, top-tier research feeds | `full` |
| General security news (Krebs, BleepingComputer, etc.) | `selective` (default) |
| Reddit/Mastodon/Bluesky firehose | `selective`, or `full` with regex enrichment off |
| Telegram/foreign-language threat actor channel | `full` with regex enrichment off, or `selective` with `auto_translate` on (the relevance keywords are English) |
| High-volume source you want matched but not AI-read | any mode, `ai_analysis_enabled=false` |
| Conference announcements / industry news | Manual |
| Untrusted source you read for awareness | Manual |
| Personal/non-security feeds | None |
| Noisy feed with persistent false positives | Manual while you fix the entity catalog |

### Operational notes

- Changing mode does not re-process existing entries — switching a feed from manual to full only affects new entries. To backfill, use the bulk rescan path (`autolink_batch` in `backend/app/intelligence/autolinker.py:1110` or the rescan endpoints).
- Adding a new threat actor or malware family triggers `link_entity_to_existing_entries` (`backend/app/intelligence/autolinker.py:1351`), which retroactively scans existing entries with the same rules as ingest autolinking: entries from manual/none feeds are skipped, the `autolinker_false_positive_names` list (for the types it covers) and `autolinker_blocked_surface_forms` drop terms, an ambiguous short name only counts where it is capitalised, and confidence is the canonical-name "high" / alias "medium" scaled by the feed's reliability rating (unrated = 0.5, so an unrated feed tops out at medium). The pending dictionary-word tier does not apply to it.
- The vocabulary is per-process and version-checked via Redis (`VOCAB_VERSION_KEY`). Creating a new entity bumps the version; all Celery workers rebuild on next scan, so there is no "stale vocab across workers" failure mode in normal operation.
- Foreign-language entries with translations (e.g., Russian Telegram with auto-translation enabled) get the autolinker run against the original and translated text concatenated (`workers/intel_feed_tasks.py:239-241`, via `entry_text_with_translation`), in any mode that runs the autolinker.

### None of this uses AI

All five modes drive deterministic string matching only: the autolinker is a pure Aho-Corasick dictionary scan (`pyahocorasick` C extension); the relevance filter is precompiled word-start keyword regexes plus three structured patterns (no AI, no DB calls); CVE/TTP/mitigation extraction is regex; NVD enrichment is a REST lookup (external, but not AI); detection rule extraction is pattern-based parsing per format; confidence weighting is arithmetic on the reliability grade. This is deliberate — the autolinker comment calls it "Layer 0 — free, instant correlation that runs on every entry": cheap, fast, no provider dependency, no rate limits, no hallucinations.

AI is a separate, opt-in layer on top (`backend/app/ai/` provider abstraction): summarization, one-pass `entry_analysis` extraction/adjudication, translation, detection rule drafts — run on demand, via automation rules, or at ingest when `ai_one_pass_enabled` is on. AI-created junction records carry a non-`auto_link` source so the rescan path leaves them alone when re-running the deterministic linker.

The deterministic layer and the AI layer are *mostly* independent, with one coupling worth knowing: `intel_extraction_mode = "none"` disables both, because `enqueue_entry_analysis` treats it as "this feed is out of the intel system entirely". Every other mode value (`full`, `selective`, `manual`) has no effect on whether the AI runs — that is `ai_one_pass_enabled` globally and `ai_analysis_enabled` per feed. Provider configuration lives under Settings → AI Configuration and the engine flags.


## Signal Engine (engine phase 2)

After post-processing (co-occurrence, correlation events, requirement matching) completes for an entry, `score_entry_task` (`app/workers/signal_tasks.py`) computes explainable signals (`app/intelligence/signals.py`) and stores them in `entry_signals` (one row per entry+signal_type, upserted) plus a denormalized `entries.priority_score`.

Signal families: novelty (novel_entity, entity_resurgence, new_pairing, scoop), coverage (source_convergence, under_reported, negative feed_echo), severity (kev_added, epss_jump, epss_high, weaponized_poc, critical_cvss), interest (pir_match, correlation_event), content (detection_content, research_depth).

Weighting is IDF self-tuning: the nightly `signal-rate-recompute` job stores each signal's 30-day firing rate in Redis (`intelfeed:signal_engine:rates`); a signal's weight is `ln(1/rate)` normalized so a 5%-rate signal weighs 1.0 (clamped 0.1–3.0). Global family multipliers live at `intelfeed:signal_engine:multipliers`. `signal-rescore-recent` (6-hourly) re-scores recent entries so late KEV/EPSS changes propagate; `backfill_entry_scores` is a manual task for scoring history.

Flags (Settings → Engine → score stage): `signal_engine_shadow` (compute + store only; validate via `GET /entries/triage?mode=signals`) and `signal_engine_surface` (drives the UI, phase 3). Scoring costs ~7ms/entry at production scale.

Scheduled-job observability: celery signal handlers in `app/workers/task_tracking.py` record every JOB_REGISTRY task run in `job_runs` (pruned at 30 days by `prune-engine-tables`).

### Surfacing (engine phase 3)

When `signal_engine_surface` is on: entry list responses carry `priority_score` + `top_signals` (top-2 explanations, only above the radar threshold) and `is_echo`; the entry list renders score-banded chips and de-emphasizes echoes; a "Radar" sort is available; `/api/entries/triage` defaults to the signal ranking. The radar threshold is auto (p95 of trailing-7d scores) with a manual override, editable with family multipliers in the Engine console's score-stage panel (Settings → Engine, `ScoreStageConfig`; backend `/api/engine/signals/*`). Per-user entity watch/mute lives at `/api/intelligence/watchlist` (Watch button in the profile header + actions menu) — watch boosts at read time, mute suppresses. Entity profiles feed `/api/engine/entities/{type}/{id}/whats-new` into the Overview tab's assessment block ("recent developments").

The Priority Queue is a `MainLayout` mode (`/priority-queue` renders `<MainLayout priorityMode />`). It interleaves open **story threads** with single ranked entries, assembled server-side by `GET /api/entries/priority-queue` (`build_priority_queue`, `backend/app/api/entries.py:1431`). A thread ranks by the 0–10 `priority_score` of its best unread, non-echo member, and its members are withheld from the queue as standalone rows. Threads with nothing unread never appear. The temporal-convergence clusters (`/intelligence/temporal-clusters`) still back the triage widget and the copilot tool, but nothing in the reading UI calls them. See [story-threads.md](story-threads.md).
