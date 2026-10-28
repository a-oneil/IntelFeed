# Architecture

This is the map of how IntelFeed works, from fetching a feed to linking entities, scoring articles and building detection rules. It is for developers and operators who want the big picture before they read the detailed docs linked from each section.

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

IntelFeed is a self-hosted threat intelligence platform built on an RSS reader. It reads security sources (RSS, Atom, YouTube, podcasts, Reddit, GitHub, NVD, Mastodon, Bluesky, Telegram and plain web pages). It finds threat entities in each article, such as threat actors, malware, CVEs and ATT&CK techniques. It then links those entities across articles, ranks articles by importance, and helps you write detection rules.

### Core Data Flow

```text
Fetch feed → parse → drop duplicates → clean HTML → save article
    ↓
Pipeline: autolink, observables, extract → relationships, correlation events, requirements → score
    ↓
One-pass AI analysis → AI review (adjudicate)
    ↓
Entity profiles, pivots, story threads, detection rules, automation
```

### Service Architecture

Ports are the dev stack (`docker-compose.dev.yml`). Production (`docker-compose.prod.yml`) puts Caddy in front for HTTPS and does not publish the internal ports.

| Service | Dev port | Role |
|---------|------|------|
| db (PostgreSQL 16 + pgvector) | 5433 | Main database |
| redis | 6380 | Task queue, caches, locks, autolinker word-list version |
| api (FastAPI) | 8000 | REST API. Runs database migrations on start |
| celery-worker | — | Background tasks on the default queue (fetching, linking, scheduled enrichment syncs) |
| celery-worker-ai | — | The `ai` queue, one task at a time. Every AI call runs here |
| celery-worker-enrichment | — | The `enrichment` queue, one task at a time: the enrichment dispatcher |
| celery-beat | — | Scheduler for the 67 jobs in `JOB_REGISTRY` (`backend/app/workers/job_registry.py`) |
| telegram-listener | — | Long-running Telegram client |
| meilisearch | 7700 | Full-text search |
| libretranslate | 5050 | Article translation |
| piper | 5060 | Read-aloud speech |
| frontend (Vite) | 3001 | The React web app |

See [operations.md](operations.md) for production.

---

## 2. Entry Lifecycle: From Feed to Intelligence

An *entry* is one article or post. Stages 1 to 5 run inside the `fetch_feed` task. Stage 6 hands the entry to a chain of Celery tasks. [entries.md](entries.md) covers this in more depth.

### Stage 1: Feed Polling

Celery Beat runs `poll_due_feeds` every 60 seconds. It picks up to 50 active feeds that are due, oldest fetch first. A feed is due when `fetch_interval_minutes` has passed since its last fetch. After a failed fetch the wait doubles each time, up to 24 hours. When per-user subscriptions are on, a feed that every subscriber has paused is skipped.

Each feed gets a Redis lock (`feed_fetch:{id}`, 10 minutes) so two workers never fetch it at once.

### Stage 2: Feed Fetch

`fetch_feed(feed_id)` calls the adapter for the feed's `feed_type` (`backend/app/adapters/`):

| Feed type | How it fetches |
|-----------|-----------|
| `rss`, `atom` | HTTP GET with `If-None-Match` / `If-Modified-Since` |
| `youtube` | Channel RSS, with an option to skip Shorts |
| `podcast` | RSS with audio enclosures |
| `reddit` | Reddit API |
| `github_releases`, `github_advisories`, `github_repo` | GitHub API: releases, security advisories, or files and commits in a repo |
| `nvd` | NVD API 2.0 |
| `mastodon` | Mastodon API |
| `bluesky` | AT Protocol: a user's posts, a custom feed, or a search |
| `telegram` | Channel messages, via the separate `telegram-listener` service |
| `web_scraper` | Fetches a page and pulls out the article, for sites without RSS |

Results:
- **304 Not Modified:** update `last_fetched_at` and stop.
- **4xx/5xx:** count the error, record it, retry up to 3 times.
- **200 OK:** parse into entries.

See [adapters.md](adapters.md).

### Stage 3: Deduplication

For each parsed item:

1. **Title filter.** Drop it if the title contains one of the feed's `exclude_title_patterns` (plain phrases, any case).
2. **GUID check.** Skip it if this feed already has an entry with the same `guid`.
3. **Shorts filter.** Skip YouTube Shorts if the feed has `exclude_shorts` on.
4. **Content hash.** A SHA-256 of the text is stored to spot the same article across feeds.

### Stage 4: Content Processing

1. **Full text.** If the feed gave less than 500 characters (a summary), fetch the full article from its URL.
2. **Clean HTML.** `sanitize_html()` removes scripts, iframes and event handlers. Images are loaded through the image proxy.
3. **Lead image.** First image in the content, then the summary, then the page's `og:image`.
4. **Media.** For podcasts and YouTube, save an `EntryMedia` row and fetch a transcript when one exists.

### Stage 5: Persistence

The entry is saved, then added to the Meilisearch index. If indexing fails, the ID is queued and retried later. A `feed_fetched` live event (Server-Sent Events) tells open browsers that new entries arrived. The full list of entry fields is in [data-model.md](data-model.md).

### Stage 6: Task Fan-out

For each new entry, `dispatch_entry_pipeline()` (`backend/app/workers/feed_tasks.py`) builds a Celery *chord*: a group of tasks that run in parallel, then a callback that runs once they all finish. The stages are listed as data in `backend/app/pipeline/registry.py`, each with a kind:

| Kind | Stages | When it runs |
|------|--------|------|
| `inline` | sanitize, dedup, relevance, index | Inside the fetch task (stages 3 to 5) |
| `pre` | translate | Before the chord, for feeds with auto-translate, so later stages see the translated text |
| `parallel` | autolink, observables, telegram_links, extract | Together, as the chord's first group. `extract` is off unless the feed turns it on |
| `post` | cooccurrence, correlation, requirements | Together, after the parallel group |
| `final` | score | Last. Scores the entry and queues its one-pass AI analysis |
| `post_analysis` | adjudicate | After the AI analysis is saved, minutes to hours later, on the `ai` queue |
| `side` | automate, enrich | Outside the chord. Automation is started by the fetch task; enrichment when a new entity is created |

With pipeline plans on (`pipeline_engine_enabled`), `PipelinePlan` rows can turn stages on or off per feed, per category, or globally. See the [entry pipeline diagram](diagrams/architecture-entry-pipeline.md) and [engine.md](engine.md).

The chord makes sure relationship and correlation work starts only when linking and extraction have finished, however long they take.

### Stages 7-12

Autolinking, extraction, enrichment, correlation, automation and requirements each have their own section below.

---

## 3. Entity Types and Data Models

An *entity* is a thing IntelFeed tracks across articles. The full list of entity types is in `backend/app/entity_types.py`. Every layer (API, database, search, AI) uses those names. There are **13**:

| Slug | Model / table | Unique on | Notes |
|---|---|---|---|
| `threat_actor` | `ThreatActor` / `threat_actors` | `name` | Groups behind attacks |
| `malware` | `MalwareFamily` / `malware_families` | `name` | The one slug that differs from its table name |
| `tool` | `Tool` / `tools` | `name` | Dual-use and red-team tools, such as Mimikatz |
| `cve` | `CVE` / `cves` | `cve_id` | Vulnerabilities |
| `cwe` | `CWE` / `cwes` | `cwe_id` | Weakness types |
| `ttp` | `TTP` / `ttps` | `technique_id` | ATT&CK techniques |
| `mitigation` | `Mitigation` / `mitigations` | `mitre_id` | ATT&CK mitigations, linked to TTPs |
| `vendor` | `Vendor` / `vendors` | `name` | Companies that make products |
| `product` | `Product` / `products` | `name` | Each belongs to a vendor |
| `country` | `Country` / `countries` | `name` | Seeded list |
| `sector` | `Sector` / `sectors` | `slug` | Seeded list of industries |
| `observable` | `Observable` / `observables` | `(kind, value)` | Indicators of compromise (IOCs). See [observables.md](observables.md) |
| `ransomware_victim` | `RansomwareVictim` | — | From leak-site tracking (`/api/ransomware`); not linked to entries |

Twelve of them (all but `ransomware_victim`) link to entries and can be pivoted. Ten are found by the autolinker (all but `observable`, `sector` and `ransomware_victim`). Campaigns, detection rules, intelligence requirements and story threads are other kinds of object, not entity types.

Field-by-field tables for every model are in [data-model.md](data-model.md).

### Field-Value Vocabularies

A few entity fields only accept values from a fixed list, because search uses them as filters:

| Module | Column(s) | Values |
|---|---|---|
| `intelligence/tactics.py` | `DetectionRule.mitre_tactics`, `TTP.tactic` | ATT&CK tactic slugs (`defense-evasion`) |
| `intelligence/platforms.py` | `Tool.platforms` | ATT&CK platform labels (`Windows`, `IaaS`) |
| `intelligence/sectors.py` | `sectors` table, `EntrySector.sector`, `*.targeted_sectors` | slug + label (`critical-infrastructure` / `Critical Infrastructure`) |
| `intelligence/actor_attributes.py` | `ThreatActor.motivation`, `.country` | five motivations; country names from the countries table |

The model enforces each list with a SQLAlchemy `@validates` hook, because many code paths write these columns. The hook fixes spelling and case but keeps unknown values, so a new ATT&CK release still works. Only placeholders such as `Unknown` are dropped. The AI prompts carry the same lists as JSON-Schema `enum`s, so the AI cannot invent a value.

### Junction Table Pattern

A *junction table* links entries to one entity type, such as `EntryThreatActor`. They all share these columns:

| Column | Meaning |
|---|---|
| `entry_id`, `{entity}_id` | The two sides (composite primary key) |
| `confidence` | `high`, `medium` or `low` |
| `source` | How it was found, such as `auto_link`, `regex` or `ai` |
| `matched_names` | The words in the text that matched |
| `extracted_at` | When |
| `paragraph_indices` | Which paragraphs mention the entity |

`paragraph_indices` powers proximity scoring: two entities in the same paragraph are more strongly related than two far apart.

Some types have extra links: `ThreatActorTargetCountry` (countries an actor targets), `TTPMitigation` (mitigations for a technique), and a `role` on `EntryCountry` (`origin`, `target`, `infrastructure` or `mentioned`).

### Main data sources per type

| Type | Comes from |
|---|---|
| Threat actor | Autolinker, AI analysis, MITRE ATT&CK sync, analysts (MISP Galaxy supplies reference aliases) |
| Malware | Autolinker, AI analysis, Malpedia sync |
| CVE | Pattern match, NVD, EPSS, CISA KEV, GitHub PoC search, AI analysis |
| TTP / mitigation | Pattern match, MITRE ATT&CK sync, AI analysis |
| Country / sector | Seed scripts (`scripts/seed/`), autolinker, AI analysis |

### Campaigns and detection rules

- **Campaign:** a collection an analyst builds for an investigation. It has a status, a TLP marking (default `TLP:GREEN`), dates and tags. `CampaignEntry` links articles, `CampaignEntity` links entities with a role (`primary`, `secondary`, `related`), and `CampaignCountry` holds geographic scope.
- **Detection rule:** a rule (`DetectionRule`) with a `rule_type`, its content, severity, tags, ATT&CK tactics and log sources. It usually links to the article it came from. Every edit is saved in `DetectionRuleVersion`, so you can compare and roll back.

---

## 4. The Autolinker: Aho-Corasick Entity Recognition

The autolinker finds known entity names in each article. It uses Aho-Corasick, an algorithm that searches for thousands of names in one pass over the text. Code: `backend/app/intelligence/autolinker.py`. Details: [intelligence-engine.md](intelligence-engine.md).

### How the Vocabulary is Built

The autolinker loads every entity name and alias into one search structure (via `pyahocorasick`). Each entry remembers its entity type, its canonical name, and whether it is an alias. For example, "Cozy Bear" points to APT29 as an alias.

The word list is rebuilt every 30 minutes (job `refresh-autolinker-vocabulary`). Its version is stored in Redis, so each worker rebuilds when the version changes.

### Ambiguity Detection

A short one-word name made only of letters, such as "Maze", is *ambiguous*: it could be an ordinary word. Such names must appear capitalised in the article to match. The length limit is `autolinker_ambiguous_name_max_length`.

### The Scanning Process

For each entry:

1. **Check the feed's mode.** `none` or `manual`: skip. `selective`: skip unless the keyword relevance score passes the threshold. `full`: scan.
2. **Split the text into paragraphs**, with the title and summary first.
3. **Dictionary scan.** Find every name, check word boundaries, apply the capital-letter rule to ambiguous names, and skip names repeated too often.
4. **Pattern scan.** Regex finds `CVE-YYYY-NNNN`, `CWE-N` and ATT&CK IDs (`T1234`, `T1234.001`).
5. **Store** with `store_autolink_matches()`. This writes the junction rows (ignoring ones that exist) and updates each entity's article count and last-seen date.

**Pending tier.** When `autolink_pending_tier_enabled` and `ai_one_pass_enabled` are both on, a match on an ordinary dictionary word is held as a `PendingAutolinkMatch`. The AI analysis then confirms or rejects it.

### Confidence Weighting

A canonical-name match starts as `high` (0.9), an alias as `medium` (0.5). That number is multiplied by the feed's reliability weight: 0.7 or more is `high`, 0.4 or more is `medium`, the rest is `low`.

| Feed rating | Weight | high becomes | medium becomes |
|--------|--------|------|------|
| A | 1.0 | high | medium |
| B | 0.85 | high | medium |
| C | 0.7 | medium | low |
| D | 0.5 | medium | low |
| E | 0.3 | low | low |
| F | 0.15 | low | low |

Unrated feeds use 0.5 (`reliability_to_weight()` in `autolinker.py`).

### False Positive Filtering

Settings (see [engine-settings.md](engine-settings.md#autolink-stage)):
- `autolinker_false_positive_names`: names never matched for actors, malware and countries.
- `autolinker_blocked_surface_forms`: words an analyst blocked, for every type.
- `autolinker_min_name_length` (default 3), `autolinker_ambiguous_name_max_length`, `autolinker_ambiguous_max_occurrences`.

**Junk aliases.** `is_junk_alias()` and `filter_aliases()` drop bad aliases (too short, on the blocklist, or shaped like a file name) when the word list is built and when aliases are saved. One bad alias can't link thousands of articles.

**Reclassify tombstones.** When an entity is moved to another type (say a "malware" that is really a tool), an `EntityReclassifyTombstone` row stops it being created again under the old type.

---

## 5. Intelligence Extraction Pipeline

Two things pull intelligence out of an article beyond autolinking:

1. **The extract stage** (`extract_entry_intel_task`). Pattern matching only, no AI. It runs when the feed has `auto_extract_on_ingest` or `extract_detection_rules` on.
   - **TTPs:** ATT&CK IDs, checked against the imported ATT&CK catalog. Unknown IDs are dropped, revoked ones are mapped to their replacement, and ICS techniques are kept only when the article is about ICS/OT.
   - **CVEs:** `CVE-` IDs. A new CVE is looked up in NVD; a known one just gets linked.
   - **Mitigations:** ATT&CK mitigation IDs.
   - **Detection rules:** see below.
2. **The one-pass AI analysis** (`entry_analysis`). After scoring, each article gets one AI call that extracts actors, malware, tools, TTPs, relationships and observables together, and confirms held autolink matches. A second AI call, the adjudicate stage, then reviews what it wrote. See [engine.md](engine.md) and [automation-ai-enrichment.md](automation-ai-enrichment.md).

### Detection Rule Extraction

When `feed.extract_detection_rules` is on, the article is scanned for rules (`backend/app/intelligence/rule_extraction.py`):

| Format | How it is found |
|--------|-----------------|
| Sigma | YAML with a `detection:` key |
| Splunk SPL | A code block |
| KQL | A Defender or Sentinel query in a code block |
| Elastic QL | EQL or ES\|QL in a code block, or an Elastic TOML rule |
| YARA | `rule name { ... condition: ... }` |
| Snort/Suricata | Alert rule lines (stored as `snort_suricata`) |

Query languages (SPL, KQL, EQL, ES|QL) come only from code blocks. Each rule is checked with `validate_rule()` before it is saved. See [detection-engineering.md](detection-engineering.md).

### GitHub Entry Special Handling

Entries from GitHub rule repositories carry a `content_type` (such as `sigma_rule`). They skip normal extraction and go to `process_github_entry()`, which imports the rule directly.

---

## 6. Enrichment Pipeline

Enrichment adds facts from outside sources to an entity.

### Automatic Enrichment

When a **new** entity is created, `enqueue()` (`backend/app/enrichment/queue.py`) adds an `enrichment_jobs` row for each enabled `EnrichmentSource` set to `auto` that handles the entity type. Every 30 seconds `dispatch_enrichment_jobs`, on its own `enrichment` queue and worker, runs the due rows: each one through its source's adapter, with the results saved on the entity. A source that says "not now" (rate limit, open breaker, budget used up) gets the row back with a later `due_at`, so the lookup waits instead of being lost. See [automation-ai-enrichment.md](automation-ai-enrichment.md#enrichment-job-queue).

Adapters (`backend/app/enrichment/adapters/`): NVD, EPSS, CISA KEV, MITRE ATT&CK, Malpedia, GitHub PoC, Wikipedia, CVEDetails, OSV, VulnCheck, and for observables VirusTotal, GreyNoise and Shodan InternetDB. Each one, and each scheduled enrichment job, makes its HTTP requests through a `SourceGateway` (`backend/app/enrichment/gateway.py`), which applies the source's rate limit, daily budget and circuit breaker to every request and refuses to send when Redis is down. See [automation-ai-enrichment.md](automation-ai-enrichment.md#source-gateway).

### Scheduled Enrichment

Some of the beat jobs that keep entities current (times UTC):

| Schedule | Job | What it does |
|----------|------|-------------|
| Every 6 hours | `sync-kev-feed` | CISA Known Exploited Vulnerabilities list |
| Daily 06:30 | `epss-bulk-sync` | EPSS scores for all CVEs |
| Daily 05:00 | `github-poc-scan` | Public exploit code on GitHub |
| Sundays 03:00 | `mitre-attack-sync` | Full ATT&CK import |
| Sundays 03:30 | `misp-galaxy-sync` | Reference aliases for threat actors |
| Saturdays 01:00 | `malpedia-sync` | Malware names, aliases, descriptions |

The full list is in [workers-search-dashboards.md](workers-search-dashboards.md).

### Enrichment Sources

Each `EnrichmentSource` row is one source's settings: on or off, a `trigger_mode` (`auto` or `manual`), an API key, a rate limit and a daily budget, and health fields (`health_status`, `last_synced_at`). What a source applies to, needs, may send and writes, and its scheduled jobs, are declared on its class (`backend/app/enrichment/manifest.py`). Manage them on Settings → Engine → Enrichment.

---

## 7. Correlation Engine

The correlation engine (`backend/app/intelligence/correlation.py`) connects entities that appear in the same articles.

### Entity Configuration

`ENTITY_CONFIG` maps each of the 12 entity types that link to entries to its model, junction table and key: `ttp`, `cve`, `cwe`, `threat_actor`, `malware`, `country`, `mitigation`, `tool`, `vendor`, `product`, `observable`, `sector`.

You can also pivot *from* a campaign (`PIVOT_SOURCE_TYPES`), but a campaign never shows up as a related entity, because it is a hand-picked list, not something found in articles.

### Pivot Queries

`pivot_from_entity(db, entity_type, entity_id)` answers "what is related to this?":

1. Find every entry linked to the entity.
2. Find every other entity linked to those entries.
3. Score each one's **strength** from corroboration (how many separate articles, weighted by feed reliability), closeness (proximity) and recency, and give it a tier.
4. Sort by strength. `sort` also accepts `recent` and `articles`.

Observables are an exception: they appear as related only through confirmed relationships, not plain co-mentions.

### Proximity Scoring

```text
proximity_score = 1.0 / (1 + decay_rate × min_distance)
```

`min_distance` is the smallest paragraph gap between the two entities. Same paragraph: 1.0. Three paragraphs apart with a decay rate of 1.0: 0.25. With no paragraph data, the score is 0.3. Both numbers are settings.

### Entity Graph

`build_entity_graph(db, entity_type, entity_id)` returns nodes and edges for the graph view. Results are cached in Redis for `correlation_cache_ttl_seconds` (default one hour).

### Correlation Events

A *correlation event* is a notable finding, such as a new technique for a known actor. `detect_correlation_events` runs the checks in `backend/app/intelligence/correlation_events.py`. Severity is fixed per type (`EVENT_SEVERITY`):

| Severity | Event type | Meaning |
|----------|-----------|---------|
| high | `coverage_gap` | A TTP or CVE with no detection rule |
| high | `exploit_status_change` | A CVE's exploit status got worse |
| high | `kev_addition` | A CVE was added to CISA KEV |
| high | `new_exploit_discovered` | First public exploit for a known CVE |
| high | `cve_score_change` | CVSS or EPSS crossed a tier |
| medium | `trending_entity` | An entity mentioned unusually often in 24 hours |
| medium | `campaign_match` | An article matches a campaign |
| medium | `requirement_match` | An article meets an intelligence requirement |
| medium | `new_ttp_for_known_actor` | A new technique for a tracked actor |
| medium | `new_ttp_for_known_malware` | A new technique for tracked malware |
| medium | `new_malware_for_known_actor` | New malware for a tracked actor |
| medium | `feed_error` | A feed keeps failing |
| low | `feed_stale` | A feed has gone quiet |
| low | `actor_malware_cooccurrence` | An actor and malware mentioned together |
| low | `new_intel_for_rule` | New intelligence relevant to an existing rule |

### Typed Relationships and Co-occurrence

`EntityRelationship` (`backend/app/models/entity_relationship.py`) is a directed link between two entities:

- `relationship_type`: a verb such as `uses`, `exploits`, `targets`, `attributed_to`, `delivers` or `variant_of`. Allowed (source type, verb, target type) combinations are listed in `backend/app/intelligence/relationship_matrix.py`, and every write is checked against it.
- `confidence`: `confirmed`, `probable` or `possible`.
- `source`: `co_occurrence`, `auto_extracted`, `analyst_confirmed`, `analyst_created`, `analyst_rejected` or `external_feed`.
- `evidence_entry_ids`: the articles that support it.

`create_cooccurrence_relationships(entry_id)` builds links from articles:

- For each pair of different-type entities in an article, it scores proximity and picks a verb and direction (for example actor → malware is `uses`). A pair with no known verb gets `related_to` only when the mentions are very close.
- An existing link gains the article as evidence. A `co_occurrence` link moves from `possible` to `probable` after one very close mention or `relationship_evidence_promote_count` separate articles.
- A link an analyst rejected is never recreated.

Analysts confirm, reject and create links in the relationship browser (`backend/app/api/entity_relationships.py`). See the [relationship lifecycle diagram](diagrams/entity-relationship-lifecycle.md).

---

## 8. Detection Engineering

IntelFeed stores and validates rules in 9 formats:

| Format | Used for |
|--------|----------|
| Sigma | Vendor-neutral rules (YAML) |
| Splunk SPL | Splunk searches |
| CrowdStrike QL | CrowdStrike Falcon queries |
| Elastic QL | EQL and ES\|QL |
| KQL | Microsoft Defender and Sentinel queries |
| YARA | File and memory patterns |
| Snort/Suricata | Network rules |
| Nuclei | Web vulnerability templates |
| Panther | Panther detections |

Six of them can be pulled out of articles (section 5). CrowdStrike QL, Nuclei and Panther can be validated but not extracted.

### Rule Lifecycle

1. **Collect:** from articles, GitHub rule repositories, or by hand.
2. **Validate:** a syntax check per format (`rule_validation.py`).
3. **Check feasibility:** can you run it with the logs you have? (`POST /api/telemetry-sources/check-feasibility`, against your `TelemetrySource` records).
4. **Store:** a `DetectionRule`, usually linked to its source article.
5. **Version:** every edit is saved in `DetectionRuleVersion`.

### Detection Gap Analysis

For campaigns and entities, IntelFeed lists the TTPs and CVEs that have no rule. The ATT&CK matrix (`/api/attack/matrix`, `backend/app/api/attack.py`) shows rule counts and recent mentions per technique. Coverage takes your configured telemetry into account, not just whether a rule exists. Gaps also raise `coverage_gap` correlation events. See [detection-engineering.md](detection-engineering.md).

---

## 9. Campaigns

A campaign gathers the articles and entities for one investigation.

### Campaign Structure

- **Entries:** source articles (`CampaignEntry`).
- **Entities:** actors, malware, CVEs, TTPs, vendors and products, each with a role: `primary`, `secondary` or `related`.
- **Countries:** where it comes from and whom it targets (`CampaignCountry`).
- **Saved searches** attached to the campaign.
- **TLP marking:** how widely it may be shared.

### Campaign Profile Tabs

A campaign opens at `/workbench/campaign/:id` on the same profile page as entities. Its tabs are Overview, Relationships and Detection. Campaigns support AI-suggested entities and detection gap analysis.

---

## 10. Automation Engine

Automation rules (`AutomationRule`) run actions when something happens. See [automation-ai-enrichment.md](automation-ai-enrichment.md).

### Entry Automation

The fetch task calls `run_entry_automations(entry_id, feed_id)` for each new entry. It evaluates rules with trigger `on_new_entry` (and the keyword and CVE triggers) against the feed, keywords, entities and other conditions.

All triggers (`VALID_TRIGGER_TYPES`, `backend/app/schemas/automation.py`): `on_new_entry`, `on_schedule`, `on_keyword_match`, `on_cve_detected`, `on_manual`, `on_correlation_event`, `on_entry_scored`, `on_observable_captured`.

Actions (`VALID_ACTION_TYPES`):
- Add or remove tags; star, bookmark, hide, mark read or mark priority.
- Create a note.
- Call a webhook (saved presets live at `/api/webhook-presets`) or send a notification.
- Run an AI task, or use the daily summary.
- Extract TTPs, CVEs, actors or malware; generate detection rules.
- Add to a campaign, create a report, export, chain another rule, or branch.

### Correlation Automation

When correlation events are created, `run_automations_for_correlation_event()` runs rules with the `on_correlation_event` trigger.

### Intelligence Requirements

An intelligence requirement (PIR, Priority Intelligence Requirement) is a standing question your team wants answered. `match_entry_against_requirements(entry_id)` checks each active one:
- It matches on keywords **or** on the requirement's linked entities. An article that links to a listed entity matches even with no keyword hit.
- Each match is saved as a `RequirementMatch` (`match_type`: keyword, entity or manual) and raises a `requirement_match` event.

---

## 11. Frontend Architecture

The web app is React with TypeScript, built with Vite. [frontend.md](frontend.md) covers it fully; this is the summary.

### Three-Panel Layout (MainLayout)

The reader has three panels:

```text
┌─────────┬──────────────┬──────────────┐
│ Sidebar │  Entry list  │   Reader     │
│ Feeds   │ Virtualized  │ Article      │
│ Folders │ scroll       │ + side panels│
│ Tags    │ Intel badges │ + entities   │
└─────────┴──────────────┴──────────────┘
```

- **Sidebar:** feeds, categories, folders, saved searches. A switch at the top changes it to the Workbench menu.
- **Entry list:** `EntryList`, which only renders the rows on screen (`@tanstack/react-virtual`). Each row shows entity counts from `EntryIntelBadges`.
- **Reader:** `EntryReader` shows the cleaned article with entities highlighted (`InlineEntityHighlighter`) and side panels for intel, AI, notes and tags.

Tool pages (Workbench, Settings, Search, Automation) use `SidebarLayout` instead.

### State Management

- **Server data** uses TanStack Query (`staleTime` 30 s, one retry, no refetch on window focus). The entry list loads one page at a time with cursor paging (50 by default; Settings → Reading offers 25, 50 or 100).
- **Browser state** uses Zustand stores in `frontend/src/stores/`. `authStore`, `uiStore`, `intelStore`, `playerStore` and `triageViewStore` are saved to localStorage; `dialogStore` and `externalLinkStore` are not. Table column layouts and the triage view are also saved to the user's server profile, so they follow the user between devices.

### Inline Entity Highlighting

`InlineEntityHighlighter` marks known entities in the article. Hovering shows a quick profile (`EntityPopover`); clicking opens the profile. You can also select text to create or link an entity.

### AI Copilot Dock

`CopilotDockPanel` is a chat panel, mounted in `App.tsx` for signed-in users (`Cmd/Ctrl+Shift+K`). It talks to `/api/ai/copilot`, which streams answers and can look things up in IntelFeed with read-only tools. Two actions, create campaign and add note, run only after you confirm them. Conversations can be shared read-only at `/shared/copilot/:token`. Each turn is recorded as an `AIResult` with its token use, so it shows in the AI cost view. See [copilot.md](copilot.md).

---

## 12. Dashboard and Priority Queue

The **Dashboard** (`/workbench/dashboard`, `frontend/src/pages/DashboardPage.tsx`) is the Workbench home page and shows what is happening now. `/workbench`, `/triage`, `/dashboards` and `/atlas` all go there. The entity browser is at `/workbench/explore`.

The **Priority Queue** (`/priority-queue`) is the reader layout in `priorityMode`: the entry list sorted by score (`radar`), with story threads folded in as single rows, and a card in the reader explaining why the article ranked (`WhyRankedCard.tsx`). The server builds the ranking (`GET /api/entries/priority-queue`, `build_priority_queue`, `backend/app/api/entries.py:1431`). It is linked from a chip under the unread count in the sidebar.

**Daily summaries** are AI recaps of each day, shown on the day dividers in the entry list and shared by all users. The `generate-daily-summaries` job (daily 06:00 UTC, `backend/app/workers/daily_summary_tasks.py`) writes yesterday's summary ahead of time.

### Telegram Mentions

`TelegramMentionsPanel` and `TelegramMentionsWidget` show activity from Telegram. The `TelegramMention` model stores channel and user mentions and forwards. The `build-telegram-forward-relationships` job (`build_telegram_forward_relationships` in `intel_feed_tasks.py`) turns forwards between channels into `communicates_with` relationships.

---

## 13. Widgets and Dashboards

Dashboard widgets live in `frontend/src/components/widgets/` and are listed in `registry.ts` (51 widget types, 5 of them hidden from the picker but still shown on boards that have them). Each entry has a type ID, label, description, default size, component and optional settings fields. `WidgetRenderer` draws a widget by type; `WidgetPicker` adds one. Widgets get data from hooks such as `useWidgetData.ts`, `useAnalytics.ts` and `useCorrelation.ts`. The board is a `react-grid-layout` grid.

Some examples:

| Family | Examples |
|--------|----------|
| Operations | `CorrelationEventsWidget`, `FeedHealthWidget`, `WorkerQueueWidget`, `AutomationLogsWidget` |
| Intelligence | `NewActorsWidget`, `TrendingEntitiesWidget`, `VendorsTrendingWidget`, `RansomwarePulseWidget` |
| Detection | `DetectionCoverageWidget`, `AttackHeatmap`, `KEVMatchesWidget`, `TelemetryGapsWidget` |
| Summary | `MorningBriefingWidget`, `WeeklyRecapWidget`, `OverviewWidget`, `IntelVelocityWidget` |

**The grid starts locked.** `uiStore.dashboardLocked` (default on, saved per device, toggled from the toolbar) turns off drag and resize. You can still add, configure and remove widgets. The lock matters most on phones: below 768 px the grid has one column, and dragging there would save a one-column layout over the desktop one. Visitors in public read-only mode always see a locked grid.

**Each user has their own boards.** `/api/dashboards` only lists and changes your own. A user with no boards gets the five default tabs in `backend/app/dashboard_defaults.py` through `POST /api/dashboards/seed-defaults`, which the Dashboard calls once. Seeding never touches a user who already has a board. To change the defaults, capture boards from a curated instance with `GET /api/dashboards` and update that module.

---

## 14. Entity Profile Pages

Every entity type, and campaigns, use one page: `frontend/src/pages/EntityProfilePage.tsx`. What each type shows (fields, stats, tabs, actions) is set in `frontend/src/components/entityProfile/entityProfileConfig.tsx`. Shared parts live in `components/entityProfile/`, with tab bodies in `tabs/`. See [entity-profiles.md](entity-profiles.md).

### Routing

Profiles open at `/workbench/{type}/{id}`, for `threat_actor`, `malware`, `cve`, `cwe`, `ttp`, `country`, `sector`, `tool`, `mitigation`, `observable`, `vendor`, `product` and `campaign`. The ID can be a UUID or a natural key such as `T1490` or a CVE ID. Rules open at `/workbench/rule/:id` and reports at `/workbench/report/:id` or `/workbench/report/new`.

### Common Profile Structure

1. **Header:** name, type, key IDs, article count, first and last seen.
2. **Fields:** type-specific, edited in place.
3. **Description:** editable text, often an AI-written summary.
4. **Related entities:** from `usePivot`, with strength tiers.
5. **Entity graph:** `EntityGraph`, a custom SVG drawing with its own layout code (`entityGraphLayout.ts`).
6. **Tabs**, set per type in `entityProfileConfig.tsx`:
   - **Overview:** activity, assessment, recent developments (`/api/engine/entities/{type}/{id}/whats-new`), AI analysis and notes.
   - **Relationships:** confirm, reject and create links (`RelationshipsTab`).
   - **Detection:** rules and coverage. A **Detection Gaps** tab opens from the profile's "Review gaps" action.
   - **Vulnerabilities:** CWE, vendor and product profiles; the CVEs involved.
   - **Weaknesses:** CVE profiles; the CWEs behind the CVE.
   - **Geography:** country profiles.
   - **Victimology:** sector profiles.

### Workbench Page

The Workbench menu (`WorkbenchNav.tsx`) shows in the app sidebar in Workbench mode:

- **Top:** Dashboard, Reports.
- **Detection:** ATT&CK Matrix, Rules Library, Telemetry Sources, Threats (`/workbench/threats`).
- **Entities:** Campaigns, Countries, CVEs, Malware, Mitigations, Observables, Products, Sectors, Threat Actors, Tools, TTPs, Vendors, Weaknesses.
- **Intelligence:** Glossary, Ransomware, Requirements, Telegram Mentions, Watchlist.

The entity tables support search, column choice, duplicate merge and bulk actions. `/workbench/rules` opens the rules section of the explorer.

---

## 15. API Layer

Every route is under `/api`. Interactive docs are served at `/docs`. [api-reference.md](api-reference.md) has the full list.

### Key Endpoint Groups

**Entries** (`/api/entries`):
- `GET /api/entries`: list with filters, cursor paging.
- `GET /api/entries/{id}`: one entry.
- `GET /api/entries/triage`: entries ranked for triage.
- `GET /api/entries/priority-queue`: the Priority Queue.
- `POST /api/entries/intel-counts`: entity counts for up to 100 entries at once.

**On-demand extraction** (intelligence router, mounted at `/api`): `POST /api/entries/{id}/extract-ttps`, and the same for `extract-cves`, `extract-threat-actors`, `extract-malware`, `extract-countries`, `extract-sectors`, `extract-mitigations`, `extract-tools` and `extract-detection-rules`.

**Correlation** (`/api/intelligence`):
- `GET /pivot/{entity_type}/{entity_id}`: related entities.
- `GET /graph/{entity_type}/{entity_id}`: entity graph.
- `GET /timeline/{entity_type}/{entity_id}`: timeline.
- `POST /detection-summary`: detection coverage summary.
- Correlation events for widgets: `GET /api/widgets/correlation-events`.

**Entities** (`/api/entities`): create, edit and delete for all types, merge duplicates, move to another type, manage aliases.

**Entity relationships** (`/api/entity-relationships`): list, confirm, reject and create links.

**Entity links** (`/api/entity-links`): entry-to-entity links across all junction tables: list, stats, unlink, bulk unlink. Used by the Engine console.

**Engine** (`/api/engine`): stages and run counts, per-entry runs and retries, signal stats and settings, pipeline plans, job runs, Radar votes. `/api/engine/extraction` manages AI-created entities.

**Detection rules** (`/api/detection-rules`): create, edit, validate (`POST /validate`), convert, version history (`/{id}/versions`) and rollback (`/{id}/versions/{version_id}/rollback`). Feasibility is `POST /api/telemetry-sources/check-feasibility`.

**Other groups:** `/api/ransomware` (leak-site victims), `/api/threads` (story threads), `/api/threat-board`, `/api/ai/copilot`, `/api/documentation` (serves `docs/` to the in-app docs page; each page's title is its first heading and its section is its folder, so a new doc needs no code change), `/api/export` (Markdown for entries, notes and entities; ZIP bundles with Markdown, CSV and an ATT&CK Navigator layer).

### Common Patterns

- **Auth:** JWT tokens, checked by the `get_current_user` dependency. Admin routes use `get_admin_user`. Routes that visitors may read in public read-only mode use `get_viewer` (see [public-read-only-mode.md](public-read-only-mode.md)).
- **Paging:** offset/limit or cursor tokens, in `PaginatedResponse[T]`.
- **Errors:** `AppError`, returned as `{code, message, details}`.
- **Caching:** pivots and graphs are cached in Redis for `correlation_cache_ttl_seconds`.
- **Middleware** (`backend/app/main.py`), outermost first: CORS, security headers, rate limiting, the visitor write lock, Prometheus metrics, audit logging, request logging. Security headers sit outside the rate limiter so every reply, even a 429, carries them.

---

## 16. Configuration and Settings

### Config Override Chain

A setting's value comes from the first of these that has one:
1. **`system_settings` table:** edited in the web UI. Engine settings are on Settings → Engine; the rest are on Settings → Users, System, Feeds & Export, and AI Configuration.
2. **`.env` or environment variables.**
3. **Defaults in `config.py`.**

`settings.get(key)` follows that order. 150 of the 201 settings can be edited in the UI; the other 51 are infrastructure and secrets. UI changes reach the API within about 5 seconds and each Celery task when it starts, with no restart.

**Every setting is listed in [engine-settings.md](engine-settings.md)** with its default and where to edit it.

### Key Configuration Areas

**Per-feed settings** (on the feed itself, not system settings):
- `intel_extraction_mode`: `full`, `selective`, `manual` or `none`. `manual` turns off autolinking; `none` takes the feed out of the intel system.
- `ai_analysis_enabled`: whether the one-pass AI reads the feed.
- `auto_extract_on_ingest`: run the extract stage (ID patterns and NVD lookups).
- `extract_detection_rules`: look for rules in articles.
- `reliability_rating`: A to F, used in confidence weighting.

The feed list shows these as a small fill bar (`frontend/src/components/IntelLevelBadge.tsx`): one third each for autolinking, AI analysis and NVD lookups.

**AI providers:** Ollama, Claude API, Claude Code CLI, and OpenAI-compatible endpoints (OpenAI, LM Studio, vLLM, llama.cpp, LiteLLM, OpenRouter, Groq). Each AI task is assigned a provider and model. Providers, prompts, task assignments and costs are on Settings → AI Configuration.

**Enrichment sources:** API keys, rate limits, trigger mode and health per source, on Settings → Engine → Enrichment.
