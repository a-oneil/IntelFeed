# Entry Lifecycle

An entry is one article, post, video or uploaded file. Its path: poll → fetch → dedup → clean → save → pipeline (autolink, extraction, correlation, scoring) → enrichment and automation. Below is the code for each step and the scheduled jobs that add data later.

See diagram: [Entry lifecycle](diagrams/entries-lifecycle.md)

## Stage map

| Stage | Code | What happens |
|---|---|---|
| Polling | `backend/app/workers/feed_tasks.py` (`poll_due_feeds`) | Every 60s, takes up to 50 due feeds, oldest first; erroring feeds wait longer. A Redis lock (`feed_fetch:{id}`, 10 min) blocks double fetches. |
| Fetch | `feed_tasks.py` (`fetch_feed`, `max_retries=3`) | `rss`, `atom`, `youtube` and `podcast` use HTTP with ETag / Last-Modified and a 30s timeout. Other types (`reddit`, `github_*`, `nvd`, `mastodon`, `web_scraper`, `bluesky`, `telegram`) use adapters in `backend/app/adapters/`. |
| Dedup | `feed_tasks.py`, `backend/app/services/dedup.py` | Skips titles matching `exclude_title_patterns`, known GUIDs, a `content_hash` stored from another feed (SHA-256 of normalized title + first 500 characters), and YouTube Shorts if the feed asks. |
| Content | `feed_tasks.py`, `backend/app/services/sanitizer.py` | Text under 500 characters or ending in "Continue reading" triggers a full-article fetch. `sanitize_html()` (nh3 allowlist) cleans HTML. Also picks a lead image, stores media and YouTube transcripts, OCRs Telegram images if enabled. |
| Save | `feed_tasks.py`, `backend/app/services/meilisearch_client.py` | Saves, indexes in Meilisearch, sends one `feed_fetched` SSE per fetch (`feed_id`, `new_entries`, `entry_ids`). |
| Dispatch | `dispatch_entry_pipeline` and `entry_post_processing` (`backend/app/workers/feed_tasks.py`); stages in `backend/app/pipeline/registry.py` | A Celery chord: (1) optional `translate_entry_task`; (2) in parallel: autolink, observables, Telegram link scan, extraction (if on for the feed); (3) `entry_post_processing` — co-occurrence, correlation events and requirement matching in parallel; (4) `score_entry_task`. `run_entry_automations` and keyword alerts run outside the chord. |
| Autolink | `backend/app/intelligence/autolinker.py` | Finds known entity names ([Autolinking](#autolinking)). |
| Observables | `backend/app/workers/intel_feed_tasks.py` (`observables_entry_task`) | Stages indicator-like strings as candidates and sights values already in the ledger. Never creates a ledger row. See [observables.md](observables.md). |
| Extraction | `backend/app/workers/intel_feed_tasks.py` (`extract_entry_intel_task`), `backend/app/intelligence/rule_extraction.py` | GitHub entries with a `content_type` (such as a Sigma file) import as rules. Otherwise regex finds ATT&CK technique, CVE and mitigation ids; new CVEs are looked up in NVD API 2.0. `extract_detection_rules` pulls Sigma, Elastic TOML (`elastic_ql` / `kql`), YARA, Snort/Suricata, and SPL / KQL / EQL / ES\|QL queries from code blocks. |
| One-pass AI analysis | `backend/app/services/entry_analysis.py` | Queued by scoring on the `ai` queue. One AI call returns entities, indicators, sectors and relationships, and confirms or rejects held autolinks; the adjudicate stage reviews its links. |
| Enrichment | `backend/app/workers/enrichment_tasks.py`, `backend/app/workers/job_registry.py` | New entities are enriched automatically; scheduled syncs add more (see [Scheduled enrichment](#beat-scheduled-enrichment)). |
| Correlation | `create_cooccurrence_relationships_task` (`intel_feed_tasks.py`), `backend/app/intelligence/correlation_events.py` | Co-occurrence adds or strengthens `entity_relationships` for entities named together. Fifteen stored event types (such as `kev_addition`, `new_ttp_for_known_actor`, `feed_stale`) can trigger automations. |
| Requirements | `match_requirements_task` (`intel_feed_tasks.py`), `backend/app/intelligence/requirement_matching.py` | Matches against intelligence requirements (PIRs), writes `requirement_matches`, raises a `requirement_match` event. |
| Scoring and triage | `score_entry_task` (`backend/app/workers/signal_tasks.py`), `backend/app/intelligence/signals.py`, `backend/app/services/triage.py` | Writes signals and `priority_score`, then queues AI analysis. Triage and the Priority Queue rank unread entries by score; story threads by their best unread article. |
| Automation | `backend/app/automation/` | Triggers: `on_new_entry`, `on_keyword_match`, `on_cve_detected`, `on_correlation_event`, `on_entry_scored`, `on_observable_captured`, `on_schedule`, `on_manual`. Conditions and actions are in the diagram. |
| Daily summaries | `backend/app/services/daily_briefing.py` | `ensure_daily_summary` writes one shared daily summary with entity links, shown in reader day dividers, the Morning Briefing widget and read-aloud audio. The `generate-daily-summaries` job (06:00 UTC) and `use_daily_summary` action share the cached row, so each day is generated once. |

### Autolinking

Scans title, summary and each paragraph with an Aho-Corasick dictionary (fast search for thousands of names at once).

- **When it runs** depends on `intel_extraction_mode`: `full` always, `selective` only for relevant articles, `manual` and `none` never.
- **What it knows:** actors, malware and countries with aliases, plus vendors, products, tools and mitigations; vocabulary versioned in Redis for all workers.
- **What it filters out:** names under a minimum length, known false-positive names, junk aliases (`is_junk_alias()`), and Windows binary names (LOLBins such as `.exe` and `.dll`).
- **Confidence:** exact canonical names score above aliases; both drop for feeds with weak reliability.
- **Dictionary words** like "Royal" or "Hive" wait in `pending_autolink_matches` until the one-pass AI confirms them.

## Beat-scheduled enrichment

UTC defaults from `backend/app/workers/job_registry.py`; admins can override.

| Job | Schedule (UTC) | What it does |
|---|---|---|
| `sync-kev-feed` | every 6h | CISA Known Exploited Vulnerabilities list |
| `cve-nvd-refresh` / `cve-nvd-backfill` | daily 12:00 / 01:30 | NVD CVE details |
| `resolve-cve-affected` | daily 03:35 | matches `cve_affected` CPE pairs to vendor and product entities |
| `epss-bulk-sync` | daily 06:30 | EPSS exploit-probability scores |
| `github-poc-scan` | daily 05:00 | public exploit code on GitHub |
| `sync-cybergeist-feeds` | daily 02:30 | CyberGeist entity attributes |
| `mitre-attack-sync` | weekly Sun 03:00 | ATT&CK techniques, groups, mitigations, aliases |
| `misp-galaxy-sync` / `malpedia-sync` | weekly Sun 03:30 | MISP Galaxy actor aliases; Malpedia descriptions and aliases |
| `metasploit-sync` | weekly Sun 03:45 | links CVEs to Metasploit modules, raises them to `weaponized` |
| `refresh-cwe-catalog` | weekly Mon 03:45 | MITRE CWE catalog |
| `rollup-targeted-sectors` | daily 04:20 | turns `entry_sectors` into `threat_actor_target_sectors` / `malware_target_sectors` claims with evidence, then rebuilds `targeted_sectors` |
| `backfill-rule-data-sources` | weekly Sun 04:50 | fills rule `data_sources` from log sources, for telemetry coverage |
| `backfill-rule-attack-mappings` | weekly Sun 05:30 | re-fetches GitHub rules for ATT&CK ids; derives tactics from techniques |
| `wikipedia-bulk-sync` | weekly Wed 04:00 | Wikipedia summaries |
| `build-telegram-forward-relationships` | every 4h | Telegram `forwarded_from` → `communicates_with` links |
| `scheduled-enrichment-check` | every 15 min | runs sources in `scheduled` trigger mode |
