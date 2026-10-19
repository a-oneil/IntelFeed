# Entry Lifecycle

The end-to-end path of an entry: feed poll → fetch → dedup → content processing → persistence → pipeline dispatch → autolink/extraction → enrichment → correlation → automation → signal scoring and triage.

See diagram: [Entry lifecycle](diagrams/entries-lifecycle.md)

## Stage map

| Stage | Code | Notes |
|---|---|---|
| Polling | `backend/app/workers/feed_tasks.py` (`poll_due_feeds`) | Beat every 60s; due feeds LIMIT 50, oldest first; Redis NX lock `feed_fetch:{id}` TTL 10 min |
| Fetch | `feed_tasks.py` (`fetch_feed`, max_retries=3) | rss/atom/youtube/podcast via HTTP with ETag/Last-Modified (30s timeout); reddit, github_*, nvd, mastodon, web_scraper, bluesky, telegram via extended adapters |
| Dedup | `feed_tasks.py`, `backend/app/services/dedup.py` | Per-feed GUID check + intra-batch set, cross-feed `content_hash` (SHA-256 of normalized title + first 500 chars), YouTube Shorts filter |
| Content | `feed_tasks.py` | Full-article readability extraction when text < 500 chars or a truncation marker is present; `sanitize_html()` (nh3); lead-image priority chain; EntryMedia + YouTube transcripts; Telegram OCR |
| Persist | `feed_tasks.py`, `backend/app/search/` | Meilisearch indexing; one coalesced SSE `feed_fetched` event per fetch (feed_id, new_entries, entry_ids) |
| Dispatch | `dispatch_entry_pipeline` (`backend/app/workers/feed_tasks.py`); stage composition in `backend/app/pipeline/registry.py` | Celery chord: optional `translate_entry_task` prologue → parallel autolink / telegram-link-scan / conditional intel extraction → `entry_post_processing` → co-occurrence + correlation events + requirements → final `score_entry_task`. `run_entry_automations` and keyword alerts fire outside the chord |
| Autolink | `backend/app/intelligence/autolinker.py` | Modes none/manual/selective/full; Redis-versioned vocab (actors, malware, countries + aliases; vendors, products, tools, mitigations); FP filters (min length, FP-names CSV, `is_junk_alias()`, LOLBin/binary names); confidence = canonical/alias × feed reliability weight; dictionary-word (provisional) matches held in `pending_autolink_matches` for AI confirmation (pending tier) |
| Extraction | `backend/app/workers/intel_feed_tasks.py`, `backend/app/intelligence/rule_extraction.py` | GitHub `content_type` entries import rules directly; one-pass AI + regex for TTPs/CVEs/vendors/products; new CVEs fetched from NVD API 2.0; rule detection covers Sigma, Elastic TOML (elastic_ql/kql), YARA, Snort/Suricata, Splunk SPL |
| Enrichment | `backend/app/workers/job_registry.py` | Auto-enrich on new entities + beat schedule (below) |
| Correlation | `backend/app/intelligence/correlation_events.py` | Co-occurrence upserts strength-model `EntityRelationship` rows; 15 correlation event types (severity list in diagram) feed correlation automations |
| Automation | `backend/app/automation/` | Triggers: on_new_entry, on_keyword_match, on_cve_detected, on_correlation_event, on_schedule; condition + action catalog in diagram |
| Requirements | `backend/app/intelligence/requirement_matching.py` | `match_requirements_task` → `RequirementMatch` → `requirement_match` event |
| Signal & triage | `backend/app/services/triage.py` | `score_entry_task` writes `priority_score` + entry signals; triage queue ranks by composite priority; story threads rank alongside entries by the score of their best unread beat |
| Daily summaries | `backend/app/services/daily_briefing.py` | `ensure_daily_summary` — one shared, idempotent per-day summary with inline entity links; surfaces as reader day dividers, the Morning Briefing widget, and read-aloud. Called by the `generate_daily_summaries` job (daily 06:00 UTC) and by the `use_daily_summary` automation action, which share the cache row so a day is only ever generated once |

## Beat-scheduled enrichment

| Job | Schedule (UTC) |
|---|---|
| sync-kev-feed | every 6h |
| cve-nvd-refresh / cve-nvd-backfill | daily 12:00 / 01:30 |
| epss-bulk-sync | daily 06:30 |
| github-poc-scan | daily 05:00 |
| CyberGeist sync | daily 02:30 |
| mitre-attack-sync / malpedia-sync | weekly Sun 03:00 / 03:30 |
| metasploit-sync | weekly Sun 03:45 (CVE → Metasploit module, escalates `weaponized`) |
| rollup-targeted-sectors | daily 04:20 (entry_sectors → `threat_actor_target_sectors` / `malware_target_sectors` claim rows with article evidence; the `targeted_sectors` arrays are a cache rebuilt from them) |
| backfill-rule-data-sources | weekly Sun 04:50 (rule log sources → `data_sources` for telemetry coverage) |
| backfill-rule-attack-mappings | weekly Sun 05:30 (re-fetch GitHub-sourced rules for ATT&CK ids; derive tactics from techniques) |
| wikipedia-bulk-sync | weekly Wed 04:00 |
| build_telegram_forward_relationships | every 4h (forwarded_from metadata → `communicates_with` edges) |
