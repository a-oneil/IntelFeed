"""Job schedule registry — all scheduled tasks with metadata and default schedules.

`settings_keys` lists the system settings that tune a job. The Jobs view renders
them inline on the job row, so a knob is reachable from the thing it controls
instead of only from whichever Engine panel happens to own its group. Every key
must exist in `CONFIGURABLE_KEYS` (guarded by tests/test_job_registry.py).
"""

from __future__ import annotations

import json
import logging
from typing import Any

import redis
from celery.schedules import crontab

from app.config import settings

logger = logging.getLogger(__name__)

REDIS_KEY = "intelfeed:job_schedule_overrides"

CATEGORY_LABELS = {
    "feeds": "Feed Polling",
    "intelligence": "Intelligence",
    "maintenance": "Maintenance",
    "enrichment": "Enrichment",
    "automation": "Automation",
    "saved_searches": "Saved Searches",
    "content": "Content Generation",
}

CATEGORY_ORDER = [
    "feeds",
    "intelligence",
    "enrichment",
    "maintenance",
    "automation",
    "saved_searches",
    "content",
]

JOB_REGISTRY: dict[str, dict[str, Any]] = {
    # --- Feed Polling ---
    "poll-feeds": {
        "settings_keys": [
            "default_feed_fetch_interval",
            "user_agent",
        ],
        "task": "app.workers.feed_tasks.poll_due_feeds",
        "description": "Check for feeds due for polling and dispatch fetch tasks",
        "category": "feeds",
        "default_schedule": {"type": "interval", "seconds": 60},
    },
    "check-feed-health": {
        "task": "app.workers.feed_tasks.check_feed_health",
        "description": "Detect stale feeds and persistent fetch errors; pause feeds dead on 4xx past the window",
        "category": "feeds",
        "settings_keys": ["feed_auto_pause_days"],
        "default_schedule": {"type": "crontab", "minute": "30", "hour": "*/6"},
    },
    # --- Intelligence ---
    "sync-kev-feed": {
        "task": "app.workers.intel_feed_tasks.sync_kev_feed",
        "description": "Sync CISA Known Exploited Vulnerabilities catalog",
        "category": "intelligence",
        "default_schedule": {"type": "crontab", "minute": "15", "hour": "*/6"},
    },
    "refresh-cwe-catalog": {
        "task": "app.workers.intel_feed_tasks.refresh_cwe_catalog",
        "description": "Re-pull the MITRE CWE catalog and re-resolve unmatched NVD weakness refs",
        "category": "intelligence",
        "default_schedule": {"type": "crontab", "minute": "45", "hour": "3", "day_of_week": "1"},
    },
    "sync-cybergeist-feeds": {
        "task": "app.workers.intel_feed_tasks.sync_cybergeist_feeds",
        "description": "Sync threat actor and malware feeds from Cybergeist",
        "category": "intelligence",
        "default_schedule": {"type": "crontab", "minute": "30", "hour": "2"},
    },
    "sync-ransomware-victims": {
        "task": "app.workers.intel_feed_tasks.sync_ransomware_victims",
        "description": "Collect ransomware leak-site victim postings",
        "category": "intelligence",
        "default_schedule": {"type": "interval", "seconds": 1800},
    },
    "refresh-autolinker-vocabulary": {
        "task": "app.workers.intel_feed_tasks.refresh_autolinker_vocabulary",
        "description": "Rebuild Aho-Corasick automaton for entity matching",
        "category": "intelligence",
        "default_schedule": {"type": "crontab", "minute": "*/30"},
    },
    "rebuild-entity-profiles": {
        "task": "app.workers.intel_feed_tasks.rebuild_entity_profiles",
        "description": "Reconstruct entity correlation profiles",
        "category": "intelligence",
        "default_schedule": {"type": "crontab", "minute": "30", "hour": "3"},
    },
    "archive-correlation-events": {
        "task": "app.workers.intel_feed_tasks.archive_correlation_events",
        "description": "Archive old and processed correlation events",
        "category": "intelligence",
        "default_schedule": {"type": "crontab", "minute": "45", "hour": "4"},
    },
    "check-requirement-expiry": {
        "task": "app.workers.intel_feed_tasks.check_requirement_expiry_task",
        "description": "Check intelligence requirements for expiry",
        "category": "intelligence",
        "default_schedule": {"type": "crontab", "minute": "30", "hour": "0"},
    },
    "build-telegram-forward-relationships": {
        "task": "app.workers.intel_feed_tasks.build_telegram_forward_relationships",
        "description": "Derive actor-to-actor 'communicates_with' edges from Telegram forwards",
        "category": "intelligence",
        "default_schedule": {"type": "crontab", "minute": "20", "hour": "*/4"},
    },
    "embed-entries": {
        "settings_keys": [
            "embeddings_enabled",
            "embedding_model",
            "embedding_base_url",
            "embedding_batch_size",
            "embedding_backfill_limit",
        ],
        "task": "app.workers.embedding_tasks.embed_pending_entries",
        "description": (
            "Embed entries that have no current vector, newest first. Feeds Story Threads and "
            "'find articles like this one'. No-op until Entry Embeddings is switched on."
        ),
        "category": "intelligence",
        # Frequent and cheap: an idle run is one indexed query. Threads are only
        # as fresh as the embeddings behind them.
        "default_schedule": {"type": "interval", "seconds": 900},
    },
    "story-threads": {
        "settings_keys": [
            "thread_window_days",
            "thread_dormancy_days",
            "thread_gap_days",
            "thread_min_body_chars",
            "thread_join_similarity",
            "thread_join_similarity_no_entity",
            "thread_seed_similarity",
            "thread_duplicate_similarity",
            "thread_merge_similarity",
            "thread_sweep_limit",
            "thread_min_entries",
            "thread_min_sources",
        ],
        "task": "app.workers.thread_tasks.rebuild_story_threads",
        "description": (
            "Group embedded entries into story threads: attach new articles to the story they "
            "continue, seed threads for stories that just broke, and fold near-duplicate re-reports."
        ),
        "category": "intelligence",
        "default_schedule": {"type": "interval", "seconds": 7200},
    },
    "narrate-story-threads": {
        "settings_keys": ["thread_narrate_limit"],
        "task": "app.workers.thread_tasks.narrate_story_threads",
        "description": (
            "Write the AI spine for threads that changed since their last narration — title, "
            "summary and one beat per wave. Threads render a heuristic spine without it."
        ),
        "category": "intelligence",
        "uses_ai": True,
        # After the nightly threat briefs, on the same serialized ai worker.
        "default_schedule": {"type": "crontab", "minute": "10", "hour": "6"},
    },
    "backfill-entity-assessments": {
        "settings_keys": [
            "assessment_backfill_batch_size",
            "assessment_backfill_min_articles",
            "assessment_backfill_retry_days",
            "assessment_refresh_enabled",
            "assessment_refresh_min_new_articles",
            "assessment_refresh_batch_size",
        ],
        "task": "app.workers.entity_maintenance_tasks.kickoff_assessment_backfill",
        "description": (
            "Draft AI assessments for entities that have linked reporting but no description yet "
            "(same output as the profile AI-refresh button; never overwrites text it did not "
            "write itself). Also re-writes its own assessments once enough new reporting has "
            "landed to make them stale. Skips CVEs \u2014 their descriptions come from NVD."
        ),
        "category": "intelligence",
        "uses_ai": True,
        # After the 04:00 link validator; per-entity tasks queue serially on
        # the ai worker so the daily batch paces itself.
        "default_schedule": {"type": "crontab", "minute": "45", "hour": "5"},
    },
    "actor-profile-refresh": {
        "settings_keys": [
            "actor_refresh_top_n_per_run",
            "actor_refresh_min_age_days",
            "actor_refresh_activity_window_days",
            "actor_refresh_sample_n",
        ],
        "task": "app.workers.entity_maintenance_tasks.kickoff_actor_profile_refresh",
        "description": "Weekly AI refresh of the top-N most-active threat actor profile descriptions",
        "category": "intelligence",
        "uses_ai": True,
        "default_schedule": {
            "type": "crontab",
            "minute": "0",
            "hour": "3",
            "day_of_week": "1",
        },
    },
    # --- Maintenance ---
    "cleanup-expired-entries": {
        "task": "app.workers.maintenance.cleanup_expired_entries",
        "description": "Delete entries older than feed retention policy",
        "category": "maintenance",
        "default_schedule": {"type": "crontab", "minute": "5", "hour": "2"},
    },
    "retro-sight-observables": {
        "task": "app.workers.maintenance.retro_sight_observables",
        "description": "Exact-string retro-sighting of recently confirmed observables across the corpus",
        "category": "maintenance",
        "default_schedule": {"type": "crontab", "minute": "40", "hour": "*/6"},
    },
    "decay-observable-confidence": {
        "settings_keys": ["observables_decay_enabled"],
        "task": "app.workers.maintenance.decay_observable_confidence",
        "description": "Nightly confidence decay and lifecycle transitions for the observables ledger",
        "category": "maintenance",
        "default_schedule": {"type": "crontab", "minute": "20", "hour": "2"},
    },
    "reconcile-observable-counters": {
        "task": "app.workers.maintenance.reconcile_observable_counters",
        "description": "Recount observable sighting/article counters from the junction (deletion cascades drift them)",
        "category": "maintenance",
        "default_schedule": {"type": "crontab", "minute": "50", "hour": "2"},
    },
    "resolve-cve-affected": {
        "task": "app.workers.maintenance.resolve_cve_affected",
        "description": "Re-resolve unmatched CVE affected-product CPE pairs against current entities",
        "category": "maintenance",
        "default_schedule": {"type": "crontab", "minute": "35", "hour": "3"},
    },
    "reenrich-cve-nvd": {
        "settings_keys": ["cve_reenrich_batch_size"],
        "task": "app.workers.maintenance.reenrich_cve_nvd",
        "description": "Re-fetch NVD data for CVEs missing it (bulk-imported or awaiting NVD analysis)",
        "category": "maintenance",
        "default_schedule": {"type": "crontab", "minute": "5", "hour": "3"},
    },
    "evict-image-cache": {
        "settings_keys": [
            "image_proxy_cache_ttl_days",
            "image_proxy_max_size_bytes",
        ],
        "task": "app.workers.maintenance.evict_image_cache",
        "description": "Delete cached images older than configured TTL",
        "category": "maintenance",
        "default_schedule": {"type": "crontab", "minute": "10", "hour": "4"},
    },
    "evict-tts-cache": {
        "settings_keys": [
            "tts_cache_ttl_days",
            "tts_cache_max_bytes",
        ],
        "task": "app.workers.maintenance.evict_tts_cache",
        "description": "Evict server-side read-aloud (Piper) audio past TTL or over the size cap",
        "category": "maintenance",
        "default_schedule": {"type": "crontab", "minute": "15", "hour": "4"},
    },
    "cleanup-telegram-media": {
        "task": "app.workers.maintenance.cleanup_telegram_media",
        "description": "Prune Telegram-downloaded media files whose parent entry is gone",
        "category": "maintenance",
        "default_schedule": {
            "type": "crontab",
            "minute": "20",
            "hour": "4",
            "day_of_week": "0",
        },
    },
    "evict-old-telegram-media": {
        "settings_keys": ["telegram_media_ttl_days"],
        "task": "app.workers.maintenance.evict_old_telegram_media",
        "description": "Delete Telegram media files older than the configured TTL (entries/intel are kept)",
        "category": "maintenance",
        "default_schedule": {"type": "crontab", "minute": "25", "hour": "4"},
    },
    "evict-old-ingest-files": {
        "settings_keys": ["ingest_files_ttl_days"],
        "task": "app.workers.maintenance.evict_old_ingest_files",
        "description": "Delete manual-upload originals past the configured TTL (entries and intel are kept)",
        "category": "maintenance",
        "default_schedule": {"type": "crontab", "minute": "35", "hour": "4"},
    },
    "backup-database": {
        "settings_keys": ["backup_retention_days"],
        "task": "app.workers.maintenance.backup_database",
        "description": "Run pg_dump with gzip compression for database backup",
        "category": "maintenance",
        "default_schedule": {"type": "crontab", "minute": "0", "hour": "2"},
    },
    "refresh-correlation-cache": {
        "settings_keys": ["correlation_cache_ttl_seconds"],
        "task": "app.workers.maintenance.refresh_correlation_cache",
        "description": "Pre-warm correlation cache for high-activity entities",
        "category": "maintenance",
        # Hourly: the cache lives `correlation_cache_ttl_seconds` (3600 s), so
        # warming it four times an hour just redid the same work.
        "default_schedule": {"type": "crontab", "minute": "10"},
    },
    "sync-entity-search-indexes": {
        "task": "app.workers.maintenance.sync_entity_search_indexes",
        "description": "Sync intelligence entities to Meilisearch indexes",
        "category": "maintenance",
        "default_schedule": {"type": "crontab", "minute": "45", "hour": "*/4"},
    },
    "retry-failed-indexing": {
        "task": "app.workers.maintenance.retry_failed_indexing",
        "description": "Re-index entries that failed Meilisearch indexing",
        "category": "maintenance",
        "default_schedule": {"type": "crontab", "minute": "*/5"},
    },
    "reconcile-meilisearch": {
        "task": "app.workers.maintenance.reconcile_meilisearch",
        "description": "Detect and repair sync drift between PostgreSQL and Meilisearch",
        "category": "maintenance",
        "default_schedule": {"type": "crontab", "minute": "15", "hour": "7"},
    },
    "cleanup-orphaned-references": {
        "task": "app.workers.maintenance.cleanup_orphaned_references",
        "description": "Remove references to deleted entities",
        "category": "maintenance",
        "default_schedule": {"type": "crontab", "minute": "15", "hour": "3"},
    },
    "relationship-confidence-decay": {
        "settings_keys": ["relationship_recency_half_life_days"],
        "task": "app.workers.maintenance.decay_relationship_confidence",
        "description": "Demote stale co-occurrence relationships (no recent evidence) from probable to possible",
        "category": "maintenance",
        "default_schedule": {"type": "crontab", "minute": "45", "hour": "3", "day_of_week": "0"},
    },
    "retry-untranslated-entries": {
        "settings_keys": ["translation_default_target"],
        "task": "app.workers.translation_tasks.retry_untranslated_entries",
        "description": "Backfill translations missed while the LibreTranslate sidecar was off (auto-translate feeds)",
        "category": "maintenance",
        "default_schedule": {"type": "crontab", "minute": "*/30"},
    },
    "refresh-copilot-auth-status": {
        "task": "app.workers.copilot_auth_tasks.refresh_claude_auth_status",
        "description": "Refresh the copilot Claude Code OAuth credential health snapshot (expiry monitor)",
        "category": "maintenance",
        "default_schedule": {"type": "crontab", "minute": "*/30"},
    },
    # --- Enrichment ---
    "enrichment-dispatch": {
        "task": "app.workers.enrichment_dispatch_tasks.dispatch_enrichment_jobs",
        "description": "Run due lookups from the enrichment job queue, by lane priority",
        "category": "enrichment",
        "default_schedule": {"type": "interval", "seconds": 30},
        # A tick that sat out a worker restart is stale (the next is 30s
        # behind it): drop it rather than run a backlog of ticks.
        "options": {"expires": 30},
    },
    "scheduled-enrichment-check": {
        "task": "app.workers.enrichment_tasks.run_scheduled_enrichment",
        "description": "Check and execute scheduled enrichment source syncs",
        "category": "enrichment",
        "default_schedule": {"type": "crontab", "minute": "*/15"},
    },
    "epss-bulk-sync": {
        "task": "app.workers.enrichment_tasks.run_epss_bulk_sync",
        "description": "Update all CVEs with EPSS scores from epss.empiricalsecurity.com",
        "category": "enrichment",
        "default_schedule": {"type": "crontab", "minute": "30", "hour": "6"},
    },
    "mitre-attack-sync": {
        "task": "app.workers.enrichment_tasks.run_mitre_attack_sync",
        "description": "Download and sync MITRE ATT&CK techniques, groups, and mitigations",
        "category": "enrichment",
        "default_schedule": {
            "type": "crontab",
            "minute": "0",
            "hour": "3",
            "day_of_week": "0",
        },
    },
    "misp-galaxy-sync": {
        "task": "app.workers.enrichment_tasks.run_misp_galaxy_sync",
        "description": "Refresh the reference alias knowledge from the MISP Galaxy threat-actor cluster",
        "category": "enrichment",
        "default_schedule": {
            "type": "crontab",
            "minute": "30",
            "hour": "3",
            "day_of_week": "0",
        },
    },
    # Writes malware, tool and actor rows, so it runs on its own day: the Sunday
    # catalog syncs above also write threat_actors, and sharing their slot
    # deadlocked.
    "malpedia-sync": {
        "task": "app.workers.enrichment_tasks.run_malpedia_sync",
        "description": "Sync malware families from Malpedia",
        "category": "enrichment",
        "default_schedule": {
            "type": "crontab",
            "minute": "0",
            "hour": "1",
            "day_of_week": "6",
        },
    },
    "backfill-rule-attack-mappings": {
        "settings_keys": ["rule_attack_backfill_limit"],
        "task": "app.workers.maintenance.backfill_rule_attack_mappings",
        "description": "Re-fetch GitHub-sourced rules to recover ATT&CK mappings, and derive tactics from techniques",
        "category": "maintenance",
        "default_schedule": {
            "type": "crontab",
            "minute": "30",
            "hour": "5",
            "day_of_week": "0",
        },
    },
    "rebuild-rule-coverage": {
        "task": "app.workers.maintenance.rebuild_rule_coverage",
        "description": "Re-resolve detection rules to the CVEs, techniques and actors they cover",
        "category": "maintenance",
        "default_schedule": {"type": "crontab", "minute": "50", "hour": "3"},
    },
    # Reads rule_coverage, so it is scheduled after the rebuild above rather
    # than alongside it.
    "rank-threat-board": {
        "task": "app.workers.maintenance.rank_threat_board",
        "description": "Recompute the Threats ranking, reopen handled threats with new tradecraft",
        "category": "intelligence",
        "default_schedule": {"type": "crontab", "minute": "20", "hour": "4"},
    },
    "promote-watchlist-threats": {
        "task": "app.workers.maintenance.promote_watchlist_threats",
        "description": "Pin watched actors/malware with window activity onto the Threats board as tracked",
        "category": "intelligence",
        "default_schedule": {"type": "crontab", "minute": "30", "hour": "4"},
    },
    # Reads the reconciled board, so it runs after rank-threat-board.
    "generate-threat-briefs": {
        "settings_keys": ["threat_brief_limit"],
        "task": "app.workers.maintenance.generate_threat_briefs",
        "description": (
            "Write the two-sentence story line for each open Threats and vulnerability row from its window's articles"
        ),
        "category": "intelligence",
        "uses_ai": True,
        "default_schedule": {"type": "crontab", "minute": "40", "hour": "4"},
    },
    "backfill-rule-data-sources": {
        "task": "app.workers.maintenance.backfill_rule_data_sources",
        "description": "Derive detection-rule data_sources from stored log sources for telemetry coverage",
        "category": "maintenance",
        "default_schedule": {
            "type": "crontab",
            "minute": "50",
            "hour": "4",
            "day_of_week": "0",
        },
    },
    "rollup-targeted-sectors": {
        "task": "app.workers.maintenance.rollup_targeted_sectors",
        "description": (
            "Derive actor/malware target-sector claims (with article evidence) from the victim sectors on "
            "their articles; rebuild the targeted_sectors cache"
        ),
        "category": "maintenance",
        "default_schedule": {
            "type": "crontab",
            "minute": "20",
            "hour": "4",
        },
    },
    "metasploit-sync": {
        "task": "app.workers.enrichment_tasks.run_metasploit_sync",
        "description": "Map tracked CVEs to Metasploit modules and escalate weaponized exploit status",
        "category": "enrichment",
        "default_schedule": {
            "type": "crontab",
            "minute": "45",
            "hour": "3",
            "day_of_week": "0",
        },
    },
    "cve-nvd-refresh": {
        "task": "app.workers.enrichment_tasks.run_cve_nvd_refresh",
        "description": "Re-check NVD for CVSS score changes on existing CVEs",
        "category": "enrichment",
        "default_schedule": {"type": "crontab", "minute": "0", "hour": "12"},
    },
    "cve-nvd-backfill": {
        "task": "app.workers.enrichment_tasks.run_cve_nvd_backfill",
        "description": "Backfill NVD data (CVSS, description, affected products, references) for CVEs missing it",
        "category": "enrichment",
        "default_schedule": {"type": "crontab", "minute": "30", "hour": "1"},
    },
    "github-poc-scan": {
        "settings_keys": [
            "github_poc_batch_limit",
            "github_poc_rescan_days",
        ],
        "task": "app.workers.enrichment_tasks.run_github_poc_scan",
        "description": "Scan GitHub for proof-of-concept exploits related to CVEs",
        "category": "enrichment",
        "default_schedule": {"type": "crontab", "minute": "0", "hour": "5"},
    },
    "wikipedia-bulk-sync": {
        "task": "app.workers.enrichment_tasks.run_wikipedia_bulk_sync",
        "description": "Enrich entities missing Wikipedia content",
        "category": "enrichment",
        "default_schedule": {
            "type": "crontab",
            "minute": "0",
            "hour": "4",
            "day_of_week": "3",
        },
    },
    # --- Automation ---
    "run-scheduled-automations": {
        "task": "app.workers.automation_tasks.run_scheduled_automations",
        "description": "Evaluate on_schedule automation rules",
        "category": "automation",
        "default_schedule": {"type": "interval", "seconds": 60},
    },
    # --- Saved Searches ---
    "refresh-saved-search-counts": {
        "task": "app.workers.saved_search_tasks.refresh_saved_search_counts",
        "description": "Refresh match counts and dispatch alerts for saved searches",
        "category": "saved_searches",
        "default_schedule": {"type": "crontab", "minute": "*/5"},
    },
    "sync-campaign-saved-searches": {
        "task": "app.workers.saved_search_tasks.sync_campaign_saved_searches",
        "description": "Auto-sync campaign saved searches and add matching entries",
        "category": "saved_searches",
        "default_schedule": {"type": "crontab", "minute": "*/5"},
    },
    "sync-campaign-sources": {
        "task": "app.workers.saved_search_tasks.sync_campaign_sources",
        "description": "Pull in articles for the entities and stories each campaign follows",
        "category": "saved_searches",
        "default_schedule": {"type": "crontab", "minute": "*/15"},
    },
    "ai-analysis-batch-submit": {
        "settings_keys": [
            "ai_one_pass_enabled",
            "ai_use_batches",
            "ai_daily_budget_usd",
            "ai_batch_max_requests",
            "ai_est_cost_per_request",
            "ai_analysis_relevance_threshold",
            "ai_analysis_content_max_chars",
        ],
        "task": "app.workers.ai_batch_tasks.submit_analysis_batches",
        "description": "Submit pending entries to the one-pass AI analysis batch (priority-ordered, budget-capped)",
        "category": "intelligence",
        "uses_ai": True,
        "default_schedule": {"type": "crontab", "minute": "*/30"},
    },
    "ai-analysis-batch-poll": {
        "task": "app.workers.ai_batch_tasks.poll_analysis_batches",
        "description": "Ingest completed AI analysis batches (results, entity links, costs)",
        "category": "intelligence",
        "default_schedule": {"type": "interval", "seconds": 600},
    },
    "signal-rate-recompute": {
        "settings_keys": ["signal_feedback_min_samples"],
        "task": "app.workers.signal_tasks.recompute_signal_rates",
        "description": "Recompute 30-day signal firing rates (IDF weights) and re-scale priority scores to 0–10",
        "category": "intelligence",
        "default_schedule": {"type": "crontab", "minute": "20", "hour": "4"},
    },
    "signal-personal-weight-fit": {
        "settings_keys": [
            "radar_personalization_enabled",
            "radar_personalization_min_samples",
            "radar_personalization_window_days",
        ],
        "task": "app.workers.signal_tasks.fit_user_signal_weights",
        "description": "Fit per-analyst Radar signal weights from each user's own thumbs",
        "category": "intelligence",
        "default_schedule": {"type": "crontab", "minute": "35", "hour": "4"},
    },
    "signal-rescore-recent": {
        "settings_keys": [
            "signal_engine_shadow",
            "signal_engine_surface",
        ],
        "task": "app.workers.signal_tasks.rescore_recent_entries",
        "description": "Re-score recent entries so KEV/EPSS changes propagate to priority scores",
        "category": "intelligence",
        "default_schedule": {"type": "crontab", "minute": "35", "hour": "*/6"},
    },
    "signal-rescore-all": {
        "settings_keys": [
            "signal_engine_shadow",
            "signal_engine_surface",
        ],
        "task": "app.workers.signal_tasks.rescore_all_entries",
        "description": "Full rescore of every scored entry — heals stored signals/explanations (run on demand)",
        "category": "intelligence",
        # Manual-only: disabled in beat by default so a corpus-wide sweep never
        # fires automatically. Use the Run now button. The schedule is only a
        # placeholder for when an admin explicitly enables + reschedules it.
        "enabled_by_default": False,
        "default_schedule": {"type": "crontab", "minute": "0", "hour": "3", "day_of_week": "0"},
    },
    # --- Content Generation ---
    "generate-reddit-digest": {
        "settings_keys": [
            "reddit_digest_min_entries",
            "reddit_digest_max_entries",
        ],
        "task": "app.workers.reddit_digest_tasks.generate_reddit_digest",
        "description": "Generate daily AI-powered digest of top Reddit security posts",
        "category": "content",
        "uses_ai": True,
        "default_schedule": {"type": "crontab", "minute": "0", "hour": "7"},
    },
    "generate-daily-summaries": {
        "settings_keys": ["narrative_themes_enabled"],
        "task": "app.workers.daily_summary_tasks.generate_daily_summaries",
        "description": (
            "Pre-generate yesterday's shared Triage daily-divider summary (all users), then record "
            "the briefing's own `### Theme` grouping of the day's articles (free — it re-reads "
            "cached markdown, no extra AI call)"
        ),
        "category": "content",
        "uses_ai": True,
        "default_schedule": {"type": "crontab", "minute": "0", "hour": "6"},
    },
    "prune-engine-tables": {
        "settings_keys": ["engine_run_retention_days"],
        "task": "app.workers.maintenance.prune_engine_tables",
        "description": "Delete engine bookkeeping rows older than 30 days (job_runs, …)",
        "category": "maintenance",
        "default_schedule": {"type": "crontab", "minute": "40", "hour": "2"},
    },
}


def schedule_to_human(sched: dict[str, Any]) -> str:
    """Convert a schedule dict to a human-readable string."""
    if sched["type"] == "interval":
        seconds = sched["seconds"]
        if seconds < 60:
            return f"Every {int(seconds)} seconds"
        if seconds < 3600:
            mins = int(seconds / 60)
            return f"Every {mins} minute{'s' if mins != 1 else ''}"
        hours = int(seconds / 3600)
        return f"Every {hours} hour{'s' if hours != 1 else ''}"

    if sched["type"] == "crontab":
        minute = str(sched.get("minute", "*"))
        hour = str(sched.get("hour", "*"))
        dow = str(sched.get("day_of_week", "*"))

        if minute.startswith("*/"):
            return f"Every {minute[2:]} minutes"

        if hour.startswith("*/"):
            return f"Every {hour[2:]} hours at :{minute.zfill(2)}"

        if dow != "*":
            day_names = {
                "0": "Sunday",
                "1": "Monday",
                "2": "Tuesday",
                "3": "Wednesday",
                "4": "Thursday",
                "5": "Friday",
                "6": "Saturday",
            }
            day = day_names.get(str(dow), dow)
            h = int(hour) if hour != "*" else 0
            m = int(minute) if minute != "*" else 0
            period = "AM" if h < 12 else "PM"
            display_h = h % 12 or 12
            return f"Weekly on {day} at {display_h}:{str(m).zfill(2)} {period}"

        if hour != "*":
            h = int(hour)
            m = int(minute) if minute != "*" else 0
            period = "AM" if h < 12 else "PM"
            display_h = h % 12 or 12
            return f"Daily at {display_h}:{str(m).zfill(2)} {period}"

        return f"Cron: {minute} {hour} * * {dow}"

    return str(sched)


def schedule_dict_to_celery(sched: dict[str, Any]):
    """Convert a schedule dict to a celery schedule object."""
    if sched["type"] == "interval":
        return float(sched["seconds"])
    if sched["type"] == "crontab":
        kwargs = {k: v for k, v in sched.items() if k != "type"}
        return crontab(**kwargs)
    raise ValueError(f"Unknown schedule type: {sched['type']}")


def read_overrides_from_redis() -> dict[str, Any]:
    """Read job schedule overrides from Redis."""
    try:
        r = redis.from_url(settings.redis_url, decode_responses=True)
        raw = r.get(REDIS_KEY)
        if raw:
            return json.loads(raw)
    except Exception as e:
        logger.warning("Failed to read job schedule overrides from Redis: %s", e)
    return {}


def write_overrides_to_redis(overrides: dict[str, Any]) -> None:
    """Write job schedule overrides to Redis."""
    try:
        r = redis.from_url(settings.redis_url, decode_responses=True)
        r.set(REDIS_KEY, json.dumps(overrides))
    except Exception as e:
        logger.warning("Failed to write job schedule overrides to Redis: %s", e)


def build_beat_schedule(overrides: dict[str, Any] | None = None) -> dict:
    """Build the celery beat schedule, applying any overrides."""
    if overrides is None:
        overrides = read_overrides_from_redis()

    schedule = {}
    for name, job in JOB_REGISTRY.items():
        override = overrides.get(name, {})

        enabled = override.get("enabled", job.get("enabled_by_default", True))
        if not enabled:
            continue

        sched = override.get("schedule") or job["default_schedule"]
        schedule[name] = {
            "task": job["task"],
            "schedule": schedule_dict_to_celery(sched),
        }
        if job.get("options"):
            schedule[name]["options"] = job["options"]

    return schedule
