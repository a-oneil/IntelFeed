"""System settings service — DB overrides env defaults, with in-memory caching."""

import time
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings as env_settings
from app.core.encryption import decrypt_value, encrypt_value
from app.models.system_setting import SystemSettings

# Which keys are secrets (encrypted in DB, masked in API responses)
SECRET_KEYS = frozenset(
    {
        "github_token",
        "nvd_api_key",
        "sentry_dsn",
        "registration_invite_code",
        "observables_publish_token",
        "smtp_password",
    }
)

# Configurable keys with their expected types
CONFIGURABLE_KEYS: dict[str, type] = {
    # Feeds
    "default_feed_fetch_interval": int,
    "feed_auto_pause_days": int,
    "user_agent": str,
    # Image Proxy
    "image_proxy_enabled": bool,
    "image_proxy_cache_ttl_days": int,
    "image_proxy_max_size_bytes": int,
    # API Keys (secrets)
    "github_token": str,
    "nvd_api_key": str,
    # Intelligence
    "autolinker_min_name_length": int,
    "autolinker_false_positive_names": str,
    "autolinker_blocked_surface_forms": str,
    "autolinker_ambiguous_name_max_length": int,
    "autolinker_ambiguous_max_occurrences": int,
    "autolink_pending_tier_enabled": bool,
    "observables_decay_enabled": bool,
    "observables_candidate_max": int,
    "observables_ai_capture_mode": str,
    "observables_analysis_tail_reserve": float,
    "observables_ai_capture_kinds": str,
    "observables_publisher_ioc_enabled": bool,
    "observables_publisher_ioc_max_values": int,
    "observables_codeblock_skip_categories": str,
    "observables_publish_enabled": bool,
    "observables_publish_token": str,
    "observables_publish_min_confidence": float,
    "observables_publish_max_age_days": int,
    "observables_publish_never_suffixes": str,
    "entity_resolution_normalized_match": bool,
    "entity_creation_gates": str,
    "attack_ics_context_keywords": str,
    # Adjudicate stage
    "adjudication_mode": str,
    "adjudication_trigger": str,
    "adjudication_max_per_hour": int,
    "adjudication_min_priority_score": float,
    "adjudication_apply_min_confidence": str,
    "adjudication_reclassify_consensus": int,
    "adjudication_circuit_breaker_pct": float,
    "adjudication_circuit_breaker_min_items": int,
    "merge_review_batch_size": int,
    "merge_review_pairs_per_call": int,
    "merge_review_min_similarity": float,
    "merge_review_min_confidence": str,
    "merge_review_retry_days": int,
    "relationship_sweep_mode": str,
    "relationship_sweep_batch_size": int,
    "relationship_sweep_min_age_hours": int,
    "relationship_sweep_retry_days": int,
    "relationship_sweep_min_confidence": str,
    "relationship_sweep_actions": str,
    "adjudication_content_max_chars": int,
    "adjudication_scope": str,
    "entity_maintenance_mode": str,
    "assessment_backfill_batch_size": int,
    "assessment_backfill_min_articles": int,
    "assessment_backfill_retry_days": int,
    "assessment_refresh_enabled": bool,
    "assessment_refresh_min_new_articles": int,
    "assessment_refresh_batch_size": int,
    "actor_refresh_top_n_per_run": int,
    "actor_refresh_min_age_days": int,
    "actor_refresh_activity_window_days": int,
    "actor_refresh_sample_n": int,
    "rule_attack_backfill_limit": int,
    # Enrichment job batch sizes
    "cve_reenrich_batch_size": int,
    "github_poc_batch_limit": int,
    "github_poc_rescan_days": int,
    "wikimedia_contact_email": str,
    "enrichment_paused": bool,
    "engine_stopped": bool,
    # Relationship strength formula (composite of corroboration/closeness/recency)
    "relationship_corroboration_saturation": int,
    "relationship_recency_half_life_days": int,
    "relationship_weight_corroboration": float,
    "relationship_weight_closeness": float,
    "relationship_weight_recency": float,
    "relationship_evidence_promote_count": int,
    "graph_max_neighbors_per_node": int,
    "correlation_max_entries": int,
    "graph_max_claim_edges": int,
    # Retention / eviction sweeps
    "engine_run_retention_days": int,
    "tts_cache_ttl_days": int,
    "tts_cache_max_bytes": int,
    "telegram_media_ttl_days": int,
    "ingest_files_ttl_days": int,
    # Bulk ingest caps
    "ingest_max_file_mb": int,
    "ingest_max_batch_items": int,
    "ingest_zip_max_members": int,
    # Translation
    "translation_default_target": str,
    # Embeddings & Story Threads
    "embeddings_enabled": bool,
    "embedding_model": str,
    "embedding_base_url": str,
    "embedding_batch_size": int,
    "embedding_backfill_limit": int,
    "thread_window_days": int,
    "thread_dormancy_days": int,
    "thread_gap_days": int,
    "thread_min_body_chars": int,
    "thread_join_similarity": float,
    "thread_join_similarity_no_entity": float,
    "thread_seed_similarity": float,
    "thread_duplicate_similarity": float,
    "thread_merge_similarity": float,
    "thread_merge_similarity_shared_entity": float,
    "thread_sweep_limit": int,
    "thread_min_entries": int,
    "thread_min_sources": int,
    "thread_narrate_limit": int,
    "thread_signals_enabled": bool,
    # Content-generation jobs
    "threat_brief_limit": int,
    "reddit_digest_min_entries": int,
    "reddit_digest_max_entries": int,
    "correlation_cache_ttl_seconds": int,
    "relationship_min_confidence": str,
    "relationship_specificity_weight": float,
    "relationship_reporting_source_specificity": float,
    "relationship_min_tier_default": str,
    "relationship_evidence_structure": bool,
    "narrative_themes_enabled": bool,
    "narrative_theme_gating": bool,
    "relationship_story_threshold": float,
    "proximity_default_score": float,
    "proximity_decay_rate": float,
    "proximity_strong_threshold": float,
    "proximity_moderate_threshold": float,
    "relationship_reliability_high_multiplier": float,
    "relationship_reliability_low_multiplier": float,
    "feed_value_weight_entity_yield": float,
    "feed_value_weight_entity_intro": float,
    "feed_value_weight_correlation": float,
    "feed_value_weight_detection": float,
    "feed_value_weight_pir": float,
    "cve_epss_high_risk_threshold": float,
    # Signal engine
    "signal_engine_shadow": bool,
    "signal_engine_surface": bool,
    "per_user_subscriptions_enabled": bool,
    "signal_feedback_min_samples": int,
    "radar_personalization_enabled": bool,
    "radar_personalization_min_samples": int,
    "radar_personalization_window_days": int,
    # My Stack exposure scoring
    "my_stack_exposure_enabled": bool,
    "exposure_attack_visibility_enabled": bool,
    # One-pass AI extraction (engine phase 4)
    "ai_one_pass_enabled": bool,
    "ai_daily_budget_usd": float,
    "ai_analysis_relevance_threshold": float,
    "ai_tool_evidence_required": bool,
    "ai_entity_evidence_required": bool,
    "ai_batch_max_requests": int,
    "site_ai_user_daily_requests": int,
    "share_ai_daily_requests": int,
    "allow_user_ai_providers": bool,
    "require_user_ai_provider": bool,
    "user_ai_provider_types": str,
    "copilot_auto_approve_tools": str,
    "user_ai_allow_private_endpoints": bool,
    "user_ai_daily_request_cap": int,
    "ai_analysis_content_max_chars": int,
    "ai_use_batches": bool,
    "ai_est_cost_per_request": float,
    "pipeline_run_logging_enabled": bool,
    "pipeline_engine_enabled": bool,
    # Security
    "public_read_only_enabled": bool,
    "registration_enabled": bool,
    "registration_invite_code": str,
    # Rate Limiting
    "rate_limit_default_interval": float,
    # Monitoring (sentry_dsn is a secret)
    "sentry_dsn": str,
    "sentry_traces_sample_rate": float,
    "sentry_profiles_sample_rate": float,
    # Email (smtp_password is a secret)
    "smtp_host": str,
    "smtp_port": int,
    "smtp_security": str,
    "smtp_username": str,
    "smtp_password": str,
    "smtp_from_address": str,
    "smtp_max_per_hour": int,
    # Backup
    "backup_retention_days": int,
    # Public RSS
    "public_rss_enabled": bool,
    "public_rss_per_feed_limit": int,
    "public_rss_full_content": bool,
}

# Human-readable metadata for each setting. Optional "options" list renders
# the setting as a select in the UI.
SETTING_METADATA: dict[str, dict] = {
    "default_feed_fetch_interval": {
        "label": "Default Fetch Interval",
        "description": "Default interval between feed fetches (minutes)",
        "group": "feeds",
    },
    "feed_auto_pause_days": {
        "label": "Auto-Pause Dead Feeds",
        "description": (
            "Pause a feed once every fetch has returned HTTP 4xx (404 gone, 403 blocked) for this many days in a "
            "row. Only client errors count, and the count is the failure streak, not the time since the last "
            "post, so a feed that rarely posts is not paused. A failing feed is polled less often as the streak "
            "grows (up to once a day). Paused feeds are listed as dead, with the reason, on the Engine Feeds view "
            "and can be resumed with one click. 0 disables."
        ),
        "group": "feeds",
    },
    "user_agent": {
        "label": "User Agent",
        "description": (
            "HTTP User-Agent header sent when fetching feeds. "
            "Browser-like default avoids 403 bot blocks (CISA/gov, Cloudflare)."
        ),
        "group": "feeds",
    },
    "image_proxy_enabled": {
        "label": "Image Proxy Enabled",
        "description": "Proxy external images through IntelFeed for privacy",
        "group": "image_proxy",
    },
    "image_proxy_cache_ttl_days": {
        "label": "Image Cache TTL",
        "description": "Days to cache proxied images",
        "group": "image_proxy",
    },
    "image_proxy_max_size_bytes": {
        "label": "Max Image Size",
        "description": "Maximum image size to proxy (bytes)",
        "group": "image_proxy",
    },
    "github_token": {
        "label": "GitHub Token",
        "description": "Personal access token for GitHub repo feeds (no scopes needed for public repos)",
        "group": "api_keys",
    },
    "nvd_api_key": {
        "label": "NVD API Key",
        "description": "NIST NVD API key. Raises the rate limit from 5 requests per 30 seconds to 50 per 30 seconds.",
        "group": "api_keys",
    },
    "autolinker_min_name_length": {
        "label": "Min Name Length",
        "description": "Minimum character length for autolinker entity matching",
        "group": "intelligence",
    },
    "autolinker_false_positive_names": {
        "label": "False Positive Names",
        "description": "Comma-separated names to exclude from autolinker matching",
        "group": "intelligence",
    },
    "autolinker_blocked_surface_forms": {
        "label": "Blocked Names (Reported)",
        "description": "Names analysts reported as wrong matches. Blocked from matching for every entity type.",
        "group": "intelligence",
    },
    "autolinker_ambiguous_name_max_length": {
        "label": "Ambiguous Name Max Length",
        "description": "Short names up to this length require capitalization to match",
        "group": "intelligence",
    },
    "autolinker_ambiguous_max_occurrences": {
        "label": "Ambiguous Max Occurrences",
        "description": "Skip ambiguous names appearing more than this many times in one article",
        "group": "intelligence",
    },
    "autolink_pending_tier_enabled": {
        "label": "Pending Autolink Tier",
        "description": (
            "Hold actor, malware, tool and country matches on common English words (e.g. Royal, Hive) until the "
            "article's one-pass AI analysis decides. The match is linked when the analysis names the entity and "
            "rejected when it does not. The adjudicator then checks both decisions."
        ),
        "group": "intelligence",
    },
    "observables_decay_enabled": {
        "label": "Confidence Decay",
        "description": (
            "Nightly per-kind confidence decay for network observables (IPs 30-day half-life, URLs 60 days, "
            "domains 90 days; hashes and host artifacts never decay). A new sighting resets the decay."
        ),
        "group": "observables",
    },
    "observables_candidate_max": {
        "label": "Candidate Cap",
        "description": (
            "Maximum observable candidates the refang and regex scan stages per entry. Candidates belong to the "
            "entry and never become observables without AI confirmation, a curated IOC list feed or an analyst "
            "promoting them."
        ),
        "group": "observables",
    },
    "observables_ai_capture_mode": {
        "label": "AI Capture Mode",
        "description": (
            "capture (default): indicators confirmed by the one-pass AI analysis are added to the observables "
            "list directly. shadow: they are held on the entry as candidates for the adjudicator to capture or "
            "drop."
        ),
        "group": "observables",
        "options": ["shadow", "capture"],
    },
    "observables_publisher_ioc_enabled": {
        "label": "Article IOC Tables",
        "description": (
            "When an article links its IOC table in an allow-listed GitHub repository (Cisco Talos IOCs, "
            "Bitdefender malware-ioc, Datadog indicators-of-compromise), fetch the table and capture its "
            "indicators, with the roles the table states, as sightings on the article. No other repositories are "
            "fetched."
        ),
        "group": "observables",
    },
    "observables_publisher_ioc_max_values": {
        "label": "Article IOC Table Cap",
        "description": "Maximum indicators taken from one article's linked IOC table.",
        "group": "observables",
    },
    "observables_ai_capture_kinds": {
        "label": "AI Capture Kinds",
        "description": (
            "In capture mode, only these observable kinds are added to the observables list from the one-pass AI "
            "analysis. Every other kind the AI reports is staged as a candidate that can be promoted. Add host "
            "kinds (cmdline, path, registry, scheduled_task, service_name, mutex, named_pipe, user_agent, "
            "http_header) once the extraction fixture shows they are precise."
        ),
        "group": "observables",
    },
    "observables_analysis_tail_reserve": {
        "label": "Analysis Tail Reserve",
        "description": (
            "Share of the one-pass analysis text budget reserved for the end of the article when the body exceeds "
            "ai_analysis_content_max_chars. Research write-ups put their IOC tables and command blocks at the "
            "end. 0 disables this and the model sees only the start of the article."
        ),
        "group": "observables",
    },
    "observables_codeblock_skip_categories": {
        "label": "Code-Block Scan Skip Categories",
        "description": (
            "Comma-separated feed categories whose entries never stage host-kind candidates from <pre> blocks "
            "(advisory bulletins are preformatted prose, not commands). Rule-repository entries (any GitHub "
            "content_type) are always skipped."
        ),
        "group": "observables",
    },
    "observables_publish_enabled": {
        "label": "Publishing",
        "description": (
            "Serve the outbound feeds: EDL blocklists, SIEM lookup CSVs and the TAXII 2.1 collection. When off, "
            "every publish endpoint returns 404."
        ),
        "group": "observables",
    },
    "observables_publish_token": {
        "label": "Publish Token",
        "description": (
            "Comma-separated name:secret consumer tokens (a bare secret also works). Each consumer gets its own "
            "revocable token and pulls are attributed to the name. Accepted as a Bearer header or ?token=."
        ),
        "group": "observables",
    },
    "observables_publish_min_confidence": {
        "label": "Publish Confidence Floor",
        "description": "Minimum current (decayed) confidence for a value to appear in any outbound feed.",
        "group": "observables",
    },
    "observables_publish_max_age_days": {
        "label": "Publish Max Age",
        "description": "Values last sighted more than this many days ago are dropped from the outbound feeds.",
        "group": "observables",
    },
    "observables_publish_never_suffixes": {
        "label": "Never-Publish Suffixes",
        "description": (
            "Comma-separated domain suffixes excluded from every outbound feed (the instance's own domains, "
            "partners, anything that must never be blocklisted). Values stay in the observables list; this "
            "filters publishing only. Shared CDN and hosting suffixes (cloudfront, workers.dev, ...) are always "
            "excluded."
        ),
        "group": "observables",
    },
    "entity_resolution_normalized_match": {
        "label": "Normalized Entity Matching",
        "description": (
            "Match AI-extracted entity names against existing profiles after normalizing case, punctuation, "
            "spacing and leetspeak, so variants like 'Cl0p' or 'Silver Fox' resolve to the existing entity "
            "instead of creating a duplicate."
        ),
        "group": "intelligence",
    },
    "entity_creation_gates": {
        "label": "Entity Creation Gates",
        "description": (
            "Checks on automated entity creation (generic name, denylist, cross-type and alias quality). off: no "
            "checks. shadow: log what would be blocked to the maintenance log but still create. on: enforce. "
            "Manual creation bypasses the checks and is logged."
        ),
        "group": "intelligence",
        "options": ["off", "shadow", "on"],
    },
    "adjudication_mode": {
        "label": "Adjudication Mode",
        "description": (
            "off: never runs. shadow: every verdict is filed as a proposal on the Review tab and nothing is "
            "changed. apply: high-confidence verdicts are applied at ingest and lower ones become proposals. This "
            "is the main switch; pipeline plans can only exclude feeds."
        ),
        "group": "adjudication",
        "options": ["off", "shadow", "apply"],
    },
    "adjudication_trigger": {
        "label": "Trigger",
        "description": (
            "all: every analyzed entry (about 100 to 500 per day). created: only entries whose analysis created "
            "an entity, added a link or relationship, promoted a pending match or captured an observable (about "
            "20 to 50 per day). Use created when reviews cannot keep up with ingest."
        ),
        "group": "adjudication",
        "options": ["all", "created"],
    },
    "adjudication_max_per_hour": {
        "label": "Hourly Budget",
        "description": (
            "Reviews started per hour. 0 (the default) means no limit: the AI worker runs one call at a time, so "
            "it paces itself. Set a number to cap spend on a metered provider, or to stop a review backlog "
            "queueing ahead of entry analysis, which shares that worker. Entries over the limit wait for the next "
            "sweep and are never dropped. While a limit is set, the backfill may use at most half of each hour "
            "and live entries get the rest. With no limit, dispatch the backfill in batches with its own limit "
            "instead."
        ),
        "group": "adjudication",
    },
    "adjudication_min_priority_score": {
        "label": "Score Floor",
        "description": (
            "Skip entries below this priority score (0 to 10). 0 means no floor. Keep it at 0 while CVE/NVD "
            "entries are the main source of junk tool entities, since a floor would exempt those entries."
        ),
        "group": "adjudication",
    },
    "adjudication_apply_min_confidence": {
        "label": "Apply Only At Confidence",
        "description": "In apply mode, verdicts below this confidence are filed as proposals instead of applied.",
        "group": "adjudication",
        "options": ["high", "medium", "low"],
    },
    "adjudication_reclassify_consensus": {
        "label": "Reclassify Consensus",
        "description": (
            "A type change affects the whole catalog, so in apply mode it is applied only once reviews of this "
            "many different articles agree on the same target type (each earlier review's proposal counts as a "
            "vote). 1 applies the first verdict that meets the confidence floor. A name an analyst removed from a "
            "type is never proposed back into it."
        ),
        "group": "adjudication",
    },
    "adjudication_circuit_breaker_pct": {
        "label": "Circuit Breaker",
        "description": (
            "If more than this share of an entry's items come back as remove, veto, demote or drop, the whole run "
            "is downgraded to proposals (0.5 = half). A rolling mean over the last 50 apply runs above the same "
            "threshold pauses dispatch for the hour. Shadow runs are not counted, because they change nothing."
        ),
        "group": "adjudication",
    },
    "adjudication_circuit_breaker_min_items": {
        "label": "Circuit Breaker: Minimum Items",
        "description": (
            "The circuit breaker only judges a run that reviewed at least this many items. Below that, each "
            "verdict stands on its own confidence. Otherwise a single remove on a one-item recheck would count as "
            "100% destructive."
        ),
        "group": "adjudication",
    },
    "merge_review_batch_size": {
        "label": "Duplicate Review: Pairs Per Run",
        "description": (
            "Likely-duplicate pairs of existing actors, malware and tools the daily duplicate review sends to the "
            "model per run (most likely first: similar names, a shared alias). Each pair the model calls the same "
            "becomes a Merge proposal on the Review tab. Nothing is merged without a person confirming. 0 turns "
            "the review off."
        ),
        "group": "adjudication",
    },
    "merge_review_pairs_per_call": {
        "label": "Duplicate Review: Pairs Per Call",
        "description": (
            "Pairs sent to the model in one call. Smaller batches are slower but less likely to be truncated."
        ),
        "group": "adjudication",
    },
    "merge_review_min_similarity": {
        "label": "Duplicate Review: Name Similarity Floor",
        "description": (
            "Trigram similarity (0 to 1) two names need to be a candidate pair on name alone. A shared alias "
            "qualifies a pair whatever its names. Shared articles only order the pairs."
        ),
        "group": "adjudication",
    },
    "merge_review_min_confidence": {
        "label": "Duplicate Review: Propose At Confidence",
        "description": "A 'same' verdict below this confidence is recorded as unsure instead of proposed.",
        "group": "adjudication",
        "options": ["high", "medium", "low"],
    },
    "merge_review_retry_days": {
        "label": "Duplicate Review: Retry After (days)",
        "description": "A pair the model called different or unsure is not asked again for this many days.",
        "group": "adjudication",
    },
    "relationship_sweep_mode": {
        "label": "Edge Sweep: Mode",
        "description": (
            "The edge sweep judges relationships the per-article review left open (never answered, unsure, or "
            "kept by one article and demoted by another), using passages from up to four of their articles. "
            "shadow: records each answer on the relationship and changes nothing. apply: keeps a relationship an "
            "article states, corrects a wrong verb or direction, and hides one no article states. Every change is "
            "listed in Review history, where Restore undoes it."
        ),
        "group": "adjudication",
        "options": ["off", "shadow", "apply"],
    },
    "relationship_sweep_batch_size": {
        "label": "Edge Sweep: Claims Per Run",
        "description": "Relationships judged per run, one model call each. 0 turns the sweep off.",
        "group": "adjudication",
    },
    "relationship_sweep_min_age_hours": {
        "label": "Edge Sweep: Minimum Age (hours)",
        "description": (
            "A relationship is left to the per-article review for this many hours before the sweep picks it up."
        ),
        "group": "adjudication",
    },
    "relationship_sweep_retry_days": {
        "label": "Edge Sweep: Retry After (days)",
        "description": "A relationship the sweep could not settle is not asked again for this many days.",
        "group": "adjudication",
    },
    "relationship_sweep_min_confidence": {
        "label": "Edge Sweep: Apply At Confidence",
        "description": "In apply mode, answers below this confidence are recorded but change nothing.",
        "group": "adjudication",
        "options": ["high", "medium", "low"],
    },
    "relationship_sweep_actions": {
        "label": "Edge Sweep: Changes It Applies",
        "description": (
            "Comma-separated changes apply mode may make: keep (settle a relationship an article states), correct "
            "(fix a wrong verb or direction), hide (a relationship no article states). Add one only after "
            "scripts/maintenance/eval_relationship_sweep.py shows it is right often enough. Other answers are "
            "recorded on the relationship and it stays in Review. A keep of an actor or malware targeting a "
            "country is never applied, because origin is too often read as target."
        ),
        "group": "adjudication",
    },
    "adjudication_content_max_chars": {
        "label": "Article Text Cap",
        "description": (
            "Characters of article text in the review prompt (the start of the article plus the indicator section "
            "at the end, as in extraction)."
        ),
        "group": "adjudication",
    },
    "adjudication_scope": {
        "label": "Review Scope",
        "description": (
            "Comma-separated manifest sections the reviewer sees: links, entities, relationships, observables, "
            "assessment. assessment is opt-in and its verdicts are only logged."
        ),
        "group": "adjudication",
    },
    "attack_ics_context_keywords": {
        "label": "ICS Context Keywords",
        "description": (
            "Comma-separated keywords (matched on word boundaries). ICS-matrix ATT&CK techniques (T0xxx) are "
            "linked only when the entry text contains one of them."
        ),
        "group": "intelligence",
    },
    "pipeline_engine_enabled": {
        "label": "Pipeline Plans",
        "description": (
            "Decide which stages run from pipeline plans (Engine > Plans), layered over the per-feed settings. "
            "Off: per-feed settings only."
        ),
        "group": "intelligence",
    },
    "pipeline_run_logging_enabled": {
        "label": "Pipeline Run Logging",
        "description": (
            "Record each entry's pipeline stage runs (entry_pipeline_runs). Off stops the recording; nothing else "
            "changes."
        ),
        "group": "intelligence",
    },
    "ai_one_pass_enabled": {
        "label": "One-Pass AI Extraction",
        "description": (
            "Run the consolidated entry_analysis AI call on entries at ingest "
            "(batched, budget-capped). Needs an enabled entry_analysis assignment."
        ),
        "group": "ai",
    },
    "ai_daily_budget_usd": {
        "label": "AI Extraction Daily Budget ($)",
        "description": (
            "Hard daily spend cap for entry_analysis. When reached, pending "
            "entries wait (highest-priority first next run)."
        ),
        "group": "ai",
    },
    "ai_analysis_relevance_threshold": {
        "label": "Extraction Junk Gate",
        "description": (
            "Relevance score (0 to 1) below which an entry skips AI analysis, and skips autolinking on selective "
            "feeds. The score measures whether there is anything to extract, not how important the entry is."
        ),
        "group": "ai",
    },
    "ai_tool_evidence_required": {
        "label": "Tool Evidence Gate",
        "description": (
            "Only store an extracted tool when the model names who used it and quotes the sentence showing its "
            "use. Turn off if tool extraction stops finding anything."
        ),
        "group": "ai",
    },
    "ai_entity_evidence_required": {
        "label": "Actor & Malware Evidence Gate",
        "description": (
            "Only create a new threat actor or malware family when the model quotes a sentence that "
            "names it as the attacker or the malicious software. Without one, the name still links to "
            "an existing entity but no new one is made."
        ),
        "group": "ai",
    },
    "ai_batch_max_requests": {
        "label": "Max Batch Size",
        "description": "Maximum entries per hourly analysis batch submission.",
        "group": "ai",
    },
    "site_ai_user_daily_requests": {
        "label": "Per-User Daily AI Allowance",
        "description": (
            "Requests one person may make each day on this instance's own AI providers for the prompts they run "
            "themselves (copilot, rule help, summaries, reports). Background work, automation rules and share "
            "links are not counted. Resets at midnight UTC. 0 = unlimited."
        ),
        "group": "ai",
    },
    "share_ai_daily_requests": {
        "label": "Share Link Daily AI Limit",
        "description": (
            "AI questions and prompts one share link may run per day. Share traffic always uses this instance's "
            "providers, never the sharer's. Resets at midnight UTC. 0 = unlimited."
        ),
        "group": "ai",
    },
    "allow_user_ai_providers": {
        "label": "Personal AI Keys",
        "description": (
            "Let people add their own AI provider keys. Prompts they run themselves use their key and "
            "fall back to this instance's providers when it is missing, failing or over its cap. Background "
            "work, automation rules and share links always use this instance's providers."
        ),
        "group": "ai",
    },
    "require_user_ai_provider": {
        "label": "Require Personal Keys",
        "description": (
            "With personal keys on: refuse a prompt a person runs themselves instead of falling back to this "
            "instance's providers when the person has no working key. Ignored while personal keys are off."
        ),
        "group": "ai",
    },
    "user_ai_provider_types": {
        "label": "Personal Key Types",
        "description": (
            "Comma-separated provider types people may register as their own: claude, openai_compatible, ollama. "
            "Claude Code cannot be personal: it is one CLI sign-in for the whole instance."
        ),
        "group": "ai",
    },
    "copilot_auto_approve_tools": {
        "label": "Copilot Writes Without Confirm",
        "description": (
            "Comma-separated copilot tools that change data but run without the person clicking Confirm, "
            "e.g. create_note,add_tag,star_entry,bookmark_entry,watch_entity. Admin-only tools and deletes "
            "always ask. Empty: every change waits for Confirm. Edited in the Prompt Workspace (Copilot)."
        ),
        "group": "ai",
    },
    "user_ai_allow_private_endpoints": {
        "label": "Personal Keys May Use Private Endpoints",
        "description": (
            "Let a personal key point at a private network address such as a LAN Ollama. Leave off on a "
            "public instance: the server calls whatever URL people enter."
        ),
        "group": "ai",
    },
    "user_ai_daily_request_cap": {
        "label": "Personal Key Daily Request Cap",
        "description": (
            "Requests this server makes on one person's own keys each day. This is not a spending limit (people "
            "set their own in My AI); it limits how hard a loop or a misbehaving client can drive the server. "
            "Counts calls, not dollars. Resets at midnight UTC. 0 = unlimited."
        ),
        "group": "ai",
    },
    "ai_analysis_content_max_chars": {
        "label": "Analysis Content Cap",
        "description": "Characters of article text sent to entry_analysis. Longer text adds little extraction quality.",
        "group": "ai",
    },
    "ai_use_batches": {
        "label": "Use Batches API",
        "description": (
            "Use the Anthropic Message Batches API (50% discount) when the provider "
            "supports it; otherwise sequential calls with prompt caching."
        ),
        "group": "ai",
    },
    "signal_engine_shadow": {
        "label": "Signal Engine (shadow)",
        "description": (
            "Compute and store entry signals and priority scores without showing them in the UI. Enable this "
            "first and check the results with GET /entries/triage?mode=signals before showing them."
        ),
        "group": "intelligence",
    },
    "per_user_subscriptions_enabled": {
        "label": "Per-user feed subscriptions",
        "description": (
            "Each analyst manages their own feed list and mutes over the shared pool. Off: one shared list, and a "
            "mute affects everyone. Every user starts subscribed to every feed, so turning this on changes "
            "nothing until someone unsubscribes."
        ),
        "group": "feeds",
    },
    "signal_engine_surface": {
        "label": "Signal Engine (show in UI)",
        "description": (
            "Show signal scores in the UI: priority chips in the entry list and the signal-ranked Radar on the "
            "triage page."
        ),
        "group": "intelligence",
    },
    "radar_personalization_enabled": {
        "label": "Personalized Radar",
        "description": (
            "Let each analyst's own Radar votes re-rank their Priority Queue. Weights are fitted nightly per user "
            "and applied at read time on top of the shared score. The stored score stays global, and any analyst "
            "can switch back to the shared ranking from their Radar panel."
        ),
        "group": "intelligence",
    },
    "radar_personalization_min_samples": {
        "label": "Personalized Radar Min Votes",
        "description": (
            "Minimum verdicts one analyst must cast in a signal family before that "
            "family gets a personal weight. Below this the family stays neutral."
        ),
        "group": "intelligence",
    },
    "radar_personalization_window_days": {
        "label": "Personalized Radar Window (days)",
        "description": (
            "How far back the nightly fit looks for a user's verdicts. Longer than the "
            "global 30-day nudge window because one analyst votes far less than all of them."
        ),
        "group": "intelligence",
    },
    "signal_feedback_min_samples": {
        "label": "Signal Feedback Min Samples",
        "description": (
            "Minimum radar feedback verdicts a signal family needs in the 30-day window before its feedback nudge "
            "is applied. Below this, the nudge is skipped so a few votes cannot swing scoring."
        ),
        "group": "intelligence",
    },
    "my_stack_exposure_enabled": {
        "label": "Vendor Watch",
        "description": (
            "Show vulnerabilities in the vendors and products a user follows: rank them higher in the Priority "
            "Queue and list them on the Vendor Watch board with detection-library coverage. Uses the entity "
            "watchlist. Applied at read time per user; stored scores do not change. Requires Signal Engine (show "
            "in UI) to be on."
        ),
        "group": "intelligence",
    },
    "exposure_attack_visibility_enabled": {
        "label": "Vendor Watch: ATT&CK Detectability (heuristic)",
        "description": (
            "On the Vendor Watch board, for vulnerabilities with no detection rule, estimate whether the "
            "available telemetry could detect exploitation by mapping the CVE's co-occurring ATT&CK techniques to "
            "their data sources. Less reliable than rule-backed coverage: the CVE-to-technique link comes from "
            "article co-occurrence, not a curated mapping."
        ),
        "group": "intelligence",
    },
    "entity_maintenance_mode": {
        "label": "Actor Refresh Mode",
        "description": (
            "shadow: the weekly actor-profile rewrite is filed as a proposal in the maintenance log. apply: the "
            "new description is written directly; the description history is the undo."
        ),
        "group": "intelligence",
        "options": ["shadow", "apply"],
    },
    "assessment_backfill_batch_size": {
        "label": "Assessment Backfill: Batch Size",
        "description": (
            "Entities dispatched per daily run of the assessment backfill. They queue serially on the "
            "single-concurrency AI worker, so the batch paces itself. Raise this to drain a backlog faster; lower "
            "it to leave more of the worker's time for ingest extraction."
        ),
        "group": "intelligence",
    },
    "assessment_backfill_min_articles": {
        "label": "Assessment Backfill: Minimum Articles",
        "description": (
            "Fewest linked entries an entity needs before it is worth summarizing. 1 covers every "
            "entity that has any reporting at all; raise it to spend the daily budget on "
            "better-covered entities first."
        ),
        "group": "intelligence",
    },
    "assessment_backfill_retry_days": {
        "label": "Assessment Backfill: Retry Window",
        "description": (
            "Do not retry an entity within this many days of its last attempt. Without this, the entities with "
            "the most articles are picked every run and the rest of the queue never runs."
        ),
        "group": "intelligence",
    },
    "assessment_refresh_enabled": {
        "label": "Assessment Refresh",
        "description": (
            "Rewrite assessments that have gone stale, not only missing ones. The backfill picks only entities "
            "with an empty description, so an entity assessed once is otherwise never revisited. Only text this "
            "writer produced is changed; analyst and enrichment descriptions are never overwritten."
        ),
        "group": "intelligence",
    },
    "assessment_refresh_min_new_articles": {
        "label": "Assessment Refresh: Staleness Threshold",
        "description": (
            "New linked articles since the assessment was written before it counts as stale. The "
            "writer reads the 20 most recent articles, so 10 means half its input has turned over."
        ),
        "group": "intelligence",
    },
    "assessment_refresh_batch_size": {
        "label": "Assessment Refresh: Batch Size",
        "description": (
            "Stale refreshes dispatched per run. Kept separate from the backfill batch so a long "
            "refresh queue can never crowd out an entity that has no assessment at all."
        ),
        "group": "intelligence",
    },
    "correlation_cache_ttl_seconds": {
        "label": "Correlation Cache TTL",
        "description": "Seconds to cache correlation engine results",
        "group": "intelligence",
    },
    "relationship_specificity_weight": {
        "label": "Relationship Specificity Weight",
        "description": (
            "How much relationship strength is damped by counterpart ubiquity (IDF). 0 disables; "
            "1 fully scales strength by specificity. Entities mentioned across the whole corpus "
            "(reporting vendors, OS names) sink toward the bottom of related lists."
        ),
        "group": "intelligence",
    },
    "relationship_reporting_source_specificity": {
        "label": "Reporting-Source Group Threshold",
        "description": (
            "Vendors and products with specificity below this are treated as reporting sources and collapsed into "
            "one group on profile relationship views (0.0 to 1.0)."
        ),
        "group": "intelligence",
    },
    "relationship_min_tier_default": {
        "label": "Default Relationship Tier Floor",
        "description": (
            "Platform-wide minimum evidence tier for profile related lists. Per-view filters can still narrow further."
        ),
        "group": "intelligence",
        "options": ["all", "moderate", "strong"],
    },
    "relationship_evidence_structure": {
        "label": "Relationship Evidence Structure",
        "description": (
            "Cluster each relationship's evidence articles into stories (using entry embeddings) so profile "
            "relationship views can tell 'recurring across N incidents' from scattered mentions in roundups. Also "
            "requires a minimum number of stories before a co-occurrence is promoted, and orders the adjudication "
            "queue. Requires entry embeddings."
        ),
        "group": "intelligence",
    },
    "narrative_themes_enabled": {
        "label": "Briefing Themes",
        "description": (
            "Read the daily briefing's `### Theme` grouping back out of its cached markdown and record which "
            "articles it grouped together. No AI call or embeddings are needed. The record changes nothing until "
            "the gate below is switched on."
        ),
        "group": "intelligence",
    },
    "narrative_theme_gating": {
        "label": "Briefing Themes: Gate Promotion",
        "description": (
            "Let the briefing's grouping block a co-occurrence promotion: a pair whose evidence all sits under "
            "one heading on one day is one round of reporting, not corroboration. Leave off until a few weeks of "
            "themes have accumulated. With no parsed themes the gate changes nothing."
        ),
        "group": "intelligence",
    },
    "relationship_story_threshold": {
        "label": "Evidence Story Threshold",
        "description": (
            "Cosine similarity for two evidence articles to count as the same story (0.0 to 1.0). Lower values "
            "group digests into incident clusters; higher values split coverage of one incident apart."
        ),
        "group": "intelligence",
    },
    "relationship_min_confidence": {
        "label": "Relationship Trust Floor",
        "description": (
            "Minimum trust tier for relationships on profiles and timelines. 'possible' shows the "
            "full ladder including dashed signal rows; 'probable' hides the signal tier (engine "
            "inferences awaiting corroboration); 'confirmed' shows only corroborated claims "
            "(MITRE / AI-adjudicated / pinned). Engine management views always show everything."
        ),
        "group": "intelligence",
        "options": ["possible", "probable", "confirmed"],
    },
    "proximity_default_score": {
        "label": "Proximity Default Score",
        "description": "Score assigned to entity pairs without paragraph data (0.0–1.0)",
        "group": "intelligence",
    },
    "proximity_decay_rate": {
        "label": "Proximity Decay Rate",
        "description": (
            "Controls how fast proximity score drops with paragraph distance. Formula: 1 / (1 + decay_rate × "
            "distance). Higher = stricter."
        ),
        "group": "intelligence",
    },
    "proximity_strong_threshold": {
        "label": "Proximity Strong Threshold",
        "description": "Minimum proximity score to label a relationship as 'strong' (0.0–1.0)",
        "group": "intelligence",
    },
    "proximity_moderate_threshold": {
        "label": "Proximity Moderate Threshold",
        "description": "Minimum proximity score to label a relationship as 'moderate' (0.0–1.0). Below this is 'weak'.",
        "group": "intelligence",
    },
    "relationship_reliability_high_multiplier": {
        "label": "Reliability High Multiplier",
        "description": (
            "Evidence weight multiplier for articles from A/B-reliability feeds in relationship strength "
            "(1.0 = no boost)"
        ),
        "group": "intelligence",
    },
    "relationship_reliability_low_multiplier": {
        "label": "Reliability Low Multiplier",
        "description": (
            "Evidence weight multiplier for articles from D/E-reliability feeds in relationship strength "
            "(1.0 = no penalty). C, F, and unrated feeds are neutral."
        ),
        "group": "intelligence",
    },
    "feed_value_weight_entity_yield": {
        "label": "Feed Value: Entity Yield Weight",
        "description": "Weight of entities-per-article in the feed intel-value score (weights normalize to sum 1.0)",
        "group": "intelligence",
    },
    "feed_value_weight_entity_intro": {
        "label": "Feed Value: Entity Intro Weight",
        "description": "Weight of first-discovered entities in the feed intel-value score",
        "group": "intelligence",
    },
    "feed_value_weight_correlation": {
        "label": "Feed Value: Correlation Weight",
        "description": "Weight of correlation events in the feed intel-value score",
        "group": "intelligence",
    },
    "feed_value_weight_detection": {
        "label": "Feed Value: Detection Weight",
        "description": "Weight of generated detection rules in the feed intel-value score",
        "group": "intelligence",
    },
    "feed_value_weight_pir": {
        "label": "Feed Value: PIR Match Weight",
        "description": "Weight of priority intelligence requirement (PIR) matches in the feed intel-value score",
        "group": "intelligence",
    },
    "cve_epss_high_risk_threshold": {
        "label": "CVE EPSS High-Risk Threshold",
        "description": (
            "EPSS score (0.0–1.0) at or above which a CVE is tiered 'high' risk. Drives CVE risk tiers, triage "
            "scoring, and opportunity badges."
        ),
        "group": "intelligence",
    },
    "public_read_only_enabled": {
        "label": "Public read-only mode",
        "description": (
            "Let anyone open IntelFeed without an account. Visitors can browse articles, entity profiles, story "
            "threads and the default dashboards, but can't change anything, run AI, or see private pages. "
            "Off by default."
        ),
        "group": "security",
    },
    "registration_enabled": {
        "label": "Account Registration",
        "description": "Allow new users to register accounts. Disable to lock registration.",
        "group": "security",
    },
    "registration_invite_code": {
        "label": "Invite Code",
        "description": "Required code for new account registration. Leave empty to allow registration without a code.",
        "group": "security",
    },
    "rate_limit_default_interval": {
        "label": "Rate Limit Interval",
        "description": "Default seconds between requests per domain",
        "group": "rate_limiting",
    },
    "sentry_dsn": {
        "label": "Sentry DSN",
        "description": "Sentry error tracking DSN (requires restart)",
        "group": "monitoring",
    },
    "sentry_traces_sample_rate": {
        "label": "Sentry Traces Sample Rate",
        "description": "Fraction of transactions to sample (0.0-1.0, requires restart)",
        "group": "monitoring",
    },
    "sentry_profiles_sample_rate": {
        "label": "Sentry Profiles Sample Rate",
        "description": "Fraction of transactions to profile (0.0-1.0, requires restart)",
        "group": "monitoring",
    },
    "smtp_host": {
        "label": "SMTP Server",
        "description": "Mail server the Send Email automation action delivers through. Leave empty to turn email off",
        "group": "email",
    },
    "smtp_port": {
        "label": "SMTP Port",
        "description": "Usually 587 for STARTTLS, 465 for TLS",
        "group": "email",
    },
    "smtp_security": {
        "label": "Connection Security",
        "description": (
            "starttls: connect plain, then upgrade before logging in (port 587). "
            "tls: encrypted from the start (port 465). Unencrypted servers aren't supported"
        ),
        "group": "email",
        "options": ["starttls", "tls"],
    },
    "smtp_username": {
        "label": "SMTP Username",
        "description": "Leave empty if the server doesn't need a login",
        "group": "email",
    },
    "smtp_password": {
        "label": "SMTP Password",
        "description": "Password or app password for the SMTP login",
        "group": "email",
    },
    "smtp_from_address": {
        "label": "From Address",
        "description": "Sender address on every email, e.g. IntelFeed <alerts@example.com>",
        "group": "email",
    },
    "smtp_max_per_hour": {
        "label": "Emails per Hour",
        "description": (
            "Maximum emails sent in one clock hour across every rule. Emails over the limit are not sent and show "
            "as errors in the rule's run log. This keeps a busy rule from hitting the mail provider's limits. 0 = "
            "no limit."
        ),
        "group": "email",
    },
    "backup_retention_days": {
        "label": "Backup Retention",
        "description": "Days to keep database backups",
        "group": "backup",
    },
    "public_rss_enabled": {
        "label": "Enable Public RSS",
        "description": (
            "Re-publish all aggregated entries as a single token-gated public RSS feed (plus per-category feeds)."
        ),
        "group": "public_rss",
    },
    "public_rss_per_feed_limit": {
        "label": "Items per Feed",
        "description": "Maximum entries to include in each public RSS feed (most recent first)",
        "group": "public_rss",
    },
    "public_rss_full_content": {
        "label": "Include Full Content",
        "description": "Embed sanitized article HTML in <description>. Disable to publish only title + summary + link.",
        "group": "public_rss",
    },
    # --- Scheduled-job knobs (Engine → Maintenance / enrich stage / Jobs) ---
    # The jobs read these through settings.get(), which ignores DB overrides for
    # a key missing from CONFIGURABLE_KEYS and falls through to the job's inline
    # default. Registering them keeps those defaults and makes them settable.
    "actor_refresh_top_n_per_run": {
        "label": "Actor Refresh: Actors Per Run",
        "description": "Threat actor profiles the weekly AI refresh rewrites per run",
        "group": "maintenance",
    },
    "actor_refresh_min_age_days": {
        "label": "Actor Refresh: Minimum Age",
        "description": "Skip actors whose profile was AI-refreshed more recently than this many days",
        "group": "maintenance",
    },
    "actor_refresh_activity_window_days": {
        "label": "Actor Refresh: Activity Window",
        "description": "Lookback window (days) used to rank which actors count as most active",
        "group": "maintenance",
    },
    "actor_refresh_sample_n": {
        "label": "Actor Refresh: Headline Sample",
        "description": "Recent headlines sampled into each actor-refresh prompt",
        "group": "maintenance",
    },
    "rule_attack_backfill_limit": {
        "label": "Rule ATT&CK Backfill Limit",
        "description": "Detection rules re-fetched per ATT&CK-mapping backfill run",
        "group": "maintenance",
    },
    "cve_reenrich_batch_size": {
        "label": "CVE Re-enrich Batch Size",
        "description": "CVEs re-fetched from NVD per maintenance run (bulk-imported or awaiting analysis)",
        "group": "enrichment",
    },
    "github_poc_batch_limit": {
        "label": "GitHub PoC Scan Batch",
        "description": "CVEs searched per PoC scan run. 0 = auto (300 with a GitHub token, 40 without)",
        "group": "enrichment",
    },
    "github_poc_rescan_days": {
        "label": "GitHub PoC Rescan Interval",
        "description": "Days before an already-scanned CVE is eligible for another PoC search",
        "group": "enrichment",
    },
    "wikimedia_contact_email": {
        "label": "Wikimedia contact email",
        "description": (
            "Sent in the User-Agent of every Wikipedia and Wikidata request, as Wikimedia's User-Agent policy "
            "asks, so Wikimedia can contact the operator instead of blocking the instance."
        ),
        "group": "enrichment",
    },
    "enrichment_paused": {
        "label": "Pause Enrichment",
        "description": "Refuse every request to outside enrichment sources. Queued lookups wait until this is off.",
        "group": "enrichment",
    },
    "engine_stopped": {
        "label": "Stop Engine",
        "description": (
            "Stop every background process: feed polling, analysis, enrichment and scheduled jobs. Queued work "
            "waits until the engine starts again."
        ),
        "group": "maintenance",
    },
    "relationship_corroboration_saturation": {
        "label": "Corroboration Saturation",
        "description": "Independent reporting count at which the corroboration component of strength maxes out",
        "group": "intelligence",
    },
    "relationship_recency_half_life_days": {
        "label": "Recency Half-Life",
        "description": (
            "Days after which a relationship's recency component halves; also the staleness "
            "window the weekly confidence-decay job demotes on"
        ),
        "group": "intelligence",
    },
    "relationship_weight_corroboration": {
        "label": "Strength Weight: Corroboration",
        "description": "Share of relationship strength driven by how many independent articles report it",
        "group": "intelligence",
    },
    "relationship_weight_closeness": {
        "label": "Strength Weight: Closeness",
        "description": "Share of relationship strength driven by in-article proximity",
        "group": "intelligence",
    },
    "relationship_weight_recency": {
        "label": "Strength Weight: Recency",
        "description": "Share of relationship strength driven by how recent the evidence is",
        "group": "intelligence",
    },
    "relationship_evidence_promote_count": {
        "label": "Evidence Promote Count",
        "description": "Independent pieces of evidence needed to promote an edge to the next confidence tier",
        "group": "intelligence",
    },
    "graph_max_neighbors_per_node": {
        "label": "Graph Max Neighbors",
        "description": "Cap on neighbors expanded per node when building an entity graph",
        "group": "intelligence",
    },
    "correlation_max_entries": {
        "label": "Pivot/Graph Entry Cap",
        "description": (
            "Most recent linked articles a pivot or graph reads per entity. Limits the cost of entities linked to "
            "very many articles."
        ),
        "group": "intelligence",
    },
    "graph_max_claim_edges": {
        "label": "Graph Max Claim Edges",
        "description": (
            "Cap on typed relationship edges per entity graph. The highest-trust edges are kept. Limits the cost "
            "of entities with very many relationships."
        ),
        "group": "intelligence",
    },
    "engine_run_retention_days": {
        "label": "Engine Run Retention",
        "description": "Days of engine bookkeeping kept (job runs, entry pipeline runs, AI request/batch rows)",
        "group": "retention",
    },
    "tts_cache_ttl_days": {
        "label": "Read-Aloud Audio TTL",
        "description": (
            "Delete cached read-aloud audio not played within this many days. A shorter per-item TTL takes precedence."
        ),
        "group": "retention",
    },
    "tts_cache_max_bytes": {
        "label": "Read-Aloud Cache Size Cap",
        "description": (
            "Size cap for cached read-aloud audio (bytes). The least recently played files are deleted first."
        ),
        "group": "retention",
    },
    "telegram_media_ttl_days": {
        "label": "Telegram Media TTL",
        "description": "Delete downloaded Telegram media files older than this. Entries and extracted intel are kept",
        "group": "retention",
    },
    "ingest_files_ttl_days": {
        "label": "Manual Upload Originals TTL",
        "description": (
            "Delete the original files behind manual uploads older than this many days (0 keeps them forever). "
            "Entries and extracted intel are kept; the reader then says the original was not kept"
        ),
        "group": "retention",
    },
    "ingest_max_file_mb": {
        "label": "Manual Upload Max File Size",
        "description": (
            "Per-file cap in MB for files dropped on the ingest modal, including members of a .zip. Larger files "
            "are listed in the batch as too large."
        ),
        "group": "feeds",
    },
    "ingest_max_batch_items": {
        "label": "Manual Upload Batch Cap",
        "description": "Most items one ingest batch may hold, counting files expanded out of a .zip or a GitHub repo",
        "group": "feeds",
    },
    "ingest_zip_max_members": {
        "label": "Manual Upload Zip Member Cap",
        "description": (
            "Most files expanded out of one .zip; an archive over the cap is refused as unsupported "
            "rather than partly imported"
        ),
        "group": "feeds",
    },
    "translation_default_target": {
        "label": "Default Translation Target",
        "description": "Language code translated into when a feed does not set its own target (e.g. en)",
        "group": "translation",
    },
    "threat_brief_limit": {
        "label": "Threat Briefs Per Run",
        "description": "Open Threats board rows given an AI-written summary per nightly run.",
        "group": "content",
    },
    "embeddings_enabled": {
        "label": "Entry Embeddings",
        "description": (
            "Embed entries so articles about the same story can be grouped into one thread. Requires an embedding "
            "model on the Ollama host."
        ),
        "group": "threads",
    },
    "embedding_model": {
        "label": "Embedding Model",
        "description": "Ollama model used for entry embeddings (must output 768 dimensions, e.g. nomic-embed-text)",
        "group": "threads",
    },
    "embedding_base_url": {
        "label": "Embedding Base URL",
        "description": "Ollama host for embeddings. Blank uses the configured Ollama provider",
        "group": "threads",
    },
    "embedding_batch_size": {
        "label": "Embedding Batch Size",
        "description": "Texts sent per embedding request",
        "group": "threads",
    },
    "embedding_backfill_limit": {
        "label": "Entries Embedded Per Run",
        "description": "Cap on entries the embedding sweeper processes each run",
        "group": "threads",
    },
    "thread_window_days": {
        "label": "Thread Window (days)",
        "description": "How far back an entry can still be pulled into a story thread",
        "group": "threads",
    },
    "thread_dormancy_days": {
        "label": "Thread Dormancy (days)",
        "description": "Silence after which a thread stops accepting new articles",
        "group": "threads",
    },
    "thread_gap_days": {
        "label": "Thread Gap (days)",
        "description": "Maximum quiet days between an article and the last article of the thread it joins",
        "group": "threads",
    },
    "thread_min_body_chars": {
        "label": "Minimum Article Length",
        "description": "Entries with less body text than this are bulletin rows and are never threaded",
        "group": "threads",
    },
    "thread_join_similarity": {
        "label": "Join Similarity",
        "description": "Cosine similarity to a thread's centroid needed to join it when an entity is shared",
        "group": "threads",
    },
    "thread_join_similarity_no_entity": {
        "label": "Join Similarity (no shared entity)",
        "description": "Higher bar for joining a thread the article shares no extracted entity with",
        "group": "threads",
    },
    "thread_seed_similarity": {
        "label": "Seed Similarity",
        "description": "Cosine similarity between unthreaded articles needed to start a new thread",
        "group": "threads",
    },
    "thread_duplicate_similarity": {
        "label": "Echo Similarity",
        "description": "At or above this similarity, an article is grouped as a re-report of an earlier one.",
        "group": "threads",
    },
    "thread_merge_similarity": {
        "label": "Merge Similarity",
        "description": (
            "Two overlapping threads whose centroids are this close are the same story and are merged into one."
        ),
        "group": "threads",
    },
    "thread_merge_similarity_shared_entity": {
        "label": "Merge Similarity (shared entity)",
        "description": (
            "Lower merge bar for two threads whose key entities overlap, the way a shared entity lowers the join bar"
        ),
        "group": "threads",
    },
    "thread_sweep_limit": {
        "label": "Entries Examined Per Sweep",
        "description": (
            "Entries the thread sweeper considers each run. Keep it above the number of articles published inside "
            "the gap window, or the newest articles are never examined."
        ),
        "group": "threads",
    },
    "thread_min_entries": {
        "label": "Minimum Articles",
        "description": "Articles required before a cluster becomes a thread",
        "group": "threads",
    },
    "thread_min_sources": {
        "label": "Minimum Outlets",
        "description": "Distinct source domains required before a cluster becomes a thread",
        "group": "threads",
    },
    "thread_narrate_limit": {
        "label": "Thread Timelines Per Run",
        "description": "Threads given an AI-written timeline per nightly run.",
        "group": "threads",
    },
    "thread_signals_enabled": {
        "label": "Score From Threads",
        "description": (
            "Let a story thread provide the echo and convergence signals: a re-report is an article the thread "
            "grouped, and corroboration is the thread's outlet count. Off uses entity overlap."
        ),
        "group": "threads",
    },
    "reddit_digest_min_entries": {
        "label": "Reddit Digest: Minimum Posts",
        "description": "Skip the daily digest when fewer than this many qualifying posts were collected",
        "group": "content",
    },
    "reddit_digest_max_entries": {
        "label": "Reddit Digest: Maximum Posts",
        "description": "Cap on posts fed into the digest prompt",
        "group": "content",
    },
    "ai_est_cost_per_request": {
        "label": "Estimated Cost Per Request",
        "description": (
            "Per-entry cost estimate used to size an analysis batch against the daily budget. "
            "Set to a near-zero value for local providers like Ollama"
        ),
        "group": "ai",
    },
}

GROUP_LABELS: dict[str, str] = {
    "feeds": "Feeds",
    "image_proxy": "Image Proxy",
    "api_keys": "API Keys",
    "ai": "AI",
    "intelligence": "Intelligence",
    "autolink": "Autolinking",
    "extraction": "Extraction",
    "observables": "Observables",
    "scoring": "Scoring",
    "adjudication": "Adjudication",
    "maintenance": "Maintenance",
    "enrichment": "Enrichment",
    "retention": "Retention & Eviction",
    "translation": "Translation",
    "content": "Content Generation",
    "threads": "Story Threads",
    "plans": "Pipeline Plans",
    "feed_value": "Feed Value Weights",
    "rate_limiting": "Rate Limiting",
    "security": "Security",
    "monitoring": "Monitoring",
    "email": "Email (SMTP)",
    "backup": "Backup",
    "public_rss": "Public RSS",
}

# Move settings into the Engine console section that owns the feature they
# tune. The metadata above puts every intelligence-engine knob in one
# "intelligence" group, which would show ~30 unrelated settings under the
# correlation stage. `group` is display-only — it decides which admin UI panel
# renders a setting and never touches its key, stored value, or backend
# consumers — so moving a setting here changes only where it appears. Only
# correlation / relationship-strength knobs stay in "intelligence" (the
# correlation stage).
_ENGINE_SECTION_GROUPS: dict[str, str] = {
    # Autolink stage
    "autolinker_min_name_length": "autolink",
    "autolinker_false_positive_names": "autolink",
    "autolinker_blocked_surface_forms": "autolink",
    "autolinker_ambiguous_name_max_length": "autolink",
    "autolinker_ambiguous_max_occurrences": "autolink",
    "autolink_pending_tier_enabled": "autolink",
    # Observables stage
    "observables_decay_enabled": "observables",
    "observables_candidate_max": "observables",
    "observables_ai_capture_mode": "observables",
    "observables_analysis_tail_reserve": "observables",
    "observables_ai_capture_kinds": "observables",
    "observables_publisher_ioc_enabled": "observables",
    "observables_publisher_ioc_max_values": "observables",
    "observables_codeblock_skip_categories": "observables",
    "observables_publish_enabled": "observables",
    "observables_publish_token": "observables",
    "observables_publish_min_confidence": "observables",
    "observables_publish_max_age_days": "observables",
    "observables_publish_never_suffixes": "observables",
    # Extraction: the first two gate AI-extracted entities and render on the
    # analyze stage panel; the last two tune pattern matching (extract stage).
    "entity_resolution_normalized_match": "extraction",
    "entity_creation_gates": "extraction",
    "attack_ics_context_keywords": "extraction",
    "cve_epss_high_risk_threshold": "extraction",
    # Adjudicate stage (post-analysis AI review)
    "adjudication_mode": "adjudication",
    "adjudication_trigger": "adjudication",
    "adjudication_max_per_hour": "adjudication",
    "adjudication_min_priority_score": "adjudication",
    "adjudication_apply_min_confidence": "adjudication",
    "adjudication_reclassify_consensus": "adjudication",
    "adjudication_circuit_breaker_pct": "adjudication",
    "adjudication_circuit_breaker_min_items": "adjudication",
    "merge_review_batch_size": "adjudication",
    "merge_review_pairs_per_call": "adjudication",
    "merge_review_min_similarity": "adjudication",
    "merge_review_min_confidence": "adjudication",
    "merge_review_retry_days": "adjudication",
    "relationship_sweep_mode": "adjudication",
    "relationship_sweep_batch_size": "adjudication",
    "relationship_sweep_min_age_hours": "adjudication",
    "relationship_sweep_retry_days": "adjudication",
    "relationship_sweep_min_confidence": "adjudication",
    "relationship_sweep_actions": "adjudication",
    "adjudication_content_max_chars": "adjudication",
    "adjudication_scope": "adjudication",
    # Score stage
    "signal_engine_shadow": "scoring",
    "signal_engine_surface": "scoring",
    "signal_feedback_min_samples": "scoring",
    "radar_personalization_enabled": "scoring",
    "radar_personalization_min_samples": "scoring",
    "radar_personalization_window_days": "scoring",
    "my_stack_exposure_enabled": "scoring",
    "exposure_attack_visibility_enabled": "scoring",
    # Maintenance browse view (assessments, actor refresh, narrative themes)
    "entity_maintenance_mode": "maintenance",
    "assessment_backfill_batch_size": "maintenance",
    "assessment_backfill_min_articles": "maintenance",
    "assessment_backfill_retry_days": "maintenance",
    "assessment_refresh_enabled": "maintenance",
    "assessment_refresh_min_new_articles": "maintenance",
    "assessment_refresh_batch_size": "maintenance",
    "narrative_themes_enabled": "maintenance",
    "narrative_theme_gating": "maintenance",
    # Score stage — Story Threads block
    "embeddings_enabled": "threads",
    "embedding_model": "threads",
    "embedding_base_url": "threads",
    "embedding_batch_size": "threads",
    "embedding_backfill_limit": "threads",
    "thread_window_days": "threads",
    "thread_dormancy_days": "threads",
    "thread_gap_days": "threads",
    "thread_min_body_chars": "threads",
    "thread_join_similarity": "threads",
    "thread_join_similarity_no_entity": "threads",
    "thread_seed_similarity": "threads",
    "thread_duplicate_similarity": "threads",
    "thread_merge_similarity": "threads",
    "thread_merge_similarity_shared_entity": "threads",
    "thread_sweep_limit": "threads",
    "thread_min_entries": "threads",
    "thread_min_sources": "threads",
    "thread_narrate_limit": "threads",
    "thread_signals_enabled": "threads",
    # Pipeline plans browse view
    "pipeline_engine_enabled": "plans",
    "pipeline_run_logging_enabled": "plans",
    # Feeds view (feed intel-value weighting)
    "feed_value_weight_entity_yield": "feed_value",
    "feed_value_weight_entity_intro": "feed_value",
    "feed_value_weight_correlation": "feed_value",
    "feed_value_weight_detection": "feed_value",
    "feed_value_weight_pir": "feed_value",
}
for _key, _group in _ENGINE_SECTION_GROUPS.items():
    SETTING_METADATA[_key]["group"] = _group

# --- In-memory cache ---
_cache: dict[str, Any] | None = None
_cache_secrets: dict[str, str] | None = None
_cache_ts: float = 0.0
_CACHE_TTL = 5.0  # seconds — short so PATCHes on one worker propagate quickly to others


def invalidate_cache() -> None:
    global _cache, _cache_secrets, _cache_ts
    _cache = None
    _cache_secrets = None
    _cache_ts = 0.0


async def _load_from_db(db: AsyncSession) -> tuple[dict, dict]:
    result = await db.execute(select(SystemSettings).where(SystemSettings.id == 1))
    row = result.scalar_one_or_none()
    if not row:
        return {}, {}
    return dict(row.settings or {}), dict(row.secrets or {})


async def _ensure_cache(db: AsyncSession) -> tuple[dict, dict]:
    global _cache, _cache_secrets, _cache_ts
    now = time.monotonic()
    if _cache is not None and (now - _cache_ts) < _CACHE_TTL:
        return _cache, _cache_secrets or {}
    db_settings, db_secrets = await _load_from_db(db)
    _cache = db_settings
    _cache_secrets = db_secrets
    _cache_ts = now
    return db_settings, db_secrets


def get_setting_cached(key: str) -> Any:
    """Synchronous read from cache. Returns None if not in cache (falls back to env)."""
    if _cache is None:
        return None
    if key in SECRET_KEYS:
        encrypted = (_cache_secrets or {}).get(key)
        if encrypted:
            try:
                return decrypt_value(encrypted)
            except Exception:
                return None
        return None
    return _cache.get(key)


async def warm_settings_cache(db: AsyncSession) -> None:
    """Refresh the in-process settings cache from the DB.

    `Settings.get()` (config.py) reads `get_setting_cached`, which is a plain
    in-process dict with no staleness check — in a long-lived Celery worker it
    holds whatever some earlier task happened to load, or nothing at all. Any
    task that reads knobs through `settings.get()` must call this first, inside
    its session and *before* the reads, or a DB override is silently ignored.
    """
    invalidate_cache()
    await _ensure_cache(db)


async def get_setting(key: str, db: AsyncSession) -> Any:
    """Get the effective value for a setting: DB override > env default."""
    db_settings, db_secrets = await _ensure_cache(db)
    if key in SECRET_KEYS:
        encrypted = db_secrets.get(key)
        if encrypted:
            try:
                return decrypt_value(encrypted)
            except Exception:
                pass
        return getattr(env_settings, key, "")
    if key in db_settings:
        return db_settings[key]
    return getattr(env_settings, key, None)


async def get_all_settings(db: AsyncSession) -> dict[str, Any]:
    """Return all configurable settings with effective values and metadata."""
    db_settings, db_secrets = await _load_from_db(db)
    result = {}
    for key, expected_type in CONFIGURABLE_KEYS.items():
        env_val = getattr(env_settings, key, None)
        meta = SETTING_METADATA.get(key, {})

        if key in SECRET_KEYS:
            has_db = bool(db_secrets.get(key))
            has_env = bool(env_val)
            result[key] = {
                "value": "",  # never return plaintext
                "is_secret": True,
                "is_set": has_db or has_env,
                "source": "database" if has_db else ("env" if has_env else "default"),
                **meta,
            }
        else:
            db_val = db_settings.get(key)
            effective = db_val if db_val is not None else env_val
            result[key] = {
                "value": effective,
                "is_secret": False,
                "source": "database" if db_val is not None else "default",
                "env_default": env_val,
                **meta,
            }
    return result


def _coerce_type(key: str, value: Any) -> Any:
    """Coerce a value to the expected type for a setting key."""
    expected = CONFIGURABLE_KEYS.get(key)
    if expected is None:
        raise ValueError(f"Unknown setting: {key}")
    if value is None:
        return None  # None means "reset to default"
    if expected is bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in ("true", "1", "yes")
        return bool(value)
    if expected is int:
        return int(value)
    if expected is float:
        return float(value)
    return str(value)


async def update_settings(db: AsyncSession, updates: dict[str, Any]) -> dict[str, Any]:
    """Validate and persist setting updates. Returns the new effective settings."""
    db_settings, db_secrets = await _load_from_db(db)

    for key, value in updates.items():
        if key not in CONFIGURABLE_KEYS:
            raise ValueError(f"Unknown setting: {key}")

        if value is None or value == "":
            # Reset to default — remove from DB
            db_settings.pop(key, None)
            db_secrets.pop(key, None)
            continue

        coerced = _coerce_type(key, value)

        if key in SECRET_KEYS:
            db_secrets[key] = encrypt_value(str(coerced))
        else:
            db_settings[key] = coerced

    await db.execute(
        update(SystemSettings).where(SystemSettings.id == 1).values(settings=db_settings, secrets=db_secrets)
    )
    await db.flush()
    invalidate_cache()

    return await get_all_settings(db)


async def reset_setting(db: AsyncSession, key: str) -> dict[str, Any]:
    """Reset a single setting back to env/default."""
    if key not in CONFIGURABLE_KEYS:
        raise ValueError(f"Unknown setting: {key}")
    return await update_settings(db, {key: None})


# Reserved (non-CONFIGURABLE) keys stored directly in the settings JSONB.
PUBLIC_RSS_TOKEN_KEY = "_public_rss_token"
DEFAULT_THEME_KEY = "_default_theme_id"
JOB_OVERRIDES_KEY = "_job_schedule_overrides"


def find_redundant_overrides(
    db_settings: dict[str, Any],
    *,
    job_registry: dict[str, Any] | None = None,
) -> dict[str, list]:
    """Classify the override row's dead weight, without touching the DB.

    An override that equals the shipped default pins the install to a stale
    copy of that default: when the default moves, the install silently does
    not. A key the code no longer reads is just confusing on the next audit.
    Returns the keys to drop, grouped by why::

        {"equal_to_default": [...], "unknown": [...],
         "job_overrides_orphaned": [...], "job_overrides_equal_to_default": [...]}

    Reserved keys (``_public_rss_token`` and the job overrides themselves)
    and secrets are never listed. ``job_registry`` defaults to the live
    registry; pass one to test with.
    """
    if job_registry is None:
        from app.workers.job_registry import JOB_REGISTRY

        job_registry = JOB_REGISTRY

    equal: list[str] = []
    unknown: list[str] = []
    for key, value in db_settings.items():
        if key in (PUBLIC_RSS_TOKEN_KEY, JOB_OVERRIDES_KEY):
            continue
        if key == DEFAULT_THEME_KEY:
            continue  # an explicit choice; a theme id has no code default to compare against
        if key not in CONFIGURABLE_KEYS:
            unknown.append(key)
            continue
        if key in SECRET_KEYS:
            continue
        default = getattr(env_settings, key, None)
        try:
            same = _coerce_type(key, value) == default
        except (TypeError, ValueError):
            same = False
        if same:
            equal.append(key)

    orphaned: list[str] = []
    job_equal: list[str] = []
    for job_name, override in (db_settings.get(JOB_OVERRIDES_KEY) or {}).items():
        job = job_registry.get(job_name)
        if job is None:
            orphaned.append(job_name)
            continue
        override = override or {}
        enabled_default = job.get("enabled_by_default", True)
        redundant = True
        if "enabled" in override and bool(override["enabled"]) != bool(enabled_default):
            redundant = False
        if override.get("schedule") and override["schedule"] != job.get("default_schedule"):
            redundant = False
        if redundant:
            job_equal.append(job_name)

    return {
        "equal_to_default": sorted(equal),
        "unknown": sorted(unknown),
        "job_overrides_orphaned": sorted(orphaned),
        "job_overrides_equal_to_default": sorted(job_equal),
    }


async def prune_redundant_overrides(db: AsyncSession) -> dict[str, list]:
    """Drop the overrides ``find_redundant_overrides`` names and return them."""
    result = await db.execute(select(SystemSettings).where(SystemSettings.id == 1))
    row = result.scalar_one_or_none()
    if not row:
        return {
            "equal_to_default": [],
            "unknown": [],
            "job_overrides_orphaned": [],
            "job_overrides_equal_to_default": [],
        }

    db_settings = dict(row.settings or {})
    report = find_redundant_overrides(db_settings)
    for key in report["equal_to_default"] + report["unknown"]:
        db_settings.pop(key, None)
    overrides = dict(db_settings.get(JOB_OVERRIDES_KEY) or {})
    for job_name in report["job_overrides_orphaned"] + report["job_overrides_equal_to_default"]:
        overrides.pop(job_name, None)
    if overrides:
        db_settings[JOB_OVERRIDES_KEY] = overrides
    else:
        db_settings.pop(JOB_OVERRIDES_KEY, None)

    row.settings = db_settings
    db.add(row)
    await db.flush()
    invalidate_cache()
    return report


async def get_default_theme_id(db: AsyncSession) -> str | None:
    """Return the instance-wide default theme id set by an admin, if any."""
    db_settings, _ = await _load_from_db(db)
    value = db_settings.get(DEFAULT_THEME_KEY)
    return str(value) if value else None


async def set_default_theme_id(db: AsyncSession, theme_id: str | None) -> None:
    """Set (or clear, with None) the instance-wide default theme id."""
    result = await db.execute(select(SystemSettings).where(SystemSettings.id == 1))
    row = result.scalar_one_or_none()
    if not row:
        if theme_id is None:
            return
        row = SystemSettings(id=1, settings={DEFAULT_THEME_KEY: theme_id}, secrets={})
        db.add(row)
    else:
        new_settings = dict(row.settings or {})
        if theme_id is None:
            new_settings.pop(DEFAULT_THEME_KEY, None)
        else:
            new_settings[DEFAULT_THEME_KEY] = theme_id
        row.settings = new_settings
        db.add(row)
    await db.flush()
    invalidate_cache()


async def get_public_rss_token(db: AsyncSession, *, create_if_missing: bool = False) -> str | None:
    """Return the current public-RSS token, optionally generating one if absent."""
    import secrets

    db_settings, _ = await _load_from_db(db)
    token = db_settings.get(PUBLIC_RSS_TOKEN_KEY)
    if token:
        return token
    if not create_if_missing:
        return None

    token = secrets.token_urlsafe(32)
    db_settings[PUBLIC_RSS_TOKEN_KEY] = token
    await db.execute(update(SystemSettings).where(SystemSettings.id == 1).values(settings=db_settings))
    await db.flush()
    invalidate_cache()
    return token


async def regenerate_public_rss_token(db: AsyncSession) -> str:
    """Generate a fresh public-RSS token, invalidating any prior URLs."""
    import secrets

    db_settings, _ = await _load_from_db(db)
    token = secrets.token_urlsafe(32)
    db_settings[PUBLIC_RSS_TOKEN_KEY] = token
    await db.execute(update(SystemSettings).where(SystemSettings.id == 1).values(settings=db_settings))
    await db.flush()
    invalidate_cache()
    return token
