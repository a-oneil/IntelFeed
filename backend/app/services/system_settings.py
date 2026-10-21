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
    {"github_token", "nvd_api_key", "sentry_dsn", "registration_invite_code", "observables_publish_token"}
)

# Configurable keys with their expected types
CONFIGURABLE_KEYS: dict[str, type] = {
    # Feeds
    "default_feed_fetch_interval": int,
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
    "adjudication_circuit_breaker_pct": float,
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
    # Relationship strength formula (composite of corroboration/closeness/recency)
    "relationship_corroboration_saturation": int,
    "relationship_recency_half_life_days": int,
    "relationship_weight_corroboration": float,
    "relationship_weight_closeness": float,
    "relationship_weight_recency": float,
    "relationship_evidence_promote_count": int,
    "graph_max_neighbors_per_node": int,
    "graph_max_claim_edges": int,
    # Retention / eviction sweeps
    "engine_run_retention_days": int,
    "tts_cache_ttl_days": int,
    "tts_cache_max_bytes": int,
    "telegram_media_ttl_days": int,
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
    "ai_batch_max_requests": int,
    "ai_analysis_content_max_chars": int,
    "ai_use_batches": bool,
    "ai_est_cost_per_request": float,
    "pipeline_run_logging_enabled": bool,
    "pipeline_engine_enabled": bool,
    # Security
    "registration_enabled": bool,
    "registration_invite_code": str,
    # Rate Limiting
    "rate_limit_default_interval": float,
    # Monitoring (sentry_dsn is a secret)
    "sentry_dsn": str,
    "sentry_traces_sample_rate": float,
    "sentry_profiles_sample_rate": float,
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
        "description": "NIST NVD API key — increases rate limit from 5/30s to 50/30s",
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
        "label": "Blocked Surface Forms",
        "description": "Analyst-reported names blocked from matching for every entity type",
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
            "Hold actor/malware/tool/country matches on common-English-word names "
            "(e.g. Royal, Hive) as pending until the one-pass AI analysis confirms "
            "the entity is actually discussed; unconfirmed matches never become links"
        ),
        "group": "intelligence",
    },
    "observables_decay_enabled": {
        "label": "Confidence Decay",
        "description": (
            "Nightly per-kind confidence decay for network observables (IPs 30d half-life, URLs 60d, "
            "domains 90d; hashes and host artifacts never decay). A new sighting resets the clock"
        ),
        "group": "observables",
    },
    "observables_candidate_max": {
        "label": "Candidate Cap",
        "description": (
            "Maximum observable candidates staged per entry by the refang+regex scan; candidates are "
            "entry-local nominations and never become ledger rows without a judgment door"
        ),
        "group": "observables",
    },
    "observables_ai_capture_mode": {
        "label": "AI Capture Mode",
        "description": (
            "shadow (default): the one-pass AI's confirmed indicators land on each entry as promotable "
            "candidates only — eyeball its judgment first. capture: confirmations become ledger rows "
            "directly. The v1 lesson, applied to the new judge"
        ),
        "group": "observables",
        "options": ["shadow", "capture"],
    },
    "observables_publisher_ioc_enabled": {
        "label": "Article IOC Tables",
        "description": (
            "When an article links its IOC table in an allow-listed repository (Cisco Talos IOCs, Bitdefender "
            "malware-ioc, Datadog indicators-of-compromise on GitHub), fetch it and capture its atoms — with the "
            "roles the table states — sighted on the article. Only those repositories are ever fetched"
        ),
        "group": "observables",
    },
    "observables_publisher_ioc_max_values": {
        "label": "Article IOC Table Cap",
        "description": "Maximum indicators taken from one article's linked IOC table",
        "group": "observables",
    },
    "observables_ai_capture_kinds": {
        "label": "AI Capture Kinds",
        "description": (
            "In capture mode, only these observable kinds become ledger rows from the one-pass AI; every other "
            "kind the AI reports is still staged as a promotable candidate. Flip host kinds (cmdline, path, "
            "registry, scheduled_task, service_name, mutex, named_pipe, user_agent, http_header) in once the "
            "extraction fixture shows they are precise"
        ),
        "group": "observables",
    },
    "observables_analysis_tail_reserve": {
        "label": "Analysis Tail Reserve",
        "description": (
            "Share of the one-pass analysis text budget reserved for an article's indicator appendix when "
            "the body exceeds ai_analysis_content_max_chars. Research write-ups put their IOC tables and "
            "command blocks at the end; 0 disables the appendix and the model only sees the head"
        ),
        "group": "observables",
    },
    "observables_codeblock_skip_categories": {
        "label": "Code-Block Scan Skip Categories",
        "description": (
            "Comma list of feed categories whose entries never nominate host-kind candidates from <pre> "
            "blocks (advisory bulletins are preformatted prose, not commands). Rule-repository entries "
            "(any GitHub content_type) are always skipped"
        ),
        "group": "observables",
    },
    "observables_publish_enabled": {
        "label": "Publishing",
        "description": (
            "Serve the outbound feeds — EDL blocklists, SIEM lookup CSVs, and the TAXII 2.1 collection. "
            "Off means every publish endpoint 404s"
        ),
        "group": "observables",
    },
    "observables_publish_token": {
        "label": "Publish Token",
        "description": (
            "Comma list of name:secret consumer tokens (bare secrets work too). Each puller gets its own "
            "revocable token; pulls are attributed to the name. Accepted as Bearer or ?token="
        ),
        "group": "observables",
    },
    "observables_publish_min_confidence": {
        "label": "Publish Confidence Floor",
        "description": "Minimum current (decayed) confidence for a value to appear in any outbound feed",
        "group": "observables",
    },
    "observables_publish_max_age_days": {
        "label": "Publish Max Age",
        "description": "Values last sighted more than this many days ago drop out of the feeds",
        "group": "observables",
    },
    "observables_publish_never_suffixes": {
        "label": "Never-Publish Suffixes",
        "description": (
            "Comma list of domain suffixes excluded from every outbound feed (your own org's domains, "
            "partners, anything you must never blocklist). Rows stay in the ledger — this is a publish "
            "filter, not a capture rule. Shared CDN/hosting suffixes (cloudfront, workers.dev, ...) are "
            "always excluded"
        ),
        "group": "observables",
    },
    "entity_resolution_normalized_match": {
        "label": "Normalized Entity Matching",
        "description": (
            "Match incoming AI-extracted entity names against existing profiles after "
            "normalization (case/punctuation/spacing/leetspeak folding) so variants like "
            "'Cl0p' or 'Silver Fox' resolve to the existing entity instead of creating a duplicate"
        ),
        "group": "intelligence",
    },
    "entity_creation_gates": {
        "label": "Entity Creation Gates",
        "description": (
            "Guardrails on automated entity creation (generic-name/denylist/cross-type/alias-quality "
            "gates): 'off', 'shadow' (log would-block decisions to the maintenance log but still "
            "create), or 'on' (enforce). Manual creation keeps a logged override"
        ),
        "group": "intelligence",
        "options": ["off", "shadow", "on"],
    },
    "adjudication_mode": {
        "label": "Adjudication Mode",
        "description": (
            "off = never runs. shadow = every verdict is filed as a proposal in the Links / AI-entities "
            "queues and nothing is touched. apply = high-confidence verdicts are applied at ingest; lower "
            "ones still become proposals. This is the master switch; plans only subtract feeds."
        ),
        "group": "adjudication",
        "options": ["off", "shadow", "apply"],
    },
    "adjudication_trigger": {
        "label": "Trigger",
        "description": (
            "all = every analysed entry (what replacing the nightly validator needs; ~100-500/day). "
            "created = only entries whose analysis minted an entity, asserted a link or edge, promoted a "
            "pending match, or captured an observable (~20-50/day) — the fallback when reviews cannot "
            "keep up with ingest"
        ),
        "group": "adjudication",
        "options": ["all", "created"],
    },
    "adjudication_max_per_hour": {
        "label": "Hourly Budget",
        "description": (
            "Reviews started per hour. 0, the default, means no ceiling: the AI worker runs one call "
            "at a time, so it paces itself. Set a number for one of two reasons — to cap spend on a "
            "metered provider, or to stop a review backlog queueing ahead of the entry analysis, which "
            "shares that worker. Over-budget entries wait for the next sweep; they are never dropped. "
            "While a ceiling is set the backfill may use at most half of each hour, live entries get "
            "the rest; with no ceiling, dispatch the backfill in batches via its own limit instead"
        ),
        "group": "adjudication",
    },
    "adjudication_min_priority_score": {
        "label": "Score Floor",
        "description": (
            "Skip entries below this priority score (0–10). 0 = no floor — keep it there while CVE/NVD "
            "entries are the main source of junk tool entities; a floor would exempt exactly those"
        ),
        "group": "adjudication",
    },
    "adjudication_apply_min_confidence": {
        "label": "Apply Only At Confidence",
        "description": "In apply mode, verdicts below this confidence are filed as proposals instead of applied",
        "group": "adjudication",
        "options": ["high", "medium", "low"],
    },
    "adjudication_circuit_breaker_pct": {
        "label": "Circuit Breaker",
        "description": (
            "If more than this share of an entry's items come back remove / veto / demote / drop, the "
            "whole run is downgraded to proposals (0.5 = half). A rolling mean over the last 50 apply "
            "runs above the same threshold pauses dispatch for the hour; shadow runs are not sampled, "
            "because they change nothing"
        ),
        "group": "adjudication",
    },
    "adjudication_content_max_chars": {
        "label": "Article Text Cap",
        "description": "Characters of article text in the review prompt (head + indicator tail, like extraction)",
        "group": "adjudication",
    },
    "adjudication_scope": {
        "label": "Review Scope",
        "description": (
            "Comma-separated manifest sections the reviewer sees: links, entities, relationships, "
            "observables, assessment. assessment is opt-in and only ever logged"
        ),
        "group": "adjudication",
    },
    "attack_ics_context_keywords": {
        "label": "ICS Context Keywords",
        "description": (
            "Comma-separated keywords (word-boundary matched) — ICS-matrix ATT&CK "
            "techniques (T0xxx) are only linked when the entry text contains one of these"
        ),
        "group": "intelligence",
    },
    "pipeline_engine_enabled": {
        "label": "Pipeline Plans",
        "description": (
            "Stage composition from pipeline plans (Engine → Plans) layered over the "
            "legacy feed booleans. Off = feed booleans only (instant rollback)."
        ),
        "group": "intelligence",
    },
    "pipeline_run_logging_enabled": {
        "label": "Pipeline Run Logging",
        "description": (
            "Record per-entry pipeline stage runs (entry_pipeline_runs). Kill switch only — write-only observability."
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
            "Relevance score below which entries skip AI analysis entirely "
            "(0-1; gate is 'anything to extract', not importance)."
        ),
        "group": "ai",
    },
    "ai_tool_evidence_required": {
        "label": "Tool Evidence Gate",
        "description": (
            "Only store an extracted tool when the model names who wielded it and quotes the "
            "sentence showing its use. Turn off if tool extraction stops finding anything."
        ),
        "group": "ai",
    },
    "ai_batch_max_requests": {
        "label": "Max Batch Size",
        "description": "Maximum entries per hourly analysis batch submission.",
        "group": "ai",
    },
    "ai_analysis_content_max_chars": {
        "label": "Analysis Content Cap",
        "description": "Characters of article text sent to entry_analysis (extraction quality plateaus early).",
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
            "Compute + store entry signals and priority scores without any UI change. "
            "Enable first; validate via GET /entries/triage?mode=signals for a week."
        ),
        "group": "intelligence",
    },
    "per_user_subscriptions_enabled": {
        "label": "Per-user feed subscriptions",
        "description": (
            "Each analyst manages their own feed list and mutes over the shared "
            "pool. Off: one shared list, mute affects everyone (legacy). The "
            "migration backfills every user as subscribed to every feed, so "
            "flipping this on changes nothing until someone unsubscribes."
        ),
        "group": "feeds",
    },
    "signal_engine_surface": {
        "label": "Signal Engine (surface)",
        "description": (
            "Surface signal scores in the UI: priority chips in the entry list "
            "and the signal-ranked Radar on the triage page."
        ),
        "group": "intelligence",
    },
    "radar_personalization_enabled": {
        "label": "Personalised Radar",
        "description": (
            "Let each analyst's own Radar thumbs re-rank their Priority Queue. Weights "
            "are fitted nightly per user and applied at read time as a lift on the "
            "shared score — the stored score stays global, and any analyst can switch "
            "back to the house ranking from their own Radar panel."
        ),
        "group": "intelligence",
    },
    "radar_personalization_min_samples": {
        "label": "Personalised Radar Min Votes",
        "description": (
            "Minimum verdicts one analyst must cast in a signal family before that "
            "family gets a personal weight. Below this the family stays neutral."
        ),
        "group": "intelligence",
    },
    "radar_personalization_window_days": {
        "label": "Personalised Radar Window (days)",
        "description": (
            "How far back the nightly fit looks for a user's verdicts. Longer than the "
            "global 30-day nudge window because one analyst votes far less than all of them."
        ),
        "group": "intelligence",
    },
    "signal_feedback_min_samples": {
        "label": "Signal Feedback Min Samples",
        "description": (
            "Minimum radar feedback verdicts a signal family needs in the 30-day "
            "window before its feedback nudge is applied. Below this, the nudge is "
            "skipped so a handful of votes can't swing scoring."
        ),
        "group": "intelligence",
    },
    "my_stack_exposure_enabled": {
        "label": "Vendor Watch",
        "description": (
            "Surface vulnerabilities in the vendors/products a user follows — float "
            "them in the Priority Queue and power the Vendor Watch board with "
            "detection-library coverage. Reuses the entity watchlist. Read-time and "
            "per-user — no rescore. Requires the Signal Engine surface to be on."
        ),
        "group": "intelligence",
    },
    "exposure_attack_visibility_enabled": {
        "label": "Vendor Watch: ATT&CK Detectability (heuristic)",
        "description": (
            "On the Vendor Watch board, for vulns with no detection rule, estimate "
            "whether the platform's telemetry could detect exploitation by mapping the "
            "CVE's co-occurring ATT&CK techniques to their data sources. Lower "
            "confidence than rule-backed coverage — the CVE→technique link is article "
            "co-occurrence, not a curated mapping."
        ),
        "group": "intelligence",
    },
    "entity_maintenance_mode": {
        "label": "Actor Refresh Mode",
        "description": (
            "'shadow' files the weekly actor-profile rewrite as a proposal in the maintenance log; "
            "'apply' writes the new description directly (the description history is the undo)"
        ),
        "group": "intelligence",
        "options": ["shadow", "apply"],
    },
    "assessment_backfill_batch_size": {
        "label": "Assessment Backfill: Batch Size",
        "description": (
            "Entities dispatched per daily run of the assessment backfill. They queue serially on "
            "the single-concurrency AI worker, so the batch paces itself — raise this to drain a "
            "backlog faster, lower it to leave more of the worker's time for ingest extraction."
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
            "Don't re-attempt an entity within this many days of its last attempt. Without it the "
            "highest-article-count entities are re-picked every run and starve the rest of the queue."
        ),
        "group": "intelligence",
    },
    "assessment_refresh_enabled": {
        "label": "Assessment Refresh",
        "description": (
            "Re-write assessments that have gone stale, not just missing ones. The backfill only "
            "picks entities with an empty description, so an entity assessed once is never "
            "revisited — its paragraph keeps describing the month it was written in. Only touches "
            "text this writer produced; analyst and enrichment descriptions are never overwritten."
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
        "label": "Reporting-Source Fold Threshold",
        "description": (
            "Vendors/products with specificity below this are treated as reporting sources and "
            "folded into a collapsed group on profile relationship views (0.0–1.0)."
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
            "Cluster each relationship's evidence articles into stories (via entry embeddings) so "
            "profile relationship views can distinguish 'recurring across N incidents' from "
            "scattered roundup co-mentions. Also adds a story floor to co-occurrence promotion and "
            "orders the adjudication queue. Requires embeddings coverage."
        ),
        "group": "intelligence",
    },
    "narrative_themes_enabled": {
        "label": "Narrative Themes",
        "description": (
            "Read the daily briefing's own `### Theme` grouping back out of its cached markdown "
            "and record which articles it placed together. Costs nothing — no AI call, no "
            "embeddings — and works as a standalone record until the gate below is switched on."
        ),
        "group": "intelligence",
    },
    "narrative_theme_gating": {
        "label": "Narrative Themes: Gate Promotion",
        "description": (
            "Let the briefing's grouping veto a co-occurrence promotion: a pair whose evidence "
            "all sits under one heading on one day is a single reporting wave, not corroboration. "
            "Leave off until a couple of weeks of themes have accumulated — with no parsed "
            "coverage the gate has no opinion and changes nothing."
        ),
        "group": "intelligence",
    },
    "relationship_story_threshold": {
        "label": "Evidence Story Threshold",
        "description": (
            "Cosine similarity for two evidence articles to count as the same story (0.0-1.0). "
            "Lower chains digests into incident clusters; higher splits incident coverage apart."
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
    # These were previously read through settings.get() against keys that existed
    # nowhere, so every lookup fell through to an inline default. Registering them
    # keeps those defaults and makes them settable.
    "actor_refresh_top_n_per_run": {
        "label": "Actor Refresh — Actors Per Run",
        "description": "Threat actor profiles the weekly AI refresh rewrites per run",
        "group": "maintenance",
    },
    "actor_refresh_min_age_days": {
        "label": "Actor Refresh — Minimum Age",
        "description": "Skip actors whose profile was AI-refreshed more recently than this many days",
        "group": "maintenance",
    },
    "actor_refresh_activity_window_days": {
        "label": "Actor Refresh — Activity Window",
        "description": "Lookback window (days) used to rank which actors count as most active",
        "group": "maintenance",
    },
    "actor_refresh_sample_n": {
        "label": "Actor Refresh — Headline Sample",
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
        "label": "Strength Weight — Corroboration",
        "description": "Share of relationship strength driven by how many independent articles assert it",
        "group": "intelligence",
    },
    "relationship_weight_closeness": {
        "label": "Strength Weight — Closeness",
        "description": "Share of relationship strength driven by in-article proximity",
        "group": "intelligence",
    },
    "relationship_weight_recency": {
        "label": "Strength Weight — Recency",
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
    "graph_max_claim_edges": {
        "label": "Graph Max Claim Edges",
        "description": "Cap on typed relationship edges per entity graph (trust-ranked; protects degenerate hubs)",
        "group": "intelligence",
    },
    "engine_run_retention_days": {
        "label": "Engine Run Retention",
        "description": "Days of engine bookkeeping kept (job runs, entry pipeline runs, AI request/batch rows)",
        "group": "retention",
    },
    "tts_cache_ttl_days": {
        "label": "Read-Aloud Audio TTL",
        "description": "Evict cached Piper audio not played within this many days (per-row TTLs still win)",
        "group": "retention",
    },
    "tts_cache_max_bytes": {
        "label": "Read-Aloud Cache Size Cap",
        "description": "LRU size cap for cached read-aloud audio (bytes); oldest-played files are evicted first",
        "group": "retention",
    },
    "telegram_media_ttl_days": {
        "label": "Telegram Media TTL",
        "description": "Delete downloaded Telegram media files older than this. Entries and extracted intel are kept",
        "group": "retention",
    },
    "translation_default_target": {
        "label": "Default Translation Target",
        "description": "Language code translated into when a feed does not set its own target (e.g. en)",
        "group": "translation",
    },
    "threat_brief_limit": {
        "label": "Threat Briefs Per Run",
        "description": "Open Threats-board rows given an AI story line per nightly run",
        "group": "content",
    },
    "embeddings_enabled": {
        "label": "Entry Embeddings",
        "description": (
            "Embed entries so the same story can be folded into one thread. "
            "Requires an embedding model on the Ollama host"
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
        "description": "At or above this, an article is folded as a re-report of an earlier one",
        "group": "threads",
    },
    "thread_merge_similarity": {
        "label": "Merge Similarity",
        "description": "Two overlapping threads this close in centroid are the same story and are folded into one",
        "group": "threads",
    },
    "thread_sweep_limit": {
        "label": "Entries Examined Per Sweep",
        "description": (
            "Entries the thread sweeper considers each run. Keep it above the number of articles "
            "published inside the gap window, or the newest arrivals never get looked at"
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
        "label": "Thread Spines Per Run",
        "description": "Threads given an AI-written spine per nightly run",
        "group": "threads",
    },
    "thread_signals_enabled": {
        "label": "Score From Threads",
        "description": (
            "Let a story thread answer the echo and convergence signals — a re-report is one the "
            "thread folded, corroboration is the thread's outlet count. Off uses entity overlap"
        ),
        "group": "threads",
    },
    "reddit_digest_min_entries": {
        "label": "Reddit Digest — Minimum Posts",
        "description": "Skip the daily digest when fewer than this many qualifying posts were collected",
        "group": "content",
    },
    "reddit_digest_max_entries": {
        "label": "Reddit Digest — Maximum Posts",
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
    "backup": "Backup",
    "public_rss": "Public RSS",
}

# Re-home settings into the Engine console sections that own the feature they
# tune. The metadata above historically lumped every intelligence-engine knob
# into one "intelligence" group, which dumped ~30 unrelated settings under the
# correlation stage. `group` is display-only — it decides which admin UI panel
# renders a setting and never touches its key, stored value, or backend
# consumers — so relocating here is purely cosmetic. Only true correlation /
# relationship-strength knobs stay in "intelligence" (the correlation stage).
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
    "adjudication_circuit_breaker_pct": "adjudication",
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
