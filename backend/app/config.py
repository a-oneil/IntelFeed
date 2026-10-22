import logging
import os

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_config_logger = logging.getLogger("app.config")

_INSECURE_DEFAULTS = {"changeme"}


class Settings(BaseSettings):
    # Environment
    env: str = "development"

    # Build stamp, baked into the image by scripts/ops/version.sh via compose
    # build args. Env-only on purpose: a value in system_settings would outlive
    # the image it describes and misreport what is actually running.
    app_version: str = "dev"
    git_sha: str = ""
    build_time: str = ""

    # Database
    postgres_host: str = "db"
    postgres_port: int = 5432
    postgres_db: str = "intelfeed"
    postgres_user: str = "intelfeed"
    postgres_password: str = "changeme"

    # Redis
    redis_url: str = "redis://redis:6379/0"

    # Meilisearch
    meili_url: str = "http://meilisearch:7700"
    meili_master_key: str = "changeme"
    # Hard ceiling on any single Meilisearch call. A paused or wedged container
    # still completes the TCP handshake and then never replies, so without this
    # the client blocks forever.
    meili_timeout: int = 30

    # Auth
    secret_key: str = "changeme"
    access_token_expire_minutes: int = 120
    refresh_token_expire_days: int = 7
    registration_enabled: bool = True

    # Signal engine (see planning/engine-plan.md)
    signal_engine_shadow: bool = True
    signal_engine_surface: bool = True
    per_user_subscriptions_enabled: bool = True
    signal_feedback_min_samples: int = 20
    # Per-user Radar personalisation — read-time lift from each analyst's own
    # thumbs (see services/radar_personalization.py). Off until enabled here.
    radar_personalization_enabled: bool = False
    radar_personalization_min_samples: int = 5
    radar_personalization_window_days: int = 90

    # My Stack exposure scoring (see planning/my-stack-exposure-scoring.md) —
    # per-user, read-time boost of CVEs that affect declared vendors/products.
    my_stack_exposure_enabled: bool = True
    # Phase 7: heuristic "could you detect it" via CVE → co-occurring ATT&CK
    # techniques → their data sources → telemetry. Lower confidence than rules.
    exposure_attack_visibility_enabled: bool = True

    # One-pass AI extraction (engine phase 4)
    ai_one_pass_enabled: bool = True
    ai_daily_budget_usd: float = 2.0
    ai_analysis_relevance_threshold: float = 0.15
    ai_tool_evidence_required: bool = True
    ai_batch_max_requests: int = 500
    ai_analysis_content_max_chars: int = 12000
    ai_use_batches: bool = True
    # Per-request cost estimate used to size a batch against the daily budget.
    ai_est_cost_per_request: float = 0.0024

    # Per-entry pipeline run logging (engine phase 5) — kill switch
    pipeline_run_logging_enabled: bool = True

    # Pipeline plans drive stage composition (engine phase 6); off = legacy Feed booleans
    pipeline_engine_enabled: bool = False

    # CORS
    cors_origins: list[str] = ["http://localhost:3000"]

    # Public base URL of the frontend (e.g. https://intelfeed.example.com), used to build
    # absolute in-app deep links (entry.app_url) that work in external posts like
    # Discord/Slack. Empty → relative links only.
    public_base_url: str = ""

    # Feed defaults
    default_feed_fetch_interval: int = 30  # minutes
    # Pause a feed whose fetches have answered HTTP 4xx for this many days
    # straight (0 disables). Only client errors count, so a quiet blog that
    # still answers 200 is never paused for being quiet.
    feed_auto_pause_days: int = 30

    # Encryption
    encryption_key: str = "changeme"
    encryption_key_previous: str = ""

    # Image proxy
    image_proxy_enabled: bool = True
    image_proxy_cache_dir: str = "data/image_cache"
    image_proxy_cache_ttl_days: int = 30
    image_proxy_max_size_bytes: int = 10 * 1024 * 1024  # 10MB

    # Rate limiting
    rate_limit_default_interval: float = 2.0  # seconds per domain
    rate_limit_overrides: dict[str, float] = {}

    # Polite fetching. Browser-like UA by default — many sites (CISA/gov, Cloudflare-
    # fronted blogs) return 403 to obvious bot user agents. Override via Settings > System.
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
    )

    # Database pool (API server)
    db_pool_size: int = 5
    db_max_overflow: int = 10

    # Database pool (Celery workers) — per-task engine, disposed after each task
    worker_db_pool_size: int = 3
    worker_db_max_overflow: int = 5

    # Backup
    backup_retention_days: int = 7

    # Sentry
    sentry_dsn: str = ""
    sentry_traces_sample_rate: float = 0.1
    sentry_profiles_sample_rate: float = 0.1

    # NVD API
    nvd_api_key: str = ""  # Get from https://nvd.nist.gov/developers/request-an-api-key
    cve_reenrich_batch_size: int = 150  # CVEs re-fetched from NVD per maintenance run

    # GitHub
    github_token: str = ""  # Shared GitHub PAT for repo monitoring (5,000 req/hr)
    # GitHub PoC scan: how many CVEs one run may search, and how long before a
    # CVE is eligible for a re-scan. The default batch is small without a token
    # because unauthenticated search 403s after ~10 requests/minute.
    github_poc_batch_limit: int = 0  # 0 = auto (300 with a token, 40 without)
    github_poc_rescan_days: int = 30
    github_repo_max_file_size_kb: int = 5120  # 5MB
    github_repo_default_interval_minutes: int = 1440

    # Telegram (channel ingestion)
    telegram_api_id: int = 0  # From https://my.telegram.org
    telegram_api_hash: str = ""  # From https://my.telegram.org
    telegram_session_path: str = "/data/telegram.session"  # Persistent volume mount
    telegram_max_media_size_mb: int = 25  # Skip media larger than this
    telegram_media_dir: str = "/app/data/telegram_media"  # Where downloaded media is stored
    telegram_media_ttl_days: int = 30  # Evict downloaded media files older than this (entries/text are kept)
    telegram_flood_sleep_threshold: int = 30  # Telethon auto-sleeps below this; we retry above
    telegram_ocr_enabled: bool = False  # Run OCR on downloaded images (requires tesseract binary)
    telegram_ocr_min_chars: int = 30  # Skip OCR results shorter than this — usually noise

    # Translation (LibreTranslate sidecar)
    libretranslate_url: str = "http://libretranslate:5000"
    libretranslate_api_key: str = ""  # Optional, only if LibreTranslate is configured to require keys
    translation_default_target: str = "en"
    translation_timeout_seconds: float = 30.0

    # Text-to-speech (Piper sidecar) — server-side read-aloud audio.
    # When enabled, "Read aloud" synthesizes a consistent voice once, caches the
    # MP3 on disk, and plays it everywhere (vs the per-OS browser Web Speech voice).
    tts_enabled: bool = True
    piper_url: str = "http://piper:5000"  # Piper sidecar HTTP endpoint
    # medium ≈6x faster than -high on CPU; -high times out on long articles.
    # lessac over ryan: ryan-medium's duration predictor rushes sentences that
    # combine spoken domains ("x dot org") with version numbers to ~2x speed.
    piper_voice: str = "en_US-lessac-medium"
    piper_timeout_seconds: float = 600.0  # headroom for long summaries under CPU contention (background)
    tts_media_dir: str = "/app/data/tts_media"  # generated MP3s (bind-mount, shared api+worker)
    tts_cache_ttl_days: int = 30  # evict audio not accessed within this window
    tts_cache_max_bytes: int = 2 * 1024 * 1024 * 1024  # 2GB LRU cap (disk is the binding constraint)
    # Cap synthesizable text: ~25k chars ≈ ~24 min audio / ~63MB WAV — bounds synth
    # time and keeps the piper WAV under the sidecar's 512M limit. Longer articles
    # are truncated (a multi-hour read-aloud helps no one, and a huge WAV OOMs piper).
    tts_max_text_chars: int = 25_000

    # Intelligence thresholds
    autolinker_min_name_length: int = 3
    autolinker_false_positive_names: str = (
        # Generic animal/nature words used as group name components
        "agent,storm,chaos,poison,ghost,hunter,shadow,razor,phantom,sniper,cobra,viper,dragon,tiger,eagle"
        ",wolf,bear,panda,buffalo,spider,kitten,jackal,leopard,lynx,ocelot,cheetah,flame,spark,night,dark"
        ",black,white,gold,iron,steel,rock,stone,cloud,rain,ice,fire,frost,dust,smoke,flash,bolt,blade"
        ",shield,hammer,target,anchor,beacon,signal"
        # Generic security/malware category words
        ",virus,worm,trojan,backdoor,rootkit,exploit,patch,update,release"
        # Common OS/software brand names that appear everywhere
        ",windows,office,server,mobile,chrome,safari,firefox,edge,linux,android,apple,amazon,google"
        ",microsoft,oracle,cisco,adobe,intel"
        # Windows built-in tools / network utilities — constant false positives
        ",cmd,net,reg,ping,ftp,arp,at,tor,route,netsh,certutil,wevtutil,schtasks,forfiles,dsquery,nbtstat"
        ",netstat,ipconfig,ifconfig,systeminfo,tasklist,attrib,expand,cipher"
        # Common-word / wrong-entity aliases (Malpedia alt_names + AI extraction)
        # that generated mass autolinker false positives. Only affects
        # actor/malware/country matching — vendors/products bypass this list, so
        # their real names (e.g. Norton the vendor) still match.
        ",page,free,lead,photo,mailto,proxy,readme,watchdog,jack,james,tokyo,soldier,volatile,coinminer"
        ",norton,setup.exe,banking trojans,financial malware,secure browser"
    )
    # Analyst hard blocks written by the reader's "Wrong? → never match this word"
    # action. Unlike `autolinker_false_positive_names` above (a curated vocabulary
    # list that vendor/product/tool/mitigation deliberately bypass, since their real
    # names are common brand words), these forms are blocked for EVERY entity type —
    # an analyst saying "stop matching this" has to actually stop it. Starts empty;
    # managed from the reader popover and Engine → Autolink.
    autolinker_blocked_surface_forms: str = ""
    # Names that are single short alpha-only words must appear capitalized in the original text
    # (as a proper noun) to avoid matching common English usage. Max word length for this rule.
    autolinker_ambiguous_name_max_length: int = 10
    # Maximum times an ambiguous name can appear in one article before it's skipped
    # (high repetition = common word usage, not a named entity reference)
    autolinker_ambiguous_max_occurrences: int = 3
    # Pending tier: actor/malware/tool/country matches whose only surface forms are
    # common English words (bundled dictionary) are held in pending_autolink_matches
    # instead of linking immediately; the one-pass AI analysis promotes or rejects
    # them. Disable to restore instant linking for dictionary-word names.
    autolink_pending_tier_enabled: bool = True
    observables_decay_enabled: bool = True
    observables_candidate_max: int = 200
    observables_ai_capture_mode: str = "capture"
    observables_analysis_tail_reserve: float = 0.4
    observables_publisher_ioc_enabled: bool = True
    observables_publisher_ioc_max_values: int = 2000
    observables_ai_capture_kinds: str = (
        "ipv4,ipv6,domain,url,uri_path,email,ja3,ja4,cert_fingerprint,md5,sha1,sha256,script"
    )
    observables_codeblock_skip_categories: str = "Security Advisories,Government / CERT"
    observables_publish_enabled: bool = False
    observables_publish_token: str = ""
    observables_publish_min_confidence: float = 0.6
    observables_publish_max_age_days: int = 90
    observables_publish_never_suffixes: str = ""
    # Entity creation guardrails (planning/entity-creation-guardrails.md).
    # Phase 1 normalized matching — only prevents duplicate creations, safe on.
    entity_resolution_normalized_match: bool = True
    # Phase 2 creation/alias gates: 'off' | 'shadow' (log would-block decisions
    # to the maintenance log, still create) | 'on' (enforce).
    entity_creation_gates: str = "on"
    # Adjudicate stage (post-analysis AI review; planning/ai-adjudication-stage.md).
    # 'off' | 'shadow' (file verdicts as proposals) | 'apply' (high-confidence
    # verdicts applied inline, the rest filed). Master switch — plans only subtract.
    adjudication_mode: str = "apply"
    adjudication_trigger: str = "all"  # all | created
    adjudication_max_per_hour: int = 0  # 0 = no ceiling; set one to cap spend or protect the ai queue
    adjudication_min_priority_score: float = 0.0  # 0 = no floor (keep it: junk comes from low-score CVE entries)
    adjudication_apply_min_confidence: str = "high"  # high | medium | low
    adjudication_circuit_breaker_pct: float = 0.5
    adjudication_content_max_chars: int = 8000
    adjudication_scope: str = "links,entities,relationships,observables"
    # ICS/OT context keywords — ICS-matrix (T0xxx) ATT&CK techniques are only
    # linked when the entry text matches one of these (comma-separated,
    # word-boundary matched). See app.intelligence.attack_catalog.
    attack_ics_context_keywords: str = (
        "ics,ot,scada,plc,plcs,hmi,dcs,rtu,modbus,dnp3,iec 61850,iec 62443,"
        "industrial,operational technology,industrial control,critical infrastructure,"
        "manufacturing,utilities,water treatment,pipeline,substation,safety instrumented"
    )
    # Entity assessment backfill (drafts descriptions for entities that have none)
    # Actor profile refresh: 'shadow' files the rewritten description as a
    # proposal, 'apply' writes it (ActorDescriptionHistory is the undo).
    entity_maintenance_mode: str = "shadow"
    assessment_backfill_batch_size: int = 50  # entities dispatched per daily run
    assessment_backfill_min_articles: int = 1  # minimum linked entries to be worth summarizing
    assessment_backfill_retry_days: int = 7  # don't re-attempt an entity within this many days
    assessment_refresh_enabled: bool = True  # also re-write assessments that have gone stale
    assessment_refresh_min_new_articles: int = 10  # half the writer's 20-article window turned over
    assessment_refresh_batch_size: int = 10  # own budget, never competes with the empty-description backfill
    # Weekly AI refresh of the most-active threat actor profiles. Defaults match
    # the values these knobs were hardcoded to before they became settings.
    actor_refresh_top_n_per_run: int = 20  # actors refreshed per weekly run
    actor_refresh_min_age_days: int = 60  # skip actors refreshed more recently than this
    actor_refresh_activity_window_days: int = 90  # window used to rank "most active"
    actor_refresh_sample_n: int = 20  # headlines sampled into the refresh prompt
    # Low-signal entity review sweep (flags for analyst review, never deletes).

    correlation_cache_ttl_seconds: int = 3600
    # Proximity correlation tuning
    proximity_default_score: float = 0.3
    proximity_decay_rate: float = 1.0
    proximity_strong_threshold: float = 0.7
    proximity_moderate_threshold: float = 0.3
    # Relationship strength (composite of corroboration / closeness / recency)
    relationship_corroboration_saturation: int = 8
    relationship_recency_half_life_days: int = 90
    relationship_weight_corroboration: float = 0.45
    relationship_weight_closeness: float = 0.40
    relationship_weight_recency: float = 0.15
    relationship_evidence_promote_count: int = 3
    # Minimum confidence for relationships to appear on display surfaces
    # (profiles, graphs, timelines): possible = show all, probable = hide
    # possible, confirmed = hide possible+probable. Engine management views
    # always show everything.
    relationship_min_confidence: str = "possible"
    # Specificity (IDF) damping: 0 = off, 1 = strength fully scaled by how
    # special the counterpart is (ubiquitous entities sink to ~0).
    relationship_specificity_weight: float = 0.5
    # Vendors/products below this specificity are folded as reporting sources.
    relationship_reporting_source_specificity: float = 0.45
    # Platform-wide default tier floor for pivot related lists (all/moderate/strong).
    relationship_min_tier_default: str = "all"
    # Evidence structure: cluster each edge's evidence entries into stories
    # via the entry embeddings, so relationship views can say "recurring
    # across N incidents" vs "scattered roundup co-mentions". Also gates the
    relationship_evidence_structure: bool = True
    narrative_themes_enabled: bool = True  # parse the briefing's grouping (free, no AI call)
    narrative_theme_gating: bool = False  # let it veto promotions — flip on once themes exist
    # Single-link join threshold for evidence story clustering (validated
    # empirically: 0.70 chains digests into incidents, 0.75 separates them).
    relationship_story_threshold: float = 0.75
    # Source reliability weighting — evidence from high-reliability feeds
    # (admiralty A/B) counts slightly more; D/E slightly less. C, F ("cannot
    # be judged") and unrated feeds are neutral (1.0).
    relationship_reliability_high_multiplier: float = 1.15
    relationship_reliability_low_multiplier: float = 0.85
    graph_max_neighbors_per_node: int = 30
    graph_max_claim_edges: int = 300
    # Feed intel-value scoring weights (normalized to sum 1.0 at compute time)
    feed_value_weight_entity_yield: float = 0.25
    feed_value_weight_entity_intro: float = 0.25
    feed_value_weight_correlation: float = 0.20
    feed_value_weight_detection: float = 0.15
    feed_value_weight_pir: float = 0.15
    # CVE risk tiering — EPSS score at/above which a CVE is considered high risk
    cve_epss_high_risk_threshold: float = 0.1

    # Detection-rule maintenance — CVEs/rules processed per backfill run.
    rule_attack_backfill_limit: int = 1500
    # Nightly Threats-board story lines — open rows given a brief per run.
    threat_brief_limit: int = 30
    # Engine bookkeeping retention (job_runs, pipeline runs, AI request rows).
    engine_run_retention_days: int = 30
    # Daily Reddit digest thresholds.
    reddit_digest_min_entries: int = 3  # below this, the digest is skipped
    reddit_digest_max_entries: int = 20  # cap on posts fed to the digest prompt

    # --- Embeddings & Story Threads ---
    # Embeddings are configured on their own rather than through an AI task
    # assignment: the sweeper is a bulk, non-generative job that must keep
    # running when every generative provider is paused or inactive.
    embeddings_enabled: bool = True
    embedding_model: str = "nomic-embed-text"
    # Blank falls back to the Ollama provider row's base_url, then OLLAMA_BASE_URL.
    embedding_base_url: str = ""
    embedding_batch_size: int = 32
    embedding_backfill_limit: int = 2000  # entries embedded per sweeper run
    # Story Threads — the clustering thresholds. Every one of these is a tuning
    # knob against live data; see app/intelligence/story_threads.py.
    thread_window_days: int = 21  # how far back an entry can still join a thread
    thread_dormancy_days: int = 14  # silence after which a thread stops accepting
    thread_gap_days: int = 5  # max quiet days between an article and the thread it joins
    thread_min_body_chars: int = 400  # below this an entry is a bulletin row, not an article
    thread_join_similarity: float = 0.84  # cosine to the nearest article already in the thread
    thread_join_similarity_no_entity: float = 0.90  # required when no entity is shared
    thread_seed_similarity: float = 0.84  # cosine between entries to start a thread
    thread_duplicate_similarity: float = 0.90  # at/above this an entry is an echo
    thread_merge_similarity: float = 0.92  # centroid similarity at which two threads are one story
    # Entries examined per sweep. Must stay comfortably above the number of
    # articles inside the gap window, or re-checks crowd out the newest arrivals
    # and today's pile never gets threaded — see _candidate_entries.
    thread_sweep_limit: int = 1500
    thread_min_entries: int = 3  # a pile of two is not a story
    thread_min_sources: int = 2  # distinct outlets, not feed rows
    thread_narrate_limit: int = 10  # threads given an AI spine per nightly run
    # When on, an entry's thread membership answers the feed_echo and
    # source_convergence signals instead of the entity-overlap probe. Off falls
    # back to the probe everywhere — the scoring behaviour before threads.
    thread_signals_enabled: bool = True

    # Webhooks
    webhook_allow_private_networks: bool = True

    # Public RSS feed (re-publishes aggregated entries via token-gated URL)
    public_rss_enabled: bool = False
    public_rss_per_feed_limit: int = 100
    public_rss_full_content: bool = True

    # Database SSL (enable in production for encrypted connections)
    postgres_ssl: bool = False

    # Global copilot: when true (default), /api/ai/copilot/stream dispatches the
    # Claude Code CLI run to the dedicated `claude_code` Celery worker
    # (celery-worker-ai, which owns the OAuth credentials volume) and relays the
    # streamed events back over Redis. This is the correct prod topology — the api
    # container never needs the CLI or credentials. Set false to run the CLI
    # in-process in the api container instead (only works where the api has the
    # CLI + credentials, e.g. a single-container dev box).
    copilot_worker_dispatch: bool = True

    @property
    def database_url(self) -> str:
        base = (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )
        return f"{base}?ssl=require" if self.postgres_ssl else base

    @property
    def database_url_sync(self) -> str:
        base = (
            f"postgresql://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )
        return f"{base}?sslmode=require" if self.postgres_ssl else base

    @field_validator("cors_origins")
    @classmethod
    def _validate_cors_origins(cls, v: list[str]) -> list[str]:
        env = os.getenv("ENV", "development").lower()
        if env == "production" and "*" in v:
            raise ValueError("Wildcard CORS origin ('*') is not allowed in production")
        return v

    @field_validator("postgres_password", "meili_master_key", "secret_key", "encryption_key")
    @classmethod
    def _reject_insecure_defaults(cls, v: str, info) -> str:
        if v in _INSECURE_DEFAULTS:
            env = os.getenv("ENV", "development").lower()
            if env == "production":
                raise ValueError(
                    f"{info.field_name} must not be '{v}' in production. "
                    "Set a strong secret via environment variable or .env file."
                )
            _config_logger.warning("Insecure default for %s — do not use in production", info.field_name)
        return v

    @field_validator("encryption_key")
    @classmethod
    def _validate_fernet_key(cls, v: str) -> str:
        if v in _INSECURE_DEFAULTS:
            return v  # Already warned above; skip Fernet check for dev default
        import base64

        try:
            decoded = base64.urlsafe_b64decode(v)
            if len(decoded) != 32:
                raise ValueError
        except Exception:
            raise ValueError(
                "encryption_key must be a valid 32-byte URL-safe base64-encoded Fernet key. "
                "Generate one with: "
                "python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'"
            )
        return v

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    def get(self, key: str) -> object:
        """Get a setting value, checking DB overrides first, then env/default."""
        # Lazy import to avoid circular dependency
        from app.services.system_settings import CONFIGURABLE_KEYS, get_setting_cached

        if key in CONFIGURABLE_KEYS:
            db_val = get_setting_cached(key)
            if db_val is not None:
                return db_val
        return getattr(self, key, None)


settings = Settings()
