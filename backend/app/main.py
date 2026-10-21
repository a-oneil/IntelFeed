import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.exceptions import HTTPException

from app.config import settings
from app.core.exceptions import AppError, app_error_handler, http_error_handler, validation_error_handler
from app.core.logging import AuditLoggingMiddleware, RequestLoggingMiddleware, setup_logging
from app.core.metrics import PrometheusMiddleware
from app.core.rate_limit import RateLimitMiddleware
from app.core.security import get_current_user
from app.core.security_headers import SecurityHeadersMiddleware
from app.models.user import User

logger = logging.getLogger(__name__)

setup_logging()


def _init_sentry() -> None:
    """Sentry from the effective settings (Settings → System overrides the
    env). Runs at startup once the settings cache is warm; the SDK cannot be
    re-pointed afterwards, which is why the UI says these need a restart."""
    dsn = settings.get("sentry_dsn")
    if not dsn:
        return
    import sentry_sdk

    sentry_sdk.init(
        dsn=str(dsn),
        traces_sample_rate=float(settings.get("sentry_traces_sample_rate") or 0.0),
        profiles_sample_rate=float(settings.get("sentry_profiles_sample_rate") or 0.0),
        send_default_pii=False,
    )


async def _warm_settings() -> None:
    """Load the system_settings overrides into the in-process cache so
    `settings.get()` sees them from the first request, not the first time
    some endpoint happens to read a setting through the DB."""
    from app.database import async_session
    from app.services.system_settings import warm_settings_cache

    try:
        async with async_session() as db:
            await warm_settings_cache(db)
    except Exception:
        logger.warning("settings cache warm-up failed; env defaults apply until the first read", exc_info=True)


async def _seed_ai_tasks() -> None:
    """Ensure all built-in AI tasks exist and have default model assignments."""
    from sqlalchemy import delete, select, text

    from app.ai.prompts.defaults import (
        DEFAULT_ASSIGNMENT_CONFIGS,
        DEFAULT_MODEL_ASSIGNMENTS,
        DEFAULT_PROVIDER_TYPE_ASSIGNMENTS,
        SYSTEM_TASKS,
    )
    from app.ai.provisioning import pick_model
    from app.database import async_session
    from app.models.ai_provider import AIProvider as AIProviderModel
    from app.models.ai_task import AITask
    from app.models.ai_task_assignment import AITaskAssignment

    async with async_session() as db:
        # Serialize across gunicorn workers: the check-then-insert below is not
        # concurrency-safe, so on a deploy that adds a new system task all
        # workers race and hit duplicate-key on ai_tasks_name_key, crash-looping
        # startup. This transaction-level advisory lock is released automatically
        # on commit/rollback; late workers then observe the already-seeded state.
        await db.execute(text("SELECT pg_advisory_xact_lock(918273641)"))

        result = await db.execute(select(AITask).where(AITask.is_system.is_(True)))
        existing_tasks = {t.name: t for t in result.scalars().all()}
        system_task_names = {t["name"] for t in SYSTEM_TASKS}

        # Add new system tasks, update variables on existing ones
        for task_data in SYSTEM_TASKS:
            if task_data["name"] not in existing_tasks:
                db.add(
                    AITask(
                        name=task_data["name"],
                        display_name=task_data["display_name"],
                        description=task_data.get("description"),
                        category=task_data.get("category"),
                        default_prompt_template=task_data["default_prompt_template"],
                        default_system_template=task_data.get("default_system_template"),
                        output_schema=task_data.get("output_schema"),
                        variables=task_data.get("variables", []),
                        is_system=True,
                        is_deprecated=bool(task_data.get("deprecated")),
                        show_in_entry_actions=task_data.get("show_in_entry_actions", True),
                        # Entity-profile visibility mirrors the entry default
                        # unless the task data says otherwise.
                        show_in_entity_actions=task_data.get(
                            "show_in_entity_actions",
                            task_data.get("show_in_entry_actions", True),
                        ),
                    )
                )
            else:
                # Sync variables, default_prompt_template, default_system_template,
                # and output_schema for existing system tasks so prompt updates
                # ship on deploy. We do NOT touch user-created AIPromptTemplate
                # rows — those remain authoritative when present (see
                # get_active_prompt in app/ai/engine.py).
                existing = existing_tasks[task_data["name"]]
                new_vars = task_data.get("variables", [])
                if existing.variables != new_vars:
                    existing.variables = new_vars
                new_template = task_data.get("default_prompt_template")
                if new_template and existing.default_prompt_template != new_template:
                    existing.default_prompt_template = new_template
                new_system = task_data.get("default_system_template")
                if existing.default_system_template != new_system:
                    existing.default_system_template = new_system
                new_schema = task_data.get("output_schema")
                if new_schema is not None and existing.output_schema != new_schema:
                    existing.output_schema = new_schema
                new_deprecated = bool(task_data.get("deprecated"))
                if existing.is_deprecated != new_deprecated:
                    existing.is_deprecated = new_deprecated

        # Remove system tasks that are no longer defined
        from app.models.ai_result import AIResult

        for name, task in existing_tasks.items():
            if name not in system_task_names:
                # Delete associated ai_results first (FK has no CASCADE)
                await db.execute(delete(AIResult).where(AIResult.task_id == task.id))
                await db.delete(task)

        await db.flush()

        # Auto-create a 'claude_code' provider on first startup so the tasks
        # pinned to that provider type (DEFAULT_PROVIDER_TYPE_ASSIGNMENTS: the
        # copilot) have an assignment target. The provider only works once
        # OAuth credentials are bootstrapped (see setup.md section 14), but
        # seeding it now means the task assignment exists from day one.
        cc_provider_result = await db.execute(
            select(AIProviderModel).where(AIProviderModel.provider_type == "claude_code").limit(1)
        )
        cc_provider = cc_provider_result.scalar_one_or_none()
        if not cc_provider:
            cc_provider = AIProviderModel(
                name="Claude Code CLI",
                provider_type="claude_code",
                base_url=None,
                api_key_encrypted=None,
                models=["sonnet", "opus", "haiku"],
                is_active=True,
                config={"cli_path": "claude", "timeout_seconds": 180},
            )
            db.add(cc_provider)
            await db.flush()

        # Auto-create default model assignments for system tasks missing an assignment.
        # openai_compatible excluded: its model catalog is too varied to guess a safe default.
        provider_result = await db.execute(
            select(AIProviderModel)
            .where(
                AIProviderModel.is_active.is_(True),
                AIProviderModel.provider_type.not_in(["claude_code", "openai_compatible"]),
            )
            .limit(1)
        )
        default_provider = provider_result.scalar_one_or_none()

        # Refresh task list after potential additions
        all_tasks_result = await db.execute(select(AITask).where(AITask.is_system.is_(True)))
        all_tasks = {t.name: t for t in all_tasks_result.scalars().all()}

        assign_result = await db.execute(select(AITaskAssignment.task_id))
        assigned_task_ids = {row[0] for row in assign_result.all()}

        # Attribute new assignments to the system service account
        from app.services.system_user import get_system_user_id

        first_user = await get_system_user_id(db)

        # Deprecated tasks: keep rows + history, but force their assignments off
        deprecated_ids = [t.id for t in all_tasks.values() if t.is_deprecated]
        if deprecated_ids:
            from sqlalchemy import update as sa_update

            await db.execute(
                sa_update(AITaskAssignment)
                .where(AITaskAssignment.task_id.in_(deprecated_ids), AITaskAssignment.is_enabled.is_(True))
                .values(is_enabled=False)
            )

        if first_user:
            for task_name, task in all_tasks.items():
                if task.id in assigned_task_ids or task_name not in DEFAULT_MODEL_ASSIGNMENTS:
                    continue
                if task.is_deprecated:
                    continue
                # Tasks pinned to a provider type get that one; others use the default.
                required_type = DEFAULT_PROVIDER_TYPE_ASSIGNMENTS.get(task_name)
                if required_type == "claude_code":
                    chosen = cc_provider
                else:
                    chosen = default_provider
                if not chosen:
                    continue
                # The default names are Claude-family; pick_model resolves them
                # against what the chosen provider actually serves.
                model_name = pick_model(DEFAULT_MODEL_ASSIGNMENTS[task_name], chosen.models)
                db.add(
                    AITaskAssignment(
                        created_by=first_user,
                        task_id=task.id,
                        provider_id=chosen.id,
                        model_name=model_name,
                        is_enabled=True,
                        config=dict(DEFAULT_ASSIGNMENT_CONFIGS.get(task_name) or {}),
                    )
                )

        # Backfill new DEFAULT_ASSIGNMENT_CONFIGS keys onto pre-existing
        # assignments — additive only, never overwrites user-set values.
        # Lets us ship a new "max_tokens": 8192 (or similar) default for an
        # already-seeded task without requiring a manual DB tweak.
        existing_assignments_result = await db.execute(select(AITaskAssignment))
        all_assignments = list(existing_assignments_result.scalars().all())
        name_by_id = {t.id: name for name, t in all_tasks.items()}
        for assignment in all_assignments:
            task_name = name_by_id.get(assignment.task_id)
            if not task_name:
                continue
            defaults = DEFAULT_ASSIGNMENT_CONFIGS.get(task_name) or {}
            if not defaults:
                continue
            current = dict(assignment.config or {})
            changed = False
            for key, value in defaults.items():
                if key not in current:
                    current[key] = value
                    changed = True
            if changed:
                assignment.config = current

        try:
            await db.commit()
        except Exception:
            await db.rollback()


async def _seed_enrichment_sources() -> None:
    """Ensure all DEFAULT_SOURCES exist in the enrichment_sources table."""
    from sqlalchemy import select, text

    from app.database import async_session
    from app.enrichment.registry import DEFAULT_SOURCES
    from app.models.enrichment import EnrichmentSource

    async with async_session() as db:
        # Serialize across gunicorn workers (see _seed_ai_tasks) so a deploy that
        # adds a new default source doesn't race on the unique source_type key.
        await db.execute(text("SELECT pg_advisory_xact_lock(918273642)"))

        result = await db.execute(select(EnrichmentSource.source_type))
        existing = {row[0] for row in result.all()}

        for src in DEFAULT_SOURCES:
            if src["source_type"] not in existing:
                db.add(
                    EnrichmentSource(
                        source_type=src["source_type"],
                        display_name=src["display_name"],
                        is_enabled=False,
                        trigger_mode=src.get("default_trigger_mode", "manual"),
                        rate_limit_config=src.get("default_rate_limit", {}),
                        health_status="unknown",
                        config={},
                    )
                )
        try:
            await db.commit()
        except Exception:
            await db.rollback()


async def _sync_job_schedules_to_redis() -> None:
    """Sync job schedule overrides from DB to Redis on startup."""
    from sqlalchemy import select

    from app.database import async_session
    from app.models.system_setting import SystemSettings
    from app.workers.job_registry import write_overrides_to_redis

    async with async_session() as db:
        result = await db.execute(select(SystemSettings).where(SystemSettings.id == 1))
        row = result.scalar_one_or_none()
        if row and row.settings:
            overrides = row.settings.get("_job_schedule_overrides", {})
            if overrides:
                write_overrides_to_redis(overrides)


async def _warn_unknown_provider_types() -> None:
    """Flag any ai_providers row with a provider_type the engine doesn't
    route (can only happen via a manual DB edit — the create schema rejects
    anything else) so it doesn't fail silently on first use.
    """
    from sqlalchemy import select

    from app.database import async_session
    from app.models.ai_provider import AIProvider

    known = {"claude", "claude_code", "ollama", "openai_compatible", ""}
    async with async_session() as db:
        result = await db.execute(select(AIProvider.name, AIProvider.provider_type))
        for name, provider_type in result.all():
            if (provider_type or "").lower() not in known:
                logger.warning("AI provider %r has unrecognized provider_type %r", name, provider_type)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await _warm_settings()
    _init_sentry()
    await _seed_enrichment_sources()
    await _seed_ai_tasks()
    await _sync_job_schedules_to_redis()
    await _warn_unknown_provider_types()
    yield
    # Shutdown


# OpenAPI tag metadata, organized by app section. Order here controls the order
# tags appear in Swagger UI; the section grouping is emitted as x-tagGroups for
# ReDoc (Swagger UI has no group concept, so sections surface there as ordering).
_OPENAPI_TAG_GROUPS: list[tuple[str, list[tuple[str, str]]]] = [
    (
        "Reader",
        [
            ("entries", "Feed entries: listing, reading state, starring, bulk actions, and per-entry detail."),
            ("feeds", "RSS/adapter feed subscriptions: CRUD, refresh, mute, and health."),
            ("categories", "Feed categories used to group subscriptions in the sidebar."),
            ("tags", "User tags applied to entries."),
            ("search", "Full-text search over entries via Meilisearch, with query syntax support."),
            ("saved-searches", "Persisted search queries."),
            ("notes", "Free-form notes attached to entries."),
            ("comments", "Per-entry comment threads."),
            ("ingest", "Manual URL ingestion into the entry pipeline."),
            ("onboarding", "First-run readiness: is this instance seeded, polling and linking?"),
            ("opml", "OPML import/export of feed subscriptions."),
            ("podcasts", "Podcast episode listing and metadata."),
            ("playback", "Audio playback position sync."),
            ("tts", "Server-side text-to-speech audio for entries."),
            (
                "threads",
                "Story threads: an unfolding story as one narrative object — its spine, its "
                "member articles, and the re-reports folded underneath them.",
            ),
            ("telegram-media", "Media files mirrored from Telegram channels."),
            ("proxy", "Authenticated image proxy for entry content."),
            ("public-rss", "Unauthenticated outbound RSS feeds published by IntelFeed."),
        ],
    ),
    (
        "Entities & Intelligence",
        [
            (
                "intelligence",
                "Core intelligence entities: threat actors, malware, CVEs, TTPs, vendors, "
                "products, countries, and detection rules.",
            ),
            ("intelligence-feed", "Aggregated intelligence activity feed."),
            (
                "entity-profiles",
                "Unified entity profile pages: dossier, timeline, related entries, and per-entity analytics.",
            ),
            ("entity-relationships", "Typed entity-to-entity relationships with provenance and trust levels."),
            ("entity-links", "Entry-to-entity link management across all junction tables."),
            ("entity-notes", "Analyst notes attached to intelligence entities."),
            ("entity-maintenance", "Entity dedup, merge, conversion, and tombstone management."),
            ("extraction", "AI-created entity review: provenance, confirmation, and cleanup."),
            ("correlation", "Cross-entity pivoting, co-occurrence graphs, and timelines."),
            ("attack", "MITRE ATT&CK catalog: techniques, tactics, and coverage."),
            ("exposure", "Exposure view matching intelligence against the tracked vendor/product stack."),
            ("watchlist", "Entity watchlists with alerting."),
            ("glossary", "Security glossary terms surfaced in the reader."),
        ],
    ),
    (
        "Workbench",
        [
            ("campaigns", "Campaign tracking: membership, timelines, and campaign-level rollups."),
            ("intel-profiles", "Named report scopes (regions × verticals) and threat-surface matching."),
            ("intel-reports", "Analyst report builder and exports."),
            ("requirements", "Intelligence requirements and their coverage tracking."),
            ("dashboards", "User-configurable dashboards."),
            ("widgets", "Dashboard widget data endpoints (triage, detection, entities, ops, strategic)."),
            ("analytics", "Usage and content analytics."),
            ("telemetry-sources", "Telemetry source catalog for detection-rule requirements."),
            ("threat-board", "Intel → Rules: threats ranked by attention and new tradecraft."),
            ("coverage-workspace", "Per-threat detection coverage: intel, behaviours, prior rules, sets."),
            ("ransomware", "Ransomware victim tracker: leak-site victims, landscape stats, and sync."),
            ("hygiene", "Data hygiene: quality reports and cleanup candidates."),
        ],
    ),
    (
        "Engine & Pipeline",
        [
            ("engine", "Signal engine console: pipeline stages, scoring, and stage settings."),
            ("enrichment", "External enrichment sources and lookups."),
            ("link-validation", "AI validation of autolinker output."),
            ("false-positives", "False-positive reports for entity autolinking."),
        ],
    ),
    (
        "Automation",
        [
            ("automation", "Automation rules: triggers, conditions, actions, and run history."),
            ("webhook-presets", "Reusable webhook destinations for automation actions."),
            ("job-schedules", "Celery beat schedule overrides for background jobs."),
            ("events", "Server-sent events stream for live UI updates."),
        ],
    ),
    (
        "AI",
        [
            (
                "ai-providers",
                "AI provider configuration (Ollama, Claude API, Claude Code CLI, OpenAI-compatible endpoints).",
            ),
            ("ai-tasks", "AI task definitions and execution."),
            ("ai-prompts", "Prompt templates behind AI tasks."),
            ("ai-conversations", "Saved AI copilot conversations."),
            ("ai-results", "Stored AI analysis results."),
            ("ai-copilot", "Interactive AI copilot sessions."),
            ("ai-copilot-auth", "OAuth flow for the Claude Code copilot provider."),
        ],
    ),
    (
        "Sharing & Export",
        [
            ("sharing", "Public share links for entries and copilot sessions."),
            ("export", "Data export in CSV and Markdown formats."),
        ],
    ),
    (
        "System & Settings",
        [
            ("auth", "Registration, login, JWT refresh, and account management."),
            ("admin", "Admin user management."),
            ("system-settings", "Runtime system settings stored in the database."),
            ("themes", "UI theme gallery and custom themes."),
            ("telegram", "Telegram adapter session and channel management."),
            ("backup", "Database backup and restore."),
            ("logs", "Application log access."),
            ("documentation", "In-app documentation: the repo's docs/ markdown, served for the docs UI."),
            ("health", "Liveness/readiness probe."),
            ("metrics", "Prometheus metrics."),
            ("tools", "Misc operational tooling endpoints."),
        ],
    ),
]

_OPENAPI_TAGS = [{"name": name, "description": desc} for _, tags in _OPENAPI_TAG_GROUPS for name, desc in tags]

app = FastAPI(
    title="IntelFeed",
    version="0.1.0",
    description="Self-hosted RSS aggregation and threat intelligence platform.",
    openapi_tags=_OPENAPI_TAGS,
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    # Served explicitly below so the spec sits behind auth in every environment.
    openapi_url=None,
)


# ReDoc understands x-tagGroups; inject the app-section grouping into the spec.
_openapi_without_groups = app.openapi


def _openapi_with_tag_groups() -> dict:
    schema = _openapi_without_groups()
    schema["x-tagGroups"] = [
        {"name": section, "tags": [name for name, _ in tags]} for section, tags in _OPENAPI_TAG_GROUPS
    ]
    return schema


app.openapi = _openapi_with_tag_groups  # type: ignore[method-assign]


# API docs are reachable in production, but only usable by signed-in users.
#
# /docs and /redoc are plain shells (stock Swagger/ReDoc bundles, no secrets), so
# they are served to anyone. The spec itself requires a bearer token. Since the SPA
# and these routes share an origin, the shells read the caller's JWT out of the
# zustand-persisted "intelfeed-auth" localStorage blob and attach it — a browser
# navigation cannot carry an Authorization header on its own. An anonymous visitor
# gets the shell plus a 401 on the spec fetch, and sees the sign-in notice.
#
# To restrict this to operators, swap get_current_user for get_admin_user below.
# Note: do NOT reach for get_current_user_from_query here — it skips the token
# blacklist check, so revoked tokens would still authenticate.
_DOCS_TOKEN_JS = """
    function intelfeedToken() {
      try {
        var raw = window.localStorage.getItem('intelfeed-auth');
        if (!raw) return null;
        var parsed = JSON.parse(raw);
        return (parsed && parsed.state && parsed.state.accessToken) || null;
      } catch (e) {
        return null;
      }
    }
    function intelfeedAuthHeaders() {
      var t = intelfeedToken();
      return t ? { Authorization: 'Bearer ' + t } : {};
    }
    // The spec fetch and the renderer bootstrap share one promise chain, so tag
    // auth failures explicitly. Without this, anything that throws downstream --
    // a CDN bundle that 404s, a renderer crash -- reports itself as "not signed
    // in" and sends you hunting for a token problem that does not exist.
    function intelfeedCheckSpec(r) {
      if (r.status === 401 || r.status === 403) {
        var e = new Error('not signed in');
        e.intelfeedAuthError = true;
        throw e;
      }
      if (!r.ok) { throw new Error('spec fetch failed with HTTP ' + r.status); }
      return r.json();
    }
    function intelfeedDocsFailure(err) {
      if (err && err.intelfeedAuthError) {
        document.getElementById('if-auth-notice').style.display = 'block';
        return;
      }
      var box = document.getElementById('if-render-error');
      box.textContent = 'Could not render the API docs: ' + ((err && err.message) || err);
      box.style.display = 'block';
    }
"""

# The token lives in the SPA's localStorage, which is per-origin. Reaching these
# routes on the api's own port (dev: :8000) is a different origin from the app
# (dev: :3001), so no token is visible and the relative sign-in link would point at
# the api root. Vite proxies /docs, /redoc and /openapi.json, so the app origin
# serves them too — that is the URL to use. Prod has one origin and is unaffected.
_DOCS_SIGNIN_NOTICE = """
  <div id="if-auth-notice" style="display:none;font:14px/1.5 system-ui,sans-serif;
       padding:12px 16px;margin:16px;border:1px solid #b45309;border-radius:6px;
       background:#fef3c7;color:#7c2d12">
    <strong>Not signed in.</strong>
    <a href="/" style="color:#7c2d12">Sign in to IntelFeed</a> and reload this page.
    <div style="margin-top:6px;opacity:.85">
      Already signed in? Open these docs on the app's own origin — in local dev that is
      <code>http://localhost:3001/docs</code>, not the api port. The access token is stored
      per-origin, so it is not readable here.
    </div>
  </div>
  <div id="if-render-error" style="display:none;font:14px/1.5 ui-monospace,monospace;
       padding:12px 16px;margin:16px;border:1px solid #b91c1c;border-radius:6px;
       background:#fee2e2;color:#7f1d1d"></div>
"""

_DOCS_BACKLINK = """
  <div style="font:14px/1.5 system-ui,sans-serif;padding:10px 16px;
       border-bottom:1px solid #d0d7de;background:#f6f8fa;color:#24292f">
    <strong>IntelFeed API</strong>
    &nbsp;·&nbsp; <a href="/documentation" style="color:#0969da">Documentation</a>
    &nbsp;·&nbsp; <a href="/docs" style="color:#0969da">Swagger</a>
    &nbsp;·&nbsp; <a href="/redoc" style="color:#0969da">ReDoc</a>
    &nbsp;·&nbsp; <a href="/" style="color:#0969da">Back to app</a>
  </div>
"""

_SWAGGER_HTML = (
    """<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>IntelFeed API - Swagger UI</title>
  <link rel="icon" href="/favicon.svg">
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
</head>
<body>
"""
    + _DOCS_BACKLINK
    + _DOCS_SIGNIN_NOTICE
    + """  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
"""
    + _DOCS_TOKEN_JS
    + """
    // Fetch the spec here rather than handing Swagger a `url`: whether its
    // requestInterceptor covers the initial spec fetch varies by version, and an
    // unauthenticated spec load would render an empty, confusing page. Fetching
    // it explicitly makes the 401 path deterministic. The interceptor below still
    // applies to "Try it out" calls.
    fetch('/openapi.json', { headers: intelfeedAuthHeaders() })
      .then(intelfeedCheckSpec)
      .then(function (spec) {
        window.ui = SwaggerUIBundle({
          spec: spec,
          dom_id: '#swagger-ui',
          presets: [SwaggerUIBundle.presets.apis],
          // 60+ tags: start every section collapsed and give the tag list a
          // filter box, otherwise the landing page is thousands of rows long.
          docExpansion: 'none',
          filter: true,
          // Suppress the trailing "Schemas" dump — 381 models rendered expanded
          // below the operations, which is most of the page's height.
          defaultModelsExpandDepth: -1,
          // Show the example payload rather than the model tree by default.
          defaultModelRendering: 'example',
          deepLinking: true,
          displayRequestDuration: true,
          persistAuthorization: true,
          tryItOutEnabled: true,
          syntaxHighlight: { theme: 'obsidian' },
          requestInterceptor: function (req) {
            var headers = intelfeedAuthHeaders();
            if (headers.Authorization) { req.headers['Authorization'] = headers.Authorization; }
            return req;
          }
        });
      })
      .catch(intelfeedDocsFailure);
  </script>
</body>
</html>"""
)

_REDOC_HTML = (
    """<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>IntelFeed API - ReDoc</title>
  <link rel="icon" href="/favicon.svg">
  <meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body style="margin:0">
"""
    + _DOCS_BACKLINK
    + _DOCS_SIGNIN_NOTICE
    + """  <div id="redoc"></div>
  <!-- Pinned: redoc@next resolves to a 3.x rc that ships no standalone bundle (404). -->
  <script src="https://unpkg.com/redoc@2/bundles/redoc.standalone.js"></script>
  <script>
"""
    + _DOCS_TOKEN_JS
    + """
    // ReDoc cannot attach headers to its own spec fetch, so fetch it here and
    // hand ReDoc the parsed document instead of a URL.
    fetch('/openapi.json', { headers: intelfeedAuthHeaders() })
      .then(intelfeedCheckSpec)
      .then(function (spec) {
        Redoc.init(spec, {
          // 519 paths: native scrollbars keep the sidebar responsive.
          nativeScrollbars: true,
          expandResponses: '200,201',
          requiredPropsFirst: true,
          jsonSampleExpandLevel: 3,
          pathInMiddlePanel: true
        }, document.getElementById('redoc'));
      })
      .catch(intelfeedDocsFailure);
  </script>
</body>
</html>"""
)


@app.get("/openapi.json", include_in_schema=False)
async def openapi_spec(_user: User = Depends(get_current_user)) -> JSONResponse:
    """The OpenAPI spec — signed-in users only, in every environment."""
    return JSONResponse(app.openapi())


@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui() -> HTMLResponse:
    return HTMLResponse(_SWAGGER_HTML)


@app.get("/redoc", include_in_schema=False)
async def custom_redoc() -> HTMLResponse:
    return HTMLResponse(_REDOC_HTML)


# Middleware (outermost first — Starlette applies bottom-up)
app.add_middleware(RequestLoggingMiddleware)
app.add_middleware(AuditLoggingMiddleware)
app.add_middleware(PrometheusMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

# Exception handlers
app.add_exception_handler(AppError, app_error_handler)
app.add_exception_handler(RequestValidationError, validation_error_handler)
app.add_exception_handler(HTTPException, http_error_handler)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={"error": {"code": "internal_error", "message": "Internal server error", "details": []}},
    )


# Routers
from app.api.ai_conversations import router as ai_conversations_router
from app.api.ai_prompts import router as ai_prompts_router
from app.api.ai_providers import router as ai_providers_router
from app.api.ai_results import router as ai_results_router
from app.api.ai_tasks import router as ai_tasks_router
from app.api.analytics import router as analytics_router
from app.api.attack import router as attack_router
from app.api.auth import router as auth_router
from app.api.automation import router as automation_router
from app.api.backup import router as backup_router
from app.api.campaigns import router as campaigns_router
from app.api.categories import router as categories_router
from app.api.comments import router as comments_router
from app.api.copilot import router as copilot_router
from app.api.copilot_auth import router as copilot_auth_router
from app.api.correlation import router as correlation_router
from app.api.coverage_workspace import router as coverage_workspace_router
from app.api.dashboards import router as dashboards_router
from app.api.documentation import router as documentation_router
from app.api.engine import router as engine_router
from app.api.enrichment_api import router as enrichment_router
from app.api.entity_links import router as entity_links_router
from app.api.entity_merge import router as entity_merge_router
from app.api.entity_notes import router as entity_notes_router
from app.api.entity_profiles import router as entity_profiles_router
from app.api.entity_relationships import router as entity_relationships_router
from app.api.entries import router as entries_router
from app.api.events import router as events_router
from app.api.export import router as export_router
from app.api.exposure import router as exposure_router
from app.api.extraction import router as extraction_router
from app.api.false_positives import router as false_positives_router
from app.api.feeds import router as feeds_router
from app.api.glossary import router as glossary_router
from app.api.health import router as health_router
from app.api.hygiene import router as hygiene_router
from app.api.ingest import router as ingest_router
from app.api.intel_feed import router as intel_feed_router
from app.api.intel_profiles import router as intel_profiles_router
from app.api.intel_reports import router as intel_reports_router
from app.api.intelligence import router as intelligence_router
from app.api.job_schedules import router as job_schedules_router
from app.api.logs import router as logs_router
from app.api.metrics import router as metrics_router
from app.api.notes import router as notes_router
from app.api.onboarding import router as onboarding_router
from app.api.opml import router as opml_router
from app.api.playback import router as playback_router
from app.api.podcasts import router as podcasts_router
from app.api.proxy import router as proxy_router
from app.api.public_rss import router as public_rss_router
from app.api.publish import router as publish_router
from app.api.ransomware import router as ransomware_router
from app.api.requirements import router as requirements_router
from app.api.saved_searches import router as saved_searches_router
from app.api.search import router as search_router
from app.api.shared import router as shared_router
from app.api.system_settings import router as system_settings_router
from app.api.tags import router as tags_router
from app.api.telegram import router as telegram_router
from app.api.telegram_media import router as telegram_media_router
from app.api.telemetry_sources import router as telemetry_sources_router
from app.api.themes import router as themes_router
from app.api.threads import router as threads_router
from app.api.threat_board import router as threat_board_router
from app.api.tools import router as tools_router
from app.api.tts import router as tts_router
from app.api.users import router as users_router
from app.api.watchlist import router as watchlist_router
from app.api.webhook_presets import router as webhook_presets_router
from app.api.widgets import router as widgets_router
from app.api.widgets_board import router as widgets_board_router
from app.api.widgets_detection import router as widgets_detection_router
from app.api.widgets_entities import router as widgets_entities_router
from app.api.widgets_ops import router as widgets_ops_router
from app.api.widgets_strategic import router as widgets_strategic_router
from app.api.widgets_triage import router as widgets_triage_router

app.include_router(health_router, tags=["health"])
app.include_router(metrics_router, tags=["metrics"])
app.include_router(auth_router, prefix="/api/auth", tags=["auth"])
app.include_router(users_router, prefix="/api/admin/users", tags=["admin"])
app.include_router(feeds_router, prefix="/api/feeds", tags=["feeds"])
app.include_router(entries_router, prefix="/api/entries", tags=["entries"])
app.include_router(categories_router, prefix="/api/categories", tags=["categories"])
app.include_router(onboarding_router, prefix="/api/onboarding", tags=["onboarding"])
app.include_router(opml_router, prefix="/api/opml", tags=["opml"])
app.include_router(events_router, prefix="/api/events", tags=["events"])
app.include_router(proxy_router, prefix="/api/proxy", tags=["proxy"])
app.include_router(podcasts_router, prefix="/api/podcasts", tags=["podcasts"])
app.include_router(playback_router, prefix="/api/playback", tags=["playback"])
app.include_router(search_router, prefix="/api/search", tags=["search"])
app.include_router(saved_searches_router, prefix="/api/saved-searches", tags=["saved-searches"])
app.include_router(notes_router, prefix="/api/notes", tags=["notes"])
app.include_router(tags_router, prefix="/api/tags", tags=["tags"])
app.include_router(export_router, prefix="/api/export", tags=["export"])
app.include_router(false_positives_router, prefix="/api/false-positives", tags=["false-positives"])
app.include_router(ai_providers_router, prefix="/api/ai/providers", tags=["ai-providers"])
app.include_router(ai_tasks_router, prefix="/api/ai/tasks", tags=["ai-tasks"])
app.include_router(ai_prompts_router, prefix="/api/ai/prompts", tags=["ai-prompts"])
app.include_router(ai_conversations_router, prefix="/api/ai/conversations", tags=["ai-conversations"])
app.include_router(copilot_router, prefix="/api/ai/copilot", tags=["ai-copilot"])
app.include_router(copilot_auth_router, prefix="/api/ai/copilot-auth", tags=["ai-copilot-auth"])
app.include_router(intelligence_router, prefix="/api", tags=["intelligence"])
app.include_router(entity_merge_router, prefix="/api", tags=["entity-maintenance"])
app.include_router(automation_router, prefix="/api/automation", tags=["automation"])
app.include_router(webhook_presets_router, prefix="/api/webhook-presets", tags=["webhook-presets"])
app.include_router(themes_router, prefix="/api/themes", tags=["themes"])
app.include_router(dashboards_router, prefix="/api/dashboards", tags=["dashboards"])
app.include_router(widgets_router, prefix="/api/widgets", tags=["widgets"])
app.include_router(widgets_board_router, prefix="/api/widgets", tags=["widgets"])
app.include_router(widgets_detection_router, prefix="/api/widgets", tags=["widgets"])
app.include_router(widgets_entities_router, prefix="/api/widgets", tags=["widgets"])
app.include_router(widgets_ops_router, prefix="/api/widgets", tags=["widgets"])
app.include_router(widgets_strategic_router, prefix="/api/widgets", tags=["widgets"])
app.include_router(widgets_triage_router, prefix="/api/widgets", tags=["widgets"])
app.include_router(attack_router, prefix="/api/attack", tags=["attack"])
app.include_router(backup_router, prefix="/api/backup", tags=["backup"])
app.include_router(correlation_router, prefix="/api/intelligence", tags=["correlation"])
app.include_router(watchlist_router, prefix="/api/intelligence/watchlist", tags=["watchlist"])
app.include_router(ransomware_router, prefix="/api/ransomware", tags=["ransomware"])
app.include_router(exposure_router, prefix="/api/intelligence/exposure", tags=["exposure"])
app.include_router(engine_router, prefix="/api/engine", tags=["engine"])
# Outbound observable feeds (EDL/lookup/TAXII) — token-authed for external
# pullers, so mounted without the app auth dependency; /api/publish/status is
# the one route on it that uses normal user auth.
app.include_router(publish_router, prefix="/api", tags=["publish"])
app.include_router(comments_router, prefix="/api/comments", tags=["comments"])
app.include_router(entity_notes_router, prefix="/api/entity-notes", tags=["entity-notes"])
app.include_router(campaigns_router, prefix="/api/campaigns", tags=["campaigns"])
app.include_router(entity_profiles_router, prefix="/api/entities", tags=["entity-profiles"])
app.include_router(entity_relationships_router, prefix="/api/entity-relationships", tags=["entity-relationships"])
app.include_router(entity_links_router, prefix="/api/entity-links", tags=["entity-links"])
app.include_router(telemetry_sources_router, prefix="/api/telemetry-sources", tags=["telemetry-sources"])
app.include_router(threat_board_router, prefix="/api/threat-board", tags=["threat-board"])
app.include_router(threads_router, prefix="/api/threads", tags=["threads"])
app.include_router(coverage_workspace_router, prefix="/api/coverage-workspace", tags=["coverage-workspace"])
app.include_router(intel_profiles_router, prefix="/api/intel-profiles", tags=["intel-profiles"])
app.include_router(intel_reports_router, prefix="/api/intel-reports", tags=["intel-reports"])
app.include_router(enrichment_router, prefix="/api/enrichment", tags=["enrichment"])
app.include_router(intel_feed_router, prefix="/api/intelligence", tags=["intelligence-feed"])
app.include_router(requirements_router, prefix="/api/requirements", tags=["requirements"])
app.include_router(glossary_router, prefix="/api/glossary", tags=["glossary"])
app.include_router(documentation_router, prefix="/api/documentation", tags=["documentation"])
app.include_router(analytics_router, prefix="/api/analytics", tags=["analytics"])
app.include_router(tools_router, prefix="/api/tools", tags=["tools"])
app.include_router(ai_results_router, prefix="/api", tags=["ai-results"])
app.include_router(system_settings_router, prefix="/api/system-settings", tags=["system-settings"])
app.include_router(shared_router, prefix="/api", tags=["sharing"])
app.include_router(job_schedules_router, prefix="/api/job-schedules", tags=["job-schedules"])
app.include_router(hygiene_router, prefix="/api", tags=["hygiene"])
app.include_router(extraction_router, prefix="/api/engine/extraction", tags=["extraction"])
app.include_router(ingest_router, prefix="/api/entries", tags=["ingest"])
app.include_router(logs_router, prefix="/api", tags=["logs"])
app.include_router(telegram_media_router, prefix="/api/telegram-media", tags=["telegram-media"])
app.include_router(tts_router, prefix="/api/tts", tags=["tts"])
app.include_router(telegram_router, prefix="/api/telegram", tags=["telegram"])
app.include_router(public_rss_router, prefix="/api/public/rss", tags=["public-rss"])
