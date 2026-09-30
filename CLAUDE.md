# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

IntelFeed — a self-hosted, security-focused RSS aggregator and threat intelligence platform. Built for security analysts and detection engineers to consume threat feeds, extract TTPs/CVEs, correlate entities, and generate detection rules.

## Tech Stack

- **Backend:** Python 3.12+ / FastAPI / SQLAlchemy (async) / Alembic / Celery + Redis
- **Frontend:** React 18 / TypeScript / Vite / TanStack Query + Zustand / CSS Modules
- **Database:** PostgreSQL 16 (async via asyncpg)
- **Search:** Meilisearch v1.6
- **AI:** Model-agnostic provider system (Ollama, Claude, OpenAI, custom)
- **Package managers:** pip (backend), pnpm (frontend)

## Common Commands

### Docker (full stack)
```bash
docker compose -f docker-compose.dev.yml up        # Start all services
docker compose -f docker-compose.dev.yml down       # Stop all services
# API: localhost:8000, Frontend: localhost:3001, Meilisearch: localhost:7700
# PostgreSQL: localhost:5433, Redis: localhost:6380

# Create the first user via the register page at localhost:3001 (the first account becomes the admin)
# (backed by POST /api/auth/register; can be invite-gated under Settings > System)
```

Prod uses `docker-compose.prod.yml` with Caddy (`Caddyfile`) fronting for auto-TLS. `update.sh` at repo root is a one-shot `git fetch && pull && docker compose up --build -d` helper for production hosts. Full EC2 walkthrough lives in [setup.md](setup.md).

### Backend
```bash
cd backend
pip install -e ".[dev]"               # Install with dev dependencies
pytest tests/ -q                      # Full suite (~40s)
pytest -n auto tests/ -q              # Parallel; each worker gets its own test DB
PYTEST_DB_SUFFIX=alt pytest tests/ -q # Claim separate test DBs (concurrent sessions in one checkout)
pytest --cov=app tests/ -x -q         # Run tests with coverage
pytest tests/path/to/test_file.py     # Run a single test file
pytest tests/path/to/test_file.py::test_name -x  # Run a single test
ruff check .                          # Lint
ruff format --check .                 # Format check
ruff format .                         # Auto-format
alembic upgrade head                  # Run migrations
alembic downgrade -1                  # Rollback one migration
```

### Frontend
```bash
cd frontend
pnpm install                          # Install dependencies
pnpm dev                              # Dev server (port 3000)
pnpm build                            # TypeScript check + production build
pnpm test                             # Vitest unit tests (one-shot)
pnpm test:watch                       # Vitest in watch mode
pnpm lint                             # ESLint
pnpm exec playwright test             # E2E tests (needs running stack)
```

### CI
GitHub Actions is split one workflow per area, so a PR only pays for what it touched:

| Workflow | Runs when | Jobs |
| --- | --- | --- |
| `backend.yml` | `backend/**` changed | `ruff`, `pytest` (py3.12/3.13/3.14, PostgreSQL 16 + pgvector and Redis service containers), `alembic` (single head, fresh `upgrade head`, `downgrade -1` + re-apply) |
| `frontend.yml` | `frontend/**` changed | `eslint`, `vitest`, `type check & build` |
| `docker.yml` | A file feeding an image changed | Builds all three images, `compose config` on dev + prod |
| `security.yml` | Every PR (gitleaks); manifest changes + weekly (audits) | `gitleaks`, `pip-audit`, `pnpm audit` |

Each workflow starts with a `changes` job that diffs against the PR base and gates the rest on an `if:`. This is deliberately **not** `on.pull_request.paths` — a workflow filtered out at the `on:` level never reports a status at all, so a required check would sit pending forever. Every workflow also ends with an aggregate job named after the workflow (`Backend`, `Frontend`, `Docker images`, `Security`) that always reports; **those four are the ones to mark required in branch protection**, never the individual jobs. A push to `main` skips the filter entirely and runs everything.

Run the same checks locally first — `ruff check` + `ruff format --check` + `pytest` (backend), `pnpm lint` + `pnpm build` + `pnpm test` (frontend). Playwright E2E and `pnpm lint:css` are deliberately not in CI (`lint:css` has a stale suppressions baseline — re-run `pnpm lint:css:baseline` before wiring it up).

**Backend passes on Python 3.12, 3.13 and 3.14.** The images ship 3.14; the pytest job runs all three, because both version bugs found so far were stdlib behaviour changes that only appeared off the pinned version (`urllib.robotparser` group layout in 3.13, `fnmatch.translate`'s anchor spelling in 3.14).

**Security gates.** `gitleaks` scans every PR against `.gitleaks.toml`; that allowlist silences individual placeholders (example JWTs, `YOUR_TOKEN`, UUID entity ids), never whole files or rules — keep it that way or it stops catching anything. `pip-audit` resolves the backend tree fresh and blocks on any advisory except those in its documented `--ignore-vuln` list (today: `ecdsa`, unfixable upstream, reached only via JWT algorithms IntelFeed doesn't use). `pnpm audit --prod` blocks on high-severity advisories in shipped dependencies; dev-tree advisories are reported in the job summary but don't gate. Dependabot (`.github/dependabot.yml`) opens grouped weekly upgrade PRs.

### Utility Scripts

All scripts live in `scripts/`, grouped by purpose — see [`scripts/README.md`](scripts/README.md) for the full index and the fresh-install seed order.

Most use the app's models and session, so they run in the api container. `./scripts` is bind-mounted to `/app/scripts` (like `./docs`), since the image only carries `./backend`:
```bash
docker compose -f docker-compose.dev.yml exec api python scripts/<folder>/<script>.py
```
```
seed/         Reference data for a fresh install. `seed_all.py` runs all nine in
              dependency order (--dry-run to preview, --offline to skip downloads,
              --only/--skip to resume); each seeder also runs standalone.
maintenance/  Repeatable repair: CVE enrichment, search reconcile, re-sanitize, requirement
              re-match, relationship purge
telegram/     telegram_login.py / telegram_join.py (interactive — needs `exec -it`)
archive/      Completed one-shot backfills, kept for reference
```

`ops/` and `dev/` run on the host from the repo root instead:
```bash
scripts/ops/backup.sh | restore.sh        # pg_dump + gzip (7-day retention, Meili snapshot) / restore
scripts/ops/deploy.sh                     # Push main, run update.sh on prod host, verify health
scripts/ops/sync_prod_to_dev.sh           # Dump prod DB over SSH and restore into local dev stack
scripts/ops/cf-origin-lockdown.sh         # Restrict prod 80/443 to Cloudflare edge ranges
scripts/ops/version.sh                    # Source (don't run) before a build to stamp images with the commit
scripts/dev/sync_skill_clis.py            # Regenerate skill CLIs from the live tool registry
```
`deploy.sh` / `sync_prod_to_dev.sh` require `INTELFEED_PROD_HOST` — there is no default host.

## Architecture

### Backend (`backend/app/`)
- **`main.py`** — FastAPI app, middleware stack (logging, Prometheus, security headers, rate limiting, CORS), many routers, startup seeders for AI tasks and enrichment sources
- **`api/`** — API routers grouped by domain (feeds, entries, intelligence, automation, detection, etc.)
- **`models/`** — SQLAlchemy ORM models. Key domains: Feed/Entry, ThreatActor/Malware/CVE/TTP/Vendor/Product, DetectionRule, Campaign, AutomationRule, Dashboard
- **`schemas/`** — Pydantic request/response schemas with generic `PaginatedResponse[T]`
- **`services/`** — Thin business logic layer (search, dedup, sanitization, rate limiting, enrichment)
- **`workers/`** — Celery tasks: feed fetching, intel extraction, enrichment, automation, maintenance (beat-scheduled)
- **`intelligence/`** — Correlation engine, autolinker (Aho-Corasick), TTP/CVE extraction, detection rule extraction, reporting
- **`ai/`** — Pluggable AI provider abstraction
- **`search/`** — Meilisearch indexing and querying
- **`adapters/`** — External data source adapters (RSS, YouTube, Reddit, GitHub, NVD, Mastodon, Bluesky, Telegram). Telegram is the one adapter that requires out-of-band setup: an interactive `scripts/telegram/telegram_login.py` to write a persistent session file, plus `TELEGRAM_API_ID` / `TELEGRAM_API_HASH` env vars.
- **`automation/`** — Automation rule engine: triggers → conditions → actions, plus prompt templates and template variables
- **`enrichment/`** — Entity enrichment pipeline: source adapters behind a registry, per-source rate limiting, entity profile updates
- **`tools/`** — Tool registry (`TOOL_DEFINITIONS` + `execute_tool()`, registered via the `@_tool` decorator). Single source of truth for the skill CLIs — see IntelFeed CLI below. Registry tools execute under `get_current_user` via /api/tools/execute; destructive/global ones (entity merges, feed pool changes, automation-rule writes, extraction curation) must be listed in `ADMIN_TOOLS` in `app/tools/__init__.py`.
- **`intelligence/story_threads.py`** — Story threads: embeddings (pgvector) cluster an unfolding story into one narrative object with a spine. See [docs/story-threads.md](docs/story-threads.md).
- **`entity_types.py`** — Canonical entity-type vocabulary (one slug per type across API, DB columns, search, AI schemas). Import the constants; never type the strings.
- **`core/`** — Cross-cutting: logging (structlog), metrics (Prometheus), rate limiting, security (JWT/bcrypt), exceptions (`AppError`)
- **`config.py`** — Pydantic settings (reads `.env`); `get()` method checks system_settings DB table before env defaults
- **`database.py`** — Async SQLAlchemy session setup with `get_db()` dependency

### Frontend (`frontend/src/`)
- **`App.tsx`** — React Router v6 with React.lazy code splitting, two layout branches
- **`pages/`** — Page components (lazy-loaded)
- **`components/`** — Reusable UI components, each with co-located `.module.css`
- **`hooks/`** — Custom hooks (TanStack Query v5 wrappers for all API data, plus UI utilities)
- **`stores/`** — Zustand stores with localStorage persistence: `authStore` (JWT tokens), `uiStore` (layout/view prefs), `intelStore` (intelligence workspace state), `playerStore` (audio playback)
- **`api/client.ts`** — Axios instance with JWT injection, automatic token refresh on 401, global error handling
- **`utils/`** — Entity theming, date formatting, query parsing, pivot link generation
- **Layouts:** `MainLayout` (three-panel feed reader), `SidebarLayout` (tool pages)
- **Styling:** CSS Modules + CSS variables for theming (no Tailwind). Entity/domain color variables in `index.css`. Themes are switchable at runtime.

### Intelligence Engine (`backend/app/intelligence/`)
This is the most complex subsystem:
- **`autolinker.py`** — Aho-Corasick dictionary scans entry content for known entities (actors, malware, CVEs, TTPs, vendors, products, countries). Redis-versioned vocab for distributed workers. Configurable false positive filtering.
- **`correlation.py`** — Pivot queries across entity types via shared entries. Proximity scoring with paragraph-distance decay. Entity graph building and timeline construction.
- **`observables.py`** — The IOC ledger (observables entity type, `(kind, value)` identity). Hard rule: regex never creates a row — pattern scanning only stages entry-local candidates; rows come from judgment doors (one-pass AI `iocs` array, TTP observable upserts, curated `ioc_list` feeds, analyst promote) and known values are then sighted by exact match. Per-kind confidence decay (hashes/host artifacts never decay) runs nightly.
- **`rule_extraction.py`** — Extracts detection rules in 6 formats (Sigma, SPL, CrowdStrike QL, Elastic QL, KQL, YARA) with syntax validation.
- **`reporting.py`** — Report generation with customizable templates (Markdown/HTML render). Bundle export (CSV/ATT&CK layer) lives in `api/export.py`; outbound indicator feeds in `api/publish.py`.

### Database Migrations
Alembic migrations in `backend/alembic/`. Migrations run automatically on API container startup via `entrypoint.sh` (controlled by `RUN_MIGRATIONS=true`).

### Docker Services (dev)
db (PostgreSQL:5433, built from `db/Dockerfile` — postgres:16-alpine + pgvector) → redis (:6380) → api (FastAPI:8000 + auto-migrations) → celery-worker (default `celery` queue) + celery-worker-ai (`ai` queue) → celery-beat → telegram-listener → frontend (Vite:3001), plus meilisearch (:7700), libretranslate (:5050, article translation), and piper (:5060, read-aloud TTS). All services have health checks. Dev uses volume mounts for live reload; prod uses gunicorn with 4 workers + resource limits.

## Key Patterns

### Backend
- **Async throughout** — All database operations use `AsyncSession`. Celery tasks wrap async code via `run_async()` helper with a persistent per-process event loop.
- **Router pattern** — Dependency injection for `get_current_user` and `get_db`. All endpoints use Pydantic schemas. Eager loading via `selectinload()`. Pagination via offset/limit or cursor tokens. Admin-only operations use the `get_admin_user` dependency, and per-user rows enforce author-or-admin checks — new endpoints must follow this.
- **Custom exceptions** — `AppError` class with structured `{code, message, details}` responses. Handlers in `main.py`.
- **Config override chain** — `config.py` checks system_settings DB table first, then `.env` defaults. Many settings are editable via Settings > System UI.
- **Worker tasks** — `@celery_app.task(bind=True, max_retries=3, soft_time_limit=600)` pattern. Each task creates/disposes its own async DB engine to prevent connection exhaustion. Tasks that invoke an AI provider (link validation, entity maintenance, assessment backfill) are routed via `task_routes` in `celery_app.py` to the `ai` queue (formerly `claude_code`), served only by the celery-worker-ai container at concurrency 1 — it serializes AI calls (paces a single Ollama GPU; owns the CLI credentials volume for the claude_code provider). New AI-calling tasks must be routed there too.
- **Intelligence entities** use junction tables (`EntryTTP`, `EntryCVE`, `EntryVendor`, `EntryProduct`, etc.) for many-to-many with entries. Uniqueness constraints: TTP `technique_id`, CVE `cve_id`, ThreatActor `name`.

### Frontend
- **Server state via TanStack Query v5** — `useInfiniteQuery` for paginated lists, `useMutation` with cache invalidation. `staleTime: 30s`, `retry: 1`, `refetchOnWindowFocus: false`.
- **Client state via Zustand** — Three stores with `persist` middleware to localStorage. `uiStore` tracks layout, selections, view mode. `intelStore` tracks intelligence workspace navigation and enrichment queue.
- **CSS theming** — CSS variables in `:root` for colors, elevation, entity types. `applyTheme()` sets variables at runtime. Auto-contrast text via WCAG luminance. Entity-specific colors (`--entity-actor`, `--entity-malware`, `--entity-vendor`, `--entity-product`, etc.).
- **Code splitting** — All pages lazy-loaded via `React.lazy()`. Manual Vite chunks for vendor-react, vendor-tanstack, vendor-misc.
- **Key libraries** — @codemirror (code editing), @xyflow/react (entity graphs), react-grid-layout (dashboards), @tanstack/react-virtual (virtualized lists), sonner (toasts), dompurify (HTML sanitization).

### Testing
- **Backend** (`backend/tests/`): Pytest with async fixtures. `conftest.py` provides `db_session` (fresh schema per test), `client` (ASGI test client with dependency override), `test_user`/`admin_user` with `auth_headers`/`admin_headers`. Test DB uses same URL + `_test` suffix.
- **Frontend**: Vitest with jsdom + React Testing Library for unit tests (`src/**/__tests__/`). Playwright for E2E (`tests/e2e/`, baseURL `localhost:3001`, workers: 1, retries: 2 in CI).

## Environment Setup

Copy `.env.example` to `.env`. Key variables: `POSTGRES_*`, `REDIS_URL`, `MEILI_URL`, `MEILI_MASTER_KEY`, `SECRET_KEY`, `ENCRYPTION_KEY`. Most operational settings (AI providers, API keys, thresholds) are configurable in the web UI under Settings > System.

## IntelFeed CLI

`intelfeed-skill/scripts/intelfeed_cli.py` is a zero-dependency CLI tool (170 tools) that executes IntelFeed operations via the API. Used by Claude skills to interact with the platform.

```bash
# Single tool call
python3 intelfeed-skill/scripts/intelfeed_cli.py search_entries '{"query": "ransomware", "limit": 5}'

# Multiple tool calls (batched)
python3 intelfeed-skill/scripts/intelfeed_cli.py search_entries '{"query": "APT29"}' get_feeds '{"limit": 10}'

# List available tools
python3 intelfeed-skill/scripts/intelfeed_cli.py --list-tools
```

Requires env vars `INTELFEED_API_URL`, `INTELFEED_USERNAME`, `INTELFEED_PASSWORD` and the Docker stack running.

`intelfeed-lite-skill/` is the read-only variant (query/search/pivot tools only, no writes). Both CLIs are code-generated from the `backend/app/tools/` registry by `scripts/dev/sync_skill_clis.py` — regenerate instead of hand-editing them; `backend/tests/test_tool_registry_sync.py` fails on drift.

`intelfeed-mcp/` serves the same registry over MCP (stdio) for local models (LM Studio etc.): nine fixed tools, per-task playbooks in `intelfeed-mcp/skills/*.md` loaded on demand, results shaped to a ~2k-token budget, read-only unless `INTELFEED_MCP_ALLOW_WRITES` is set. It reads the live registry from `/api/tools/tools`; its offline copy `intelfeed-mcp/registry.json` is generated by the same sync script and drift-checked by the same test. See [intelfeed-mcp/README.md](intelfeed-mcp/README.md).

## Deeper Documentation

- [docs/architecture.md](docs/architecture.md) — full architecture reference beyond the summary above
- [docs/story-threads.md](docs/story-threads.md) — embeddings, thread clustering/merging, the spine, and its tuning knobs
- [docs/entity-profiles.md](docs/entity-profiles.md), [docs/entries.md](docs/entries.md) — domain deep-dives
- `planning/` (gitignored) — active phase plans (e.g. `vendor-product-entities.md`, `mobile-responsiveness.md`)
