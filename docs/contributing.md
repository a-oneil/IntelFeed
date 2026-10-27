# Contributing to IntelFeed

A guide for developers who just cloned the repo and want to contribute code.

**Before you start:** Read [CLAUDE.md](../CLAUDE.md) for concise conventions and commands. Read [setup.md](../setup.md) for production deployment details. This document focuses on *local development*.

**Contents**

- [TL;DR Quickstart](#tldr-quickstart)
- [Repo Tour](#repo-tour)
- [Local Development Setups (Three Options)](#local-development-setups-three-options)
  - [Full Docker (Recommended)](#full-docker-recommended)
  - [Hybrid (Docker for infra, native for code)](#hybrid-docker-for-infra-native-for-code)
  - [Fully Native (Uncommon)](#fully-native-uncommon)
- [Backend Development](#backend-development)
  - [Setup](#setup)
  - [Code Quality](#code-quality)
  - [Tests](#tests)
  - [Async Patterns](#async-patterns)
  - [Database Migrations](#database-migrations)
  - [Adding an Endpoint](#adding-an-endpoint)
  - [Celery Tasks](#celery-tasks)
- [Frontend Development](#frontend-development)
  - [Setup](#setup-1)
  - [Development Server](#development-server)
  - [Building & Checks](#building--checks)
  - [Adding a Page](#adding-a-page)
  - [TanStack Query Hooks](#tanstack-query-hooks)
  - [Zustand Store](#zustand-store)
  - [CSS Modules](#css-modules)
  - [Component Location Heuristics](#component-location-heuristics)
- [Tests](#tests-1)
  - [Backend Unit Tests](#backend-unit-tests)
  - [Frontend Unit Tests](#frontend-unit-tests)
  - [Frontend E2E Tests (Playwright)](#frontend-e2e-tests-playwright)
- [CI/CD](#cicd)
- [Database Migration Recipe](#database-migration-recipe)
  - [1. Edit the Model](#1-edit-the-model)
  - [2. Generate Migration](#2-generate-migration)
  - [3. Review & Edit](#3-review--edit)
  - [4. Test Locally](#4-test-locally)
  - [5. Commit](#5-commit)
- [Code Style & Conventions](#code-style--conventions)
  - [Backend](#backend)
  - [Frontend](#frontend)
- [Pre-commit Hooks](#pre-commit-hooks)
- [Branch & PR Workflow](#branch--pr-workflow)
  - [Branching](#branching)
  - [Commits](#commits)
  - [Pull Requests](#pull-requests)
- [Adding Feed Adapters / Enrichment Sources / AI Tasks / Automation](#adding-feed-adapters--enrichment-sources--ai-tasks--automation)
- [Debugging Tips](#debugging-tips)
  - [Backend](#backend-1)
  - [Frontend](#frontend-1)
  - [Workers & Search](#workers--search)
- [Local Data Seeding](#local-data-seeding)
- [Skills & CLI](#skills--cli)
  - [Claude Code Skills](#claude-code-skills)
- [Releasing & Deploying](#releasing--deploying)
- [Where to Ask for Help](#where-to-ask-for-help)
- [Next Steps](#next-steps)

## TL;DR Quickstart

```bash
git clone https://github.com/a-oneil/IntelFeed.git intelfeed
cd intelfeed

# Copy config and generate secrets
cp .env.example .env
openssl rand -hex 32                                                           # SECRET_KEY
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"  # ENCRYPTION_KEY
openssl rand -base64 24                                                        # POSTGRES_PASSWORD, MEILI_MASTER_KEY
# Edit .env with your generated values
# (Dev Redis runs without a password — REDIS_PASSWORD is prod-only; see .env.example.)

# Full Docker stack
docker compose -f docker-compose.dev.yml up

# Open http://localhost:3001 and register the first account
# (backed by POST /api/auth/register; registration can be disabled or
# invite-gated afterwards under Settings > Users)
```

Services: Frontend 3001, API 8000, Meilisearch 7700, PostgreSQL 5433, Redis 6380, LibreTranslate 5050, Piper (TTS) 5060.

> **Host ports vs service ports.** Those are the *host* ports `docker-compose.dev.yml` publishes; inside the Docker network each service keeps its own default (frontend 3000, PostgreSQL 5432, Redis 6379, LibreTranslate and Piper 5000). Run a service natively instead (the setups below) and you get the plain defaults — Vite on `localhost:3000`, Redis on `localhost:6379`. So `REDIS_URL=redis://localhost:6379/0` is right for a Redis you installed yourself, and wrong for the Docker one, which is on `localhost:6380`. Override a host port that's already taken with `FRONTEND_PORT`, `DB_PORT`, `REDIS_PORT`, `LIBRETRANSLATE_PORT` or `PIPER_PORT` in `.env`.

---

## Repo Tour

```
backend/              FastAPI app, SQLAlchemy models, Alembic migrations, Celery workers
frontend/             React + TypeScript, Vite, CSS Modules, TanStack Query + Zustand
intelfeed-skill/      Claude Code skill (187 tools for API access)
intelfeed-lite-skill/ Lightweight skill variant
docs/                 Architecture, domain deep-dives, feed adapters, automation, detection
                      (mounted read-only into the api container — rendered as the in-app docs)
scripts/              seed/ maintenance/ telegram/ ops/ dev/ archive/ (see scripts/README.md)
                      (mounted into the api container at /app/scripts)
docker-compose.dev.yml / docker-compose.prod.yml
Caddyfile             Reverse proxy + auto-TLS (production)
update.sh             Helper script for in-place prod updates
CLAUDE.md             Terse repo conventions (read first)
setup.md              Production deployment walkthrough (EC2 or any Linux host)
```

---

## Local Development Setups (Three Options)

### Full Docker (Recommended)

Everything in containers, fast feedback loop.

```bash
docker compose -f docker-compose.dev.yml up
```

**What runs where:**
- Frontend: Vite dev server at `localhost:3001` (hot reload, proxies `/api` to container)
- API: uvicorn at `localhost:8000` with auto-reload
- Celery workers (default queue + `celery-worker-ai` for the serialized `ai` queue), beat scheduler, Telegram listener in separate containers
- PostgreSQL, Redis, Meilisearch, LibreTranslate (translation, host port 5050), Piper (text-to-speech read-aloud, host port 5060) as named services
- All volumes mounted for live code reload

See diagram: [Dev stack services](diagrams/contributing-dev-stack.md)

**Hot reload:** Edit backend Python → uvicorn restarts. Edit frontend TypeScript/CSS → browser hot reload.

**Playwright e2e:** Run stack first, then:
```bash
cd frontend
pnpm exec playwright test
```
baseURL is `http://localhost:3001` (not 3000); Vite dev server runs on 3000 internally, but docker-compose exposes the container's 3000 port as host 3001.

Note: `@playwright/test` is not a `package.json` dependency — install it locally once before the first run (`pnpm add -D @playwright/test`, then `pnpm exec playwright install chromium`; don't commit the dependency change).

---

### Hybrid (Docker for infra, native for code)

Faster debugger attachment, pip-install iteration.

```bash
# Start database, cache, search only
docker compose -f docker-compose.dev.yml up db redis meilisearch

# In backend terminal (Python 3.14)
cd backend
python3 -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install --require-hashes --no-deps -r requirements-dev.lock
alembic upgrade head
uvicorn app.main:app --reload --port 8000

# In another terminal (Node 26)
cd frontend
pnpm install
pnpm dev  # runs on http://localhost:3000
```

**When to use:** Debugging with `debugpy`, tight pip-install loops, editor integrations (pytest discovery), hot module reload during Celery task development.

**Celery workers:** If you need them:
```bash
cd backend
celery -A app.workers.celery_app worker --loglevel=info
```

---

### Fully Native (Uncommon)

All services on host. Useful for editor integrations or when Docker isn't available.

Requires: PostgreSQL 16, Redis 7, Meilisearch v1.6 running locally.

```bash
# Point to local services in .env
POSTGRES_HOST=localhost
REDIS_URL=redis://localhost:6379/0
MEILI_URL=http://localhost:7700

# Backend
cd backend
pip install --require-hashes --no-deps -r requirements-dev.lock
alembic upgrade head
uvicorn app.main:app --reload --port 8000

# Frontend
cd frontend
pnpm install
pnpm dev
```

---

## Backend Development

### Setup

Python 3.14. Install dev dependencies:

```bash
cd backend
pip install --require-hashes --no-deps -r requirements-dev.lock
```

This installs all runtime + test dependencies (pytest, pytest-asyncio, pytest-cov, pytest-timeout, pytest-xdist, factory-boy, ruff) at the exact versions the images and CI use. Run commands from `backend/` so `app` imports from the checkout; the project itself is not installed as a package.

**Dependencies are locked.** `pyproject.toml` declares them; `requirements.lock` (runtime) and `requirements-dev.lock` (runtime + test toolchain) pin every package with hashes, and both images install from those files with `--require-hashes`. They are generated by `backend/lock.sh`, which needs [uv](https://docs.astral.sh/uv/):

```bash
./lock.sh                          # after editing pyproject.toml; keeps existing pins
./lock.sh --upgrade-package lxml   # move one package (e.g. for an advisory)
./lock.sh --upgrade                # refresh everything to the newest allowed versions
```

Commit the lockfiles with the change. CI re-runs `./lock.sh` and fails when the output differs, and `pip-audit` grades the lock itself. The production image installs only `requirements.lock`, so pytest, ruff and the compiler never ship.

**Python 3.14 only.** `backend/Dockerfile` is `python:3.14.9`, and every container that runs app code (api, celery-worker, celery-worker-ai, celery-beat, telegram-listener) is built from it. CI tests that one version; `requires-python` is `>=3.14`.

This used to be a 3.12/3.13/3.14 matrix, kept because two stdlib behaviour changes had bitten the codebase — `urllib.robotparser` moved the catch-all `*` group in 3.13 (`app/services/robots.py`), and `fnmatch.translate` changed its end anchor from `\Z` to `\z` in 3.14 (`app/adapters/github_content_types.py`). Both were found climbing *toward* 3.14, and both were fixed by deriving what they need at runtime instead of assuming a layout — so they stay correct on any version. Once 3.14 became the only runtime, the matrix was costing about a quarter of the repo's CI minutes to test interpreters nothing runs. Keep those two call sites version-agnostic; there is no matrix to keep green any more.

### Code Quality

```bash
# Check linting (E, F, I, UP rules)
ruff check .

# Format (reformat in-place)
ruff format .

# Format check only
ruff format --check .
```

CI runs `ruff check` + `ruff format --check` on every PR (see CI/CD below), but running them locally first is faster than waiting on a red build.

Line length: 120. Ruff's `target-version` is `py312`, deliberately behind the 3.14 runtime: bumping it turns on UP043 (25 findings) and changes formatter output across 45 files, so that reformat wants its own PR. See `pyproject.toml` for full ruff config.

### Tests

```bash
# Full suite (~40s)
pytest tests/ -q

# Parallel — each xdist worker gets its own test database
pytest -n auto tests/ -q

# Second concurrent session in the same checkout — claim separate test DBs
PYTEST_DB_SUFFIX=alt pytest tests/ -q

# Run all tests with coverage
pytest --cov=app tests/ -x -q

# Run a single file
pytest tests/test_security.py -x -q

# Run a single test
pytest tests/test_security.py::TestPasswordHashing::test_hash_password_returns_bcrypt_string -x

# Verbose output
pytest tests/ -v
```

If you're on the full-Docker setup (no local venv), run the same commands inside the api container from the repo root:

```bash
docker compose -f docker-compose.dev.yml exec api pytest --cov=app tests/ -x -q
```

**Async fixtures** (`conftest.py`): `db_session` (fresh schema in a `<db>_test` PostgreSQL database per test), `client` (async ASGI test client with dependency override), `test_user`/`admin_user` with `auth_headers`/`admin_headers`.

**Test DB:** Uses `_test` suffix on the main DB URL; under `pytest -n auto` each xdist worker appends its worker id so parallel runs never share schema, and `PYTEST_DB_SUFFIX=<x>` inserts a further suffix so a second concurrent session in the same checkout gets its own databases. Each test gets a fresh schema via `DROP SCHEMA public CASCADE / CREATE SCHEMA public` teardown.

**Seeding:** Use provided fixtures (`test_feed`, `test_category`, `test_entry`, `test_threat_actor`, `test_ttp`). `factory-boy` is installed with the dev extras if you want factories, though current tests build models directly.

### Async Patterns

All database operations use `AsyncSession`. Dependency injection via FastAPI:

```python
async def my_endpoint(db: AsyncSession = Depends(get_db), user = Depends(get_current_user)):
    result = await db.execute(select(MyModel))
    items = result.scalars().all()
    return items
```

**Celery + async:** Wrap with `run_async()` helper (defined in `app.workers.db`):

```python
@celery_app.task(bind=True, max_retries=3, soft_time_limit=600)
def my_task(self, user_id: str):
    run_async(process_user, user_id)
```

This maintains a per-worker event loop to avoid exhaustion.

### Database Migrations

Alembic in `backend/alembic/`. Migrations run automatically on API container startup via `entrypoint.sh` (if `RUN_MIGRATIONS=true`).

**Workflow:**

```bash
# After changing a model, auto-generate a migration
alembic revision --autogenerate -m "add_user_email_column"

# Review the generated SQL in backend/alembic/versions/
# Edit if needed (e.g. for complex logic or data transforms)

# Apply locally
alembic upgrade head

# Rollback one revision if needed
alembic downgrade -1
```

**Naming:** Auto-generated files are named `<rev>_<slug>.py`. Slugs are auto-derived from model changes. Ensure each file has a unique revision ID.

**Multiple heads:** If you merge branches with conflicting migrations, Alembic will raise `multiple heads`. Resolve via `alembic merge -m "merge head1 head2"` and review the merge commit in git log.

**Data migrations:** If a schema change is destructive (e.g., making a nullable column non-nullable), write manual migration logic in the revision file to backfill defaults before the `NOT NULL` constraint is applied.

### Adding an Endpoint

1. **Router file:** `backend/app/api/` (e.g., `backend/app/api/my_domain.py`)
2. **Pydantic schema:** `backend/app/schemas/` (request/response models)
3. **SQLAlchemy model:** `backend/app/models/`
4. **Service (optional):** `backend/app/services/` for complex logic

Example:

```python
# backend/app/api/items.py
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from sqlalchemy import select

from app.database import get_db
from app.models.item import Item
from app.schemas.item import ItemResponse, PaginatedResponse

router = APIRouter(prefix="/items", tags=["items"])

@router.get("", response_model=PaginatedResponse[ItemResponse])
async def list_items(skip: int = 0, limit: int = 10, db: AsyncSession = Depends(get_db)):
    query = select(Item).offset(skip).limit(limit)
    result = await db.execute(query)
    items = result.scalars().all()
    return {"items": items, "total": len(items)}
```

Register in `backend/app/main.py`:

```python
from app.api import items
app.include_router(items.router)
```

**Eager loading:** Use `selectinload()` to prevent N+1 queries:

```python
query = select(Item).options(selectinload(Item.related_entity))
```

**Error handling:** Raise `AppError(code="item_not_found", message="...")` for controlled responses. See `app/core/exceptions.py`.

**Pagination:** Use `PaginatedResponse[T]` generic, or offset/limit query params.

### Celery Tasks

Workers run from `backend/app/workers/celery_app.py`. Task decorator pattern:

```python
@celery_app.task(bind=True, max_retries=3, soft_time_limit=600)
def enrich_entry(self, entry_id: str):
    try:
        run_async(do_enrichment, entry_id)
    except Exception as exc:
        retry_delay = 2 ** self.request.retries
        raise self.retry(exc=exc, countdown=retry_delay)
```

**Options:**
- `bind=True`: Celery passes task instance as first arg (access to retry/request)
- `max_retries=3`: Max automatic retries on exception
- `soft_time_limit=600`: Kill task if it exceeds 600 seconds

**Beat schedule:** Periodic tasks are declared in `app/workers/job_registry.py` (`JOB_REGISTRY`). `build_beat_schedule()` assembles the Celery beat schedule from the registry — applying per-job overrides stored in Redis (editable via the UI) — and `celery_app.py` wires it in. Add a job by adding a registry entry:

```python
"refresh-my-data": {
    "task": "app.workers.my_tasks.refresh_my_data",
    "description": "What it does",
    "category": "maintenance",
    "default_schedule": {"type": "crontab", "minute": "*/30"},
},
```

**Inspect workers:** `celery -A app.workers.celery_app inspect active` / `scheduled` / `stats`.

---

## Frontend Development

### Setup

Node 26 and pnpm 10.31, the versions both frontend images use (pnpm's exact version is the `packageManager` field in `frontend/package.json`). Install:

```bash
cd frontend
pnpm install
```

### Development Server

```bash
pnpm dev
```

Runs on `http://localhost:3000` (or port from Vite config). Vite proxies `/api` to the API backend.

### Building & Checks

```bash
# TypeScript check + Vite build
pnpm build

# ESLint
pnpm lint

# Vitest unit tests
pnpm test

# Playwright E2E (requires running stack)
pnpm exec playwright test
```

CI runs the first three on every PR (see CI/CD below); Playwright is not yet wired into CI, so run it locally when you touch a user-facing flow.

### Adding a Page

1. Create component in `src/pages/YourPage.tsx`
2. Add lazy import + route in `src/App.tsx`:

```typescript
import { lazy } from 'react';
const YourPage = lazy(() => import('./pages/YourPage'));

// In <Routes>
<Route path="/your-page" element={<YourPage />} />
```

3. Choose layout (import at top of App.tsx):

```typescript
// In render, wrap with MainLayout or SidebarLayout
<MainLayout>
  <YourPage />
</MainLayout>
```

- **MainLayout:** Three-panel feed reader (sidebar feeds, center entries, right detail pane)
- **SidebarLayout:** Sidebar nav + main content area (used for tool pages like automation, detection, etc.)

### TanStack Query Hooks

API data fetching via TanStack Query v5. Custom hooks in `src/hooks/`:

```typescript
// src/hooks/useMyData.ts
import { useQuery } from '@tanstack/react-query';
import { apiClient } from '@/api/client';

export function useMyData(id: string) {
  return useQuery({
    queryKey: ['mydata', id],
    queryFn: async () => {
      const response = await apiClient.get(`/my-endpoint/${id}`);
      return response.data;
    },
    staleTime: 30 * 1000,  // 30 seconds
    retry: 1,
  });
}

// In component
const { data, isLoading, error } = useMyData(id);
```

**Cache invalidation:** After mutations:

```typescript
const queryClient = useQueryClient();
const mutation = useMutation({
  mutationFn: (data) => apiClient.post('/my-endpoint', data),
  onSuccess: () => {
    queryClient.invalidateQueries({ queryKey: ['mydata'] });
  },
});
```

**Paginated queries:** Use `useInfiniteQuery`:

```typescript
const { data, fetchNextPage, hasNextPage } = useInfiniteQuery({
  queryKey: ['items'],
  queryFn: async ({ pageParam = 0 }) => {
    const response = await apiClient.get('/items', { params: { skip: pageParam } });
    return response.data;
  },
  getNextPageParam: (lastPage, pages) => pages.length * 10,
});
```

### Zustand Store

Client state (auth, UI prefs, intelligence workspace) via Zustand. Stores in `src/stores/`:

```typescript
// src/stores/myStore.ts
import { create } from 'zustand';
import { persist } from 'zustand/middleware';

interface MyState {
  count: number;
  increment: () => void;
}

export const useMyStore = create<MyState>()(
  persist(
    (set) => ({
      count: 0,
      increment: () => set((state) => ({ count: state.count + 1 })),
    }),
    {
      name: 'my-store',  // localStorage key
    }
  )
);
```

Use in component:

```typescript
const { count, increment } = useMyStore();
```

Existing stores: `authStore` (tokens), `uiStore` (layout/view), `intelStore` (intelligence workspace), `playerStore` (audio playback).

### CSS Modules

Every component has co-located `.module.css`. No Tailwind; use CSS Modules + CSS variables for theming.

```typescript
// src/components/MyComponent.tsx
import styles from './MyComponent.module.css';

export function MyComponent() {
  return <div className={styles.container}>...</div>;
}
```

```css
/* src/components/MyComponent.module.css */
.container {
  padding: var(--spacing-2);
  background: var(--surface-primary);
  border-radius: var(--radius-sm);
}
```

**Theming:** Entity types have color variables (`--entity-actor`, `--entity-malware`, etc.). See `src/index.css` for all available variables. Themes are switched at runtime in the UI.

**Text contrast:** Use `applyTheme()` utility to auto-set text color based on background luminance (WCAG AA).

### Component Location Heuristics

- **Top-level:** Frequently reused (HeaderBar, Sidebar, etc.)
- **Subfolder:** Domain-specific
  - `src/components/feed/` — feed-related UI
  - `src/components/automation/` — automation rule builder
  - `src/components/triage/` — triage workflows
  - `src/components/widgets/` — reusable dashboard widgets

---

## Tests

### Backend Unit Tests

Location: `backend/tests/test_*.py`

Pattern:

```python
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

class TestMyFeature:
    @pytest.mark.asyncio
    async def test_my_endpoint(self, client: AsyncClient, test_user: User, db_session: AsyncSession):
        # Arrange: Set up fixtures
        entry = Entry(title="Test")
        db_session.add(entry)
        await db_session.flush()
        
        # Act: Call endpoint
        response = await client.get(f"/api/entries/{entry.id}", headers=auth_headers)
        
        # Assert: Check response
        assert response.status_code == 200
        assert response.json()["title"] == "Test"
```

**Mocking external services:** Use `unittest.mock.patch` or `pytest-mock`. Example (AI provider):

```python
from unittest.mock import patch

@patch('app.ai.providers.claude_provider.AsyncAnthropic')
async def test_ai_summarization(self, mock_anthropic, db_session, client):
    mock_anthropic.return_value.messages.create.return_value = "Summary"
    response = await client.post("/api/entries/summarize", json={"entry_id": "..."})
    assert response.status_code == 200
```

**Seeding test entities:** See fixtures in `conftest.py`. Extend with custom factories using `factory-boy`:

```python
from factory import Factory
from app.models.entry import Entry

class EntryFactory(Factory):
    class Meta:
        model = Entry
    
    title = factory.Faker('sentence')
    guid = factory.Faker('uuid4')
```

### Frontend Unit Tests

Location: `frontend/src/**/__tests__/*.spec.ts` or `.test.ts`

Tools: Vitest + React Testing Library.

Pattern:

```typescript
import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MyComponent } from '../MyComponent';

describe('MyComponent', () => {
  it('renders title', () => {
    render(<MyComponent title="Hello" />);
    expect(screen.getByText('Hello')).toBeInTheDocument();
  });

  it('calls onClick when button is clicked', async () => {
    const handleClick = vi.fn();
    render(<MyComponent onClick={handleClick} />);
    await userEvent.click(screen.getByRole('button'));
    expect(handleClick).toHaveBeenCalled();
  });
});
```

**Mocking API calls:** `src/test/setup.ts` only shims jsdom gaps (a working `localStorage` for zustand persist, `matchMedia`) — axios is not auto-mocked. Mock the API client per-test with `vi.mock`:

```typescript
vi.mock('@/api/client', () => ({
  apiClient: {
    get: vi.fn(() => Promise.resolve({ data: { items: [] } })),
  },
}));
```

**Zustand store tests:** Create a test store instance, reset between tests:

```typescript
it('updates count', () => {
  const { useTestStore } = create(() => ({ count: 0, inc: () => {} }));
  const { count, inc } = useTestStore();
  expect(count).toBe(0);
});
```

### Frontend E2E Tests (Playwright)

Location: `frontend/tests/e2e/*.spec.ts`

Config: `frontend/playwright.config.ts` (workers: 1, retries: 2 in CI).

Pattern:

```typescript
import { test, expect } from '@playwright/test';

test('user can log in', async ({ page }) => {
  // baseURL is localhost:3001
  await page.goto('/login');
  await page.fill('input[name="username"]', 'testuser');
  await page.fill('input[name="password"]', 'testpassword');
  await page.click('button[type="submit"]');
  await expect(page).toHaveURL('/');
});
```

**Before running:** Start the full Docker stack:

```bash
docker compose -f docker-compose.dev.yml up
```

Then (after the one-time `@playwright/test` install noted in the Full Docker section):

```bash
cd frontend
pnpm exec playwright test
```

Or for a specific test file:

```bash
pnpm exec playwright test tests/e2e/feeds.spec.ts
```

**Common flake fixes:**
- Wait for element visibility: `page.waitForSelector()`
- Use `page.goto(url, { waitUntil: 'networkidle' })`
- Increase timeout: `test.setTimeout(60000)`

**Coverage expectations:** Backend 70%+, frontend 50%+ for critical paths (auth, data fetching).

---

## CI/CD

GitHub Actions runs on every pull request and every push to `main`.

`.github/workflows/ci.yml` is the only workflow. A `changed?` job diffs the
branch and gates the rest, so a PR pays only for the areas it touched:

| Job | Runs when | What it runs | Services |
| --- | --- | --- | --- |
| **backend** | `backend/**` changed | `ruff check`, `ruff format --check`, alembic (one head, `upgrade head` on a fresh DB, then `downgrade -1` and re-apply), then the full `pytest` suite on Python 3.14 | PostgreSQL 16 + pgvector, Redis 7 |
| **frontend** | `frontend/**` changed | one `pnpm install --frozen-lockfile`, then `pnpm lint`, `pnpm build` (`tsc -b` is the type check), `pnpm test` | — |
| **images** | a file that feeds an image changed | builds the backend, frontend and db images (no push), then `docker compose config` over the dev and prod compose files | — |
| **security** | always; the audit steps are gated on the manifests | `gitleaks`, plus `pip-audit` / `pnpm audit` when a manifest moved | — |
| **CI** | always | aggregate gate — this is the one required check | — |

Each area is a single job running its checks in sequence rather than several
parallel ones. That is deliberate: Actions bills per job, rounded up to a whole
minute, so splitting `ruff`/`alembic`/`pytest` cost three per-job minimums and
three dependency installs to save about ninety seconds of wall clock. Expect
feedback in roughly four to six minutes, and read the failing *step* rather than
looking for a failing job.

CI tests Python 3.14 only — that is what `backend/Dockerfile` ships and what
every container running app code uses.

Notes:

- Secrets are never needed: `SECRET_KEY` and a Fernet `ENCRYPTION_KEY` are generated per run, so CI passes on pull requests from forks.
- Meilisearch has no service container — `conftest.py` patches the client off.
- `pnpm lint:css` (stylelint) is **not** in CI; its suppression baseline is stale (228 errors). Fix the baseline before adding it as a gate.
- Playwright E2E is **not** in CI — it needs the full Compose stack. Run it locally.

**Run locally before pushing:**

```bash
# Backend
cd backend && ruff check . && ruff format --check . && pytest --cov=app tests/

# Frontend
cd frontend && pnpm lint && pnpm build && pnpm test && pnpm exec playwright test
```

---

## Database Migration Recipe

Step-by-step: model → migration → verify → deploy.

### 1. Edit the Model

```python
# backend/app/models/my_model.py
class MyModel(Base):
    __tablename__ = 'my_model'
    id = Column(UUID, primary_key=True, default=uuid4)
    name = Column(String(255), nullable=False)
    description = Column(String, nullable=True)  # NEW
```

### 2. Generate Migration

```bash
cd backend
alembic revision --autogenerate -m "add_description_to_my_model"
```

This creates a file in `backend/alembic/versions/` with:

```python
def upgrade() -> None:
    op.add_column('my_model', sa.Column('description', sa.String(), nullable=True))

def downgrade() -> None:
    op.drop_column('my_model', 'description')
```

### 3. Review & Edit

Open the generated file. For complex logic or data backfills, add custom SQL:

```python
def upgrade() -> None:
    # Add column
    op.add_column('my_model', sa.Column('category_id', UUID, nullable=True))
    
    # Backfill with defaults before adding NOT NULL
    op.execute("UPDATE my_model SET category_id = '...' WHERE category_id IS NULL")
    
    # Now make it NOT NULL
    op.alter_column('my_model', 'category_id', existing_type=UUID, nullable=False)
```

### 4. Test Locally

```bash
alembic upgrade head
# Test app works
uvicorn app.main:app --reload

# Rollback to verify downgrade works
alembic downgrade -1
alembic upgrade head
```

### 5. Commit

Commit the migration file with the model changes:

```bash
git add backend/app/models/my_model.py backend/alembic/versions/...
git commit -m "add description to my_model"
```

On deploy, `entrypoint.sh` runs `alembic upgrade head` automatically.

---

## Code Style & Conventions

From [CLAUDE.md](../CLAUDE.md), plus observations:

### Backend

- **Async throughout:** All DB operations use `AsyncSession`. No blocking I/O in request handlers.
- **Comments only for why:** Code should be self-documenting. Comments explain non-obvious decisions or business logic.
- **Error handling:** Raise `AppError(code="...", message="...")` for user-facing errors. Let exceptions bubble for bugs (Sentry will catch).
- **Imports:** Alphabetical, grouped (stdlib, third-party, local).
- **File size:** Keep routers under 500 lines; split into multiple files if needed.
- **Naming:** `snake_case` for functions/variables, `PascalCase` for classes/models. Domain-specific prefixes for private functions (`_sync_feeds`).

### Frontend

- **Edit, don't create:** Modify existing components/hooks rather than adding new files unless structure requires it.
- **CSS Modules:** No inline styles. All styling in `.module.css` co-located with component.
- **Constants:** Define theme colors, breakpoints in `src/index.css` as CSS variables.
- **Error messages:** User-facing; brief and actionable.
- **Naming:** `camelCase` for components/functions. Component names PascalCase. Hook names start with `use` (TanStack Query + Zustand convention).

---

## Pre-commit Hooks

No pre-commit framework configured yet. Recommended local script before pushing:

```bash
#!/bin/bash
set -e

# Backend
cd backend
ruff check .
ruff format --check .
pytest --cov=app tests/ -q

# Frontend
cd ../frontend
pnpm lint
pnpm build

echo "✓ All checks passed!"
```

Save as `pre-push.sh`, make executable, run manually before `git push`.

---

## Branch & PR Workflow

### Branching

Branch off `main`:

```bash
git checkout main
git pull
git checkout -b feature/my-feature
```

Branch naming: `feature/`, `fix/`, `docs/`, `refactor/` prefixes.

### Commits

Commit message style (from recent git log):

```
add description to my_model
fix mobile sidebar scroll
update vendor descriptions for 50 new vendors
```

- First line: imperative mood, <50 chars, lowercase
- Body: explain why (not what) if non-obvious
- Multiple commits per PR OK; aim for logical units

### Pull Requests

No PR template yet. When pushing, include:

1. What changed (1-2 sentences)
2. Why (motivation, issue link if any)
3. Testing: what you tested and how

Rebase onto `main` before merging (or use "squash & merge" if many incremental commits).

---

## Adding Feed Adapters / Enrichment Sources / AI Tasks / Automation

These are complex subsystems. See focused docs:

- **Feed adapters:** `docs/adapters.md` — add a new RSS/YouTube/Telegram/etc. source
- **Enrichment sources:** `docs/automation-ai-enrichment.md` — enrich entities with external data
- **AI providers:** `docs/automation-ai-enrichment.md` — integrate Claude, OpenAI, Ollama, or custom
- **Automation rules:** `docs/automation-ai-enrichment.md` — rule-based filtering, tagging, PIR matching

Start with those docs. They have code examples and integration patterns.

---

## Debugging Tips

### Backend

**Logs:** Structured logging via structlog. JSON output in production, pretty-printed in dev.

```bash
docker compose -f docker-compose.dev.yml logs -f api
```

**Debugger (hybrid mode):** Install `debugpy` in your venv:

```bash
pip install debugpy
```

Add to your code:

```python
import debugpy
debugpy.listen(("0.0.0.0", 5678))
debugpy.wait_for_client()
```

Attach from VS Code or PyCharm. API container will wait for debugger on startup.

**JWT issues:** Check clock skew (server vs. client time). Expired tokens show in logs. Refresh token endpoint: `POST /api/auth/refresh`.

**Async errors:** Check for blocking I/O (requests library, file I/O) in async handlers. Use `httpx` for async HTTP, `aiofiles` for file ops.

**Celery worker inspection:**

```bash
# Inside container
celery -A app.workers.celery_app inspect active
celery -A app.workers.celery_app inspect scheduled
celery -A app.workers.celery_app inspect stats

# Redis lock leftovers (can block processing)
redis-cli KEYS "celery-lock*"
redis-cli DEL "celery-lock:key-name"
```

### Frontend

**TanStack Query devtools:** Install for local debugging:

```bash
pnpm add @tanstack/react-query-devtools --save-dev
```

Import in App:

```typescript
import { ReactQueryDevtools } from '@tanstack/react-query-devtools';
// In render: <ReactQueryDevtools initialIsOpen={false} />
```

**Zustand devtools:** Redux DevTools support (browser extension). Inspect store state changes.

**Source maps:** Vite generates source maps in dev mode. Check browser DevTools for mapped source lines.

**Common pitfalls:**
- **Stale closures in subscriptions:** Ensure dependencies are captured in useEffect's dependency array.
- **CSS variable cascade:** Override specificity if theme vars not applying. Check computed styles in DevTools.

### Workers & Search

**Stuck index:** Meilisearch can get stuck after crashes.

```bash
docker compose -f docker-compose.dev.yml exec meilisearch sh -c \
  'curl -X POST -H "Authorization: Bearer $MEILI_MASTER_KEY" "http://localhost:7700/tasks/cancel?indexUids=entries"'
```

Full reindex from UI: Settings > Engine ("Rebuild search index").

**DB slow queries:** Enable slow query logging in PostgreSQL:

```bash
docker compose -f docker-compose.dev.yml exec db psql -U intelfeed -d intelfeed
```

```sql
SET log_statement = 'all';
SET log_min_duration_statement = 100;  -- log queries > 100ms
-- pg_stat_statements needs shared_preload_libraries (not enabled in the dev
-- compose Postgres); if you enable it, sort by mean_exec_time:
-- SELECT * FROM pg_stat_statements ORDER BY mean_exec_time DESC;
```

---

## Local Data Seeding

All scripts live in [`scripts/`](../scripts/), grouped by purpose — [`scripts/README.md`](../scripts/README.md) indexes every one. Most use the app's models and session and run inside the api container: `./scripts` is bind-mounted to `/app/scripts` the same way `./docs` is, because the image only carries `./backend`. The `ops/` and `dev/` folders are the exception and run on the host.

A fresh install has countries and a baseline of ATT&CK techniques (migrations load them) but not the CWE catalog, vendors, products or actor attribution, so most entity types never link. Seed the reference entities first, in this order:

```bash
docker compose -f docker-compose.dev.yml exec api python scripts/seed/seed_all.py --dry-run
docker compose -f docker-compose.dev.yml exec api python scripts/seed/seed_all.py
```

`seed_all.py` runs all ten seeders in dependency order — countries, country aliases, sectors, MITRE ATT&CK, CWE catalog, vendors/products, vendor descriptions, CPE names, actor attribution, entity attributes. Each runs as a subprocess, so one failure can't poison another's session; on failure it stops and prints a `--only <steps>` command to resume. All ten support `--dry-run`, so `seed_all.py --dry-run` previews the whole set (~15s) without writing. `--offline` skips the four that download from MITRE and Wikipedia, `--list` shows the step names, and any seeder can still be run on its own.

Every one is idempotent, so re-run them any time to fill gaps — the last two only enrich entities that already exist, and are worth repeating once feeds have been ingesting for a while.

Maintenance passes use the same invocation, e.g.:

```bash
docker compose -f docker-compose.dev.yml exec api python scripts/maintenance/resanitize_entries.py
docker compose -f docker-compose.dev.yml exec api python scripts/maintenance/purge_invalid_relationships.py  # dry-run
```

**Create first user:** Register via the web UI at `http://localhost:3001` (backed by `POST /api/auth/register`) — the first registered account becomes the admin. Registration can be disabled or invite-gated afterwards under Settings → Users.

**Bootstrap feeds:** Upload OPML file via UI: Settings > Feeds > Import OPML. Or use CLI tool in `intelfeed-skill/`.

---

## Skills & CLI

### Claude Code Skills

Two zero-dependency Python skills let Claude interact with IntelFeed:

- **`intelfeed-skill/`** — full feature set (187 tools)
- **`intelfeed-lite-skill/`** — read-only variant (87 tools)

Both execute via `intelfeed-skill/scripts/intelfeed_cli.py`.

**Env vars:**

```bash
export INTELFEED_API_URL=http://localhost:8000  # or prod URL
export INTELFEED_USERNAME=your-username
export INTELFEED_PASSWORD=your-password
```

**Test locally:**

```bash
python3 intelfeed-skill/scripts/intelfeed_cli.py --list-tools
python3 intelfeed-skill/scripts/intelfeed_cli.py search_entries '{"query": "ransomware", "limit": 5}'
```

Update skills when the API schema or auth changes.

---

## Releasing & Deploying

**Local → Production:** See [setup.md](../setup.md) for one-time production deployment walkthrough.

**In-place upgrades:** On the prod server:

```bash
cd ~/intelfeed
./update.sh
```

This does `git fetch && git pull && docker compose -f docker-compose.prod.yml up --build -d`.

**Migrations:** Automatic on API startup. Monitor with `docker compose logs -f api`.

**Backup before major changes:**

```bash
./scripts/ops/backup.sh
# Creates timestamped backup in `./backups/`
```

---

## Where to Ask for Help

- **Issues:** Report bugs and request features on the repository's issue tracker
- **Docs:** Start with [CLAUDE.md](../CLAUDE.md) for conventions, [docs/architecture.md](architecture.md) for deep dives
- **PR reviews:** Ask questions in comments; maintainers provide guidance
- **Slack/Discord (if available):** For real-time questions during development

---

## Next Steps

1. Set up local dev environment (pick one of the three setups above)
2. Run tests locally: `pytest --cov=app tests/ -q` (backend) + `pnpm test` (frontend)
3. Make a small change (e.g., add a test, fix a typo) to verify workflow
4. Read a domain doc in `docs/` that matches your area of interest
5. Pick a small issue and submit a PR

Happy contributing!
