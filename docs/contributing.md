# Contributing to IntelFeed

For developers who have cloned the repo and want to change the code. After reading it you can run the stack locally, run the same checks CI runs, add an endpoint, page or migration, and open a pull request.

Short repo conventions live in [CLAUDE.md](../CLAUDE.md). Production installs are in [setup.md](../setup.md). How to report bugs and what support to expect is in the root [contributing.md](../contributing.md).

**Contents**

- [Quickstart](#quickstart)
- [Repo Tour](#repo-tour)
- [Local Development Setups](#local-development-setups)
- [Backend Development](#backend-development)
- [Frontend Development](#frontend-development)
- [Tests](#tests)
- [CI](#ci)
- [Database Migration Recipe](#database-migration-recipe)
- [Code Style & Conventions](#code-style--conventions)
- [Branch & PR Workflow](#branch--pr-workflow)
- [Debugging Tips](#debugging-tips)
- [Local Data Seeding](#local-data-seeding)
- [Skills, CLI & MCP](#skills-cli--mcp)
- [Releasing & Deploying](#releasing--deploying)

## Quickstart

On your machine, from wherever you keep code:

```bash
git clone https://github.com/a-oneil/IntelFeed.git intelfeed
cd intelfeed
cp .env.example .env

# Generate secrets and paste them into .env
openssl rand -hex 32         # SECRET_KEY
openssl rand -base64 32 | tr '+/' '-_'   # ENCRYPTION_KEY (a Fernet key)
openssl rand -hex 24         # POSTGRES_PASSWORD, MEILI_MASTER_KEY

docker compose -f docker-compose.dev.yml up
```

Open <http://localhost:3001> and register. The first account becomes the admin. Dev Redis has no password, so leave `REDIS_URL` as it is in `.env.example`.

The dev stack publishes these ports on your machine:

| Service | Host port | Port inside Docker |
|---|---|---|
| Frontend (Vite) | 3001 | 3000 |
| API | 8000 | 8000 |
| PostgreSQL | 5433 | 5432 |
| Redis | 6380 | 6379 |
| Meilisearch | 7700 | 7700 |
| LibreTranslate | 5050 | 5000 |
| Piper (text-to-speech) | 5060 | 5000 |

If a host port is taken, change it with `FRONTEND_PORT`, `DB_PORT`, `REDIS_PORT`, `LIBRETRANSLATE_PORT` or `PIPER_PORT` in `.env`.

---

## Repo Tour

```text
backend/              FastAPI app, models, Alembic migrations, Celery workers, tests
frontend/             React + TypeScript (Vite, CSS Modules, TanStack Query, Zustand)
android/              Native Android client (see docs/android-app.md)
db/                   PostgreSQL 16 image with pgvector
piper/                Text-to-speech sidecar
intelfeed-skill/      Claude skill + CLI with every registry tool (196)
intelfeed-lite-skill/ Read-only skill + CLI (97 tools)
intelfeed-mcp/        MCP server for local models, over the same tool registry
docs/                 Documentation (also shown in the app; mounted into the api container)
scripts/              seed/ maintenance/ telegram/ ops/ dev/ (see scripts/README.md)
docker-compose.dev.yml, docker-compose.prod.yml
Caddyfile             Production reverse proxy and TLS
update.sh             Production update script
CLAUDE.md             Short repo conventions
setup.md              Production install walkthrough
```

---

## Local Development Setups

### Full Docker (Recommended)

Everything runs in containers:

```bash
docker compose -f docker-compose.dev.yml up
```

- **Frontend:** Vite at `localhost:3001`, with hot reload. It forwards `/api` to the api container.
- **API:** uvicorn at `localhost:8000`. It restarts when you save a backend file.
- **Workers:** `celery-worker` (the `celery` queue), `celery-worker-ai` (the `ai` queue, one task at a time), `celery-worker-enrichment` (the `enrichment` queue: the enrichment dispatcher), `celery-beat` and `telegram-listener`, each in its own container. They see your code through the same mount but **do not reload on their own**: after editing task code, run `docker compose -f docker-compose.dev.yml restart celery-worker celery-worker-ai celery-worker-enrichment`.
- **Data services:** PostgreSQL, Redis, Meilisearch, LibreTranslate and Piper.

Diagram: [Dev stack services](diagrams/contributing-dev-stack.md).

### Hybrid (Docker for data, your machine for code)

Useful for attaching a debugger or running pytest from your editor. Start only the data services:

```bash
docker compose -f docker-compose.dev.yml up db redis meilisearch
```

The backend reads `.env` from the folder it starts in, so give `backend/` its own copy and point it at the ports Docker publishes. `backend/.env` is gitignored. Inside the containers the compose `env_file` values still win, so this copy does not affect the Docker stack.

```bash
cd backend
cp ../.env .env
# In backend/.env set:
#   POSTGRES_HOST=localhost
#   POSTGRES_PORT=5433
#   REDIS_URL=redis://localhost:6380/0
#   MEILI_URL=http://localhost:7700

python3.14 -m venv venv
source venv/bin/activate
pip install --require-hashes --no-deps -r requirements-dev.lock
alembic upgrade head
uvicorn app.main:app --reload --port 8000
```

In a second terminal (Node 26, pnpm 10.31):

```bash
cd frontend
pnpm install
pnpm dev        # http://localhost:3000
```

Workers, if you need them (from `backend/`, venv active):

```bash
celery -A app.workers.celery_app worker --loglevel=info --queues=celery
```

You can also run PostgreSQL 16 (with pgvector), Redis 7 and Meilisearch v1.6 yourself instead of in Docker. Then use their normal ports (5432, 6379, 7700) in `backend/.env`.

---

## Backend Development

### Setup

Python 3.14. From `backend/`:

```bash
pip install --require-hashes --no-deps -r requirements-dev.lock
```

This installs the app's dependencies plus the test tools (pytest, pytest-asyncio, pytest-cov, pytest-timeout, pytest-xdist, factory-boy, ruff) at the exact versions CI and the images use. The project itself is not installed as a package, so run commands from `backend/` so that `app` imports from your checkout.

**Dependencies are locked.** You declare them in `pyproject.toml`. `requirements.lock` (runtime) and `requirements-dev.lock` (runtime plus test tools) pin every package with hashes. Regenerate them with `backend/lock.sh`, which needs [uv](https://docs.astral.sh/uv/):

```bash
./lock.sh                          # after editing pyproject.toml; keeps existing pins
./lock.sh --upgrade-package lxml   # move one package, e.g. for an advisory
./lock.sh --upgrade                # move everything to the newest allowed version
```

Commit the lockfiles with your change. CI re-runs `./lock.sh` and fails if the output differs. The production image installs only `requirements.lock`, so test tools never ship.

**Only Python 3.14 is supported.** `backend/Dockerfile` is `python:3.14.9`, every container that runs app code is built from it, and CI tests only that version (`requires-python = ">=3.14"`). Two places depend on standard-library details that changed between versions, and work them out at run time instead of assuming: `urllib.robotparser` group handling (`app/services/robots.py`) and `fnmatch.translate` output (`app/adapters/github_content_types.py`). Keep them that way.

### Code Quality

From `backend/`:

```bash
ruff check .            # lint (rules E, F, I, UP)
ruff format --check .   # check formatting
ruff format .           # fix formatting
```

Line length is 120. Ruff's `target-version` stays at `py312` on purpose: moving it to 3.14 turns on a new rule with 25 findings and reformats 45 files, which should be its own PR. The full config is in `backend/pyproject.toml`.

### Tests

From `backend/`:

```bash
pytest tests/ -q                       # full suite (about 40 s)
pytest -n auto tests/ -q               # in parallel; each worker gets its own test database
PYTEST_DB_SUFFIX=alt pytest tests/ -q  # separate test databases for a second session in the same checkout
pytest --cov=app tests/ -x -q          # with coverage, stop at the first failure
pytest tests/test_security.py          # one file
pytest tests/test_security.py::TestPasswordHashing::test_hash_password_returns_bcrypt_string   # one test
```

On the full-Docker setup, run them in the api container from the repo root:

```bash
docker compose -f docker-compose.dev.yml exec api pytest tests/ -q
```

The fixtures and test database are described under [Backend Tests](#backend-tests).

### Async Patterns

All database work uses `AsyncSession`. Endpoints get the session and the user through FastAPI dependencies:

```python
async def list_things(db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    result = await db.execute(select(Thing))
    return result.scalars().all()
```

Celery tasks are synchronous, so they run async code with `run_async()` from `app.workers.db`, passing it a coroutine. It keeps one event loop per worker process. Inside the coroutine, open a session with `worker_session()`, which creates and disposes its own engine so tasks never exhaust the connection pool.

```python
from app.workers.db import run_async, worker_session

@celery_app.task(bind=True, max_retries=3, soft_time_limit=600)
def refresh_thing(self, thing_id: str):
    run_async(_refresh_thing(thing_id))

async def _refresh_thing(thing_id: str):
    async with worker_session() as db:
        ...
```

### Database Migrations

Migrations live in `backend/alembic/`. The API container applies them on start (`entrypoint.sh`, when `RUN_MIGRATIONS=true`). Step by step: [Database Migration Recipe](#database-migration-recipe).

### Adding an Endpoint

1. **Router:** a file in `backend/app/api/`.
2. **Schemas:** Pydantic request and response models in `backend/app/schemas/`.
3. **Model:** SQLAlchemy in `backend/app/models/`, if you need a table.
4. **Logic:** anything bigger than a query goes in `backend/app/services/`.
5. **Register it** in `backend/app/main.py` with its prefix, e.g. `app.include_router(things_router, prefix="/api/things", tags=["things"])`.

```python
# backend/app/api/things.py
from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.pagination import PaginatedResponse
from app.core.security import get_current_user
from app.database import get_db
from app.models.thing import Thing
from app.models.user import User
from app.schemas.thing import ThingResponse

router = APIRouter()

@router.get("", response_model=PaginatedResponse[ThingResponse])
async def list_things(
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """List things, newest first."""
    total = await db.scalar(select(func.count()).select_from(Thing))
    rows = (await db.execute(select(Thing).offset(offset).limit(limit))).scalars().all()
    return PaginatedResponse(items=rows, total=total, limit=limit, offset=offset, has_more=offset + len(rows) < total)
```

Rules every endpoint follows:

- **Access.** Use `get_current_user` for signed-in users and `get_admin_user` for admin-only actions. Rows that belong to one user need an author-or-admin check.
- **Public read-only mode.** A route that signed-out visitors may read takes `get_viewer` (or `get_entry_viewer` for an `{entry_id}` route) and must be added to `VISITOR_ROUTES` in `backend/tests/test_public_read_only.py`. See [public-read-only-mode.md](public-read-only-mode.md).
- **Errors.** Raise `AppError(code="thing_not_found", message="...", status_code=404)` from `app/core/exceptions.py`. It returns `{"error": {"code", "message", "details"}}`.
- **Eager loading.** Load related rows with `selectinload()` to avoid one query per row.
- **Pagination.** Return `PaginatedResponse[T]` (offset and limit) or `CursorPaginatedResponse[T]` (cursor), both in `app/core/pagination.py`.
- **Tools.** To expose the action to the skill CLIs and the copilot, add it to the tool registry in `backend/app/tools/` with the `@_tool` decorator. Destructive or instance-wide tools go in `ADMIN_TOOLS` in `app/tools/__init__.py`. Then regenerate the CLIs with `python3 scripts/dev/sync_skill_clis.py`; `backend/tests/test_tool_registry_sync.py` fails if you forget.
- **Settings.** A new setting must be registered in `CONFIGURABLE_KEYS` (`app/services/system_settings.py`). `settings.get()` on a key that is not registered never sees the value saved in the UI.

### Celery Tasks

Tasks live in `backend/app/workers/` and use this pattern:

```python
@celery_app.task(bind=True, max_retries=3, soft_time_limit=600)
def enrich_entry(self, entry_id: str):
    try:
        run_async(_enrich_entry(entry_id))
    except Exception as exc:
        raise self.retry(exc=exc, countdown=2 ** self.request.retries)
```

- `bind=True` passes the task itself as `self`, for `self.retry` and `self.request`.
- `max_retries=3` caps automatic retries.
- `soft_time_limit=600` raises `SoftTimeLimitExceeded` inside the task after 600 seconds.

**Tasks that call an AI provider must run on the `ai` queue.** Add them to `task_routes` in `backend/app/workers/celery_app.py`. Only `celery-worker-ai` serves that queue, one task at a time. An AI task left on the default queue can starve feed ingestion.

**Scheduled jobs** are declared in `JOB_REGISTRY` in `backend/app/workers/job_registry.py`. `build_beat_schedule()` turns the registry into the beat schedule and applies any schedule changes made in the UI. Add a job with an entry like:

```python
"refresh-my-data": {
    "task": "app.workers.my_tasks.refresh_my_data",
    "description": "What it does",
    "category": "maintenance",
    "default_schedule": {"type": "crontab", "minute": "*/30"},
},
```

---

## Frontend Development

### Setup

Node 26 and pnpm 10.31, the versions the frontend images use (the exact pnpm version is `packageManager` in `frontend/package.json`). The app is React 19, React Router 7, TypeScript 6 and Vite 8.

```bash
cd frontend
pnpm install
```

### Development Server

```bash
pnpm dev
```

Vite serves on `http://localhost:3000` and forwards `/api`, `/docs`, `/redoc` and `/openapi.json` to `VITE_API_URL` (default `http://localhost:8000`).

### Building & Checks

From `frontend/`:

```bash
pnpm lint         # ESLint
pnpm build        # type check (tsc -b) and production build
pnpm test         # Vitest, once
pnpm test:watch   # Vitest, watching
pnpm exec playwright test   # end-to-end tests; needs the running stack
```

CI runs lint, build and test. It does not run Playwright or `pnpm lint:css` (stylelint): the stylelint baseline is out of date, so refresh it with `pnpm lint:css:baseline` before using it as a check.

### Adding a Page

1. Create the page in `src/pages/`.
2. Add a lazy import and a `<Route>` in `src/App.tsx`. Every page is loaded with `React.lazy()`.
3. Put the route inside the right layout route. Layouts in `App.tsx` are parent routes that render their children:
   - `MainLayout` — the three-panel feed reader.
   - `SidebarLayout` — tool pages such as settings, search, automation and campaigns.
   - `WorkbenchLayout` — pages under `/workbench`.

```tsx
const ThingsPage = lazy(() => import("@/pages/ThingsPage").then((m) => ({ default: m.ThingsPage })));

// inside the SidebarLayout parent route
<Route path="/things" element={<SignedInOnly><ThingsPage /></SignedInOnly>} />
```

### TanStack Query Hooks

All server data goes through TanStack Query v5 hooks in `src/hooks/`, using the shared Axios client (`import api from "@/api/client"`). The client adds the JWT, refreshes it on a 401, and handles errors globally. Defaults (`src/queryClient.ts`): data stays fresh for 30 seconds, a failed request is retried once (never on 401, 403 or 429), and nothing refetches on window focus.

```ts
// src/hooks/useThings.ts
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import api from "@/api/client";

export function useThings() {
  return useQuery({
    queryKey: ["things"],
    queryFn: async () => (await api.get<Thing[]>("/things")).data,
  });
}

export function useCreateThing() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: NewThing) => api.post("/things", body),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["things"] }),
  });
}
```

Use `useInfiniteQuery` for paginated lists.

### Zustand Store

Browser-side state lives in Zustand stores in `src/stores/`. The main ones are `authStore` (tokens), `uiStore` (layout and view settings), `intelStore` (intelligence workspace) and `playerStore` (audio). Stores that should survive a reload use the `persist` middleware, which saves to localStorage:

```ts
import { create } from "zustand";
import { persist } from "zustand/middleware";

export const useThingStore = create<ThingState>()(
  persist(
    (set) => ({ count: 0, increment: () => set((s) => ({ count: s.count + 1 })) }),
    { name: "thing-store" },   // localStorage key
  ),
);
```

### CSS Modules

Each component has a `.module.css` file next to it. There is no Tailwind. Colours and spacing come from CSS variables defined in `src/index.css`, including the entity colours (`--entity-actor`, `--entity-malware` and so on). Themes swap those variables at run time with `applyTheme()`, which also picks readable text colours from the background.

```tsx
import styles from "./ThingCard.module.css";

export function ThingCard() {
  return <div className={styles.card}>...</div>;
}
```

### Component Location Heuristics

- Shared components go at the top of `src/components/`.
- Shared building blocks (chips, panels, page headers, segmented controls, hints and so on) are in `src/components/primitives/`.
- Feature components go in a subfolder, e.g. `automation/`, `engine/`, `entityProfile/`, `search/`, `table/`, `triage/`, `widgets/`.

---

## Tests

### Backend Tests

Tests are in `backend/tests/test_*.py`. pytest runs in `asyncio_mode = "auto"`, so async tests need no marker, and each test times out after 60 seconds.

**Fixtures** (`backend/tests/conftest.py`):

- `db_session` — a session inside a transaction that is rolled back after the test.
- `client` — an async HTTP client wired to the app with that session.
- `test_user`, `admin_user`, and their `auth_headers`, `admin_headers`.
- `test_feed`, `test_category`, `test_entry`, `test_threat_actor`, `test_ttp`.

**Test database.** The suite uses your database name plus `_test` (plus the `PYTEST_DB_SUFFIX` and xdist worker id, when set). The schema is dropped and recreated once per run. Tests marked `@pytest.mark.committed_db` really commit, for code that opens its own connections like a worker does, and the tables are emptied afterwards. Meilisearch is switched off for every test; tests that need it patch the client themselves.

```python
from httpx import AsyncClient

from app.models.entry import Entry


async def test_get_entry(client: AsyncClient, auth_headers: dict, test_entry: Entry):
    response = await client.get(f"/api/entries/{test_entry.id}", headers=auth_headers)
    assert response.status_code == 200
```

Mock outside services with `unittest.mock.patch`. `factory-boy` is installed if you want factories, but the current tests build models directly.

### Frontend Unit Tests

Tests are in `src/**/__tests__/*.test.ts(x)` and use Vitest, jsdom and React Testing Library. `src/test/setup.ts` adds the jest-dom matchers and fills jsdom gaps (a working `localStorage` for Zustand, `matchMedia`). Axios is not mocked for you; mock the client in each test:

```ts
vi.mock("@/api/client", () => ({
  default: { get: vi.fn(() => Promise.resolve({ data: [] })) },
}));
```

### Frontend E2E Tests (Playwright)

Tests are in `frontend/tests/e2e/*.spec.ts`. The config (`frontend/playwright.config.ts`) uses `baseURL: http://localhost:3001`, one worker, and two retries in CI. Start the full Docker stack first, then from `frontend/`:

```bash
pnpm exec playwright install chromium   # once
pnpm exec playwright test
pnpm exec playwright test tests/e2e/feeds.spec.ts
```

---

## CI

GitHub Actions runs one workflow, `.github/workflows/ci.yml`, on every pull request, every push to `main`, a Monday-morning sweep and manual runs. A `changed?` job looks at which files changed, and only the matching jobs run:

| Job | Runs when | What it does |
|---|---|---|
| `changed?` | Always | Decides which jobs below run |
| `backend` | `backend/**` changed | Lockfiles match `pyproject.toml` (`./lock.sh` + `git diff`); `ruff check`; `ruff format --check`; exactly one migration head; `alembic upgrade head` on a fresh database, then `downgrade -1` and back up; `pytest`. Uses PostgreSQL 16 + pgvector and Redis 7 service containers |
| `frontend` | `frontend/**` changed | `pnpm install --frozen-lockfile`, `pnpm lint`, `pnpm build`, `pnpm test`, and a bundle-size report (not a gate) |
| `android` | `android/**` changed (not on the Monday sweep) | Gradle unit tests and a debug APK. On `main`, publishes a release when `android/version.properties` has a new version |
| `images` | A Dockerfile, lockfile, `package.json`, `nginx.conf`, compose file or `.env.example` changed | Builds the backend, frontend and db images (no push) and validates both compose files |
| `security` | Always | `gitleaks` secret scan; `scripts/dev/check_doc_links.py` and `scripts/dev/check_doc_refs.py`; `pip-audit` and `pnpm audit --prod` when a manifest changed or on the Monday sweep |
| `CI` | Always | Passes only if nothing above failed. This is the one required check |

Editing `ci.yml` itself runs everything. Each area is one job with its checks as steps, so a failure names a step, not a job.

- No secrets are needed. CI generates a throwaway `SECRET_KEY` and `ENCRYPTION_KEY`, so pull requests from forks pass.
- Playwright and stylelint do not run in CI.

**Before you push**, run the same checks:

```bash
# Backend, from backend/
ruff check . && ruff format --check . && pytest tests/ -q

# Frontend, from frontend/
pnpm lint && pnpm build && pnpm test

# Docs, from the repo root, if you touched docs/
python3 scripts/dev/check_doc_links.py && python3 scripts/dev/check_doc_refs.py
```

There is no pre-commit framework; run these by hand or from your own git hook.

---

## Database Migration Recipe

### 1. Edit the Model

```python
# backend/app/models/thing.py
class Thing(Base):
    __tablename__ = "things"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)   # new
```

### 2. Generate the Migration

From `backend/`:

```bash
alembic revision --autogenerate -m "add description to things"
```

This writes a file in `backend/alembic/versions/` with `upgrade()` and `downgrade()` functions.

### 3. Review & Edit

Always read the generated file; autogenerate misses some changes and guesses others. To make a column `NOT NULL`, fill existing rows first:

```python
def upgrade() -> None:
    op.add_column("things", sa.Column("category", sa.String(), nullable=True))
    op.execute("UPDATE things SET category = 'general' WHERE category IS NULL")
    op.alter_column("things", "category", nullable=False)
```

If two branches each add a migration, Alembic reports multiple heads, and CI fails on it. Fix it with `alembic merge -m "merge heads" <rev1> <rev2>`, or by pointing the newer migration's `down_revision` at the other one.

### 4. Test Locally

```bash
alembic upgrade head
alembic downgrade -1
alembic upgrade head
```

CI runs the same round trip on a fresh database. Locally it runs against your dev database, so a downgrade that drops a column drops your data in it too.

### 5. Commit

Commit the migration with the model change. On deploy the API applies it on start.

---

## Code Style & Conventions

### Backend

- **Async everywhere.** No blocking calls in request handlers: use `httpx` for HTTP, and `asyncio.to_thread` for CPU-heavy work.
- **Entity types.** Import the type names from `app/entity_types.py`; never type the strings.
- **Errors.** Raise `AppError` for errors a user should see. Let real bugs raise, so Sentry gets them.
- **Comments** explain why, not what.
- **Imports** are sorted by ruff (stdlib, third-party, local).
- **Names:** `snake_case` for functions and variables, `PascalCase` for classes, a leading `_` for module-private helpers.

### Frontend

- **Change existing components** before adding new ones.
- **No inline styles.** Styles go in the component's `.module.css`.
- **Colours and sizes** come from CSS variables in `src/index.css`.
- **Names:** `PascalCase` for components, `camelCase` for functions, `use` prefix for hooks.
- **Check phone width** for any visual change.
- **Error messages** are short and say what to do next.

---

## Branch & PR Workflow

### Branching

Branch off `main` with a prefix such as `feat/`, `fix/`, `docs/` or `refactor/`:

```bash
git switch main && git pull
git switch -c fix/sidebar-scroll
```

### Commits

Keep commits small and logical. Write the first line in plain words saying what changes; use the body for why, when it is not obvious.

### Pull Requests

- For anything bigger than a small fix, open an issue first. Issue templates are in `.github/ISSUE_TEMPLATE/`.
- Fill in the pull request template (`.github/pull_request_template.md`): what changed, how you checked it, and the checklist for the areas you touched.
- PRs are squash-merged, so the PR title becomes the commit on `main`. Make it a plain sentence that says what changes.
- `.github/CODEOWNERS` assigns reviewers.

### Adding Feed Adapters, Enrichment Sources, AI Tasks or Automation

- **Feed adapters:** [adapters.md](adapters.md)
- **Enrichment sources, AI providers and tasks, automation rules:** [automation-ai-enrichment.md](automation-ai-enrichment.md)

---

## Debugging Tips

### Backend

**Logs.** Pretty-printed in dev, JSON in prod:

```bash
docker compose -f docker-compose.dev.yml logs -f api
```

**Debugger (hybrid setup).** `debugpy` is not in the lockfile, so install it in your venv (`pip install debugpy`) and add this where you want to stop:

```python
import debugpy
debugpy.listen(("127.0.0.1", 5678))
debugpy.wait_for_client()
```

Then attach from your editor.

**Login problems.** Access tokens last 120 minutes; refresh is `POST /api/auth/refresh`. Changing `SECRET_KEY` logs everyone out.

**Celery,** in a worker container:

```bash
docker compose -f docker-compose.dev.yml exec celery-worker celery -A app.workers.celery_app inspect active
docker compose -f docker-compose.dev.yml exec celery-worker celery -A app.workers.celery_app inspect scheduled
docker compose -f docker-compose.dev.yml exec celery-worker celery -A app.workers.celery_app inspect stats
```

### Frontend

- Vite serves source maps in dev, so the browser's DevTools show your real source lines.
- If a theme colour does not apply, inspect the element's computed styles to see which variable wins.

### Workers & Search

**Stuck Meilisearch tasks** after a crash:

```bash
docker compose -f docker-compose.dev.yml exec meilisearch sh -c \
  'curl -X POST -H "Authorization: Bearer $MEILI_MASTER_KEY" "http://localhost:7700/tasks/cancel?indexUids=entries"'
```

**Rebuild the search index:** **Settings → System → Rebuild Search Index**, or:

```bash
docker compose -f docker-compose.dev.yml exec api python scripts/maintenance/rebuild_search_indexes.py
```

**Slow queries.** Open psql and log anything slower than 100 ms for your session:

```bash
docker compose -f docker-compose.dev.yml exec db psql -U intelfeed -d intelfeed
```

```sql
SET log_min_duration_statement = 100;
```

---

## Local Data Seeding

All scripts are in [`scripts/`](../scripts/); [`scripts/README.md`](../scripts/README.md) lists every one. Most run in the api container, where `./scripts` is mounted at `/app/scripts`. The `ops/` and `dev/` folders run on your machine instead.

A fresh install has countries and a starting set of ATT&CK techniques (the migrations add them), but no CWE catalog, vendors, products or actor attribution. Seed them so entries link to entities:

```bash
docker compose -f docker-compose.dev.yml exec api python scripts/seed/seed_all.py --dry-run   # preview
docker compose -f docker-compose.dev.yml exec api python scripts/seed/seed_all.py
```

`seed_all.py` runs ten seeders in order: countries, country aliases, sectors, MITRE ATT&CK, CWE catalog, vendors and products, vendor descriptions, CPE names, actor attribution and entity attributes. Each runs in its own process. If one fails it stops and prints the `--only <steps>` command to resume. Other flags: `--offline` skips the four that download data, `--skip`, `--overwrite`, `--continue-on-error`, and `--list` to show step names. Every seeder is safe to re-run.

Maintenance scripts run the same way, for example:

```bash
docker compose -f docker-compose.dev.yml exec api python scripts/maintenance/resanitize_entries.py
docker compose -f docker-compose.dev.yml exec api python scripts/maintenance/purge_invalid_relationships.py   # dry run; add --apply to change data
```

**First user.** Register at <http://localhost:3001>. The first account becomes the admin; invite codes and registration are under **Settings → Users**.

**Feeds.** Pick a starter pack during onboarding, import an OPML file from the **Add feed** dialog, or seed the starter feeds with `scripts/seed/seed_feeds.py`.

---

## Skills, CLI & MCP

- **`intelfeed-skill/`** — Claude skill and CLI with every tool in the registry (196).
- **`intelfeed-lite-skill/`** — the read-only version (97 tools).
- **`intelfeed-mcp/`** — the same registry served over MCP for local models. See [intelfeed-mcp/README.md](../intelfeed-mcp/README.md).

Each skill has its own zero-dependency `scripts/intelfeed_cli.py`. Both CLIs and the MCP server's `registry.json` are generated from `backend/app/tools/`. Do not edit them by hand; run `python3 scripts/dev/sync_skill_clis.py` after changing a tool.

Try a CLI on your machine:

```bash
export INTELFEED_API_URL=http://localhost:8000
export INTELFEED_USERNAME=your-username
export INTELFEED_PASSWORD=your-password

python3 intelfeed-skill/scripts/intelfeed_cli.py --list-tools
python3 intelfeed-skill/scripts/intelfeed_cli.py search_entries '{"query": "ransomware", "limit": 5}'
```

Full reference: [cli-reference.md](cli-reference.md).

---

## Releasing & Deploying

Merging to `main` is a deploy on any host that runs `update.sh` from cron. It pulls, rebuilds only when an image's inputs changed, and the API applies new migrations when it starts. Details are in [operations.md](operations.md#update--deployment); the first install is in [setup.md](../setup.md).

Before a risky change, take a backup on the production host, from the repo folder:

```bash
./scripts/ops/backup.sh    # writes ./backups/intelfeed_<timestamp>.sql.gz
```

The Android app ships separately: see [android-app.md](android-app.md).
