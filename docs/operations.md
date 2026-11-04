# Operations Guide

Running IntelFeed in production. Install first with [setup.md](../setup.md); code structure is in [architecture.md](./architecture.md).

---

## Table of Contents

1. [Deployment Architecture](#deployment-architecture)
2. [Service Inventory](#service-inventory)
3. [Configuration & Secrets](#configuration--secrets)
4. [Security](#security)
5. [Observability](#observability)
6. [Backups & Recovery](#backups--recovery)
7. [Performance & Scaling](#performance--scaling)
8. [Troubleshooting](#troubleshooting)
9. [Update & Deployment](#update--deployment)

---

## Deployment Architecture

### Dev vs. Prod Docker Compose

Dev mounts code for live edits; prod builds it into images and adds memory limits, a TLS proxy and network separation.

| | Dev ([docker-compose.dev.yml](../docker-compose.dev.yml)) | Prod ([docker-compose.prod.yml](../docker-compose.prod.yml)) |
|---|---|---|
| Code | `./backend` mounted at `/app` | Built into the image |
| API server | `uvicorn --reload` | Gunicorn, 3 Uvicorn workers, 180 s timeout, recycled after 800–1,000 requests |
| Default worker | `--concurrency=4`, `celery` queue | `--concurrency=2`, `celery` queue, child restart after 50 tasks or 300 MB |
| AI worker | `celery-worker-ai`, one task at a time | Same, plus child restart after 20 tasks |
| Enrichment worker | `celery-worker-enrichment`, one task at a time, child restart after 200 tasks | Same, plus child restart at 250 MB |
| Redis | 512 MB cap, `allkeys-lru`, no password | 1 GB cap, `volatile-lru`, password, append-only file |
| Health checks | db, redis, meilisearch, libretranslate, piper | Same, plus api and frontend |
| Host ports | 8000, 3001, 5433, 6380, 7700, 5050, 5060 | 80 and 443 only (Caddy) |
| Memory limits | None | Per service (below) |
| Restart policy | `unless-stopped` | Same |

- **The AI worker** (`celery-worker-ai`) drains the `ai` queue and a second queue named `claude_code`, one task at a time (`CLAUDE_CODE_CONCURRENCY`, default 1) so AI calls never overlap. Only it holds the Claude CLI login (`claude_cli` volume).
- **The enrichment worker** (`celery-worker-enrichment`) drains the `enrichment` queue, one task at a time: the enrichment dispatcher, which beat queues every 30 seconds to run due lookups from `enrichment_jobs`. If it is down, lookups wait in that table and nothing is lost; ticks queued meanwhile expire after 30 seconds.
- **LibreTranslate** is off by default, behind the `translate` profile, since its models hold about 740 MB. Start: `docker compose -f docker-compose.prod.yml --profile translate up -d libretranslate`. While off, auto-translate skips; `retry-untranslated-entries` (every 30 minutes) catches up later.
- **Startup seeders** (AI tasks, enrichment sources) take a Postgres advisory lock so the three API workers don't collide.
- **OOM order.** `oom_score_adj` sets what the kernel kills first: workers (+600) and piper (+300); db (−900), redis (−800), api (−700) and caddy (−500) are protected. Add host swap so spikes slow rather than kill.
- **Container logs**: `json-file` driver, 3 × 20 MB per container.

**Memory limits (prod):**

| Service | Limit |
|---|---|
| db | 1500M |
| redis | 1500M |
| meilisearch | 1536M |
| libretranslate | 2G |
| piper | 1536M |
| api | 1500M |
| celery-worker | 2G |
| celery-worker-ai | 1G |
| celery-worker-enrichment | 384M |
| celery-beat | 256M |
| telegram-listener | 512M |
| frontend | 128M |
| caddy | 128M |

---

## Service Inventory

### Service Dependency Graph

See [diagrams/operations-service-topology.md](./diagrams/operations-service-topology.md) for the production service graph.

### Services & Ports

"Internal" = reachable only from other containers.

| Service (compose name) | Dev host port | Prod | Prod network | Purpose |
|---|---|---|---|---|
| `db` (PostgreSQL 16 + pgvector) | 5433 | internal 5432 | backend | Database |
| `redis` | 6380 | internal 6379 | backend | Celery broker, caches, locks, rate-limit counters |
| `meilisearch` | 7700 | internal 7700 | backend | Full-text search |
| `libretranslate` (v1.9.6) | 5050 | internal 5000, `translate` profile | backend | Article translation |
| `piper` | 5060 | internal 5000 | backend | Read-aloud TTS |
| `api` | 8000 | internal 8000 | backend, frontend | FastAPI app |
| `celery-worker` | — | — | backend | Background jobs (`celery` queue) |
| `celery-worker-ai` | — | — | backend | AI tasks and copilot turns (`ai` queue), serially |
| `celery-worker-enrichment` | — | — | backend | Enrichment dispatcher (`enrichment` queue), serially |
| `celery-beat` | — | — | backend | Scheduler |
| `telegram-listener` | — | — | backend | Telegram channel watcher |
| `frontend` | 3001 | internal 80 | frontend | Web app (Vite in dev; nginx in prod, forwarding `/api/*` to `api`) |
| `caddy` | — | 80, 443 | frontend | Reverse proxy, TLS (prod only) |

Only Caddy is public in prod. The `backend` network holds data services and workers; `frontend` holds the frontend and Caddy; the API is on both.

### Caddy Reverse Proxy & TLS

[Caddyfile](../Caddyfile):

```text
{$SITE_DOMAIN} {
	@sw path /sw.js
	header @sw Cache-Control "no-store"

	reverse_proxy frontend:80
}
```

- `SITE_DOMAIN` comes from `.env`; prod compose won't start without it.
- Caddy gets and renews a Let's Encrypt certificate, ends TLS, redirects HTTP to HTTPS, and proxies to the frontend.
- DNS for `SITE_DOMAIN` must point at the server **before** Caddy starts, or the certificate request fails.
- The service worker (`/sw.js`) is never cached.
- The frontend nginx ([frontend/nginx.conf](../frontend/nginx.conf)) serves `index.html` with `expires -1`, so browsers fetch the new build after a deploy.

---

## Configuration & Secrets

### Environment Variables

Settings go in `.env` at the repo root; [`.env.example`](../.env.example) documents each. Prod needs:

```bash
# Secrets
SECRET_KEY=<generated>          # signs login tokens; at least 32 characters in prod
ENCRYPTION_KEY=<generated>      # Fernet key for encrypted columns
POSTGRES_PASSWORD=<generated>
MEILI_MASTER_KEY=<generated>
REDIS_PASSWORD=<generated>
REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379/0

# Where the app lives
SITE_DOMAIN=intelfeed.example.com
CORS_ORIGINS=["https://intelfeed.example.com"]   # a JSON list; a bare string fails to parse
```

Generate secrets:

```bash
openssl rand -hex 32        # SECRET_KEY
openssl rand -base64 32 | tr '+/' '-_'   # ENCRYPTION_KEY (a Fernet key)
openssl rand -hex 24        # POSTGRES_PASSWORD, REDIS_PASSWORD, MEILI_MASTER_KEY
```

Prod compose sets `ENV=production` on app containers and `RUN_MIGRATIONS=true` on the API. With `ENV=production` the app won't start if a secret is a placeholder like `changeme`, `SECRET_KEY` is under 32 characters, or `CORS_ORIGINS` contains `*`; logs are JSON instead of coloured.

Also:

- `TRUSTED_CLIENT_IP_HEADER` — [Cloudflare Origin Lockdown](#cloudflare-origin-lockdown).
- `ENCRYPTION_KEY_PREVIOUS` — the old key after rotation, so stored secrets stay readable.
- `SENTRY_DSN` — error reporting (also in **Settings → System**).
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURITY`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM_ADDRESS`, `SMTP_MAX_PER_HOUR` — the mail server for the `send_email` automation action (also in **Settings → System**).
- `PUBLIC_BASE_URL` — builds full article links in notifications and reports.

### System Settings (Database)

Most settings live in the database and are edited in the Settings UI; saved values beat `.env` defaults.

- **Table:** `system_settings`, one row (`id = 1`) with `settings` and `secrets` JSONB columns and `updated_at`.
- **Keys:** `CONFIGURABLE_KEYS` in `backend/app/services/system_settings.py`, described in [engine-settings.md](engine-settings.md).
- **Secrets:** `github_token`, `nvd_api_key`, `sentry_dsn`, `registration_invite_code` and `observables_publish_token` are encrypted and masked in API responses. AI-provider and enrichment keys have their own tables.
- **Job schedules:** Jobs UI overrides are stored under `_job_schedule_overrides` (`app/api/job_schedules.py`) and copied to Redis for beat.
- **API (admin):** `GET`, `PATCH /api/system-settings`, `DELETE /api/system-settings/{key}`.

---

## Security

### Authentication & JWT

1. `POST /api/auth/login` checks the password against the bcrypt hash in `users.password_hash`.
2. It returns an access token (120 minutes, `access_token_expire_minutes`) and a refresh token (7 days, `refresh_token_expire_days`).
3. The frontend keeps both in localStorage (Zustand `authStore`) and sends `Authorization: Bearer <access_token>`.
4. On 401 it calls `POST /api/auth/refresh` and retries.

Tokens are HS256 (PyJWT) signed with `SECRET_KEY`, algorithm pinned on every decode; changing `SECRET_KEY` logs everyone out. An access token carries:

```json
{
  "sub": "<user uuid>",
  "role": "admin",
  "username": "alice",
  "type": "access",
  "jti": "<token id>",
  "exp": 1234567890,
  "iat": 1234567800
}
```

On logout the `jti` goes on a Redis blocklist (checked on every request) until the token would expire. Passwords are bcrypt-hashed (12 rounds).

Code: `backend/app/core/security.py`.

### HTTPS & TLS

Caddy defaults: Let's Encrypt certificates, auto-renewal, HTTP-to-HTTPS redirect, TLS 1.2+. Certificates persist in the `caddy_data` volume across restarts.

### Cloudflare Origin Lockdown

Behind Cloudflare, anyone who learns the server's IP can bypass Cloudflare's firewall and rate limits. [scripts/ops/cf-origin-lockdown.sh](../scripts/ops/cf-origin-lockdown.sh) allows ports 80 and 443 only from Cloudflare's published ranges (via ufw). On the host:

```bash
sudo ./scripts/ops/cf-origin-lockdown.sh [--dry-run]
```

- It sets both `ufw allow` (host traffic) and `ufw route allow` (Docker-forwarded traffic) rules; either alone leaves a gap.
- Safe to re-run: it fetches and checks current ranges before touching rules.
- It never touches port 22, so SSH stays open.

Then set `TRUSTED_CLIENT_IP_HEADER=CF-Connecting-IP` in `.env` so anonymous traffic counts per visitor, not per edge node. Without lockdown, leave it unset — the header is fakeable. [Public read-only mode](public-read-only-mode.md) behind Cloudflare requires it: otherwise all visitors behind one edge node share one limit of 20 articles a minute.

### Security Headers

`SecurityHeadersMiddleware` (`backend/app/core/security_headers.py`) adds to every API response:

```text
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 0
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
Strict-Transport-Security: max-age=63072000; includeSubDomains
X-Robots-Tag: noindex, nofollow
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: https:; connect-src 'self'; font-src 'self'; media-src 'self' https:; worker-src 'self' blob:; frame-src 'self' https://www.youtube.com https://www.youtube-nocookie.com; frame-ancestors 'none'; upgrade-insecure-requests
```

- **CSP:** own scripts only; images from any HTTPS source; only YouTube embeds. The API docs (`/docs`, `/redoc`, `/openapi.json`) get a looser policy so Swagger loads from its CDN.
- **HSTS:** HTTPS for two years.
- **No framing:** other sites can't embed IntelFeed.
- **No caching:** `/api/*` responses (and `/openapi.json`) get `Cache-Control: private, no-store` unless the route sets its own (the image proxy and audio files do), so shared caches like Cloudflare never leak one user's data to another.
- **No indexing:** the SPA adds `<meta name="robots" content="noindex, nofollow">` and a crawler-blocking `robots.txt`.

### CORS Configuration

`CORS_ORIGINS` is a JSON list of browser origins allowed to call the API:

Dev `CORS_ORIGINS=["http://localhost:3000","http://localhost:3001"]`; prod `CORS_ORIGINS=["https://intelfeed.example.com"]`.

It feeds `CORSMiddleware` in `backend/app/main.py`, allowing credentials and all methods and headers.

### Rate Limiting

`RateLimitMiddleware` (`backend/app/core/rate_limit.py`) limits by path. Normal signed-in use is **not** limited; limits protect logins, AI spend and anonymous access.

| Bucket | Applies to | Limit |
|---|---|---|
| `auth` | `/api/auth/login`, `/api/auth/register`, `/api/auth/refresh` | 10 per 5 minutes |
| `chat` | `POST /api/chat` | 10 per minute |
| `ai` | AI calls under `/api/ai/*`; creating or testing an AI provider; the share page's `ask-agent` and `run-ai-task`. Not counted: settings reads under `/api/ai/tasks`, `/api/ai/providers`, `/api/ai/prompts`, `/api/ai/copilot-auth` | 20 per minute |
| `anon_article` | `GET /api/entries/{id}` without a valid token (a full article) | 20/min and 150/hour |
| `anon_heavy` | Graph, pivot, timeline, analytics, map, calendar, priority-queue, relationship, entity-link, CWE and autolink-scan routes without a valid token | 20/min and 200/hour |
| `anon` | Other `/api/*` requests without a valid token ([public read-only mode](public-read-only-mode.md), share pages) | 180/min and 1,500/hour |
| `indicator_feeds` | `/api/taxii2/*` and `/api/publish/*` without a valid token (publish-token pulls) | 240/min |
| — | Everything else signed in | Not limited |

Never limited: `/api/health`, `/metrics`, `OPTIONS` requests.

- **Who is counted:** the user for a valid, signature-checked JWT; else the client IP.
- **Client IP.** For private-network connections (Caddy, or your machine in dev), the API uses the `TRUSTED_CLIENT_IP_HEADER` header if set, else the first `X-Forwarded-For` entry. Caddy overwrites `X-Forwarded-For` with the real peer; never publish port 8000 to your LAN, or anyone could fake it.
- **Counting.** Redis sliding windows, checked and recorded by one script, so parallel requests can't slip past. Refused requests aren't counted.
- **Responses.** Allowed: `X-RateLimit-Limit` and `X-RateLimit-Remaining` for the tightest window. Refused: `429` with `Retry-After` (seconds until a request fits).
- **Redis down:** requests are allowed, with a logged warning.

### SQL Injection Prevention

All queries use SQLAlchemy bound parameters; raw SQL uses `text()` with named parameters (`:id`), never string formatting.

### CSRF Protection

Not needed: login uses no cookies, and forged cross-site requests lack the bearer token.

### XSS & Content Sanitization

- **Server:** article HTML is cleaned with `nh3` before storage (`backend/app/services/sanitizer.py`). Only allowlisted formatting tags survive (paragraphs, links, images, headings, lists, tables, code and similar); `<script>`, `<iframe>` and `<style>` are removed.
- **Browser:** DOMPurify cleans HTML again before display; the CSP blocks inline scripts.
- **Images** load through `/api/proxy/image` while `image_proxy_enabled` is on (default), cached in `image_cache`, so original hosts can't track readers.
- After a sanitizer change, re-clean stored entries with [scripts/maintenance/resanitize_entries.py](../scripts/maintenance/resanitize_entries.py) in the api container.

### Encrypted Columns

Encrypted with Fernet (AES-128 plus HMAC) using `ENCRYPTION_KEY`:

- `ai_providers.api_key_encrypted`
- `enrichment_sources.api_key_encrypted`
- `user_enrichment_overrides.api_key_encrypted`
- `system_settings.secrets`

Back up `ENCRYPTION_KEY`: without it these are unreadable, even from a good backup. `users.password_hash` is a bcrypt hash, only ever compared.

---

## Observability

### Structured Logging

`structlog` (`backend/app/core/logging.py`) writes JSON lines to host-mounted `logs/`, rotating at 10 MB, 5 old files kept:

| File | Contents |
|---|---|
| `app.log` | App INFO and above, excluding workers |
| `error.log` | ERROR and above |
| `http.log` | One line per request: method, path, status, `duration_ms`, client |
| `jobs.log` | Celery worker and beat |
| `audit.log` | Create, update and delete actions via the API |
| `update.log` | `update.sh` output |

Admins read them in **Settings → Logs** or via the API:

`GET /api/logs` (list), `GET /api/logs/{filename}?lines=500` (last N lines, up to 10,000), `DELETE /api/logs/{filename}` (empty a file).

### Prometheus Metrics

`/metrics` answers only a direct peer on loopback or a private (RFC 1918) address (`backend/app/api/metrics.py`); it ignores `X-Real-IP` and other forwarding headers. In prod the frontend nginx always returns **404** for it, since behind the proxy every request looks private. Scrape `http://api:8000/metrics` from Prometheus on the compose `backend` network; in dev, use `http://localhost:8000/metrics`.

```yaml
scrape_configs:
  - job_name: intelfeed
    scrape_interval: 15s
    metrics_path: /metrics
    static_configs:
      - targets: ['api:8000']
```

Metrics (`backend/app/core/metrics.py`):

| Metric | Type | Labels |
|---|---|---|
| `intelfeed_http_requests_total` | Counter | method, path, status |
| `intelfeed_http_request_duration_seconds` | Histogram | method, path |
| `intelfeed_feeds_active` | Gauge | — |
| `intelfeed_feed_fetch_total` | Counter | status (success, error, not_modified, rate_limited) |
| `intelfeed_feed_fetch_duration_seconds` | Histogram | feed_type |
| `intelfeed_entries_ingested_total` | Counter | feed_type |
| `intelfeed_ai_requests_total` | Counter | provider, task |
| `intelfeed_ai_tokens_total` | Counter | provider, direction (input, output) |
| `intelfeed_ai_cost_total` | Counter | provider (estimated USD) |
| `intelfeed_ai_request_duration_seconds` | Histogram | provider, task |
| `intelfeed_signal_probe_failures_total` | Counter | probe |
| `intelfeed_entry_signals_fired_total` | Counter | signal_type |
| `intelfeed_automation_runs_total` | Counter | trigger_type, status |
| `intelfeed_correlation_events_total` | Counter | event_type |
| `intelfeed_search_queries_total` | Counter | — |
| `intelfeed_celery_tasks_total` | Counter | task_name, status |
| `intelfeed_celery_task_duration_seconds` | Histogram | task_name |
| `intelfeed_entries_cleaned_total` | Counter | — |
| `intelfeed_images_evicted_total` | Counter | — |
| `intelfeed_telegram_media_evicted_total` | Counter | — |

`/api/health` and `/metrics` aren't counted in HTTP metrics.

### Health Endpoints

`GET /api/health` (no login) pings PostgreSQL, Redis and Meilisearch. A caller on the api host itself (the container health check, `docker compose exec api curl …`) also gets each component's latency and error text:

```json
{
  "status": "healthy",
  "version": "v1.2.3",
  "git_sha": "abc1234",
  "built_at": "2026-10-01T12:00:00Z",
  "components": {
    "database": {"status": "ok", "latency_ms": 2.5},
    "redis": {"status": "ok", "latency_ms": 1.2},
    "meilisearch": {"status": "ok", "latency_ms": 5.3}
  }
}
```

Anyone else, including every request through the proxy, gets each component's `status` only (`{"database": {"status": "ok"}, …}`).

`healthy` = all up; `degraded` = database up, Redis or Meilisearch down; `unhealthy` = database down.

`GET /api/version` returns only the build stamp (cheap to poll). Prod health check:

```yaml
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:8000/api/health"]
  interval: 30s
  timeout: 10s
  retries: 3
  start_period: 30s
```

Code: `backend/app/api/health.py`.

---

## Backups & Recovery

Two ways:

1. **Nightly job.** `backup-database` runs `pg_dump` in the worker daily at 02:00 UTC, writing `backups/intelfeed_YYYYMMDD_HHMMSS.sql.gz` (host `./backups`) and keeping `backup_retention_days` days (default 7, **Settings → System**). No encryption or Meilisearch snapshot; schedule is in the Jobs view (**Settings → Engine**).
2. **[scripts/ops/backup.sh](../scripts/ops/backup.sh)** on the host, which can encrypt and also requests a Meilisearch snapshot.

Copy backups off the server either way.

### Backup Strategy

Run `backup.sh` **from the repo folder** (it finds the compose file relative to it).

```bash
# On the host, from the repo folder
./scripts/ops/backup.sh                 # writes to ./backups
./scripts/ops/backup.sh /mnt/backups    # or to another folder

# Cron, daily at 03:00
0 3 * * * cd /path/to/intelfeed && scripts/ops/backup.sh /mnt/backups
```

It:

1. **Dumps the database** with `pg_dump --clean --if-exists --no-owner`, streamed through `gzip` (and `gpg` when encrypting), never holding it uncompressed.
2. **Requests a Meilisearch snapshot** from inside its container (no host port needed), written in the background to `/meili_data/snapshots` in the `meilidata` volume, not the backup folder.
3. **Deletes backups** past retention.

Settings come from the shell environment, not `.env`:

| Variable | Default | Meaning |
|---|---|---|
| `RETENTION_DAYS` | 7 | Delete backups older than this; 0 keeps all |
| `BACKUP_ENCRYPT_KEY` | empty | If set, GPG (AES-256) encrypt to `.sql.gz.gpg` |
| `COMPOSE_FILE` | `docker-compose.prod.yml` | `docker-compose.dev.yml` for the dev stack |
| `POSTGRES_USER` / `POSTGRES_DB` | `intelfeed` | If your `.env` uses other names |

A `pg_dump` failure stops it. A snapshot-only failure keeps the backup, still prunes, and exits 1 for cron or monitoring.

### Restore Procedure

[scripts/ops/restore.sh](../scripts/ops/restore.sh) replaces the database with a backup (on the host, from the repo folder):

```bash
./scripts/ops/restore.sh ./backups/intelfeed_20260503_020000.sql.gz

# Encrypted backup
export BACKUP_ENCRYPT_KEY="<passphrase>"
./scripts/ops/restore.sh ./backups/intelfeed_20260503_020000.sql.gz.gpg
```

With no argument it lists `./backups`. It asks for confirmation, stops every service that holds a database connection (`api`, the four Celery services and `telegram-listener`), drops and recreates the database, loads the backup in one transaction, and starts them again. It honours `COMPOSE_FILE`, `POSTGRES_USER` and `POSTGRES_DB`.

**Restoring overwrites the current database.** Keep backups read-only.

**Meilisearch.** After a restore, rebuild the index from the database: **Settings → System → Rebuild Search Index**, or:

```bash
docker compose -f docker-compose.prod.yml exec api python scripts/maintenance/rebuild_search_indexes.py
```

Or start Meilisearch once with `--import-snapshot`:

```bash
docker compose -f docker-compose.prod.yml exec meilisearch ls /meili_data/snapshots
# Then temporarily set the meilisearch service's command to
#   meilisearch --import-snapshot /meili_data/snapshots/<file>.snapshot
```

### Volume Layout

Prod named volumes:

| Volume | Mounted at | Holds | Safe to delete? |
|---|---|---|---|
| `pgdata` | `/var/lib/postgresql/data` | Database | No |
| `redisdata` | `/data` | Redis append-only file | Yes, losing queued jobs, the logout blocklist and rate-limit counts |
| `meilidata` | `/meili_data` | Search index and snapshots | Yes, then rebuild |
| `image_cache` | `/app/data/image_cache` | Cached article images | Yes, refetched |
| `libretranslate_models` | `/home/libretranslate/.local` | Translation models | Yes, redownloaded on start |
| `piper_voices` | `/voices` | TTS voice models | Yes, redownloaded on start |
| `claude_cli` | `/home/appuser/.claude` | Claude CLI login (AI worker only) | No, you'd have to sign in again |
| `caddy_data` | `/data` (caddy) | TLS certificates | No, re-requesting can hit Let's Encrypt rate limits |
| `caddy_config` | `/config` (caddy) | Caddy config | Yes |

Host folders (relative to the repo):

| Folder | Used by | Notes |
|---|---|---|
| `./logs` | api, workers, beat, telegram-listener | Log files |
| `./backups` | api, celery-worker | Nightly-job and `backup.sh` backups |
| `./docs` | api (read-only) | In-app documentation (`app/api/documentation.py`); without it the docs page is empty |
| `./scripts` | api (read-only) | Seed and maintenance scripts |
| `./intelfeed-mcp` | celery-worker-ai (read-only) | MCP server for the Claude CLI provider |
| `./telegram_data`, `./telegram_media` | api, celery-worker, telegram-listener | Telegram session and media; media older than `telegram_media_ttl_days` (default 30) is deleted |
| `./tts_media` | api, celery-worker | Read-aloud MP3s; must be owned by uid 1000 (`update.sh` fixes this) |
| `./ingest_files` | api, celery-worker | Uploaded originals, deleted after `ingest_files_ttl_days` (default 180); must be owned by uid 1000 (`update.sh` fixes this) |

The `cvelist-backfill` job downloads the cvelistV5 baseline zip (about 650 MB; a zip over 2 GB is refused) into `/tmp` inside the celery-worker container and keeps it there between runs, so that container's writable layer needs about 2 GB free.

---

## Performance & Scaling

### Bottlenecks

| Symptom | Likely cause | What to try |
|---|---|---|
| Feeds fall behind | Many or slow feeds | More default-worker concurrency, longer fetch intervals |
| AI analysis backlog grows | The AI worker runs one task at a time by design | Faster model or provider; raise `CLAUDE_CODE_CONCURRENCY` only if the provider handles parallel calls |
| Slow pages, timeouts | API out of memory or database disk-bound | Check `docker stats`; raise api or db memory limits and Postgres buffers |
| Too many database connections | Up to 15 per API worker (`db_pool_size` 5 + `db_max_overflow` 10), 8 per task | Lower pool settings or raise Postgres `max_connections` (prod default 100) |

### Scaling Strategies

**One bigger server.** Add CPU and RAM, then raise `memory` limits in `docker-compose.prod.yml` and worker `--concurrency`. Keep Gunicorn's worker count (`-w 3`) small enough to fit under the api memory limit; a swapping worker is worse than one fewer.

**Queues.** `celery` (everything else) is served by `celery-worker`; `ai` (every task calling an AI provider) only by `celery-worker-ai`; `enrichment` (the enrichment dispatcher) only by `celery-worker-enrichment`. New AI-calling tasks must be routed to `ai` in `task_routes` in `backend/app/workers/celery_app.py`. A second `celery-worker-enrichment` is safe (claims use `SKIP LOCKED`, and each source's allowance lives in Redis) but buys little: the sources' rate limits set the pace, not the worker.

**Postgres tuning.** Prod `db` settings are command-line flags (`shared_buffers=320MB`, `work_mem=24MB`, `maintenance_work_mem=96MB`, `effective_cache_size=2GB`, `random_page_cost=1.1`). They override `ALTER SYSTEM`; edit the compose file and recreate:

```bash
docker compose -f docker-compose.prod.yml up -d db
```

**Several servers.** Point `POSTGRES_HOST`, `REDIS_URL` and `MEILI_URL` at managed services (`POSTGRES_SSL=true` for remote databases); extra worker hosts share the broker and database. Keep one `celery-worker-ai` if it paces a single GPU.

---

## Troubleshooting

Run commands on the prod host from the repo folder.

### Common Failure Modes & Solutions

#### 1. A feed stops updating

**Cause:** a crashed fetch left its Redis lock, which expires after 10 minutes — wait first.

**Fix:**

```bash
docker compose -f docker-compose.prod.yml exec redis redis-cli -a "$REDIS_PASSWORD" DEL feed_fetch:<feed_id>
docker compose -f docker-compose.prod.yml restart celery-worker celery-beat
```

#### 2. A database migration fails

**Symptom:** the API restart-loops with a migration error. `exec` won't work (migrations run at start); use a one-off container:

```bash
docker compose -f docker-compose.prod.yml run --rm -e RUN_MIGRATIONS=false api alembic current
docker compose -f docker-compose.prod.yml run --rm -e RUN_MIGRATIONS=false api alembic history
docker compose -f docker-compose.prod.yml logs api --tail 100
```

**Fix:** correct the migration and push to `main`; the next `update.sh` rebuilds and applies it. Downgrade (`alembic downgrade -1`) only if you know what it drops.

#### 3. Search is missing entries or shows old results

**Fix:** **Settings → System → Rebuild Search Index**, or:

```bash
docker compose -f docker-compose.prod.yml exec api python scripts/maintenance/rebuild_search_indexes.py
```

#### 4. Telegram messages stop arriving

**Cause:** expired session or network drop.

**Fix:**

```bash
docker compose -f docker-compose.prod.yml logs telegram-listener --tail 100
docker compose -f docker-compose.prod.yml restart telegram-listener

# Expired session: log in again (interactive). The api container has the
# scripts and shares the session folder.
docker compose -f docker-compose.prod.yml exec -it api python scripts/telegram/telegram_login.py
```

#### 5. AI tasks time out

**Cause:** slow or unreachable provider.

**Fix:** in **Settings → AI Configuration**, raise `timeout_seconds` in the task's assignment config, or switch provider or model. For Ollama, check it's really on the GPU.

#### 6. A container is killed for using too much memory

**Symptom:** a restart with `OOMKilled: true` in `docker inspect`.

```bash
docker stats --no-stream
```

**Fix:** raise its `memory` limit in `docker-compose.prod.yml` or lower worker `--concurrency`, then `docker compose -f docker-compose.prod.yml up -d <service>`.

#### 7. Redis says "OOM command not allowed"

**Cause:** Redis hit its 1 GB cap, and `volatile-lru` evicts only expiring keys. Celery results expire hourly (`result_expires=3600`); find big keys without expiry:

```bash
docker compose -f docker-compose.prod.yml exec redis redis-cli -a "$REDIS_PASSWORD" INFO memory
docker compose -f docker-compose.prod.yml exec redis redis-cli -a "$REDIS_PASSWORD" --bigkeys
```

`$REDIS_PASSWORD` isn't in your shell by default; paste it from `.env` or run `set -a; . ./.env; set +a`.

#### 8. Entity data is wrong after a rule change

**Symptom:** a profile shows far more articles than it links, a graph shows edges from "Related:" lines or roundups, the Review queue's auto-applied removals took out good links, or article text reads as glued words ("powerSource", an IP running into the next one).

**Fix:** four repair scripts. Each is a dry run unless you add `--apply`, prints a summary, and is safe to run again. CSVs go to `/tmp` in the container (`scripts/` is read-only in prod); copy them out with `docker compose cp`.

```bash
D="docker compose -f docker-compose.prod.yml exec -T api python scripts/maintenance"

# Stored article counts vs. the links that exist (all types, or --type/--entity)
$D/recount_article_counts.py
$D/recount_article_counts.py --apply

# Co-occurrence edges whose articles fail the same-paragraph rule
$D/sweep_cooccurrence_edges.py                 # writes the plan CSV
$D/sweep_cooccurrence_edges.py --apply         # keep the CSV: it is the undo
$D/sweep_cooccurrence_edges.py --undo /tmp/cooccurrence_sweep.csv --apply

# Removals the adjudicate stage applied on its own that match known-bad patterns
$D/audit_auto_removals.py --since YYYY-MM-DD   # review CSV, restore=y prefilled
$D/audit_auto_removals.py --restore /tmp/auto_removals.csv --apply

# Article text whose blocks or table cells run together
$D/rederive_content_text.py --since YYYY-MM-DD
$D/rederive_content_text.py --apply --rerun    # --rerun re-queues the link stages
```

- `recount_article_counts.py` counts each entity's linked articles and writes that number where the stored one differs. It re-indexes the changed entities in search and clears the cached graphs. Observables are left to the nightly counter job.
- `sweep_cooccurrence_edges.py` checks each article behind a `co_occurrence` edge: both names in one body paragraph, not boilerplate, fewer than five entities in it, with a recorded position. Articles that fail are dropped from the edge's evidence. An edge with none left is rejected, the same as the Reject button. A trimmed `probable` edge that falls below the promotion rule goes back to `possible`. Articles the adjudicate stage kept the edge on always stay. No other edge source is touched.
- `audit_auto_removals.py` lists applied removals that are sector links, legitimate or defensive tools, TTPs from a detection rule's ATT&CK tags or an article's ATT&CK table, hashes from an indicator table, and removals whose reason calls the entity legitimate, a victim or the publisher. `--restore` puts back the rows marked `y` through the same Restore the Review queue uses.
- `rederive_content_text.py` rebuilds each article's text from its stored HTML and keeps the Transcript or Image OCR text added after it. It writes only rows where the change is whitespace alone and updates search. `content_hash` stays as it is, so duplicate detection does not shift. `--rerun` queues autolink, observables, extract and co-occurrence for the changed articles (no AI, no automation rules).
- Run `rederive_content_text.py --rerun` first, then `sweep_cooccurrence_edges.py` and `recount_article_counts.py`, so they see the new links.

### Useful Commands

**Containers:**

```bash
docker compose -f docker-compose.prod.yml ps                     # state and health
docker compose -f docker-compose.prod.yml logs api --tail 100 -f # follow a service's log
docker compose -f docker-compose.prod.yml exec api bash          # shell in a container
docker compose -f docker-compose.prod.yml restart api            # restart one service
```

**Database:**

```bash
docker compose -f docker-compose.prod.yml exec db psql -U intelfeed -d intelfeed
```

```sql
SELECT count(*) FROM entries;
SELECT count(*) FROM feeds WHERE is_active;
```

**Celery:**

```bash
docker compose -f docker-compose.prod.yml exec celery-worker celery -A app.workers.celery_app inspect active
docker compose -f docker-compose.prod.yml exec celery-worker celery -A app.workers.celery_app inspect stats
# Deletes every waiting job in the celery queue
docker compose -f docker-compose.prod.yml exec celery-worker celery -A app.workers.celery_app purge -Q celery
```

**Migrations:**

```bash
docker compose -f docker-compose.prod.yml exec api alembic current
docker compose -f docker-compose.prod.yml exec api alembic history
```

### Log Analysis Examples

Logs are JSON lines, so use `jq`:

```bash
# Last 20 errors
tail -n 20 logs/error.log | jq .

# Requests slower than one second
jq -c 'select(.duration_ms > 1000) | {path, status, duration_ms}' logs/http.log | tail

# Rate-limited requests
grep '"rate_limited"' logs/app.log | tail
```

---

## Update & Deployment

[update.sh](../update.sh) updates a prod checkout from `origin/main`. Run from cron (the script's own example is every 2 minutes), a push to `main` becomes a deploy:

```bash
*/2 * * * * /path/to/intelfeed/update.sh
```

Run by hand with `./update.sh`. Each run:

1. Fetches `origin/main`; stops if nothing is new and no update is unfinished.
2. Pulls.
3. Does the least that works for what changed since the last deploy:

| Changed path | Action |
|---|---|
| `backend/**`, `frontend/**`, `db/**`, `piper/**`, `docker-compose*.yml` | Build the images, then `up -d` |
| `Caddyfile` | `caddy reload` in place (TLS stays up) |
| Anything else | Pull only; nothing restarts |

4. Before a build, ensures `./tts_media`, `./ingest_files`, `./telegram_data` and `./telegram_media` exist, owned by uid 1000.
5. Logs to `logs/update.log` (JSON lines, also in **Settings → Logs**).

- **Most commits need no rebuild.** Docs, scripts, Android and CI aren't in any image; mounted `./docs` and `./scripts` go live on pull. Rebuilds cost CPU minutes and `up -d` drops in-flight requests.
- **Code changes rebuild** (prod has no code mounts).
- **Images build before anything restarts.** A failed build leaves the stack running; the next run retries.
- **It diffs against what's deployed.** `.update-deployed` (gitignored) holds the containers' build commit, so a failed backend build retries even after a docs commit lands on top; a missing file during a retry means rebuild.
- **The app's version can trail `HEAD`** after a pull-only run.
- **Profile services:** `up -d` doesn't start `libretranslate`; use `--profile translate`.

**From a workstation,** [scripts/ops/deploy.sh](../scripts/ops/deploy.sh) (on `main`) pushes, runs `update.sh` over SSH, checks for `Update complete.`, and fails on any unhealthy, restarting or exited container. Set `INTELFEED_PROD_HOST` (such as `user@prod.example.com`); `INTELFEED_PROD_DIR` overrides the host checkout path (default `intelfeed`). `--skip-push` deploys what's already on origin.

---

## Summary: Operations Checklist

- [ ] All containers up and healthy (`docker compose -f docker-compose.prod.yml ps`)
- [ ] No placeholder secrets in `.env`; `ENCRYPTION_KEY` backed up
- [ ] Site loads over HTTPS with a valid certificate
- [ ] `logs/error.log` checked regularly
- [ ] Nightly backups copied off the host; a restore tested
- [ ] Prometheus scraping `api:8000/metrics` inside the compose network, if used
- [ ] Memory and disk under ~80%
- [ ] `update.sh` cron running and `logs/update.log` ending in `Update complete.`

---

## References

- Compose: [docker-compose.prod.yml](../docker-compose.prod.yml), [docker-compose.dev.yml](../docker-compose.dev.yml)
- Proxy: [Caddyfile](../Caddyfile), [frontend/nginx.conf](../frontend/nginx.conf)
- Startup and migrations: [backend/entrypoint.sh](../backend/entrypoint.sh)
- Backups: [scripts/ops/backup.sh](../scripts/ops/backup.sh), [scripts/ops/restore.sh](../scripts/ops/restore.sh)
- Updates: [update.sh](../update.sh), [scripts/ops/deploy.sh](../scripts/ops/deploy.sh)
- Install: [setup.md](../setup.md)
- Design: [architecture.md](./architecture.md), [diagrams/operations-service-topology.md](./diagrams/operations-service-topology.md)
