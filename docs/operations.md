# Operations Guide

Deployment, security, observability, and troubleshooting for IntelFeed in production.

**Prerequisites:** Complete [setup.md](../setup.md) first. See [architecture.md](./architecture.md) for system design context.

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

---

## Deployment Architecture

### Dev vs. Prod Docker Compose

**Development** (`docker-compose.dev.yml`):
- **Volumes:** Full code volume mount (`./backend:/app`) for hot reload
- **API:** Uvicorn with `--reload` flag (slow, for development)
- **Workers:** 4 Celery workers (light load) + the single-concurrency `celery-worker-ai` serializing AI tasks (copilot, batch AI jobs)
- **Healthchecks:** All services
- **Ports:** Exposed individually (8000, 5433, 6380, 7700, 5050, 5060, 3001)
- **Resources:** Unlimited memory
- **Storage:** Local Docker volumes (`pgdata`, `redisdata`, `meilidata`, …)

**Production** (`docker-compose.prod.yml`):
- **Volumes:** No code mounts (code copied into image) — only host mounts for logs, backups, `docs/` (read-only, serves the in-app documentation), Telegram session/media, and TTS audio, plus named volumes for data/cache
- **API:** Gunicorn with 4 UvicornWorker workers (180s timeout). Startup seeders (enrichment sources, AI tasks) serialize across workers via a Postgres advisory lock, so multiple workers never race the unique keys.
- **Workers:** 4 Celery workers with memory limits (300 MB/child, 50 tasks/child), plus `celery-worker-ai` (`--queues=ai,claude_code` — the second is the pre-rename queue name, kept so in-flight tasks from an older deploy still drain; concurrency 1 via `CLAUDE_CODE_CONCURRENCY`, `--prefetch-multiplier=1`, `--max-tasks-per-child=20`. It serializes every AI-provider call and owns the Claude CLI OAuth credentials volume). Managed by `update.sh` like every other service
- **LibreTranslate:** on-demand only, behind the `translate` compose profile (preloading ~20 language models pins ~740 MB 24/7). Start with `--profile translate up -d libretranslate`; auto-translate degrades gracefully while it's down and the `retry_untranslated_entries` beat task (every 30 min) backfills once it's up
- **Redis:** Capped at 1 GB (`--maxmemory 1gb --maxmemory-policy volatile-lru`); Celery task results expire after 1 hour (`result_expires=3600`), which keeps accumulated results from triggering "OOM command not allowed"
- **Healthchecks:** All services (10–30s intervals)
- **Port:** Only Caddy reverse proxy (80, 443)
- **Networks:** Separate `backend` and `frontend` networks (service isolation)
- **Resources:** Per-service memory limits (DB 1500M, Redis 1500M, Meilisearch 1536M, LibreTranslate 2G, Piper 1536M, API 1G, Workers 2G, CLI worker 1G, Beat 256M, Telegram listener 512M, Frontend 128M, Caddy 128M)
- **OOM priorities:** `oom_score_adj` orders kernel OOM kills — protect db (−900), redis (−800), api (−700), caddy (−500); sacrifice workers (+600) and piper (+300) first. Paired with host swap so a memory spike degrades instead of taking the site down
- **Restart:** `unless-stopped` (auto-recovery on crash)

**Key Diff:** Dev mounts code; prod bakes it into the image. Prod has strict resource limits.

File: [docker-compose.dev.yml](../docker-compose.dev.yml)
File: [docker-compose.prod.yml](../docker-compose.prod.yml)

---

## Service Inventory

### Service Dependency Graph

See [diagrams/operations-service-topology.md](./diagrams/operations-service-topology.md) for the full production service graph (Caddy → frontend nginx → API, the backend data services, and the Celery/Telegram/CLI workers).

### Services & Ports

| Service | Port (Dev) | Port (Prod) | Docker Network | Purpose |
|---------|------------|------------|---|---|
| **PostgreSQL** | 5433 | internal | backend | Persistent data store |
| **Redis** | 6380 | internal | backend | Celery broker, caching, locks |
| **Meilisearch** | 7700 | internal (7700) | backend | Full-text search index |
| **LibreTranslate** | 5050 | internal (5000) | backend | Entry translation (self-hosted, pinned v1.9.6). Prod: behind the `translate` compose profile (on-demand) |
| **Piper** | 5060 | internal (5000) | backend | Text-to-speech read-aloud sidecar (called by API + workers) |
| **API** | 8000 | 8000 (internal) | backend, frontend | FastAPI application |
| **Celery Worker** | — | — | backend | Background job execution (`celery` queue) |
| **Celery Worker (AI)** | — | — | backend | Serialized AI tasks + copilot turns (`ai` queue, concurrency 1) |
| **Celery Beat** | — | — | backend | Scheduled job execution |
| **Telegram Listener** | — | — | backend | Telegram channel monitoring |
| **Frontend** | 3001 | 80 (internal) | frontend | React SPA (nginx, proxies `/api/*` to API) |
| **Caddy** | — | 80, 443 | frontend | Reverse proxy + TLS |

**Network Isolation (Prod):**
- `backend` network: DB, Redis, Meilisearch, API, workers (no external access)
- `frontend` network: Frontend, Caddy (external access via Caddy)
- Only Caddy exposed to internet (ports 80, 443)

File: [docker-compose.prod.yml](../docker-compose.prod.yml)

### Caddy Reverse Proxy & TLS

**Configuration:** `Caddyfile`

```
{$SITE_DOMAIN} {
    # Service worker never cached
    @sw path /sw.js
    header @sw Cache-Control "no-store"

    reverse_proxy frontend:80
}
```

The domain comes from `SITE_DOMAIN` in `.env`, which `docker-compose.prod.yml` passes into the caddy container. It is required in prod — compose fails fast with a message rather than starting a Caddy with no site.

**What it does:**
- Auto-obtains a Let's Encrypt certificate for `$SITE_DOMAIN`
- Manages TLS termination
- Routes all traffic to frontend:80
- Frontend internally routes `/api/*` to API container

**SPA caching:** the frontend nginx serves `index.html` with `expires -1` so browsers always revalidate it. Without it, a heuristically cached `index.html` would reference the previous build's hashed chunks after a deploy, stranding users on a stale bundle. The service worker (`/sw.js`) is additionally `no-store` at the Caddy layer.

**Important:** DNS must resolve `$SITE_DOMAIN` → EC2 public IP **before** Caddy starts (Let's Encrypt verification).

File: [Caddyfile](../Caddyfile), [frontend/nginx.conf](../frontend/nginx.conf)

---

## Configuration & Secrets

### Environment Variables

**Required in `.env`:**

```bash
# Database
POSTGRES_HOST=db
POSTGRES_PORT=5432
POSTGRES_DB=intelfeed
POSTGRES_USER=intelfeed
POSTGRES_PASSWORD=<generated>

# Redis
REDIS_PASSWORD=<generated>
REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379/0

# Meilisearch
MEILI_URL=http://meilisearch:7700
MEILI_MASTER_KEY=<generated>

# API
SECRET_KEY=<generated>  # JWT signing key
ENCRYPTION_KEY=<generated>  # Fernet key for encrypted DB columns
CORS_ORIGINS=["https://intelfeed.example.com"]  # JSON array — a bare string fails to parse

# Frontend
VITE_API_URL=/api
```

**Optional:**
- `SENTRY_DSN` — Sentry error tracking
- `BACKUP_ENCRYPT_KEY` — GPG encryption for backups
- `RUN_MIGRATIONS=true` — auto-run migrations on startup (set in compose)
- `ENV=production` — enable production optimizations

**Secret Generation (setup.md references these):**

```bash
# SECRET_KEY (32 hex bytes)
openssl rand -hex 32

# ENCRYPTION_KEY (Fernet base64)
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# Password & MEILI_MASTER_KEY (24 base64 bytes)
openssl rand -base64 24
```

File: [`setup.md`](../setup.md), step 5

### System Settings (Database)

**Singleton table:** `system_settings` (id = 1)

**Columns:**
- `settings` (JSONB) — public configuration
- `secrets` (JSONB) — encrypted secrets (API keys, webhook URLs)
- `updated_at` — last modification

Keys are declared in `CONFIGURABLE_KEYS` in `backend/app/services/system_settings.py`; DB values override the `.env`/`config.py` defaults (`config.get()` chain). **Example settings:**

```json
{
  "default_feed_fetch_interval": 30,
  "image_proxy_enabled": true,
  "ai_one_pass_enabled": true,
  "ai_daily_budget_usd": 5.0,
  "autolinker_min_name_length": 4,
  "adjudication_mode": "shadow",
  "_job_schedule_overrides": {
    "fetch-feeds": {"type": "crontab", "minute": "*/15"}
  }
}
```

(`_job_schedule_overrides` is written by the Jobs UI via `app/api/job_schedules.py`, mirrored into Redis for beat.)

**Secrets (encrypted):** `github_token`, `nvd_api_key`, `sentry_dsn`, `registration_invite_code` — stored Fernet-encrypted in the `secrets` JSONB, masked in API responses. (AI-provider and enrichment API keys live on their own tables, not here.)

Access via API (admin only): `GET /api/system-settings` / `PATCH /api/system-settings`

---

## Security

### Authentication & JWT

**Flow:**
1. User submits username + password → `/api/auth/login`
2. API verifies password (bcrypt) against `users.password_hash`
3. API returns `access_token` (2-hour TTL, `access_token_expire_minutes`) + `refresh_token` (7-day TTL)
4. Frontend stores tokens in localStorage (Zustand `authStore` with persist middleware)
5. Frontend attaches `Authorization: Bearer <access_token>` header to requests
6. API verifies token signature and expiration

**Token Structure (JWT payload):**

```json
{
  "sub": "<user_uuid>",
  "role": "admin|user",
  "username": "alice",
  "type": "access",
  "jti": "<token_id>",
  "exp": 1234567890,
  "iat": 1234567800
}
```

**Refresh Flow:**
- Frontend detects 401 response (expired access token)
- Frontend calls `/api/auth/refresh` with refresh token
- API returns new access token
- Frontend retries original request

**Token Blacklist (on logout):**
- API adds JTI to Redis blacklist with TTL = token expiration
- Subsequent requests check Redis for revoked token

**Password Hashing:**
- Bcrypt with salt (cost 12)
- Never store plaintext passwords

File: `backend/app/core/security.py` (lines 1–100+)

### HTTPS & TLS

**Caddy auto-TLS:**
- Requests Let's Encrypt certificate on first run
- Auto-renews 30 days before expiration
- Stores certs in `caddy_data` volume (persistent)
- Enforces HTTP → HTTPS redirect

**SSL/TLS versions:** TLS 1.2+ (Caddy default)

**Certificate validation:** `$SITE_DOMAIN` must resolve to the server IP before Caddy startup.

File: [Caddyfile](../Caddyfile)

### Cloudflare Origin Lockdown

The site is proxied through Cloudflare, but an origin that accepts 80/443 from anywhere lets anyone who learns its IP bypass the WAF, bot rules, and rate limiting entirely. `scripts/ops/cf-origin-lockdown.sh` closes that hole by restricting inbound 80/443 to Cloudflare's published edge ranges via ufw:

```bash
sudo ./scripts/ops/cf-origin-lockdown.sh [--dry-run]
```

- Narrows **both** rule families: `ufw allow` (INPUT — the host-bound docker-proxy listener) **and** `ufw route allow` (FORWARD — Docker DNATs container traffic through the FORWARD chain). Narrowing only one leaves the other wide open.
- Idempotent — re-run any time to refresh the ranges (fetched live from cloudflare.com/ips-v4 and ips-v6, with a sanity gate so a bad fetch never wipes the rules).
- Port 22 is never touched, so it cannot lock you out of SSH.

File: [scripts/ops/cf-origin-lockdown.sh](../scripts/ops/cf-origin-lockdown.sh)

With the origin locked down, every request's `CF-Connecting-IP` header is Cloudflare's, so set `TRUSTED_CLIENT_IP_HEADER=CF-Connecting-IP` in `.env`: the rate limiter then buckets anonymous traffic (login, the share page's AI calls) per visitor instead of per edge node. Without the lockdown leave it unset — anyone who reaches the origin directly could send the header.

### Security Headers

**Applied by `SecurityHeadersMiddleware`:**

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 0
Referrer-Policy: strict-origin-when-cross-origin
Strict-Transport-Security: max-age=63072000; includeSubDomains
Content-Security-Policy: default-src 'self'; script-src 'self'; img-src 'self' data: blob: https:; ...
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

- **CSP:** No external scripts, styles from CDN (except for `/docs`), image proxying allowed
- **HSTS:** 730 days cache (enforce HTTPS)
- **Clickjacking:** X-Frame-Options DENY (no embedding)

File: `backend/app/core/security_headers.py` (lines 5–25)

### CORS Configuration

Value is a JSON array of allowed origins (a bare string fails to parse):

**Dev:** `CORS_ORIGINS=["http://localhost:3000","http://localhost:3001"]`
**Prod:** `CORS_ORIGINS=["https://intelfeed.example.com"]`

Configured in FastAPI middleware (`app/main.py`, line ~14):

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

---

### Rate Limiting

**Middleware:** `RateLimitMiddleware` in `app/core/rate_limit.py`

Limits are bucketed by path, not a global per-IP cap — general authenticated API traffic is **not** rate limited (self-hosted app with a small trusted user base; a global cap broke normal operation with 200+ feeds triggering SSE-driven query invalidations):

| Bucket | Paths | Limit |
|--------|-------|-------|
| `auth` | `/api/auth/login`, `/api/auth/register`, `/api/auth/refresh` | 10 req / 5 min (brute-force protection) |
| `chat` | `POST /api/chat` | 10 req / min (protects API credits) |
| `ai` | `/api/ai/*` inference calls (config/read prefixes like `/api/ai/tasks`, `/api/ai/providers`, `/api/ai/prompts` are exempt) | 20 req / min |
| everything else | — | not limited |

**Exempt:** `/api/health`, `/metrics` (the metrics endpoint has its own IP allowlist), and all `OPTIONS` requests.

**Mechanics:** Redis sliding-window (sorted set per identity). Identity is the `sub` of a JWT whose signature verifies, else the client IP: the first `X-Forwarded-For` hop when the direct peer is on a private network (Caddy strips the incoming header and writes its own peer there, so it can't be forged), or the header named in `TRUSTED_CLIENT_IP_HEADER` first (an unverified bearer falls back to the IP). This trusts whatever a private-network peer forwards, so the API port must only be reachable through the proxy, as the prod compose file arranges; a port 8000 published to the LAN would let a caller forge the header and the bucket. If Redis is down the limiter fails open (allows the request, logs a warning). Responses carry `X-RateLimit-Limit` / `X-RateLimit-Remaining`; a 429 includes `Retry-After`.

File: `backend/app/core/rate_limit.py`

### SQL Injection Prevention

**Method:** SQLAlchemy ORM (parameterized queries)

All database access goes through SQLAlchemy, which:
- Uses parameterized queries (placeholders, no string interpolation)
- Prevents SQL injection by design

**Raw SQL (if needed):**
```python
from sqlalchemy import text

result = await db.execute(text(
    "SELECT * FROM entries WHERE id = :id"
).bindparams(id=entry_id))
```

Never do:
```python
# WRONG — vulnerable to SQL injection
db.execute(f"SELECT * FROM entries WHERE id = '{entry_id}'")
```

### CSRF Protection

Not applicable by design: the API does not use cookie-based sessions. Authentication is a Bearer token read from localStorage and attached explicitly by the frontend's Axios client — a cross-site request from another origin never carries it, so the classic CSRF vector doesn't exist. There is no CSRF token middleware.

### XSS & Content Sanitization

**Server-side:**
- HTML in feed entries sanitized with the `nh3` library (Rust ammonia bindings) before storage
- Only safe tags allowed: `<p>`, `<a>`, `<img>`, `<br>`, `<code>`, `<pre>`, etc.
- `<script>`, `<iframe>`, `<style>` stripped

**Client-side (Frontend):**
- `DOMPurify` library sanitizes HTML before rendering
- CSP prevents inline scripts

**Image Proxying:**
- All `<img src>` URLs rewritten to `/api/proxy/image?url=...`
- Prevents direct external resource loading
- Caches proxied images locally (protects against tracking)
- Migration script: `scripts/maintenance/resanitize_entries.py` fixed historical entries

File: [scripts/maintenance/resanitize_entries.py](../scripts/maintenance/resanitize_entries.py)

### Encrypted Columns

**Columns encrypted at rest (Fernet):**
- `ai_providers.api_key_encrypted` — AI provider API keys
- `enrichment_sources.api_key_encrypted` — decrypted on-read for API calls
- `user_enrichment_overrides.api_key_encrypted` — per-user API key
- `system_settings.secrets` — JSONB of encrypted secrets

(`users.password_hash` is bcrypt-*hashed*, not encrypted — it is never decrypted, only compared.)

**Encryption:** Fernet (AES-128 + HMAC) via `cryptography` library

```python
from cryptography.fernet import Fernet

cipher = Fernet(settings.encryption_key)
encrypted = cipher.encrypt(plaintext.encode())
decrypted = cipher.decrypt(encrypted).decode()
```

**Key storage:** `ENCRYPTION_KEY` env var (must be backed up securely)

---

## Observability

### Structured Logging

**Framework:** `structlog` with JSON output

**Log files** (in `logs/` directory):
- `app.log` — all INFO+ logs (catch-all)
- `error.log` — ERROR+ only
- `http.log` — HTTP request/response logs
- `tasks.log` — Celery worker/beat logs
- `audit.log` — mutating API actions (create/update/delete)
- `update.log` — `update.sh` deployment log

**Log format (JSON lines):**

```json
{"timestamp": "2026-05-03T21:02:00Z", "level": "INFO", "event": "entry_fetched", "feed_id": "uuid-123", "logger": "app.tasks.fetch_feeds"}
{"timestamp": "2026-05-03T21:02:01Z", "level": "ERROR", "event": "api_error", "exception": "...", "logger": "app.api.entries"}
```

**Correlation IDs:**
- Each request gets unique `request_id` (set via middleware)
- All logs within request include `request_id`
- Enables tracing request → worker job → database queries

File: `backend/app/core/logging.py` (lines 1–150+)

**API Logs Viewer (Admin):**
- `GET /api/logs` — list available log files
- `GET /api/logs/{filename}?lines=500` — tail last 500 lines
- `DELETE /api/logs/{filename}` — clear log file

File: `backend/app/api/logs.py` (lines 1–119)

### Prometheus Metrics

**Endpoint:** `/metrics` — the API gates it to loopback/RFC1918 client IPs (`app/api/metrics.py`). In prod the frontend nginx returns **404** for `/metrics` outright: the proxy hop rewrote `$remote_addr`/`X-Real-IP` to the Caddy container's (always-RFC1918) IP, which defeated any ACL, so the path is simply never served through the proxy. Scrapers must run inside the compose `backend` network and hit `http://api:8000/metrics` directly.

**Instrumented metrics:**

| Metric | Type | Labels |
|--------|------|--------|
| `intelfeed_http_requests_total` | Counter | method, path, status |
| `intelfeed_http_request_duration_seconds` | Histogram | method, path |
| `intelfeed_feeds_active` | Gauge | — |
| `intelfeed_feed_fetch_total` | Counter | status (success, error, not_modified) |
| `intelfeed_feed_fetch_duration_seconds` | Histogram | feed_type |
| `intelfeed_entries_ingested_total` | Counter | feed_type |
| `intelfeed_ai_requests_total` | Counter | provider, task |
| `intelfeed_ai_tokens_total` | Counter | provider, direction (input/output) |
| `intelfeed_ai_cost_total` | Counter | provider |
| `intelfeed_automation_runs_total` | Counter | trigger_type, status |
| `intelfeed_search_queries_total` | Counter | — |

**Scrape config (Prometheus, running as a container on the compose `backend` network):**

```yaml
scrape_configs:
  - job_name: 'intelfeed'
    scrape_interval: 15s
    static_configs:
      - targets: ['api:8000']
    metrics_path: '/metrics'
```

(In dev, `localhost:8000` works from the host since the API port is published.)

File: `backend/app/core/metrics.py` (lines 1–100+)

### Health Endpoints

**Liveness check:** `GET /api/health`

**Response (healthy):**
```json
{
  "status": "healthy",
  "version": "0.1.0",
  "components": {
    "database": {"status": "ok", "latency_ms": 2.5},
    "redis": {"status": "ok", "latency_ms": 1.2},
    "meilisearch": {"status": "ok", "latency_ms": 5.3}
  }
}
```

**Statuses:**
- `healthy` — all critical components OK (database is critical)
- `degraded` — database OK, but non-critical services down
- `unhealthy` — database down

**Docker Compose healthcheck:**
```yaml
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:8000/api/health"]
  interval: 30s
  timeout: 10s
  retries: 3
  start_period: 30s
```

File: `backend/app/api/health.py` (lines 1–73)

---

## Backups & Recovery

### Backup Strategy

**Script:** `scripts/ops/backup.sh`

**What's backed up:**
1. **PostgreSQL database** — full dump via `pg_dump --clean --if-exists --no-owner`
2. **Meilisearch index** — snapshot via `POST /snapshots`, executed **inside the meilisearch container** (`docker compose exec meilisearch curl …`). This works in prod where Meilisearch is internal-only (no host port) and needs no host-side env: the container ships curl (its healthcheck uses it) and already has `MEILI_MASTER_KEY`. The snapshot is written asynchronously by Meilisearch to `/meili_data/snapshots` in the `meilidata` volume — not to `backups/`.
3. **Compression:** gzip (default) or GPG+gzip (if `BACKUP_ENCRYPT_KEY` set)

**Failure behavior:** a failed `pg_dump` aborts immediately (`set -e`). A failed Meilisearch snapshot does **not** block the database backup — the script logs a clear `ERROR`, still runs retention pruning, and then exits `1` so cron/monitoring notices.

**Streaming:** the dump is piped straight through `gzip` (and `gpg` when encrypting) to the backup file — no uncompressed intermediate ever hits disk or memory. Resource usage stays flat regardless of database size; buffering the dump before compressing it would risk OOMing the host on large DBs.

**Schedule:** Recommended daily or after major changes

```bash
# Run manually
./scripts/ops/backup.sh ./backups

# Cron (daily at 2 AM)
0 2 * * * /path/to/intelfeed/scripts/ops/backup.sh /mnt/backups
```

**Retention:** 7 days (configurable `RETENTION_DAYS=7`)

**Backup file:** `backups/intelfeed_YYYYMMDD_HHMMSS.sql.gz` (or `.sql.gz.gpg`)

**Size estimate:** ~50–200 MB compressed (depends on entry count)

File: [scripts/ops/backup.sh](../scripts/ops/backup.sh)

### Restore Procedure

**Script:** `scripts/ops/restore.sh`

**Restore from backup:**

```bash
./scripts/ops/restore.sh ./backups/intelfeed_20260503_020000.sql.gz
# OR (encrypted)
export BACKUP_ENCRYPT_KEY="<passphrase>"
./scripts/ops/restore.sh ./backups/intelfeed_20260503_020000.sql.gz.gpg
```

**What it does:**
1. Stops API and worker services
2. Drops and recreates database
3. Restores from backup (gunzip → psql)
4. Restarts services

**Warning:** Restoring **overwrites** the current database. Backups should be immutable copies.

**Meilisearch restore:** Manual — snapshots live in the `meilidata` volume at `/meili_data/snapshots/` (created by `backup.sh`):
```bash
# List available snapshots
docker compose -f docker-compose.prod.yml exec meilisearch ls /meili_data/snapshots

# Import: start Meilisearch once with --import-snapshot pointing at the file
# (e.g. temporary `command: meilisearch --import-snapshot /meili_data/snapshots/<file>.snapshot`)
```
Alternatively, skip snapshot restore entirely: the index is derived data and can be rebuilt from PostgreSQL via the search reindex task.

File: [scripts/ops/restore.sh](../scripts/ops/restore.sh)

### Volume Layout

**Production volumes:**

| Volume | Mount | Purpose | Cleanup |
|--------|-------|---------|---------|
| `pgdata` | `/var/lib/postgresql/data` | DB persistence | Never (data)
| `redisdata` | `/data` | Redis persistence (AOF) | With DB restore |
| `meilidata` | `/meili_data` | Meilisearch index | With index rebuild |
| `image_cache` | `/app/data/image_cache` | Cached article images | Safe to delete (re-cache on next access) |
| `libretranslate_models` | `/home/libretranslate/.local` | Downloaded language models | Safe to delete (re-downloaded on start) |
| `piper_voices` | `/voices` | Downloaded Piper TTS voice models | Safe to delete (re-downloaded on start) |
| `claude_cli` | `/home/appuser/.claude` | Claude Code CLI OAuth credentials + state (CLI worker only) | Never (loses copilot auth) |
| `caddy_data` | `/data` | TLS certificates | Never (expiration tracking) |
| `caddy_config` | `/config` | Caddy config state | Safe to delete (re-generated) |

**Logs:** Mounted from host `./logs/` (not a volume)
**Backups:** Mounted from host `./backups/` (not a volume)
**Docs:** `./docs/` mounted read-only into the API container at `/app/docs` — serves the in-app documentation (`app/api/documentation.py`); if the mount is missing the docs page degrades to an empty index
**Telegram:** Session file and media mounted from host `./telegram_data/` and `./telegram_media/` (media grows unbounded — monitor disk)
**TTS audio:** Generated read-aloud MP3s mounted from host `./tts_media/` — written by uid 1000 inside the containers, so the dir must be owned by 1000 (`update.sh` chowns it idempotently)
**Manual upload originals:** The files behind bulk ingest mounted from host `./ingest_files/` (api writes, celery-worker reads and evicts past `ingest_files_ttl_days`) — same uid-1000 ownership rule, same idempotent chown in `update.sh`

---

## Performance & Scaling

### Bottlenecks

**Common failure points:**

1. **Feed fetching** — if many feeds + slow upstream
   - Mitigation: Increase fetch workers, stagger feed schedules, HTTP timeout

2. **Meilisearch indexing** — if large entry volume
   - Mitigation: Run rebuild at off-peak hours (2 AM), increase `MEILI_MAX_INDEX_SIZE`

3. **AI API calls** — if heavy auto-extraction + many providers
   - Mitigation: Rate limit via `AIProvider.config`, queue management

4. **Database connections** — if high concurrency
   - Mitigation: Increase `max_connections` in PostgreSQL, tune connection pool

5. **Telegram listener** — if monitoring many channels
   - Mitigation: Stagger polling, filter channels

### Scaling Strategies

**Vertical Scaling (single server):**
- Increase EC2 instance size (more CPU, RAM)
- Increase resource limits in `docker-compose.prod.yml` (see lines 19–126)
- Add Celery workers: change `--concurrency=4` to `--concurrency=8`

**Horizontal Scaling (multiple servers):**
- Run PostgreSQL on RDS (managed)
- Run Redis on ElastiCache
- Run multiple Celery worker nodes (share Broker & Database)
- Use ELB/ALB for load balancing API

**Queue Separation (single server):**
```bash
# Worker 1 — feed fetching only
celery -A app.workers.celery_app worker -Q feeds --loglevel=info

# Worker 2 — AI extraction only
celery -A app.workers.celery_app worker -Q ai --loglevel=info

# Worker 3 — general tasks
celery -A app.workers.celery_app worker -Q celery --loglevel=info
```

**Database Tuning:**
```sql
-- Increase connections (in PostgreSQL container)
ALTER SYSTEM SET max_connections = 500;
ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET work_mem = '32MB';
SELECT pg_reload_conf();
```

---

## Troubleshooting

### Common Failure Modes & Solutions

#### 1. **Feed Stuck (Redis Lock)**

**Symptom:** Feed not updating despite scheduled time.

**Cause:** Previous fetch job holds Redis lock (crashed without releasing).

**Fix:**
```bash
# Clear lock manually (locks self-expire after 10 minutes)
docker compose -f docker-compose.prod.yml exec redis redis-cli -a ${REDIS_PASSWORD}
> DEL feed_fetch:<feed_id>
> EXIT

# Restart feed fetcher
docker compose -f docker-compose.prod.yml restart celery-worker celery-beat
```

#### 2. **Failed Database Migration**

**Symptom:** API fails to start; migration error in logs.

**Cause:** Migration file has syntax error or schema conflict.

**Fix:**
```bash
# Check current migration status
docker compose -f docker-compose.prod.yml exec api alembic current
docker compose -f docker-compose.prod.yml exec api alembic history

# Downgrade to last known-good migration
docker compose -f docker-compose.prod.yml exec api alembic downgrade -1

# Fix migration file, commit, and re-deploy
git commit -am "fix: migration syntax"
./update.sh
```

#### 3. **Meilisearch Out of Sync**

**Symptom:** Entries visible in UI but not searchable; search returns stale results.

**Cause:** Index rebuild failed or lagged.

**Fix:** Trigger a full rebuild from the UI (**Settings > Engine** — "Rebuild search index" clears the index and re-indexes all entries from the database), or from the CLI:
```bash
# Re-trigger rebuild job (task lives in intel_feed_tasks and takes an admin user id)
docker compose -f docker-compose.prod.yml exec api \
  python -c "from app.workers.intel_feed_tasks import rebuild_search_index; rebuild_search_index.delay('<admin_user_uuid>')"
```

#### 4. **Telegram Listener Idle**

**Symptom:** Telegram mentions stop appearing; listener logs show no activity.

**Cause:** Telegram session expired or network connectivity lost.

**Fix:**
```bash
# Check listener logs
docker compose -f docker-compose.prod.yml logs telegram-listener --tail 100

# Restart listener
docker compose -f docker-compose.prod.yml restart telegram-listener

# Re-authenticate if the session expired (interactive; writes the session file)
docker compose -f docker-compose.prod.yml exec telegram-listener \
  python scripts/telegram/telegram_login.py
```

#### 5. **AI Provider Timeout**

**Symptom:** AI extraction tasks fail with timeout; error logs show "exceeded maximum retries".

**Cause:** Provider API slow or unreachable; request timeout too short.

**Fix:**
- Increase `timeout_seconds` in the affected task's assignment config in **Settings > AI Configuration**, or temporarily reassign the task to a healthier provider/model there.
- Inspect provider config via the API:
```bash
curl -H "Authorization: Bearer ${ACCESS_TOKEN}" http://localhost:8000/api/ai/providers
```

#### 6. **High Memory Usage**

**Symptom:** Container killed due to OOM; Docker logs show "Killed" signal.

**Cause:** Memory leak in worker or large cache buildup.

**Fix:**
```bash
# Check memory usage
docker compose -f docker-compose.prod.yml stats

# Increase worker memory limit (in docker-compose.prod.yml)
# celery-worker deploy.resources.limits.memory: "3G"  (was 2G)

# OR reduce Celery worker count
# --concurrency=2 (was 4)

# Restart with new limits
docker compose -f docker-compose.prod.yml up -d --build
```

#### 7. **Redis "OOM command not allowed"**

**Symptom:** Tasks fail; Redis logs `OOM command not allowed when used memory > 'maxmemory'`.

**Cause:** Redis hit its memory cap — usually Celery task results accumulating in the same Redis as the broker/copilot streams.

**Fix:** Two mitigations are on by default — Redis runs with `--maxmemory 1gb --maxmemory-policy volatile-lru`, and Celery `result_expires=3600` caps result retention at 1 hour. If OOM still occurs:
```bash
# Inspect what's consuming memory
docker compose -f docker-compose.prod.yml exec redis redis-cli -a ${REDIS_PASSWORD} INFO memory
docker compose -f docker-compose.prod.yml exec redis redis-cli -a ${REDIS_PASSWORD} --bigkeys

# volatile-lru only evicts keys WITH a TTL — look for large keys without one
```

### Useful Commands

**One-shot after deploying the per-user tags migration (`y6q8s0u2w4y6`):**
```bash
# Re-push tag fields to Meilisearch so `tag:` search and the Tags facet stop showing
# pre-migration shared tags to everyone. Safe to re-run; --dry-run just counts.
docker compose -f docker-compose.prod.yml exec api python scripts/maintenance/reindex_entry_tags.py --all
```

**Docker Compose:**
```bash
# View logs for service
docker compose -f docker-compose.prod.yml logs api --tail 100 -f

# Execute command in container
docker compose -f docker-compose.prod.yml exec api bash

# View resource usage
docker compose -f docker-compose.prod.yml stats

# Restart service
docker compose -f docker-compose.prod.yml restart api

# Rebuild service
docker compose -f docker-compose.prod.yml up -d --build api
```

**Database:**
```bash
# Connect to PostgreSQL
docker compose -f docker-compose.prod.yml exec db psql -U intelfeed -d intelfeed

# Common queries
SELECT count(*) FROM entries;
SELECT count(*) FROM feeds WHERE is_active = true;
SELECT name, article_count FROM threat_actors ORDER BY article_count DESC LIMIT 10;
```

**Celery (worker inspection):**
```bash
# List active tasks
docker compose -f docker-compose.prod.yml exec celery-worker celery -A app.workers.celery_app inspect active

# Check worker stats
docker compose -f docker-compose.prod.yml exec celery-worker celery -A app.workers.celery_app inspect stats

# Purge queue (warning: deletes pending jobs)
docker compose -f docker-compose.prod.yml exec celery-worker celery -A app.workers.celery_app purge

# Revoke task (stop running task)
docker compose -f docker-compose.prod.yml exec celery-worker celery -A app.workers.celery_app revoke <task_id>
```

**Alembic (migration inspection):**
```bash
# Current migration
docker compose -f docker-compose.prod.yml exec api alembic current

# Migration history
docker compose -f docker-compose.prod.yml exec api alembic history

# Downgrade (careful!)
docker compose -f docker-compose.prod.yml exec api alembic downgrade -1
```

---

### Log Analysis Examples

**Find errors in app.log:**
```bash
grep "ERROR" logs/app.log | tail -20
```

**Find slow HTTP requests (>1 second):**
```bash
grep "duration_ms" logs/http.log | awk '{print $NF}' | awk '$1 > 1000 {print}' | tail
```

**Find failed feed fetches:**
```bash
grep "status.*error" logs/app.log | grep "feed_fetch"
```

**Count entries ingested today:**
```bash
grep "entry_ingested" logs/app.log | grep "$(date +%Y-%m-%d)" | wc -l
```

---

## Update & Deployment

**Automated updates:** `update.sh`

**What it does:**
1. Fetches latest commits from `origin/main`
2. Checks if commits exist (skip if up-to-date)
3. Pulls latest code
4. Classifies what changed since the last deploy, and does the least that works (see below)
5. For an image change: ensures `./tts_media/` and `./ingest_files/` exist and are owned by uid 1000 (chowns if not — Piper audio and manual-upload originals are written by the in-container appuser), then rebuilds images and `up -d`
6. Logs all activity to `logs/update.log`

**It only rebuilds when a rebuild would change something.** Most commits here touch
`docs/`, `scripts/`, `planning/`, the Android client or CI, and none of those are
baked into an image — `./docs`, `./scripts` and `./intelfeed-skill` are bind-mounted
read-only, so new content is live the moment the pull lands. A cold build on the prod
box is minutes of CPU on a box that OOMs under load, and `up -d` drops every request
in flight, so paying that for a typo fix is pure downtime. The classification:

| Changed path | Action |
| --- | --- |
| `backend/**`, `frontend/**`, `db/**`, `piper/**`, `docker-compose*.yml` | `build` then `up -d` |
| `Caddyfile` | `caddy reload` in place (it is bind-mounted, so `up -d` would never re-read it) |
| anything else | pull only; nothing is restarted |

Note that `backend/**` and `frontend/**` count *in full* here, unlike the narrower
`images` filter in CI: prod has no source volume mounts, so the api, worker and SPA
images `COPY` the code at build time and a lone Python or TSX edit reaches the running
stack only through a build.

The decision diffs against `.update-deployed`, a gitignored file holding the commit
the running containers were last built from — **not** against the previous `HEAD`. That
distinction is the whole point: a docs-only commit landing on top of a backend change
that failed to build must still rebuild, and diffing `HEAD~1..HEAD` would skip it.
If that file is missing during a retry the script cannot know what is running, so it
rebuilds.

One consequence: on a pull-only tick the images keep the version stamp of the commit
they were actually built from, so the About page can sit a few commits behind `HEAD`.
That is accurate rather than wrong — the image really is that old.

Note: profile-gated services (`libretranslate`) are **not** restarted by `update.sh` — re-enable them explicitly with `--profile translate` after an update if you use them. (`celery-worker-ai` was un-gated when the CLI-credential era ended; update.sh now manages it like any other service.)

**Usage (manual):**
```bash
./update.sh
```

**Cron (auto-update every 15 minutes):**
```bash
*/15 * * * * /path/to/intelfeed/update.sh
```

**Log file:** `logs/update.log` (JSON format, viewable via `/api/logs/update.log`)

**From a workstation:** `scripts/ops/deploy.sh` wraps the whole flow — pushes `main` to origin, runs `update.sh` on the prod host over SSH, verifies "Update complete." appeared, and checks container health (`docker compose ps`), failing loudly on unhealthy/restarting containers.

File: [update.sh](../update.sh), [scripts/ops/deploy.sh](../scripts/ops/deploy.sh)

---

## Summary: Operations Checklist

- [ ] **Deployment** — services running, healthchecks passing
- [ ] **Secrets** — `.env` file generated, no defaults exposed
- [ ] **TLS** — Caddy certificate valid (check `/data/caddy_data/`)
- [ ] **Logs** — no ERROR entries; check `logs/app.log` daily
- [ ] **Backups** — scheduled daily, tested restore procedure
- [ ] **Monitoring** — `/metrics` accessible, Prometheus scraping
- [ ] **Capacity** — memory usage <80%, disk usage <80%
- [ ] **Security** — security headers present, rate limiting active
- [ ] **Updates** — `update.sh` cron running, migrations up-to-date

---

## References

- Docker Compose: [docker-compose.prod.yml](../docker-compose.prod.yml)
- Caddy: [Caddyfile](../Caddyfile)
- Entrypoint: [backend/entrypoint.sh](../backend/entrypoint.sh)
- Backup/Restore: [scripts/ops/backup.sh](../scripts/ops/backup.sh), [scripts/ops/restore.sh](../scripts/ops/restore.sh)
- Update Script: [update.sh](../update.sh)
- Setup Guide: [setup.md](../setup.md)
- Architecture: [architecture.md](./architecture.md)
- Service topology diagram: [diagrams/operations-service-topology.md](./diagrams/operations-service-topology.md)
