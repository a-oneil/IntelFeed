# REST API Reference

**Version:** 0.1.0  
**Base URL:** `/api`  
**Protocol:** HTTPS (self-hosted)  

## Overview

IntelFeed's FastAPI backend provides a comprehensive REST API for threat intelligence ingestion, enrichment, analysis, and dissemination. The API is designed for self-hosted deployments with a single authenticated user or small teams. See [`backend/app/main.py:767-846`] for router mounting and prefix definitions — 77 routers in all. The interactive OpenAPI docs at `/docs` (and `/redoc`) are generated from the same source and are always current; this page is the narrative companion, not a replacement.

This documentation covers:
- **Authentication & Authorization:** JWT-based with access/refresh tokens
- **Error Handling:** Consistent `AppError` envelopes with structured details
- **Pagination:** Offset/limit (standard) or cursor-based (for large result sets)
- **Rate Limiting:** Per-endpoint strategies to protect against abuse
- **Security:** CORS, security headers, token blacklisting, audit logging

For architectural context, see [`docs/architecture.md`].

---

## Table of Contents

1. [Authentication & Authorization](#authentication--authorization)
2. [Error Handling & Status Codes](#error-handling--status-codes)
3. [Pagination & Cursor Navigation](#pagination--cursor-navigation)
4. [Rate Limiting](#rate-limiting)
5. [Security & Middleware](#security--middleware)
6. [API Endpoints by Domain](#api-endpoints-by-domain)
   - [Auth & Users](#auth--users)
   - [Feeds & Content Ingestion](#feeds--content-ingestion)
   - [Entries & Article Management](#entries--article-management)
   - [Story Threads](#story-threads)
   - [Intelligence Extraction](#intelligence-extraction)
   - [Entity Management](#entity-management)
   - [Intelligence Requirements (PIRs)](#intelligence-requirements-pirs)
   - [Automation & Rules](#automation--rules)
   - [Dashboards & Widgets](#dashboards--widgets)
   - [Detection Rules & Tools](#detection-rules--tools)
   - [AI & Enrichment](#ai--enrichment)
   - [Sharing & Public Endpoints](#sharing--public-endpoints)
   - [System & Operations](#system--operations)
   - [Other Routers](#other-routers)

---

## Authentication & Authorization

### JWT Token Flow

IntelFeed uses **JWT (HS256)** for stateless authentication with access + refresh token rotation.

**Token Types:**
- **Access Token:** Short-lived (default 15 minutes), required for all protected endpoints
- **Refresh Token:** Long-lived (default 7 days), used to obtain new access tokens
- **Token Blacklist:** Redis-backed, tokens are blacklisted on logout or refresh for revocation

See [`backend/app/core/security.py:29-54`] for token generation and [`backend/app/core/security.py:84-107`] for validation.

#### JWT Claims

```json
{
  "sub": "<user_id_uuid>",
  "role": "admin|user",
  "username": "optional",
  "type": "access|refresh",
  "jti": "<token_unique_id>",
  "exp": 1234567890,
  "iat": 1234567800
}
```

#### Common Dependencies

All protected endpoints use:
```python
user: User = Depends(get_current_user)  # Validates JWT, checks blacklist
db: AsyncSession = Depends(get_db)      # Database session
```

- **`get_current_user`** [`backend/app/core/security.py:84`]: Validates access token, blocks blacklisted tokens
- **`get_admin_user`** [`backend/app/core/security.py:129`]: Ensures role == "admin"
- **`get_current_user_from_query`** [`backend/app/core/security.py:109`]: Token via query param (for SSE endpoints)

---

## Error Handling & Status Codes

### Error Response Format

All errors follow a consistent envelope (see [`backend/app/core/exceptions.py`]):

```json
{
  "error": {
    "code": "error_code_string",
    "message": "Human-readable message",
    "details": [
      { "field": "fieldname", "message": "...", "code": "validation_code" }
    ]
  }
}
```

### Common Error Codes

| Code | Status | Meaning |
|------|--------|---------|
| `unauthorized` | 401 | Missing/invalid/expired token |
| `forbidden` | 403 | Insufficient permissions (not admin) |
| `not_found` | 404 | Resource does not exist |
| `conflict` | 409 | Resource already exists (duplicate) |
| `validation_error` | 400 | Request body validation failed |
| `rate_limited` | 429 | Rate limit exceeded |
| `bad_request` | 400 | Invalid query parameters or business logic error |
| `internal_error` | 500 | Unhandled exception |

**Example Error:**
```bash
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user","password":"wrong"}'

# Response:
# {"error":{"code":"unauthorized","message":"Invalid username or password","details":[]}}
```

---

## Pagination & Cursor Navigation

### Offset-Limit Pagination (Standard)

Used for most list endpoints:

```json
{
  "items": [ ... ],
  "total": 1000,
  "limit": 50,
  "offset": 0,
  "has_more": true
}
```

**Query Parameters:**
- `limit`: Max items per page (default 50, max 500)
- `offset`: Page offset (default 0)

**Example:**
```bash
curl http://localhost:8000/api/feeds?limit=20&offset=40
```

### Cursor Pagination (for Large Datasets)

Used by `/api/entries` and other high-cardinality endpoints to avoid deep offset scanning:

```json
{
  "items": [ ... ],
  "next_cursor": "base64_encoded_cursor_token",
  "has_more": true
}
```

**Query Parameters:**
- `limit`: Max items per page (default 50, max 500)
- `cursor`: Opaque token for next page

**Example:**
```bash
# First page
curl http://localhost:8000/api/entries?limit=50

# Next page (use next_cursor from previous response)
curl "http://localhost:8000/api/entries?limit=50&cursor=<next_cursor>"
```

**Note:** When using cursor pagination, `total` count is not available; use `has_more` to detect remaining items.

---

## Rate Limiting

Rate limiting is implemented via middleware (see [`backend/app/core/rate_limit.py`]).

**Limits by Path:**

| Path Pattern | Limit | Window | Reason |
|--------------|-------|--------|--------|
| `/api/auth/login`, `/api/auth/register`, `/api/auth/refresh` | 10 req/5 min | Per identity (user or IP) | Brute-force protection |
| `/api/ai/...` (inference only) | 20 req/min | Per user | Protect API credits |
| `/api/chat` (POST) | 10 req/min | Per user | Protect streaming costs |
| All others | Unlimited | — | Self-hosted, small trusted user base |

**Headers:**
- `X-RateLimit-Limit`: Max requests in window
- `X-RateLimit-Remaining`: Requests left in window
- `Retry-After`: Seconds to wait (on 429)

**Identity:** Derived from JWT `sub` claim; fallback to client IP if unauthenticated.

---

## Security & Middleware

### Middleware Stack (applied bottom-up)

1. **CORS Middleware:** Allow configured origins, credentials, standard methods
2. **RateLimitMiddleware** [`backend/app/core/rate_limit.py`]: Sliding-window rate limiting via Redis
3. **SecurityHeadersMiddleware** [`backend/app/core/security_headers.py`]: Inject CSP, X-Frame-Options, HSTS, etc.
4. **PrometheusMiddleware** [`backend/app/core/metrics.py`]: Observe HTTP metrics
5. **AuditLoggingMiddleware** [`backend/app/core/logging.py`]: Log auth/data changes
6. **RequestLoggingMiddleware** [`backend/app/core/logging.py`]: Structured request/response logs

### Security Headers

**Production Headers:**
- `Strict-Transport-Security: max-age=63072000; includeSubDomains`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Content-Security-Policy: default-src 'self'; ...`
- `Permissions-Policy: camera=(), microphone=(), geolocation=()`

**Docs Endpoints** (`/docs`, `/openapi.json`, `/redoc`): Relaxed CSP to allow CDN JS/CSS from unpkg, jsdelivr.

### Token Blacklisting

On logout or token refresh, the previous token's JTI is added to a Redis set with a TTL equal to remaining token lifetime. All protected endpoints check the blacklist (see [`backend/app/core/security.py:66`], `blacklist_token`).

---

## API Endpoints by Domain

### Auth & Users

Base path: `/api/auth`, `/api/admin/users`

#### Registration & Login

**`GET /api/auth/registration-status`**

Check if registration is open and whether an invite code is required.

**Auth:** None  
**Response:**
```json
{
  "registration_enabled": true,
  "invite_code_required": false
}
```

---

**`POST /api/auth/register`**

Create a new user account. Registration may be disabled or require an invite code. The first account registered on a fresh install automatically becomes the admin.

**Auth:** None  
**Status:** 201 Created  
**Request:**
```json
{
  "username": "alice",
  "password": "securepass123",
  "invite_code": "optional-code"
}
```
**Response:**
```json
{
  "access_token": "eyJhbGc...",
  "refresh_token": "eyJhbGc..."
}
```

See [`backend/app/schemas/auth.py`] for schema details.

---

**`POST /api/auth/login`**

Authenticate with username/password. Tracks `last_login`.

**Auth:** None  
**Status:** 200 OK  
**Request:**
```json
{
  "username": "alice",
  "password": "securepass123"
}
```
**Response:**
```json
{
  "access_token": "eyJhbGc...",
  "refresh_token": "eyJhbGc..."
}
```

**Rate Limit:** 10 req/5 min (brute-force protection)

---

**`POST /api/auth/refresh`**

Issue new access+refresh tokens by rotating refresh token. The old refresh token is blacklisted.

**Auth:** None  
**Status:** 200 OK  
**Request:**
```json
{
  "refresh_token": "eyJhbGc..."
}
```
**Response:**
```json
{
  "access_token": "eyJhbGc...",
  "refresh_token": "eyJhbGc..."
}
```

**Rate Limit:** 10 req/5 min

---

**`POST /api/auth/logout`**

Revoke the current access token and optional refresh token by blacklisting their JTIs.

**Auth:** Bearer token required  
**Status:** 200 OK  
**Request:**
```json
{
  "refresh_token": "eyJhbGc..."
}
```
**Response:**
```json
{
  "message": "Logged out successfully"
}
```

---

**`GET /api/auth/me`**

Get the current authenticated user's profile.

**Auth:** Bearer token required  
**Response:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "username": "alice",
  "role": "admin",
  "is_active": true,
  "settings": {},
  "created_at": "2024-01-15T10:30:00Z",
  "last_login": "2024-01-20T14:22:00Z"
}
```

---

**`PUT /api/auth/me`**

Update the current user's settings (user preferences, UI config, etc.).

**Auth:** Bearer token required  
**Status:** 200 OK  
**Request:**
```json
{
  "settings": {
    "theme": "dark",
    "items_per_page": 25,
    "default_dashboard": "summary"
  }
}
```

---

**`PATCH /api/auth/me/settings`**

Shallow-merge top-level keys into the current user's settings blob, leaving every key not named in the request untouched. Prefer this over `PUT /api/auth/me` whenever a client writes one slice of the blob (triage view, table layouts) — a full replace built from a stale snapshot silently drops the other slices.

**Auth:** Bearer token required  
**Status:** 200 OK — returns the full updated user  
**Request:**
```json
{
  "settings": {
    "table_layouts": {
      "entries": {
        "columnVisibility": { "feed": false },
        "columnWidths": { "title": 420 },
        "columnOrder": ["title", "published_at"],
        "updatedAt": 1756500000000
      }
    }
  }
}
```

---

**`PUT /api/auth/me/password`**

Change the current user's password.

**Auth:** Bearer token required  
**Status:** 200 OK  
**Request:**
```json
{
  "current_password": "oldpass123",
  "new_password": "newpass456"
}
```

---

**`GET /api/auth/invite-code`** (Admin only)

Retrieve the current registration invite code (if set).

**Auth:** Bearer token + admin role  
**Response:**
```json
{
  "invite_code": "ABC-DEF-123" or null
}
```

---

**`GET /api/admin/users`**

List all users. Admin only. Returns a plain array (not paginated).

**Auth:** Bearer token + admin role  
**Response:**
```json
[
  { "id": "550e8400-...", "username": "alice", "role": "admin", "is_active": true, ... }
]
```

---

**`GET /api/admin/users/{user_id}`**

Get a single user. Admin only.

**Auth:** Bearer token + admin role

---

**`PATCH /api/admin/users/{user_id}`**

Update a user's role, active flag, or password. Admin only.

**Auth:** Bearer token + admin role  
**Status:** 200 OK

---

**`DELETE /api/admin/users/{user_id}`**

Delete a user. Admin only.

**Auth:** Bearer token + admin role  
**Status:** 204 No Content

---

### Feeds & Content Ingestion

Base paths: `/api/feeds`, `/api/opml`, `/api/entries` (ingest)

#### Feed Management

**`GET /api/feeds`**

List configured feeds with unread counts and sync status.

**Auth:** Bearer token  
**Query Params:**
- `limit`, `offset`: Pagination
- `search`: Filter by feed title
- `feed_type`: Filter by type (e.g., "rss", "atom", "github_repo")
- `category_id`: Filter by category
- `include_stats`: Include analytics (hit count, publishing rate)

**Response:**
```json
{
  "items": [
    {
      "id": "550e8400-...",
      "title": "Example Security Feed",
      "url": "https://example.com/feed.xml",
      "feed_type": "rss",
      "category_id": "550e8401-...",
      "unread_count": 42,
      "is_muted": false,
      "is_active": true,
      "interval": 60,
      "last_sync_at": "2024-01-20T14:22:00Z",
      "adapter_config": {},
      "custom_title": "Custom Title"
    }
  ],
  "total": 100,
  "limit": 50,
  "offset": 0,
  "has_more": true
}
```

---

**`POST /api/feeds`**

Add a new feed. Auto-detects feed type and interval based on URL.

**Auth:** Bearer token  
**Status:** 201 Created  
**Request:**
```json
{
  "url": "https://example.com/feed.xml",
  "category_id": "550e8401-...",
  "custom_title": "Optional custom name",
  "is_muted": false,
  "adapter_config": {}
}
```
**Response:** Same as `GET /api/feeds` item

---

**`GET /api/feeds/health`**

Get feed sync health dashboard: total feeds, sync status distribution, last sync time.

**Auth:** Bearer token  
**Response:**
```json
{
  "total_feeds": 200,
  "syncing": 5,
  "idle": 190,
  "error": 5,
  "last_sync_at": "2024-01-20T14:22:00Z"
}
```

---

**`GET /api/feeds/health/failing`**

Breakage alerts: active feeds with `error_count >= threshold` consecutive fetch failures. High-value feeds (reliability rating A/B) are flagged `is_high_value` and sorted first.

**Auth:** Bearer token  
**Query Params:**
- `threshold`: Consecutive-failure cutoff (default 5, max 100)

**Response:**
```json
{
  "threshold": 5,
  "total": 3,
  "high_value_count": 1,
  "feeds": [
    { "id": "...", "title": "...", "error_count": 12, "last_error": "...", "is_high_value": true }
  ]
}
```

---

**`GET /api/feeds/{feed_id}/analytics`**

Per-feed source reliability analytics (publishing cadence, intel yield, reliability rating).

**Auth:** Bearer token

---

**`GET /api/feeds/{feed_id}/entries`**

List a single feed's entries (cursor-paginated, same shape as `GET /api/entries`).

**Auth:** Bearer token

---

**`GET /api/feeds/{feed_id}`**

Get a single feed's detailed configuration.

**Auth:** Bearer token  
**Response:** Feed object (see POST response)

---

**`PUT /api/feeds/{feed_id}`**

Update feed configuration (title, category, interval, adapter config). Infrastructure fields (`url`, `feed_type`, `is_active`, `fetch_interval_minutes`, `retention_days`, `adapter_config`, `exclude_shorts`, `intel_extraction_mode`, `ai_analysis_enabled`, `auto_extract_on_ingest`, `extract_detection_rules`) are admin-only; curation fields (`custom_title`, `category_id`, `is_muted`, ratings, `analyst_notes`) are open to all users. `is_muted` is per-user when per-user subscriptions are enabled.

**Auth:** Bearer token (admin for infrastructure fields)  
**Status:** 200 OK  
**Request:**
```json
{
  "custom_title": "New title",
  "category_id": "550e8401-...",
  "interval": 120,
  "adapter_config": { ... }
}
```

---

**`DELETE /api/feeds/{feed_id}`**

Delete a feed (admin only) — removes the feed record and cascades its entries. With the `per_user_subscriptions_enabled` system setting on, this endpoint instead unsubscribes the caller (any user): the feed and its entries stay for everyone else, and a feed with zero subscribers stops fetching. Admins pass `?purge=true` for a physical delete in that mode.

**Auth:** Bearer token (admin for physical delete; any user to unsubscribe when per-user subscriptions are enabled)  
**Status:** 204 No Content

---

**`GET /api/feeds/{feed_id}/value`**

One feed's intelligence value score plus its rank among the scored set. Scoring runs over every active feed rather than this one alone — "entity introductions" means *first seen anywhere*, so a single-feed computation would count every entity the feed ever mentioned — but the response is a single row. Backs the Edit Feed modal's Overview pane.

**Auth:** Bearer token
**Query:** `days` (7-365, default 90)
**Status:** 200 OK, 404 if the feed does not exist
**Response:**
```json
{
  "feed_id": "d5b2c8a1-4f3e-4b7a-9c6d-2e8f1a0b3c4d",
  "scored": true,
  "score": 48.2,
  "tier": "B",
  "articles": 142,
  "unique_entities": 87,
  "entity_introductions": 11,
  "correlation_events": 3,
  "detection_rules": 0,
  "pir_matches": 2,
  "rank": 4,
  "of": 37,
  "days": 90
}
```

---

**`GET /api/feeds/{feed_id}/pipeline`**

Which pipeline stages run for this feed, and what decided each one. `decided_by` is `"legacy"` when the value still comes from the Feed columns (the case while `pipeline_engine_enabled` is off), otherwise the plan scope that overrode it — `global`, `category` or `feed`. The Edit Feed modal's Pipeline pane reads this so it can stop presenting its own checkbox as authoritative for a stage a plan controls.

**Auth:** Bearer token
**Status:** 200 OK, 404 if the feed does not exist
**Response:**
```json
{
  "engine_enabled": true,
  "stages": {
    "autolink": { "enabled": true, "config": {} },
    "extract": { "enabled": false, "config": { "mode": "selective", "detection_rules": false } }
  },
  "decided_by": { "autolink": "feed", "extract": "legacy" }
}
```

---

**`POST /api/feeds/{feed_id}/refresh`**

Trigger an immediate sync of a single feed (background job).

**Auth:** Bearer token  
**Status:** 200 OK  
**Response:**
```json
{
  "feed_id": "550e8400-...",
  "status": "queued",
  "message": "Sync job enqueued"
}
```

---

**`POST /api/feeds/{feed_id}/full-sync`**

Perform a full resync: clear the feed's cursor/since token and reindex all available articles.

**Auth:** Bearer token  
**Status:** 200 OK  
**Response:**
```json
{
  "status": "in_progress",
  "message": "Full sync initiated",
  "job_id": "..."
}
```

---

**`GET /api/feeds/{feed_id}/full-sync/progress`**

Poll the status of a running full-sync job.

**Auth:** Bearer token  
**Response:**
```json
{
  "status": "in_progress",
  "fetched": 250,
  "stored": 180,
  "errors": 5,
  "elapsed_seconds": 32
}
```

---

**`POST /api/feeds/discover`**

Discover a feed URL from a website. Returns possible feed URLs found via link tags.

**Auth:** Bearer token  
**Status:** 200 OK  
**Request:**
```json
{
  "url": "https://example.com"
}
```
**Response:**
```json
{
  "feeds": [
    { "url": "https://example.com/feed.xml", "title": "Main Feed", "type": "rss" },
    { "url": "https://example.com/blog/feed", "title": "Blog", "type": "atom" }
  ]
}
```

---

#### Extended Feed Types

**`POST /api/feeds/github-repo/bulk-setup`**

Create multiple GitHub repository feeds from a CSV or list.

**Auth:** Bearer token  
**Request:**
```json
{
  "repos": [
    { "owner": "torvalds", "repo": "linux", "content_type": "releases" }
  ],
  "category_id": "550e8401-..."
}
```

---

**`GET /api/feeds/github-repo/templates`**

List template configurations for GitHub feed types (releases, issues, advisories, etc.).

**Auth:** Bearer token

---

**`POST /api/feeds/bluesky/resolve-feed-url`**

Resolve a Bluesky feed URL from a handle or feed name.

**Auth:** Bearer token

---

**`PUT /api/feeds/youtube/exclude-shorts`**

Bulk filter YouTube shorts from a category.

**Auth:** Bearer token

---

**`PUT /api/feeds/category/{category_id}/intel-mode`**

Toggle intelligence extraction mode for every feed in a category.

**Auth:** Bearer token

---

**`PUT /api/feeds/category/{category_id}/bulk-update`**

Bulk-update feed settings (interval, mute, active flag, etc.) for a whole category.

**Auth:** Bearer token

---

#### OPML Import/Export

**`POST /api/opml/import`**

Import feeds from an OPML file (bulk add from another reader). Admin-only unless the `per_user_subscriptions_enabled` system setting is on, in which case any user may import (imported feeds subscribe the importer).

**Auth:** Bearer token (admin unless per-user subscriptions are enabled)  
**Status:** 200 OK  
**Request:** Multipart form with `opml_file`  
**Response:**
```json
{
  "imported": 45,
  "skipped": 3,
  "errors": [ { "line": 5, "message": "Invalid URL" } ]
}
```

---

**`GET /api/opml/export`**

Export all feeds as OPML (XML).

**Auth:** Bearer token  
**Response:** `Content-Type: application/xml`

---

### Entries & Article Management

Base path: `/api/entries`

#### Listing & Filtering

**`GET /api/entries`**

List articles with advanced filtering, cursor pagination, and deduplication.

**Auth:** Bearer token  
**Query Params:**
- `feed_id`: Filter by feed
- `category_id`: Filter by category
- `is_read`: true|false|null (unread only)
- `is_starred`: true|false
- `is_bookmarked`: true|false
- `content_type`: e.g., "github_repo", "mastodon" (for extended feeds)
- `since`: ISO date, only after this timestamp
- `before`: ISO date, only before this timestamp
- `country_id`, `country_role`: Filter by country (origin, target, mentioned, infrastructure)
- `campaign_id`: Filter by campaign
- `sort`: "newest" | "oldest" | "most_relevant"
- `dedup`: true (default, merge near-duplicates from multiple feeds)
- `limit`: Max items (default 50, max 500)
- `cursor`: Pagination cursor

**Response:**
```json
{
  "items": [
    {
      "id": "550e8400-...",
      "title": "Article Title",
      "summary": "Brief excerpt",
      "url": "https://example.com/article",
      "published_at": "2024-01-20T10:00:00Z",
      "feed_id": "550e8401-...",
      "feed_title": "Example Feed",
      "author": "John Doe",
      "content_type": "article",
      "is_read": false,
      "is_starred": true,
      "is_bookmarked": false,
      "created_at": "2024-01-20T11:00:00Z"
    }
  ],
  "next_cursor": "eyJvZmZzZXQiOiA1MCwgInRpbWVzdGFtcCI6ICIyMDI0LTAxLTIwVDEwOjAwOjAwWiJ9",
  "has_more": true
}
```

---

**`GET /api/entries/priority-queue`**

The ranked reading queue, assembled as the Priority Queue page renders it: unread
entries clearing the radar threshold, ordered by signal score, with open story
threads folded in as single rows. A thread ranks by the score of its best unread
beat plus a capped bump for each extra outlet covering the story, and its members
are withheld from the queue as standalone entries — the thread row stands for
them. Threads with nothing unread never appear.

**Auth:** Bearer token
**Query Params:**
- `unread_only`: true (default) — false also returns entries already read
- `with_threads`: true (default) — false returns entries only, unfolded
- `exclude_thread_ids`: repeatable; drops a thread row and releases its members
- `limit`: entries per page (default 50, max 200); thread rows are additional
- `cursor`: pagination cursor from the previous page

**Response:**
```json
{
  "items": [
    {
      "kind": "thread",
      "score": 11.72,
      "entry": null,
      "thread": { "slug": "gitlab-path-traversal-exploited", "source_count": 14, "unread_count": 9, "...": "..." },
      "absorbed_entry_ids": ["550e8400-..."]
    },
    {
      "kind": "entry",
      "score": 7.3,
      "entry": { "id": "550e8401-...", "title": "Article Title", "...": "..." },
      "thread": null,
      "absorbed_entry_ids": []
    }
  ],
  "next_cursor": "eyJlbnRyeSI6...",
  "has_more": true,
  "radar_threshold": 1.5
}
```

`radar_threshold` is null when the signal engine is not surfacing, in which case
the queue is every unread entry ranked by score rather than a filtered set.

---

**`GET /api/entries/triage`**

High-priority triage queue: scores entries by recency, engagement (reads/stars), and matching intelligence requirements.

**Auth:** Bearer token  
**Query Params:**
- `days`: Look-ahead window (default 7, max 30)
- `limit`, `offset`: Pagination
- `user`: Populated from JWT claims

**Response:**
```json
{
  "items": [
    {
      "id": "550e8400-...",
      "title": "Critical Vulnerability Disclosure",
      "triage_score": 0.92,
      "reason": "CVE extraction pending, matches 3 requirements",
      "feed_title": "SecurityAffairs",
      "published_at": "2024-01-20T08:00:00Z"
    }
  ],
  "total": 23,
  "limit": 50,
  "offset": 0,
  "has_more": false
}
```

---

**`GET /api/entries/{entry_id}`**

Fetch a single article with full content and metadata.

**Auth:** Bearer token  
**Response:**
```json
{
  "id": "550e8400-...",
  "title": "...",
  "content_html": "<p>Full HTML content</p>",
  "content_text": "Full plain text",
  "media": [
    {
      "id": "550e8402-...",
      "url": "https://example.com/image.jpg",
      "media_type": "image",
      "title": "Screenshot"
    }
  ],
  "countries": [
    { "id": "550e8403-...", "name": "CN", "role": "origin" }
  ],
  "threat_actors": [ ... ],
  "malware": [ ... ],
  "ttps": [ ... ],
  "cves": [ ... ],
  "tags": [ { "id": "...", "name": "vulnerability", "color": "#FF0000" } ],
  "comments_count": 5,
  "notes_count": 2
}
```

---

#### Entry State & Bulk Actions

**`PUT /api/entries/{entry_id}/read`** / **`PUT /api/entries/{entry_id}/unread`**  
**`PUT /api/entries/{entry_id}/star`** / **`PUT /api/entries/{entry_id}/bookmark`**

Toggle per-entry user state (star and bookmark endpoints toggle; read/unread set explicitly).

**Auth:** Bearer token  
**Status:** 200 OK

---

**`POST /api/entries/bulk-action`**

Perform one bulk state change across many entries.

**Auth:** Bearer token  
**Status:** 200 OK  
**Request:**
```json
{
  "entry_ids": [ "550e8400-...", "550e8401-..." ],
  "action": "read"
}
```
`action` is one of `read`, `unread`, `star`, `unstar`, `bookmark`, `unbookmark`, `hide`. Returns `{ "updated": <count> }`.

---

**`POST /api/entries/mark-all-read`**

Mark all unread entries (optionally in a feed/category, optionally before a timestamp) as read.

**Auth:** Bearer token  
**Status:** 200 OK  
**Request:**
```json
{
  "feed_id": "550e8400-..." ,
  "category_id": "550e8401-...",
  "before": "2024-01-20T10:00:00Z"
}
```

---

#### Views & Aggregates

**`GET /api/entries/calendar`**

Per-day entry counts for the calendar view (respects entry filters).

**Auth:** Bearer token

---

**`GET /api/entries/map`**

Country-bucketed entry counts for the map view.

**Auth:** Bearer token

---

**`GET /api/entries/count`**

Count entries matching the standard entry filters (no items returned).

**Auth:** Bearer token

---

**`GET /api/entries/day-intel`**

Top entities + urgency signals for a day window (`since`/`before`, optional `feed_id`/`category_id`). Powers the day-divider strip: top actor/malware/CVE/TTP/sector/product/country, an exploited-first CVE pick, actively-exploited count, newly-tracked entities.

**Auth:** Bearer token

---

**`GET /api/entries/day-entities`**

Distinct entities mentioned by all entries in a day window (`since`/`before`, optional `feed_id`/`category_id`). Includes the autolinker's aggregated `matched_names` surface forms — used for inline entity linking on the day's AI summary.

**Auth:** Bearer token

---

**`GET /api/entries/daily-summary`** / **`POST /api/entries/daily-summary`**

AI briefing for a day (`day_key: YYYY-MM-DD` plus the standard entry filters). `GET` returns the cached summary or `null` — it never generates; `POST` generates (or returns cache unless `force: true`). Summaries for the default unfiltered view are cached as a **shared** row visible to all users; filtered summaries stay per-user.

**Auth:** Bearer token  
**Response:** `{ "summary": "...", "cached": true, "generated_at": "..." }`

---

#### Per-Entry Extras

**`POST /api/entries/{entry_id}/translate`** — Translate an entry via the configured AI provider.  
**`GET /api/entries/{entry_id}/similar`** — Near-duplicate / related entries. Answers from the embedding index (cosine nearest neighbours, `similarity` and `thread_slug` per item, `method: "embedding"`), falling back to Meilisearch term overlap for entries that have not been embedded (`method: "keyword"`).  
**`GET /api/entries/{entry_id}/media`** — Attached media items.  
**`GET /api/entries/{entry_id}/urls`** — URLs referenced by the entry content.  
**`POST /api/entries/resolve-names`** — Resolve entry IDs to titles (batch helper).

**Auth:** Bearer token

---

#### Ingest & Processing

**`POST /api/entries/ingest/url`**

Ingest a web page/article URL as a manual entry. Dispatches the full intelligence pipeline and indexes in Meilisearch.

**Auth:** Bearer token  
**Request:**
```json
{ "url": "https://example.com/report" }
```
**Response:** `{ "id": "...", "title": "...", "url": "...", "word_count": 1234, "feed_id": "...", "content_hash": "...", "message": "Entry created" }`

---

**`POST /api/entries/ingest/pdf`**

Ingest a PDF file as a manual entry.

**Auth:** Bearer token  
**Request:** Multipart form with `file` (PDF) and optional `title`

---

### Story Threads

One unfolding story instead of the twenty-three articles that reported it. See
[story-threads.md](story-threads.md) for how threads are built.

**`GET /api/threads`** — Open threads, most recently active first.
Query: `status` (`open` default, `dormant`, `closed`, `any`), `limit` (1-200).
Each row carries `entry_count`, `source_count` (outlets, not feed rows), `echo_count`,
`unread_count`, `new_since_opened`, `top_score` (the best unread non-echo member's priority
score — the rank the row takes in the queue), `key_entities`, and every member `entry_ids`
so a list view can absorb them into the thread row.

**`GET /api/threads/{slug}`** — One thread: `beats` (the spine, `is_ai` false when it came
from the day-grouping fallback), `members` (with `role` = `origin` | `beat` | `echo` and
`duplicate_of_entry_id` for echoes), `thread_yield` (techniques / CVEs / products / rules /
echoes folded), and `nearest` threads by centroid.

**`POST /api/threads/{thread_id}/open`** — Stamp the thread as seen; `new_since_opened` is
measured from this.

**Auth:** Bearer token

---

### Intelligence Extraction

Base path: `/api` (mixed prefixes)

Intelligence endpoints extract structured threat data (TTPs, CVEs, threat actors, malware, mitigations) from articles using AI or regex patterns.

#### TTP (Tactics & Techniques)

**`POST /api/entries/{entry_id}/extract-ttps`**

Extract MITRE ATT&CK techniques from an article. Uses AI by default, regex as fallback.

**Auth:** Bearer token  
**Query Params:**
- `use_ai`: true (default, calls configured LLM) or false (regex only)

**Status:** 200 OK  
**Response:**
```json
{
  "items": [
    {
      "technique_id": "T1566.002",
      "technique_name": "Phishing: Spearphishing Link",
      "tactic": "Initial Access",
      "confidence": "high",
      "source_text": "The attacker used spear phishing emails..."
    }
  ],
  "status": "success",
  "error_message": null
}
```

---

**`GET /api/entries/{entry_id}/ttps`**

List TTPs already extracted for an entry.

**Auth:** Bearer token

---

**`GET /api/entries/{entry_id}/ttps/navigator`**

Export TTPs as MITRE ATT&CK Navigator JSON layer.

**Auth:** Bearer token  
**Response:** Navigator layer JSON (importable to https://attack.mitre.org/navigator)

---

**`GET /api/ttps`**

List all TTPs in the database, with article count and dates.

**Auth:** Bearer token  
**Query Params:**
- `search`: Filter by technique ID or name
- `tactic`: Filter by tactic (e.g., "Initial Access")
- `sort_by`: "technique_id" | "article_count" | "last_seen_at"
- `sort_order`: "asc" | "desc"
- `limit`, `offset`: Pagination

**Response:**
```json
{
  "items": [
    {
      "technique_id": "T1566.002",
      "technique_name": "Phishing: Spearphishing Link",
      "tactic": "Initial Access",
      "article_count": 542,
      "first_seen_at": "2023-06-01T00:00:00Z",
      "last_seen_at": "2024-01-20T12:00:00Z"
    }
  ],
  "total": 1240,
  "limit": 50,
  "offset": 0,
  "has_more": true
}
```

---

**`GET /api/ttps/by-technique/{technique_id}`**

Get a single TTP by MITRE technique ID.

**Auth:** Bearer token

---

**`GET /api/ttps/{ttp_id}/mitigations`** — MITRE mitigations for a technique.  
**`GET /api/ttps/{ttp_id}/related-techniques`** — Related techniques (same tactic / sub-technique family).  
**`GET /api/entries/{entry_id}/kill-chain`** — Entry's TTPs grouped in kill-chain order.

**Auth:** Bearer token

---

#### ATT&CK Catalog & Matrix

Base path: `/api/attack` (full MITRE ATT&CK catalog, seeded via `scripts/seed/seed_mitre_attack.py`)

**`GET /api/attack/matrix`**

Navigator-style matrix: tactics in kill-chain order, techniques with feed frequency (article counts) and telemetry-aware detection coverage, nested sub-techniques. Heavy aggregate, cached in Redis.

**Auth:** Bearer token  
**Query Params:**
- `domain`: "enterprise" | "mobile" | "ics" (default enterprise)
- `days`: Feed-frequency window (omit for all-time)
- `include_deprecated`: Include deprecated techniques

---

**`GET /api/attack/layer`** — ATT&CK Navigator layer JSON (optionally scoped by `entry_id` or `date_from`/`date_to`).  
**`GET /api/attack/techniques`** — Techniques observed in a date range, ranked by article count.

**Auth:** Bearer token

---

#### CVE (Common Vulnerabilities & Exposures)

**`POST /api/entries/{entry_id}/extract-cves`**

Extract CVE IDs from an article. Uses regex pattern matching.

**Auth:** Bearer token  
**Status:** 200 OK  
**Response:**
```json
{
  "items": [
    {
      "cve_id": "CVE-2024-1234",
      "title": "Buffer overflow in Example Software",
      "severity": "high",
      "cvss_v3_score": 8.6,
      "published_at": "2024-01-15T00:00:00Z"
    }
  ],
  "status": "success",
  "error_message": null
}
```

---

**`GET /api/entries/{entry_id}/cves`**

List CVEs already extracted for an entry.

**Auth:** Bearer token

---

**`GET /api/cves`**

List all CVEs in the database.

**Auth:** Bearer token  
**Query Params:**
- `search`: Filter by CVE ID
- `severity`: "low" | "medium" | "high" | "critical"
- `sort_by`: "cve_id" | "severity" | "article_count"
- `limit`, `offset`: Pagination

CVE responses carry NVD/KEV/EPSS enrichment fields: `epss_score`, `epss_percentile`, `is_kev`, `kev_date_added`, `kev_due_date`, plus a computed priority/risk tier (critical = KEV, high = EPSS/Metasploit, medium = PoC/CVSS, low). See [`backend/app/schemas/intelligence.py`].

---

**`GET /api/cves/trending`** — CVEs trending across recent entries.  
**`GET /api/cves/{cve_id}`** — Single CVE by ID (e.g. `CVE-2024-1234`) with enrichment.  
**`POST /api/sync/cve-backfill`** — Backfill NVD/KEV/EPSS enrichment for stored CVEs.  
**`POST /api/sync/mitre-attack`** — Refresh the MITRE ATT&CK catalog.

**Auth:** Bearer token

---

#### Threat Actors

**`POST /api/entries/{entry_id}/extract-threat-actors`**

Extract threat actor references (APT groups, campaigns, individuals).

**Auth:** Bearer token  
**Status:** 200 OK  
**Response:**
```json
{
  "items": [
    {
      "id": "550e8400-...",
      "name": "APT29",
      "aliases": [ "Cozy Bear", "The Dukes" ],
      "countries": [ "RU" ],
      "category": "nation-state",
      "confidence": "high"
    }
  ],
  "status": "success",
  "error_message": null
}
```

---

**`GET /api/entries/{entry_id}/threat-actors`**

List threat actors extracted for an entry.

**Auth:** Bearer token

---

#### Malware

**`POST /api/entries/{entry_id}/extract-malware`**

Extract malware family names and samples.

**Auth:** Bearer token  
**Status:** 200 OK

---

**`GET /api/entries/{entry_id}/malware`**

List malware extracted for an entry.

**Auth:** Bearer token

---

#### Countries

**`POST /api/entries/{entry_id}/extract-countries`**

Extract country references (origin, target, mentioned, infrastructure).

**Auth:** Bearer token  
**Status:** 200 OK  
**Response:**
```json
{
  "items": [
    {
      "id": "550e8400-...",
      "iso_code": "CN",
      "name": "China",
      "role": "origin",
      "confidence": "high"
    }
  ],
  "status": "success",
  "error_message": null
}
```

Related catalog endpoints: `GET /api/countries`, `GET /api/countries/{country_id}`, `GET /api/countries/{country_id}/profile`, `GET /api/regions`.

---

#### Sectors

A closed, seeded vocabulary of 21 victim industries, promoted to an entity. Every route accepts a sector by UUID, canonical slug (`healthcare`), display name or alias.

- **`GET /api/sectors`** — paginated list; `search`, `sort_by` in `name|article_count|last_seen_at|linked_count|targeting_actor_count|victim_count`. Items carry `targeting_actor_count`, `targeting_malware_count` and `victim_count` (leak-site disclosures, last 90 days).
- **`GET /api/sectors/{ref}`**, **`GET /api/sectors/{ref}/profile`** (`window_days`) — the victimology profile: `reported_actors`/`reported_malware` (ranked by articles describing both the entity and the sector being hit), `asserted_actors`/`asserted_malware` (target-sector claims with `source` and `article_count`), `campaigns`, `victims` (totals, 12-month series, top groups, recent disclosures), `countries` (article and victim counts), `intel_profiles`, `recent_entries`, `articles_monthly`.
- **`GET /api/entries/{entry_id}/sectors`** / **`DELETE /api/entries/{entry_id}/sectors/{sector_id}`** — the sectors an article describes as targeted (written only by the one-pass AI analysis; `POST /api/entries/{entry_id}/extract-sectors` runs it). The response carries `id`/`slug`/`name` and the legacy `sector`/`label` spellings.
- **`PUT /api/entities/sectors/{sector_id}`** — `aliases`, `description`. Name and slug are the vocabulary itself; there is no create, delete, merge or convert.
- **`GET/POST /api/entities/{threat_actor|malware}/{id}/target-sectors`**, **`DELETE .../target-sectors/{ref}`** — the asserted targets-sector claims on an actor or family. `POST` records an analyst claim (upgrading a rolled-up or enriched row); the `targeted_sectors` label array on the entity is a cache rebuilt from these rows.
- **`GET/POST /api/campaigns/{id}/sectors`**, **`DELETE .../sectors/{ref}`**, **`GET .../sectors/suggested`** — a campaign's victim verticals; suggestions come from its own articles' sectors.

Sectors are also watchable (`entity_type: "sector"` on the watchlist) — a watch boosts the sector's articles in the Priority Queue — and pivot/graph/timeline through the generic correlation routes.

---

#### Mitigations & Offensive Tools

Same extract/list pattern as the entity types above:

- **`POST /api/entries/{entry_id}/extract-mitigations`** / **`GET /api/entries/{entry_id}/mitigations`** — catalog at `GET /api/mitigations`, `GET /api/mitigations/{mitigation_id}`
- **`POST /api/entries/{entry_id}/extract-tools`** / **`GET /api/entries/{entry_id}/tools`** — catalog at `GET /api/tools` (paginated), `GET /api/tools/{tool_id}`

**Auth:** Bearer token

---

#### Vendors & Products

Vendors/products are autolinked (not AI-extracted):

- **`GET /api/entries/{entry_id}/vendors`** / **`GET /api/entries/{entry_id}/products`** — entities linked to an entry
- **`GET /api/vendors`**, **`GET /api/vendors/{vendor_id}`**, **`GET /api/vendors/{vendor_id}/products`** — vendor catalog
- **`GET /api/products`**, **`GET /api/products/{product_id}`** — product catalog

**Auth:** Bearer token

---

#### Manual Entity Linking & Unlinking

**`POST /api/entries/{entry_id}/link-entity`**

Manually link an existing entity (any type) to an entry.

**Auth:** Bearer token  
**Status:** 201 Created

---

**`DELETE /api/entries/{entry_id}/{collection}/{entity_id}`**

Unlink an entity from an entry. Supported collections: `ttps`, `cves`, `threat-actors`, `malware`, `countries`, `mitigations`, `tools`, `vendors`, `products`.

**Auth:** Bearer token  
**Status:** 204 No Content

---

#### Autolinker

- **`POST /api/entries/{entry_id}/autolink`** — Re-run the autolinker on one entry
- **`POST /api/autolink/scan`** / **`POST /api/autolink/rescan`** / **`POST /api/autolink/revalidate`** — Bulk scans (background jobs)
- **`GET /api/autolink/status`** — Progress of a running scan
- **`GET /api/proximity-settings`** — Correlation proximity-scoring settings

**Auth:** Bearer token

---

#### Detection Rules

**`POST /api/entries/{entry_id}/generate-rules`**

Generate detection rules (Sigma, YARA, Splunk SPL) from article content using AI.

**Auth:** Bearer token  
**Status:** 200 OK  
**Request:**
```json
{
  "rule_types": [ "sigma", "yara" ],
  "template_id": "550e8400-...",
  "use_ai": true
}
```
**Response:**
```json
{
  "rules": [
    {
      "rule_type": "sigma",
      "content": "title: ...\nlogsource:\n  product: ...\ndetection:\n  ...",
      "source_text": "Based on: malware C2 communication pattern..."
    }
  ],
  "status": "success"
}
```

---

### Entity Management

Base paths: `/api/entities`, `/api/campaigns`, `/api/entity-relationships`, etc.

#### Entity Profiles (Threat Actors, Malware, Vendors, Products, Tools, ...)

There is no generic `/api/entities` CRUD. **Reading** entities uses the type-specific list/detail endpoints in the Intelligence section (`GET /api/threat-actors`, `/api/malware`, `/api/cves`, `/api/ttps`, `/api/countries`, `/api/mitigations`, `/api/tools`, `/api/vendors`, `/api/products` — all paginated with `search`/sort params, e.g. `GET /api/threat-actors/{actor_id}` for detail). **Managing** profiles uses the per-type endpoints under `/api/entities`:

**`POST /api/entities/{type}`** — Create an entity. Types: `threat-actors`, `malware`, `cves`, `ttps`, `countries`, `mitigations`, `tools`, `vendors`, `products`.

**`PUT /api/entities/{type}/{id}`** — Update an entity (name, aliases, description, metadata).

**`DELETE /api/entities/{type}/{id}`** — Delete an entity.

**Auth:** Bearer token

---

**`DELETE /api/entities/{entity_type}/{entity_id}/unlink-all`**

Remove all entry links for an entity (keeps the entity itself).

**Auth:** Bearer token

---

**`POST /api/entities/{entity_type}/{entity_id}/ai-summary`** — Generate an AI profile summary.  
**`GET /api/entities/{entity_type}/{entity_id}/wikipedia/search`** / **`POST .../wikipedia`** / **`DELETE .../wikipedia`** — Attach/detach a Wikipedia description.  
**`POST /api/entities/convert`** — Convert an entity to another type (e.g. malware → tool), migrating entry links, relationships, notes, and campaign memberships.

**Auth:** Bearer token

---

#### Entity Merge & Deduplication

**`POST /api/entities/{entity_type}/merge`**

Merge duplicate entities into a keeper: reassigns entry links and relationships, merges aliases (each merged entity's name becomes an alias), sums article counts, deletes the merged entities.

**Auth:** Bearer token  
**Request:**
```json
{
  "keeper_id": "550e8400-...",
  "merge_ids": [ "550e8401-...", "550e8402-..." ]
}
```

---

**`GET /api/entities/{entity_type}/duplicates`** — Heuristic duplicate-pair listing.  
**`GET /api/entities/{entity_type}/merge-suggestions`** — Ranked duplicate-pair suggestions (name/alias similarity, shared relationships, co-mentions) with human-readable reasons; cross-type tool-vs-malware collisions flagged `cross_type`.  
**`POST /api/entities/merge-suggestions/dismiss`** — Persistently dismiss a suggested pair.

**Auth:** Bearer token

---

**`POST /api/{type}/{target_id}/merge`** (Admin)

Merge-into for a single pair: merges `source_id` **into** `{target_id}` and deletes the source. Available for `threat-actors`, `malware`, `vendors`, `products`, `offensive-tools`. Every merge is recorded in the entity-maintenance log.

**Auth:** Bearer token + admin role  
**Request:**
```json
{
  "source_id": "550e8401-...",
  "mode": "apply",
  "extra_aliases": [],
  "new_description": null
}
```
`mode: "shadow"` logs what would happen without changing anything.

Related maintenance endpoints (admin): `POST /api/entity-maintenance/reclassify`, `GET /api/entity-maintenance/log`, `POST /api/entity-maintenance/log/{log_id}/apply`, `POST /api/entity-maintenance/log/apply-all`, `DELETE /api/entity-maintenance/log/{log_id}`.

---

#### Entity Profile Export (Markdown)

**`GET /api/export/entities/{entity_type}/{entity_id}`**

Export a single entity profile as a Markdown document (`text/markdown` download).

**Auth:** Bearer token

---

**`POST /api/export/entities/bulk`**

Export many entity profiles of one type as a ZIP of Markdown files. Pass explicit `entity_ids`, or `all: true` for every entity of the type (capped, most-referenced first).

**Auth:** Bearer token  
**Request:**
```json
{ "entity_type": "threat_actor", "entity_ids": [], "all": true }
```

Entry/note exports live alongside: `GET /api/export/entries/{entry_id}`, `GET /api/export/notes/{note_id}`, `POST /api/export/bulk`.

---

#### Campaigns

**`GET /api/campaigns`**

List campaigns with related threat actors, malware, and article count.

**Auth:** Bearer token  
**Query Params:**
- `search`: Filter by campaign name
- `threat_actor_id`: Filter by threat actor
- `limit`, `offset`: Pagination

**Response:**
```json
{
  "items": [
    {
      "id": "550e8400-...",
      "name": "Operation Stealth",
      "description": "...",
      "threat_actors": [ { "id": "...", "name": "APT29" } ],
      "malware": [ { "id": "...", "name": "Cozybot" } ],
      "start_date": "2023-01-01",
      "end_date": null,
      "article_count": 125,
      "created_at": "2024-01-01T00:00:00Z"
    }
  ],
  "total": 50,
  "limit": 50,
  "offset": 0,
  "has_more": false
}
```

---

**`POST /api/campaigns`**

Create a new campaign.

**Auth:** Bearer token  
**Status:** 201 Created  
**Request:**
```json
{
  "name": "Operation Sunrise",
  "description": "...",
  "threat_actor_ids": [ "550e8400-..." ],
  "start_date": "2024-01-01"
}
```

---

**`GET /api/campaigns/{campaign_id}`**

Get campaign details with members and related intelligence.

**Auth:** Bearer token

---

**`PUT /api/campaigns/{campaign_id}`**

Update campaign details.

**Auth:** Bearer token  
**Status:** 200 OK

---

**`DELETE /api/campaigns/{campaign_id}`**

Delete a campaign.

**Auth:** Bearer token  
**Status:** 204 No Content

---

#### Campaign Sub-Resources

- **`POST /api/campaigns/{id}/entries`** / **`DELETE /api/campaigns/{id}/entries/{entry_id}`** — Attach/detach entries
- **`GET/POST /api/campaigns/{id}/entities`** / **`DELETE /api/campaigns/{id}/entities/{entity_id}`** — Campaign entity membership
- **`GET/POST /api/campaigns/{id}/countries`** / **`DELETE .../countries/{country_id}`**, **`GET .../countries/suggested`** — Targeted/attributed countries
- **`GET/POST /api/campaigns/{id}/sectors`** / **`DELETE .../sectors/{ref}`**, **`GET .../sectors/suggested`** — Victim verticals (sector by UUID, slug or name)
- **`GET /api/campaigns/{id}/timeline`**, **`GET .../stats`**, **`GET .../attack-layer`**, **`GET .../detection-gaps`**, **`GET .../export`**, **`GET .../suggest`** — Analysis views
- **`GET/POST /api/campaigns/{id}/saved-searches`**, **`PATCH/DELETE .../saved-searches/{css_id}`**, **`POST .../saved-searches/{css_id}/sync`** — Links to an analyst's own saved searches. Prefer a `query` source below: it belongs to the campaign instead of to one person.
- **`GET/POST /api/campaigns/{id}/sources`**, **`PATCH/DELETE .../sources/{source_id}`**, **`POST .../sources/{source_id}/sync`** — Standing intake the campaign owns (see below)
- **`GET /api/campaigns/{id}/sources/suggested`** — What it could follow, drawn from what it already holds
- **`POST /api/campaigns/{id}/sources/preview`** — Dry run: what a source *would* add, before it exists
- **`GET /api/campaigns/source-options`** — Which source kinds exist and which entity types can be followed
- **`POST /api/campaigns/auto-detect`** — Suggest new campaigns from entry clustering
- **`GET /api/campaigns/by-entry/{entry_id}`** — Campaigns containing an entry

**Auth:** Bearer token

---

#### Campaign Sources

Standing intake owned by the campaign rather than by one analyst. Three kinds:

| `kind` | Body | Claims |
| --- | --- | --- |
| `entity` | `entity_type` + `ref_id` | Every article linked to that entity |
| `story` | `ref_id` (thread UUID) | Every member of that story thread |
| `query` | `query` (query-language string) | Everything the query matches — see [query-language.md](query-language.md) |

Each recomputes its full claimed set on every run and inserts only what the
campaign does not already hold, so an article that joins a story, gains an
entity link or starts matching the query later still arrives. The
`sync_campaign_sources` beat job runs every 15 minutes; `auto_sync: false`
pauses a source without losing the row or what it has added.

**`POST /api/campaigns/{id}/sources/preview`**

A dry run. Creates nothing, so it is safe to call as an analyst types.

**Request:** `{"kind": "query", "query": "malware:\"Akira\" AND date:>30d"}`

**Response:**
```json
{
  "kind": "query",
  "entity_type": null,
  "ref_id": null,
  "query": "malware:\"Akira\" AND date:>30d",
  "label": "malware:\"Akira\" AND date:>30d",
  "would_add": 47,
  "already_held": 3,
  "preview": [{ "entry_id": "...", "title": "...", "published_at": "..." }],
  "error": null,
  "unknown_fields": []
}
```

`error` is a parse failure (reported in the body, not as a 4xx, because the UI
previews mid-typing). `unknown_fields` names fields the query language does not
have — `actor:` instead of `threat_actor:`, say — which are not fatal (they
become text terms) but on a standing source answer plausibly forever.

**Refusals on `POST .../sources`:** an unparseable query, a `query` source with a
`ref_id` (or any other kind without one), and an `entity_type` that owns no
articles — `GET /api/campaigns/source-options` lists the ones that do.

---

#### Entity Relationships

Typed, directed relationships between entities (e.g., "APT29 *uses* Cozybot") with a strength model:

- **`relationship_type`** (verb): `uses` | `exploits` | `targets` | `attributed_to` | `variant_of` | `communicates_with` | `delivers` | `drops` | `hosts` | `related_to`
- **`confidence`** (strength tier): `confirmed` | `probable` | `possible`
- **`source`** (provenance/lifecycle): auto-extracted vs `analyst_created` / `analyst_confirmed` / `analyst_rejected`. Rejected relationships are kept as tombstones (hidden from pivot/graph/list surfaces) so re-ingestion can't resurrect them.
- **`evidence_entry_ids`**: entries backing the claim; responses include resolved `source_name` / `target_name`

Entity types: `ttp`, `cve`, `threat_actor`, `malware`, `campaign`, `country`, `mitigation`, `tool`, `vendor`, `product`. Lifecycle diagram: [`docs/diagrams/entity-relationship-lifecycle.md`](diagrams/entity-relationship-lifecycle.md).

**`GET /api/entity-relationships`**

List relationships (paginated). Rejected ones are excluded unless `include_rejected=true`.

**Auth:** Bearer token  
**Query Params:**
- `entity_type` + `entity_id`: Match either endpoint of the relationship
- `relationship_type`: Filter by verb
- `include_rejected`: Include analyst-rejected rows (default false)
- `limit`, `offset`: Pagination

**Response:**
```json
{
  "items": [
    {
      "id": "550e8400-...",
      "source_type": "threat_actor", "source_id": "...", "source_name": "APT29",
      "target_type": "malware", "target_id": "...", "target_name": "Cozybot",
      "relationship_type": "uses",
      "confidence": "probable",
      "source": "auto_extracted",
      "description": null,
      "evidence_entry_ids": [ "550e8401-..." ],
      "created_at": "2024-01-20T12:00:00Z",
      "updated_at": "2024-01-20T12:00:00Z"
    }
  ],
  "total": 1000, "limit": 50, "offset": 0, "has_more": true
}
```

---

**`GET /api/entity-relationships/by-entity/{entity_type}/{entity_id}`**

All relationships for one entity (as source or target), unpaginated.

**Auth:** Bearer token

---

**`POST /api/entity-relationships/signals/{entity_type}`**

Batched relationship signals for table columns. **POST with a body, not a query string** — the table sends every loaded row's ID, which overflowed the request line as a GET. Per entity ID: count of non-rejected typed relationships and the top 3 by confidence + evidence volume (verb, direction, counterpart).

**Auth:** Bearer token  
**Request:**
```json
{ "ids": [ "550e8400-...", "550e8401-..." ] }
```
**Response:** `{ "<entity_id>": { "count": 7, "top": [ { "verb": "uses", "direction": "outbound", "other_type": "malware", "other_label": "Cozybot", "confidence": "confirmed" } ] } }`

---

**`POST /api/entity-relationships`**

Create a relationship. Upserts on (source, target, verb): re-creating an existing relationship merges evidence (returns 200 instead of 201), and explicitly re-creating a rejected one resurrects it.

**Auth:** Bearer token  
**Status:** 201 Created (200 on upsert-merge)  
**Request:**
```json
{
  "source_type": "threat_actor",
  "source_id": "550e8400-...",
  "target_type": "malware",
  "target_id": "550e8401-...",
  "relationship_type": "uses",
  "confidence": "probable",
  "description": null,
  "evidence_entry_ids": []
}
```

---

**`PUT /api/entity-relationships/{relationship_id}`** — Update verb, confidence, description, or evidence.  
**`POST /api/entity-relationships/{relationship_id}/confirm`** — Upgrade to `analyst_confirmed` + `confidence: confirmed`.  
**`POST /api/entity-relationships/{relationship_id}/reject`** — Tombstone as `analyst_rejected` (hidden, not deleted).  
**`DELETE /api/entity-relationships/{relationship_id}`** — Hard-delete (prefer reject: deletion lets re-ingestion recreate the pair).

**Auth:** Bearer token

---

#### Correlation, Pivot & Graph

Base path: `/api/intelligence` (correlation router)

- **`GET /api/intelligence/pivot/{entity_type}/{entity_id}`** — Pivot across entity types via shared entries (proximity-scored)
- **`GET /api/intelligence/graph/{entity_type}/{entity_id}`** — Typed entity graph: nodes + edges carrying relationship verb/confidence/provenance
- **`GET /api/intelligence/entry-graph/{entry_id}`** — Graph of all entities in one entry
- **`GET /api/intelligence/timeline/{entity_type}/{entity_id}`** / **`DELETE ...`** — Entity activity timeline (+ cache reset)
- **`GET /api/intelligence/search`** — Cross-type entity name search
- **`DELETE /api/intelligence/related/{entity_type}/{entity_id}/{other_type}/{other_id}`** — Suppress a co-occurrence pairing
- **`GET /api/intelligence/events`**, **`/events/grouped`**, **`/events/unread-count`**, **`PUT /events/{event_id}/read`**, **`PUT /events/read-all`** — Correlation event stream (new cross-source matches)
- **`GET /api/intelligence/temporal-clusters`** — Bursts of related activity
- **`POST /api/intelligence/detection-summary`** + **`GET/POST/DELETE /api/intelligence/detection-summaries[/{id}]`** — Ad-hoc and saved detection summaries for an entity set

**Auth:** Bearer token

---

#### Entity Notes

**`GET /api/entity-notes`**

List analyst notes for one entity (not article-specific notes).

**Auth:** Bearer token  
**Query Params:**
- `entity_type` (required), `entity_id` (required)
- `note_type`: "annotation" | "analysis" | "action_taken" | "false_positive" | "context"
- `limit`, `offset`: Pagination

---

**`GET /api/entity-notes/search`**

Search entity notes across all entities (paginated).

**Auth:** Bearer token

---

**`POST /api/entity-notes`**

Create a note on an entity for internal documentation.

**Auth:** Bearer token  
**Status:** 201 Created  
**Request:**
```json
{
  "entity_type": "threat_actor",
  "entity_id": "550e8400-...",
  "title": null,
  "content": "Observed new variant in the wild...",
  "note_type": "analysis",
  "tags": []
}
```

---

**`PUT /api/entity-notes/{note_id}`** — Update a note.  
**`DELETE /api/entity-notes/{note_id}`** — Delete a note (204).

**Auth:** Bearer token

---

### Intelligence Requirements (PIRs)

Base path: `/api/requirements`

Priority Intelligence Requirements: standing questions that incoming entries are matched against.

**`GET /api/requirements`** — List requirements (paginated).  
**`POST /api/requirements`** — Create a requirement (201).  
**`GET /api/requirements/{id}`** / **`PATCH /api/requirements/{id}`** / **`DELETE /api/requirements/{id}`** — CRUD.  
**`GET /api/requirements/coverage`** — Coverage summary across all requirements.  
**`GET /api/requirements/{id}/matches`** — Entries matched to a requirement (paginated).  
**`POST /api/requirements/{id}/match`** — Manually match an entry (201).  
**`DELETE /api/requirements/{id}/matches/{entry_id}`** — Remove a match (204).  
**`POST /api/requirements/{id}/fulfill`** — Mark a requirement fulfilled.  
**`GET /api/requirements/{id}/entities`** — Entities extracted from the requirement's matched entries (PIR entity matching: pivots a requirement into the actors/malware/CVEs it has surfaced).

**Auth:** Bearer token

---

### Automation & Rules

Base path: `/api/automation`, `/api/job-schedules`

Webhook management lives in the Automations area of the UI.

#### Automation Rules

Rules trigger automated actions on incoming entries (apply tags, send alerts, update entities, run enrichment).

**`GET /api/automation/rules`**

List automation rules with execution stats.

**Auth:** Bearer token  
**Query Params:**
- `limit`, `offset`: Pagination

**Response:**
```json
{
  "items": [
    {
      "id": "550e8400-...",
      "name": "Tag CVE articles",
      "description": "Auto-tag articles containing CVEs",
      "match_logic": {
        "conditions": [
          {
            "field": "contains_cves",
            "operator": "is_true"
          }
        ],
        "combinator": "all"
      },
      "actions": [
        {
          "type": "apply_tag",
          "params": { "tag_id": "..." }
        }
      ],
      "is_enabled": true,
      "execution_count": 1523,
      "last_executed_at": "2024-01-20T14:22:00Z",
      "created_at": "2024-01-01T00:00:00Z"
    }
  ],
  "total": 15,
  "limit": 50,
  "offset": 0,
  "has_more": false
}
```

---

**`POST /api/automation/rules`**

Create a new automation rule.

**Auth:** Bearer token  
**Status:** 201 Created  
**Request:**
```json
{
  "name": "Alert on APT29",
  "description": "Send webhook on new APT29 articles",
  "match_logic": {
    "conditions": [
      {
        "field": "threat_actors",
        "operator": "includes",
        "value": "550e8400-..." // APT29 entity ID
      }
    ],
    "combinator": "any"
  },
  "actions": [
    {
      "type": "send_webhook",
      "params": {
        "preset_id": "550e8401-..."
      }
    },
    {
      "type": "apply_tag",
      "params": { "tag_id": "550e8402-..." }
    }
  ],
  "is_enabled": true
}
```

---

**`GET /api/automation/rules/{rule_id}`**

Get a single rule's configuration.

**Auth:** Bearer token

---

**`PUT /api/automation/rules/{rule_id}`**

Update rule configuration.

**Auth:** Bearer token  
**Status:** 200 OK

---

**`DELETE /api/automation/rules/{rule_id}`**

Delete a rule.

**Auth:** Bearer token  
**Status:** 204 No Content

---

**`POST /api/automation/rules/{rule_id}/toggle`**

Enable or disable a rule without deleting it.

**Auth:** Bearer token  
**Status:** 200 OK

---

**`POST /api/automation/rules/{rule_id}/test`**

Test a rule against recent entries (dry-run).

**Auth:** Bearer token  
**Status:** 200 OK  
**Response:**
```json
{
  "matched_entries": 5,
  "would_apply_tags": [ "tag1", "tag2" ],
  "would_send_webhooks": 2
}
```

---

**`POST /api/automation/rules/{rule_id}/run`**

Run a rule now (for real, not a dry-run). Batch rules run once over the matched set; per-entry rules execute per matching entry.

**Auth:** Bearer token  
**Status:** 200 OK

---

**`GET /api/automation/templates`** — Prebuilt rule templates.  
**`GET /api/automation/variable-contexts`** — Variables available to action templates per trigger type.  
**`GET /api/automation/rules/export`** / **`GET /api/automation/rules/export/{rule_id}`** — Export rules as a portable JSON payload.  
**`POST /api/automation/rules/import`** — Import a previously exported payload.

**Auth:** Bearer token

---

**`GET /api/automation/rules/{rule_id}/logs`**

Execution logs for a specific rule.

**Auth:** Bearer token  
**Query Params:**
- `limit`, `offset`: Pagination

---

**`GET /api/automation/logs`**

All automation execution logs across rules.

**Auth:** Bearer token  
**Query Params:**
- `limit`, `offset`: Pagination

---

**`DELETE /api/automation/logs`**

Clear automation logs.

**Auth:** Bearer token  
**Status:** 204 No Content

---

#### Webhook Presets

**`GET /api/webhook-presets`**

List configured webhook endpoints.

**Auth:** Bearer token

**Response:**
```json
{
  "items": [
    {
      "id": "550e8400-...",
      "name": "Slack #threats",
      "url": "https://hooks.slack.com/...",
      "headers": { "Authorization": "Bearer ..." },
      "is_active": true,
      "test_payload": { "text": "Test message" }
    }
  ]
}
```

---

**`POST /api/webhook-presets`**

Create a webhook preset.

**Auth:** Bearer token  
**Status:** 201 Created

---

**`PUT /api/webhook-presets/{preset_id}`**

Update a webhook preset.

**Auth:** Bearer token  
**Status:** 200 OK

---

**`DELETE /api/webhook-presets/{preset_id}`**

Delete a preset.

**Auth:** Bearer token  
**Status:** 204 No Content

---

#### Job Schedules

Override the default schedules for background jobs (feed sync, enrichment, etc.).

**`GET /api/job-schedules`**

List job schedule configuration.

**Auth:** Bearer token

---

**`PATCH /api/job-schedules/{job_name}`**

Override the schedule for a job.

**Auth:** Bearer token  
**Status:** 200 OK

---

**`DELETE /api/job-schedules/{job_name}`** — Remove the override (revert to default schedule).  
**`POST /api/job-schedules/{job_name}/run`** — Trigger the job immediately.

**Auth:** Bearer token

---

### Dashboards & Widgets

Base paths: `/api/dashboards`, `/api/widgets`

#### Dashboards

**`GET /api/dashboards`**

List the caller's dashboards. Boards are private to the user who created them —
another user's board is invisible here and 404s on every other endpoint below.

**Auth:** Bearer token  
**Query Params:**
- `limit`, `offset`: Pagination

**Response:**
```json
{
  "items": [
    {
      "id": "550e8400-...",
      "name": "Executive Summary",
      "description": "High-level metrics and alerts",
      "layout": "grid",
      "is_default": true,
      "widgets": [ ... ],
      "created_at": "2024-01-01T00:00:00Z",
      "updated_at": "2024-01-20T14:22:00Z"
    }
  ],
  "total": 5,
  "limit": 50,
  "offset": 0,
  "has_more": false
}
```

---

**`POST /api/dashboards`**

Create a new dashboard.

**Auth:** Bearer token  
**Status:** 201 Created  
**Request:**
```json
{
  "name": "Incident Response",
  "description": "Real-time incident tracking",
  "layout": "grid",
  "is_default": false
}
```

---

**`POST /api/dashboards/seed-defaults`**

Give a user who owns no dashboards the instance's default board set (five
`__triage__/`-prefixed tabs defined in `backend/app/dashboard_defaults.py`).
Idempotent and non-destructive: a user who already owns any board gets that back
untouched. The dashboard page calls this once for a user with no boards.

**Auth:** Bearer token
**Response:** same shape as `GET /api/dashboards`

---

**`GET /api/dashboards/{dashboard_id}`**

Get dashboard with all widgets.

**Auth:** Bearer token

---

**`PUT /api/dashboards/{dashboard_id}`**

Update dashboard metadata.

**Auth:** Bearer token  
**Status:** 200 OK

---

**`DELETE /api/dashboards/{dashboard_id}`**

Delete a dashboard.

**Auth:** Bearer token  
**Status:** 204 No Content

---

**`PUT /api/dashboards/reorder`**

Reorder dashboard tabs.

**Auth:** Bearer token  
**Status:** 200 OK  
**Request:**
```json
{
  "dashboard_ids": [ "550e8400-...", "550e8401-...", "550e8402-..." ]
}
```

---

#### Widgets

**`POST /api/dashboards/{dashboard_id}/widgets`**

Add a widget to a dashboard.

**Auth:** Bearer token  
**Status:** 201 Created  
**Request:**
```json
{
  "type": "entry_feed",
  "title": "Critical Articles",
  "config": {
    "feed_ids": [ "550e8400-..." ],
    "filters": { "is_starred": true },
    "limit": 10
  },
  "position": { "x": 0, "y": 0, "w": 6, "h": 4 }
}
```

Widget `type` corresponds to one of the widget data endpoints below.

---

**`PUT /api/dashboards/{dashboard_id}/widgets/{widget_id}`**

Update widget config or position.

**Auth:** Bearer token  
**Status:** 200 OK

---

**`DELETE /api/dashboards/{dashboard_id}/widgets/{widget_id}`**

Remove widget from dashboard.

**Auth:** Bearer token  
**Status:** 204 No Content

---

**`PUT /api/dashboards/{dashboard_id}/layout`**

Update entire dashboard layout (grid positions).

**Auth:** Bearer token  
**Status:** 200 OK  
**Request:**
```json
{
  "widgets": [
    { "id": "550e8400-...", "position": { "x": 0, "y": 0, "w": 6, "h": 4 } }
  ]
}
```

---

#### Widget Data Endpoints

All `GET /api/widgets/{name}`, Bearer token, read-only aggregates consumed by dashboard widgets:

- **Core:** `feed-activity`, `cve-severity`, `threat-timeline`, `trending-cves`, `new-cves`, `attack-heatmap`, `stats`, `new-actors`, `detection-coverage`, `correlation-events`, `new-detections`, `automation-logs`
- **Detection:** `detection-format-breakdown`, `attack-coverage-gap`, `kev-matches` (stored CVEs present in CISA KEV)
- **Entities:** `trending-vendors`, `trending-products`, `targeted-countries`, `active-campaigns`
- **Ops:** `feed-health`, `worker-queue`, `ai-usage`
- **Strategic:** `weekly-recap`, `actor-activity`, `hot-correlations`
- **Triage:** `triage-queue-stats`, `saved-search-hits`, `top-tags`, `telegram-mentions`

---

### Detection Rules & Tools

Base paths: `/api/tools`, `/api/intelligence` (overlap)

#### Detection Rule Management

**`POST /api/entries/{entry_id}/generate-rules`**

(See Intelligence section above)

---

**`GET /api/detection-rules`**

List all stored detection rules.

**Auth:** Bearer token  
**Query Params:**
- `rule_type`: "sigma" | "splunk_spl" | "crowdstrike_ql" | "elastic_ql" | "kql" | "snort_suricata" | "yara" | "nuclei" | "panther"
- `status`: Rule lifecycle status filter
- `search`: Filter by title
- `limit`, `offset`: Pagination

**Response:**
```json
{
  "items": [
    {
      "id": "550e8400-...",
      "title": "Detect Cozybot C2 Communication",
      "rule_type": "sigma",
      "status": "active",
      "content": "title: ...\nlogsource:\n  product: windows\ndetection:\n  ...",
      "version": 3,
      "created_at": "2024-01-01T00:00:00Z",
      "updated_at": "2024-01-20T14:22:00Z"
    }
  ],
  "total": 250,
  "limit": 50,
  "offset": 0,
  "has_more": true
}
```

---

**`GET /api/detection-rules/telemetry-vocabulary`**

The library's Telemetry facet values split into `{collected, missing}` by whether the enabled Telemetry Sources inventory answers them — what the "My telemetry" / "Gaps" one-click selections tick. Server-side because the match is tiered (ticked product name → canonical behaviour id → category with a ticked source), so comparing the two lists client-side under-counts badly.

**Auth:** Bearer token

---

**`GET /api/detection-rules/search`**

The Rule Library's list *and* its facet counts, in one Meilisearch round trip. Unlike `GET /api/detection-rules` (PostgreSQL, `ILIKE` substring matching), this ranks by relevance with typo tolerance and returns a facet distribution scoped to the active filters, so the rail narrows as you click.

**Auth:** Bearer token  
**Query Params:**

| Param | Repeatable | Notes |
|-------|-----------|-------|
| `q` | | Full-text over title/description/tags/tactics/products/linked entities; empty matches all |
| `rule_type`, `severity`, `license`, `tag` | ✓ | Rule's own columns |
| `source_repo`, `source_author` | ✓ | Upstream provenance |
| `tactic`, `technique` | ✓ | ATT&CK tactics, technique IDs |
| `data_source` | ✓ | Values of the rule's own `data_sources` column |
| `telemetry_token` | ✓ | Required telemetry across every rule format — what the library's Telemetry rail faces. Wider than `data_source`: falls back to the Sigma `log_source` triple and the per-format defaults |
| `actor`, `malware`, `tool`, `vendor`, `product` | ✓ | Entities borrowed from the rule's source entry |
| `is_draft`, `authored_local` | | Booleans. `authored_local=true` means no upstream repo |
| `telemetry` | | `covered` (every required source is collected) \| `missing` (at least one isn't), judged against the enabled Telemetry Sources inventory at request time. Rules declaring no telemetry need match neither. Stricter than `telemetry_token`, which ORs and so also admits partially covered rules |
| `created_after` | | ISO timestamp |
| `sort_by` | | `relevance` \| `title` \| `rule_type` \| `severity` \| `is_draft` \| `created_at` \| `updated_at` \| `upstream_updated_at` |
| `sort_order` | | `asc` \| `desc` |
| `limit` (default 100, max 500), `offset` | | |

Values **within** a repeatable param are ORed; different params AND together — ticking two rule formats widens the result set rather than emptying it.

**Response:**
```json
{
  "items": [ { "id": "550e8400-...", "title": "...", "rule_type": "sigma", "telemetry": { ... } } ],
  "total": 4820,
  "limit": 100,
  "offset": 0,
  "has_more": true,
  "facets": {
    "rule_type": [ { "value": "sigma", "count": 3910 }, { "value": "yara", "count": 512 } ],
    "mitre_tactics": [ { "value": "persistence", "count": 811 } ],
    "actors": [ { "value": "APT29", "count": 14 } ]
  }
}
```

Notes:
- Facet counts are **disjunctive** — each facet is counted with every other filter applied but not its own, so selecting "sigma" still shows the other formats. Meilisearch's native distribution is conjunctive, which would collapse a facet to the single value you just picked and leave no way to switch. Each active facet costs one extra query, batched into a single multi-search request.
- `total` is exact (`page`/`hitsPerPage`, not `estimatedTotalHits`).
- Rows are hydrated from PostgreSQL by id **in Meilisearch's order**: the index carries only what is searched, filtered or sorted on, while derived fields (telemetry coverage against the live inventory, linked entry counts) stay computed off the authoritative row. A doc whose row was deleted is skipped rather than surfacing as a hole.
- Returns **503 `rule_search_unavailable`** if Meilisearch is down — the whole library is served from this, so a silent `[]` would read as "you have no rules".
- Facet groups returned: `rule_type`, `actors`, `malware`, `tools`, `vendors`, `products`, `techniques`, `source_repo`, `source_author`, `mitre_tactics`, `data_sources`, `severity`, `license`, `tags`.

---

**`POST /api/detection-rules`**

Create a rule manually or from template.

**Auth:** Bearer token  
**Status:** 201 Created  
**Request:**
```json
{
  "title": "New Malware Signature",
  "rule_type": "yara",
  "content": "rule MalwareX { ... }",
  "description": "...",
  "tags": [ "malware", "apt29" ]
}
```

---

**`GET /api/detection-rules/{rule_id}`**

Get a rule and its version history.

**Auth:** Bearer token

---

**`PUT /api/detection-rules/{rule_id}`**

Update a rule (creates new version).

**Auth:** Bearer token  
**Status:** 200 OK

---

**`DELETE /api/detection-rules/{rule_id}`**

Delete a rule and all versions.

**Auth:** Bearer token  
**Status:** 204 No Content

---

**`POST /api/detection-rules/validate`**

Validate rule syntax without saving.

**Auth:** Bearer token  
**Request:**
```json
{
  "rule_type": "sigma",
  "content": "title: Test\nlogsource: ..."
}
```
**Response:**
```json
{
  "is_valid": true,
  "errors": []
}
```

---

#### Rule Workbench & Lifecycle

- **`PATCH /api/detection-rules/{rule_id}/status`** — Move a rule through its lifecycle
- **`POST /api/detection-rules/{rule_id}/convert`** — Convert between rule formats
- **`POST /api/detection-rules/chat`** — AI-assisted rule editing chat
- **`GET /api/detection-rules/{rule_id}/diff`** — Diff between rule versions
- **`GET /api/detection-rules/{rule_id}/provenance`** / **`GET .../commits`** — Source-entry provenance and change history
- **`POST /api/detection-rules/extract-metadata`** — Parse title/logsource/ATT&CK refs out of raw rule text
- **`POST /api/detection-rules/bulk-update`** / **`POST .../bulk-delete`** — Bulk operations
- **`POST /api/detection-rules/import`** / **`GET /api/detection-rules/export`** — Import/export rule sets
- **`GET /api/detection-rules/needing-review`** — Rules flagged for review
- **`POST /api/entries/{entry_id}/extract-detection-rules`** — Extract rules embedded in an article

**Auth:** Bearer token

---

#### Detection Coverage

**`POST /api/intelligence/detection-coverage`**

Classify a set of ATT&CK techniques as `covered` (a referencing rule's data sources are all satisfiable by enabled telemetry), `library_only` (rule exists but telemetry can't satisfy it), or `no_rule`.

**Auth:** Bearer token

See also `GET /api/analytics/detection-coverage` and the `attack-coverage-gap` widget. Telemetry source management lives at `/api/telemetry-sources` (CRUD, `check-feasibility`, `telemetry-gaps`, `taxonomy`, `catalog`, `sync`).

---

#### Tools (Registry Execution)

**`POST /api/tools/execute`**

Execute a registered agent tool by name (the registry behind the skill CLIs). Tools in the registry's `ADMIN_TOOLS` set (entity merges, feed pool changes, automation-rule writes, extraction curation) require an admin caller — the registry is not a side door around the API layer's gates.

**Auth:** Bearer token (admin for `ADMIN_TOOLS` tools)  
**Request:**
```json
{
  "tool_name": "search_entries",
  "args": { "query": "LockBit", "limit": 5 }
}
```
**Response:**
```json
{
  "result": "<JSON result string>"
}
```

---

**`GET /api/tools/tools`**

List all registered tool definitions (name, description, schema).

**Auth:** Bearer token

---

### AI & Enrichment

Base paths: `/api/ai/*`, `/api/enrichment`

#### AI Providers

**`GET /api/ai/providers`**

List configured AI providers (LLMs).

**Auth:** Bearer token  
**Response:**
```json
{
  "items": [
    {
      "id": "550e8400-...",
      "name": "OpenAI",
      "provider_type": "openai",
      "is_active": true,
      "models": [ "gpt-4", "gpt-3.5-turbo" ],
      "config": { "api_key_set": true },
      "created_at": "2024-01-01T00:00:00Z"
    }
  ]
}
```

---

**`POST /api/ai/providers`**

Add an AI provider.

**Auth:** Bearer token  
**Status:** 201 Created  
**Request:**
```json
{
  "name": "Claude",
  "provider_type": "anthropic",
  "config": {
    "api_key": "sk-ant-...",
    "default_model": "claude-3-5-sonnet-20241022"
  }
}
```

---

**`PUT /api/ai/providers/{provider_id}`**

Update provider configuration.

**Auth:** Bearer token  
**Status:** 200 OK

---

**`DELETE /api/ai/providers/{provider_id}`**

Remove a provider.

**Auth:** Bearer token  
**Status:** 204 No Content

---

**`POST /api/ai/providers/{provider_id}/test`** — Run a connectivity/inference test.  
**`GET /api/ai/providers/{provider_id}/models`** — List models available from the provider.  
**`POST /api/ai/providers/{provider_id}/resume`** — Resume a provider that was auto-paused (e.g. after auth/billing errors).

**Auth:** Bearer token

---

#### AI Tasks

**`GET /api/ai/tasks`**

List AI tasks (intelligence extraction, content summarization, etc.).

**Auth:** Bearer token  
**Response:**
```json
{
  "items": [
    {
      "id": "550e8400-...",
      "name": "extract_ttps",
      "display_name": "Extract MITRE ATT&CK Techniques",
      "description": "Extract TTPs from article content",
      "category": "intelligence",
      "is_system": true,
      "default_prompt_template": "Extract MITRE techniques from: {content}",
      "variables": [ "content", "article_title" ],
      "created_at": "2024-01-01T00:00:00Z"
    }
  ]
}
```

---

**`POST /api/ai/tasks`**

Create a custom AI task (template for a specific enrichment workflow).

**Auth:** Bearer token  
**Status:** 201 Created

---

**`DELETE /api/ai/tasks/{task_id}`**

Delete a custom AI task.

**Auth:** Bearer token  
**Status:** 204 No Content

---

**`GET /api/ai/tasks/assignments/all`** — Provider/model assignment for every task.  
**`GET /api/ai/tasks/{task_id}/assignments`** / **`PUT /api/ai/tasks/{task_id}/assignments`** — Read/set which provider+model runs a task.

**Auth:** Bearer token

---

#### AI Prompts

Prompt templates are editable per task in the UI at Settings → AI Configuration.

**`GET /api/ai/prompts`** — List prompt templates for all tasks.  
**`GET /api/ai/prompts/{task_id}`** — Get the template for one task.  
**`PUT /api/ai/prompts/{task_id}`** — Update the template (creates a history version).  
**`POST /api/ai/prompts/{task_id}/reset`** — Reset to the built-in default.  
**`POST /api/ai/prompts/{task_id}/preview`** — Render the template against sample data without running inference.  
**`GET /api/ai/prompts/{task_id}/history`** — Prior versions.

**Auth:** Bearer token

---

#### AI Results & Cost Dashboard

AI results are cached per target (`target_type` is e.g. `entry`, `daily_summary`, an entity type):

**`GET /api/ai/results/{target_type}/{target_id}`** — All current results for a target.  
**`GET /api/ai/results/{target_type}/{target_id}/{task_name}`** — Current result for one task.  
**`GET /api/ai/results/{target_type}/{target_id}/{task_name}/history`** — Prior runs.  
**`POST /api/ai/results/{target_type}/{target_id}/run`** — Run (or re-run) a task against a target.

**Auth:** Bearer token

---

**`GET /api/ai/cost-breakdown`**

Cost dashboard: token/cost usage broken down by task, provider, and model over a time window.

**Auth:** Bearer token

---

**`GET /api/ai/cost-summary`** — Compact cost totals (used by the ops widgets).  
**`POST /api/ai/run-text`** — Run an ad-hoc AI task over raw text (no target persistence).

**Auth:** Bearer token

---

#### AI Copilot (Global)

Base paths: `/api/ai/copilot`, `/api/ai/copilot-auth`, `/api/ai/conversations`

**`POST /api/ai/copilot/stream`**

Stream a copilot answer over SSE. The copilot has tool access to platform data; each turn is persisted to an `AIConversation`.

**Auth:** Bearer token  
**Response:** SSE stream (`data:` lines of JSON events)

---

**`POST /api/ai/copilot/confirm`**

Confirm or deny a pending action the copilot proposed via an `intelfeed-action` fenced block (only `create_campaign` and `add_note` are supported; nothing is written until confirmed).

**Auth:** Bearer token

---

**Copilot provider auth** (`/api/ai/copilot-auth`): `GET /status`, `POST /refresh`, `POST /start`, `GET /session/{session_id}`, `POST /session/{session_id}/code`, `POST /session/{session_id}/cancel` — in-app OAuth login flow for the copilot's Claude session.

**Conversations** (`/api/ai/conversations`): `GET` (paginated), `POST`, `GET/PATCH/DELETE /{conversation_id}`, plus `POST /{conversation_id}/share` / `DELETE .../share` to mint or revoke a public share token (readable at `GET /api/shared/copilot/{token}`).

**Auth:** Bearer token

---

#### Enrichment

**`GET /api/enrichment/sources`**

List enrichment data sources (NVD, EPSS, CISA KEV, Malpedia, Wikipedia, etc.) and their status.

**Auth:** Bearer token  
**Response:**
```json
{
  "items": [
    {
      "id": "550e8400-...",
      "source_type": "vulncheck",
      "display_name": "VulnCheck",
      "is_enabled": true,
      "trigger_mode": "manual",
      "health_status": "healthy",
      "rate_limit_config": { "requests_per_day": 1000 },
      "config": { "api_key_set": true }
    }
  ]
}
```

---

**`PUT /api/enrichment/sources/{source_id}`**

Enable/disable a source or update its config.

**Auth:** Bearer token  
**Status:** 200 OK  
**Request:**
```json
{
  "is_enabled": true,
  "trigger_mode": "auto",
  "config": { "api_key": "..." }
}
```

---

**`POST /api/enrichment/sources/{source_id}/test`** — Test a source's connectivity/credentials.  
**`GET /api/enrichment/sources/{source_id}/health`** — Source health history.  
**`GET /api/enrichment/budget-summary`** — Per-source API budget consumption.  
**`GET /api/enrichment/user-overrides`** / **`PUT|DELETE /api/enrichment/user-overrides/{source_id}`** — Per-user source enable/disable overrides.

**Auth:** Bearer token

---

**`POST /api/enrichment/enrich`**

On-demand enrichment for a specific entity (cached + rate-limited pipeline).

**Auth:** Bearer token  
**Status:** 200 OK  
**Request:**
```json
{
  "entity_type": "cve",
  "entity_id": "550e8400-...",
  "source_types": null
}
```
`entity_type` is one of `cve`, `threat_actor`, `malware`, `ttp`.

---

**`GET /api/enrichment/results`** — Stored enrichment results for an entity.  
**`GET /api/enrichment/status`** — Overall enrichment pipeline status.

**Auth:** Bearer token

---

### Sharing & Public Endpoints

Base paths: `/api/entries/{id}/share`, `/api/shared`, `/api/public/rss`

**`POST /api/entries/{entry_id}/share`** — Create (or return the existing) public share link for an entry: `{ "token": "...", "url": "/shared/<token>", ... }`.  
**`GET /api/entries/{entry_id}/share`** — Current share link or `null`.  
**`DELETE /api/entries/{entry_id}/share`** — Revoke the link.

**Auth:** Bearer token

---

**`GET /api/shared/{token}`** (public)

Read a shared entry: content plus its extracted intelligence (TTPs, CVEs, actors, malware, detection rules, glossary matches, cached AI results).

**Auth:** None

---

**`POST /api/shared/{token}/run-ai-task`** / **`POST /api/shared/{token}/ask-agent`** (public)

Run a whitelisted AI task or ask the agent about a shared entry without authentication (detection-engineering and rule-generation tasks are excluded).

**Auth:** None

---

**`GET /api/shared/copilot/{token}`** (public) — Read a shared copilot conversation.

---

**Public RSS** (`/api/public/rss`, token-gated by the system public-RSS token): `GET /{token}.xml`, `GET /{token}/category/{slug}.xml`, `GET /{token}/categories`. Token management: `GET /api/system-settings/public-rss/token`, `POST /api/system-settings/public-rss/regenerate-token` (admin).

---

### System & Operations

Base paths: `/api/system-settings`, `/api/analytics`, `/api/backup`, `/api/logs`, health endpoints

#### System Settings

**`GET /api/system-settings`**

Get all system settings with current effective values (env default vs DB override), grouped for the settings UIs — the `group` on each key decides which surface renders it (Settings → Engine's stage panels and browse screens, or a Settings section).

**Auth:** Bearer token + admin  
**Response:**
```json
{
  "settings": { "registration_enabled": { "value": true, ... }, ... },
  "groups": { ... }
}
```

---

**`PATCH /api/system-settings`**

Update one or more settings. Set a value to `null` to reset it to its default.

**Auth:** Bearer token + admin  
**Status:** 200 OK  
**Request:**
```json
{
  "settings": { "registration_enabled": false }
}
```

---

**`DELETE /api/system-settings/{key}`**

Reset a single setting back to its env/default value.

**Auth:** Bearer token + admin

---

#### Analytics

**`GET /api/analytics/overview`**

Dashboard metrics: article count, extraction status, top entities, trend graphs.

**Auth:** Bearer token  
**Query Params:**
- `days`: Time window (default 7)

**Response:**
```json
{
  "total_articles": 5000,
  "articles_this_week": 1250,
  "feeds_synced": 200,
  "last_sync": "2024-01-20T14:22:00Z",
  "top_entities": [
    { "type": "threat_actor", "name": "APT29", "count": 120 },
    { "type": "malware", "name": "Cozybot", "count": 85 }
  ],
  "coverage": {
    "cves_extracted": 450,
    "ttps_extracted": 320,
    "actors_extracted": 180
  }
}
```

---

**`GET /api/analytics/trending/{entity_type}`** — Trending entities of a type over a window.  
**`GET /api/analytics/velocity`** — Publishing/ingest velocity over time.  
**`GET /api/analytics/source-overlap`** — Which feeds report the same stories.  
**`GET /api/analytics/detection-coverage`** — ATT&CK coverage rollup (covered / library-only / no-rule counts).  
**`GET /api/analytics/entries/{entry_id}/insights`** — Per-entry analytics (novelty, overlap, entity density).

**Auth:** Bearer token

---

#### Feed Reliability

**`GET /api/analytics/source-reliability`**

Reliability scoring for every feed: cadence, intel yield, error history — feeds are graded (A–F) and the rating feeds the high-value flag on breakage alerts.

**Auth:** Bearer token

---

**`GET /api/analytics/feed-value`**

Feed value ranking: which sources actually contribute unique, intel-bearing entries.

**Auth:** Bearer token

---

#### Backup & Export

**`GET /api/backup/export`**

Export platform data as a JSON download (feeds, categories, settings, entities, rules).

**Auth:** Bearer token (admin)  
**Response:** JSON file download

---

**`POST /api/backup/import`**

Restore from backup file.

**Auth:** Bearer token (admin)  
**Status:** 200 OK  
**Request:** Multipart form with `backup_file`

---

#### Logs

Application **log files** (structured audit events land in `audit.log`; there is no queryable audit-log API).

**`GET /api/logs`**

List available log files (app.log, http.log, tasks.log, audit.log, update.log) with size and modified time.

**Auth:** Bearer token + admin  
**Response:** `{ "files": [ { "name": "app.log", "size": 123456, "modified": "..." } ] }`

---

**`GET /api/logs/{filename}`** — Download/tail a log file.  
**`DELETE /api/logs/{filename}`** — Truncate a log file.

**Auth:** Bearer token + admin

---

#### Health & Metrics

**`GET /api/health`**

Health check: database (critical), Redis, and Meilisearch component status.

**Auth:** None (public)  
**Response:**
```json
{
  "status": "healthy",
  "version": "0.1.0",
  "components": {
    "database": { "status": "ok" },
    "redis": { "status": "ok" },
    "meilisearch": { "status": "ok" }
  }
}
```

---

**`GET /metrics`**

Prometheus metrics: HTTP request counts, latencies, feed sync times, etc.

**Auth:** None (can be rate-limited in reverse proxy)  
**Response:** Prometheus text format

---

#### Additional Operations

**Themes** (`/api/themes`): `GET` (list), `GET/PUT/DELETE /{theme_id}`, `POST` (create), `POST /{theme_id}/duplicate`, `PUT /api/themes/user/preferences` (apply a theme for the current user).

**Auth:** Bearer token

---

#### Search

**`GET /api/search`**

Full-text search across articles using Meilisearch.

**Auth:** Bearer token  
**Query Params:**
- `q`: Search query
- `feed_id`, `category_id`, `feed_type`, `tags`: Repeatable filters
- `date_from`, `date_to`: ISO timestamps
- `is_read`, `is_starred`, `is_bookmarked`, `has_notes`, `media_type`
- `sort`: "relevance" (default) or date sorts
- `limit` (default 20, max 500), `offset`

**Response:**
```json
{
  "hits": [ { "id": "550e8400-...", "title": "...", "_formatted": { ... } } ],
  "query": "ransomware",
  "processingTimeMs": 12,
  "estimatedTotalHits": 250,
  "facetDistribution": { ... },
  "searchUnavailable": false
}
```

---

**`POST /api/search/advanced`** — Structured query-language search (see [`docs/query-language.md`]).

---

**`POST /api/search/unified`**

The one search endpoint the `/search` page and the header input use. Runs the full query language: text terms and indexed filters against Meilisearch, `category:`/`signal:`/`url:`/`feed.*:`/`is:muted|translated|image` against PostgreSQL, entity filters against the entity tables — then intersects the three.

**Auth:** Bearer token  
**Body:**

| Field | Default | Max | Purpose |
|-------|---------|-----|---------|
| `q` | `""` | — | The query string |
| `limit` | 20 | 500 | Entry page size |
| `offset` | 0 | — | Entry pagination offset |
| `entity_limit` | 200 | 500 | How many entities the intelligence half may match in total |
| `entity_group_limit` | 25 | 500 | Rows carried per entity type. Applied **after** `counts` is computed, so per-type totals stay honest while the payload stays small |

```json
{
  "q": "threat_actor:APT29 cve.severity:critical date:>2026-01-01",
  "limit": 20,
  "offset": 0,
  "entity_limit": 200,
  "entity_group_limit": 25
}
```

**Response:**
```json
{
  "entries": {
    "hits": [ { "id": "550e8400-...", "title": "...", "_formatted": { ... } } ],
    "estimatedTotalHits": 261,
    "facetDistribution": {
      "feed_type": { "rss": 210, "youtube": 12 },
      "feed_title": { "Dark Reading": 44 },
      "tags": { "ransomware": 87 },
      "media_type": { "image": 190 },
      "language": { "en": 255 }
    }
  },
  "entities": {
    "items": [ { "id": "...", "type": "threat_actor", "name": "APT29", "match_kind": "direct" } ],
    "counts": { "threat_actor": 57, "malware": 12, "cve": 3 }
  },
  "query": "threat_actor:APT29 ...",
  "parsed_filters": [ { "field": "threat_actor", "value": "APT29", "exact": false, "negated": false, "raw": "threat_actor:APT29" } ],
  "did_you_mean": null,
  "processingTimeMs": 38
}
```

Notes:
- `entities.counts` is the **untrimmed** per-type total; `entities.items` is trimmed to `entity_group_limit` per type. The facet rail reads the former, the list renders the latter.
- Each entity item carries `match_kind`: `direct` (the query hit its name, alias, or catalogued identifier) or `mention` (it hit a description, tag, tactic, or rule body). Results from an explicit field filter are always `direct`.
- `entities.items` includes analyst **notes** under `"type": "note"` on free-text queries. Both note tables come back as one type, discriminated by `note_source`:

  ```json
  {
    "id": "…", "type": "note", "note_source": "note",
    "title": "Fortibleed",
    "description": "…centred on the match, markdown and HTML flattened…",
    "entry_id": "db491933-…", "entry_title": "DEW #147 — Flying Blind with your Logs",
    "is_pinned": false, "tags": [], "match_field": "title", "match_kind": "direct"
  }
  {
    "id": "…", "type": "note", "note_source": "entity_note",
    "title": "Note on CVE-2026-20262",
    "description": "…", "note_type": "context",
    "entity_type": "cve", "entity_id": "…", "entity_name": "CVE-2026-20262",
    "tags": [], "match_field": "content", "match_kind": "mention"
  }
  ```

  `note_source: "note"` is a note on an article (`entry_id` set) or a standalone one (both `entry_id` and `entry_title` null). `note_source: "entity_note"` hangs off an entity; `entity_name` is the resolved subject, and the title falls back to `"Note on {subject}"` when the author left it blank. Subjects resolve for `threat_actor`, `malware`, `cve`, `ttp`, `campaign`, `vendor` and `product`.

  Notes arrive from two directions: the free-text cross-entity sweep, and the `note:` field grammar (`note:`, `note.tag:`, `note.type:`, `note.about:`, `note.pinned:` — see [`query-language.md`]). A `note:` query whose matches hang off articles also contributes those articles as linked entries, exactly as any other entity filter does. `match_kind` is set on the free-text path but not the `note:` field path.

  Notes are **not scoped to the requesting user** — search returns every note on the instance, matching `GET /api/notes`.
- `estimatedTotalHits` is exact, not estimated, whenever the query takes the PostgreSQL path — `sort:radar`, an entity-only query, or a constraint above 800 entry IDs. On that path `facetDistribution` is **absent**, since facets come from Meilisearch.
- `parsed_filters` echoes what the parser extracted; the UI renders it as removable chips.
- `did_you_mean` is a corrected query string, or `null`. A value ends at the first space, so `country:North Korea` filters on `country:North` and full-text searches `Korea` — a plausible wrong answer rather than an error. The field is only set when the extended value is a real value for that field (the same lookup autocomplete uses), so it stays `null` on a deliberate filter-plus-search-term like `threat_actor:APT29 ransomware`. Longer extensions win: `country:North Korea attacks` returns `country:"North Korea" attacks`.

---

**`GET /api/search/facets`** — Facet counts for the current filter set.  
**`GET /api/search/autocomplete`** — Field and value completions for the search input. Suggestion categories: `entity`, `entry`, `meta`.  
**`GET /api/search/entities`** / **`POST /api/search/entities/sync`** — Entity index query and reindex.  
**`POST /api/search/rebuild`** — Rebuild the Meilisearch index.

**Auth:** Bearer token

---

**Saved searches** (`/api/saved-searches`): `GET` (list), `POST` (create, 201), `PUT /{search_id}`, `DELETE /{search_id}`. Saved searches are per-user: the list returns the caller's own, and update/delete require owner or admin.

**Categories** (`/api/categories`): `GET`, `POST` (201), `PUT /{category_id}`, `DELETE /{category_id}` (admin only — the folder tree is shared), `PUT /reorder`.

**Tags** (`/api/tags`): `GET`, `POST` (201), `PUT /{tag_id}`, `DELETE /{tag_id}`, `GET/POST /entries/{entry_id}` (entry tags), `DELETE /entries/{entry_id}/{tag_id}`, `POST /entries/bulk-tag`, `POST /entries/bulk-untag`, `POST /merge`.

**Auth:** Bearer token

---

### Other Routers

Concise index of the remaining routers (all Bearer-token unless noted; see the router files in [`backend/app/api/`] for details):

| Router | Base path | Purpose |
|--------|-----------|---------|
| Signal engine | `/api/engine` | Pipeline/extraction status, per-entry stage runs and retries, signal stats/settings, plans, job runs, radar feedback |
| Extraction management | `/api/engine/extraction` | AI-created entity provenance: `GET /stats`, `GET /entities` (filter/sort AI-extracted entities), `POST /confirm` |
| Entity links | `/api/entity-links` | Entry↔entity link (edge) management: `GET` (list, unified across junctions), `GET /stats`, `DELETE /{entity_type}/{entity_id}/{entry_id}`, `POST /bulk-unlink` |
| Ransomware tracker | `/api/ransomware` | Leak-site victim disclosures: `GET /disclosures`, `GET /stats`, `GET /victims/{victim_id}`, `GET /groups/{actor_id}/victims` (behind `ransomware_tracker_enabled`) |
| Stack exposure | `/api/intelligence/exposure` | CVEs affecting the user's vendor/product stack, ranked by exposure lift with detection posture (`GET`) |
| Documentation | `/api/documentation` | In-app docs: `GET` (page index from `docs/`), `GET /{slug}` (raw markdown for one page) |
| Hygiene (admin) | `/api/admin/hygiene`, `/api/entities/.../cascade-preview` | Orphan pruning, alias/vendor/ID hygiene scans, enrichment gaps, name normalization, hygiene feed/stats |
| Link validation (admin) | `/api/admin/link-validation` | Dead-link stats/log, restore, apply-removal, run |
| Intel reports | `/api/intel-reports` | Report CRUD, templates, AI generation (full / per-section / from-campaign), versions, export, publish/archive |
| Intel feed | `/api/intelligence/feed` | Aggregated intelligence activity feed |
| Watchlist | `/api/intelligence/watchlist` | Per-user entity watch list (`GET`, `PUT`, `DELETE /{entity_type}/{entity_id}`) |
| Notes | `/api/notes` | Per-entry analyst notes CRUD + export |
| Comments | `/api/comments` | Entry comments with @mentions |
| Glossary | `/api/glossary` | Term CRUD, categories, counts, per-term entries, in-text detection |
| Podcasts & playback | `/api/podcasts`, `/api/playback` | Podcast feeds/episodes; playback progress per media item |
| Telegram | `/api/telegram`, `/api/telegram-media` | Channel discovery, listener status, keyword mentions (dismiss/subscribe), media file serving |
| Events | `/api/events` | SSE stream of server events (`GET`, token via query param) + `POST /ticket` |
| Proxy | `/api/proxy/image` | Image proxy for entry content |
| Observables (IOC ledger) | `/api/observables` | `GET` (list/filter by kind, role, status, capture door, `infra_tag`, `min_confidence`, `linked_entity=<type>:<uuid>` — the profile pivot to one actor's/family's/campaign's/tool's claimed + reported-alongside observables; sortable by `report_count` / `feed_source_count`), `GET /{id}/backlinks` (who claims it, who it is reported with), `GET /rollup`, `GET /candidates` (the promote queue), `GET /{id}`, `PATCH /{id}`, `DELETE /{id}` (drops the row, its sightings and its relationship claims — no tombstone, so the value can be captured again), `POST /{id}/deny` (admin; keeps the row as the never-capture tombstone), `POST /never-capture`, `GET /{id}/sightings.csv`. Per-entry: `GET/POST /entries/{entry_id}/observables`, `/promote` (accepts `role`, `evidence`, `label`), `/dismiss` |
| Entity infrastructure | `/api/entities/{threat_actor\|malware\|campaign\|tool}/{id}/infrastructure` | `GET` → `{claimed, reported_alongside, counts}` (`counts.staged_candidate_articles` feeds the profile's empty state; cached in the pivot key space so unlink/relationship writes invalidate it); `?format=csv` for the flat export |
| Publishing (outbound) | `/api/publish`, `/api/taxii2` | Token-authed observable feeds for external pullers — `GET /publish/edl/{filename}` (EDL blocklists), `GET /publish/lookup/{filename}` (SIEM lookup CSVs), the TAXII 2.1 collection under `/taxii2/`, and `GET /publish/status` (normal user auth). Mounted **without** the app auth dependency; 404s entirely unless `observables_publish_enabled` |
| CWE | `/api/cwes` | MITRE weakness catalog: `GET` (list), `GET /rollup`, `GET /{cwe_id}`, `/family` (lineage), `/affected-cves`, `/vendors`. CVE side: `GET /cves/{cve_id}/weaknesses` |
| Intel profiles | `/api/intel-profiles` | Named report scopes (regions × verticals × window): CRUD, `GET /{id}/surface` (matched threat surface with why-matched evidence), `POST /surface-preview` (unsaved scope), `GET /sector-vocabulary` |
| Threat board | `/api/threat-board` | The Threats board: `GET` (ranked rows), `GET /windows`, `GET /precedent`, `GET /{entity_type}/{entity_key}/rules`, `PUT /{entity_type}/{entity_key}/state` (open / handled / muted) |
| Coverage workspace | `/api/coverage-workspace` | Per-entity detection coverage: `GET /{entity_type}/{entity_key}`, `/behaviours/{technique_id}/rules`, `/sets`, `GET /windows`, and set export (`/sets/{summary_id}/export`, `.zip`) |
| False positives | `/api/false-positives` | Analyst FP reports on entity links, feeding the autolinker denylists |
| Read-aloud (TTS) | `/api/tts`, `/api/shared/{token}/tts` | `POST /prepare` (enqueue Piper synthesis), `GET /file/{cache_key}.mp3`. The shared variant serves the pre-generated audio on a share link |
| Backup | `/api/backup` | See above |

---

## Common Query Patterns

### Filter Entries by Multiple Criteria

```bash
# Articles about APT29 from last 7 days, unread
curl -X GET "http://localhost:8000/api/entries?since=2024-01-13T00:00:00Z&is_read=false" \
  -H "Authorization: Bearer <token>"

# All starred or bookmarked articles
curl -X GET "http://localhost:8000/api/entries?is_starred=true&limit=100" \
  -H "Authorization: Bearer <token>"
```

### Pagination Through Large Result Sets

```bash
# Fetch first 50 entries
curl "http://localhost:8000/api/entries?limit=50" \
  -H "Authorization: Bearer <token>"

# Examine `next_cursor` in response, then fetch next page
curl "http://localhost:8000/api/entries?limit=50&cursor=<next_cursor>" \
  -H "Authorization: Bearer <token>"
```

### Extract Intelligence from an Entry

```bash
# Extract TTPs, CVEs, threat actors in one flow
curl -X POST "http://localhost:8000/api/entries/550e8400-/extract-ttps" \
  -H "Authorization: Bearer <token>"

curl -X POST "http://localhost:8000/api/entries/550e8400-/extract-cves" \
  -H "Authorization: Bearer <token>"

curl -X POST "http://localhost:8000/api/entries/550e8400-/extract-threat-actors" \
  -H "Authorization: Bearer <token>"
```

### Trigger Automation Rule

```bash
curl -X POST "http://localhost:8000/api/automation/rules/550e8400-/run" \
  -H "Authorization: Bearer <token>"

# Test rule before running (dry-run)
curl -X POST "http://localhost:8000/api/automation/rules/550e8400-/test" \
  -H "Authorization: Bearer <token>"
```

---

## Error Examples

**401 Unauthorized (Invalid Token):**
```json
{
  "error": {
    "code": "unauthorized",
    "message": "Invalid or expired token",
    "details": []
  }
}
```

**429 Rate Limited (Auth endpoint):**
```json
{
  "error": {
    "code": "rate_limited",
    "message": "Too many requests",
    "details": []
  }
}
```
Header: `Retry-After: 300`

**400 Validation Error:**
```json
{
  "error": {
    "code": "validation_error",
    "message": "Request validation failed",
    "details": [
      { "field": "username", "message": "ensure this value has at least 3 characters", "code": "string_too_short" },
      { "field": "email", "message": "invalid email format", "code": "value_error.email.invalid" }
    ]
  }
}
```

---

## Implementation Notes

- **Database:** PostgreSQL with async SQLAlchemy ORM; see [`backend/app/database.py`]
- **Caching:** Redis for token blacklist, rate limiting, and optional result caching
- **Indexing:** Meilisearch for full-text entry search
- **Async:** All endpoints use `async def` with `await` for database operations
- **Logging:** Structured logs via `structlog`; audit trail in database
- **Monitoring:** Prometheus metrics exported at `/metrics`

---

## Further Reading

- **Architecture:** [`docs/architecture.md`]
- **Database Models:** [`backend/app/models/`]
- **Pydantic Schemas:** [`backend/app/schemas/`]
- **Core Security:** [`backend/app/core/security.py`]
- **Rate Limiting:** [`backend/app/core/rate_limit.py`]
- **Main App Setup:** [`backend/app/main.py`]

