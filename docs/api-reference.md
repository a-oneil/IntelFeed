# REST API Reference

For developers who want to script IntelFeed or build on its REST API. After reading this you will know how to sign in, how errors, paging and rate limits work, and which endpoint does what. For ready-made recipes see [integrations.md](integrations.md). For the same operations as a command-line tool see [cli-reference.md](cli-reference.md).

## Overview

- **Base URL:** `/api` on your IntelFeed host (in the dev stack, `http://localhost:8000`).
- **Format:** JSON in, JSON out, unless an endpoint says otherwise (file downloads, SSE streams, RSS, CSV).
- **Full schemas:** the interactive docs at `/docs` (Swagger) and `/redoc` list every parameter and response field. They are built from the code, so they are always current. The pages themselves load for anyone, but the spec behind them (`/openapi.json`) needs a signed-in user: the docs page reads your token from the web app's local storage, so sign in to IntelFeed in the same browser first.
- **This page** is the map: how the API behaves, plus every endpoint with its access level and a one-line purpose. The routers are mounted in `backend/app/main.py:825-906`.

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
   - [Observables (IOC Ledger)](#observables-ioc-ledger)
   - [Entity Management](#entity-management)
   - [Intelligence Requirements (PIRs)](#intelligence-requirements-pirs)
   - [Automation & Rules](#automation--rules)
   - [Dashboards & Widgets](#dashboards--widgets)
   - [Detection Rules & Tools](#detection-rules--tools)
   - [AI & Enrichment](#ai--enrichment)
   - [Reports, Profiles & Exposure](#reports-profiles--exposure)
   - [Search](#search)
   - [Sharing & Public Endpoints](#sharing--public-endpoints)
   - [System & Operations](#system--operations)
   - [Other Routers](#other-routers)
7. [Common Query Patterns](#common-query-patterns)

---

## Authentication & Authorization

### JWT Token Flow

IntelFeed signs you in with JWTs (JSON Web Tokens, signed with HS256). You get two tokens:

- **Access token:** sent on every request as `Authorization: Bearer <token>`. Lasts 120 minutes by default (`ACCESS_TOKEN_EXPIRE_MINUTES`).
- **Refresh token:** trades in for a new pair at `POST /api/auth/refresh`. Lasts 7 days by default (`REFRESH_TOKEN_EXPIRE_DAYS`).

Logging out, or refreshing, revokes the old token: its ID (`jti`) goes on a Redis blacklist until the token would have expired anyway. Every protected route checks that list. Tokens are made by `create_access_token()` (`backend/app/core/security.py:31`) and revoked by `blacklist_token()` (`backend/app/core/security.py:107`).

Sign in from the host:

```bash
curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"analyst1","password":"hunter2secure"}'
# {"access_token":"eyJ...","refresh_token":"eyJ...","token_type":"bearer"}
```

#### JWT Claims

```json
{
  "sub": "<user id>",
  "role": "admin | user",
  "username": "analyst1",
  "type": "access | refresh",
  "jti": "<unique token id>",
  "exp": 1234567890
}
```

Refresh tokens carry only `sub`, `type`, `jti` and `exp`.

#### Common Dependencies

Each endpoint below lists one of these access levels:

| Level | Who may call it | Dependency |
| --- | --- | --- |
| **Public** | Anyone, no token. Some of these check their own token instead (share links, publish feeds, RSS). | none |
| **Visitor** | A signed-in user. With [public read-only mode](public-read-only-mode.md) on, also an anonymous visitor (read only, with some fields removed). | `get_viewer()` (`backend/app/core/security.py:179`), or `get_entry_viewer()` (`backend/app/core/security.py:212`) for one-article routes |
| **User** | Any signed-in user. | `get_current_user()` (`backend/app/core/security.py:125`) |
| **Admin** | Users with the `admin` role. Everyone else gets 403. | `get_admin_user()` (`backend/app/core/security.py:317`) |
| **Owner** | A signed-in user, but only the row's creator or an admin may change or delete it (403 otherwise). | checked inside the route |

"User (admin for …)" means the route is open to users, but some fields or options are admin-only.

The first account registered on a fresh install becomes the admin. Right after that, registration needs an invite code, which the admin sees under Settings > Users.

---

## Error Handling & Status Codes

### Error Response Format

Every error uses the same envelope (`AppError` in `backend/app/core/exceptions.py:7`):

```json
{
  "error": {
    "code": "not_found",
    "message": "Feed not found",
    "details": []
  }
}
```

A request that fails validation returns 400 with one entry in `details` per bad field:

```json
{
  "error": {
    "code": "validation_error",
    "message": "Request validation failed",
    "details": [
      { "field": "password", "message": "String should have at least 6 characters", "code": "string_too_short" }
    ]
  }
}
```

### Common Error Codes

| Code | Status | Meaning |
|------|--------|---------|
| `bad_request` | 400 | The request makes no sense for this resource |
| `validation_error` | 400 | The body or query failed validation |
| `unauthorized` | 401 | Missing, invalid, expired or revoked token |
| `forbidden` | 403 | Signed in, but not allowed (not admin, not the owner) |
| `not_found` | 404 | No such resource |
| `conflict` | 409 | It already exists (for example a taken username) |
| `rate_limited` | 429 | Too many requests; wait `Retry-After` seconds |
| `internal_error` | 500 | Unhandled server error |

Many routes use their own, more specific codes (`invalid_title_filter`, `task_has_results`, `rule_search_unavailable` and so on). Check `error.code`, not only the status.

---

## Pagination & Cursor Navigation

### Offset-Limit Pagination (Standard)

Most list endpoints take `limit` and `offset` and return:

```json
{ "items": [], "total": 1000, "limit": 50, "offset": 0, "has_more": true }
```

Defaults and maximums differ per endpoint (`GET /api/feeds` allows up to 1000). Some lists return a plain array instead; `/docs` shows which.

### Cursor Pagination (for Large Datasets)

The entry lists (`GET /api/entries`, `GET /api/feeds/{feed_id}/entries`, `GET /api/entries/priority-queue`) page with a cursor so deep pages stay fast:

```json
{ "items": [], "next_cursor": "eyJpZCI6...", "has_more": true }
```

Pass `next_cursor` back as `cursor` to get the next page. There is no `total`; use `has_more`, or `GET /api/entries/count` with the same filters.

---

## Rate Limiting

Limits are counted in Redis by `_get_limit()` (`backend/app/core/rate_limit.py:89`). Signed-in reads and most writes are not limited.

| Requests | Limit |
| --- | --- |
| `POST /api/auth/login`, `/register`, `/refresh` | 10 per 5 minutes |
| Everything under `/api/ai/` except `/tasks`, `/providers`, `/prompts` and `/copilot-auth`; also creating or testing a provider | 20 per minute |
| `POST /api/shared/{token}/run-ai-task` and `/ask-agent` | 20 per minute (plus a per-link daily cap, `share_ai_daily_requests`) |
| Anonymous visitors (public read-only mode), most routes | 180 per minute and 1500 per hour |
| Anonymous: one full article (`GET /api/entries/{id}`) | 20 per minute and 150 per hour |
| Anonymous: heavy reads (graphs, pivots, timelines, analytics, map, calendar, priority queue, relationships, entity links, CWEs) | 20 per minute and 200 per hour |
| `/api/taxii2/` and `/api/publish/` pulls | 240 per minute |
| `/api/health`, `/metrics` | never limited |

Limited responses carry `X-RateLimit-Limit` and `X-RateLimit-Remaining`. A 429 carries `Retry-After`.

**Who is counted:** the user in a token whose signature checks out; otherwise the client IP. Behind a proxy on a private network, the IP is the first `X-Forwarded-For` hop. If an edge such as Cloudflare fronts the server, set `TRUSTED_CLIENT_IP_HEADER` (for example `CF-Connecting-IP`) and that header is read first.

---

## Security & Middleware

### Middleware Stack (applied bottom-up)

A request passes through these in order (outermost first):

1. **CORS:** allows the origins in `CORS_ORIGINS`.
2. **Security headers** (`backend/app/core/security_headers.py`): adds the headers below to every reply.
3. **Rate limit** (`backend/app/core/rate_limit.py`): see above.
4. **Anonymous write lock** (`backend/app/core/public_access.py`): a request with no token may only read. Any other write returns 401 "Sign in to make changes". It also caps anonymous page sizes on the article lists at 50, and strips private fields from anonymous replies.
5. **Prometheus metrics** (`backend/app/core/metrics.py`).
6. **Audit log** (`backend/app/core/logging.py`): writes every `/api/` request with method, path, status, user and client IP to `audit.log`.
7. **Request log** (`backend/app/core/logging.py`): structured request logs.

### Security Headers

Every reply gets `Strict-Transport-Security: max-age=63072000; includeSubDomains`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy: camera=(), microphone=(), geolocation=()`, `X-Robots-Tag: noindex, nofollow` and a strict `Content-Security-Policy`. `/api/` replies also get `Cache-Control: private, no-store` (unless the route sets its own), so no shared cache serves one person's data to another.

`/docs`, `/redoc` and `/openapi.json` get a looser CSP so the Swagger and ReDoc bundles can load from `cdn.jsdelivr.net` and `unpkg.com`.

### Token Blacklisting

See [JWT Token Flow](#jwt-token-flow). Logout revokes the access token and, if you send it, the refresh token.

---

## API Endpoints by Domain

All paths below start with `/api` unless shown otherwise. `{id}`-style names are path parameters.

### Auth & Users

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/api/auth/registration-status` | Public | `registration_enabled`, `invite_code_required`, `public_read_only_enabled` |
| POST | `/api/auth/register` | Public | Create an account (`username`, `password` of 6+ characters, `invite_code`). Returns a token pair (201). 403 when closed or the code is wrong, 409 when the name is taken |
| POST | `/api/auth/login` | Public | Username and password in, token pair out. Updates `last_login` |
| POST | `/api/auth/refresh` | Public | `{"refresh_token"}` in, new pair out. The old refresh token is revoked |
| POST | `/api/auth/logout` | Bearer token | Revoke the current access token and the `refresh_token` in the body |
| GET | `/api/auth/me` | User | Your profile: id, username, role, settings, theme, feed counts |
| PUT | `/api/auth/me` | User | Replace your `settings` object |
| PATCH | `/api/auth/me/settings` | User | Merge top-level keys into `settings`, leaving the rest alone. Use this when you change one part (say `table_layouts`): a full `PUT` built from a stale copy drops the other parts |
| PUT | `/api/auth/me/password` | User | Change password (`current_password`, `new_password`) |
| GET | `/api/auth/invite-code` | Admin | The current invite code, or null |
| GET | `/api/admin/users` | Admin | All accounts, oldest first (plain array) |
| GET | `/api/admin/users/{user_id}` | Admin | One account |
| PATCH | `/api/admin/users/{user_id}` | Admin | Change username, role, active flag or password. You can't demote or deactivate yourself |
| DELETE | `/api/admin/users/{user_id}` | Admin | Delete an account (not your own) |

---

### Feeds & Content Ingestion

#### Feed Management

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/api/feeds` | Visitor | Your feeds with unread counts. `category_id`, `limit` (max 1000), `offset` |
| POST | `/api/feeds` | User | Add a feed. The category's `feed_defaults` fill any pipeline settings you leave out |
| POST | `/api/feeds/discover` | User | Find the feed behind a web page URL, without adding it |
| GET | `/api/feeds/{feed_id}` | Visitor | One feed |
| PUT | `/api/feeds/{feed_id}` | User (admin for infrastructure fields) | Change the fields you send. See below |
| DELETE | `/api/feeds/{feed_id}` | User (admin to delete) | See below |
| GET | `/api/feeds/{feed_id}/entries` | Visitor | The feed's articles, cursor-paged like `GET /api/entries` |
| POST | `/api/feeds/{feed_id}/refresh` | User | Fetch the feed now (queued) |
| POST | `/api/feeds/{feed_id}/resume` | Admin | Turn back on a feed the health check paused, and clear its failure count |
| POST | `/api/feeds/{feed_id}/pause` | Admin | Stop polling a feed for everyone (the PUT `is_active` toggle pauses only your own subscription) |
| POST | `/api/feeds/{feed_id}/remove` | Admin | Unsubscribe every reader and stop polling; entries stay (DELETE without `purge` unsubscribes only you) |
| GET | `/api/feeds/health` | User | Counts of healthy, stale, erroring and disabled feeds |
| GET | `/api/feeds/health/failing` | User | Feeds failing `threshold` times in a row (default 5). High-value feeds (rated A/B) come first |
| GET | `/api/feeds/{feed_id}/analytics` | User | Source reliability numbers for one feed |
| GET | `/api/feeds/{feed_id}/value` | User | The feed's value score and its rank among all scored feeds. `days` 7-365, default 90 |
| GET | `/api/feeds/{feed_id}/pipeline` | User | Which pipeline stages run for this feed and what decided each one |
| GET | `/api/feeds/{feed_id}/ai-usage` | User | AI calls and tokens spent on the feed's articles. `days` 1-365, default 30 |
| POST | `/api/feeds/{feed_id}/title-filter/preview` | User | How many of the last 100 titles an exclude list would drop, with up to five examples. Saves nothing |
| GET | `/api/feeds/{feed_id}/subscribers` | Admin | Who reads this feed and who doesn't |
| POST | `/api/feeds/{feed_id}/subscribers` | Admin | Subscribe users on their behalf |
| DELETE | `/api/feeds/{feed_id}/subscribers/{user_id}` | Admin | Unsubscribe a user on their behalf |
| POST | `/api/feeds/{feed_id}/full-sync` | User | Full tree sync of a GitHub repo feed |
| GET | `/api/feeds/{feed_id}/full-sync/progress` | User | Progress of that sync |

**Editing a feed.** Anyone may change curation fields: `custom_title`, `category_id`, `is_muted`, the ratings and `analyst_notes`. Only an admin may change the shared settings: `url`, `feed_type`, `fetch_interval_minutes`, `retention_days`, `adapter_config`, `exclude_shorts`, `intel_extraction_mode`, `ai_analysis_enabled`, `auto_extract_on_ingest`, `extract_detection_rules`, `extract_tools`, `exclude_title_patterns` and `visible_to_visitors`. `is_active` is admin-only too, unless per-user subscriptions are on (then pausing is personal).

**Deleting a feed.** With the `per_user_subscriptions_enabled` setting off, only an admin may delete, and the feed's articles go with it. With it on, `DELETE` unsubscribes the caller and leaves the feed for everyone else. A feed nobody subscribes to stops fetching. An admin passes `?purge=true` to really delete it.

**Exclude-title lists** are plain phrases, one per line, matched anywhere in the title, ignoring case. A line under 3 or over 200 characters, or more than 50 lines, returns 422 `invalid_title_filter`.

**Pipeline answer.** `decided_by` per stage is `legacy` (the feed's own columns decide, as they do while `pipeline_engine_enabled` is off) or the plan scope that decided it: `global`, `category` or `feed`.

```json
{
  "engine_enabled": true,
  "stages": { "extract": { "enabled": false, "config": { "mode": "selective" } } },
  "decided_by": { "extract": "legacy" }
}
```

#### Extended Feed Types

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/api/feeds/github-repo/templates` | User | The built-in list of detection-rule GitHub repos |
| POST | `/api/feeds/github-repo/bulk-setup` | User | Add a feed for each repo in that list |
| POST | `/api/feeds/bluesky/resolve-feed-url` | User | Turn a `bsky.app` custom feed URL into its `at://` URI |
| PUT | `/api/feeds/youtube/exclude-shorts` | Admin | Set `exclude_shorts` on every YouTube feed |
| PUT | `/api/feeds/category/{category_id}/intel-mode` | Admin | Set `intel_extraction_mode` on every feed in a category |
| PUT | `/api/feeds/category/{category_id}/bulk-update` | Admin | Change settings on every feed in a category. `save_as_category_default: true` also saves the pipeline settings as the category's `feed_defaults`; `apply_to_feeds: false` saves only the defaults |

#### Categories

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/api/categories` | Visitor | The category tree with feed counts |
| POST | `/api/categories` | User | Create a category (201) |
| PUT | `/api/categories/{category_id}` | User (admin for `feed_defaults`) | Rename, move or reorder. `feed_defaults` replaces the category's defaults (`{}` clears them) |
| PUT | `/api/categories/reorder` | User | Save a new order and parent for many categories |
| DELETE | `/api/categories/{category_id}` | Admin | Delete a category. Its feeds move to uncategorized |

`feed_defaults` are the pipeline settings a new feed in the category starts with. They apply once, when the feed is created. Changing them later, or moving a feed into the category, does not change existing feeds.

#### OPML Import/Export

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| POST | `/api/opml/import` | User (admin unless per-user subscriptions are on) | Import an OPML file (multipart field `file`, max 10 MB). Returns `feeds_added`, `feeds_skipped`, `categories_created`, `errors` |
| GET | `/api/opml/export` | User | All feeds as OPML XML |
| GET | `/api/opml/starter-packs` | User | The curated starter feed packs |
| POST | `/api/opml/starter-packs/import` | User (admin unless per-user subscriptions are on) | Import starter packs by id |
| GET | `/api/onboarding/status` | User | Whether this install is seeded, fetching feeds and linking entities |

---

### Entries & Article Management

An entry is one article (or post, video, file) pulled from a feed.

#### Listing & Filtering

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/api/entries` | Visitor | The reader's article list, cursor-paged. Filters below |
| GET | `/api/entries/count` | Visitor | How many entries match the same filters |
| GET | `/api/entries/{entry_id}` | Visitor | One article: content, translation, your read/star state, duplicates from other feeds |
| GET | `/api/entries/priority-queue` | Visitor | The ranked reading queue. See below |
| GET | `/api/entries/priority-unread-count` | Visitor | The Priority Queue badge count |
| GET | `/api/entries/triage` | User | Triage queue scored by recency, engagement and requirement matches |
| POST | `/api/entries/resolve-names` | Visitor | Entry ids in, `{id, title, feed_title}` out |

`GET /api/entries` filters: `feed_id`, `category_id`, `is_read`, `is_starred`, `is_bookmarked`, `content_type`, `change_type`, `since`, `before`, `country_id` + `country_role` (`origin`, `target`, `infrastructure`, `mentioned`), `campaign_id`, `exploited_cves`, `entity_type` + `entity_id`, `sector`, `watched`, `sort` (`newest`, `oldest`, `title_asc`, `title_desc`, `shortest`, `longest`, `radar`), `dedup` (default true: show one copy of the same article from several feeds), `limit` (default 50, max 500), `cursor`. Muted feeds are left out of the all-feeds view, but included when you pass `feed_id` or `category_id`.

**Priority Queue.** Unread articles above the radar threshold, ranked by their 0-10 priority score. Open story threads are folded in as single rows: a thread ranks by its best unread article, and its members don't also appear on their own. Parameters: `unread_only` (default true), `with_threads` (default true), `exclude_thread_ids` (repeatable; those threads' members come back as normal rows), `limit` (default 50, max 200; thread rows come on top), `cursor`.

```json
{
  "items": [
    { "kind": "thread", "score": 9.6, "entry": null, "thread": { "slug": "gitlab-path-traversal-exploited" }, "absorbed_entry_ids": ["..."] },
    { "kind": "entry", "score": 8.7, "entry": { "id": "...", "title": "..." }, "thread": null, "absorbed_entry_ids": [] }
  ],
  "next_cursor": "eyJlbnRyeSI6...",
  "has_more": true,
  "radar_threshold": 8.4
}
```

`radar_threshold` is null when the signal engine isn't surfacing; then the queue is every unread entry ranked by score.

#### Entry State & Bulk Actions

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| PUT | `/api/entries/{entry_id}/read` | User | Mark read |
| PUT | `/api/entries/{entry_id}/unread` | User | Mark unread |
| PUT | `/api/entries/{entry_id}/star` | User | Toggle star; returns the new value |
| PUT | `/api/entries/{entry_id}/bookmark` | User | Toggle bookmark; returns the new value |
| POST | `/api/entries/bulk-action` | User | `{"entry_ids": [...], "action": "read"}`. Actions: `read`, `unread`, `star`, `unstar`, `bookmark`, `unbookmark`, `hide` |
| POST | `/api/entries/mark-all-read` | User | Mark read by feed or category and an optional `since`/`before` window. `radar_only` limits it to Priority Queue entries |

#### Views & Aggregates

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/api/entries/calendar` | Visitor | Articles per day, for the calendar view |
| GET | `/api/entries/map` | Visitor | Articles per country, for the map view |
| GET | `/api/entries/day-intel` | Visitor | Top entities and urgent signals for one day (`since`/`before`, optional `feed_id`/`category_id`) |
| GET | `/api/entries/day-entities` | Visitor | Every entity mentioned that day, with the names matched in the text |
| GET | `/api/entries/daily-summary` | User | The saved AI summary for a day, or null. Never generates one |
| POST | `/api/entries/daily-summary` | User | Generate the day's AI summary (`day_key: YYYY-MM-DD` plus filters; `force: true` regenerates). The unfiltered summary is shared by everyone; filtered ones are per user |

#### Per-Entry Extras

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| POST | `/api/entries/{entry_id}/translate` | User | Translate the article through the LibreTranslate service |
| GET | `/api/entries/{entry_id}/similar` | Visitor | Related articles. Uses embeddings when the article has one (`method: "embedding"`), else keyword overlap in Meilisearch (`method: "keyword"`) |
| GET | `/api/entries/{entry_id}/media` | User | Attached images, audio and video |
| GET | `/api/entries/{entry_id}/urls` | Visitor | Links found in the article |
| GET | `/api/entries/{entry_id}/article-metadata` | Visitor | Report type, victim organisations, timeline dates, patch availability |
| POST | `/api/entries/{entry_id}/run-ai-task` | User | Run any AI task (for example `article_summary`) on the article |
| POST | `/api/entries/bulk-summarize` | User | One AI briefing over several articles |
| POST | `/api/entries/intel-counts` | Visitor | Entity counts for a batch of entries (for list badges) |

#### Notes, Tags & Comments

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/api/notes` | User | Every user's notes, pinned first |
| POST | `/api/notes` | User | Create a note not tied to an article |
| GET | `/api/notes/{note_id}` | User | One note |
| PUT | `/api/notes/{note_id}` | Owner | Change a note |
| DELETE | `/api/notes/{note_id}` | Owner | Delete a note |
| GET | `/api/notes/entry/{entry_id}` | User | Notes on an article |
| POST | `/api/notes/entry/{entry_id}` | User | Add a note to an article |
| GET | `/api/tags` | Visitor | All tags with entry counts |
| POST | `/api/tags` | User | Create a tag (409 if the name exists) |
| PUT | `/api/tags/{tag_id}` | User | Rename, recolour, describe, show as a chip, or switch `is_global` |
| DELETE | `/api/tags/{tag_id}` | User | Delete a tag everywhere |
| POST | `/api/tags/merge` | User | Fold `source_ids` into `target_id` |
| GET | `/api/tags/entries/{entry_id}` | Visitor | An article's tags as you see them |
| POST | `/api/tags/entries/{entry_id}` | User | Tag an article |
| DELETE | `/api/tags/entries/{entry_id}/{tag_id}` | User | Untag an article |
| POST | `/api/tags/entries/bulk-tag` | User | Tag many articles |
| POST | `/api/tags/entries/bulk-untag` | User | Untag many articles |
| GET | `/api/comments` | User | Comments on one object, oldest first |
| POST | `/api/comments` | User | Comment, or reply with `parent_id`. `@username` mentions are picked up |
| PATCH | `/api/comments/{comment_id}` | Owner | Edit a comment |
| DELETE | `/api/comments/{comment_id}` | Owner | Delete a comment |
| GET | `/api/comments/mentions` | User | Comments that mention you |

**Tags are shared, assignments are personal.** Everyone sees the same tag list, but tagging an article only tags it for you, and every read (entry `tags`, counts, the search `tags` facet) shows your own view. A tag with `is_global: true` has one shared assignment for everyone instead. Switching a tag to global merges everyone's assignments into one; switching it back gives the shared assignment to every user. Tag names are 1-100 characters and can't contain `"` or `\`.

#### Export

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/api/export/entries/{entry_id}` | User | One article as Markdown, with its tags and notes |
| GET | `/api/export/notes/{note_id}` | User | One note as Markdown |
| POST | `/api/export/bulk` | User | Many articles and notes as a ZIP of Markdown files |
| POST | `/api/export/research-bundle` | User | Selected articles as a research bundle ZIP |
| GET | `/api/export/campaigns/{campaign_id}/bundle` | User | Every article in a campaign as a research bundle ZIP |
| GET | `/api/export/entities/{entity_type}/{entity_id}` | User | One entity profile as Markdown |
| POST | `/api/export/entities/bulk` | User | Many profiles of one type as a ZIP. Send `entity_ids`, or `all: true` (capped, most-mentioned first) |

#### Ingest & Processing

Manual ingest adds articles by hand. See [adapters.md](adapters.md#manual-ingest) for how it works.

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| POST | `/api/entries/ingest/url` | User | Add one web page now (`{"url"}`). Errors: 409 `duplicate`, 422 `extraction_failed`, 400 `invalid_url` |
| POST | `/api/entries/ingest/pdf` | User | Add one PDF now (multipart `file`, optional `title`). The original is kept for download |
| GET | `/api/entries/ingest/capabilities` | User | Accepted file types and limits (`max_file_mb`, `max_batch_items`, `zip_max_members`) |
| POST | `/api/entries/ingest/batches` | User | Open a batch (`{"label"}`). Items start processing the moment you add them; there is no submit step |
| GET | `/api/entries/ingest/batches` | User | Recent batches (`limit`, `mine`) |
| GET | `/api/entries/ingest/batches/{batch_id}` | User | A batch and the status of each item |
| POST | `/api/entries/ingest/batches/{batch_id}/files` | Owner | Add one file (multipart `file`, optional `title`, `is_ioc_list`). One request per file |
| POST | `/api/entries/ingest/batches/{batch_id}/urls` | Owner | Add URLs. A `github.com/owner/repo[/tree/<branch>/<path>]` link expands into one item per file |
| POST | `/api/entries/ingest/batches/{batch_id}/text` | Owner | Add pasted text (`text`, optional `title`, `source_url`, `is_ioc_list`). One paste is one article |
| POST | `/api/entries/ingest/batches/{batch_id}/items/{item_id}/retry` | Owner | Retry a failed item. 409 `original_not_kept` once the stored file is gone |
| DELETE | `/api/entries/ingest/batches/{batch_id}/items/{item_id}` | Owner | Remove an item and its file. The article it made stays |
| GET | `/api/ingest-files/{file_id}` | Token in header or `?token=` | Download an upload's original file. `?inline=true` opens it in the browser. 404 `ingest_file_evicted` once retention has removed it |

Item `status` is one of `queued`, `parsing`, `created`, `expanded`, `duplicate`, `no_text`, `unsupported`, `too_large`, `failed`, `cancelled`. Created items also have a `phase`: `analyzing` until the AI analysis lands, then `done`. The `ingest_item_updated` event on the SSE stream fires on each change.

---

### Story Threads

A story thread is one unfolding story, instead of the twenty articles that reported it. See [story-threads.md](story-threads.md) for how threads are built.

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/api/threads` | Visitor | Threads, most recently active first. `status` (`open` default, `dormant`, `closed`, `any`), `q` (title search), `limit` (default 40, max 200) |
| GET | `/api/threads/{slug}` | Visitor | One thread: its `beats` (the timeline), `members` (each an `origin`, `beat` or `echo`), what it produced, and the `nearest` similar threads |
| POST | `/api/threads/{thread_id}/open` | User | Mark the thread as seen. `new_since_opened` counts from here |

Each list row has `entry_count`, `source_count` (outlets, not feeds), `echo_count`, `unread_count`, `new_since_opened`, `top_score` (its best unread article's priority score), `key_entities` and the member `entry_ids`.

---

### Intelligence Extraction

These endpoints pull structured threat data out of articles and serve the entity catalogs. An *entity* is a tracked thing: a threat actor, malware family, CVE (a published vulnerability), TTP (a MITRE ATT&CK technique), tool, vendor, product, country, sector, mitigation or CWE (a weakness type).

#### Extract and List per Article

`POST /api/entries/{entry_id}/extract-<type>` runs extraction on one article and saves the links. `GET /api/entries/{entry_id}/<type>` lists what is linked. `DELETE /api/entries/{entry_id}/<type>/{id}` removes one link (the entity itself stays).

| Type | Extract (User) | List (Visitor) | Unlink (User) | How it extracts |
| --- | --- | --- | --- | --- |
| TTPs | `extract-ttps` | `ttps` | `ttps/{ttp_id}` | Patterns plus AI; `use_ai=false` for patterns only |
| CVEs | `extract-cves` | `cves` | `cves/{cve_id}` | Patterns; `enrich=true` (default) pulls NVD data for new CVEs. Returns a plain list |
| Threat actors | `extract-threat-actors` | `threat-actors` | `threat-actors/{actor_id}` | AI |
| Malware | `extract-malware` | `malware` | `malware/{malware_id}` | AI |
| Countries | `extract-countries` | `countries` | `countries/{country_id}` | AI |
| Sectors | `extract-sectors` | `sectors` | `sectors/{sector_id}` | AI |
| Mitigations | `extract-mitigations` | `mitigations` | `mitigations/{mitigation_id}` | Patterns plus AI |
| Tools | `extract-tools` | `tools` | `tools/{tool_id}` | AI |
| Detection rules | `extract-detection-rules` | | | Code blocks in the article. Returns a plain list |
| Vendors | | `vendors` | `vendors/{vendor_id}` | Autolinker only |
| Products | | `products` | `products/{product_id}` | Autolinker only |
| CWEs | | `cwes` | `cwes/{cwe_id}` | Autolinker only |

Most extract calls return `{"items": [...], "status": "success", "error_message": null}`. `status` can also be `ai_not_configured`, `provider_error` or `parse_error`.

Other per-article routes:

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| POST | `/api/entries/{entry_id}/link-entity` | User | Link an existing entity of any type |
| GET | `/api/entries/{entry_id}/kill-chain` | Visitor | The article's TTPs in attack-chain order |
| GET | `/api/entries/{entry_id}/ttps/navigator` | Visitor | The article's TTPs as an ATT&CK Navigator layer |
| POST | `/api/entries/{entry_id}/generate-rules` | User | AI-written detection rules. Body `{"rule_types": ["sigma", "splunk_spl"]}`. Returns the saved rules |
| POST | `/api/entries/{entry_id}/autolink` | User | Re-run the autolinker on this article |

#### Entity Catalogs

All Visitor. The lists are paginated and take `search` and sort parameters.

| Type | List | One | More |
| --- | --- | --- | --- |
| TTPs | `GET /api/ttps` | `GET /api/ttps/by-technique/{technique_id}` | `/api/ttps/{ttp_id}/mitigations`, `/api/ttps/{ttp_id}/related-techniques` |
| CVEs | `GET /api/cves` | `GET /api/cves/{cve_id}` (UUID or `CVE-2024-1234`) | `/api/cves/trending`, `/api/cves/{cve_id}/affected`, `/api/cves/{cve_id}/weaknesses` |
| Threat actors | `GET /api/threat-actors` | `GET /api/threat-actors/{actor_id}` | |
| Malware | `GET /api/malware` | `GET /api/malware/{malware_id}` | |
| Countries | `GET /api/countries` | `GET /api/countries/{country_id}` | `/api/countries/{country_id}/profile`, `GET /api/regions` |
| Sectors | `GET /api/sectors` | `GET /api/sectors/{sector_ref}` | `/api/sectors/{sector_ref}/profile` |
| Mitigations | `GET /api/mitigations` | `GET /api/mitigations/{mitigation_id}` | |
| Tools | `GET /api/tools` | `GET /api/tools/{tool_id}` | |
| Vendors | `GET /api/vendors` | `GET /api/vendors/{vendor_id}` | `/products`, `/affected-cves`, `/weaknesses` |
| Products | `GET /api/products` | `GET /api/products/{product_id}` | `/affected-cves`, `/weaknesses` |
| CWEs | `GET /api/cwes` | `GET /api/cwes/{cwe_id}` | `/api/cwes/rollup`, `/family`, `/affected-cves`, `/vendors` |

`POST /api/intelligence/resolve-names` (Visitor) turns entity ids into names.

**CVEs** carry NVD, CISA KEV (the list of vulnerabilities known to be exploited) and EPSS (a score for how likely exploitation is) fields: `epss_score`, `epss_percentile`, `is_kev`, `kev_date_added`, `kev_due_date`. They also get a risk tier: `critical` if in KEV, `high` if EPSS is over the threshold or a Metasploit module exists, `medium` for a public proof of concept or CVSS 9+ / critical / high severity, else `low`.

**Sectors** are a fixed list of 21 victim industries. Every sector route accepts a UUID, slug (`healthcare`), display name or alias. The sector profile (`window_days`) shows who targets it, leak-site victims, countries, campaigns, intel profiles and recent articles. Only the AI analysis writes article-sector links.

#### ATT&CK Catalog & Matrix

The full MITRE ATT&CK catalog, loaded by `scripts/seed/seed_mitre_attack.py`. All Visitor.

| Method | Path | What it does |
| --- | --- | --- |
| GET | `/api/attack/matrix` | Tactics in order, techniques with article counts and detection coverage. `domain` (`enterprise`, `mobile`, `ics`), `days`, `include_deprecated`. Cached in Redis |
| GET | `/api/attack/layer` | An ATT&CK Navigator layer from extracted TTPs |
| GET | `/api/attack/techniques` | Techniques seen in a window, by article count |

#### Autolinker

The autolinker scans article text for names of known entities.

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| POST | `/api/autolink/scan` | Visitor | Find known entities in text you send |
| GET | `/api/autolink/status` | User | The autolinker's vocabulary status |
| POST | `/api/autolink/rescan` | Admin | Re-scan recent articles |
| POST | `/api/autolink/revalidate` | Admin | Remove links that no longer pass the matching rules |
| GET | `/api/proximity-settings` | User | The proximity-scoring settings used by pivots |

#### Bulk and Maintenance

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| POST | `/api/intelligence/bulk-extract` | Admin | Queue extraction over many articles |
| POST | `/api/intelligence/bulk-translate` | Admin | Queue translation by feed, category, tag or ids |
| POST | `/api/intelligence/rescan-all-extraction` | Admin | Re-run pattern extraction (TTP, CVE, mitigation) on every article |
| POST | `/api/intelligence/reset-correlation` | Admin | Unlink every entity from every article and clear relationships |
| POST | `/api/sync/mitre-attack` | Admin | Refresh the ATT&CK catalog now |
| POST | `/api/sync/cve-backfill` | Admin | Fill in missing NVD data on stored CVEs |

---

### Observables (IOC Ledger)

Observables are IOCs (indicators of compromise: hashes, IPs, domains, URLs and so on), stored once per kind and value. Pattern matching never creates a row on its own. It only suggests candidates, which an analyst or the AI confirms. See [observables.md](observables.md).

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/api/observables` | User | The ledger. `search`, `kind`, `role`, `status`, `created_via` (how it was captured), `infra_tag`, `min_confidence`, or `linked_entity=<type>:<uuid>`; sort by `report_count` or `feed_source_count` |
| GET | `/api/observables/rollup` | User | Counts by kind and state |
| GET | `/api/observables/candidates` | User | Suggested values nobody has confirmed yet |
| GET | `/api/observables/{observable_id}` | User | One observable |
| PATCH | `/api/observables/{observable_id}` | User (admin to change the never-capture flag) | Edit label, role, description, confidence |
| DELETE | `/api/observables/{observable_id}` | User | Delete the row, its sightings and relationships. The value can be captured again later |
| POST | `/api/observables/{observable_id}/deny` | Admin | Never capture or export this value again. Keeps the row as a marker |
| POST | `/api/observables/never-capture` | Admin | Ban a value from the candidates queue for good |
| GET | `/api/observables/{observable_id}/backlinks` | User | Who claims it, and what it was reported alongside |
| GET | `/api/observables/{observable_id}/sightings.csv` | User | Every sighting as CSV |
| GET | `/api/entries/{entry_id}/observables` | User | An article's confirmed observables and its candidates |
| POST | `/api/entries/{entry_id}/observables/promote` | User | Confirm a candidate (`role`, `evidence`, `label`) |
| POST | `/api/entries/{entry_id}/observables/dismiss` | User | Drop a candidate from this article |
| DELETE | `/api/entries/{entry_id}/observables/{observable_id}` | User | Remove one sighting (the observable stays) |
| GET | `/api/entities/{entity_type}/{entity_id}/infrastructure` | User | Observables behind an actor, malware, campaign or tool: `{claimed, reported_alongside, counts}`. `?format=csv` for a flat file |

To share observables with firewalls and SIEMs, see [Sharing & Public Endpoints](#sharing--public-endpoints).

---

### Entity Management

#### Entity Profiles (Threat Actors, Malware, Vendors, Products, Tools, ...)

Reading entities uses the catalogs above. Creating and editing uses `/api/entities/<type>`.

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| POST | `/api/entities/{threat-actors, malware, cves, ttps, countries, mitigations, tools, vendors, products}` | User | Create an entity, and optionally link it to an article |
| PUT | `/api/entities/{threat-actors, malware, cves, ttps, countries, sectors, tools, vendors, products}/{id}` | User | Edit an entity. Removing an alias unlinks articles matched only by it |
| DELETE | `/api/entities/{threat-actors, malware, cves, ttps, countries, mitigations, tools, vendors, products}/{id}` | User | Delete an entity with its links and relationships |
| GET | `/api/entities/{entity_type}/{entity_id}/cascade-preview` | User | What a delete would remove (links, campaigns, rules, relationships) |
| DELETE | `/api/entities/{entity_type}/{entity_id}/unlink-all` | Admin | Unlink every article, keep the entity |
| POST | `/api/entities/{entity_type}/{entity_id}/deny-name` | User | Add its name and aliases to the do-not-recreate list |
| POST | `/api/entities/{entity_type}/{entity_id}/rescan` | User | Re-scan all articles for this entity |
| POST | `/api/entities/convert` | Admin | Change an entity's type (for example malware to tool), moving its links, relationships, notes and campaigns |
| GET | `/api/entities/{entity_type}/{entity_id}/provenance` | Visitor | Who stated each fact on the profile, and whether they still agree |
| GET | `/api/entities/{entity_type}/{entity_id}/context` | Visitor | What the enabled enrichment sources say about the entity, with header badges; admins also get sources missing a key |
| GET | `/api/entities/{entity_type}/{entity_id}/glance` | Visitor | The highlight popover's few words from enrichment: up to two verdict chips and three facts, each with its source and date, the sources its Look up button runs, and (admins) sources that need a key |
| GET | `/api/entities/{entity_type}/{entity_id}/detection-gaps` | User | Detection coverage for the entity's techniques |
| GET | `/api/entities/{entity_type}/{entity_id}/story-threads` | Visitor | Story threads that mention the entity |
| GET | `/api/entities/{entity_type}/{entity_id}/attack-techniques` | Visitor | Techniques from its articles, by evidence |
| GET | `/api/entities/{entity_type}/{entity_id}/attack-layer` | Visitor | Those techniques as a Navigator layer |
| GET | `/api/entities/{entity_type}/{entity_id}/mentions-timeseries` | Visitor | Mention counts over time |
| GET | `/api/entities/{entity_type}/{entity_id}/entries-window` | Visitor | Articles inside one chart bucket |
| GET | `/api/entities/{entity_type}/{entity_id}/top-entries` | Visitor | The most important articles about it |
| POST | `/api/entities/{entity_type}/{entity_id}/ai-summary` | User | Write an AI summary and save it as the description |
| GET | `/api/entities/{entity_type}/{entity_id}/wikipedia/search` | User | Find candidate Wikipedia articles |
| POST | `/api/entities/{entity_type}/{entity_id}/wikipedia` | User | Attach a Wikipedia article |
| DELETE | `/api/entities/{entity_type}/{entity_id}/wikipedia` | User | Remove it and stop auto-attaching |
| GET | `/api/entities/{entity_type}/{entity_id}/target-sectors` | Visitor | Sectors an actor or malware is said to target, with the source of each claim |
| POST | `/api/entities/{entity_type}/{entity_id}/target-sectors` | User | Record an analyst claim that it targets a sector |
| DELETE | `/api/entities/{entity_type}/{entity_id}/target-sectors/{sector_ref}` | User | Withdraw a claim. The nightly rollup adds it back if its articles still say so |

`PUT /api/entities/sectors/{sector_id}` changes only `aliases` and `description`. Sectors can't be created, deleted, merged or converted.

#### Entity Merge & Deduplication

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| POST | `/api/entities/{entity_type}/merge` | Admin | Merge `merge_ids` into `keeper_id`: moves links and relationships, keeps old names as aliases, deletes the rest |
| POST | `/api/{threat-actors, malware, vendors, products, tools, offensive-tools}/{target_id}/merge` | Admin | Merge one `source_id` into the target. `mode: "shadow"` logs what would happen without doing it. Also takes `extra_aliases`, `new_description`. Logged |
| POST | `/api/entity-maintenance/reclassify` | Admin | Move an entity to another type, merging into an existing one or creating it |
| GET | `/api/entities/{entity_type}/duplicates` | User | Possible duplicates by name and alias |
| GET | `/api/entities/{entity_type}/merge-suggestions` | User | Ranked duplicate pairs with reasons |
| POST | `/api/entities/merge-suggestions/dismiss` | User | Never suggest this pair again |

`/api/offensive-tools/{target_id}/merge` is an older name for the tools merge and does the same thing.

#### Entity Profile Export (Markdown)

See [Export](#export): `GET /api/export/entities/{entity_type}/{entity_id}` and `POST /api/export/entities/bulk`.

#### Campaigns

A campaign groups the articles and entities about one operation.

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/api/campaigns` | User | Campaigns, most recently updated first, with counts |
| POST | `/api/campaigns` | User | Create one. Can start with `entry_ids` and a main entity |
| GET | `/api/campaigns/{campaign_id}` | User | One campaign |
| PUT, PATCH | `/api/campaigns/{campaign_id}` | User | Change the fields you send (both methods do the same) |
| DELETE | `/api/campaigns/{campaign_id}` | User | Delete it. Articles and entities stay |
| GET | `/api/campaigns/by-entry/{entry_id}` | User | Campaigns holding an article |
| GET | `/api/campaigns/by-entity/{entity_type}/{entity_id}` | User | Campaigns an entity belongs to |
| POST | `/api/campaigns/auto-detect` | User | Suggest new campaigns from story threads and entity clusters |
| GET | `/api/campaigns/source-options` | User | Which source kinds exist and which entity types can be followed |

#### Campaign Sub-Resources

All User.

| Method | Path | What it does |
| --- | --- | --- |
| POST | `/api/campaigns/{campaign_id}/entries` | Add an article (409 if already in) |
| POST | `/api/campaigns/{campaign_id}/entries/bulk` | Add several articles |
| DELETE | `/api/campaigns/{campaign_id}/entries/{entry_id}` | Remove an article |
| GET, POST | `/api/campaigns/{campaign_id}/entities` | List or link entities, with a role |
| DELETE | `/api/campaigns/{campaign_id}/entities/{entity_id}` | Unlink an entity |
| GET, POST | `/api/campaigns/{campaign_id}/countries` | List or link countries (`origin` or `target`) |
| GET | `/api/campaigns/{campaign_id}/countries/suggested` | Countries its articles mention |
| DELETE | `/api/campaigns/{campaign_id}/countries/{country_id}` | Unlink a country |
| GET, POST | `/api/campaigns/{campaign_id}/sectors` | List or add victim sectors |
| GET | `/api/campaigns/{campaign_id}/sectors/suggested` | Sectors its articles name |
| DELETE | `/api/campaigns/{campaign_id}/sectors/{sector_ref}` | Remove a sector |
| GET | `/api/campaigns/{campaign_id}/timeline` | Articles in date order |
| GET | `/api/campaigns/{campaign_id}/stats` | Summary numbers |
| GET | `/api/campaigns/{campaign_id}/attack-layer` | Its TTPs as a Navigator layer |
| GET | `/api/campaigns/{campaign_id}/detection-gaps` | Detection coverage for its techniques |
| GET | `/api/campaigns/{campaign_id}/export` | Everything as one JSON bundle |
| GET | `/api/campaigns/{campaign_id}/suggest` | Articles worth adding |
| GET, POST | `/api/campaigns/{campaign_id}/saved-searches` | List or link a saved search |
| PATCH, DELETE | `/api/campaigns/{campaign_id}/saved-searches/{css_id}` | Change or unlink it |
| POST | `/api/campaigns/{campaign_id}/saved-searches/{css_id}/sync` | Run it now |
| GET, POST | `/api/campaigns/{campaign_id}/sources` | List or add sources (below) |
| GET | `/api/campaigns/{campaign_id}/sources/suggested` | Sources it could follow |
| POST | `/api/campaigns/{campaign_id}/sources/preview` | What a source would add, without creating it |
| PATCH, DELETE | `/api/campaigns/{campaign_id}/sources/{source_id}` | Pause, change or stop a source. Articles already added stay |
| POST | `/api/campaigns/{campaign_id}/sources/{source_id}/sync` | Run one source now |

A linked saved search belongs to one analyst. Prefer a `query` source, which belongs to the campaign.

#### Campaign Sources

A source keeps pulling matching articles into the campaign. There are three kinds:

| `kind` | You send | It adds |
| --- | --- | --- |
| `entity` | `entity_type` + `ref_id` | Every article linked to that entity |
| `story` | `ref_id` (a thread id) | Every article in that story thread |
| `query` | `query` (see [query-language.md](query-language.md)) | Every article the query matches |

Each run works out the full set again and adds only what the campaign doesn't have yet, so articles that start matching later still arrive. The `sync-campaign-sources` job runs every 15 minutes. `auto_sync: false` pauses a source.

Preview request and answer:

```json
{ "kind": "query", "query": "malware:\"Akira\" AND date:>30d" }
```

```json
{
  "kind": "query", "entity_type": null, "ref_id": null,
  "query": "malware:\"Akira\" AND date:>30d", "label": "malware:\"Akira\" AND date:>30d",
  "would_add": 47, "already_held": 3,
  "preview": [{ "entry_id": "...", "title": "...", "published_at": "..." }],
  "error": null, "unknown_fields": []
}
```

A query that doesn't parse comes back in `error` (not as a 4xx), because the UI previews as you type. `unknown_fields` lists field names the query language doesn't know (say `actor:` instead of `threat_actor:`); they become plain text search terms. Creating a source refuses a query that doesn't parse, a `query` source with a `ref_id`, any other kind without one, and an `entity_type` that has no articles.

#### Entity Relationships

Typed, directed links between entities, such as "APT29 *uses* Cozybot". Each has:

- **`relationship_type`:** `uses`, `exploits`, `targets`, `attributed_to`, `variant_of`, `communicates_with`, `delivers`, `drops`, `hosts`, `related_to`. Only sensible pairs are allowed (`backend/app/intelligence/relationship_matrix.py`).
- **`confidence`:** `confirmed`, `probable` or `possible`.
- **`source`:** where it came from: `co_occurrence`, `auto_extracted`, `external_feed`, `analyst_created`, `analyst_confirmed` or `analyst_rejected`. Rejected ones are kept but hidden, so new articles can't bring them back.
- **`evidence_entry_ids`:** the articles that back it.

Entity types: `ttp`, `cve`, `threat_actor`, `malware`, `campaign`, `country`, `tool`, `vendor`, `product`, `mitigation`. Lifecycle diagram: [entity-relationship-lifecycle.md](diagrams/entity-relationship-lifecycle.md).

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/api/entity-relationships` | Visitor | Paginated list. `entity_type` + `entity_id`, `relationship_type`, `include_rejected` |
| GET | `/api/entity-relationships/by-entity/{entity_type}/{entity_id}` | Visitor | Every relationship for one entity |
| GET | `/api/entity-relationships/claims/{entity_type}/{entity_id}` | User | Which enrichment sources claim each of the entity's connections (`by_target`, keyed `<type>-<id>`), linked claims per source (`sources`), and the names its sources gave that matched no entity or several (`held`, `held_count`) |
| POST | `/api/entity-relationships/signals/{entity_type}` | Visitor | Body `{"ids": [...]}`: per id, the count and top 3 relationships. A POST because the id list is too long for a URL |
| POST | `/api/entity-relationships` | User | Create one. Creating an existing one merges the evidence (200 instead of 201); re-creating a rejected one restores it |
| PUT | `/api/entity-relationships/{relationship_id}` | User | Change verb, confidence, description or evidence |
| POST | `/api/entity-relationships/{relationship_id}/confirm` | User | Mark it analyst-confirmed |
| POST | `/api/entity-relationships/{relationship_id}/reject` | User | Mark it rejected (hidden, not deleted) |
| DELETE | `/api/entity-relationships/{relationship_id}` | User | Delete it. Prefer reject: after a delete, new articles can create it again |

#### Entity Links

The links between articles and entities that the autolinker and extraction create.

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/api/entity-links` | Visitor | Every link, newest first |
| GET | `/api/entity-links/stats` | User | Totals by type and source, and the held-match queue size |
| DELETE | `/api/entity-links/{entity_type}/{entity_id}/{entry_id}` | User | Remove one link |
| POST | `/api/entity-links/bulk-unlink` | User | Remove up to 500 links |
| POST | `/api/false-positives` | User | Report a wrong match (this article, this alias, this entity or this word) |

#### Correlation, Pivot & Graph

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/api/intelligence/pivot/{entity_type}/{entity_id}` | Visitor | Related entities through shared articles, scored by how close they appear |
| GET | `/api/intelligence/graph/{entity_type}/{entity_id}` | Visitor | Graph of nodes and edges |
| GET | `/api/intelligence/entry-graph/{entry_id}` | Visitor | Graph of every entity in one article |
| GET | `/api/intelligence/timeline/{entity_type}/{entity_id}` | Visitor | Activity over time |
| DELETE | `/api/intelligence/timeline/{entity_type}/{entity_id}` | Admin | Clear the entity's correlation events |
| DELETE | `/api/intelligence/related/{entity_type}/{entity_id}/{other_type}/{other_id}` | User | Unlink `other` from every article it shares with `entity` |
| GET | `/api/intelligence/search` | User | Name search across all entity types |
| GET | `/api/intelligence/temporal-clusters` | Visitor | Articles from different feeds close in time that share entities |
| GET | `/api/intelligence/events` | User | Correlation events (new cross-source matches) |
| GET | `/api/intelligence/events/grouped` | Visitor | Events grouped by article |
| GET | `/api/intelligence/events/unread-count` | User | Unread event count |
| PUT | `/api/intelligence/events/{event_id}/read` | User | Mark one read |
| PUT | `/api/intelligence/events/read-all` | User | Mark all read |
| POST | `/api/intelligence/detection-summary` | User | AI detection summary for some articles |
| GET, POST | `/api/intelligence/detection-summaries` | User | List or create saved summaries |
| GET | `/api/intelligence/detection-summaries/{summary_id}` | User | One saved summary |
| DELETE | `/api/intelligence/detection-summaries/{summary_id}` | Owner | Delete one |
| GET | `/api/intelligence/watchlist` | User | Your watched, muted and stack entities |
| PUT | `/api/intelligence/watchlist` | User | Add or change a watch |
| DELETE | `/api/intelligence/watchlist/{entity_type}/{entity_id}` | User | Remove a watch |
| GET | `/api/intelligence/feed` | User or `X-API-Key` | Paginated feed of CVEs, TTPs, actors and malware for outside tools |

A watch on a sector or entity boosts its articles in the Priority Queue.

#### Entity Notes

Notes on an entity (article notes are under [Notes, Tags & Comments](#notes-tags--comments)).

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/api/entity-notes` | User | Notes on one entity (`entity_type`, `entity_id`), newest first |
| GET | `/api/entity-notes/search` | User | Search all entity notes by text, tag, type or entity type |
| POST | `/api/entity-notes` | User | Add a note (`entity_type`, `entity_id`, `title`, `content`, `note_type`, `tags`) |
| PUT | `/api/entity-notes/{note_id}` | Owner | Edit a note |
| DELETE | `/api/entity-notes/{note_id}` | Owner | Delete a note |

#### Cleanup Queues (Admin)

Proposed fixes to entity data wait in review queues. Every route here is Admin. See [engine.md](engine.md) for the adjudicate stage that files most proposals.

| Method | Path | What it does |
| --- | --- | --- |
| GET | `/api/admin/hygiene/feed` | Every proposal from both logs, newest first (`entity_type` + `entity_id` narrow it to one entity). `context=true` adds each row's article text around the match (at most 320 characters); the Review tab asks for it on one entity's rows |
| GET | `/api/admin/hygiene/review-groups` | Every pending proposal, one row per entity, with what each kind wants done |
| POST | `/api/admin/hygiene/decisions` | Decide many proposals in one call: `[{id: "<source>:<log_id>", decision: "apply" \| "dismiss" \| "reclassify:<type>"}]`, one result per row. A row an earlier decision already closed comes back `settled`; an apply with nothing left to do comes back `resolved` |
| POST | `/api/admin/hygiene/review-groups/dismiss` | Settle each entity's row the leave-it-alone way and stop the proposals coming back |
| POST | `/api/admin/hygiene/scan-duplicates` | Run the duplicate review now; its Merge proposals land in the queue |
| GET | `/api/admin/hygiene/stats` | Queue counts and the adjudicate stage's mode |
| DELETE | `/api/admin/hygiene/feed/{source}/{row_id}` | Delete one proposal row |
| POST | `/api/admin/hygiene/dismiss-proposals` | Discard pending proposals without applying them |
| POST | `/api/admin/hygiene/adjudication/{log_id}/apply` | Apply one adjudicate-stage proposal |
| POST | `/api/admin/hygiene/adjudication/{log_id}/restore` | Undo an applied one |
| POST | `/api/admin/hygiene/adjudication/apply-all` | Apply up to `limit` pending proposals now |
| POST | `/api/admin/hygiene/bulk-apply` | Apply a whole queue in the background |
| GET | `/api/admin/hygiene/bulk-apply/{job_id}` | Progress of that job |
| GET | `/api/admin/hygiene/reclassify-groups` | Pending type changes, one row per entity |
| POST | `/api/admin/hygiene/reclassify-groups/apply` | Convert each entity to its proposed type |
| POST | `/api/admin/hygiene/reclassify-groups/dismiss` | Drop those proposals and stop new ones |
| POST | `/api/admin/hygiene/apply-reclassify-advisories` | Turn advisory type changes into real proposals |
| GET | `/api/admin/hygiene/unlink-groups` | Pending link removals, one row per entity |
| GET | `/api/admin/hygiene/unlink-groups/rows` | The articles behind one entity's removals |
| POST | `/api/admin/hygiene/unlink-groups/apply` | Remove those links |
| POST | `/api/admin/hygiene/unlink-groups/keep` | Keep the links and clear the proposals |
| POST | `/api/admin/hygiene/link-log/{log_id}/restore` | Put back a removed link |
| POST | `/api/admin/hygiene/link-log/{log_id}/apply-removal` | Carry out a proposed link removal |
| GET | `/api/admin/hygiene/orphans` | Entities with no articles |
| POST | `/api/admin/hygiene/orphans/prune` | Delete them |
| POST | `/api/admin/hygiene/enrichment-gaps/enrich` | Have the AI research and fill one field |
| POST | `/api/admin/hygiene/run-name-normalization` | Start the AI name check |
| POST | `/api/admin/hygiene/normalize-name/{log_id}/apply` | Apply one rename or merge |
| POST | `/api/admin/hygiene/scan-alias-hygiene` | Find duplicate aliases |
| POST | `/api/admin/hygiene/alias-collision/{log_id}/apply` | Remove the clashing alias |
| POST | `/api/admin/hygiene/scan-vendor-autolink` | Propose vendors for products with none |
| POST | `/api/admin/hygiene/vendor-autolink/{log_id}/apply` | Set the proposed vendor |
| POST | `/api/admin/hygiene/scan-id-hygiene` | Find malformed TTP and CVE ids, CVE ids that can't be real (sequence too long or zero-padded), and withdrawn CVEs |
| POST | `/api/admin/hygiene/id-hygiene/{log_id}/apply` | Apply one id fix |

#### AI-Created Entities (Admin)

| Method | Path | What it does |
| --- | --- | --- |
| GET | `/api/engine/extraction/stats` | Totals for entities the AI created: by type, needing review, orphaned, likely duplicates |
| GET | `/api/engine/extraction/entities` | List them with a status (linked, review, orphan, dupe) |
| POST | `/api/engine/extraction/confirm` | Sign off on them |
| POST | `/api/engine/extraction/not-duplicate` | Mark two entities as different things |
| POST | `/api/engine/extraction/delete` | Delete entities (AI-created types plus vendor, product, country) with their links, relationships and pending proposals; unless `deny=false`, ban their names (countries are never banned) |
| GET, POST | `/api/engine/extraction/denylist` | List or add banned names (`entity_type: "any"` bans for every type) |
| DELETE | `/api/engine/extraction/denylist/{row_id}` | Lift a ban |

---

### Intelligence Requirements (PIRs)

Priority Intelligence Requirements are standing questions. New articles are matched against their keywords, feeds and entities. All User.

| Method | Path | What it does |
| --- | --- | --- |
| GET | `/api/requirements` | List, most recently updated first |
| POST | `/api/requirements` | Create one |
| GET | `/api/requirements/coverage` | Counts by status, priority, category and staleness |
| GET | `/api/requirements/{requirement_id}` | One requirement |
| PATCH | `/api/requirements/{requirement_id}` | Change it. Removing a keyword or entity also removes its matches |
| DELETE | `/api/requirements/{requirement_id}` | Delete it and its matches |
| GET | `/api/requirements/{requirement_id}/matches` | Matched articles |
| POST | `/api/requirements/{requirement_id}/match` | Match an article by hand |
| DELETE | `/api/requirements/{requirement_id}/matches/{entry_id}` | Remove a match |
| POST | `/api/requirements/{requirement_id}/fulfill` | Mark fulfilled, optionally with the report that answered it |
| GET | `/api/requirements/{requirement_id}/entities` | Entities found in the matched articles |

---

### Automation & Rules

#### Automation Rules

A rule runs actions (tag, alert, run AI, call a webhook) when its trigger fires. See [automation-ai-enrichment.md](automation-ai-enrichment.md).

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/api/automation/rules` | User | List rules, newest first (`label` filter) |
| POST | `/api/automation/rules` | User | Create a rule |
| GET | `/api/automation/rules/{rule_id}` | User | One rule. Webhook URLs and headers are hidden unless you own it or are admin |
| PUT | `/api/automation/rules/{rule_id}` | Owner | Change the fields you send |
| DELETE | `/api/automation/rules/{rule_id}` | Owner | Delete a rule |
| POST | `/api/automation/rules/{rule_id}/toggle` | Owner | Turn it on or off |
| POST | `/api/automation/rules/{rule_id}/test` | Owner | Dry run against one article (`?entry_id=`). Saves nothing |
| POST | `/api/automation/rules/{rule_id}/run` | Owner | Run it now against recent articles |
| GET | `/api/automation/rules/{rule_id}/logs` | User | That rule's run history |
| GET | `/api/automation/logs` | User | All run history |
| DELETE | `/api/automation/logs` | Admin | Clear all run history |
| GET | `/api/automation/rules/export` | User | All rules as portable JSON |
| GET | `/api/automation/rules/export/{rule_id}` | User | One rule as portable JSON |
| POST | `/api/automation/rules/import` | User | Import exported rules. A rule with the same name is overwritten only if it is yours (an admin overwrites any) |
| GET | `/api/automation/templates` | User | Ready-made rule templates |
| GET | `/api/automation/variable-contexts` | User | Template variables each action provides |

Create request:

```json
{
  "name": "Flag LockBit coverage",
  "trigger_type": "on_keyword_match",
  "trigger_config": { "keywords": ["LockBit"], "match_fields": ["title", "content"] },
  "conditions": {},
  "actions": [
    { "type": "add_tags", "config": { "tags": ["ransomware"] } },
    { "type": "mark_priority", "config": {} }
  ],
  "labels": ["ransomware"],
  "is_enabled": true
}
```

`trigger_type` is one of `on_new_entry`, `on_schedule`, `on_keyword_match`, `on_cve_detected`, `on_manual`, `on_correlation_event`, `on_entry_scored`, `on_observable_captured`.

#### Webhook Presets

A preset is a saved URL, payload and headers that rule actions can reuse.

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/api/webhook-presets` | User | List presets (optional type filter) |
| POST | `/api/webhook-presets` | User | Create one |
| GET | `/api/webhook-presets/{preset_id}` | User | One preset |
| PUT | `/api/webhook-presets/{preset_id}` | Owner | Change it |
| DELETE | `/api/webhook-presets/{preset_id}` | Owner | Delete it |

#### Job Schedules

Background jobs (feed fetching, enrichment, cleanup) and their schedules. All Admin.

| Method | Path | What it does |
| --- | --- | --- |
| GET | `/api/job-schedules` | Every job and its schedule, with its last 30 days of runs (`runs_30d`, `ok_30d`) and how its last run ended (`last_status`, `last_error`, `last_run_at`). A job an enrichment source owns carries `source` and `source_label` |
| PATCH | `/api/job-schedules/{job_name}` | Change a job's schedule or turn it off |
| DELETE | `/api/job-schedules/{job_name}` | Go back to the default schedule |
| POST | `/api/job-schedules/{job_name}/run` | Run it now |

---

### Dashboards & Widgets

#### Dashboards

Dashboards are private. Another user's board is invisible and returns 404.

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/api/dashboards` | Visitor | Your dashboards with their widgets |
| POST | `/api/dashboards` | User | Create one. `is_default: true` unsets your other default |
| POST | `/api/dashboards/seed-defaults` | User | Give a user with no boards the default set (from `backend/app/dashboard_defaults.py`). Does nothing if you already have a board |
| PUT | `/api/dashboards/reorder` | User | Save the tab order |
| GET | `/api/dashboards/{dashboard_id}` | Visitor | One dashboard |
| PUT | `/api/dashboards/{dashboard_id}` | User | Rename it or make it the default |
| DELETE | `/api/dashboards/{dashboard_id}` | User | Delete it and its widgets |

#### Widgets

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| POST | `/api/dashboards/{dashboard_id}/widgets` | User | Add a widget at a grid position |
| PUT | `/api/dashboards/{dashboard_id}/widgets/{widget_id}` | User | Change title, config, position or size |
| DELETE | `/api/dashboards/{dashboard_id}/widgets/{widget_id}` | User | Remove a widget |
| PUT | `/api/dashboards/{dashboard_id}/layout` | User | Save every widget's position and size at once |

#### Widget Data Endpoints

Each widget reads one `GET /api/widgets/<name>` endpoint. All are read-only.

- **Visitor:** `feed-activity`, `cve-severity`, `threat-timeline`, `trending-cves`, `new-cves`, `attack-heatmap`, `stats`, `new-actors`, `correlation-events`, `overview`, `kev-deadlines`, `triage-flow`, `under-reported`, `kev-matches`, `trending-vendors`, `trending-products`, `targeted-countries`, `weekly-recap`, `actor-activity`, `hot-correlations`, `triage-queue-stats`, `top-tags`
- **User:** `detection-coverage`, `new-detections`, `automation-logs`, `watchlist-pulse`, `ransomware-pulse`, `rules-attention`, `targeting-grid`, `campaign-momentum`, `morning-briefing`, `relationship-inbox`, `playbook-drift`, `detection-format-breakdown`, `attack-coverage-gap`, `active-campaigns`, `feed-health`, `worker-queue`, `ai-usage`, `saved-search-hits`, `telegram-mentions`

---

### Detection Rules & Tools

#### Detection Rule Management

All User unless marked. See [detection-engineering.md](detection-engineering.md).

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/api/detection-rules` | User | Paginated rule list (no rule bodies) |
| GET | `/api/detection-rules/search` | User | The rule library: search plus facet counts in one call. See below |
| GET | `/api/detection-rules/facets` | User | Facet counts for the library rail |
| GET | `/api/detection-rules/telemetry-vocabulary` | User | Telemetry values split into `collected` and `missing` by your telemetry inventory |
| GET | `/api/detection-rules/coverage-board` | User | Trending entities and how many rules cover each |
| GET | `/api/detection-rules/needing-review` | User | Rules whose techniques have new intel |
| POST | `/api/detection-rules` | User | Create a rule. Metadata is read from the rule text where you leave it blank |
| GET | `/api/detection-rules/{rule_id}` | User | One rule with its content |
| PUT | `/api/detection-rules/{rule_id}` | User | Change the fields you send |
| DELETE | `/api/detection-rules/{rule_id}` | User | Delete a rule and its versions |
| PATCH | `/api/detection-rules/{rule_id}/status` | User | Set `is_draft` |
| POST | `/api/detection-rules/validate` | User | Check syntax without saving |
| POST | `/api/detection-rules/extract-metadata` | User | Read title, log source and ATT&CK ids from rule text |
| POST | `/api/detection-rules/{rule_id}/convert` | User | AI-convert to another rule language |
| GET | `/api/detection-rules/{rule_id}/conversions` | User | Rules converted from this one |
| POST | `/api/detection-rules/{rule_id}/extend` | User | Make a draft copy to build on |
| POST | `/api/detection-rules/chat` | User | Streaming AI help with a rule |
| GET | `/api/detection-rules/{rule_id}/versions` | User | Saved versions, newest first |
| GET | `/api/detection-rules/{rule_id}/versions/{version_id}` | User | One version |
| POST | `/api/detection-rules/{rule_id}/versions/{version_id}/rollback` | User | Restore a version (the current text is saved first) |
| GET | `/api/detection-rules/{rule_id}/diff` | User | Diff two versions, or a version and now |
| GET | `/api/detection-rules/{rule_id}/provenance` | User | The intel chain behind the rule |
| GET | `/api/detection-rules/{rule_id}/fresh-intel` | User | Articles on its CVEs and techniques since it was last edited |
| GET | `/api/detection-rules/{rule_id}/related` | User | Rules sharing a CVE or technique, other formats, near-copies |
| GET | `/api/detection-rules/{rule_id}/commits` | User | Commit history for a rule from a GitHub repo |
| POST | `/api/detection-rules/bulk-update` | User | Set draft status or add and remove tags on many rules |
| POST | `/api/detection-rules/bulk-delete` | Admin | Delete many rules |
| DELETE | `/api/intelligence/detection-rules` | Admin | Delete every rule |
| POST | `/api/detection-rules/import` | User | Import Sigma rules from YAML or a ZIP |
| GET | `/api/detection-rules/export` | User | Export rules as YAML or ZIP |
| POST | `/api/intelligence/entities/{entity_type}/{entity_id}/generate-rules` | User | AI-written rules for an actor, malware, CVE or TTP |

Rule formats (`rule_type`): `sigma`, `splunk_spl`, `crowdstrike_ql`, `elastic_ql`, `kql`, `snort_suricata`, `yara`, `nuclei`, `panther`.

**Rule library search** (`GET /api/detection-rules/search`) ranks by relevance, tolerates typos and returns facet counts for the current filters.

| Param | Repeatable | Notes |
|-------|-----------|-------|
| `q` | | Text to search; empty matches all |
| `scope` | | What `q` searches: `metadata`, `content` or `both` (default) |
| `rule_type`, `severity`, `license`, `tag` | yes | The rule's own fields |
| `source_repo`, `source_author` | yes | Where it came from upstream |
| `tactic`, `technique` | yes | ATT&CK tactics and technique ids |
| `data_source` | yes | The rule's `data_sources` values |
| `telemetry_token` | yes | Telemetry the rule needs, across every format |
| `actor`, `malware`, `tool`, `vendor`, `product` | yes | Entities from the rule's source article |
| `is_draft`, `authored_local` | | `authored_local=true` means written here, not imported |
| `telemetry` | | `covered` (you collect everything it needs) or `missing` (you lack at least one source) |
| `created_after` | | ISO timestamp |
| `sort_by` | | `relevance`, `title`, `rule_type`, `severity`, `is_draft`, `created_at` (default), `updated_at`, `upstream_updated_at` |
| `sort_order` | | `asc` or `desc` (default) |
| `limit`, `offset` | | `limit` default 100, max 500 |

Values within one parameter are ORed; different parameters are ANDed. Each facet is counted with every filter except its own, so ticking "sigma" still shows the other formats. `total` is exact. Returns 503 `rule_search_unavailable` if Meilisearch is down.

#### Detection Coverage

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| POST | `/api/intelligence/detection-coverage` | User | Sort techniques into `covered` (a rule exists and your telemetry can feed it), `library_only` (a rule exists but you lack the telemetry) or `no_rule` |
| GET | `/api/analytics/detection-coverage` | User | Observed TTPs versus rules |
| GET | `/api/telemetry-sources` | User | Your telemetry inventory (the log sources you collect) |
| POST | `/api/telemetry-sources` | User | Add a source |
| PUT | `/api/telemetry-sources/{source_id}` | User | Change a source |
| DELETE | `/api/telemetry-sources/{source_id}` | User | Remove a source |
| POST | `/api/telemetry-sources/check-feasibility` | User | Which data sources your inventory covers |
| GET | `/api/telemetry-sources/telemetry-gaps` | User | Rules that need sources you don't have |
| GET | `/api/telemetry-sources/taxonomy` | User | The older data-source list for the picker |
| GET | `/api/telemetry-sources/catalog` | User | The ready-made data-source catalog |
| POST | `/api/telemetry-sources/sync` | Admin | Save catalog selections as sources |

#### Threats Board & Coverage Workspace

All User.

| Method | Path | What it does |
| --- | --- | --- |
| GET | `/api/threat-board` | Threats and vulnerabilities ranked over a window |
| GET | `/api/threat-board/windows` | The windows the board offers |
| GET | `/api/threat-board/precedent` | Past stories shaped like this one |
| GET | `/api/threat-board/{entity_type}/{entity_key}/rules` | Rules that match a board row |
| PUT | `/api/threat-board/{entity_type}/{entity_key}/state` | Mark a row `open`, `handled` or `muted` |
| GET | `/api/coverage-workspace/{entity_type}/{entity_key}` | Articles and behaviours for one threat |
| GET | `/api/coverage-workspace/{entity_type}/{entity_key}/behaviours/{technique_id}/rules` | Rules for one behaviour |
| GET, POST | `/api/coverage-workspace/{entity_type}/{entity_key}/sets` | List or save rule sets for the threat |
| POST | `/api/coverage-workspace/sets/{summary_id}/export` | Export a set |
| GET | `/api/coverage-workspace/sets/{summary_id}/export.zip` | A set as a ZIP, one file per rule |
| GET | `/api/coverage-workspace/windows` | The windows the workspace offers |

#### Tools (Registry Execution)

The tool registry behind the skill CLIs and the MCP server.

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| POST | `/api/tools/execute` | User or agent token (admin for `ADMIN_TOOLS`) | Run a tool: `{"tool_name": "search_entries", "args": {"query": "LockBit", "limit": 5}}`. Returns `{"result": "<JSON string>"}` |
| GET | `/api/tools/tools` | User or agent token | Every tool's name, description and argument schema |

Tools in `ADMIN_TOOLS` (`backend/app/tools/__init__.py`) need an admin, the same as their API routes. An agent token may only run read tools.

---

### AI & Enrichment

#### AI Providers

A provider is a connection to an AI service (Ollama, Claude, an OpenAI-compatible server). A provider does nothing until a task is assigned to it.

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/api/ai/providers` | User | The instance's providers plus your own personal keys |
| POST | `/api/ai/providers` | User (admin for instance providers) | Add a provider. `?test=true` checks it first and saves only if it answers (400 `provider_unreachable` otherwise) |
| PUT | `/api/ai/providers/{provider_id}` | User | Change an instance provider (admin) or your own key. On someone else's key an admin may only set `is_active` |
| DELETE | `/api/ai/providers/{provider_id}` | User | Delete your own key; an admin may delete any |
| POST | `/api/ai/providers/{provider_id}/test` | User | Health check and model list. Another person's key returns 404, even for an admin |
| POST | `/api/ai/providers/{provider_id}/resume` | User | Clear an automatic pause (after quota errors) |
| POST | `/api/ai/providers/{provider_id}/commission` | Admin | Test a provider and point the AI tasks at it in one step |
| GET | `/api/ai/providers/user-keys` | Admin | Every personal key with its owner (keys themselves are never returned) |

Non-admins may add a personal key only when the admin has turned on `allow_user_ai_providers`. The type must be one the admin allows, never `claude_code`, and it may not point at a private address unless the admin allows that.

#### Personal AI (`/api/ai/me`)

What Settings > My AI reads and writes. All User.

| Method | Path | What it does |
| --- | --- | --- |
| GET | `/api/ai/me/policy` | The admin's personal-key policy and whether you have any routes |
| GET | `/api/ai/me/overview` | Policy, your fallback and cap, your spend this month and today, and where each task would run right now (`will_run_on`: `user`, `site` or `refused`) |
| PATCH | `/api/ai/me/preferences` | `fallback_to_site` (let the instance answer when your key can't) and `monthly_cap_usd` (null removes it) |
| GET | `/api/ai/me/routes` | Your default key first, then per-task routes |
| PUT | `/api/ai/me/routes` | `{task_id, provider_id, model_name, config}`. `task_id: null` sets your default key. 400 `task_site_only` for a task closed to personal keys |
| DELETE | `/api/ai/me/routes/{route_id}` | Remove a route |

#### AI Tasks

A task is one AI job (summarise an article, extract entities, write a report section).

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/api/ai/tasks` | User | All tasks. Old tasks hidden unless `include_deprecated` |
| POST | `/api/ai/tasks` | Admin | Create a custom task (409 if the name exists) |
| PATCH | `/api/ai/tasks/{task_id}` | Admin | Change how it shows in the reader and its output schema |
| DELETE | `/api/ai/tasks/{task_id}` | Admin | Delete a custom task. 403 for a built-in task, 409 `task_has_results` if it has results |
| GET | `/api/ai/tasks/assignments/all` | User | Every task's provider and model |
| GET | `/api/ai/tasks/{task_id}/assignments` | User | One task's provider and model, or null |
| PUT | `/api/ai/tasks/{task_id}/assignments` | Admin | Set which provider and model run a task |

#### AI Prompts

Prompts can also be edited at Settings > AI Configuration.

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/api/ai/prompts` | User | Every saved prompt override |
| GET | `/api/ai/prompts/{task_id}` | User | The prompt in use for a task |
| PUT | `/api/ai/prompts/{task_id}` | Admin | Save a new version |
| POST | `/api/ai/prompts/{task_id}/reset` | Admin | Go back to the built-in prompt (history is kept) |
| POST | `/api/ai/prompts/{task_id}/preview` | User | Fill the template with sample data, without running it |
| GET | `/api/ai/prompts/{task_id}/history` | User | Every saved version |

#### AI Results & Cost Dashboard

AI results are saved per target. `target_type` is, for example, `entry`, `daily_summary` or an entity type.

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/api/ai/results/{target_type}/{target_id}` | User | All current results for a target |
| GET | `/api/ai/results/{target_type}/{target_id}/{task_name}` | User | The current result for one task |
| GET | `/api/ai/results/{target_type}/{target_id}/{task_name}/history` | User | Every run, current and old |
| POST | `/api/ai/results/{target_type}/{target_id}/run` | User | Run a task on the target |
| POST | `/api/ai/run-text` | User | Run a task on text you send (nothing is saved to a target) |
| GET | `/api/ai/cost-breakdown` | Admin | Last 30 days of spend by task, by model and by who asked, with budgets |
| GET | `/api/ai/cost-summary` | Admin | Last 30 days in total: cost, requests, tokens |

#### AI Copilot (Global)

The copilot is the chat assistant that looks up platform data and proposes changes you confirm. See [copilot.md](copilot.md).

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/api/ai/copilot/config` | User | Which provider would answer you, and why a turn would be refused |
| POST | `/api/ai/copilot/stream` | User | Stream an answer over SSE. Each turn is saved to a conversation |
| POST | `/api/ai/copilot/confirm` | User | Run or cancel a tool call the copilot staged for you to confirm |
| GET | `/api/ai/conversations/` | User | Your conversations (no message bodies) |
| POST | `/api/ai/conversations/` | User | Start one |
| GET | `/api/ai/conversations/{conversation_id}` | User | One conversation with its messages |
| PATCH | `/api/ai/conversations/{conversation_id}` | User | Rename it or add messages |
| DELETE | `/api/ai/conversations/{conversation_id}` | User | Delete it |
| POST | `/api/ai/conversations/{conversation_id}/share` | User | Make a read-only public link (read at `GET /api/shared/copilot/{token}`) |
| DELETE | `/api/ai/conversations/{conversation_id}/share` | User | Revoke the link |

The copilot's Claude sign-in, for the `claude_code` provider (all Admin): `GET /api/ai/copilot-auth/status`, `POST /api/ai/copilot-auth/refresh`, `POST /api/ai/copilot-auth/start`, `GET /api/ai/copilot-auth/session/{session_id}`, `POST /api/ai/copilot-auth/session/{session_id}/code`, `POST /api/ai/copilot-auth/session/{session_id}/cancel`.

#### Enrichment

Enrichment fills in entity details from outside sources (NVD, EPSS, CISA KEV, Malpedia and others).

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/api/enrichment/sources` | User | Every source with what it needs and what it covers |
| PUT | `/api/enrichment/sources/{source_id}` | Admin | Turn a source on or off; change its trigger, rate limits or budget |
| GET | `/api/enrichment/sources/{source_id}/health` | User | Its current health |
| GET | `/api/enrichment/console` | Admin | Every source's status, what it fills and sends out, its key, the problems with one action each, and a 24-hour summary (`?entity_type=` narrows the list) |
| GET | `/api/enrichment/sources/{source_type}/detail` | Admin | One source's limits (rate, refresh interval, requests at once), 24-hour requests, queue (with why rows are waiting), fill rates, backfill gap, jobs and the settings its form edits |
| POST | `/api/enrichment/sources/{source_type}/backfill` | Admin | Queue backfill lookups for entities missing the source's first column (`entity_type`, `limit`) |
| GET | `/api/enrichment/coverage` | Admin | How full each field a source fills is, who fills it, and a backfill or AI research to fill the rest |
| GET | `/api/enrichment/activity` | Admin | The queue by lane, the lookups that gave up, and requests by source over 24 hours |
| POST | `/api/enrichment/retry` | Admin | Queue the lookups that gave up again (`?source_type=` optional) |
| POST | `/api/enrichment/pause` | Admin | Pause or resume every request to outside sources (`{"paused": true}`) |
| GET | `/api/enrichment/keys` | Admin | One row per API key: the sources it serves, whether it's set, missing, optional or rejected, and whether you have your own |
| PUT | `/api/enrichment/keys/{id}` | Admin | Set or remove a shared key (`{"api_key": "…"}`) |
| PUT | `/api/enrichment/keys/{id}/mine` | Admin | Set or remove your own key, used for the lookups you start |
| POST | `/api/enrichment/keys/{id}/test` | Admin | Test the shared key |
| POST | `/api/enrichment/enrich` | User | Enrich one entity now (`entity_type`, `entity_id`, optional `source_types`, `refresh`, and `lane`, which can only be `manual`); sources that refused are queued in the `manual` lane to retry and listed in `queued`. A ransomware victim is looked up by its domain |

---

### Reports, Profiles & Exposure

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/api/intel-profiles` | User | Intel profiles (named scopes of regions, sectors and a time window), shared across the install |
| POST | `/api/intel-profiles` | User | Create one |
| GET | `/api/intel-profiles/sector-vocabulary` | User | The sector list for pickers |
| GET | `/api/intel-profiles/{profile_id}` | User | One profile |
| PUT | `/api/intel-profiles/{profile_id}` | Owner | Change it |
| DELETE | `/api/intel-profiles/{profile_id}` | Owner | Delete it. Reports built from it keep their copy |
| GET | `/api/intel-profiles/{profile_id}/surface` | User | Actors and malware active against its regions and sectors, with the evidence |
| POST | `/api/intel-profiles/surface-preview` | User | The same for a scope you haven't saved |
| GET | `/api/intel-reports` | User | Reports, filtered by status and template |
| POST | `/api/intel-reports` | User | Create a report |
| GET | `/api/intel-reports/{report_id}` | User | One report |
| PUT | `/api/intel-reports/{report_id}` | User | Change it. A content change saves the old content as a version |
| DELETE | `/api/intel-reports/{report_id}` | Owner | Delete a draft. Published and archived reports can't be deleted |
| GET | `/api/intel-reports/{report_id}/versions` | User | Version history |
| GET | `/api/intel-reports/{report_id}/export` | User | Export in a chosen format |
| POST | `/api/intel-reports/{report_id}/publish` | User | Publish (bumps the version) |
| POST | `/api/intel-reports/{report_id}/archive` | User | Archive |
| POST | `/api/intel-reports/{report_id}/clone` | User | Copy with a different template |
| POST | `/api/intel-reports/{report_id}/attach` | User | Add articles and entities to a draft |
| POST | `/api/intel-reports/{report_id}/regenerate` | User | Rewrite all AI sections |
| POST | `/api/intel-reports/{report_id}/sections/{section_name}/generate` | User | Write one section with AI |
| POST | `/api/intel-reports/generate` | User | New report filled from a template and entities |
| POST | `/api/intel-reports/generate-full` | User | Full AI report from source material |
| POST | `/api/intel-reports/generate-from-campaign` | User | Full AI report from a campaign |
| POST | `/api/intel-reports/generate-exposure` | User | Threat Exposure Report from an intel profile |
| GET, POST | `/api/intel-reports/templates` | User | List or create templates |
| PUT, DELETE | `/api/intel-reports/templates/{template_id}` | Owner | Change or delete a custom template (built-in ones are fixed) |
| POST | `/api/intel-reports/templates/{template_id}/clone` | User | Copy a template |
| GET | `/api/intelligence/exposure` | User | CVEs affecting your vendor and product stack, ranked, with detection status |
| GET | `/api/ransomware/disclosures` | User | Newest ransomware leak-site victim posts |
| GET | `/api/ransomware/stats` | User | Totals for the ransomware dashboard |
| GET | `/api/ransomware/victims/{victim_id}` | User | One victim's posts and details |
| GET | `/api/ransomware/groups/{actor_id}/victims` | User | Victims listed by one group |
| GET | `/api/ransomware/groups/{actor_id}/victims/stats` | User | That group's victim counts and trend |

---

### Search

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| POST | `/api/search/unified` | User | The main search: articles and entities in one call. See below |
| GET | `/api/search` | User | Article search in Meilisearch |
| POST | `/api/search/advanced` | User | Same as `GET /api/search`, with a JSON body |
| GET | `/api/search/facets` | User | Facet counts for a query |
| GET | `/api/search/autocomplete` | User | Suggestions for the search box |
| GET | `/api/search/entities` | User | Entity search in Meilisearch |
| POST | `/api/search/entities/sync` | Admin | Rebuild the entity index |
| POST | `/api/search/rebuild` | Admin | Rebuild the article index |
| GET | `/api/saved-searches` | User | Your saved searches with unread and total counts (cached 10 minutes) |
| POST | `/api/saved-searches` | User | Save a search |
| PUT | `/api/saved-searches/{search_id}` | Owner | Change it |
| DELETE | `/api/saved-searches/{search_id}` | Owner | Delete it |

`GET /api/search` takes `q`, `feed_id`, `category_id`, `feed_type`, `tags` (all repeatable), `date_from`, `date_to`, `is_read`, `is_starred`, `is_bookmarked`, `has_notes`, `media_type`, `sort` (`relevance`, `newest`, `oldest`, `title_asc`, `title_desc`), `limit` (default 20, max 500), `offset`.

**Unified search** (`POST /api/search/unified`) runs the full [query language](query-language.md). Text and indexed filters go to Meilisearch, some filters go to PostgreSQL, and entity filters go to the entity tables; the results are combined.

| Field | Default | Max | Purpose |
|-------|---------|-----|---------|
| `q` | `""` | | The query |
| `limit` | 20 | 500 | Articles per page |
| `offset` | 0 | | Article offset |
| `entity_limit` | 200 | 500 | Total entities to match |
| `entity_group_limit` | 25 | 500 | Entities returned per type (counted before trimming) |

```json
{
  "entries": {
    "hits": [{ "id": "...", "title": "...", "_formatted": {} }],
    "estimatedTotalHits": 261,
    "facetDistribution": { "feed_type": { "rss": 210 }, "tags": { "ransomware": 87 } }
  },
  "entities": {
    "items": [{ "id": "...", "type": "threat_actor", "name": "APT29", "match_kind": "direct" }],
    "counts": { "threat_actor": 57, "malware": 12, "cve": 3 }
  },
  "query": "threat_actor:APT29 ...",
  "parsed_filters": [{ "field": "threat_actor", "value": "APT29", "exact": false, "negated": false, "raw": "threat_actor:APT29" }],
  "did_you_mean": null,
  "processingTimeMs": 38
}
```

- `entities.counts` is the full count per type; `entities.items` is trimmed to `entity_group_limit` per type.
- `match_kind` is `direct` (the name, alias or id matched) or `mention` (a description, tag or rule body matched).
- Free-text queries also return notes as `"type": "note"`. `note_source` tells them apart: `note` (on an article, or standalone) or `entity_note` (on an entity, with `entity_name`). Notes are not limited to your own: search returns every note, like `GET /api/notes`. The `note:` filters (`note:`, `note.tag:`, `note.type:`, `note.about:`, `note.pinned:`) are in [query-language.md](query-language.md).
- When the query runs in PostgreSQL (`sort:radar`, an entity-only query, or more than 800 matching article ids), `estimatedTotalHits` is exact and `facetDistribution` is missing.
- `parsed_filters` is what the parser understood; the UI shows them as chips.
- `did_you_mean` suggests a fix when a filter value was cut at a space. `country:North Korea` filters on `country:North` and searches the text `Korea`; the suggestion is `country:"North Korea"`. It is only set when the longer value really exists.

---

### Sharing & Public Endpoints

#### Share Links

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| POST | `/api/entries/{entry_id}/share` | User | Make a public link to an article, or return yours if it exists. It never sets an expiry. With read-aloud on, the audio is prepared in advance |
| GET | `/api/entries/{entry_id}/share` | User | Your link for this article, or null |
| DELETE | `/api/entries/{entry_id}/share` | User | Turn your link off |
| GET | `/api/shared/{token}` | Share token | The shared article and its intel (TTPs, CVEs, actors, malware, rules, glossary terms, saved AI results) |
| GET | `/api/shared/{token}/og` | Share token | An HTML page with link-preview (Open Graph) tags for the shared article |
| POST | `/api/shared/{token}/run-ai-task` | Share token | Run an allowed AI task on the shared article (each task once per article). Detection and report tasks are not allowed |
| POST | `/api/shared/{token}/ask-agent` | Share token | Ask the AI a question about the shared article |
| POST | `/api/shared/{token}/tts/prepare` | Share token | Prepare read-aloud audio |
| GET | `/api/shared/{token}/tts/file/{cache_key}.mp3` | Share token | The audio file |
| GET | `/api/shared/copilot/{token}` | Share token | A shared copilot conversation |

#### Public RSS

Admin-managed token in the URL. Turn it on and get the token under Settings.

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/api/public/rss/{token}.xml` | RSS token | RSS of the newest articles across all active, unmuted feeds |
| GET | `/api/public/rss/{token}/category/{slug}.xml` | RSS token | RSS for one category |
| GET | `/api/public/rss/{token}/categories` | RSS token | The category slugs you can use |
| GET | `/api/system-settings/public-rss/token` | Admin | Get (or create) the token |
| POST | `/api/system-settings/public-rss/regenerate-token` | Admin | New token; old URLs stop working |

#### Observable Feeds (Outbound)

For firewalls, SIEMs and threat-intel platforms to pull observables. Everything returns 404 until `observables_publish_enabled` is on and a token is set in `observables_publish_token`. Send the token as a bearer header, or `?token=` for devices that can't set headers.

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/api/publish/edl/{filename}` | Publish token | Plain-text blocklist (EDL), one value per line |
| GET | `/api/publish/lookup/{filename}` | Publish token | SIEM lookup CSV: kind, value, label, role, confidence, last_seen |
| GET | `/api/taxii2/`, `/api/taxii2/api/`, `/api/taxii2/api/collections/`, `.../collections/{collection_id}/`, `.../collections/{collection_id}/objects/` | Publish token | TAXII 2.1 server (a standard protocol for sharing threat data) |
| GET | `/api/publish/status` | User | Whether publishing is on and what it serves |

---

### System & Operations

#### System Settings

Instance settings, stored in the database and falling back to `.env`. All Admin.

| Method | Path | What it does |
| --- | --- | --- |
| GET | `/api/system-settings` | Every setting with its current value, grouped for the settings screens |
| PATCH | `/api/system-settings` | `{"settings": {"registration_enabled": false}}`. A `null` value resets that key |
| DELETE | `/api/system-settings/{key}` | Reset one key to its default |

#### Signal Engine & Pipeline

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/api/engine/pipeline` | User | Pipeline stages, 24-hour activity and engine flags |
| GET | `/api/engine/pipeline/stages/{stage}/runs` | User | Recent runs of one stage |
| GET | `/api/engine/processing` | Admin | Per-article stage grid and window stats |
| GET | `/api/engine/entries/{entry_id}/runs` | User | Every stage run for one article |
| GET | `/api/engine/entries/{entry_id}/adjudication` | User | What the adjudicate stage decided for one article |
| POST | `/api/engine/entries/{entry_id}/stages/{stage}/retry` | Admin | Re-run one stage for one article |
| POST | `/api/engine/pipeline/retry-errors` | Admin | Re-run every stage still stuck on an error (optionally one stage) for articles in a window |
| GET | `/api/engine/extraction/status` | User | AI extraction health: queue, today's spend, last batch |
| GET | `/api/engine/plans` | User | Pipeline plans (global, per category, per feed) |
| PUT | `/api/engine/plans` | Admin | Create or change one plan |
| DELETE | `/api/engine/plans/{plan_id}` | Admin | Delete a category or feed plan (not the global one) |
| GET | `/api/engine/job-runs` | User | Recent scheduled job runs |
| GET | `/api/engine/state` | User | Whether the engine is stopped, and tasks waiting on each queue |
| PUT | `/api/engine/state` | Admin | Stop or start all background work |
| GET | `/api/engine/signals/stats` | User | Signal firing rates, weights and the radar threshold |
| PUT | `/api/engine/signals/settings` | Admin | Change signal weights or the radar threshold, then rescore |
| GET | `/api/engine/entities/{entity_type}/{entity_id}/whats-new` | Visitor | Recent signals on an entity's articles |
| PUT | `/api/engine/radar-feedback` | User | Vote on a radar item (1 useful, -1 noise, 0 clears) |
| GET | `/api/engine/my-radar` | User | Your learned signal weights and the votes behind them |
| PUT | `/api/engine/my-radar` | User | Turn your learned weights on or off |
| DELETE | `/api/engine/my-radar` | User | Throw away your learned weights |
| GET, POST, DELETE | `/api/engine/autolink/fp-names` | Admin | Names the autolinker must not match |
| GET, POST, DELETE | `/api/engine/autolink/blocked-names` | Admin | Words blocked for every entity type |

See [engine.md](engine.md) and [engine-settings.md](engine-settings.md).

#### Analytics

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/api/analytics/overview` | Visitor | Summary numbers for dashboards |
| GET | `/api/analytics/trending/{entity_type}` | Visitor | Most-mentioned entities of a type in a window |
| GET | `/api/analytics/velocity` | Visitor | New entities per day |
| GET | `/api/analytics/source-overlap` | User | Feeds that cover the same topics |
| GET | `/api/analytics/entries/{entry_id}/insights` | User | Insights about one article's entities |

#### Feed Reliability

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/api/analytics/source-reliability` | User | Feeds ranked by articles and entities they contribute |
| GET | `/api/analytics/feed-value` | User | Feeds ranked by useful intel output |

#### Backup & Export

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/api/backup/export` | Admin | Download the configuration as JSON |
| POST | `/api/backup/import` | Admin | Import a backup (JSON body). Merges; deletes nothing |

For a full database backup use `scripts/ops/backup.sh` instead (see [operations.md](operations.md)).

#### Logs

Log files on the server. All Admin.

| Method | Path | What it does |
| --- | --- | --- |
| GET | `/api/logs` | The log files with size and change time |
| GET | `/api/logs/{filename}` | The last `lines` lines (default 500, max 10000) as text |
| DELETE | `/api/logs/{filename}` | Empty a log file |

Files: `app.log`, `error.log`, `http.log`, `jobs.log`, `audit.log`, `update.log`. There is no audit-log query API; audit events are in `audit.log`.

#### Health & Metrics

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/api/health` | Public | Checks PostgreSQL, Redis and Meilisearch. Latency and error text only for callers on the api host |
| GET | `/api/version` | Public | Build `version`, `git_sha` and `built_at`. An unstamped build reports `dev` |
| GET | `/metrics` | Private networks only | Prometheus metrics. Returns 403 to any address outside loopback and private ranges |

```json
{
  "status": "healthy",
  "version": "dev",
  "git_sha": null,
  "built_at": null,
  "components": {
    "database": { "status": "ok", "latency_ms": 1.2 },
    "redis": { "status": "ok", "latency_ms": 0.4 },
    "meilisearch": { "status": "ok", "latency_ms": 3.1 }
  }
}
```

`status` is `healthy` when all three are ok, `degraded` when only the database is ok, and `unhealthy` when the database is down.

#### Additional Operations

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/api/themes` | Visitor | All themes |
| GET | `/api/themes/{theme_id}` | Visitor | One theme |
| GET | `/api/themes/schema` | Public | Colour names and default theme values |
| GET | `/api/themes/default` | Public | The instance default theme (styles the sign-in page) |
| GET | `/api/themes/default.css` | Public | The same as a stylesheet |
| POST | `/api/themes` | User | Create a theme |
| PUT | `/api/themes/{theme_id}` | Owner | Change a custom theme (built-in themes are fixed) |
| DELETE | `/api/themes/{theme_id}` | Owner | Delete a custom theme |
| POST | `/api/themes/{theme_id}/duplicate` | User | Copy a theme as your own |
| PUT | `/api/themes/user/preferences` | User | Choose your theme |
| PUT | `/api/themes/{theme_id}/default` | Admin | Make it the instance default |
| DELETE | `/api/themes/{theme_id}/default` | Admin | Clear the instance default |
| POST | `/api/events/ticket` | User | Get a 30-second, single-use ticket for the event stream |
| GET | `/api/events` | Ticket | The server-sent event (SSE) stream: `?ticket=` from the call above |
| GET | `/api/documentation` | Visitor | The in-app docs index (built from `docs/`) |
| GET | `/api/documentation/{slug}` | Visitor | One docs page as Markdown |
| GET | `/api/documentation/assets/{path}` | Public | An image used by the docs |

---

### Other Routers

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/api/glossary` | Visitor | Glossary terms (category, name search, system or user) |
| POST | `/api/glossary` | User | Add a term (409 if it exists) |
| PUT | `/api/glossary/{term_id}` | User | Change a term |
| DELETE | `/api/glossary/{term_id}` | User | Delete a user term (built-in terms can't be deleted) |
| GET | `/api/glossary/categories` | Visitor | Term categories |
| GET | `/api/glossary/counts` | Visitor | Article counts per term |
| GET | `/api/glossary/{term_id}/entries` | Visitor | Articles that use the term |
| POST | `/api/glossary/detect` | Visitor | Find glossary terms in an article's text |
| GET | `/api/podcasts` | User | Podcasts |
| GET | `/api/podcasts/{feed_id}` | User | One podcast |
| GET | `/api/podcasts/{feed_id}/episodes` | User | Its episodes with your progress |
| GET | `/api/playback/in-progress` | User | Media you started but didn't finish |
| GET, PUT | `/api/playback/{media_id}/progress` | User | Read or save your position |
| PUT | `/api/playback/{media_id}/complete` | User | Mark finished |
| POST | `/api/tts/prepare` | User | Make (or find) read-aloud audio; then fetch the file |
| GET | `/api/tts/file/{cache_key}.mp3` | Token in header or `?token=` | The audio file |
| GET | `/api/tts/existing` | Visitor | Whether audio already exists for an article or entity |
| GET | `/api/proxy/image` | Visitor | Fetch and optionally resize an outside image |
| GET | `/api/telegram/discover` | User | Channels the Telegram account has joined |
| GET | `/api/telegram/feeds/{feed_id}/health` | User | Health of one Telegram feed |
| GET | `/api/telegram/listener/status` | User | Whether the live listener has checked in |
| GET | `/api/telegram/mentions` | User | Telegram channels mentioned in articles |
| GET | `/api/telegram/mentions/{mention_id}` | User | One mention with sample articles |
| POST | `/api/telegram/mentions/{mention_id}/dismiss` | User | Hide a mention |
| POST | `/api/telegram/mentions/{mention_id}/undismiss` | User | Show it again |
| POST | `/api/telegram/mentions/{mention_id}/subscribe` | User | Add a feed for that channel |
| GET | `/api/telegram-media/{channel_id}/{filename}` | Token in header or `?token=` | A downloaded Telegram media file |

---

## Common Query Patterns

All of these run on the host against the dev stack. Set `TOKEN` to an access token from `POST /api/auth/login` first.

### Filter Entries by Multiple Criteria

```bash
# Unread articles from the last 7 days that mention a known-exploited CVE
curl -s "http://localhost:8000/api/entries?since=2026-10-20T00:00:00Z&is_read=false&exploited_cves=true" \
  -H "Authorization: Bearer $TOKEN"

# Articles linked to one threat actor
curl -s "http://localhost:8000/api/entries?entity_type=threat_actor&entity_id=<actor uuid>" \
  -H "Authorization: Bearer $TOKEN"
```

### Pagination Through Large Result Sets

```bash
# First page
curl -s "http://localhost:8000/api/entries?limit=50" -H "Authorization: Bearer $TOKEN"

# Next page: pass next_cursor from the previous answer
curl -s "http://localhost:8000/api/entries?limit=50&cursor=<next_cursor>" -H "Authorization: Bearer $TOKEN"
```

### Extract Intelligence from an Entry

```bash
curl -s -X POST "http://localhost:8000/api/entries/<entry uuid>/extract-ttps" -H "Authorization: Bearer $TOKEN"
curl -s -X POST "http://localhost:8000/api/entries/<entry uuid>/extract-cves" -H "Authorization: Bearer $TOKEN"
curl -s -X POST "http://localhost:8000/api/entries/<entry uuid>/extract-threat-actors" -H "Authorization: Bearer $TOKEN"
```

### Trigger Automation Rule

```bash
# Dry run against one article
curl -s -X POST "http://localhost:8000/api/automation/rules/<rule uuid>/test?entry_id=<entry uuid>" \
  -H "Authorization: Bearer $TOKEN"

# Run it for real
curl -s -X POST "http://localhost:8000/api/automation/rules/<rule uuid>/run" -H "Authorization: Bearer $TOKEN"
```

---

## Further Reading

- [architecture.md](architecture.md): how the pieces fit together
- [data-model.md](data-model.md): the database tables
- [public-read-only-mode.md](public-read-only-mode.md): what anonymous visitors can see
- `backend/app/api/`: the routers; `backend/app/schemas/`: request and response models
