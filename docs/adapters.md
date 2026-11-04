# Adapters and Feed Ingestion

This page is for developers and admins who want to know how IntelFeed pulls
articles in. It covers how feeds are polled, how duplicates are caught, what
each feed type does and which settings it takes, OPML import and export,
manual uploads, and how to add a new adapter.

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Adapter Base Classes](#adapter-base-classes)
4. [Feed Model & Type Detection](#feed-model--type-detection)
5. [Feed Polling Loop](#feed-polling-loop)
6. [Entry Deduplication & Processing](#entry-deduplication--processing)
7. [Feed Reliability & Breakage Alerts](#feed-reliability--breakage-alerts)
8. [Per-Adapter Details](#per-adapter-details)
   - [RSS/Atom](#rssatom)
   - [YouTube](#youtube)
   - [Podcast](#podcast)
   - [Reddit](#reddit)
   - [GitHub (Releases & Advisories)](#github-releases--advisories)
   - [GitHub (Repository Monitor)](#github-repository-monitor)
   - [NVD/CVE](#nvdcve)
   - [Mastodon](#mastodon)
   - [Bluesky](#bluesky)
   - [Telegram](#telegram)
   - [Telegram Operations](#telegram-operations)
   - [Web Scraper](#web-scraper)
   - [Ransomware Leak Sites (ransomware.live)](#ransomware-leak-sites-ransomwarelive)
9. [OPML Import/Export](#opml-importexport)
10. [Manual Ingest](#manual-ingest)
11. [Building a New Adapter](#building-a-new-adapter)

---

## Overview

Every feed has a **feed type** (`rss`, `youtube`, `reddit` and so on). Each
type has an **adapter**: code in `backend/app/adapters/` that fetches that
kind of source and turns it into a common shape. The registry is
`backend/app/adapters/__init__.py`.

| Feed type | Adapter | Kind | Needs |
| --- | --- | --- | --- |
| `rss`, `atom` | `RSSAdapter` | URL feed | A feed URL |
| `youtube` | `YouTubeAdapter` | URL feed | A channel's feed URL |
| `podcast` | `PodcastAdapter` | URL feed | A podcast RSS URL |
| `reddit` | `RedditAdapter` | API | `subreddit` |
| `github_releases` | `GitHubReleasesAdapter` | API | `owner`, `repo` |
| `github_advisories` | `GitHubAdvisoriesAdapter` | API | Nothing (filters optional) |
| `github_repo` | `GitHubRepoAdapter` | API | `owner`, `repo` |
| `nvd` | `NVDAdapter` | API | Nothing (filters optional) |
| `mastodon` | `MastodonAdapter` | API | `instance_url` + `account_id` or `hashtags` |
| `bluesky` | `BlueskyAdapter` | API | A handle, feed URI or search query |
| `telegram` | `TelegramAdapter` | API | A Telegram login session and a channel |
| `web_scraper` | `WebScraperAdapter` | API | `blog_url` |

`manual` is a pseudo-type for the Manual Uploads feed. It has no adapter and
is never polled (see [Manual Ingest](#manual-ingest)).

There are two kinds of adapter:

- **URL feeds** (`BaseAdapter`) receive the raw text the worker downloaded
  from the feed URL and parse it.
- **API adapters** (`ExtendedAdapter`) make their own requests, using the
  feed's `adapter_config`.

Both return the same objects (`ParsedFeedMeta`, `ParsedEntry`,
`ParsedMedia`), so everything after the fetch is shared.

---

## Architecture

See diagram: [Feed ingestion pipeline](diagrams/adapters-ingest-pipeline.md)

In short:

1. Celery Beat runs `poll_due_feeds` every 60 seconds. It picks the feeds that
   are due and queues one `fetch_feed` task per feed.
2. `fetch_feed` downloads the feed (or calls the API adapter) and parses it.
3. New items are checked for duplicates, cleaned up, enriched (full article
   text, lead image, transcripts), saved, and indexed in Meilisearch.
4. Each new entry then goes through the entry pipeline: linking known
   entities, extracting intelligence, post-processing and scoring.

---

## Adapter Base Classes

Both classes live in `backend/app/adapters/base.py`.

### BaseAdapter

For sources with a feed URL. One method to implement:

```python
def parse_entries(self, feed_url: str, content: str) -> tuple[ParsedFeedMeta, list[ParsedEntry]]:
    """Parse raw feed content and return (feed_metadata, entries)."""
```

It also has `detect_feed_type()`, described under
[Type Detection](#type-detection).

### ExtendedAdapter

For sources the adapter calls itself. Two methods to implement:

```python
async def fetch_entries(self, config: dict, since: datetime | None = None) -> tuple[ParsedFeedMeta, list[ParsedEntry]]:
    """Fetch entries. `config` is the feed's adapter_config; `since` is the last fetch time."""

def get_feed_meta(self, config: dict) -> ParsedFeedMeta:
    """Feed metadata for display, without fetching entries."""
```

### The shared objects

**`ParsedEntry`** is one item:

| Field | Meaning |
| --- | --- |
| `guid` | Unique ID within the feed. Used to spot items already saved. |
| `url` | Link to the original. Anything but `http(s)` or a relative link is dropped, so a `javascript:` link can't reach the page. |
| `title` | Defaults to "Untitled". |
| `author`, `summary`, `published_at` | Optional. |
| `content_html` | The body. The worker cleans it before saving. |
| `metadata` | Adapter-specific extras, saved on the entry. |
| `media` | The main attachment (`ParsedMedia`), if any. |
| `additional_media` | Extra attachments. Only Telegram uses it, for photo albums. |

**`ParsedMedia`** is an attachment: `media_type` (audio, video, image,
document), `url`, and optional `mime_type`, `file_size`, `duration_seconds`,
`thumbnail_url`, `transcript_url` and `metadata`.

**`ParsedFeedMeta`** is feed-level information: `title`, `description`,
`site_url`, `icon_url`, `language`, podcast show fields (`podcast_author`,
`podcast_categories`, `podcast_explicit`, `podcast_type`,
`podcast_artwork_url`), and `extra`, a dict an adapter can use to hand state
back to the worker (see [Building a New Adapter](#building-a-new-adapter)).

---

## Feed Model & Type Detection

### Feed Model

`backend/app/models/feed.py`. The fields that matter for ingestion:

| Field | Meaning |
| --- | --- |
| `url` | Unique. The feed URL, or a placeholder for API adapters. |
| `feed_type` | Which adapter runs. |
| `is_active` | Inactive (paused) feeds are never polled. |
| `fetch_interval_minutes` | How often to poll. Default 30. |
| `last_fetched_at` | When the last fetch ran. |
| `etag`, `last_modified` | Saved from the last answer, for conditional requests. |
| `error_count`, `last_error`, `error_since` | The current failure streak. Cleared by a good fetch. |
| `auto_paused_at` | Set when the health check paused the feed. |
| `adapter_config` | JSON settings for the adapter, plus state it keeps between fetches. |
| `exclude_title_patterns` | Phrases, one per line. Items whose title contains one are dropped. |
| `intel_extraction_mode` | `full`, `selective` (default), `manual` or `none`. `none` turns off analysis for the feed. |
| `auto_extract_on_ingest`, `extract_detection_rules` | Run the extract stage on new entries. Off by default. |
| `ai_analysis_enabled` | Run the one-pass AI analysis on this feed's entries. On by default. |
| `extract_tools` | Let AI extraction create tool entities from this feed. On by default. |
| `reliability_rating` (A–F), `timeliness_rating`, `relevance_rating`, `analyst_notes` | Analyst ratings of the source. |
| `visible_to_visitors` | Shown in [public read-only mode](public-read-only-mode.md). Off by default. |
| `retention_days`, `category_id`, `custom_title`, `is_muted` | Housekeeping. |

### Type Detection

After a successful download of an `rss` or `atom` feed,
`BaseAdapter.detect_feed_type()` checks what it really is and updates
`feed_type` if needed:

1. A `youtube.com` URL is `youtube`.
2. A feed with iTunes tags (`itunes:type` or `itunes:author`), or an audio
   attachment in its first five items, is `podcast`.
3. A feed that `feedparser` reports as Atom is `atom`.
4. Anything else is `rss`.

---

## Feed Polling Loop

All of this is in `backend/app/workers/feed_tasks.py`.

### Celery Beat Task: `poll_due_feeds()`

Runs every 60 seconds (the `poll-feeds` job in `workers/job_registry.py`). It
selects up to 50 feeds, oldest fetch first, that are:

- active;
- due: never fetched, or `fetch_interval_minutes` have passed since the last
  fetch (longer while the feed is failing, see
  [Failure backoff](#feed-reliability--breakage-alerts));
- wanted: when per-user subscriptions are on, at least one reader has the
  feed un-paused.

For each one it sets a Redis lock (`feed_fetch:{feed_id}`, 10 minutes) and
queues `fetch_feed`. A feed whose lock is already set is skipped, so the same
feed is never fetched twice at once. `fetch_feed` removes the lock when it
finishes.

### Task: `fetch_feed()`

Fetches one feed. Up to 3 retries on an unexpected error, waiting
`2^retries × 10` seconds plus up to 10 seconds of jitter, at most 300
seconds. Soft time limit 10 minutes, hard limit 11 minutes.

### Core Fetch Logic: `_fetch_feed()`

The steps, in order:

1. **Pick the path.** API feed types go to `_fetch_extended_feed()` (see
   below). `manual` feeds and URLs that aren't `http(s)` are skipped quietly.
2. **Per-domain rate limit.** At most one request per domain every
   `rate_limit_default_interval` seconds (default 2, editable in Settings),
   with per-domain overrides in `RATE_LIMIT_OVERRIDES`. If the domain is busy,
   the feed waits for the next poll.
3. **Conditional request.** The worker sends `If-None-Match` and
   `If-Modified-Since` from the last answer. A `304 Not Modified` ends the
   fetch with nothing to do. The request also carries a browser-like
   `Accept` and `Accept-Language`, and the `user_agent` setting.
4. **Bot walls.** If the answer is a 403, or a 429/503 whose body looks like
   a challenge page, the worker tries once more with **curl_cffi**, which
   imitates Chrome's network fingerprint. Some publishers (CISA, for example)
   refuse Python's TLS handshake whatever the headers. Others hang up instead
   of answering (SiteGround's anti-bot, Akamai on sophos.com): a dropped
   connection, a reset or stalled read, or a refused TLS handshake gets the
   same retry. A DNS failure or connect timeout does not, since the host is down. Whichever client gets a
   200 or 304 is remembered in `adapter_config.fetch_health.client`, and later
   polls start with it. Blocks by IP address can't be worked around this way.
5. **YouTube retries.** YouTube's feed sometimes answers 404 or 5xx for no
   reason. The worker retries twice, 5 seconds apart. If both fail, it skips
   this cycle without counting an error.
6. **Other errors.** Any other non-200 answer counts as a failure (see
   [Feed Reliability](#feed-reliability--breakage-alerts)). After 3 or more
   404s in a row on an `rss`, `atom` or `podcast` feed, the worker looks for
   a new feed URL on the site's home page (`<link rel="alternate">` tags),
   checks that it really is a feed, and switches the feed to it. The change
   is logged in `adapter_config.url_autodiscovery_history`.
7. **Detect the type** (see [Type Detection](#type-detection)) and **parse**
   with the adapter.
8. **Spot dead feeds.** An `rss` or `atom` feed that answers 200 with an
   HTML page and no items counts as a failure, not an empty poll. That is
   usually an old feed URL that now shows the website.
9. **Drop duplicates** (see
   [Entry Deduplication](#entry-deduplication--processing)).
10. **YouTube Shorts.** If `adapter_config.exclude_shorts` is set, each new
    video is checked with a request to `youtube.com/shorts/{id}`. A 200 means
    it is a Short and it is dropped.
11. **Full article text** (`rss` and `atom` only). When an item's text is
    under 500 characters, or ends in "Continue reading on … »", the worker
    downloads the article page and pulls out the body. Up to 25 per fetch.
    See [Full-text extraction](#full-text-extraction).
12. **Clean up the HTML** and work out the plain text and word count.
13. **Lead image.** The first `<img>` in the body, then in the summary, then
    the page's `og:image` (from step 11, or a separate fetch that reads only
    the first 50 KB of the page).
14. **Save** the entry and its media. A publish date in the future is set to
    now. A duplicate that slips in at the same moment is skipped.
15. **Index** it in Meilisearch. If that fails, the entry id goes into the
    Redis set `meili:failed_entry_ids` to retry later.
16. **Update the feed**: fetch time, `etag`, `last_modified`, clear the
    failure streak. The feed's title, description and site URL are filled in
    from the source if they are empty (or if the title is still just the
    URL).
17. **Tell the rest of the app.** One `feed_fetched` live-update event,
    automation rules for each new entry, and the entry pipeline.

**The entry pipeline** (`dispatch_entry_pipeline`, stages listed in
`app/pipeline/registry.py`) runs these in parallel: autolink, observables,
Telegram link scan, and extract (only when the feed has
`auto_extract_on_ingest` or `extract_detection_rules` on and analysis isn't
turned off). Then co-occurrence, correlation and requirement matching run,
then scoring. If the feed has `adapter_config.auto_translate`, translation
runs first so every stage sees the translated text. The target language is
`adapter_config.translation_target`, else the `translation_default_target`
setting (default `en`).

### Full-text extraction

`_extract_full_text()`:

1. **Google News links** are decoded to the real publisher URL first, and the
   entry's link is changed to match.
2. **Permission.** `robots.txt` must allow the fetch, and its `Crawl-delay`
   is used as the minimum gap for that domain.
3. **Fetch** with httpx, falling back to curl_cffi on a block. Medium-hosted
   sites go straight to curl_cffi.
4. **Extract.** Medium has its own extractor. Everything else uses
   readability-lxml, then a list of common article-body CSS selectors.
5. **Reject wall pages.** If the result is under 1,000 characters and reads
   like "Please enable JavaScript" or a bot check ("Checking your browser"),
   it is thrown away and the entry keeps the feed's own text
   (`app/services/js_wall.py`). Single-page sites such as NCSC, Europol and
   MSRC only show that notice to non-browsers.

### API feeds: `_fetch_extended_feed()`

API adapters skip steps 2–8 and 10–11. The worker calls `fetch_entries()`
with the feed's `adapter_config` (plus a temporary `_feed_id` key) and the
last fetch time. Then it applies the title filter, GUID and content-hash
checks, cleaning, the lead image (also from `metadata.image_url`), saving,
the [auto-attribution](#auto-attribution) links, indexing, and the same
events and pipeline. Adapter state handed back in
`feed_meta.extra["_adapter_state"]` is merged into `adapter_config`. An
exception from the adapter counts as a failed fetch.

---

## Entry Deduplication & Processing

### Deduplication Strategy

Checks run in this order. An item that matches any of them is not saved.

1. **Title filter** (every feed type). Items whose title contains one of the
   feed's `exclude_title_patterns` are dropped before anything else
   (`app/services/title_filter.py`). The phrases are plain text, not regular
   expressions, and matching ignores case. Edit them in the feed settings'
   Source pane, which previews how many of the last 100 titles would be
   dropped (`POST /api/feeds/{id}/title-filter/preview`). Dropped items are
   never saved, so they are checked again on every fetch.
2. **GUID** (per feed). An item whose `guid` this feed already has is skipped.
3. **Same link, new GUID** (per feed; URL feeds only). Some feeds give the
   same article a new GUID on every fetch (CrowdStrike's RSS does). So an
   item whose link, title and attachment match one this feed already has is
   treated as the same article (`item_key()` in `app/services/dedup.py`).
   Links are compared without the `#fragment` and tracking parameters
   (`utm_*`, `mc_*`, `fbclid`, `gclid` and similar); other parameters such as
   `?p=123` still count. If the new copy has a real body (500+ characters,
   not a teaser) that differs from the saved one, the saved entry is updated
   and re-indexed.
4. **Content hash** (across all feeds). A SHA-256 of the cleaned-up title
   plus the first 500 characters of the text. Catches the same article
   republished under a different GUID or in another feed.

### HTML Sanitization

`app/services/sanitizer.py` uses **nh3**, a fast HTML cleaner. It keeps a
fixed list of safe tags (paragraphs, links, images, headings, lists, code,
quotes, tables, emphasis and so on) and removes everything else, including
scripts, event handlers and iframes. Links get
`rel="noopener noreferrer nofollow"`.

`html_to_text()` builds the entry's `content_text` from the HTML. Text from
neighbouring elements never runs together: paragraphs, headings and other
blocks are separated by a blank line; list items, table rows, captions and
`<br>` by a newline; table cells by a tab. Where the source already has a
newline there, it is kept as is. This keeps the regex scans honest: two list
items of IPs stay two IPs, and a CVE cell stays apart from its CVSS cell.

### Image Proxying

`sanitize_html()` rewrites every `<img src>` to IntelFeed's image proxy
(`/api/proxy/image?url=…`) when the entry is saved. That keeps the reader's
IP address away from outside servers and lets images be cached. Telegram
media (`/api/telegram-media/…`) is already served by IntelFeed and is left
alone.

### Transcript Handling

`_create_entry_media()` saves the attachment rows (including every Telegram
album photo) and adds text where it can:

- **Podcasts:** the Podcast 2.0 `transcript` URL is downloaded.
- **YouTube:** the video's transcript is fetched with youtube-transcript-api.
- **Telegram:** when `TELEGRAM_OCR_ENABLED` is on, images are run through
  Tesseract OCR (reading text out of a picture). Results shorter than
  `TELEGRAM_OCR_MIN_CHARS` (default 30) are ignored.

Transcript and OCR text is added to the entry's text before the entry
pipeline starts, so it is searchable and the intelligence stages see it.

---

## Feed Reliability & Breakage Alerts

- **`error_count`** goes up on every failed fetch (network error, non-200
  answer, adapter error, HTML instead of a feed) and goes back to 0 on any
  good fetch. So it counts failures *in a row*. `error_since` records when the
  streak began.
- **`feed_error` events.** Once `error_count` reaches 3, a `feed_error`
  correlation event is created, so broken feeds show up in the events stream.
- **`check_feed_health`** (every 6 hours, at minute 30) creates:
  - `feed_stale` events for active feeds fetched in the last 2 days whose
    newest entry is more than 120 days old;
  - `feed_error` events for active feeds with 3 or more failures in a row;
  - and pauses dead feeds (see Auto-pause).
- **Failure backoff.** While a feed is failing, the poller doubles its wait
  for each failure in a row, up to 64 times the normal interval and at most
  24 hours (an interval already longer than that is kept). The first good
  fetch resets it. A blocked feed then logs about 20 failures before it is
  paused, not thousands.
- **Auto-pause.** `check_feed_health` pauses a feed whose current failure
  streak is an HTTP 4xx (a client error such as 403 or 404) that began more
  than `feed_auto_pause_days` ago (default 30; 0 turns it off; see
  [engine-settings.md](engine-settings.md)). Server errors and timeouts never
  pause a feed. The reason is saved in `adapter_config.fetch_health.paused`:
  the error, status, failure count, when the streak began and which client
  was used. The feed settings, the sidebar tooltip and the Feeds view show it
  as "paused automatically after HTTP 403 for 30 days", while a feed someone
  paused by hand just says "Paused". Resuming the feed clears it.
- **Reachable but empty.** An `rss`, `atom` or `podcast` feed that answers
  200 but has no items is noted in `adapter_config.fetch_health.empty` (since
  when, where a redirect ended up, the content type). The next fetch with
  items clears it. It becomes a warning (`FeedResponse.health_warning`) at
  once if the feed URL redirected somewhere else, or after 3 days otherwise.
  The Feeds view lists these as **Empty**.
- `fetch_health` belongs to the server: updating a feed, creating one, and
  OPML import and export all drop it.
- **`GET /api/feeds/health/failing`** lists active feeds with at least
  `threshold` failures in a row (default 5). Feeds rated A or B for
  reliability are marked `is_high_value` and listed first.
- **`GET /api/feeds/{feed_id}/analytics`** gives per-feed source analytics
  (`app/intelligence/source_analytics.py`): volume, how much intelligence the
  feed yields, and the analyst ratings.

---

## Per-Adapter Details

Settings below are keys in the feed's `adapter_config`. The add-feed form
fills them in; you only see the raw keys in the API, the registry tools and
OPML exports.

### RSS/Atom

**Type**: URL feed. **File**: `backend/app/adapters/rss.py`

Parses RSS 2.0 and Atom with **feedparser**.

- **GUID:** the item's `id`, else its link, else its title. Items with none
  are skipped. GUIDs and titles are cut at 2,000 characters.
- **Body:** the item's `content`, else `summary`, else `description`.
- **Summary:** cut to 500 characters.
- **Date:** `published`, else `updated`.
- **Feed info:** title, description (or subtitle), site link, image, language.

Short items get the full article text fetched (see
[Full-text extraction](#full-text-extraction)).

---

### YouTube

**Type**: URL feed. **File**: `backend/app/adapters/youtube.py`

Parses a channel's YouTube feed.

- **Link:** `https://www.youtube.com/watch?v={video_id}`.
- **Body:** the video description, with plain-text links made clickable and
  line breaks kept. The summary is its first 500 characters.
- **Thumbnail:** from the feed, else `i.ytimg.com/vi/{id}/hqdefault.jpg`.
- **Metadata:** `video_id`, `channel_id`, `channel_name`, `view_count`,
  `star_rating`, `embed_url`.
- **Transcript:** fetched when the entry is saved.

| Setting | Meaning |
| --- | --- |
| `exclude_shorts` | Drop YouTube Shorts. If the check fails, the video is kept. |

---

### Podcast

**Type**: URL feed. **File**: `backend/app/adapters/podcast.py`

Parses podcast RSS, including iTunes and Podcast 2.0 tags.

- **Audio:** the first attachment whose type is `audio/*`,
  `application/octet-stream` or blank.
- **Duration:** from `itunes:duration`, written as `1:23:45`, `12:30` or
  plain seconds.
- **Metadata:** `episode_number`, `season_number`, `episode_type`,
  `is_explicit`.
- **Show info** (author, categories, explicit flag, episodic or serial,
  artwork) is stored in a separate `Podcast` row for the feed.
- **Transcript:** the Podcast 2.0 `transcript` URL is downloaded when the
  entry is saved.

---

### Reddit

**Type**: API. **File**: `backend/app/adapters/reddit.py`

Reads a subreddit's public `/hot.rss` feed. Reddit blocks JSON access without
a login, so RSS is the only route.

| Setting | Default | Meaning |
| --- | --- | --- |
| `subreddit` | (required) | For example `netsec`. |
| `limit` | 50 | Posts per fetch, at most 100. |

- **GUID:** SHA-256 of the post's id (or link), cut to 32 characters.
- **Author:** with the `/u/` prefix removed.
- **Metadata:** `subreddit`, `reddit_url`, `hot_rank`, and `score`. RSS has
  no real vote counts, so `score` comes from the post's position in the hot
  list (first post scores highest).

---

### GitHub (Releases & Advisories)

**Type**: API. **File**: `backend/app/adapters/github.py`

#### GitHubReleasesAdapter

Reads the 30 most recent releases of one repository. Drafts are skipped.

| Setting | Default | Meaning |
| --- | --- | --- |
| `owner`, `repo` | (required) | The repository. |
| `include_prereleases` | `false` | Also include pre-releases. |
| `token` | none | GitHub token for a higher rate limit. |

The release notes (Markdown) become the body. Metadata: `owner`, `repo`,
`tag_name`, `prerelease`.

#### GitHubAdvisoriesAdapter

Reads the 30 newest entries in the GitHub Advisory Database.

| Setting | Default | Meaning |
| --- | --- | --- |
| `ecosystem` | all | A GitHub ecosystem name, such as `npm` or `pip`. |
| `severity` | `high,critical` | Comma-separated: `critical`, `high`, `moderate`, `low`. |
| `token` | none | GitHub token for a higher rate limit. |

Links go to the GitHub advisory page. Metadata: `ghsa_id`, `cve_ids`,
`severity`, `cvss_score`, `ecosystem`.

Without a token, GitHub allows 60 API requests an hour; with one, 5,000.

---

### GitHub (Repository Monitor)

**Type**: API. **File**: `backend/app/adapters/github_repo.py`

Watches a repository for new and changed files, such as detection rules. Each
file is one entry (GUID `{owner}/{repo}/{path}`), updated in place when the
file changes.

| Setting | Default | Meaning |
| --- | --- | --- |
| `owner`, `repo` | (required) | The repository. |
| `branch` | `main` | Branch to watch. |
| `paths` | all files | Glob patterns, such as `rules/**/*.yml`. |
| `watch_mode` | `commits` | `commits` or `tree_diff` (see below). |
| `max_entries_per_poll` | 50 | Files per fetch. |
| `include_content` | `true` | Download each file's content. |
| `backfill_days` | 90 | On the first fetch, how far back to look. |
| `last_commit_sha` | (kept by the adapter) | Where the last fetch stopped. |

The GitHub token is **not** a feed setting. One token serves every repo
feed: the `github_token` setting (Settings → Engine → Enrichment → Keys), or the `GITHUB_TOKEN` env var.

**Watch modes:**

- **`commits`** reads new commits through the Commits API. Good for normal
  polling.
- **`tree_diff`** compares `last_commit_sha` with the branch head through the
  Compare API. Faster for busy repos. If the difference is too large for
  GitHub to return (over 250 commits or 300 files), it falls back to
  `commits`.

**File types** (`github_content_types.py`):

1. A known repository path decides first, for example
   `SigmaHQ/sigma:rules/**/*.yml` is `sigma_rule`.
2. Otherwise the file extension: `.yar`/`.yara` is a YARA rule, `.kql` a KQL
   query, `.yml`/`.yaml` and `.toml` generic files, and so on.
3. A generic YAML or TOML file is then checked for a rule format the importer
   supports: Sigma, a Microsoft Sentinel analytics rule, a Splunk detection,
   an Anvilogic Armory detection, or an Elastic TOML rule. The rule's query
   must pass the rule validator (`rule_validation.py`), or the file stays
   generic.

The title comes from the file where it can (a Sigma `title`, an Elastic
`rule.name`), else the filename. The body is rendered for reading: rules with
ATT&CK badges, code in a code block, Markdown as is.

**Full sync.** The `full_sync_github_feed` Celery task reads **every** file in
the repository through the Git Trees API, not just recent changes, adds the
ones not yet saved, and records the head commit for later fetches.

**Limits:**

- Files larger than `GITHUB_REPO_MAX_FILE_SIZE_KB` (default 5120, so 5 MB)
  are skipped.
- The adapter watches GitHub's rate-limit headers and backs off when fewer
  than 100 requests remain.

---

### NVD/CVE

**Type**: API. **File**: `backend/app/adapters/nvd.py`

Reads CVEs (published vulnerabilities) from the NIST National Vulnerability
Database API 2.0.

| Setting | Default | Meaning |
| --- | --- | --- |
| `api_key` | none | NVD API key for a higher rate limit. |
| `keywords` | none | List of words; CVEs must match them. |
| `min_cvss` | 0.0 | Skip CVEs scored below this. |

- One request per fetch, up to 50 CVEs changed since the last fetch. The first
  fetch looks back 7 days.
- The CVSS score is taken from v3.1, else v3.0, else v2.0, and turned into a
  severity label.
- **Title:** `CVE-ID: description`, with the description cut to 120
  characters. The body is the full English description.
- **Link:** the NVD detail page. Metadata: `cve_id`, `cvss_score`,
  `severity`, `references`.

---

### Mastodon

**Type**: API. **File**: `backend/app/adapters/mastodon.py`

Reads public posts from one account, or from hashtag timelines, on a Mastodon
server.

| Setting | Default | Meaning |
| --- | --- | --- |
| `instance_url` | (required) | For example `https://infosec.exchange`. |
| `account_id` | none | The account's numeric id (not its handle). |
| `hashtags` | none | List of hashtags, used when there is no `account_id`. |
| `access_token` | none | Optional token. |
| `limit` | 40 | Posts per request, at most 40. |

- Account posts leave out replies and boosts.
- **Title:** the post text without HTML, cut to 120 characters. The body is
  Mastodon's own HTML.
- **Author:** `Display Name (@account)`.
- **Metadata:** `instance`, `account`, `status_id`, `reblogs_count`,
  `favourites_count`, `tags`.
- Attachments are not saved as media.

---

### Bluesky

**Type**: API. **File**: `backend/app/adapters/bluesky.py`

Reads public posts through Bluesky's public API
(`https://public.api.bsky.app/xrpc`). No login is needed. An app password is
optional and raises the rate limit.

| Setting | Default | Meaning |
| --- | --- | --- |
| `mode` | `author` | `author`, `feed` or `search`. |
| `handle` | | For `author` mode, such as `alice.bsky.social`. |
| `filter` | `posts_no_replies` | For `author` mode. |
| `include_reposts` | `false` | For `author` mode. |
| `feed_uri` | | For `feed` mode: an `at://` URI of a custom feed. |
| `query`, `lang` | | For `search` mode. |
| `render_replies` | `false` | Add a "Reply to …" line naming the parent post. |
| `identifier`, `app_password` | none | Optional login. The password is stored encrypted. |
| `pds_url` | `https://bsky.social` | Server to log in to. |
| `max_per_poll` | 50 | Posts per fetch. |
| `last_seen_cid` | (kept by the adapter) | Newest post already seen. |

- Requests fetch 50 posts in `author` and `feed` mode, 25 in `search` mode.
- **GUID:** a hash of the post's CID (its content ID).
- The fetch stops at the post saved in `last_seen_cid`.
- **Login session:** cached in Redis (`bluesky:session:{feed_id}`, 90
  minutes) and created again when it stops working.
- **Rate limit:** on a 429 the adapter returns nothing and tries again next
  poll.
- **Embeds:** images, video, link cards and quoted posts are rendered into
  the body. The first image or video becomes the entry's media.

---

### Telegram

**Type**: API. **File**: `backend/app/adapters/telegram.py`

Reads messages from Telegram channels with the Telethon library, logged in as
a real Telegram account.

| Setting | Default | Meaning |
| --- | --- | --- |
| `channel` | (required) | `@name` or a `t.me` link. |
| `session_name` | default session | Which login session to use (see Setup). |
| `max_messages_per_fetch` | 200 | Messages per fetch. |
| `max_message_age_days` | 30 | On the first fetch, how far back to look. |
| `include_media` | `true` | Download attachments. |
| `media_types` | photo, video, document, audio | Which attachments to download. |
| `extract_forwards` | `true` | Record where a forwarded message came from. |
| `edit_probe_window` | 50 | How many recent messages to re-check for edits and deletes. 0 turns it off; blank means the default. |
| `realtime` | `false` | Get new messages as they arrive (see [Telegram Operations](#telegram-operations)). |
| `threat_actor_id`, `campaign_id`, `author_entity` | none | [Auto-attribution](#auto-attribution). |
| `channel_id`, `channel_username`, `last_seen_id` | (kept by the adapter) | The resolved channel and the newest message seen. |

**Setup** (once per session, outside the app):

```bash
# On the host. Set in .env, then restart the stack:
TELEGRAM_API_ID=123456
TELEGRAM_API_HASH=abcd1234...
# Optional; this is the default. Named sessions sit in the same folder.
TELEGRAM_SESSION_PATH=/data/telegram.session

# Log in interactively. This writes the session file.
docker compose -f docker-compose.dev.yml exec -it api python scripts/telegram/telegram_login.py

# A second, named session (adapter_config.session_name = "osint"):
docker compose -f docker-compose.dev.yml exec -it api python scripts/telegram/telegram_login.py --session osint
```

A named session lives at `{folder of TELEGRAM_SESSION_PATH}/osint.session`.
The session file is as sensitive as the account's password.
`scripts/telegram/telegram_join.py` joins a channel with the session account.

**How a fetch works:**

- The first fetch reads messages from the last `max_message_age_days`. Later
  fetches read messages newer than `last_seen_id`, oldest first.
- **GUID:** `telegram:{channel_id}:{message_id}`.
- **Link:** `t.me/{username}/{id}` for public channels, `t.me/c/{id}/{id}`
  for private ones.
- **Title:** the first line of the message, else "Message {id}".
- **Body:** Telegram's formatting (bold, code, links, mentions) is turned
  into HTML. A forwarded message gets a "Forwarded from …" line.
- **Metadata:** `message_id`, `channel_id`, `channel_username`, `edited_at`,
  `views`, `reactions`, and `forwarded_from` when forwarded.
- **Albums:** Telegram sends an album of N photos as N messages. The adapter
  merges them into one entry: the message with the caption is the entry, and
  the other photos go into `additional_media`.
- **Media:** attachments of the chosen types up to `TELEGRAM_MAX_MEDIA_SIZE_MB`
  (default 25) are downloaded. Videos also get a thumbnail. See
  [Telegram Operations](#telegram-operations) for storage.
- **Flood waits:** when Telegram says "slow down", the adapter keeps what it
  has so far and stops. `last_seen_id` only moves past messages actually
  read.
- **Handles:** `t.me/s/<name>` preview links are turned into the plain
  channel name.
- **One login per process:** the session file is read once per process, then
  Telethon runs from an in-memory copy. That stops the api, listener and
  worker from fighting over the file ("database is locked").

**Edits and deletes.** After each fetch the worker re-reads the last
`edit_probe_window` saved messages. An edited message gets its text updated
and goes through the entry pipeline again. A deleted message is not removed:
it gets `metadata.telegram_deleted_at`, because a Telegram hiccup can look
like a delete.

#### Auto-attribution

Many Telegram channels *are* the threat actor (leak sites, hacktivist
channels). If the feed's `adapter_config` has `threat_actor_id` or
`campaign_id`, every new entry is linked to that actor (confidence `high`) or
added to that campaign. `author_entity`
(`{"type": "threat_actor" | "vendor" | "product", "id": "<uuid>"}`) does the
same for any API feed whose author is a known entity. Repeat links are
ignored, so this never fails an ingest.

---

### Telegram Operations

**Realtime listener** (`backend/app/workers/telegram_listener.py`)

A long-running process in its own container (`telegram-listener`, command
`python -m app.workers.telegram_listener`), not a Celery task. It stays
connected to Telegram and watches every channel whose feed has
`adapter_config.realtime = true`. When a message arrives it queues
`fetch_feed` for that feed (waiting 1.5 seconds to group bursts), so the
normal fetch does all the work.

- Normal polling keeps running, so messages still arrive if the listener
  stops.
- Every 5 minutes it re-reads the database for feeds that turned realtime on
  or off.
- Every 30 seconds it writes a heartbeat to Redis
  (`intelfeed:telegram_listener:heartbeat`). `GET /api/telegram/listener/status`
  reports `running: false` when the heartbeat is more than 2 minutes old.
- Without `TELEGRAM_API_ID` and `TELEGRAM_API_HASH` it sits idle instead of
  exiting, so the container doesn't restart in a loop. Restart it after you
  log in.

**Channel discovery** (`backend/app/api/telegram.py`)

- `GET /api/telegram/discover` lists every channel the logged-in account has
  joined, marked `is_subscribed`, with channels not yet added listed first.
- `GET /api/telegram/feeds/{id}/health` shows one feed's state: the resolved
  channel, `last_seen_id`, any flood wait, edited and deleted counts for the
  last 7 days, the session name, and the channel's subscriber count when
  available.

**Link mentions** (`backend/app/workers/telegram_link_tasks.py`)

A stage of the entry pipeline finds `t.me` links in entries from
**non-Telegram** feeds and records which channels are being mentioned
(`telegram_channel_mentions`, `telegram_link_mentions`).
`GET /api/telegram/mentions` lists channels your feeds mention that you
don't read yet. You can dismiss them, or subscribe with
`POST /api/telegram/mentions/{id}/subscribe`, which creates a Telegram feed.
Invite-only channels are refused: join them first.

**Forward graph** (`backend/app/workers/intel_feed_tasks.py`)

`build_telegram_forward_relationships` runs every 4 hours. When a channel
attributed to actor X forwards a message from a channel attributed to actor
Y, it records a `communicates_with` relationship between the two actors
(confidence `probable`, source `auto_extracted`, up to 50 evidence entries).

**Album repair** (`backend/app/workers/telegram_backfill_tasks.py`)

`backfill_telegram_albums` merges album photos that were saved as separate
entries into the entry with the caption, then deletes the extras. Run it with
`backfill_telegram_albums.delay()` (optionally with a `feed_id`).

**Media storage and serving** (`backend/app/api/telegram_media.py`)

Telegram media has no public URL. The worker downloads it into
`TELEGRAM_MEDIA_DIR` (default `/app/data/telegram_media`, the shared
`telegram_media` volume used by the api, worker and listener), as
`<channel_id>/<message_id>.<ext>` plus `<message_id>.thumb.jpg` for video
thumbnails. Files are served by:

```text
GET /api/telegram-media/{channel_id}/{filename}
```

It needs a login token, in the `Authorization` header or as `?token=` (so
`<img>` and `<video>` tags work). File names are checked so a request can't
reach outside the media folder. Responses carry
`Cache-Control: private, max-age=86400`.

**Media cleanup** (`backend/app/workers/maintenance.py`)

- `cleanup_telegram_media` (Sundays 04:20 UTC) deletes files whose entry no
  longer exists. Media of soft-deleted messages is kept.
- `evict_old_telegram_media` (daily 04:25 UTC) deletes files older than
  `telegram_media_ttl_days` (default 30). The entries and their intelligence
  are kept; only the file goes.

---

### Web Scraper

**Type**: API. **File**: `backend/app/adapters/web_scraper.py`

For blogs with no RSS feed. It reads the blog's index page, finds article
links, and downloads each article.

| Setting | Default | Meaning |
| --- | --- | --- |
| `blog_url` | (required) | The index page. |
| `link_selector` | built-in list | CSS selector for article links. |
| `url_pattern` | none | Regular expression a link must match. |
| `max_articles` | 20 | Articles per fetch, at most 100. |
| `follow_pagination` | `false` | Also read the next index pages. |
| `pagination_selector` | built-in list | CSS selector for the "next page" link. |
| `max_pages` | 3 | Index pages to read, at most 10. |

- Only links on the same domain are kept. Login, about and similar pages, and
  links to images and PDFs, are skipped.
- Every request checks `robots.txt` and the per-domain rate limit (with
  `Crawl-delay` as the minimum gap).
- Up to 3 articles download at once, with the curl_cffi fallback for
  bot-protected sites.
- From each article it takes the title (`og:title` or `<title>`, without the
  site name), author, date, `og:image`, description, and the body
  (readability-lxml, then common article CSS selectors).
- **GUID:** SHA-256 of the article URL, cut to 32 characters.
- **Feed name:** the index page's `<title>`, else `og:title`, else
  `og:site_name`, else the host name. A feed created without a name is titled
  with its URL until the first fetch names it. A real name is never replaced.

---

### Ransomware Leak Sites (ransomware.live)

**Type**: API adapter with **no feed type**. **File**:
`backend/app/adapters/ransomware_live.py`

Reads ransomware leak-site victim postings from the ransomware.live v2
`/recentvictims` API. It is not in the adapter registry and never runs in the
feed loop, and its items are not saved as entries. Instead,
`app/intelligence/ransomware_sync.py` turns each one into a
`RansomwareVictim` (the organization) and a `VictimDisclosure` (the posting).

- Runs as the `sync-ransomware-victims` job every 30 minutes.
- The API can't filter by date, so the adapter keeps only postings
  discovered since the last run. The first run looks back 7 days.
- **GUID:** a hash of source, group, victim and discovery time
  (`make_disclosure_guid`), the same on every run.
- Each sync reads the group list from `/v2/groups` once (the API allows one
  call a minute), so group names can be matched to tracked threat actors by
  alias. A sync that creates new groups rebuilds the autolinker vocabulary.
- More sources can be added as sibling adapters with their own `SOURCE`
  name.
- Shown through `GET /api/ransomware/*` and the Workbench ransomware pages.
  Watchlist matches raise live alerts.

---

## OPML Import/Export

**File**: `backend/app/api/opml.py`

OPML is the standard file format feed readers use to share subscription
lists.

### Import

`POST /api/opml/import` takes an OPML file (up to 10 MB, parsed with
defusedxml so a hostile file can't attack the parser).

- An outline with children is a folder. An existing folder with the same name
  is reused; otherwise it is created.
- An outline with no folder goes in the default folder for its feed type.
- A feed whose URL already exists is skipped (and, with per-user
  subscriptions on, subscribed to).
- Outlines whose `xmlUrl` isn't `http(s)` are skipped (for example another
  reader's keyword monitors), except for API feed types.
- New feeds get a first fetch queued straight away.
- With per-user subscriptions off, import changes the shared feed list, so it
  is admin-only.

The plain OPML `type` attribute can only be `rss`, `atom`, `youtube` or
`podcast` (`PORTABLE_FEED_TYPES`); anything else becomes `rss`. That stops a
file from another reader creating, say, a `reddit` feed with no settings,
which could never fetch.

### The `intelfeed:` extension

IntelFeed adds its own attributes in the namespace
`https://intelfeed.app/ns/opml/1`. Other readers ignore them, so the file
still works elsewhere. On import they win over the plain attributes:

| Attribute | Feed field |
| --- | --- |
| `intelfeed:feedType` | `feed_type` (any type that has an adapter) |
| `intelfeed:config` | `adapter_config`, as JSON |
| `intelfeed:interval` | `fetch_interval_minutes` |
| `intelfeed:extractionMode` | `intel_extraction_mode` |
| `intelfeed:aiAnalysis`, `intelfeed:extractTools`, `intelfeed:extractRules`, `intelfeed:autoExtract` | The extraction switches (`true` / `false`) |
| `intelfeed:excludeTitles` | `exclude_title_patterns`, as a JSON list of phrases |

A bad attribute is dropped on its own; it doesn't fail the import.

```xml
<opml version="1.0" xmlns:intelfeed="https://intelfeed.app/ns/opml/1">
  <body>
    <outline text="Detection">
      <outline text="SigmaHQ rules" type="rss" xmlUrl="https://github.com/SigmaHQ/sigma"
               intelfeed:feedType="github_repo"
               intelfeed:config='{"owner":"SigmaHQ","repo":"sigma","paths":["rules/**/*.yml"]}' />
    </outline>
  </body>
</opml>
```

### Export

`GET /api/opml/export` downloads `intelfeed-subscriptions.opml`, grouped by
folder. With per-user subscriptions on, it holds the feeds you read.

- `type` is the real type when it is one of the four portable types, else
  `rss`.
- The `intelfeed:` attributes are written only when they differ from the
  defaults, so the file stays easy to compare.
- Secrets are never exported: `token`, `api_key` and `app_password` are left
  out of `intelfeed:config`, and so is `fetch_health`.

### Starter feed packs

A fresh install has no feeds. The starter packs in `backend/app/feed_packs/`
fix that: ten curated OPML files with the `intelfeed:` extension, listed in
`packs.json`. **Core** is the recommended one; the others are news and
government, vendor advisories, vendor research, detection engineering,
GitHub rule repos (needs a GitHub token), blogs, Reddit, YouTube and
podcasts. Telegram and Bluesky sources are never included, because they need
setup or credentials.

- The onboarding wizard reads them from `GET /api/opml/starter-packs` and
  imports with `POST /api/opml/starter-packs/import`.
- `scripts/seed/seed_feeds.py` imports them without the UI.
- `scripts/maintenance/audit_feed_packs.py` checks the packs for dead
  sources. Run it before a release.

---

## Manual Ingest

Not everything comes from a feed. Analysts can add material by hand with the
ingest button in the sidebar: files, a list of URLs, pasted text, or a GitHub
repository read once.

| File | Role |
| --- | --- |
| `backend/app/services/ingest_batches.py` | Runs batches |
| `backend/app/services/ingest_parsers.py` | One parser per file type |
| `backend/app/services/manual_ingest.py` | The Manual Uploads feed and the single-item routes |
| `backend/app/api/ingest.py` | The API, under `/api/entries` |

**The Manual Uploads feed.** Every hand-added entry belongs to one shared
feed, "Manual Uploads" (`url = "manual://uploads"`, `feed_type = "manual"`),
created the first time it is needed. It is never polled: it is created
inactive, and `fetch_feed` skips the `manual` type anyway. It uses
`intel_extraction_mode = "full"` with both extraction switches on, so uploads
get the fullest analysis. Batches are grouped by `metadata.batch_id`, not by
separate feeds.

**Batches**

- `POST /api/entries/ingest/batches` opens a batch. Items are added one per
  request: `.../files` (one file, multipart), `.../urls` (a JSON list) or
  `.../text` (a paste). Each item is queued for a worker as soon as it is
  added; there is no submit step. One file per request keeps a large drop
  under the 100 MB per-request limit of a Cloudflare proxy.
- The worker parses each item into **one normal entry** and sends it through
  the same entry pipeline as a polled entry. The AI analysis follows from its
  regular sweep. Entities the AI creates go through the same checks as
  always and can be reviewed in Settings → Engine, in the **Entities** view.
- **Every result is a status on the item, never a failed request:**

  | Status | Meaning |
  | --- | --- |
  | `queued` | Waiting for a worker |
  | `parsing` | A worker has it |
  | `created` | The entry exists |
  | `expanded` | A `.zip` or repo that became child items |
  | `duplicate` | Same URL or same bytes as an existing entry (`entry_id` points to it) |
  | `no_text` | Nothing to read (a scanned PDF, an empty file) |
  | `unsupported` | No parser for this type |
  | `too_large` | Over the size limit; not stored |
  | `failed` | Fetch or parse error; can be retried |
  | `cancelled` | Removed before a worker took it |

- `GET .../batches/{id}` returns every item and a summary. `created` items
  show a `phase` of `analyzing` until the AI analysis exists, then `done`. An
  `ingest_item_updated` live-update event fires on every change.
  `.../items/{item_id}/retry` retries an item and `DELETE .../items/{item_id}`
  cancels one. `GET /api/entries/ingest/capabilities` returns the limits.

**Originals are kept.** Each file (pastes too, as `.txt`) is saved under
`INGEST_FILES_DIR` (`<batch_id>/<file_id>.<ext>`, a folder shared by the api
and worker) and downloaded with `GET /api/ingest-files/{file_id}` (login
token in the header or `?token=`). The nightly `evict-old-ingest-files` job
deletes files older than `ingest_files_ttl_days` (default 180; 0 keeps them
forever) and sets the entry's `metadata.original_retained` to `false`. The
entry and its intelligence stay.

**Duplicates** are spotted by GUID:

| Source | GUID |
| --- | --- |
| URL | `manual:url:<sha256 of url>` |
| PDF | `manual:pdf:<sha256 of bytes>` |
| Other file or paste | `manual:file:<sha256 of bytes>` |
| GitHub repo file | `manual:github:<owner>/<repo>/<path>` |

**Entry metadata:** `source` (`url_ingest`, `pdf_upload`, `file_upload`,
`text_paste`, `github_repo`), `batch_id`, `ingest_item_id`, `ingest_file_id`,
`filename`, `file_content_type`, `size_bytes`, `original_retained`,
`uploaded_by`. The reader shows the original file (name, type, size,
Download) and a batch chip. The Manual Uploads feed's table view adds File,
Size and Original columns.

**Formats** (`ingest_parsers.py`; detected by extension, then content type,
then the file's first bytes):

- PDF (text plus page HTML with images, via PyMuPDF)
- HTML, plain text, Markdown
- CSV/TSV (shown as a table)
- `.eml` email (subject as title; attachments listed, not parsed)
- `.docx` (paragraphs, headings and tables)
- JSON, YAML, XML and logs (shown as code)
- `.zip` (one item per file inside, with a file count limit, a per-file size
  limit and protection against path tricks; zips inside zips are not opened)

There is no OCR: a scanned PDF ends as `no_text`.

**Indicator lists.** An item marked as an indicator list (`is_ioc_list`) is
saved with `metadata.content_type = "ioc_list"`. The observables stage then
reads it as a trusted list of IOCs (indicators of compromise) instead of
treating it as prose. Regular expressions alone never create an observable.

**GitHub repositories, read once.** A `github.com/owner/repo` URL (optionally
`/tree/<branch>/<path>`) on the URLs tab becomes a `github_repo` item. The
worker reads the repository once with the
[repository monitor](#github-repository-monitor)'s full-tree reader and makes
one child item per file. No feed is created and nothing polls afterwards. The
adapter's file types (Sigma, YARA, indicator lists for repos it knows) carry
over; an analyst's own indicator-list mark wins.

**The single-item routes** answer in the same request, for the Android app
and the `ingest_url` tool:

- `POST /api/entries/ingest/url` returns the entry, or `409 duplicate`, or
  `422 extraction_failed`.
- `POST /api/entries/ingest/pdf` runs as a one-item batch (so the original is
  kept) but still returns the entry, or `409`, `422`, `413 file_too_large` or
  `400 invalid_file`.

**Settings** (Settings → Engine):

| Setting | Default | Meaning |
| --- | --- | --- |
| `ingest_files_ttl_days` | 180 | Days to keep originals. 0 keeps them forever. |
| `ingest_max_file_mb` | 50 | Per-file limit, zip contents included. |
| `ingest_max_batch_items` | 200 | Items per batch, zip contents and repo files included. |
| `ingest_zip_max_members` | 100 | Files taken out of one `.zip`. |

`INGEST_FILES_DIR` is set only in the environment.

**Registry tools:** `ingest_url`, `ingest_text`, `ingest_file` (base64),
`ingest_batch` (URLs and texts), `get_ingest_batch`.

---

## Building a New Adapter

1. **Pick a base class.**
   - `BaseAdapter` if the user gives a URL and the worker can download it
     (RSS-like formats, HTML).
   - `ExtendedAdapter` if you build the requests yourself from settings, need
     credentials, or page through an API.

2. **Write the class** in `backend/app/adapters/` and return `ParsedEntry`
   objects. Each entry needs a `guid` that is unique and stable within the
   feed: that is how duplicates are spotted. Add a `metadata["source"]` name.

   ```python
   from app.adapters.base import ExtendedAdapter, ParsedEntry, ParsedFeedMeta

   class MyAdapter(ExtendedAdapter):
       async def fetch_entries(self, config, since=None):
           entry = ParsedEntry(
               guid="unique-id-for-this-item",
               url="https://example.com/article",
               title="Article Title",
               content_html="<p>Article body</p>",
               metadata={"source": "my_adapter"},
           )
           return self.get_feed_meta(config), [entry]

       def get_feed_meta(self, config):
           return ParsedFeedMeta(title="My source")
   ```

3. **Register it** in `backend/app/adapters/__init__.py`: URL feeds in
   `_ADAPTERS`, API adapters in `_EXTENDED_ADAPTERS`, and the class in
   `__all__`. `is_extended_feed_type()`, `get_extended_adapter()` and
   `known_feed_types()` read those dicts, and the feed API and OPML import
   check feed types against `known_feed_types()`. No migration is needed:
   `feed_type` is a plain text column (up to 30 characters).

4. **Add it to the UI.** The add-feed form and the feed settings need fields
   for its settings (`frontend/src/components/AddFeedModal.tsx`,
   `frontend/src/components/feedModal/panes/adapterFields.tsx`) and an icon
   (`frontend/src/components/FeedTypeIcon.tsx`).

5. **Handle errors.** Log with enough context to debug (feed, endpoint). An
   exception from `fetch_entries()` counts as a failed fetch, with the
   message saved in `last_error`. For a quiet "nothing this time" (a 429, say)
   return an empty list instead.

6. **Keep state between fetches** by returning it in
   `feed_meta.extra["_adapter_state"] = {...}` (Bluesky does this with
   `last_seen_cid`). The worker merges it into `adapter_config` after a good
   fetch. The worker also passes a temporary `_feed_id` in `config` for
   per-feed caches; it is never saved.

7. **Test it.** Adapter tests live in `backend/tests/` (for example
   `test_adapters.py`, `test_bluesky_adapter.py`).

   ```python
   @pytest.mark.asyncio
   async def test_fetch_entries():
       meta, entries = await MyAdapter().fetch_entries({"setting": "value"})
       assert entries and entries[0].guid and entries[0].title
   ```

---

## See Also

- [architecture.md](architecture.md): system design, entity extraction,
  correlation events.
- [entries.md](entries.md): the entry lifecycle, fields and cleaning.
- [entity-profiles.md](entity-profiles.md): how entities are modelled.
- [engine-settings.md](engine-settings.md): the settings mentioned here.
