# Adapters and Feed Ingestion

This document provides a comprehensive reference for IntelFeed's pluggable adapter architecture and feed polling infrastructure. It covers how adapters work, how feeds are polled and ingested, and details specific to each supported feed type.

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

IntelFeed is a self-hosted threat intelligence RSS aggregator built on a modular adapter system. Each **feed type** (RSS, YouTube, Reddit, GitHub, etc.) has a corresponding **adapter** that knows how to fetch and normalize entries from that source.

The system supports two adapter patterns:

- **BaseAdapter**: Parses raw feed content (XML, HTML, etc.) into normalized entries.
- **ExtendedAdapter**: Makes direct API calls to fetch entries without requiring the user to provide a feed URL.

Both return a common set of normalized data structures (`ParsedEntry`, `ParsedFeedMeta`, `ParsedMedia`) that the feed polling loop (`poll_due_feeds`) consumes.

---

## Architecture

See diagram: [Feed ingestion pipeline](diagrams/adapters-ingest-pipeline.md)

In short: Celery Beat runs `poll_due_feeds()` every 60 seconds, which dispatches `fetch_feed(feed_id)` tasks guarded by Redis NX locks. Each fetch goes through conditional GET, per-domain rate limiting, and the appropriate adapter (`BaseAdapter.parse_entries()` or `ExtendedAdapter.fetch_entries()`), then normalized entries are deduplicated, sanitized, enriched (full-text extraction, lead images, transcripts), persisted, indexed in Meilisearch, and handed to the entry processing pipeline (autolink, intel extraction, post-processing, signal scoring).

---

## Adapter Base Classes

### BaseAdapter

**File**: `backend/app/adapters/base.py:61-103`

Base class for feed sources that require the user to provide a feed URL.

```python
class BaseAdapter(ABC):
    @abstractmethod
    def parse_entries(self, feed_url: str, content: str) -> tuple[ParsedFeedMeta, list[ParsedEntry]]:
        """Parse raw feed content and return (feed_metadata, entries)."""
```

**Key responsibilities**:
- Parse raw feed content (XML, HTML) into normalized `ParsedEntry` objects.
- Extract feed-level metadata (`title`, `description`, `icon_url`, language, etc.)
- Detect and handle format-specific metadata (e.g., iTunes namespace for podcasts).
- Auto-detect feed type via `detect_feed_type()` if initialized as generic RSS.

**Data structures**:

```python
@dataclass
class ParsedEntry:
    guid: str                           # Unique per feed
    url: str | None = None
    title: str = "Untitled"
    author: str | None = None
    content_html: str | None = None     # Sanitized by worker
    summary: str | None = None
    published_at: datetime | None = None
    metadata: dict = field(default_factory=dict)  # Adapter-specific state
    media: ParsedMedia | None = None    # Primary attachment
    # Extra attachments — only Telegram populates this today, when an album of
    # grouped messages collapses into a single entry
    additional_media: list[ParsedMedia] = field(default_factory=list)

@dataclass
class ParsedMedia:
    media_type: str                  # audio, video, image, document
    url: str
    mime_type: str | None = None
    file_size: int | None = None
    duration_seconds: int | None = None
    thumbnail_url: str | None = None
    transcript_url: str | None = None
    metadata: dict = field(default_factory=dict)

@dataclass
class ParsedFeedMeta:
    title: str | None = None
    description: str | None = None
    site_url: str | None = None
    icon_url: str | None = None
    language: str | None = None
    # Podcast-specific
    podcast_author: str | None = None
    podcast_categories: list[str] = field(default_factory=list)
    podcast_explicit: bool = False
    podcast_type: str = "episodic"
    podcast_artwork_url: str | None = None
    # Generic adapter state (e.g., GitHub head SHA)
    extra: dict = field(default_factory=dict)
```

### ExtendedAdapter

**File**: `backend/app/adapters/base.py:106-129`

Base class for API-based sources (Reddit, GitHub, NVD, etc.).

```python
class ExtendedAdapter(ABC):
    @abstractmethod
    async def fetch_entries(self, config: dict, since: datetime | None = None) 
        -> tuple[ParsedFeedMeta, list[ParsedEntry]]:
        """Fetch entries from the external source."""

    @abstractmethod
    def get_feed_meta(self, config: dict) -> ParsedFeedMeta:
        """Return feed metadata without fetching entries."""
```

**Key responsibilities**:
- Manage API authentication and rate limiting.
- Construct the correct API endpoint(s) from `config`.
- Paginate/scroll through results if needed.
- Return the same normalized data as BaseAdapter.

---

## Feed Model & Type Detection

### Feed Model

**File**: `backend/app/models/feed.py`

The `Feed` model stores subscription metadata and adapter configuration:

```python
class Feed(Base):
    id: UUID                            # Primary key
    title: str                          # Display name
    url: str                            # Unique; feed URL or API endpoint
    feed_type: str                      # 'rss', 'atom', 'youtube', 'podcast', 'reddit', 'github_releases', ...
    site_url: str | None                # Canonical website URL
    icon_url: str | None
    description: str | None
    language: str | None
    is_active: bool                     # Inactive feeds are never polled
    
    # Polling state
    last_fetched_at: datetime | None
    fetch_interval_minutes: int         # Default 30
    etag: str | None                    # For conditional GET
    last_modified: str | None           # For conditional GET
    
    # Error tracking
    error_count: int                    # Incremented on failure; reset on success
    last_error: str | None              # Last HTTP or parse error
    
    # Adapter-specific config (JSON)
    adapter_config: dict                # E.g. {'subreddit': 'netsec', 'limit': 50}
    
    # Intelligence extraction
    auto_extract_on_ingest: bool        # Auto-extract CVEs, TTPs, etc.
    extract_detection_rules: bool       # Auto-extract SIGMA, YARA, etc.
    intel_extraction_mode: str          # 'full', 'selective', 'manual', 'none'
    
    # Source quality ratings
    reliability_rating: str | None      # A-F
    timeliness_rating: str | None
    relevance_rating: str | None
    analyst_notes: str | None
```

### Type Detection

**File**: `backend/app/adapters/base.py:80-103`

The `BaseAdapter.detect_feed_type()` static method auto-detects feed type from URL and content:

```python
@staticmethod
def detect_feed_type(url: str, content: str) -> str:
    """Detect feed type from URL and content."""
    import feedparser
    
    if "youtube.com" in url:
        return "youtube"
    
    parsed = feedparser.parse(content)
    
    # Podcast detection: iTunes namespace or audio enclosures
    feed = parsed.feed
    if hasattr(feed, "itunes_type") or hasattr(feed, "itunes_author"):
        return "podcast"
    
    for entry in parsed.entries[:5]:
        for enclosure in getattr(entry, "enclosures", []):
            if enclosure.get("type", "").startswith("audio/"):
                return "podcast"
    
    # Atom feeds have explicit version
    if "atom" in getattr(parsed, "version", "").lower():
        return "atom"
    
    return "rss"  # default
```

This is called during `_fetch_feed()` (line 366-373 of `feed_tasks.py`) if the feed type is still generic.

---

## Feed Polling Loop

### Celery Beat Task: `poll_due_feeds()`

**File**: `backend/app/workers/feed_tasks.py:173-212`

Runs every 60 seconds (beat default from `workers/job_registry.py`). Finds feeds due for polling and dispatches fetch tasks:

```python
@celery_app.task(name="app.workers.feed_tasks.poll_due_feeds", soft_time_limit=120)
def poll_due_feeds():
    """Check for feeds that are due for polling and dispatch fetch tasks."""
    run_async(_poll_due_feeds())

async def _poll_due_feeds():
    # Find feeds where:
    # - is_active = TRUE
    # - last_fetched_at is NULL OR NOW() > last_fetched_at + fetch_interval_minutes
    # Order by last_fetched_at ASC NULLS FIRST (oldest first)
    # Limit 50 per cycle to avoid monopolizing the worker
    
    # For each feed, try to acquire a Redis NX lock (10-minute TTL)
    lock_key = f"feed_fetch:{feed_id}"
    if r.set(lock_key, "1", nx=True, ex=600):
        fetch_feed.delay(feed_id)  # Dispatch to queue
```

**Purpose**: Prevents duplicate in-flight fetches for the same feed. The lock is explicitly released in `fetch_feed`'s `finally` block, so a finished feed can be re-dispatched before the TTL expires.

### Task: `fetch_feed()`

**File**: `backend/app/workers/feed_tasks.py:215-243`

Fetches and parses a single feed with automatic retries:

- **Max retries**: 3
- **Soft time limit**: 10 minutes (600s) → graceful shutdown
- **Hard time limit**: 11 minutes (660s) → forceful kill
- **Exponential backoff**: `2^retries * 10 + random(0-10)` seconds, capped at 300s
- **Error tracking**: Increments `feed.error_count` on failure; resets to 0 on success

### Core Fetch Logic: `_fetch_feed()`

**File**: `backend/app/workers/feed_tasks.py:246-627`

Implements the full feed ingestion pipeline:

#### 1. Determine Adapter Type
```python
from app.adapters import is_extended_feed_type

if is_extended_feed_type(feed.feed_type):
    await _fetch_extended_feed(db, feed)
    return
```

Pseudo-feeds with nothing to fetch (`NON_FETCHABLE_FEED_TYPES`, currently `manual` — e.g. the `manual://` uploads feed) are skipped instead of erroring every cycle.

#### 2. Rate Limiting
```python
from app.services.rate_limiter import acquire_rate_limit

if not await acquire_rate_limit(feed.url):
    logger.warning(f"Rate limited for feed {feed.id}, will retry on next poll")
    return
```

Per-domain Redis-backed rate limiter (default interval with per-domain overrides). Article-level fetches (full-text extraction, og:image, web scraper) additionally honor `robots.txt` `Crawl-delay` as a floor.

#### 3. Conditional GET (HTTP 304 Not Modified)
```python
headers = _feed_request_headers(user_agent)  # UA + browser-like Accept/Accept-Language
# User-Agent: system_settings DB override > env default
if feed.etag:
    headers["If-None-Match"] = feed.etag
if feed.last_modified:
    headers["If-Modified-Since"] = feed.last_modified

response = await client.get(feed.url, headers=headers)

if response.status_code == 304:
    # Not modified; skip ingestion
    feed.last_fetched_at = datetime.now(timezone.utc)
    db.add(feed)
    await db.commit()
    return
```

Saves bandwidth and API quota.

#### 4. YouTube Retry Logic (Quirk)
```python
# YouTube feed API returns spurious 404/500s — retry up to 2 times
if feed.feed_type == "youtube" and response.status_code in (404, 500, 502, 503):
    for _retry in range(2):
        await asyncio.sleep(5)
        try:
            response = await client.get(feed.url)
            if response.status_code == 200:
                break
        except httpx.HTTPError:
            pass
```

**Other non-200 responses** increment `feed.error_count`, record `last_error = "HTTP {status}"`, and create a `feed_error` correlation event once `error_count >= 3` (see [Feed Reliability & Breakage Alerts](#feed-reliability--breakage-alerts)). After 3+ consecutive HTTP 404s on an rss/atom/podcast feed, `_attempt_feed_url_autodiscovery()` fetches the site homepage, parses RSS/Atom autodiscovery `<link>` tags, verifies the first working candidate actually parses as a feed, and repoints `feed.url` (audit trail kept in `adapter_config.url_autodiscovery_history`).

#### 5. Parse with Adapter
```python
from app.adapters import get_adapter

adapter = get_adapter(feed.feed_type)
feed_meta, parsed_entries = adapter.parse_entries(feed.url, response.text)
```

**Silent failure detection**: an rss/atom feed that returns HTTP 200 with an HTML content-type and zero parsed entries (a deprecated feed URL now serving the site's HTML page) is treated as an error, not an empty poll.

#### 6. Entry Deduplication

**GUID-based deduplication** (primary):
```python
existing = await db.execute(
    select(Entry).where(Entry.feed_id == feed.id, Entry.guid == parsed.guid)
)
if existing.scalar_one_or_none():
    continue  # Skip; GUID already seen
```

**Content-hash deduplication** (cross-feed, catches republishes):
```python
content_hash = compute_content_hash(parsed.title, content_text)

existing = await db.execute(
    select(Entry.id).where(Entry.content_hash == content_hash).limit(1)
)
if existing.scalar_one_or_none():
    logger.debug("Skipping content-hash duplicate %s for feed %s", parsed.guid, feed.id)
    continue
```

Prevents exact duplicates even when GUIDs change (e.g., WordPress republish).

#### 7. YouTube Shorts Filtering
```python
if feed.feed_type == "youtube" and feed.adapter_config.get("exclude_shorts"):
    from app.services.youtube import filter_shorts
    
    video_ids = [p.metadata.get("video_id") for p in new_parsed_entries if p.metadata.get("video_id")]
    if video_ids:
        short_ids = await filter_shorts(video_ids)
        new_parsed_entries = [p for p in new_parsed_entries if p.metadata.get("video_id") not in short_ids]
```

Async HEAD requests to `youtube.com/shorts/{video_id}` classify videos as Shorts or full-length.

#### 8. Full-Text Extraction (for RSS)
```python
# For RSS articles with short summaries, fetch full article content
if feed.feed_type in ("rss", "atom") and parsed.url:
    content_text_plain = html_to_text(content_html) if content_html else ""
    is_truncated = bool(re.search(r"Continue reading on .+\s*»", content_text_plain))
    
    if is_truncated or len(content_text_plain) < 500:
        extracted, og_image = await _extract_full_text(parsed.url)
        if extracted:
            content_html = extracted
```

Extraction strategy (`_extract_full_text()`):
1. **Google News resolution**: `news.google.com` wrapper URLs are decoded to the real publisher URL first (via `googlenewsdecoder`); `parsed.url` is also rewritten so "Open original" links point at the canonical article.
2. **Fetch**: httpx, falling back to **curl_cffi** (browser impersonation) on 403/429/503 bot challenges; Medium-hosted domains go straight to curl_cffi. Checks `robots.txt` and rate limits per domain.
3. **Extract**: Medium gets a dedicated `<article><section>` extractor (readability misses their DOM); everything else tries **readability-lxml**, then a CSS-selector fallback for known article-body patterns (`div.article-body`, `div.entry-content`, etc.).

Capped at 25 extractions per cycle to avoid monopolizing workers.

#### 9. HTML Sanitization & Proxy
```python
from app.services.sanitizer import sanitize_html, html_to_text

sanitized_html = sanitize_html(content_html) if content_html else None
content_text = html_to_text(content_html) if content_html else None
word_count = len(content_text.split()) if content_text else None
```

Uses **nh3** (Rust HTML sanitizer) to allow safe tags but strip scripts, XSS vectors, etc.

#### 10. Image Extraction & Proxying
```python
image_url = (extract_first_image(content_html, base_url=parsed.url) if content_html else None) 
            or extract_first_image(parsed.summary or "", base_url=parsed.url)

if not image_url and og_image:
    image_url = og_image
```

Prioritizes:
1. First `<img>` in content
2. First `<img>` in summary
3. og:image captured during full-text extraction
4. Dedicated og:image fetch (`_fetch_og_image()` — streams only the first 50KB of the article page, shares the 25-per-cycle cap)

The frontend rewrites the stored URL through the image proxy for display.

#### 11. Create Entry & Media Records
```python
entry = Entry(
    feed_id=feed.id,
    guid=parsed.guid,
    url=parsed.url,
    title=parsed.title,
    author=parsed.author,
    content_html=sanitized_html,
    content_text=content_text,
    summary=parsed.summary,
    image_url=image_url,
    published_at=min(parsed.published_at, datetime.now(UTC)) if parsed.published_at else None,  # clamp future dates
    word_count=word_count,
    content_hash=content_hash,
    metadata_=parsed.metadata,
)
db.add(entry)
await db.flush()  # inside a SAVEPOINT; unique-violation races are skipped, not fatal

# Create media record (shared helper)
await _create_entry_media(db, feed, entry, parsed)
```

#### 12. Meilisearch Indexing
```python
from app.services.meilisearch_client import index_entry

try:
    index_entry(
        entry_id=entry.id,
        feed_id=feed.id,
        title=parsed.title,
        content_text=entry.content_text,
        summary=parsed.summary,
        author=parsed.author,
        published_at=parsed.published_at.isoformat() if parsed.published_at else None,
        feed_type=feed.feed_type,
        feed_title=feed.title,
        language=entry.language,
        word_count=entry.word_count,
    )
except Exception as meili_exc:
    # Queue for retry
    r.sadd("meili:failed_entry_ids", str(entry.id))
```

#### 13. Update Feed Metadata
```python
feed.last_fetched_at = datetime.now(timezone.utc)
feed.etag = response.headers.get("etag")
feed.last_modified = response.headers.get("last-modified")
feed.error_count = 0
feed.last_error = None

# Update feed title/description from parsed metadata if missing
if feed_meta.title and not feed.title:
    feed.title = feed_meta.title
```

#### 14. Broadcast & Automation
```python
broadcast_event("feed_fetched", {"feed_id": ..., "new_entries": n, "entry_ids": [...]})  # SSE

for eid in new_entry_ids:
    run_entry_automations.delay(eid, str(feed.id))  # user automation rules
```

#### 15. Dispatch Entry Processing Pipeline
```python
run_extraction = bool(feed.auto_extract_on_ingest or feed.extract_detection_rules)
feed_plan = await resolve_feed_plan(db, feed)          # per-feed pipeline plan
translate_target = _auto_translate_target(feed)        # adapter_config.auto_translate
for eid in new_entry_ids:
    dispatch_entry_pipeline(eid, run_extraction=run_extraction, plan=feed_plan, translate_target=translate_target)
```

Uses a **Celery chord** to run autolink + extraction in parallel, then post-processing (correlation, requirements) once both complete, then signal scoring as a final callback. Stage composition comes from `app/pipeline/registry.py`; feeds with `auto_translate` set get a translate stage chained ahead of the chord so all downstream stages see the translated text.

#### 16. Check Keyword Alerts
```python
await _check_keyword_alerts(db, new_entry_ids, feed)
```

Dispatches real-time notifications for highlight keywords configured with `alert_enabled=True`.

---

## Entry Deduplication & Processing

### Deduplication Strategy

**GUID** (per feed):
```python
existing = await db.execute(
    select(Entry).where(Entry.feed_id == feed.id, Entry.guid == parsed.guid)
)
```

Fastest check; catches feed re-publishes of the same ID.

**Content Hash** (global):
```python
content_hash = compute_content_hash(parsed.title, content_text)

existing = await db.execute(
    select(Entry.id).where(Entry.content_hash == content_hash).limit(1)
)
```

Catches articles republished under different GUIDs (e.g., WordPress updates, feed ID resets).

### HTML Sanitization

Uses **nh3** library (Rust-based, sandboxed HTML parser):
- Allows safe tags: `<p>`, `<a>`, `<img>`, `<blockquote>`, `<code>`, `<pre>`, etc.
- Strips scripts, event handlers, `<iframe>`, `<embed>`.
- Preserves links but adds `rel="noopener noreferrer nofollow"`.

### Image Proxying

`sanitize_html()` rewrites every `<img src>` in entry content to IntelFeed's proxy endpoint (`/api/proxy/image?url=...`) at ingest time, to:
- Avoid leaking user IP to external hosts.
- Cache images locally.
- Handle redirects gracefully.

Telegram-downloaded media (`/api/telegram-media/...`) is served by IntelFeed's own auth-gated route and is never proxied.

### Transcript Handling

All handled by the shared `_create_entry_media()` helper (`feed_tasks.py:688-770`), which also persists any `additional_media` (e.g. Telegram album items) as sibling `EntryMedia` rows:

**For YouTube**: Auto-fetches transcript via **youtube-transcript-api**.

**For Podcasts**: Extracts `transcript_url` from Podcast 2.0 namespace and fetches it during entry creation.

**For Telegram**: OCR images with **Tesseract** if `settings.telegram_ocr_enabled` — runs synchronously inside the fetch task so OCR text lands before the autolink pipeline dispatches.

Fetched transcripts are appended to `entry.content_html` / `content_text` so they're searchable and visible to intel extraction.

---

## Feed Reliability & Breakage Alerts

Fetch failures feed a breakage-alerting layer on top of the polling loop:

- **`error_count` semantics**: incremented on every failed fetch (HTTP error, non-200, adapter exception, non-feed response), reset to 0 on any success — so it counts *consecutive* failures.
- **`feed_error` correlation events**: `_maybe_create_feed_error_event()` creates a correlation event (via `app/intelligence/correlation_events.py`) once `error_count >= 3`, surfacing broken feeds in the events stream.
- **`check_feed_health` beat task** (`backend/app/workers/feed_tasks.py:1642`, every 6 hours): creates `feed_stale` events for active, recently-polled feeds whose newest entry is older than 120 days, and `feed_error` events for feeds with 3+ consecutive errors.
- **`GET /api/feeds/health/failing`** (`api/feeds.py`): lists active feeds with `error_count >= threshold` (default 5). Feeds rated A/B for reliability are flagged `is_high_value` and sorted first so alerting UIs can highlight them.
- **`GET /api/feeds/{feed_id}/analytics`**: per-feed source analytics (`app/intelligence/source_analytics.py`) — volume, intel yield, and the analyst-assigned reliability ratings.
- **404 recovery**: persistent 404s trigger RSS autodiscovery and automatic URL repointing (see the polling loop above).

---

## Per-Adapter Details

### RSS/Atom

**Type**: BaseAdapter  
**File**: `backend/app/adapters/rss.py`

Uses **feedparser** library to parse RSS 2.0 and Atom feeds.

**Entry extraction**:
```python
def parse_entries(self, feed_url: str, content: str) -> tuple[ParsedFeedMeta, list[ParsedEntry]]:
    parsed = feedparser.parse(content)
    
    for item in parsed.entries:
        guid = item.get("id") or item.get("link") or item.get("title")
        
        # Try content > summary > description
        content_html = ""
        if item.get("content"):
            content_html = item.content[0].get("value", "")
        elif item.get("summary"):
            content_html = item.summary
        elif item.get("description"):
            content_html = item.description
        
        published_at = _parse_date(item)  # From published_parsed or updated_parsed
```

**Feed metadata extraction**:
- `title`, `description` (or `subtitle`), `link` (site_url), `image.href` (icon_url), `language`.

**Quirks**:
- Summaries longer than 500 chars are truncated with an ellipsis; title/GUID capped at 2000 chars.
- Date parsing via `calendar.timegm()` to handle feedparser's internal time tuple format.

---

### YouTube

**Type**: BaseAdapter  
**File**: `backend/app/adapters/youtube.py`

Parses YouTube Atom feeds (namespace-aware).

**Entry extraction**:
```python
# Extract video ID from feed entry
video_id = item.get("yt_videoid") or re.match(YT_VIDEO_RE, guid).group(1)

# Thumbnail: try media:thumbnail or construct from video_id
thumbnail_url = media_thumbnail[0].get("url") or f"https://i.ytimg.com/vi/{video_id}/hqdefault.jpg"

# Media statistics: view_count, star_rating
media_stats = item.get("media_statistics")
view_count = int(media_stats.get("views", 0)) if media_stats.get("views") else None

entry = ParsedEntry(
    guid=guid,
    url=f"https://www.youtube.com/watch?v={video_id}",
    title=item.get("title", "Untitled"),
    author=item.get("author") or parsed.feed.get("title"),
    content_html=_format_description(description),  # Plain text → HTML with links
    summary=description[:500],
    published_at=published_at,
    metadata={
        "video_id": video_id,
        "channel_id": channel_id or item.get("yt_channelid"),
        "channel_name": ...,
        "view_count": view_count,
        "star_rating": star_rating,
        "embed_url": f"https://www.youtube.com/embed/{video_id}",
    },
    media=ParsedMedia(
        media_type="video",
        url=video_url,
        mime_type="text/html",
        thumbnail_url=thumbnail_url,
    ),
)
```

**Quirks**:
- Shorts filtering: Can be enabled in `adapter_config.exclude_shorts`. Detection is a HEAD request to `youtube.com/shorts/{video_id}` — 200 means Short, redirect means regular video (fail-open).
- Description formatting: Converts plain-text URLs to `<a>` tags; preserves newlines as `<br>`.
- Retry logic: YouTube feed API has spurious 404s; feed_tasks retries up to 2 times with 5s delay.

---

### Podcast

**Type**: BaseAdapter  
**File**: `backend/app/adapters/podcast.py`

Parses podcast RSS with iTunes and Podcast 2.0 namespace extensions.

**Feed metadata extraction**:
```python
meta = ParsedFeedMeta(
    title=feed.get("title"),
    description=feed.get("description") or feed.get("subtitle"),
    site_url=feed.get("link"),
    language=feed.get("language"),
    podcast_author=getattr(feed, "itunes_author", None) or feed.get("author"),
    podcast_categories=[tag.get("term") for tag in feed.tags if tag.get("term")],
    podcast_explicit=_parse_explicit(getattr(feed, "itunes_explicit", None)),
    podcast_type=getattr(feed, "itunes_type", "episodic") or "episodic",  # episodic or serial
    podcast_artwork_url=itunes_image.get("href") or feed.itunes_image.get("href"),
)
```

**Episode extraction**:
```python
for item in parsed.entries:
    # Audio enclosure (first audio/* MIME type)
    audio_url = None
    for enclosure in item.enclosures:
        if enclosure.type.startswith("audio/") or enclosure.type == "application/octet-stream":
            audio_url = enclosure.href
            audio_mime = enclosure.type or "audio/mpeg"
            audio_size = int(enclosure.length) or None
            break
    
    # Duration from itunes:duration (HH:MM:SS, MM:SS, or seconds)
    duration_seconds = parse_duration(getattr(item, "itunes_duration", None))
    
    # Episode metadata
    entry_metadata = {
        "episode_number": int(getattr(item, "itunes_episode", None)) or None,
        "season_number": int(getattr(item, "itunes_season", None)) or None,
        "episode_type": getattr(item, "itunes_episodetype", "full"),
        "is_explicit": _parse_explicit(getattr(item, "itunes_explicit", None)),
    }
    
    # Media: audio + transcript URL
    media = ParsedMedia(
        media_type="audio",
        url=audio_url,
        mime_type=audio_mime,
        file_size=audio_size,
        duration_seconds=duration_seconds,
        thumbnail_url=episode_artwork or artwork_url,
        transcript_url=getattr(item, "podcast_transcript", {}).get("url"),
    ) if audio_url else None
```

**Quirks**:
- Podcast show metadata (author, categories, explicit flag, type) stored in separate `Podcast` model.
- Transcript URLs fetched asynchronously during entry creation.
- Duration parsing handles multiple formats: `"1:23:45"`, `"12:30"`, or `"3600"` (seconds).

---

### Reddit

**Type**: ExtendedAdapter  
**File**: `backend/app/adapters/reddit.py`

Fetches posts from a subreddit's public `/hot.rss` feed. There is no JSON API path — Reddit blocks unauthenticated JSON access.

**Configuration**:
```python
{
    "subreddit": "netsec",          # Required
    "limit": 50,                    # Max 100
}
```

**Fetch**:
```python
url = f"https://www.reddit.com/r/{subreddit}/hot.rss?limit={limit}"
# Parsed with feedparser

for idx, item in enumerate(parsed.entries):
    entry = ParsedEntry(
        guid=hashlib.sha256(guid_raw.encode()).hexdigest()[:32],  # guid_raw = item id or link
        url=item.link,
        title=item.title,
        author=_clean_author(item.author),   # strips "/u/" prefix
        content_html=item.content or item.summary,
        published_at=published,
        metadata={
            "source": "reddit",
            "subreddit": subreddit,
            "reddit_url": item.link,
            "hot_rank": idx + 1,
            # Synthetic engagement proxy: RSS exposes no real score, but /hot.rss
            # is already ordered by Reddit's hot algorithm, so rank position keeps
            # the digest's "top posts" sort working.
            "score": max(limit - idx, 1),
        },
    )
```

**Quirks**:
- GUID is a truncated SHA-256 hash of the RSS item ID (or link).
- No `since` filtering: deduplication handled entirely in `feed_tasks.py` (GUID-based).
- No real engagement metrics — `score` is synthesized from the item's `/hot.rss` rank position.

---

### GitHub (Releases & Advisories)

**Type**: ExtendedAdapter  
**File**: `backend/app/adapters/github.py`

Two separate adapters for different GitHub data:

#### GitHubReleasesAdapter

**Configuration**:
```python
{
    "owner": "foo",
    "repo": "bar",
    "include_prereleases": false,
    "token": "ghp_...",  # Optional; increases rate limit
}
```

**Fetch**:
```python
url = f"https://api.github.com/repos/{owner}/{repo}/releases?per_page=30"

for rel in releases:
    if rel.get("draft"):
        continue
    if not include_prereleases and rel.get("prerelease"):
        continue
    
    entry = ParsedEntry(
        guid=hashlib.sha256(str(rel.get("id")).encode()).hexdigest()[:32],
        url=rel.get("html_url"),
        title=rel.get("name") or rel.get("tag_name"),
        author=rel.get("author", {}).get("login"),
        content_html=rel.get("body") or "",  # Release notes in Markdown
        published_at=datetime.fromisoformat(rel.get("published_at") or rel.get("created_at")),
        metadata={
            "source": "github_releases",
            "owner": owner,
            "repo": repo,
            "tag_name": rel.get("tag_name"),
            "prerelease": rel.get("prerelease", False),
        },
    )
```

#### GitHubAdvisoriesAdapter

**Configuration**:
```python
{
    "ecosystem": "npm",  # Optional: npm, pip, rubygems, maven, nuget, composer, rust
    "severity": "high,critical",  # Comma-separated: critical, high, moderate, low
    "token": "ghp_...",
}
```

**Fetch**:
```python
url = "https://api.github.com/advisories"
params = {
    "per_page": 30,
    "direction": "desc",
    "sort": "published",
}
if ecosystem:
    params["ecosystem"] = ecosystem
if severity:
    params["severity"] = severity

for adv in advisories:
    cve_ids = [v.get("value") for v in adv.get("identifiers", []) if v.get("type") == "CVE"]
    
    entry = ParsedEntry(
        guid=hashlib.sha256(adv.get("ghsa_id", "").encode()).hexdigest()[:32],
        url=adv.get("html_url"),
        title=adv.get("summary"),
        content_html=adv.get("description") or "",
        published_at=datetime.fromisoformat(adv.get("published_at")),
        metadata={
            "source": "github_advisories",
            "ghsa_id": adv.get("ghsa_id"),
            "cve_ids": cve_ids,
            "severity": adv.get("severity"),
            "cvss_score": adv.get("cvss", {}).get("score"),
            "ecosystem": ecosystem,
        },
    )
```

**Quirks**:
- Token optional; unauthenticated requests have lower rate limit (60 req/hr vs 5000).
- Release body is raw Markdown; stored in `content_html` as-is (sanitized by worker).
- Advisory links point to GitHub security advisory page, not CVE detail.

---

### GitHub (Repository Monitor)

**Type**: ExtendedAdapter  
**File**: `backend/app/adapters/github_repo.py`

Monitors a GitHub repository for new/changed files (detection rules, configs, etc.).

**Configuration**:
```python
{
    "owner": "SigmaHQ",
    "repo": "sigma",
    "branch": "main",
    "paths": ["rules/**/*.yml"],          # Glob patterns (** for recursive)
    "watch_mode": "commits",              # "commits" or "tree_diff"
    "max_entries_per_poll": 50,
    "include_content": true,              # Fetch file content
    "backfill_days": 90,                  # On first poll, how far back to go (default 30)
    "last_commit_sha": "abc...",          # Persisted in adapter_config
}
```

The GitHub token is **not** per-feed config: `_get_token()` reads the `github_token` system setting (DB) with fallback to the `GITHUB_TOKEN` env var, so one token serves all GitHub repo feeds.

**Watch Modes**:

1. **`commits`** (default): Polls the Commits API for new commits.
   ```python
   url = f"https://api.github.com/repos/{owner}/{repo}/commits"
   params = {
       "sha": branch,
       "per_page": max_entries_per_poll,
       "since": since.isoformat() if since else ...,
   }
   ```
   Efficient for incremental polling; handles renames naturally.

2. **`tree_diff`**: Uses the Compare API to diff `last_commit_sha` against branch HEAD.
   ```python
   url = f"https://api.github.com/repos/{owner}/{repo}/compare/{last_commit_sha}...{branch_head_sha}"
   
   # Response includes: files added, modified, deleted, renamed
   # More efficient for high-volume repos; can exceed GitHub's 250-commit / 300-file limit
   # (falls back to commits mode if diff too large).
   ```

**Content Extraction**:

For each file matched by `paths` patterns:

1. **Detect content type**: YAML rule, Elastic detection, YARA rule, Markdown, etc.
   - Uses `github_content_types.py:detect_content_type()`.
   - Example: `SigmaHQ/sigma:rules/**/*.yml` → `sigma_rule`.

2. **Derive title**: Extracted from file content.
   - SIGMA: `title` field from YAML.
   - Elastic: `rule.name` from TOML.
   - Markdown: Filename (fallback).

3. **Render content**: Formatted for readability.
   - SIGMA: Highlighted YAML with metadata badges.
   - Code: Syntax-highlighted code block.
   - Markdown: Rendered as-is.

**Entry Creation**:

```python
entry = ParsedEntry(
    guid=f"{owner}/{repo}/{file_path}",  # Plain path GUID — one entry per file, updated in place
    url=f"https://github.com/{owner}/{repo}/blob/{branch}/{file_path}",
    title=derive_title(file_path, content, content_type),
    author=_extract_commit_author(commit),
    content_html=render_content(file_path, content, content_type),
    published_at=datetime.fromisoformat(commit.get("commit").get("author").get("date")),
    metadata={
        "source": "github_repo",
        "owner": owner,
        "repo": repo,
        "file_path": file_path,
        "content_type": content_type,
        "commit_sha": commit.get("sha"),
        "_head_sha": head_sha,  # Persisted to adapter_config for next poll
    },
)
```

**Full-Tree Sync**:

The `full_sync_github_feed()` Celery task (`backend/app/workers/feed_tasks.py:1817`) enumerates **every** file in the repo (not just recent changes):

```python
# Uses Git Trees API to get complete file list
await adapter.fetch_full_tree(config, existing_guids=existing_guids)

# Creates entries for files not yet ingested
# Persists head SHA for incremental fetches afterward
```

**Quirks**:
- Max file size: 5 MB (configurable via `GITHUB_REPO_MAX_FILE_SIZE_KB`, default 5120).
- Rate limiting: Tracks GitHub API quota via response headers; backs off if remaining < 100.
- State persistence: `last_commit_sha` stored in `feed.adapter_config` for next poll.

---

### NVD/CVE

**Type**: ExtendedAdapter  
**File**: `backend/app/adapters/nvd.py`

Fetches CVEs from the NIST National Vulnerability Database API 2.0.

**Configuration**:
```python
{
    "api_key": "nvd_...",       # Optional; increases rate limit
    "keywords": ["Cisco", "ASA"],  # Optional keyword filtering
    "min_cvss": 7.0,            # Filter by CVSS score
}
```

**Fetch**:
```python
url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

params = {
    "resultsPerPage": 50,
}

# Incremental polling
if since:
    params["lastModStartDate"] = since.strftime("%Y-%m-%dT%H:%M:%S.000")
    params["lastModEndDate"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")
else:
    # First poll: last 7 days
    start = datetime.now(timezone.utc) - timedelta(days=7)
    params["lastModStartDate"] = start.strftime("%Y-%m-%dT%H:%M:%S.000")

if keywords:
    params["keywordSearch"] = " ".join(keywords)
    params["keywordExactMatch"] = ""

for vuln in data.get("vulnerabilities", []):
    cve_id = vuln.get("cve", {}).get("id", "")
    
    # Extract CVSS score (tries v3.1, v3.0, v2.0 in order)
    cvss_score = _extract_cvss_score(cve)
    if cvss_score is not None and cvss_score < min_cvss:
        continue
    
    # Convert CVSS score to severity label
    severity = _score_to_severity(cvss_score) if cvss_score else None
    
    # Get English description
    descriptions = cve.get("descriptions", [])
    desc_en = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "")
    
    entry = ParsedEntry(
        guid=hashlib.sha256(cve_id.encode()).hexdigest()[:32],
        url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        title=f"{cve_id}: {desc_en[:120]}..." if len(desc_en) > 120 else f"{cve_id}: {desc_en}",
        content_html=desc_en,
        published_at=datetime.fromisoformat(cve.get("published")),
        metadata={
            "source": "nvd",
            "cve_id": cve_id,
            "cvss_score": cvss_score,
            "severity": severity,
            "references": [r.get("url") for r in cve.get("references", [])],
        },
    )
```

**Quirks**:
- Single request per poll (`resultsPerPage: 50`), windowed by `lastModStartDate`/`lastModEndDate` from the last fetch time.
- CVSS score logic: tries v3.1 (latest), falls back to v3.0, then v2.0.
- Title truncates long descriptions; content_html stores full description.
- Links point to NVD detail page, not external CVE databases.

---

### Mastodon

**Type**: ExtendedAdapter  
**File**: `backend/app/adapters/mastodon.py`

Fetches public posts from Mastodon instances.

**Configuration**:
```python
{
    "instance_url": "https://fosstodon.org",
    "account_id": "123456",          # Numeric account ID (resolve via webfinger if needed)
    "hashtags": ["infosec"],         # Alternative to account_id
    "access_token": "...",           # Optional; enables private timeline access
    "limit": 40,                     # Max 40
}
```

**Fetch Account Posts**:
```python
url = f"{instance_url}/api/v1/accounts/{account_id}/statuses"
params = {
    "limit": limit,
    "exclude_replies": true,    # Skip replies (only top-level posts)
    "exclude_reblogs": true,    # Skip boosts
}

for status in statuses:
    author = status.get("account", {})
    content_html = status.get("content", "")  # HTML
    
    # Title: first line of content (HTML tags stripped)
    plain = re.sub(r"<[^>]+>", "", content_html).strip()
    title = plain[:120] + "..." if len(plain) > 120 else plain
    
    entry = ParsedEntry(
        guid=hashlib.sha256(str(status.get("id")).encode()).hexdigest()[:32],
        url=status.get("url"),
        title=title,
        author=f"{author.get('display_name')} (@{author.get('acct')})",
        content_html=content_html,
        published_at=datetime.fromisoformat(status.get("created_at")),
        metadata={
            "source": "mastodon",
            "instance": instance_url,
            "account": author.get("acct"),
            "status_id": status.get("id"),
            "reblogs_count": status.get("reblogs_count", 0),
            "favourites_count": status.get("favourites_count", 0),
            "tags": [t.get("name") for t in status.get("tags", [])],
        },
    )
```

**Fetch Hashtag Timeline**:
```python
url = f"{instance_url}/api/v1/timelines/tag/{hashtag}"

# Same parsing as account posts
```

**Quirks**:
- Content is pre-rendered HTML (includes `<a>` tags for mentions, hashtags).
- Replies and boosts excluded by default for cleaner timeline.
- Account ID is numeric (not handle); if only handle provided, must resolve via webfinger first.

---

### Bluesky

**Type**: ExtendedAdapter  
**File**: `backend/app/adapters/bluesky.py`

Fetches public posts via the AT Protocol XRPC API (no auth required; optional app-password for higher rate limits).

**Configuration**:
```python
{
    "mode": "author",                       # "author", "feed", or "search"
    "handle": "alice.bsky.social",          # For mode="author"
    "filter": "posts_no_replies",           # Author-feed filter (default)
    "include_reposts": false,               # Author mode: include reposts
    "feed_uri": "at://...",                 # For mode="feed" (algorithmic feed)
    "query": "detection rules",             # For mode="search"
    "lang": "en",                           # Optional search language filter
    "render_replies": false,                # Render reply context into content_html
    "identifier": "alice.bsky.social",      # Optional auth: account identifier...
    "app_password": "<encrypted>",          # ...plus app password (stored encrypted)
    "pds_url": "https://bsky.social",       # PDS for session creation (default)
    "max_per_poll": 50,
    "last_seen_cid": "bafy...",             # Watermark; persisted via _adapter_state
}
```

**Author Timeline**:
```python
url = f"{PUBLIC_BASE}/app.bsky.feed.getAuthorFeed"   # PUBLIC_BASE = https://public.api.bsky.app/xrpc
params = {
    "actor": handle,
    "limit": 50,        # AUTHOR_PAGE_SIZE
    "filter": "posts_no_replies",
}

for post in response.get("feed", []):
    record = post.get("post", {}).get("record", {})
    
    entry = ParsedEntry(
        guid=_stable_guid(post.get("post", {}).get("cid", "")),  # SHA-256 of CID
        url=_bsky_post_url(handle, post.get("post", {}).get("uri", "")),
        title=record.get("text", "")[:120],
        author=handle,
        content_html=...,  # text + embedded media rendered to HTML
        published_at=_parse_iso(record.get("createdAt")),
        metadata={"source": "bluesky", "cid": ..., "uri": ...},
    )
```

**Feed (Algorithmic)**:
```python
url = f"{PUBLIC_BASE}/app.bsky.feed.getFeed"
params = {
    "feed": feed_uri,
    "limit": 50,      # FEED_PAGE_SIZE
}
```

**Search**:
```python
url = f"{PUBLIC_BASE}/app.bsky.feed.searchPosts"
params = {
    "q": query,
    "limit": 25,      # SEARCH_PAGE_SIZE
}
```

**Quirks**:
- **Session caching**: access JWT cached in Redis (`bluesky:session:{feed_id}`, 90-min TTL, in-process fallback); session invalidated and re-created on auth failure. `app_password` is stored encrypted and decrypted via `app.core.encryption`.
- **GUID stability**: Uses CID (content hash) instead of URI so GUID doesn't change if post is edited/deleted.
- **Incremental polling**: newest CID is persisted to `adapter_config.last_seen_cid` (via `feed_meta.extra["_adapter_state"]`) so the next poll short-circuits at already-seen posts.
- **Rate limiting**: on a 429 the adapter backs off and returns an empty batch until the next poll; app-password auth lifts limits.
- **Embeds**: Posts can embed images, videos, links, etc.; extracted into metadata.

---

### Telegram

**Type**: ExtendedAdapter  
**File**: `backend/app/adapters/telegram.py`

Fetches messages from public Telegram channels via MTProto protocol (Telethon library).

**Configuration**:
```python
{
    "channel": "@channelname",          # Username or t.me link
    "channel_id": 123456789,            # Numeric channel ID (resolved and cached)
    "channel_username": "channelname",  # Cached after first fetch
    "session_name": "default",          # Session file name
    "last_seen_id": 0,                  # Message ID watermark (persisted)
    "max_messages_per_fetch": 200,
    "max_message_age_days": 30,         # First fetch: only get last N days
    "include_media": true,
    "media_types": ["photo", "video"],  # Default: photo, video, document, audio
    "extract_forwards": true,
    "edit_probe_window": 50,            # Probe last 50 messages for edits/deletes
    "threat_actor_id": "uuid",          # Auto-link entries to threat actor
    "campaign_id": "uuid",              # Auto-link entries to campaign
}
```

**Setup** (out-of-band, one-time per session):

```bash
# Run interactive login script (creates persistent session file)
python scripts/telegram/telegram_login.py

# Env vars required:
export TELEGRAM_API_ID=123456
export TELEGRAM_API_HASH=abcd1234...
export TELEGRAM_SESSION_PATH=/data/telegram.session   # Default; named sessions live alongside it
```

Session file persists Telegram auth state; reused across worker restarts. Named sessions (`adapter_config.session_name = "osint"`) resolve to `{dirname(TELEGRAM_SESSION_PATH)}/osint.session` and are bootstrapped with `scripts/telegram/telegram_login.py --session osint`.

**Fetch Messages**:
```python
# Lazy-init client per session (post-fork, to avoid shared socket in Celery prefork)
client = await self._get_client(session_name)

# Resolve channel entity
entity = await client.get_entity(channel_input or channel_id)
resolved_channel_id = entity.id
resolved_username = entity.username or ""

# Fetch messages (newest first, then reversed to chronological)
async for message in client.iter_messages(
    entity,
    min_id=last_seen_id,          # Only fetch messages after watermark
    limit=max_messages_per_fetch,
    reverse=True,                 # Chronological order
):
    msg_id = int(message.id or 0)
    if msg_id > max_id_seen:
        max_id_seen = msg_id
    
    # Parse message to entry
    parsed = self._message_to_entry(
        message,
        channel_id=resolved_channel_id,
        channel_username=resolved_username,
        extract_forwards=extract_forwards,
    )
    
    # Extract media (if enabled)
    if include_media and message.media:
        media = await self._build_media(
            client,
            message,
            channel_id=resolved_channel_id,
            media_types=media_types,
            max_size_mb=settings.telegram_max_media_size_mb,
        )
        if media:
            parsed.media = media
    
    entries.append(parsed)
```

**Entry Parsing**:
```python
def _message_to_entry(self, message, channel_id, channel_username, extract_forwards):
    msg_id = int(message.id or 0)
    msg_date = message.date
    
    # Content: message text
    text = message.message or ""
    
    # Metadata: message_id, edited_at, views, reactions, forwarded_from
    metadata = {
        "source": "telegram",
        "message_id": msg_id,
        "channel_id": channel_id,
        "channel_username": channel_username,
        "edited_at": message.edit_date.isoformat() if message.edit_date else None,
        "views": message.views,
        "reactions": [{"emoji": ..., "count": ...}],
        "reactions_total": ...,
    }
    
    # If forwarded, extract original author into metadata["forwarded_from"]
    # and prepend a "Forwarded from ..." banner to content_html
    
    entry = ParsedEntry(
        guid=f"telegram:{channel_id}:{msg_id}",
        # Public channels: t.me/<username>/<msg_id>; private: t.me/c/<id>/<msg_id>
        url=f"https://t.me/{channel_username}/{msg_id}",
        title=first_line[:120] or f"Message {msg_id}",   # First line of text
        content_html=self._render_message_html(message), # Entity-aware rich rendering
        published_at=msg_date,
        metadata=metadata,
    )
    
    return entry
```

`_render_message_html()` converts Telegram's per-character formatting entities (bold, italic, code, pre, links, mentions) into HTML rather than just escaping the raw text.

**Media Extraction**:

Supports photos, videos, documents, audio with size and type filtering:

```python
media = await self._build_media(client, message, ...)

# For photos: download to disk (OCR if enabled)
# For documents: extract filename, MIME type, size
# For videos/audio: metadata only (don't download large files)

media_record = ParsedMedia(
    media_type="photo",        # or video, audio, document
    url="...",                 # Proxied URL to IntelFeed media storage
    mime_type="image/jpeg",
    file_size=12345,
    duration_seconds=60,       # For audio/video
    thumbnail_url="...",
    metadata={"telegram_file_id": "..."},
)
```

**OCR** (optional, experimental):

If enabled (`TELEGRAM_OCR_ENABLED=1`), runs Tesseract on images:
```python
if feed.feed_type == "telegram" and parsed.media.media_type in ("photo", "image"):
    if settings.telegram_ocr_enabled:
        ocr_text = ocr_image(local_path, min_chars=settings.telegram_ocr_min_chars)
        if ocr_text:
            entry.content_text += "\n\n[Image OCR]\n" + ocr_text
```

**Edit/Delete Probing**:

After each fetch, re-fetches the last N messages to detect edits and deletes:

```python
async def _probe_telegram_edits_and_deletes(db, feed, adapter, config):
    # Get last 50 messages from DB
    candidates = await db.execute(
        select(Entry)
        .where(Entry.feed_id == feed.id)
        .order_by(Entry.published_at.desc())
        .limit(50)
    )
    
    # Re-fetch those message IDs
    probe = await adapter.probe_messages(config, [e.metadata_.get("message_id")])
    
    for msg_id, parsed in probe.items():
        entry = by_msg_id[msg_id]
        
        if parsed is None:
            # Soft-delete (mark as deleted, don't hard-delete)
            entry.metadata_["telegram_deleted_at"] = datetime.now().isoformat()
        else:
            # Check if edited
            new_edited_at = parsed.metadata.get("edited_at")
            old_edited_at = entry.metadata_.get("edited_at")
            if new_edited_at and new_edited_at != old_edited_at:
                # Update content and re-run autolink/extraction
                entry.content_html = parsed.content_html
                entry.content_text = parsed.content_text
                dispatch_entry_pipeline(entry.id, run_extraction=...)
```

**Auto-Attribution**:

If `threat_actor_id` or `campaign_id` set in `adapter_config`, every entry is auto-linked:

```python
await _apply_post_ingest_links(db, feed, entry, parsed, config)

# Creates EntryThreatActor, CampaignEntry with "high" confidence
# Many Telegram channels ARE operated by threat actors, so auto-attribution is safe
```

The same hook also supports a generic `author_entity: {"type": "threat_actor"|"vendor"|"product", "id": "uuid"}` config for feeds whose author is a known entity. All inserts use `ON CONFLICT DO NOTHING`, so re-ingest and autolinker passes never error.

**Quirks**:
- **Session bootstrap**: Interactive login required once per session; persists session file.
- **Telethon client**: Per-process, per-session singleton, lazy-init'd post-fork (avoids shared socket in Celery). The SQLite session file is read **once** per process to extract the auth key, then Telethon runs entirely off an in-memory `StringSession` so api/listener/celery processes don't fight over the SQLite writer lock ("database is locked").
- **Album coalescing**: Telegram sends an N-photo album as N messages sharing a `grouped_id`; the adapter merges them into a single entry — caption entry becomes canonical, extra attachments land in `ParsedEntry.additional_media`.
- **Channel handle normalization**: `t.me/s/<handle>` web-preview URLs (which Telethon rejects) are normalized to the real channel handle.
- **Flood waiting**: Telegram API rate limits; adapter catches `FloodWaitError` and returns partial batch.
- **Watermarking**: `last_seen_id` prevents re-fetching old messages; updated only if fetch succeeded (safe on partial batches).
- **Soft-delete**: Deleted messages not hard-deleted (preserves audit trail); marked with `telegram_deleted_at` in metadata.
- **Edit probing**: Detects post-publish edits (Telegram allows message editing); re-runs intel extraction on edited content.

---

### Telegram Operations

Beyond the adapter itself, Telegram has a small operational subsystem: a realtime listener process, media storage/serving, discovery endpoints, and scheduled tasks.

**Realtime listener** (`backend/app/workers/telegram_listener.py`):

A long-lived process run as its own docker-compose service (`telegram-listener`, command `python -m app.workers.telegram_listener`) — **not** a Celery task. It holds a persistent MTProto connection per session file and registers a Telethon `NewMessage` handler for each subscribed channel. On a new message it just dispatches `fetch_feed.delay(feed_id)` (debounced 1.5 s per channel to coalesce bursts), so the existing polling pipeline does all dedup/sanitization/media/autolink work — nothing is duplicated in the listener.

- **Opt-in per feed**: only feeds with `adapter_config.realtime = true` are subscribed.
- **Polling stays on** as the safety net — if the listener dies, entries still arrive on the normal fetch interval.
- **Reconciliation**: re-polls the DB every 5 minutes to pick up added/removed realtime feeds.
- **Heartbeat**: writes `intelfeed:telegram_listener:heartbeat` to Redis every 30 s (plus a subscription count). `GET /api/telegram/listener/status` reports `running: false` when the heartbeat is older than 2 minutes.
- **Unconfigured behavior**: if `TELEGRAM_API_ID`/`TELEGRAM_API_HASH` are unset, the process idles instead of exiting, so the container stays "Up" without a restart loop; restart it after bootstrapping a session.

**Channel discovery** (`backend/app/api/telegram.py`):

`GET /api/telegram/discover` calls `TelegramAdapter.list_my_dialogs()` to list every broadcast channel the bootstrap account is joined to, annotated with `is_subscribed` (unsubscribed channels sort first so "to add" candidates are on top). `GET /api/telegram/feeds/{id}/health` gives a per-feed snapshot: resolved channel, watermark, flood-wait state, edited/soft-deleted counts (7d), session name, and best-effort live subscriber count.

**Link mentions** (`backend/app/workers/telegram_link_tasks.py`):

`scan_telegram_links_task` runs per entry as part of the entry processing pipeline (alongside autolink). It extracts `t.me` channel/invite/message links from **non-Telegram** entries (Telegram-sourced entries are skipped to avoid self-mention noise) and upserts `telegram_channel_mentions` (per-channel aggregate with mention/feed counters) and `telegram_link_mentions` (raw refs, deduped on `(entry_id, url)`). Surfaced at `GET /api/telegram/mentions` — "channels mentioned across my feeds that I'm not ingesting yet" — with dismiss/undismiss and a one-click `POST /mentions/{id}/subscribe` that creates a Telegram feed (invite-only channels are refused; join out-of-band first).

**Forward graph** (`backend/app/workers/intel_feed_tasks.py`):

`build_telegram_forward_relationships` runs on beat every 4 hours. When channel A (auto-attributed to actor X via `adapter_config.threat_actor_id`) forwards a message from channel B (attributed to actor Y), it materializes an `EntityRelationship` of type `communicates_with` between the actors (confidence `probable`, source `auto_extracted`, evidence entry IDs capped at 50). Idempotent via `ON CONFLICT DO NOTHING`.

**Album backfill** (`backend/app/workers/telegram_backfill_tasks.py`):

`backfill_telegram_albums` is a one-shot repair task for entries that pre-date the adapter's album-merge logic: groups fragment entries by `metadata.telegram_grouped_id`, reparents all `EntryMedia` onto the caption-bearing canonical entry, and deletes the strays. Trigger via `docker compose exec api python -m app.scripts.backfill_telegram_albums` or `backfill_telegram_albums.delay()`; optional `feed_id` scopes to one feed.

**Media storage & serving** (`backend/app/api/telegram_media.py`):

Telegram media has no public URL — bytes are downloaded over MTProto by the celery-worker and written to `settings.telegram_media_dir` (`/app/data/telegram_media`, the shared `telegram_media` volume mounted by api, worker, and listener), laid out as `<channel_id>/<message_id>.<ext>` plus `<message_id>.thumb.jpg` thumbnails. Files are served by an auth-gated route:

```
GET /api/telegram-media/{channel_id}/{filename}
```

Accepts the JWT via `Authorization: Bearer` **or** `?token=` query param (so `<img>`/`<video>` tags work). Both path segments are regex-validated and resolved paths are checked against the media root to block traversal. Responses are `Cache-Control: private, max-age=86400`.

**Media cleanup** (`backend/app/workers/maintenance.py`):

`cleanup_telegram_media` runs weekly on beat (Sun 04:20 UTC). It walks the media dir and deletes files whose `(channel_id, message_id)` pair no longer matches any entry — i.e. media orphaned by entry deletion or feed retention. Soft-deleted entries (`telegram_deleted_at` set) keep their media so analysts can still inspect the artefact.

> **Operational note**: this task only prunes *orphans* — there is no size cap or age-based eviction for media whose entries are retained. On feeds with unlimited retention the media dir grows unbounded.

**Session files**: the session-file architecture (interactive bootstrap via `scripts/telegram/telegram_login.py`, named sessions, in-memory `StringSession` to avoid SQLite lock contention) is covered under [Telegram](#telegram) above; the listener reuses the same per-session client init as the adapter.

---

### Web Scraper

**Type**: ExtendedAdapter  
**File**: `backend/app/adapters/web_scraper.py`

Discovers and scrapes blog index pages for article links (no RSS feed required).

**Configuration**:
```python
{
    "blog_url": "https://blog.example.com",
    "link_selector": "a.post-link",                    # CSS selector to find article links
    "url_pattern": "/blog/.*",                         # Regex to filter URLs
    "max_articles": 20,                                # Max per fetch (capped at 100)
    "follow_pagination": true,                         # Default false
    "pagination_selector": "a[rel='next'], a.next",    # CSS selector for next page link
    "max_pages": 3,                                    # Capped at 10
}
```

**Article Discovery**:
```python
# Fetch index page(s) and find article links via CSS selectors
visited_pages = set()
pages_to_visit = [blog_url]

for page_num in range(max_pages):
    if not pages_to_visit:
        break
    
    page_url = pages_to_visit.pop(0)
    if page_url in visited_pages:
        continue
    visited_pages.add(page_url)
    
    response = await client.get(page_url)
    tree = lxml_html.fromstring(response.text)
    
    # Find article links using CSS selector
    if link_selector:
        links = tree.cssselect(link_selector)
    else:
        # Default selectors: article a[href], main a[href], .post a[href], etc.
        links = []
        for sel in _INDEX_LINK_SELECTORS:
            links.extend(tree.cssselect(sel))
    
    # Filter by URL pattern and domain
    for link in links:
        href = link.get("href", "")
        full_url = urljoin(page_url, href)
        
        if not full_url.startswith(("http://", "https://")):
            continue
        if urlparse(full_url).netloc != base_domain:
            continue  # Stay on same domain
        if _SKIP_PATH_PATTERNS.match(urlparse(full_url).path):
            continue  # Skip login, about, etc.
        if _SKIP_EXTENSIONS.match(full_url):
            continue  # Skip images, PDFs, etc.
        
        all_links.append(full_url)
    
    # Find next page link
    if follow_pagination:
        next_links = tree.cssselect(pagination_selector)
        if next_links:
            next_url = urljoin(page_url, next_links[0].get("href", ""))
            if next_url and next_url not in visited_pages:
                pages_to_visit.append(next_url)
```

**Article Parsing**:

Articles are fetched concurrently (semaphore of 3) with a curl_cffi browser-impersonation fallback for bot-protected sites, then parsed by `_extract_article()`:

```python
# Extract metadata from <meta>/<title> tags
title = self._extract_title(raw_html)          # og:title / <title>, site-suffix stripped
author = self._extract_author(raw_html)
published_at = self._extract_date(raw_html)    # article:published_time etc.
image_url = self._extract_og_image(raw_html)
summary = self._extract_description(raw_html)

# Extract article body: readability-lxml first, then CSS-selector fallback
content_html = self._extract_content(raw_html)

entry = ParsedEntry(
    guid=hashlib.sha256(url.encode()).hexdigest()[:32],
    url=url,
    title=title,
    author=author,
    content_html=content_html,
    summary=summary,
    published_at=published_at,
    metadata={
        "source": "web_scraper",
        "blog_url": blog_url,
        "image_url": image_url,   # Promoted to entry.image_url by the worker
    },
)
```

**Quirks**:
- Heuristic-based link discovery; requires tuning CSS selectors per blog.
- Respects `robots.txt` (fetched and cached).
- Rate-limited per domain; honors `Crawl-delay`.
- Body extraction is **readability-lxml** first, with `_ARTICLE_CONTENT_SELECTORS` CSS fallback.
- Requires no RSS feed (useful for blogs that don't publish feeds).

---

### Ransomware Leak Sites (ransomware.live)

**Type**: ExtendedAdapter (deliberately unregistered — no feed type)  
**File**: `backend/app/adapters/ransomware_live.py`

Polls the ransomware.live v2 `/recentvictims` API for leak-site victim postings. Structurally it mirrors `nvd.py` — an `ExtendedAdapter` returning `ParsedEntry` objects with a rich `metadata` dict — but it is **not** registered in `_EXTENDED_ADAPTERS` and never runs through the feed polling loop. Its entries are not persisted as `Entry` rows: the sync path (`app/intelligence/ransomware_sync.py`) reads each entry's `metadata` and upserts structured `RansomwareVictim` (the organization) + `VictimDisclosure` (the posting event) records instead.

**Wiring**:

- Driven by the `sync_ransomware_victims` beat task (`app/workers/intel_feed_tasks.py`), every 30 minutes (`sync-ransomware-victims` in `job_registry.py`).
- The v2 endpoint has no server-side `since` filter, so incremental polling is client-side against each posting's `discovered` timestamp (first poll looks back 7 days).
- GUID is `make_disclosure_guid(source, group, victim, discovered)` — a truncated SHA-256 over the posting event, stable across runs.
- A group name/alias catalog is fetched once per sync from `/v2/groups` (the endpoint is rate-limited to 1/min) so the resolver can fold group slugs into tracked ThreatActors by alias; syncs that create new groups trigger `refresh_autolinker_vocabulary`.
- Source-pluggable: each leak-site aggregator is one `ExtendedAdapter` subclass with a distinct `SOURCE` string (`"ransomware.live"` today); additional sources slot in as siblings iterated by the sync function.
- Surfaced via `GET /api/ransomware/*` (victims feed, landscape stats, sync) and the Workbench ransomware views; watchlist matches raise SSE alerts.

---

## OPML Import/Export

**File**: `backend/app/api/opml.py`

### Import

```python
@router.post("/import")
async def import_opml(file: UploadFile, user: User, db: AsyncSession):
    """Import OPML file (Outline Processor Markup Language)."""
    
    content = await file.read()
    if len(content) > 10 * 1024 * 1024:  # 10 MB limit
        return {"error": "OPML file too large"}
    
    root = DefusedET.fromstring(content)  # Safely parse XML
    body = root.find("body")
    
    stats = {"feeds_added": 0, "feeds_skipped": 0, "categories_created": 0, "errors": []}
    
    for outline in body:
        children = list(outline)
        if children:
            # This outline has children → category
            category_name = outline.get("text") or outline.get("title")
            
            # Reuse existing category by name, or create it
            category = existing_by_name(category_name) or Category(created_by=user.id, name=category_name)
            
            # Import feeds in category
            for feed_outline in children:
                await _import_feed_outline(feed_outline, user, category.id, db, stats)
        else:
            # Top-level feed (no category)
            await _import_feed_outline(outline, user, None, db, stats)
    
    # Queue initial fetch for newly added feeds
    if stats["feeds_added"] > 0:
        unfetched = await db.execute(select(Feed.id).where(Feed.last_fetched_at == None))
        for (feed_id,) in unfetched.all():
            fetch_feed.delay(str(feed_id))
    
    return stats
```

**OPML Format**:
```xml
<?xml version="1.0"?>
<opml version="1.0">
  <head>
    <title>My Subscriptions</title>
  </head>
  <body>
    <outline text="Security" title="Security">
      <outline text="Hacker News" type="rss" xmlUrl="https://news.ycombinator.com/rss" htmlUrl="https://news.ycombinator.com" />
      <outline text="Reddit /r/netsec" type="rss" xmlUrl="https://www.reddit.com/r/netsec/.rss" htmlUrl="https://www.reddit.com/r/netsec" />
    </outline>
    <outline text="Blog" title="Blog">
      <outline text="My Blog" type="rss" xmlUrl="https://example.com/feed.xml" htmlUrl="https://example.com" />
    </outline>
  </body>
</opml>
```

### Export

```python
@router.get("/export")
async def export_opml(user: User, db: AsyncSession):
    """Export all subscriptions as OPML."""
    
    # Fetch feeds grouped by category
    feeds_result = await db.execute(
        select(Feed, Category)
        .outerjoin(Category, Category.id == Feed.category_id)
        .order_by(Category.name, Feed.title)
    )
    
    # Build OPML structure
    opml = ET.Element("opml", version="1.0")
    head = ET.SubElement(opml, "head")
    title = ET.SubElement(head, "title")
    title.text = "IntelFeed Subscriptions"
    body = ET.SubElement(opml, "body")
    
    # Group by category and create outline hierarchy
    categories: dict[str | None, list] = {}
    for feed, category in rows:
        cat_name = category.name if category else None
        if cat_name not in categories:
            categories[cat_name] = []
        categories[cat_name].append(feed)
    
    for cat_name, feeds in categories.items():
        if cat_name:
            cat_outline = ET.SubElement(body, "outline", text=cat_name, title=cat_name)
            parent = cat_outline
        else:
            parent = body
        
        for feed in feeds:
            attrs = {
                "text": feed.custom_title or feed.title,
                "title": feed.custom_title or feed.title,
                "type": "rss",  # Always export as RSS (OPML standard)
                "xmlUrl": feed.url,
            }
            if feed.site_url:
                attrs["htmlUrl"] = feed.site_url
            ET.SubElement(parent, "outline", **attrs)
    
    return Response(
        content=ET.tostring(opml, encoding="unicode", xml_declaration=True),
        media_type="text/xml",
        headers={"Content-Disposition": "attachment; filename=intelfeed-subscriptions.opml"},
    )
```

**Quirks**:
- Import type detection: if `type` attribute not present, defaults to `rss`. Only `rss`, `atom`, `youtube`, `podcast` are accepted; anything else falls back to `rss`.
- Only imports feeds with `xmlUrl` starting with `http://` or `https://` (skips keyword monitoring, etc.).
- Categories created on-demand during import (reused by name if they already exist).
- Export always marks feeds as `type="rss"` for compatibility.

---

## Manual Ingest

Not everything arrives via a feed. `backend/app/services/manual_ingest.py` lets analysts push individual articles and PDFs into the platform; `backend/app/api/ingest.py` exposes the endpoints (mounted under `/api/entries`). In the UI this is the "Ingest URL or PDF" button in the sidebar (`IngestModal`).

**The `manual` pseudo-feed**:

All manually ingested entries attach to a singleton "Manual Uploads" feed (`url = "manual://uploads"`, `feed_type = "manual"`), created on first use. The poller skips it twice over: it is created with `is_active = False` (so `poll_due_feeds()` never selects it), and `fetch_feed()` independently rejects `feed_type = "manual"` via `NON_FETCHABLE_FEED_TYPES` — there is no adapter behind it. It defaults to `intel_extraction_mode = "full"` with `auto_extract_on_ingest` and `extract_detection_rules` enabled, so manual uploads get the most aggressive intel treatment.

**`POST /api/entries/ingest/url`**:

- Validates http/https scheme; GUID is `manual:url:<sha256(url)>` — re-ingesting the same URL returns `409 duplicate`.
- Reuses the polling pipeline's readability extraction (`_extract_full_text()` from `feed_tasks.py`); falls back to a basic fetch for `<title>`/og:image if extraction fails, and `422`s if neither yields content.
- Resolves relative `src`/`href` attributes against the source URL, then runs the standard `sanitize_html()`, title fallback chain (`<title>` → `<h1>` → domain+path), lead-image extraction, and `content_hash` computation.

**`POST /api/entries/ingest/pdf`** (multipart upload, optional `title` form field):

- 50 MB cap, content-type plus `%PDF-` magic-bytes validation; GUID is `manual:pdf:<sha256(bytes)>` (same 409 dedup).
- Text + HTML extracted per page with PyMuPDF (`fitz`); images come through as base64 `data:` URIs, so PDF HTML is sanitized with a dedicated nh3 profile that allows the `data:` scheme (regular entry sanitization does not).

**Same pipeline afterwards**: both endpoints commit the entry, then call `dispatch_entry_pipeline(entry_id, run_extraction=True)` — the exact same Celery chord as polled entries (autolink, intel extraction, post-processing, signal scoring) — index into Meilisearch inline (failures queue the entry ID in Redis `meili:failed_entry_ids` for retry), and broadcast an `entry_ingested` SSE event. Downstream, a manual entry is indistinguishable from a fetched one apart from `metadata_.source` (`url_ingest` / `pdf_upload`) and its feed.

---

## Building a New Adapter

### Step 1: Choose Base Class

**BaseAdapter** if:
- You have a URL to fetch raw content (RSS, Atom, HTML, etc.).
- User provides the feed URL.

**ExtendedAdapter** if:
- You construct API endpoints from `config` (no user-provided URL).
- You have API credentials/tokens to manage.
- You paginate through API results.

### Step 2: Define Data Structures

```python
from app.adapters.base import BaseAdapter, ParsedEntry, ParsedFeedMeta, ParsedMedia

class MyAdapter(BaseAdapter):
    def parse_entries(self, feed_url: str, content: str) -> tuple[ParsedFeedMeta, list[ParsedEntry]]:
        # Parse raw content into entries
        # Return (feed_meta, list_of_entries)
        pass
```

### Step 3: Normalize Entries

Each entry must have:
- **guid**: Unique per feed (used for deduplication).
- **url**: Link to original entry (optional).
- **title**: Human-readable title (fallback to "Untitled").
- **content_html**: HTML content (sanitized by worker).
- **published_at**: Timestamp (optional).
- **metadata**: Adapter-specific dict (optional).
- **media**: ParsedMedia object (optional).

Example:

```python
entry = ParsedEntry(
    guid="unique-id-for-this-entry",
    url="https://example.com/article",
    title="Article Title",
    author="Jane Doe",
    content_html="<p>Article body...</p>",
    summary="Short summary...",
    published_at=datetime.now(timezone.utc),
    metadata={
        "source": "my_adapter",
        "custom_field": "value",
    },
)
```

### Step 4: Register Adapter

**File**: `backend/app/adapters/__init__.py`

```python
from app.adapters.my_adapter import MyAdapter

# BaseAdapter subclasses go in _ADAPTERS; ExtendedAdapter subclasses in _EXTENDED_ADAPTERS
_EXTENDED_ADAPTERS: dict[str, ExtendedAdapter] = {
    "my_feed_type": MyAdapter(),
    ...
}
```

Also add the class to `__all__`. `is_extended_feed_type()` and `get_extended_adapter()` pick it up automatically from `_EXTENDED_ADAPTERS`.

### Step 5: Add Feed Type to Feed Model

Create a migration to add your feed_type to the database if needed.

### Step 6: Configure in Feed

Users create feeds with:
```python
feed = Feed(
    title="My Feed",
    url="https://...",  # or dummy URL for ExtendedAdapter
    feed_type="my_feed_type",
    adapter_config={
        "setting1": "value1",
        "setting2": 123,
    },
)
```

### Step 7: Handle Errors Gracefully

- Catch exceptions in `parse_entries()` / `fetch_entries()`.
- Log with context (feed URL, API endpoint, etc.).
- Raise specific exceptions for `feed_tasks` to handle retry logic.

**State persistence**: an ExtendedAdapter can return state to persist into `feed.adapter_config` by setting `feed_meta.extra["_adapter_state"] = {...}` (e.g. Bluesky's `last_seen_cid`); the worker merges it after a successful fetch. The worker also injects a scratch `_feed_id` key into `config` so adapters can scope per-feed caches.

### Step 8: Test

```python
# Unit tests
@pytest.mark.asyncio
async def test_fetch_entries():
    adapter = MyAdapter()
    config = {"setting": "value"}
    meta, entries = await adapter.fetch_entries(config)
    
    assert len(entries) > 0
    assert entries[0].guid
    assert entries[0].title
```

---

## Summary Table: Adapter Capabilities

| Feed Type | Class | Auth | Pagination | Rate Limiting | Media | Notes |
|-----------|-------|------|-----------|---------------|-------|-------|
| **RSS** | BaseAdapter | No | N/A | Domain-based | No | Standard feedparser library |
| **Atom** | BaseAdapter | No | N/A | Domain-based | No | Same as RSS (feedparser) |
| **YouTube** | BaseAdapter | No | Feed-based | Domain-based | Yes (video) | Shorts filtering, retry logic |
| **Podcast** | BaseAdapter | No | Feed-based | Domain-based | Yes (audio) | iTunes/Podcast 2.0 namespaces |
| **Reddit** | ExtendedAdapter | No | N/A | Reddit quota | No | Public /hot.rss (JSON API blocked); synthetic rank-based score |
| **GitHub Releases** | ExtendedAdapter | Optional token | API pagination | GitHub quota | No | Pre-releases filterable |
| **GitHub Advisories** | ExtendedAdapter | Optional token | API pagination | GitHub quota | No | Severity/ecosystem filtering |
| **GitHub Repo** | ExtendedAdapter | Optional token | API pagination | GitHub quota | No | File content extraction, commits/tree diff modes |
| **NVD CVE** | ExtendedAdapter | Optional key | API pagination | NVD quota | No | CVSS score filtering, incremental polling |
| **Mastodon** | ExtendedAdapter | Optional token | API pagination | Instance quota | Yes (images) | Public timelines, hashtag support |
| **Bluesky** | ExtendedAdapter | Optional app-password | API pagination | AT Protocol quota | Yes (images) | Author/feed/search modes, JWT caching |
| **Telegram** | ExtendedAdapter | Session file | MTProto streaming | Telegram rate limit | Yes (photos/video) | Edit/delete probing, OCR, auto-attribution |
| **Web Scraper** | ExtendedAdapter | No | Pagination selectors | Domain-based | No | Blog discovery, CSS selectors, robots.txt |

Not listed: `RansomwareLiveAdapter` has no feed type — it feeds the ransomware victim tracker's structured records via its own beat task, not the entry pipeline (see [Ransomware Leak Sites](#ransomware-leak-sites-ransomwarelive)).

---

## See Also

- **architecture.md**: System design, entity extraction, correlation events.
- **entries.md**: Entry lifecycle, field definitions, sanitization.
- **entity-profiles.md**: Threat actor, CVE, TTP modeling.

