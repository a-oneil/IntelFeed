import asyncio
import logging
import random
import re
import time as _time
from datetime import UTC, datetime, timedelta

import httpx
from celery import chain, chord, group
from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.metrics import (
    CELERY_TASK_DURATION_SECONDS,
    CELERY_TASKS_TOTAL,
    ENTRIES_INGESTED_TOTAL,
    FEED_FETCH_DURATION_SECONDS,
    FEED_FETCH_TOTAL,
)
from app.core.safe_http import safe_async_client, safe_curl_get
from app.models.entry import Entry
from app.models.entry_media import EntryMedia
from app.models.feed import Feed
from app.models.podcast import Podcast
from app.services.dedup import compute_content_hash
from app.services.feed_fetch_health import record_auto_pause
from app.services.sanitizer import extract_first_image, extract_og_image, html_to_text, sanitize_html
from app.workers.celery_app import celery_app
from app.workers.db import run_async, worker_session

logger = logging.getLogger(__name__)

# Feed types that have no fetchable URL (pseudo-feeds populated out-of-band,
# e.g. the manual:// uploads feed). Skipped instead of erroring every cycle.
NON_FETCHABLE_FEED_TYPES = frozenset({"manual"})

# Standard browser-like request headers — some servers (gov sites, Cloudflare-
# fronted blogs) reject requests missing them.
FEED_ACCEPT_HEADER = (
    "application/rss+xml, application/atom+xml, application/xml;q=0.9, text/xml;q=0.8, text/html;q=0.7, */*;q=0.6"
)
FEED_ACCEPT_LANGUAGE = "en-US,en;q=0.9"

# Attempt RSS autodiscovery only after this many consecutive HTTP 404 failures
FEED_404_AUTODISCOVERY_MIN_FAILURES = 3

# Failure-streak backoff for the poller: each consecutive failure doubles the
# wait, up to 2**FEED_ERROR_BACKOFF_MAX_DOUBLINGS times the feed's interval and
# never more than FEED_ERROR_BACKOFF_CAP_MINUTES (unless the interval itself is
# longer). Without it a blocked feed polled every 7 minutes logs ~5,700 failures
# before the auto-pause window closes; with it, about 20.
FEED_ERROR_BACKOFF_MAX_DOUBLINGS = 6
FEED_ERROR_BACKOFF_CAP_MINUTES = 24 * 60

# Feeds due for a fetch. The interval stretches while a failure streak runs
# (see the backoff constants above) and snaps back on the first clean fetch.
DUE_FEEDS_SQL = f"""
    SELECT id FROM feeds
    WHERE is_active = TRUE
    -- With per-user subscriptions on, a feed every reader has paused
    -- has nobody to deliver to, so stop paying to fetch it. One
    -- un-paused reader is enough to keep it running for the pool.
    AND (NOT :per_user OR EXISTS (
            SELECT 1 FROM user_feed_subscriptions s
            WHERE s.feed_id = feeds.id AND s.is_paused = FALSE))
    AND (last_fetched_at IS NULL
         OR NOW() > last_fetched_at + (
            CASE WHEN COALESCE(error_count, 0) > 0
                 THEN GREATEST(
                        fetch_interval_minutes,
                        LEAST({FEED_ERROR_BACKOFF_CAP_MINUTES},
                              fetch_interval_minutes
                              * (1 << LEAST(error_count, {FEED_ERROR_BACKOFF_MAX_DOUBLINGS}))))
                 ELSE fetch_interval_minutes
            END || ' minutes')::interval)
    ORDER BY last_fetched_at ASC NULLS FIRST
    LIMIT 50
"""

# Statuses a bot wall answers with. 403 always triggers the curl_cffi retry;
# 429/503 only when the body looks like a challenge page, since both are also
# honest "slow down" / "down for maintenance" answers.
_BLOCKED_STATUS = 403
_CHALLENGE_STATUSES = frozenset({429, 503})
_CHALLENGE_MARKERS = (
    "just a moment",
    "cf-chl",
    "challenge-platform",
    "attention required",
    "_incapsula_",
    "captcha",
    "access denied",
    "bot detection",
)
FEED_FETCH_TIMEOUT = 30.0

# "HTTP 4xx" as written by the fetchers below. Only client errors count as a
# dead feed: a 5xx or a timeout is the publisher's bad day, not a moved feed.
_HTTP_4XX = re.compile(r"^HTTP 4\d\d\b")


def _note_fetch_error(feed: Feed, message: str) -> None:
    """Count a failed fetch. `error_since` marks the start of the streak so
    the health check can tell a feed dead for a month from one that hiccupped
    this morning; a successful fetch clears it."""
    now = datetime.now(UTC)
    feed.error_count += 1
    feed.last_error = message
    if feed.error_since is None:
        feed.error_since = now
    feed.last_fetched_at = now


def _note_fetch_success(feed: Feed) -> None:
    """A clean fetch ends the failure streak."""
    feed.error_count = 0
    feed.last_error = None
    feed.error_since = None


async def _auto_pause_dead_feeds(db: AsyncSession, pause_days: int) -> int:
    """Pause active feeds whose current failure streak is a 4xx that began
    more than `pause_days` ago. Returns how many were paused."""
    cutoff = datetime.now(UTC) - timedelta(days=pause_days)
    result = await db.execute(
        select(Feed).where(
            Feed.is_active.is_(True),
            Feed.error_since.isnot(None),
            Feed.error_since <= cutoff,
            Feed.error_count >= 3,
        )
    )
    paused = 0
    for feed in result.scalars().all():
        if not feed.last_error or not _HTTP_4XX.match(feed.last_error):
            continue
        feed.is_active = False
        feed.auto_paused_at = datetime.now(UTC)
        record_auto_pause(feed)
        db.add(feed)
        paused += 1
        logger.warning(
            "Feed %s (%s) auto-paused: %s since %s (%d consecutive failures)",
            feed.id,
            feed.url,
            feed.last_error,
            feed.error_since.date(),
            feed.error_count,
        )
    if paused:
        await db.commit()
    return paused


async def _resolve_user_agent(db: AsyncSession) -> str:
    """Effective User-Agent: system_settings DB override > env default."""
    try:
        from app.services.system_settings import get_setting

        ua = await get_setting("user_agent", db)
        if ua:
            return str(ua)
    except Exception:
        logger.debug("Failed to read user_agent from system settings, using env default", exc_info=True)
    return settings.user_agent


def _looks_blocked(response) -> bool:
    """A bot wall rather than a real answer about the feed."""
    status = response.status_code
    if status == _BLOCKED_STATUS:
        return True
    if status in _CHALLENGE_STATUSES:
        try:
            body = (response.text or "")[:4000].lower()
        except Exception:
            return False
        return any(marker in body for marker in _CHALLENGE_MARKERS)
    return False


async def _curl_get_feed(url: str, headers: dict[str, str]):
    """GET through curl_cffi impersonating Chrome. The impersonation sets its
    own User-Agent to match the TLS fingerprint it presents, so ours is
    dropped; Accept and the conditional headers go through."""
    curl_headers = {k: v for k, v in headers.items() if k.lower() != "user-agent"}
    return await safe_curl_get(url, impersonate="chrome", timeout=FEED_FETCH_TIMEOUT, headers=curl_headers)


async def _get_feed_response(feed: Feed, client: httpx.AsyncClient, headers: dict[str, str]):
    """GET the feed with whichever client last worked for it, retrying once
    with the other when the answer is a bot wall (or, for curl_cffi, an error).

    Some publishers (CISA) refuse Python's TLS handshake whatever the headers
    while answering curl. The client that got a 200/304 is remembered in
    adapter_config so later polls go straight to it. Raises httpx.HTTPError
    when httpx was the last resort and it failed.
    """
    from app.services.feed_fetch_health import CLIENT_CURL, CLIENT_HTTPX, preferred_client, remember_client

    first = preferred_client(feed)
    second = CLIENT_HTTPX if first == CLIENT_CURL else CLIENT_CURL

    async def attempt(name: str):
        if name == CLIENT_HTTPX:
            return await client.get(feed.url)
        return await _curl_get_feed(feed.url, headers)

    if first == CLIENT_HTTPX:
        response = await attempt(first)  # httpx errors propagate as before
        if not _looks_blocked(response):
            return response
    else:
        try:
            response = await attempt(first)
        except Exception as e:
            logger.info("Feed %s: curl_cffi fetch failed (%s), trying httpx", feed.id, e)
            response = await attempt(second)  # last resort: errors propagate
            if response.status_code in (200, 304):
                remember_client(feed, second)
            return response
        if not _looks_blocked(response):
            return response

    try:
        retry = await attempt(second)
    except Exception as e:
        logger.info("Feed %s: %s fallback after HTTP %s failed: %s", feed.id, second, response.status_code, e)
        return response
    if retry.status_code in (200, 304):
        logger.info(
            "Feed %s: %s answered HTTP %s, %s got %s; using %s from now on",
            feed.id,
            first,
            response.status_code,
            second,
            retry.status_code,
            second,
        )
        remember_client(feed, second)
        return retry
    return response if _looks_blocked(retry) else retry


def _feed_request_headers(user_agent: str) -> dict[str, str]:
    """Base headers for feed fetching (browser-like UA + standard Accept headers)."""
    return {
        "User-Agent": user_agent,
        "Accept": FEED_ACCEPT_HEADER,
        "Accept-Language": FEED_ACCEPT_LANGUAGE,
    }


@celery_app.task(
    name="app.workers.feed_tasks.entry_post_processing",
    soft_time_limit=300,
    time_limit=360,
)
def entry_post_processing(*_args, entry_id: str = "", **_kwargs):
    """Callback dispatched after autolink + extraction finish for an entry.

    Triggers co-occurrence relationship creation, correlation event detection,
    and requirement matching — tasks that depend on entity data being present.
    Their outputs are the signal engine's inputs, so scoring runs as a second
    chord callback once all three complete (score_entry_task no-ops unless the
    signal engine flags are enabled).
    """
    from app.pipeline.registry import stages_of_kind
    from app.workers.celery_app import celery_app as _capp

    header = [_capp.signature(stage.task_path, args=[entry_id], immutable=True) for stage in stages_of_kind("post")]
    final = stages_of_kind("final")[0]
    callback = _capp.signature(final.task_path, kwargs={"entry_id": entry_id}, immutable=True)
    chord(group(header), callback).apply_async()


def _auto_translate_target(feed: Feed) -> str | None:
    """Target language for the translate pipeline prologue, or None when the
    feed doesn't have auto-translation enabled."""
    cfg = feed.adapter_config or {}
    if not cfg.get("auto_translate"):
        return None
    return (cfg.get("translation_target") or settings.get("translation_default_target") or "en").lower()


def _maybe_dispatch_auto_translate(feed: Feed, entry_ids: list[str]) -> None:
    """Standalone translate dispatch for existing entries (backfills). New-entry
    ingest translates via the pipeline prologue in dispatch_entry_pipeline."""
    target_lang = _auto_translate_target(feed)
    if not target_lang or not entry_ids:
        return
    try:
        from app.workers.translation_tasks import translate_entry_task

        for eid in entry_ids:
            translate_entry_task.delay(eid, target_lang)
    except Exception:
        logger.warning("Failed to dispatch auto-translate tasks for feed %s", feed.id, exc_info=True)


def dispatch_entry_pipeline(
    entry_id: str,
    *,
    run_extraction: bool = False,
    plan: dict | None = None,
    translate_target: str | None = None,
):
    """Build and dispatch the entry processing pipeline using a Celery chord.

    Stage composition comes from app/pipeline/registry.py. When a resolved
    PipelinePlan is provided (pipeline_engine_enabled), it decides which
    parallel stages run; otherwise the legacy run_extraction boolean does —
    identical structure to the previous hand-built chord (asserted by
    tests/test_pipeline_registry.py).

    When translate_target is set (feeds with auto_translate), the translate
    stage is chained ahead of the chord so autolink/extract/relevance/scoring
    all see the translated text. translate_entry_task swallows every failure
    (returns a status string), so the prologue can never stall the chain.
    """
    from app.pipeline.registry import PIPELINE_STAGES, stages_of_kind
    from app.workers.celery_app import celery_app as _capp

    header = []
    for stage in stages_of_kind("parallel"):
        if plan is not None:
            enabled = plan.get(stage.name, {}).get("enabled", stage.default_enabled)
        else:
            enabled = run_extraction if stage.name == "extract" else True
        if enabled:
            header.append(_capp.signature(stage.task_path, args=[entry_id], immutable=True))
    if not header:
        header = [
            _capp.signature(stage.task_path, args=[entry_id], immutable=True)
            for stage in stages_of_kind("parallel")
            if stage.name == "autolink"
        ]

    callback = entry_post_processing.si(entry_id=entry_id)
    pipeline = chord(group(header), callback)
    if translate_target:
        prologue = _capp.signature(
            PIPELINE_STAGES["translate"].task_path,
            args=[entry_id, translate_target],
            kwargs={"requeue_autolink": False},
            immutable=True,
        )
        chain(prologue, pipeline).apply_async()
    else:
        pipeline.apply_async()


def _get_worker_session():
    return worker_session()


@celery_app.task(name="app.workers.feed_tasks.poll_due_feeds", soft_time_limit=120, time_limit=180)
def poll_due_feeds():
    """Check for feeds that are due for polling and dispatch fetch tasks."""
    return run_async(_poll_due_feeds())


async def _poll_due_feeds():
    import redis as _redis

    async with _get_worker_session() as db:
        from sqlalchemy import text

        from app.services.feed_visibility import subscriptions_enabled

        per_user = await subscriptions_enabled(db)
        result = await db.execute(text(DUE_FEEDS_SQL), {"per_user": per_user})
        feed_ids = [str(row[0]) for row in result.all()]

    # Deduplicate: skip feeds that already have a pending/active fetch
    r = _redis.from_url(settings.redis_url)
    try:
        dispatched = 0
        for feed_id in feed_ids:
            lock_key = f"feed_fetch:{feed_id}"
            # SET NX with 10-minute TTL — only dispatch if not already in-flight
            if r.set(lock_key, "1", nx=True, ex=600):
                fetch_feed.delay(feed_id)
                dispatched += 1

        if dispatched:
            logger.info(f"Dispatched fetch tasks for {dispatched} feeds ({len(feed_ids) - dispatched} already queued)")
        return {"due": len(feed_ids), "dispatched": dispatched, "already_in_flight": len(feed_ids) - dispatched}
    finally:
        r.close()


@celery_app.task(
    name="app.workers.feed_tasks.fetch_feed", bind=True, max_retries=3, soft_time_limit=600, time_limit=660
)
def fetch_feed(self, feed_id: str):
    """Fetch and parse a single feed."""
    start = _time.monotonic()
    try:
        run_async(_fetch_feed(feed_id))
        CELERY_TASKS_TOTAL.labels(task_name="fetch_feed", status="success").inc()
    except SoftTimeLimitExceeded:
        CELERY_TASKS_TOTAL.labels(task_name="fetch_feed", status="timeout").inc()
        logger.warning("Feed fetch timed out after 10 minutes: %s", feed_id)
    except Exception as exc:
        CELERY_TASKS_TOTAL.labels(task_name="fetch_feed", status="retry").inc()
        logger.error(f"Error fetching feed {feed_id}: {exc}")
        raise self.retry(exc=exc, countdown=min(300, 2**self.request.retries * 10 + random.uniform(0, 10)))
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="fetch_feed").observe(_time.monotonic() - start)
        # Release dedup lock so this feed can be dispatched again
        try:
            import redis as _redis

            r = _redis.from_url(settings.redis_url)
            try:
                r.delete(f"feed_fetch:{feed_id}")
            finally:
                r.close()
        except Exception:
            logger.warning("Failed to release feed_fetch lock for %s", feed_id, exc_info=True)


async def _fetch_feed(feed_id: str):
    fetch_start = _time.monotonic()
    async with _get_worker_session() as db:
        result = await db.execute(select(Feed).where(Feed.id == feed_id))
        feed = result.scalar_one_or_none()
        if not feed or not feed.is_active:
            return

        # Check if this is an extended (API-based) adapter
        from app.adapters import is_extended_feed_type

        if is_extended_feed_type(feed.feed_type):
            await _fetch_extended_feed(db, feed)
            return

        # Pseudo-feeds (e.g. manual:// uploads) have nothing to fetch — skip
        # instead of erroring every cycle on an unsupported URL scheme.
        if feed.feed_type in NON_FETCHABLE_FEED_TYPES or not feed.url.lower().startswith(("http://", "https://")):
            feed.last_fetched_at = datetime.now(UTC)
            if feed.error_count:
                _note_fetch_success(feed)
            db.add(feed)
            await db.commit()
            FEED_FETCH_TOTAL.labels(status="skipped").inc()
            logger.debug("Feed %s (%s): non-fetchable feed type %r, skipping", feed.id, feed.url, feed.feed_type)
            return

        # Resolve the User-Agent first: that read warms the settings cache the
        # rate limiter's per-domain interval comes from.
        base_headers = _feed_request_headers(await _resolve_user_agent(db))

        # Acquire domain rate limit
        from app.services.rate_limiter import acquire_rate_limit

        if not await acquire_rate_limit(feed.url):
            FEED_FETCH_TOTAL.labels(status="rate_limited").inc()
            logger.warning(f"Rate limited for feed {feed.id}, will retry on next poll")
            return
        headers = dict(base_headers)
        if feed.etag:
            headers["If-None-Match"] = feed.etag
        if feed.last_modified:
            headers["If-Modified-Since"] = feed.last_modified

        async with safe_async_client(
            follow_redirects=True,
            timeout=FEED_FETCH_TIMEOUT,
            headers=headers,
        ) as client:
            try:
                response = await _get_feed_response(feed, client, headers)
            except httpx.HTTPError as e:
                _note_fetch_error(feed, str(e))
                db.add(feed)
                await db.commit()
                await _maybe_create_feed_error_event(db, feed)
                FEED_FETCH_TOTAL.labels(status="error").inc()
                FEED_FETCH_DURATION_SECONDS.labels(feed_type=feed.feed_type).observe(_time.monotonic() - fetch_start)
                logger.warning(f"HTTP error fetching feed {feed.id}: {e}")
                return

            if response.status_code == 304:
                feed.last_fetched_at = datetime.now(UTC)
                db.add(feed)
                await db.commit()
                FEED_FETCH_TOTAL.labels(status="not_modified").inc()
                FEED_FETCH_DURATION_SECONDS.labels(feed_type=feed.feed_type).observe(_time.monotonic() - fetch_start)
                logger.debug(f"Feed {feed.id} not modified")
                return

            if response.status_code != 200:
                # YouTube's feed API returns spurious 404/500s — retry up to 2 times
                if feed.feed_type == "youtube" and response.status_code in (404, 500, 502, 503):
                    for _retry in range(2):
                        await asyncio.sleep(5)
                        try:
                            response = await client.get(feed.url)
                            if response.status_code == 200:
                                break
                        except httpx.HTTPError:
                            pass
                    else:
                        # All retries failed — skip this cycle without incrementing error count
                        feed.last_fetched_at = datetime.now(UTC)
                        db.add(feed)
                        await db.commit()
                        FEED_FETCH_TOTAL.labels(status="error").inc()
                        FEED_FETCH_DURATION_SECONDS.labels(feed_type=feed.feed_type).observe(
                            _time.monotonic() - fetch_start
                        )
                        logger.info(
                            "Feed %s: YouTube returned %s after retries, skipping cycle", feed.id, response.status_code
                        )
                        return

                if response.status_code != 200:
                    prev_error = feed.last_error
                    _note_fetch_error(feed, f"HTTP {response.status_code}")
                    db.add(feed)
                    await db.commit()
                    await _maybe_create_feed_error_event(db, feed)
                    # Persistent 404s usually mean the feed URL moved (e.g. a blog
                    # relocation) — conservatively try RSS autodiscovery from the
                    # site homepage and repoint the feed if a working URL is found.
                    if (
                        response.status_code == 404
                        and prev_error == "HTTP 404"
                        and feed.error_count >= FEED_404_AUTODISCOVERY_MIN_FAILURES
                        and feed.feed_type in ("rss", "atom", "podcast")
                    ):
                        await _attempt_feed_url_autodiscovery(db, feed, base_headers)
                    FEED_FETCH_TOTAL.labels(status="error").inc()
                    FEED_FETCH_DURATION_SECONDS.labels(feed_type=feed.feed_type).observe(
                        _time.monotonic() - fetch_start
                    )
                    return

        # Auto-detect feed type if still generic
        if feed.feed_type in ("rss", "atom"):
            from app.adapters.base import BaseAdapter

            detected = BaseAdapter.detect_feed_type(feed.url, response.text)
            if detected != feed.feed_type:
                feed.feed_type = detected
                logger.info(f"Feed {feed.id} auto-detected as {detected}")

        # Use adapter to parse
        from app.adapters import get_adapter

        adapter = get_adapter(feed.feed_type)
        feed_meta, parsed_entries = adapter.parse_entries(feed.url, response.text)

        # Reachable but empty: a feed URL that now redirects to a landing page,
        # or a feed that answers 200 with no items, never errors — it just
        # stops delivering. Note it so the Feeds view can say so.
        if feed.feed_type in ("rss", "atom", "podcast"):
            from app.services.feed_fetch_health import note_items

            note_items(
                feed,
                len(parsed_entries),
                final_url=str(getattr(response, "url", "") or ""),
                content_type=response.headers.get("content-type"),
            )

        # Detect silent failure: rss/atom feed responding with HTML body and no entries.
        # Happens when the feed URL has been deprecated and now serves the site's HTML page.
        if feed.feed_type in ("rss", "atom") and not parsed_entries:
            content_type = (response.headers.get("content-type") or "").lower()
            if "html" in content_type:
                _note_fetch_error(
                    feed, f"Non-feed response: HTTP 200 with content-type {content_type!r} and 0 entries parsed"
                )
                db.add(feed)
                await db.commit()
                await _maybe_create_feed_error_event(db, feed)
                FEED_FETCH_TOTAL.labels(status="error").inc()
                FEED_FETCH_DURATION_SECONDS.labels(feed_type=feed.feed_type).observe(_time.monotonic() - fetch_start)
                logger.warning(
                    "Feed %s (%s): non-feed response, content-type=%s",
                    feed.id,
                    feed.url,
                    content_type,
                )
                return

        # Update podcast show metadata if this is a podcast feed
        if feed.feed_type == "podcast" and feed_meta.podcast_author:
            await _upsert_podcast_metadata(db, feed, feed_meta)

        new_entries = 0
        new_entry_ids = []

        # Pre-filter to only new entries (skip existing GUIDs and intra-batch dupes)
        new_parsed_entries = []
        seen_guids = set()
        for parsed in parsed_entries:
            if parsed.guid in seen_guids:
                continue
            seen_guids.add(parsed.guid)
            existing = await db.execute(select(Entry).where(Entry.feed_id == feed.id, Entry.guid == parsed.guid))
            if existing.scalar_one_or_none():
                continue
            new_parsed_entries.append(parsed)

        # Filter out YouTube Shorts from new entries only
        if feed.feed_type == "youtube" and feed.adapter_config.get("exclude_shorts") and new_parsed_entries:
            from app.services.youtube import filter_shorts

            video_ids = [p.metadata.get("video_id") for p in new_parsed_entries if p.metadata.get("video_id")]
            if video_ids:
                short_ids = await filter_shorts(video_ids)
                if short_ids:
                    before = len(new_parsed_entries)
                    new_parsed_entries = [p for p in new_parsed_entries if p.metadata.get("video_id") not in short_ids]
                    logger.info(
                        "Feed %s: filtered %d Shorts from %d new entries",
                        feed.id,
                        before - len(new_parsed_entries),
                        before,
                    )

        # Cap full-text extraction per cycle to avoid monopolizing the worker
        # on feeds with many short entries (e.g. MSRC CVE feeds with 1000+ items)
        MAX_FULLTEXT_EXTRACTIONS = 25
        fulltext_extraction_count = 0

        for parsed in new_parsed_entries:
            content_html = parsed.content_html or ""
            og_image = None

            # Google News and similar aggregators wrap real article URLs in an
            # obfuscated redirect. Resolve to the publisher URL so the entry's
            # "Open original" link, full-text extraction, and og:image fetch all
            # operate on the canonical article, not the JS-only wrapper page.
            if parsed.url and "news.google.com" in parsed.url:
                resolved = _resolve_google_news_url(parsed.url)
                if resolved:
                    parsed.url = resolved

            # For RSS articles, try full-text extraction if content is short
            # or if it's a known truncation pattern (e.g. "Continue reading on ...")
            if (
                feed.feed_type in ("rss", "atom")
                and parsed.url
                and fulltext_extraction_count < MAX_FULLTEXT_EXTRACTIONS
            ):
                content_text_plain = html_to_text(content_html) if content_html else ""
                is_truncated = bool(re.search(r"Continue reading on .+\s*»", content_text_plain))
                if is_truncated or len(content_text_plain) < 500:
                    extracted, og_image = await _extract_full_text(parsed.url)
                    fulltext_extraction_count += 1
                    if extracted:
                        content_html = extracted

            # Sanitize
            sanitized_html = sanitize_html(content_html) if content_html else None
            content_text = html_to_text(content_html) if content_html else None

            # Compute word count and content hash
            word_count = len(content_text.split()) if content_text else None
            content_hash = compute_content_hash(parsed.title, content_text)

            # Cross-guid dedup: skip if an entry with this content_hash already exists.
            # Catches feeds that change guids on article updates (e.g. WordPress re-publish).
            existing = await db.execute(select(Entry.id).where(Entry.content_hash == content_hash).limit(1))
            if existing.scalar_one_or_none():
                logger.debug("Skipping content-hash duplicate %s for feed %s", parsed.guid, feed.id)
                continue

            # Extract lead image: content → summary → og:image (fetched)
            image_url = (
                extract_first_image(content_html, base_url=parsed.url) if content_html else None
            ) or extract_first_image(parsed.summary or "", base_url=parsed.url)
            if not image_url and og_image:
                image_url = og_image
            if (
                not image_url
                and parsed.url
                and feed.feed_type in ("rss", "atom")
                and fulltext_extraction_count < MAX_FULLTEXT_EXTRACTIONS
            ):
                image_url = await _fetch_og_image(parsed.url)

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
                published_at=min(parsed.published_at, datetime.now(UTC)) if parsed.published_at else None,
                word_count=word_count,
                content_hash=content_hash,
                metadata_=parsed.metadata,
            )
            db.add(entry)
            try:
                async with db.begin_nested():
                    await db.flush()
            except Exception as flush_exc:
                if "UniqueViolation" in str(flush_exc) or "IntegrityError" in str(flush_exc):
                    logger.debug("Skipping duplicate entry %s for feed %s", parsed.guid, feed.id)
                    continue
                raise
            new_entries += 1
            new_entry_ids.append(str(entry.id))

            # Create media record if parsed entry has media (shared helper)
            await _create_entry_media(db, feed, entry, parsed)

            # Index in Meilisearch
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
                logger.warning(
                    "Meilisearch indexing failed for entry %s, queuing for retry: %s",
                    entry.id,
                    meili_exc,
                )
                try:
                    import redis as _redis

                    r = _redis.from_url(settings.redis_url)
                    r.sadd("meili:failed_entry_ids", str(entry.id))
                except Exception:
                    pass

        # Update feed metadata
        feed.last_fetched_at = datetime.now(UTC)
        feed.etag = response.headers.get("etag")
        feed.last_modified = response.headers.get("last-modified")
        _note_fetch_success(feed)

        # Update feed title/description from parsed metadata
        if feed_meta.title and not feed.title:
            feed.title = feed_meta.title
        if feed_meta.description and not feed.description:
            feed.description = feed_meta.description
        if feed_meta.site_url and not feed.site_url:
            feed.site_url = feed_meta.site_url

        db.add(feed)
        await db.commit()

        FEED_FETCH_TOTAL.labels(status="success").inc()
        FEED_FETCH_DURATION_SECONDS.labels(feed_type=feed.feed_type).observe(_time.monotonic() - fetch_start)
        if new_entries:
            ENTRIES_INGESTED_TOTAL.labels(feed_type=feed.feed_type).inc(new_entries)
            logger.info(f"Feed {feed.id} ({feed.title}): {new_entries} new entries")

            # Publish single coalesced SSE event (not two separate events)
            try:
                from app.api.events import broadcast_event

                broadcast_event(
                    "feed_fetched",
                    {"feed_id": str(feed.id), "new_entries": new_entries, "entry_ids": new_entry_ids},
                )
            except Exception:
                logger.warning("Failed to publish SSE events for feed %s", feed.id, exc_info=True)

            # Dispatch automation tasks for new entries
            try:
                from app.workers.automation_tasks import run_entry_automations

                for eid in new_entry_ids:
                    run_entry_automations.delay(eid, str(feed.id))
            except Exception:
                logger.warning("Failed to dispatch automation tasks for feed %s", feed.id, exc_info=True)

            # Dispatch entry processing pipeline (translate? → autolink + extraction → post-processing)
            run_extraction = bool(feed.auto_extract_on_ingest or feed.extract_detection_rules)
            try:
                from app.pipeline.plans import resolve_feed_plan

                feed_plan = await resolve_feed_plan(db, feed)
                translate_target = _auto_translate_target(feed)
                for eid in new_entry_ids:
                    dispatch_entry_pipeline(
                        eid,
                        run_extraction=run_extraction,
                        plan=feed_plan,
                        translate_target=translate_target,
                    )
            except Exception:
                logger.warning("Failed to dispatch entry pipeline for feed %s", feed.id, exc_info=True)


async def _create_entry_media(db: AsyncSession, feed: Feed, entry: Entry, parsed) -> None:
    """Create the EntryMedia row (and optional transcript) from a ParsedEntry.media.

    Shared between BaseAdapter (_fetch_feed) and ExtendedAdapter (_fetch_extended_feed) paths
    so adapters like Telegram can emit media without re-implementing this block.
    """
    if not parsed.media:
        return

    media_record = EntryMedia(
        entry_id=entry.id,
        media_type=parsed.media.media_type,
        url=parsed.media.url,
        mime_type=parsed.media.mime_type,
        file_size=parsed.media.file_size,
        duration_seconds=parsed.media.duration_seconds,
        thumbnail_url=parsed.media.thumbnail_url,
        metadata_=parsed.media.metadata,
    )

    # Persist any additional media (e.g. Telegram album items) as sibling rows.
    extras = getattr(parsed, "additional_media", None) or []
    for extra in extras:
        db.add(
            EntryMedia(
                entry_id=entry.id,
                media_type=extra.media_type,
                url=extra.url,
                mime_type=extra.mime_type,
                file_size=extra.file_size,
                duration_seconds=extra.duration_seconds,
                thumbnail_url=extra.thumbnail_url,
                metadata_=extra.metadata,
            )
        )

    transcript_text = None
    if parsed.media.transcript_url:
        from app.services.transcript import fetch_transcript

        transcript_text = await fetch_transcript(parsed.media.transcript_url)
        if transcript_text:
            media_record.transcript_text = transcript_text

    if not transcript_text and feed.feed_type == "youtube" and parsed.metadata.get("video_id"):
        from app.services.youtube_transcript import fetch_youtube_transcript

        transcript_text = await fetch_youtube_transcript(parsed.metadata["video_id"])
        if transcript_text:
            media_record.transcript_text = transcript_text

    db.add(media_record)

    if transcript_text:
        import html as html_mod

        transcript_section = (
            f'<div class="transcript"><h3>Transcript</h3><p>{html_mod.escape(transcript_text)}</p></div>'
        )
        entry.content_html = (entry.content_html or "") + transcript_section
        entry.content_text = (entry.content_text or "") + "\n\nTranscript:\n" + transcript_text
        entry.word_count = len(entry.content_text.split())

    # Telegram image OCR — best-effort, gated on settings.telegram_ocr_enabled.
    # Runs synchronously inside the fetch task so the OCR text lands before the
    # autolink pipeline dispatches and has a chance to extract entities from it.
    if feed.feed_type == "telegram" and parsed.media.media_type in ("photo", "image") and settings.telegram_ocr_enabled:
        try:
            from app.services.telegram_ocr import is_available, local_path_for_url, ocr_image

            if is_available():
                local = local_path_for_url(parsed.media.url, settings.telegram_media_dir)
                if local:
                    ocr_text = ocr_image(local, min_chars=settings.telegram_ocr_min_chars)
                    if ocr_text:
                        meta = dict(media_record.metadata_ or {})
                        meta["ocr_text"] = ocr_text
                        media_record.metadata_ = meta
                        entry.content_text = (entry.content_text or "") + "\n\n[Image OCR]\n" + ocr_text
                        if entry.content_text:
                            entry.word_count = len(entry.content_text.split())
        except Exception:
            logger.warning("Telegram OCR failed for entry %s", entry.id, exc_info=True)


async def _apply_post_ingest_links(
    db: AsyncSession,
    feed: Feed,
    entry: Entry,
    parsed,
    config: dict,
) -> None:
    """Apply operator-asserted post-ingest links from adapter_config.

    Currently used by the Telegram adapter where many channels ARE the threat actor
    (ransomware leak sites, hacktivist channels, broker channels). When the operator
    sets `threat_actor_id` and/or `campaign_id` in adapter_config, every entry from
    that feed is auto-attributed with high confidence — no autolinker guessing required.

    Idempotent: uses ON CONFLICT DO NOTHING so re-ingest or autolinker passes don't error.
    Failures here MUST NOT abort the ingest — log and continue.
    """
    if not config:
        return

    threat_actor_id = config.get("threat_actor_id")
    campaign_id = config.get("campaign_id")
    author_entity = config.get("author_entity") if isinstance(config.get("author_entity"), dict) else None

    if not threat_actor_id and not campaign_id and not author_entity:
        return

    import uuid as _uuid

    from sqlalchemy.dialects.postgresql import insert as pg_insert

    channel_username = config.get("channel_username") or config.get("channel") or ""
    matched_names = [channel_username] if channel_username else []

    if threat_actor_id:
        try:
            from app.models.threat_actor import EntryThreatActor

            actor_uuid = _uuid.UUID(str(threat_actor_id))
            stmt = (
                pg_insert(EntryThreatActor.__table__)
                .values(
                    entry_id=entry.id,
                    threat_actor_id=actor_uuid,
                    confidence="high",
                    source="tg_channel",
                    matched_names=matched_names,
                    paragraph_indices=None,
                )
                .on_conflict_do_nothing(index_elements=["entry_id", "threat_actor_id"])
            )
            await db.execute(stmt)
        except Exception:
            logger.warning(
                "Failed to apply telegram threat-actor attribution for entry %s on feed %s",
                entry.id,
                feed.id,
                exc_info=True,
            )

    if author_entity:
        a_type = author_entity.get("type")
        a_id = author_entity.get("id")
        if a_type and a_id:
            try:
                ent_uuid = _uuid.UUID(str(a_id))
                if a_type == "threat_actor":
                    from app.models.threat_actor import EntryThreatActor as _Ent

                    stmt = (
                        pg_insert(_Ent.__table__)
                        .values(
                            entry_id=entry.id,
                            threat_actor_id=ent_uuid,
                            confidence="high",
                            source="feed_author",
                            matched_names=None,
                            paragraph_indices=None,
                        )
                        .on_conflict_do_nothing(index_elements=["entry_id", "threat_actor_id"])
                    )
                    await db.execute(stmt)
                elif a_type == "vendor":
                    from app.models.vendor import EntryVendor as _Ent

                    stmt = (
                        pg_insert(_Ent.__table__)
                        .values(
                            entry_id=entry.id,
                            vendor_id=ent_uuid,
                            confidence="high",
                            source="feed_author",
                            matched_names=None,
                            paragraph_indices=None,
                        )
                        .on_conflict_do_nothing(index_elements=["entry_id", "vendor_id"])
                    )
                    await db.execute(stmt)
                elif a_type == "product":
                    from app.models.product import EntryProduct as _Ent

                    stmt = (
                        pg_insert(_Ent.__table__)
                        .values(
                            entry_id=entry.id,
                            product_id=ent_uuid,
                            confidence="high",
                            source="feed_author",
                            matched_names=None,
                            paragraph_indices=None,
                        )
                        .on_conflict_do_nothing(index_elements=["entry_id", "product_id"])
                    )
                    await db.execute(stmt)
            except Exception:
                logger.warning(
                    "Failed to apply author-entity attribution for entry %s on feed %s",
                    entry.id,
                    feed.id,
                    exc_info=True,
                )

    if campaign_id:
        try:
            from app.models.campaign import CampaignEntry

            campaign_uuid = _uuid.UUID(str(campaign_id))
            note = (
                f"Auto-linked from Telegram channel @{channel_username}"
                if channel_username
                else "Auto-linked from Telegram feed"
            )
            stmt = (
                pg_insert(CampaignEntry.__table__)
                .values(
                    campaign_id=campaign_uuid,
                    entry_id=entry.id,
                    added_by=None,
                    notes=note,
                )
                .on_conflict_do_nothing(index_elements=["campaign_id", "entry_id"])
            )
            await db.execute(stmt)
        except Exception:
            logger.warning(
                "Failed to apply telegram campaign attribution for entry %s on feed %s",
                entry.id,
                feed.id,
                exc_info=True,
            )


async def _fetch_extended_feed(db: AsyncSession, feed: Feed) -> None:
    """Fetch entries from an API-based extended adapter (Reddit, GitHub, NVD, Mastodon)."""
    from app.adapters import get_extended_adapter

    # Ensure system settings cache is loaded so adapters can read API keys
    from app.services.system_settings import _ensure_cache

    await _ensure_cache(db)

    adapter = get_extended_adapter(feed.feed_type)
    if not adapter:
        logger.error(f"No extended adapter found for feed type {feed.feed_type}")
        return

    config = dict(feed.adapter_config) if feed.adapter_config else {}
    # Pass feed_id so adapters can scope per-feed caches (e.g. Bluesky JWT in Redis).
    config.setdefault("_feed_id", str(feed.id))

    try:
        feed_meta, parsed_entries = await adapter.fetch_entries(config, since=feed.last_fetched_at)
    except Exception as e:
        _note_fetch_error(feed, str(e))
        db.add(feed)
        await db.commit()
        await _maybe_create_feed_error_event(db, feed)
        logger.warning(f"Extended feed {feed.id} fetch error: {e}")
        return

    new_entries = 0
    new_entry_ids = []

    for parsed in parsed_entries:
        existing = await db.execute(select(Entry).where(Entry.feed_id == feed.id, Entry.guid == parsed.guid))
        if existing.scalar_one_or_none():
            continue

        content_text = None
        if parsed.content_html:
            from app.services.sanitizer import html_to_text, sanitize_html

            sanitized = sanitize_html(parsed.content_html)
            content_text = html_to_text(parsed.content_html)
        else:
            sanitized = None

        word_count = len(content_text.split()) if content_text else None

        from app.services.dedup import compute_content_hash

        content_hash = compute_content_hash(parsed.title, content_text)

        # Cross-guid dedup: skip if an entry with this content_hash already exists.
        existing = await db.execute(select(Entry.id).where(Entry.content_hash == content_hash).limit(1))
        if existing.scalar_one_or_none():
            logger.debug("Skipping content-hash duplicate %s for feed %s", parsed.guid, feed.id)
            continue

        image_url = (
            extract_first_image(parsed.content_html, base_url=parsed.url) if parsed.content_html else None
        ) or extract_first_image(parsed.summary or "", base_url=parsed.url)
        # Fallback to image_url from adapter metadata (e.g. og:image from web scraper)
        if not image_url and parsed.metadata.get("image_url"):
            from urllib.parse import urljoin as _urljoin

            meta_img = parsed.metadata["image_url"]
            image_url = _urljoin(parsed.url, meta_img) if parsed.url else meta_img

        # Sanitize metadata: convert date/datetime to strings for JSONB
        entry_metadata = parsed.metadata
        if entry_metadata:
            from datetime import date as _date
            from datetime import datetime as _datetime

            def _sanitize_json(obj):
                if isinstance(obj, dict):
                    return {k: _sanitize_json(v) for k, v in obj.items()}
                if isinstance(obj, list):
                    return [_sanitize_json(v) for v in obj]
                if isinstance(obj, (_date, _datetime)):
                    return str(obj)
                return obj

            entry_metadata = _sanitize_json(entry_metadata)

        entry = Entry(
            feed_id=feed.id,
            guid=parsed.guid,
            url=parsed.url,
            title=parsed.title,
            author=parsed.author,
            content_html=sanitized,
            content_text=content_text,
            summary=parsed.summary,
            image_url=image_url,
            published_at=parsed.published_at,
            word_count=word_count,
            content_hash=content_hash,
            metadata_=entry_metadata,
        )
        db.add(entry)
        await db.flush()
        new_entries += 1
        new_entry_ids.append(str(entry.id))

        # Create media record from parsed.media (shared helper)
        await _create_entry_media(db, feed, entry, parsed)

        # Apply per-feed auto-attribution (Telegram channels operated by named threat actors / campaigns)
        await _apply_post_ingest_links(db, feed, entry, parsed, config)

        # Index in Meilisearch
        from app.services.meilisearch_client import index_entry

        try:
            index_entry(
                entry_id=entry.id,
                feed_id=feed.id,
                title=parsed.title,
                content_text=content_text,
                summary=parsed.summary,
                author=parsed.author,
                published_at=parsed.published_at.isoformat() if parsed.published_at else None,
                feed_type=feed.feed_type,
                word_count=entry.word_count,
                language=entry.language,
                feed_title=feed.title,
            )
        except Exception as meili_exc:
            logger.warning(
                "Meilisearch indexing failed for entry %s, queuing for retry: %s",
                entry.id,
                meili_exc,
            )
            try:
                import redis as _redis

                r = _redis.from_url(settings.redis_url)
                r.sadd("meili:failed_entry_ids", str(entry.id))
            except Exception:
                pass

    # Update feed metadata
    feed.last_fetched_at = datetime.now(UTC)
    _note_fetch_success(feed)

    if feed_meta.title and not feed.title:
        feed.title = feed_meta.title
    if feed_meta.description and not feed.description:
        feed.description = feed_meta.description

    # Persist telegram channel resolution (channel_id, channel_username, last_seen_id) back to adapter_config
    if feed.feed_type == "telegram":
        adapter_extras = (feed_meta.extra or {}) if hasattr(feed_meta, "extra") else {}
        if adapter_extras:
            adapter_config = dict(feed.adapter_config) if feed.adapter_config else {}
            for key in ("channel_id", "channel_username", "last_seen_id"):
                if adapter_extras.get(key) is not None:
                    adapter_config[key] = adapter_extras[key]
            feed.adapter_config = adapter_config

    # Generic adapter-state merge: any extended adapter can return state to persist
    # back into adapter_config via feed_meta.extra["_adapter_state"].
    adapter_state: dict = {}
    if hasattr(feed_meta, "extra") and isinstance(feed_meta.extra, dict):
        maybe_state = feed_meta.extra.get("_adapter_state")
        if isinstance(maybe_state, dict):
            adapter_state.update(maybe_state)

    # Backward-compat: GitHub repo adapter still emits _head_sha at the top level
    # of feed_meta.extra and via entry metadata. Promote it into adapter_state.
    if feed.feed_type == "github_repo":
        head_sha = None
        if hasattr(feed_meta, "extra") and feed_meta.extra.get("_head_sha"):
            head_sha = feed_meta.extra["_head_sha"]
        if not head_sha:
            for pe in parsed_entries:
                if pe.metadata and pe.metadata.get("_head_sha"):
                    head_sha = pe.metadata["_head_sha"]
                    break
        if head_sha:
            adapter_state["last_commit_sha"] = head_sha

    if adapter_state:
        merged = dict(feed.adapter_config) if feed.adapter_config else {}
        merged.pop("_feed_id", None)  # scratch key, never persist
        merged.update(adapter_state)
        feed.adapter_config = merged

    db.add(feed)
    await db.commit()

    if new_entries:
        logger.info(f"Extended feed {feed.id} ({feed.title}): {new_entries} new entries")

        # Publish single coalesced SSE event (not two separate events)
        try:
            from app.api.events import broadcast_event

            broadcast_event(
                "feed_fetched",
                {"feed_id": str(feed.id), "new_entries": new_entries, "entry_ids": new_entry_ids},
            )
        except Exception:
            logger.warning("Failed to publish SSE events for extended feed %s", feed.id, exc_info=True)

        # Dispatch automation tasks
        try:
            from app.workers.automation_tasks import run_entry_automations

            for eid in new_entry_ids:
                run_entry_automations.delay(eid, str(feed.id))
        except Exception:
            logger.warning("Failed to dispatch automation tasks for extended feed %s", feed.id, exc_info=True)

        # Dispatch entry processing pipeline (translate? → autolink + extraction → post-processing)
        run_extraction = bool(feed.auto_extract_on_ingest or feed.extract_detection_rules)
        try:
            from app.pipeline.plans import resolve_feed_plan

            feed_plan = await resolve_feed_plan(db, feed)
            translate_target = _auto_translate_target(feed)
            for eid in new_entry_ids:
                dispatch_entry_pipeline(
                    eid,
                    run_extraction=run_extraction,
                    plan=feed_plan,
                    translate_target=translate_target,
                )
        except Exception:
            logger.warning("Failed to dispatch entry pipeline for extended feed %s", feed.id, exc_info=True)

    # Telegram-specific: probe the most recent K previously-ingested messages for
    # edits and deletes (the Telegram source itself can mutate post-publish).
    if feed.feed_type == "telegram" and hasattr(adapter, "probe_messages"):
        try:
            await _probe_telegram_edits_and_deletes(db, feed, adapter, config)
        except Exception:
            logger.warning("Telegram edit/delete probe failed for feed %s", feed.id, exc_info=True)


async def _probe_telegram_edits_and_deletes(db: AsyncSession, feed: Feed, adapter, config: dict) -> None:
    """Re-fetch the last N ingested telegram messages and reconcile edits / deletes.

    Edits: when message.edit_date > entry.metadata_["edited_at"] (or the latter is missing
    and edit_date is now set), update content_html / content_text / word_count and re-dispatch
    the autolink / extraction pipeline so derived intel reflects the new text.

    Deletes: when get_messages returns None for an id we have on file, soft-delete the entry
    by setting `metadata_["telegram_deleted_at"]`. We don't hard-delete because a transient
    Telegram outage could falsely report deletion; soft-delete preserves history and is
    reversible.
    """
    probe_window = int((feed.adapter_config or {}).get("edit_probe_window") or 50)
    if probe_window <= 0:
        return

    # Pull the most-recent N entries on this feed that have a telegram message_id
    result = await db.execute(
        select(Entry)
        .where(Entry.feed_id == feed.id)
        .order_by(Entry.published_at.desc().nullslast())
        .limit(probe_window)
    )
    candidates = result.scalars().all()
    by_msg_id: dict[int, Entry] = {}
    for entry in candidates:
        meta = entry.metadata_ or {}
        if meta.get("telegram_deleted_at"):
            continue  # already marked deleted
        msg_id = meta.get("message_id")
        if msg_id is None:
            continue
        try:
            by_msg_id[int(msg_id)] = entry
        except (TypeError, ValueError):
            continue

    if not by_msg_id:
        return

    probe = await adapter.probe_messages(config, list(by_msg_id.keys()))
    if not probe:
        return

    edited = 0
    deleted = 0
    re_extract_ids: list[str] = []

    for msg_id, parsed in probe.items():
        entry = by_msg_id.get(msg_id)
        if entry is None:
            continue

        if parsed is None:
            # Soft-delete
            existing_meta = dict(entry.metadata_ or {})
            existing_meta["telegram_deleted_at"] = datetime.now(UTC).isoformat()
            entry.metadata_ = existing_meta
            db.add(entry)
            deleted += 1
            continue

        # Compare edit timestamps to decide if this is a real edit
        new_edited_at = parsed.metadata.get("edited_at")
        old_edited_at = (entry.metadata_ or {}).get("edited_at")
        if not new_edited_at or new_edited_at == old_edited_at:
            continue

        # Edit detected — update the entry content and metadata
        from app.services.sanitizer import html_to_text, sanitize_html

        new_html = sanitize_html(parsed.content_html or "")
        new_text = html_to_text(parsed.content_html or "") if parsed.content_html else None

        entry.content_html = new_html
        entry.content_text = new_text
        if new_text:
            entry.word_count = len(new_text.split())
        # Content changed → any stored translation is stale; clearing it lets the
        # pipeline's translate prologue re-translate on re-dispatch below.
        entry.translated_html = None
        entry.translated_title = None
        entry.translated_at = None
        merged_meta = dict(entry.metadata_ or {})
        # Preserve existing values that the probe doesn't recompute (forwarded_from etc),
        # but always overwrite views / reactions / edited_at since they're refreshed.
        for k in ("views", "reactions", "edited_at"):
            if parsed.metadata.get(k) is not None:
                merged_meta[k] = parsed.metadata[k]
        entry.metadata_ = merged_meta
        db.add(entry)
        edited += 1
        re_extract_ids.append(str(entry.id))

    if edited or deleted:
        await db.commit()
        logger.info(
            "Telegram edit/delete probe for feed %s: edited=%d deleted=%d",
            feed.id,
            edited,
            deleted,
        )

    # Re-run autolink/extraction for edited entries so derived intel matches new content
    run_extraction = bool(feed.auto_extract_on_ingest or feed.extract_detection_rules)
    try:
        from app.pipeline.plans import resolve_feed_plan

        feed_plan = await resolve_feed_plan(db, feed)
    except Exception:
        feed_plan = None
    translate_target = _auto_translate_target(feed)
    for eid in re_extract_ids:
        try:
            dispatch_entry_pipeline(
                eid,
                run_extraction=run_extraction,
                plan=feed_plan,
                translate_target=translate_target,
            )
        except Exception:
            logger.warning("Failed to re-dispatch pipeline for edited entry %s", eid, exc_info=True)


async def _upsert_podcast_metadata(db: AsyncSession, feed: Feed, meta) -> None:
    """Create or update podcast show metadata."""
    result = await db.execute(select(Podcast).where(Podcast.feed_id == feed.id))
    podcast = result.scalar_one_or_none()

    if podcast:
        podcast.author = meta.podcast_author
        podcast.categories = meta.podcast_categories
        podcast.is_explicit = meta.podcast_explicit
        podcast.podcast_type = meta.podcast_type
        podcast.artwork_url = meta.podcast_artwork_url
    else:
        podcast = Podcast(
            feed_id=feed.id,
            author=meta.podcast_author,
            categories=meta.podcast_categories,
            is_explicit=meta.podcast_explicit,
            podcast_type=meta.podcast_type,
            artwork_url=meta.podcast_artwork_url,
        )
    db.add(podcast)


def _is_medium_url(url: str) -> bool:
    """Check if URL is hosted on Medium (including custom domains)."""
    from urllib.parse import urlparse

    MEDIUM_DOMAINS = {
        "medium.com",
        "towardsdatascience.com",
        "betterprogramming.pub",
        "levelup.gitconnected.com",
        "blog.devgenius.io",
        "infosecwriteups.com",
        "systemweakness.com",
        "blog.securitybreak.io",
        "detect.fyi",
        "detecteng.com",
        "meetcyber.net",
        "blog.grumpygoose.io",
        "blog.opentide.org",
        "medium.engineering",
    }
    host = urlparse(url).hostname or ""
    return host in MEDIUM_DOMAINS or host.endswith(".medium.com")


def _extract_medium_article(raw_html: str) -> str | None:
    """Extract article content from Medium's <article><section> HTML structure.

    Readability-lxml misses most Medium content because of their DOM structure.
    Extracting from <article><section> gets the full article reliably.

    Medium uses <picture><source srcSet="..."><img/></picture> for images where
    the <img> has no src attribute.  We resolve each <picture> block by pulling
    the first non-webp srcSet URL and injecting it as the img src.
    """
    article_match = re.search(r"<article[^>]*>(.*?)</article>", raw_html, re.DOTALL)
    if not article_match:
        return None

    section_match = re.search(r"<section[^>]*>(.*?)</section>", article_match.group(1), re.DOTALL)
    content = section_match.group(1) if section_match else article_match.group(1)
    if not content or len(content) <= 100:
        return None

    # Resolve Medium <picture> blocks: pull src from <source> srcSet into <img>
    def _resolve_picture(match: re.Match) -> str:
        picture_html = match.group(0)
        # Prefer the non-webp source (data-testid="og") for broader compatibility
        source_match = re.search(r'<source[^>]+data-testid="og"[^>]+srcSet="([^"]+)"', picture_html)
        if not source_match:
            # Fall back to any source with srcSet
            source_match = re.search(r'<source[^>]+srcSet="([^"]+)"', picture_html)
        if not source_match:
            return picture_html

        # Take the last (largest) URL from the srcSet
        srcset = source_match.group(1)
        urls = [part.strip().split()[0] for part in srcset.split(",") if part.strip()]
        img_url = urls[-1] if urls else None
        if not img_url:
            return picture_html

        img_match = re.search(r"<img\b([^>]*)(/?>)", picture_html)
        if not img_match:
            return picture_html

        img_attrs = img_match.group(1)
        if 'src="' not in img_attrs and "src='" not in img_attrs:
            img_attrs = f' src="{img_url}"' + img_attrs
        return f"<img{img_attrs}{img_match.group(2)}"

    content = re.sub(r"<picture[^>]*>.*?</picture>", _resolve_picture, content, flags=re.DOTALL)
    return content


def _extract_with_css_selectors(raw_html: str) -> str | None:
    """Try CSS selector-based extraction when readability fails.

    Many news sites use specific class/id patterns for article bodies that
    readability-lxml misses due to surrounding DOM noise.
    """
    import lxml.etree as etree
    from lxml import html as lxml_html

    try:
        tree = lxml_html.fromstring(raw_html)
    except Exception:
        return None

    # Ordered by specificity — check most specific patterns first
    selectors = [
        "div.zox-post-body",  # SecurityWeek (Flavor theme)
        "div.article-body",  # Common news sites
        "div.entry-content",  # WordPress default
        "div.post-content",  # Common blog theme
        "div.story-body",  # News sites
        "article .content",  # Generic article content
    ]

    for selector in selectors:
        elements = tree.cssselect(selector)
        if elements:
            content = etree.tostring(elements[0], encoding="unicode", method="html")
            if content and len(content) > 200:
                return content

    return None


def _resolve_google_news_url(url: str) -> str | None:
    """Resolve a news.google.com/rss/articles/... URL to the publisher article URL.

    Google News obfuscates outbound links via base64-encoded protobuf article IDs
    that have to be exchanged with their batchexecute endpoint to get the real URL.
    Returns the resolved URL on success, None on failure (in which case the caller
    should fall back to the original URL — extraction will likely yield nothing).
    """
    if "news.google.com" not in url:
        return None
    try:
        from googlenewsdecoder import gnewsdecoder

        result = gnewsdecoder(url, interval=1)
        if result and result.get("status") and result.get("decoded_url"):
            return result["decoded_url"]
    except Exception as exc:
        logger.debug("Google News URL decode failed for %s: %s", url, exc)
    return None


async def _extract_full_text(url: str) -> tuple[str | None, str | None]:
    """Extract full article text from a URL.

    Uses curl_cffi with browser impersonation for sites with bot protection
    (e.g. Medium/Cloudflare), falling back to httpx for other sites.
    Checks robots.txt before fetching. Returns (content_html, og_image) tuple.
    """
    from app.services.rate_limiter import acquire_rate_limit
    from app.services.robots import can_fetch, get_crawl_delay

    # Google News articles redirect through an obfuscated wrapper that returns a
    # JS-only SPA. Resolve to the publisher URL up front so the rest of this
    # function operates on real article HTML.
    resolved = _resolve_google_news_url(url)
    if resolved:
        logger.info("Resolved Google News URL %s -> %s", url, resolved)
        url = resolved

    # Check robots.txt
    if not await can_fetch(url):
        logger.debug(f"robots.txt disallows fetching {url}")
        return None, None

    # Rate limit the article fetch, honoring robots.txt Crawl-delay as floor
    crawl_delay = await get_crawl_delay(url)
    if not await acquire_rate_limit(url, min_interval=crawl_delay):
        return None, None

    is_medium = _is_medium_url(url)

    try:
        raw_html = None

        # Medium (and other Cloudflare-protected sites) require browser
        # impersonation to avoid 403 bot challenges
        if is_medium:
            response = await safe_curl_get(url, impersonate="chrome", timeout=15)
            if response.status_code != 200:
                return None, None
            content_type = response.headers.get("content-type", "")
            if "html" not in content_type:
                return None, None
            raw_html = response.text
        else:
            async with safe_async_client(
                follow_redirects=True,
                timeout=15.0,
                headers={"User-Agent": str(settings.get("user_agent") or settings.user_agent)},
            ) as client:
                response = await client.get(url)
                content_type = response.headers.get("content-type", "")

                if response.status_code == 200 and "html" in content_type:
                    raw_html = response.text
                elif response.status_code in (403, 429, 503):
                    # Likely bot protection — retry with browser impersonation
                    pass

            # Fallback to curl_cffi if httpx was blocked
            if raw_html is None:
                try:
                    response = await safe_curl_get(url, impersonate="chrome", timeout=15)
                    if response.status_code == 200:
                        content_type = response.headers.get("content-type", "")
                        if "html" in content_type:
                            raw_html = response.text
                except Exception as e:
                    logger.debug(f"curl_cffi fallback failed for {url}: {e}")

        if raw_html is None:
            return None, None

        og_image = extract_og_image(raw_html, base_url=url)

        # Medium-specific extraction (readability misses most of their content)
        if is_medium:
            content = _extract_medium_article(raw_html)
            if content:
                return content, og_image

        # Try readability-lxml first
        from readability import Document

        doc = Document(raw_html)
        content = doc.summary()

        # Check plain text length (HTML tags inflate char count)
        if content:
            plain_len = len(html_to_text(content))
            if plain_len > 500:
                return content, og_image

        # Readability failed or too short — try CSS selector-based extraction
        css_content = _extract_with_css_selectors(raw_html)
        if css_content:
            return css_content, og_image

        # Return readability content if we got anything at all
        if content and len(html_to_text(content)) > 100:
            return content, og_image

        return None, og_image

    except Exception as e:
        logger.debug(f"Full-text extraction failed for {url}: {e}")

    return None, None


async def _fetch_og_image(url: str) -> str | None:
    """Lightweight fetch of just the og:image from a URL.

    Only reads the first 50KB to find the meta tag in <head>.
    """
    from app.services.rate_limiter import acquire_rate_limit
    from app.services.robots import can_fetch, get_crawl_delay

    if not await can_fetch(url):
        return None
    crawl_delay = await get_crawl_delay(url)
    if not await acquire_rate_limit(url, min_interval=crawl_delay):
        return None

    try:
        async with safe_async_client(
            follow_redirects=True,
            timeout=10.0,
            headers={"User-Agent": str(settings.get("user_agent") or settings.user_agent)},
        ) as client:
            async with client.stream("GET", url) as response:
                if response.status_code != 200:
                    return None
                content_type = response.headers.get("content-type", "")
                if "html" not in content_type:
                    return None
                # Only read the first 50KB — og:image is always in <head>
                chunks = []
                total = 0
                async for chunk in response.aiter_bytes(4096):
                    chunks.append(chunk)
                    total += len(chunk)
                    if total >= 51200:
                        break
                head_html = b"".join(chunks).decode("utf-8", errors="ignore")
                return extract_og_image(head_html, base_url=str(response.url))
    except Exception:
        return None


async def _attempt_feed_url_autodiscovery(db: AsyncSession, feed: Feed, headers: dict[str, str]) -> bool:
    """Recover a feed whose URL persistently 404s (e.g. a moved blog).

    Fetches the site homepage, parses RSS/Atom autodiscovery <link> tags, and
    verifies the first working candidate actually parses as a feed before
    updating feed.url. The URL change is recorded in adapter_config
    (url_autodiscovery_history) as an audit trail. Only called after
    FEED_404_AUTODISCOVERY_MIN_FAILURES consecutive 404s.
    """
    from urllib.parse import urlparse

    import feedparser

    from app.services.feed_discovery import extract_feed_links

    homepage = feed.site_url
    if not homepage:
        parsed_url = urlparse(feed.url)
        homepage = f"{parsed_url.scheme}://{parsed_url.netloc}/"

    try:
        # Fresh client: the fetch client carries If-None-Match/If-Modified-Since
        # conditional headers that belong to the dead feed URL.
        async with safe_async_client(follow_redirects=True, timeout=30.0, headers=headers) as client:
            try:
                response = await client.get(homepage)
            except httpx.HTTPError as e:
                logger.info("Feed %s: autodiscovery homepage fetch failed (%s): %s", feed.id, homepage, e)
                return False
            if response.status_code != 200 or "html" not in (response.headers.get("content-type") or "").lower():
                return False

            # The final URL after redirects is the correct base for relative hrefs
            candidates = extract_feed_links(response.text, str(response.url))
            for candidate in candidates:
                if candidate == feed.url:
                    continue
                # Don't take a URL already used by another feed (unique constraint)
                existing = await db.execute(select(Feed.id).where(Feed.url == candidate, Feed.id != feed.id))
                if existing.scalar_one_or_none():
                    continue
                try:
                    feed_response = await client.get(candidate)
                except httpx.HTTPError:
                    continue
                if feed_response.status_code != 200:
                    continue
                parsed_feed = feedparser.parse(feed_response.text)
                if not parsed_feed.entries:
                    continue

                old_url = feed.url
                cfg = dict(feed.adapter_config or {})
                history = list(cfg.get("url_autodiscovery_history") or [])
                history.append(
                    {
                        "old_url": old_url,
                        "new_url": candidate,
                        "at": datetime.now(UTC).isoformat(),
                        "reason": f"autodiscovery after {feed.error_count} consecutive HTTP 404s",
                    }
                )
                cfg["url_autodiscovery_history"] = history
                feed.adapter_config = cfg
                feed.url = candidate
                feed.etag = None
                feed.last_modified = None
                _note_fetch_success(feed)
                db.add(feed)
                await db.commit()
                logger.info(
                    "Feed %s (%s): URL auto-updated after persistent 404s: %s -> %s",
                    feed.id,
                    feed.title,
                    old_url,
                    candidate,
                )
                return True
    except Exception:
        logger.warning("Feed %s: URL autodiscovery failed", feed.id, exc_info=True)
    return False


async def _maybe_create_feed_error_event(db: AsyncSession, feed: Feed) -> None:
    """Create a feed_error correlation event if error_count >= 3."""
    if feed.error_count >= 3:
        try:
            from app.intelligence.correlation_events import create_feed_error_event

            event = await create_feed_error_event(
                db, feed.id, feed.title or str(feed.id), feed.error_count, feed.last_error
            )
            if event:
                await db.commit()
        except Exception:
            logger.warning("Failed to create feed_error event for feed %s", feed.id, exc_info=True)


@celery_app.task(name="app.workers.feed_tasks.check_feed_health", soft_time_limit=300, time_limit=360)
def check_feed_health():
    """Periodic task to detect stale feeds and create alerts."""
    run_async(_check_feed_health())


async def _check_feed_health():
    """Check for feeds that haven't produced entries in a long time."""
    from sqlalchemy import func as sqlfunc

    from app.intelligence.correlation_events import create_feed_stale_event
    from app.services.system_settings import warm_settings_cache

    async with _get_worker_session() as db:
        await warm_settings_cache(db)
        # Find active feeds where last entry is older than 4 months
        # and last_fetched_at is recent (so we know the feed IS being polled)
        stale_threshold = datetime.now(UTC) - timedelta(days=120)
        recently_fetched = datetime.now(UTC) - timedelta(days=2)

        result = await db.execute(
            select(Feed).where(
                Feed.is_active.is_(True),
                Feed.last_fetched_at >= recently_fetched,
            )
        )
        feeds = result.scalars().all()

        created = 0
        for feed in feeds:
            # Find the most recent entry for this feed
            latest_entry = await db.execute(select(sqlfunc.max(Entry.published_at)).where(Entry.feed_id == feed.id))
            last_published = latest_entry.scalar()

            if last_published is None:
                # No entries at all — check how long the feed has existed
                if feed.last_fetched_at and feed.last_fetched_at < stale_threshold:
                    days_since = (datetime.now(UTC) - feed.last_fetched_at).days
                    event = await create_feed_stale_event(db, feed.id, feed.title or str(feed.id), days_since)
                    if event:
                        created += 1
            elif last_published < stale_threshold:
                days_since = (datetime.now(UTC) - last_published).days
                event = await create_feed_stale_event(db, feed.id, feed.title or str(feed.id), days_since)
                if event:
                    created += 1

        if created:
            await db.commit()
            logger.info("Created %d feed_stale events", created)

        # Also create events for feeds with persistent errors (3+)
        error_result = await db.execute(
            select(Feed).where(
                Feed.is_active.is_(True),
                Feed.error_count >= 3,
            )
        )
        error_feeds = error_result.scalars().all()
        error_created = 0
        for feed in error_feeds:
            from app.intelligence.correlation_events import create_feed_error_event

            event = await create_feed_error_event(
                db, feed.id, feed.title or str(feed.id), feed.error_count, feed.last_error
            )
            if event:
                error_created += 1

        if error_created:
            await db.commit()
            logger.info("Created %d feed_error events from health check", error_created)

        # Dead feeds: a 4xx streak that has outlasted the window is a moved or
        # withdrawn feed, not a quiet one. Only client errors count — a
        # seldom-posting blog answers 200 with an old feed, never 404 — and
        # the clock is the streak start, not the last post, so a quiet source
        # is never paused for being quiet.
        pause_days = int(settings.get("feed_auto_pause_days") or 0)
        if pause_days > 0:
            paused = await _auto_pause_dead_feeds(db, pause_days)
            if paused:
                logger.info("Auto-paused %d dead feeds (HTTP 4xx for %d+ days)", paused, pause_days)


@celery_app.task(name="app.workers.feed_tasks.backfill_transcripts", soft_time_limit=1800, time_limit=1860)
def backfill_transcripts():
    """Backfill transcripts into entry content.

    1. For YouTube entries: fetch transcripts via youtube-transcript-api
    2. For all entries with media transcript_text: append to entry content if not already there
    """
    run_async(_backfill_transcripts())


async def _backfill_transcripts():
    import html as html_mod

    from app.services.meilisearch_client import index_entry
    from app.services.youtube_transcript import fetch_youtube_transcript

    stats = {"youtube_fetched": 0, "youtube_failed": 0, "content_updated": 0, "already_has": 0}

    async with _get_worker_session() as db:
        # Step 1: Fetch missing YouTube transcripts
        yt_media_result = await db.execute(
            select(EntryMedia)
            .join(Entry, Entry.id == EntryMedia.entry_id)
            .join(Feed, Feed.id == Entry.feed_id)
            .where(
                Feed.feed_type == "youtube",
                EntryMedia.media_type == "video",
                EntryMedia.transcript_text.is_(None),
            )
        )
        yt_media_records = yt_media_result.scalars().all()
        logger.info("Found %d YouTube entries missing transcripts", len(yt_media_records))

        for media in yt_media_records:
            # Get video_id from entry metadata
            entry_result = await db.execute(select(Entry).where(Entry.id == media.entry_id))
            entry = entry_result.scalar_one_or_none()
            if not entry or not entry.metadata_:
                continue

            video_id = entry.metadata_.get("video_id")
            if not video_id:
                continue

            transcript_text = await fetch_youtube_transcript(video_id)
            if transcript_text:
                media.transcript_text = transcript_text
                stats["youtube_fetched"] += 1
            else:
                stats["youtube_failed"] += 1

        await db.commit()
        logger.info(
            "YouTube transcript fetch: %d fetched, %d failed", stats["youtube_fetched"], stats["youtube_failed"]
        )

        # Step 2: Append transcript to entry content where missing
        media_with_transcript = await db.execute(select(EntryMedia).where(EntryMedia.transcript_text.isnot(None)))
        for media in media_with_transcript.scalars().all():
            entry_result = await db.execute(select(Entry).where(Entry.id == media.entry_id))
            entry = entry_result.scalar_one_or_none()
            if not entry:
                continue

            # Skip if transcript already appended
            if entry.content_text and "Transcript:" in entry.content_text:
                stats["already_has"] += 1
                continue

            transcript_section = (
                f'<div class="transcript"><h3>Transcript</h3><p>{html_mod.escape(media.transcript_text)}</p></div>'
            )
            entry.content_html = (entry.content_html or "") + transcript_section
            entry.content_text = (entry.content_text or "") + "\n\nTranscript:\n" + media.transcript_text
            entry.word_count = len(entry.content_text.split())

            # Re-index in Meilisearch
            try:
                index_entry(
                    entry_id=entry.id,
                    feed_id=entry.feed_id,
                    title=entry.title,
                    content_text=entry.content_text,
                    summary=entry.summary,
                    author=entry.author,
                    published_at=entry.published_at.isoformat() if entry.published_at else None,
                    feed_type=None,
                    word_count=entry.word_count,
                )
            except Exception:
                pass
            stats["content_updated"] += 1

        await db.commit()

    logger.info("Transcript backfill complete: %s", stats)
    return stats


@celery_app.task(
    name="app.workers.feed_tasks.full_sync_github_feed",
    soft_time_limit=3600,
    time_limit=3660,
)
def full_sync_github_feed(feed_id: str, user_id: str | None = None):
    """Import ALL matching files from a GitHub repo, not just recent changes.

    Uses the Git Trees API to enumerate every file in the repo, then creates
    entries for files we don't already have.  Dispatches intel extraction for
    each new entry afterwards.
    """
    start = _time.monotonic()
    try:
        stats = run_async(_full_sync_github_feed(feed_id, user_id))
        CELERY_TASKS_TOTAL.labels(task_name="full_sync_github_feed", status="success").inc()
        logger.info("Full sync complete for feed %s: %s", feed_id, stats)
        return stats
    except SoftTimeLimitExceeded:
        CELERY_TASKS_TOTAL.labels(task_name="full_sync_github_feed", status="timeout").inc()
        logger.warning("Full sync timed out for feed %s", feed_id)
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="full_sync_github_feed", status="error").inc()
        logger.exception("Full sync failed for feed %s", feed_id)
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="full_sync_github_feed").observe(_time.monotonic() - start)


def _update_sync_progress(feed_id: str, data: dict) -> None:
    """Write progress to Redis so it can be polled."""
    try:
        import json

        import redis as _redis

        r = _redis.from_url(settings.redis_url)
        try:
            r.setex(
                f"full_sync:{feed_id}",
                3600,  # expire after 1 hour
                json.dumps(data),
            )
        finally:
            r.close()
    except Exception:
        logger.warning("Failed to update sync progress for feed %s", feed_id, exc_info=True)


async def _full_sync_github_feed(feed_id: str, user_id: str | None = None) -> dict:
    from app.adapters.github_repo import GitHubRepoAdapter

    stats = {"total_in_tree": 0, "already_existed": 0, "imported": 0, "to_import": 0}

    async with _get_worker_session() as db:
        # Ensure system settings cache is loaded so the adapter can read
        # the GitHub token (stored as an encrypted DB secret).
        from app.services.system_settings import _ensure_cache

        await _ensure_cache(db)
        result = await db.execute(select(Feed).where(Feed.id == feed_id))
        feed = result.scalar_one_or_none()
        if not feed or feed.feed_type != "github_repo":
            return {"error": "Feed not found or not a github_repo feed"}

        feed_title = feed.title or f"{feed.adapter_config.get('owner')}/{feed.adapter_config.get('repo')}"
        config = dict(feed.adapter_config) if feed.adapter_config else {}

        _update_sync_progress(
            feed_id,
            {
                "feed_title": feed_title,
                "status": "scanning_tree",
                **stats,
            },
        )

        # Collect existing GUIDs for this feed so the adapter can skip them
        guid_result = await db.execute(select(Entry.guid).where(Entry.feed_id == feed.id))
        existing_guids = {row[0] for row in guid_result.all()}
        stats["already_existed"] = len(existing_guids)

        adapter = GitHubRepoAdapter()
        feed_meta, parsed_entries = await adapter.fetch_full_tree(config, existing_guids=existing_guids)
        stats["total_in_tree"] = len(existing_guids) + len(parsed_entries)
        stats["to_import"] = len(parsed_entries)

        _update_sync_progress(
            feed_id,
            {
                "feed_title": feed_title,
                "status": "importing",
                **stats,
            },
        )

        # Publish progress event
        try:
            from app.api.events import publish_event

            if user_id:
                publish_event(
                    user_id,
                    "full_sync_progress",
                    {
                        "feed_id": feed_id,
                        "status": "importing",
                        "new_files": len(parsed_entries),
                    },
                )
        except Exception:
            logger.warning("Failed to publish sync progress event for feed %s", feed_id, exc_info=True)

        new_entry_ids = []
        for parsed in parsed_entries:
            # Double-check GUID uniqueness (adapter already filtered, but be safe)
            dup = await db.execute(select(Entry.id).where(Entry.feed_id == feed.id, Entry.guid == parsed.guid))
            if dup.scalar_one_or_none():
                continue

            content_text = None
            sanitized = None
            if parsed.content_html:
                sanitized = sanitize_html(parsed.content_html)
                content_text = html_to_text(parsed.content_html)

            word_count = len(content_text.split()) if content_text else None
            content_hash = compute_content_hash(parsed.title, content_text)

            # Cross-guid dedup: skip if an entry with this content_hash already exists.
            existing = await db.execute(select(Entry.id).where(Entry.content_hash == content_hash).limit(1))
            if existing.scalar_one_or_none():
                logger.debug("Skipping content-hash duplicate %s for feed %s", parsed.guid, feed.id)
                continue

            entry_metadata = parsed.metadata

            entry = Entry(
                feed_id=feed.id,
                guid=parsed.guid,
                url=parsed.url,
                title=parsed.title,
                author=parsed.author,
                content_html=sanitized,
                content_text=content_text,
                summary=parsed.summary,
                image_url=None,
                published_at=parsed.published_at,
                word_count=word_count,
                content_hash=content_hash,
                metadata_=entry_metadata,
            )
            db.add(entry)
            await db.flush()
            new_entry_ids.append(str(entry.id))
            stats["imported"] += 1

            # Commit in batches to avoid holding a huge transaction
            if len(new_entry_ids) % 50 == 0:
                await db.commit()
                _update_sync_progress(
                    feed_id,
                    {
                        "feed_title": feed_title,
                        "status": "importing",
                        **stats,
                    },
                )
                logger.info(
                    "Full sync %s: imported %d/%d entries so far",
                    feed.title,
                    stats["imported"],
                    len(parsed_entries),
                )

        # Persist head SHA so incremental fetches continue from here
        if hasattr(feed_meta, "extra") and feed_meta.extra.get("_head_sha"):
            adapter_config = dict(feed.adapter_config) if feed.adapter_config else {}
            adapter_config["last_commit_sha"] = feed_meta.extra["_head_sha"]
            feed.adapter_config = adapter_config
            db.add(feed)

        await db.commit()

        # Dispatch entry processing pipeline for new entries
        if new_entry_ids:
            run_extraction = bool(feed.auto_extract_on_ingest or feed.extract_detection_rules)
            try:
                from app.pipeline.plans import resolve_feed_plan

                feed_plan = await resolve_feed_plan(db, feed)
                translate_target = _auto_translate_target(feed)
                for eid in new_entry_ids:
                    dispatch_entry_pipeline(
                        eid,
                        run_extraction=run_extraction,
                        plan=feed_plan,
                        translate_target=translate_target,
                    )
            except Exception:
                logger.warning("Failed to dispatch entry pipeline for full sync feed %s", feed_id, exc_info=True)

        stats["status"] = "complete"
        _update_sync_progress(
            feed_id,
            {
                "feed_title": feed_title,
                **stats,
            },
        )

        # Publish completion event
        try:
            from app.api.events import publish_event

            if user_id:
                publish_event(
                    user_id,
                    "full_sync_complete",
                    {
                        "feed_id": feed_id,
                        "feed_title": feed_title,
                        **stats,
                    },
                )
        except Exception:
            logger.warning("Failed to publish sync completion event for feed %s", feed_id, exc_info=True)

    return stats
