"""Celery task: daily Reddit digest via AI summarization."""

import logging
import time
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import Integer, cast, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.metrics import CELERY_TASK_DURATION_SECONDS, CELERY_TASKS_TOTAL
from app.workers.celery_app import celery_app
from app.workers.db import run_async, worker_session

logger = logging.getLogger(__name__)

DIGEST_FEED_URL = "intelfeed://reddit-digest"
MIN_ENTRIES_FOR_DIGEST = 3  # fallback for reddit_digest_min_entries
MAX_ENTRIES_FOR_PROMPT = 20  # fallback for reddit_digest_max_entries


@celery_app.task(
    name="app.workers.reddit_digest_tasks.generate_reddit_digest",
    soft_time_limit=300,
    time_limit=360,
)
def generate_reddit_digest():
    """Generate a daily AI digest of top Reddit security posts."""
    start = time.monotonic()
    try:
        result = run_async(_generate_reddit_digest())
        logger.info("Reddit digest result: %s", result)
        CELERY_TASKS_TOTAL.labels(task_name="generate_reddit_digest", status="success").inc()
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="generate_reddit_digest", status="error").inc()
        logger.exception("Reddit digest generation failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="generate_reddit_digest").observe(time.monotonic() - start)


async def _generate_reddit_digest():
    from app.ai.engine import run_task
    from app.config import settings
    from app.models.entry import Entry
    from app.models.feed import Feed
    from app.services.sanitizer import html_to_text
    from app.services.system_settings import warm_settings_cache

    async with worker_session() as db:
        await warm_settings_cache(db)
        min_entries = int(settings.get("reddit_digest_min_entries") or MIN_ENTRIES_FOR_DIGEST)
        max_entries = int(settings.get("reddit_digest_max_entries") or MAX_ENTRIES_FOR_PROMPT)

        # 1. Find all active Reddit feeds
        reddit_feeds = (
            (
                await db.execute(
                    select(Feed).where(Feed.feed_type == "reddit", Feed.is_active == True)  # noqa: E712
                )
            )
            .scalars()
            .all()
        )

        if not reddit_feeds:
            return {"status": "skipped", "reason": "no active reddit feeds"}

        reddit_feed_ids = [f.id for f in reddit_feeds]
        feed_id_to_sub = {f.id: (f.adapter_config or {}).get("subreddit", f.title) for f in reddit_feeds}

        # 2. Get entries from the last 24 hours, take top N per subreddit for balanced coverage
        cutoff = datetime.now(UTC) - timedelta(hours=24)
        all_entries_result = await db.execute(
            select(Entry)
            .where(
                Entry.feed_id.in_(reddit_feed_ids),
                Entry.fetched_at >= cutoff,
            )
            .order_by(cast(Entry.metadata_["score"].as_string(), Integer).desc().nulls_last())
        )
        all_entries = all_entries_result.scalars().all()

        # Take up to 3 per subreddit to ensure representation, then fill remaining slots
        max_per_sub = 3
        by_sub: dict[str, list] = {}
        overflow = []
        for e in all_entries:
            sub = feed_id_to_sub.get(e.feed_id, "unknown")
            if sub not in by_sub:
                by_sub[sub] = []
            if len(by_sub[sub]) < max_per_sub:
                by_sub[sub].append(e)
            else:
                overflow.append(e)

        # Merge: guaranteed slots first, then fill with highest-scored overflow
        entries = []
        for sub_entries in by_sub.values():
            entries.extend(sub_entries)
        remaining = max_entries - len(entries)
        if remaining > 0:
            entries.extend(overflow[:remaining])

        # Sort final list by score descending for the prompt
        entries.sort(
            key=lambda e: (
                (e.metadata_ or {}).get("score", 0) if isinstance((e.metadata_ or {}).get("score"), int) else 0
            ),
            reverse=True,
        )

        if len(entries) < min_entries:
            return {
                "status": "skipped",
                "reason": f"only {len(entries)} entries (need {min_entries})",
            }

        # 3. Get or create the digest feed
        digest_feed = await _ensure_digest_feed(db)

        # 4. Check for existing digest today (dedup by guid)
        today_str = datetime.now(UTC).strftime("%Y-%m-%d")
        digest_guid = f"reddit-digest-{today_str}"
        existing = await db.execute(select(Entry.id).where(Entry.feed_id == digest_feed.id, Entry.guid == digest_guid))
        if existing.scalar_one_or_none():
            return {"status": "skipped", "reason": "digest already exists for today"}

        # 5. Build variables for the AI prompt
        subreddits = sorted(set((e.metadata_ or {}).get("subreddit", "unknown") for e in entries))
        entry_vars = []
        for e in entries:
            meta = e.metadata_ or {}
            entry_vars.append(
                {
                    "title": e.title,
                    "url": e.url,
                    "subreddit": meta.get("subreddit", "unknown"),
                    "score": meta.get("score", 0),
                    "num_comments": meta.get("num_comments", 0),
                    "content_text": (e.content_text or "")[:500],
                }
            )

        variables = {
            "entries": entry_vars,
            "entry_count": len(entry_vars),
            "date": today_str,
            "subreddits": subreddits,
        }

        # 6. Task assignments are app-wide, so one run as the system user suffices
        from app.services.system_user import get_system_user_id

        system_user_id = await get_system_user_id(db)
        result = None
        if system_user_id:
            result = await run_task(
                db=db,
                user_id=system_user_id,
                task_name="reddit_digest",
                variables=variables,
                target_type="digest",
                target_id=uuid.uuid5(uuid.NAMESPACE_URL, digest_guid),
                force=True,
            )

        if not result or "_error" in (result or {}):
            await db.commit()
            return {"status": "no_ai_assignment"}

        # 7. Extract digest content — handle JSON parse failures gracefully
        digest_html = result.get("digest_html", "")
        top_posts = result.get("top_posts", [])

        # If the AI response failed JSON parsing, try to extract HTML from raw text
        if not digest_html and result.get("_extraction_status") == "parse_error":
            raw = result.get("raw", "")
            digest_html = _extract_html_from_raw(raw)
            logger.info("Extracted %d chars of HTML from raw AI response", len(digest_html))
        content_text = html_to_text(digest_html) if digest_html else ""

        digest_entry = Entry(
            feed_id=digest_feed.id,
            guid=digest_guid,
            url=None,
            title=f"Reddit Digest \u2014 {today_str}",
            author="IntelFeed AI",
            content_html=digest_html,
            content_text=content_text,
            summary=content_text[:300] if content_text else None,
            published_at=datetime.now(UTC),
            word_count=len(content_text.split()) if content_text else 0,
            metadata_={
                "source": "reddit_digest",
                "top_posts": top_posts,
                "entry_count": len(entries),
                "subreddits": subreddits,
                "generated_at": datetime.now(UTC).isoformat(),
            },
        )
        db.add(digest_entry)
        await db.flush()

        # Index in Meilisearch
        try:
            from app.services.meilisearch_client import index_entry

            index_entry(
                entry_id=digest_entry.id,
                feed_id=digest_feed.id,
                title=digest_entry.title,
                content_text=content_text,
                summary=digest_entry.summary,
                author=digest_entry.author,
                published_at=digest_entry.published_at.isoformat(),
                feed_type="reddit",
                word_count=digest_entry.word_count,
                language=None,
                feed_title=digest_feed.title,
            )
        except Exception as exc:
            logger.warning("Meilisearch indexing failed for digest: %s", exc)

        await db.commit()

        return {
            "status": "created",
            "date": today_str,
            "entries_analyzed": len(entries),
            "subreddits": subreddits,
        }


async def _ensure_digest_feed(db: AsyncSession):
    """Get or create the synthetic Reddit Digest feed."""
    from app.models.feed import Feed

    result = await db.execute(select(Feed).where(Feed.url == DIGEST_FEED_URL))
    feed = result.scalar_one_or_none()

    if feed:
        return feed

    feed = Feed(
        url=DIGEST_FEED_URL,
        title="Reddit Digest",
        feed_type="reddit",
        is_active=True,
        fetch_interval_minutes=525600,  # ~1 year; effectively never polled — populated by Celery task
        description="Daily AI-generated digest of top Reddit security community posts",
        intel_extraction_mode="none",
    )
    db.add(feed)
    await db.flush()

    # System feed — visible to everyone
    from app.services.feed_visibility import subscribe_all_users

    await subscribe_all_users(db, feed.id)
    await db.flush()
    logger.info("Created Reddit Digest feed: %s", feed.id)
    return feed


def _extract_html_from_raw(raw: str) -> str:
    """Best-effort extraction of HTML from a raw AI response that failed JSON parsing."""
    import json
    import re

    # Try to extract JSON from markdown code blocks
    content = raw.strip()
    if "```json" in content:
        content = content.split("```json", 1)[1].split("```", 1)[0].strip()
    elif "```" in content:
        content = content.split("```", 1)[1].split("```", 1)[0].strip()

    # Try parsing as JSON
    try:
        parsed = json.loads(content)
        return parsed.get("digest_html", "")
    except json.JSONDecodeError:
        pass

    # Try to extract digest_html value with regex
    match = re.search(r'"digest_html"\s*:\s*"(.*?)"\s*,\s*"top_posts"', content, re.DOTALL)
    if match:
        # Unescape JSON string
        try:
            return json.loads(f'"{match.group(1)}"')
        except json.JSONDecodeError:
            return match.group(1).replace('\\"', '"').replace("\\n", "\n")

    # Last resort: if the response contains HTML tags, use it directly
    if "<h3>" in raw and "</p>" in raw:
        start = raw.index("<h3>")
        # Find the last closing tag
        for tag in ["</ul>", "</p>", "</li>"]:
            idx = raw.rfind(tag)
            if idx > start:
                return raw[start : idx + len(tag)]

    return ""
