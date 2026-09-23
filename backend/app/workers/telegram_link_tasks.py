"""Scan ingested entries for Telegram channel/invite/message links and persist them.

Runs as part of the entry processing pipeline (alongside autolink + extraction).
Reads entry.content_html + entry.content_text, extracts Telegram URLs, upserts
into telegram_channel_mentions (deduped) and telegram_link_mentions (raw refs).
"""

from __future__ import annotations

import logging
import time as _time
import uuid as _uuid

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.core.metrics import CELERY_TASK_DURATION_SECONDS, CELERY_TASKS_TOTAL
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.telegram_mention import TelegramChannelMention, TelegramLinkMention
from app.services.telegram_link_extractor import extract_links, unique_handles
from app.workers.celery_app import celery_app
from app.workers.db import run_async, worker_session
from app.workers.pipeline_logging import pipeline_stage

logger = logging.getLogger(__name__)


@celery_app.task(
    name="app.workers.telegram_link_tasks.scan_telegram_links_task",
    soft_time_limit=60,
    time_limit=90,
)
@pipeline_stage("telegram_links")
def scan_telegram_links_task(entry_id: str):
    """Scan one entry's body for telegram links and write mentions."""
    start = _time.monotonic()
    try:
        result = run_async(_scan_one(entry_id))
        CELERY_TASKS_TOTAL.labels(task_name="scan_telegram_links_task", status="success").inc()
        return result
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="scan_telegram_links_task", status="error").inc()
        logger.exception("scan_telegram_links_task failed for entry %s", entry_id)
        return None
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="scan_telegram_links_task").observe(_time.monotonic() - start)


async def _scan_one(entry_id: str) -> dict:
    async with worker_session() as db:
        result = await db.execute(select(Entry).where(Entry.id == _uuid.UUID(entry_id)))
        entry = result.scalar_one_or_none()
        if entry is None:
            return {"entry_id": entry_id, "skipped": "not_found"}

        # Don't scan telegram-feed entries — that would record the channel itself as a mention
        # of itself on every post. Pointless noise.
        feed = await db.get(Feed, entry.feed_id) if entry.feed_id else None
        if feed and feed.feed_type == "telegram":
            return {"entry_id": entry_id, "skipped": "telegram_source"}

        haystack_parts = []
        if entry.content_html:
            haystack_parts.append(entry.content_html)
        if entry.content_text:
            haystack_parts.append(entry.content_text)
        if entry.summary:
            haystack_parts.append(entry.summary)
        if not haystack_parts:
            return {"entry_id": entry_id, "links_found": 0}

        haystack = "\n".join(haystack_parts)
        links = extract_links(haystack)
        if not links:
            return {"entry_id": entry_id, "links_found": 0}

        handle_map = unique_handles(links)
        new_channels = 0
        new_links = 0

        for handle, repr_link in handle_map.items():
            # Upsert the per-channel aggregate row first to obtain its id
            channel_row = await db.execute(
                select(TelegramChannelMention).where(TelegramChannelMention.handle == handle)
            )
            channel = channel_row.scalar_one_or_none()
            if channel is None:
                channel = TelegramChannelMention(
                    handle=handle,
                    display_handle=repr_link.display_handle,
                    canonical_url=repr_link.url,
                    primary_link_type=repr_link.link_type if repr_link.link_type != "deep_link" else "channel",
                    mention_count=0,
                    distinct_feed_count=0,
                )
                db.add(channel)
                await db.flush()
                new_channels += 1

            # If we now know the channel exists (e.g. previously only invite-known, now seen
            # by handle), upgrade primary_link_type and canonical_url
            if channel.primary_link_type == "invite" and repr_link.link_type in ("channel", "message"):
                channel.primary_link_type = "channel"
                channel.canonical_url = f"https://t.me/{repr_link.display_handle}"
                channel.display_handle = repr_link.display_handle

            # Insert one link mention per (entry_id, url) — uq constraint dedupes re-runs
            for link in links:
                if link.handle != handle:
                    continue
                stmt = (
                    pg_insert(TelegramLinkMention.__table__)
                    .values(
                        channel_id=channel.id,
                        entry_id=entry.id,
                        feed_id=entry.feed_id,
                        url=link.url,
                        link_type=link.link_type,
                        message_id=link.message_id,
                        invite_hash=link.invite_hash,
                    )
                    .on_conflict_do_nothing(index_elements=["entry_id", "url"])
                )
                result = await db.execute(stmt)
                if result.rowcount:
                    new_links += int(result.rowcount)

            # Refresh aggregate counters from the canonical source (the link table):
            # mention_count = total link rows, distinct_feed_count = distinct feed_ids,
            # last_seen = max discovered_at — all in one aggregate query.
            from sqlalchemy import func as _f

            agg = await db.execute(
                select(
                    _f.count().label("n"),
                    _f.count(_f.distinct(TelegramLinkMention.feed_id)).label("feeds"),
                    _f.max(TelegramLinkMention.discovered_at).label("last_seen"),
                ).where(TelegramLinkMention.channel_id == channel.id)
            )
            row = agg.one()
            channel.mention_count = int(row.n or 0)
            channel.distinct_feed_count = int(row.feeds or 0)
            if row.last_seen:
                channel.last_seen_at = row.last_seen

            # Cache feed_id if we now have a Telegram feed for this channel
            if channel.feed_id is None:
                feed_lookup = await db.execute(select(Feed).where(Feed.feed_type == "telegram"))
                for f in feed_lookup.scalars().all():
                    cfg = f.adapter_config or {}
                    cfg_handle = (cfg.get("channel_username") or (cfg.get("channel") or "")).lstrip("@").lower()
                    if cfg_handle == handle:
                        channel.feed_id = f.id
                        break

            db.add(channel)

        await db.commit()
        return {
            "entry_id": entry_id,
            "links_found": len(links),
            "unique_channels": len(handle_map),
            "new_channels": new_channels,
            "new_links": new_links,
        }
