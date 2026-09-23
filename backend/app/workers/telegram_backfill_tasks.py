"""One-shot backfills for Telegram entries that pre-date later adapter fixes.

The album-merge logic in `TelegramAdapter._merge_album_groups` only applies to
fresh fetches, so existing albums in the DB still live as N separate per-message
entries — caption stranded on one row, the rest carrying empty "Message N" titles
with one media item each. This module groups those by `metadata.telegram_grouped_id`,
moves all sibling media onto the canonical caption-bearing entry, and deletes the
strays.

Trigger via:
    docker compose exec api python -m app.scripts.backfill_telegram_albums
or queue from the worker shell:
    backfill_telegram_albums.delay()
"""

from __future__ import annotations

import logging
import time as _time
from collections import defaultdict

from sqlalchemy import delete, select, update

from app.core.metrics import CELERY_TASK_DURATION_SECONDS, CELERY_TASKS_TOTAL
from app.models.entry import Entry
from app.models.entry_media import EntryMedia
from app.models.feed import Feed
from app.workers.celery_app import celery_app
from app.workers.db import run_async, worker_session
from app.workers.feed_tasks import _maybe_dispatch_auto_translate

logger = logging.getLogger(__name__)


@celery_app.task(
    name="app.workers.telegram_backfill_tasks.backfill_telegram_albums",
    soft_time_limit=600,
    time_limit=900,
)
def backfill_telegram_albums(feed_id: str | None = None) -> dict:
    """Coalesce existing Telegram album-fragment entries into a single entry each.

    Pass `feed_id` to scope to one feed; omit to scan every Telegram feed.
    """
    start = _time.monotonic()
    try:
        result = run_async(_backfill(feed_id))
        CELERY_TASKS_TOTAL.labels(task_name="backfill_telegram_albums", status="success").inc()
        return result
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="backfill_telegram_albums", status="error").inc()
        logger.exception("backfill_telegram_albums failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="backfill_telegram_albums").observe(_time.monotonic() - start)


async def _backfill(feed_id: str | None) -> dict:
    stats = {"feeds_scanned": 0, "groups_merged": 0, "entries_deleted": 0, "media_reparented": 0}
    async with worker_session() as db:
        feed_q = select(Feed).where(Feed.feed_type == "telegram")
        if feed_id:
            feed_q = feed_q.where(Feed.id == feed_id)
        feeds = (await db.execute(feed_q)).scalars().all()

        for feed in feeds:
            stats["feeds_scanned"] += 1
            entries = (
                (
                    await db.execute(
                        select(Entry)
                        .where(Entry.feed_id == feed.id)
                        .where(Entry.metadata_["telegram_grouped_id"].isnot(None))
                    )
                )
                .scalars()
                .all()
            )
            groups: dict[int, list[Entry]] = defaultdict(list)
            for e in entries:
                gid = (e.metadata_ or {}).get("telegram_grouped_id")
                if gid:
                    groups[int(gid)].append(e)

            translate_targets: list[str] = []
            for gid, group in groups.items():
                if len(group) < 2:
                    continue
                # Canonical = the entry that actually has caption text. Title fallback
                # in the adapter starts with "Message " for media-only items, so the
                # one without that prefix carries the caption.
                canonical = next(
                    (e for e in group if e.title and not e.title.startswith("Message ")),
                    None,
                )
                if canonical is None:
                    # Whole album is media-only — keep the lowest-id entry as canonical
                    # so subsequent fetches don't re-create the stragglers.
                    canonical = min(group, key=lambda e: (e.metadata_ or {}).get("message_id", 0))
                sibling_ids = [e.id for e in group if e.id != canonical.id]
                if not sibling_ids:
                    continue

                reparented = await db.execute(
                    update(EntryMedia).where(EntryMedia.entry_id.in_(sibling_ids)).values(entry_id=canonical.id)
                )
                stats["media_reparented"] += reparented.rowcount or 0

                deleted = await db.execute(delete(Entry).where(Entry.id.in_(sibling_ids)))
                stats["entries_deleted"] += deleted.rowcount or 0
                stats["groups_merged"] += 1
                translate_targets.append(str(canonical.id))

            await db.commit()

            if translate_targets:
                _maybe_dispatch_auto_translate(feed, translate_targets)

    logger.info("backfill_telegram_albums done: %s", stats)
    return stats
