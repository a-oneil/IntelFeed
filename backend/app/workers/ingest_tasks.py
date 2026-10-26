"""Celery side of bulk ingest: one task per batch item.

Parsing is CPU and I/O, not AI, so this runs on the default ``celery`` queue —
never inside the api process, whose memory cap is the tightest in the stack.
The entry pipeline the item goes on to (autolink, observables, extract, score,
and the one-pass AI analysis on the ``ai`` queue) is dispatched by
services/ingest_batches.process_item exactly as for a polled entry.
"""

import logging
import time
import uuid

from celery.exceptions import SoftTimeLimitExceeded

from app.core.metrics import CELERY_TASK_DURATION_SECONDS, CELERY_TASKS_TOTAL
from app.services.system_settings import warm_settings_cache
from app.workers.celery_app import celery_app
from app.workers.db import run_async, worker_session

logger = logging.getLogger(__name__)


def _get_worker_session():
    return worker_session()


@celery_app.task(
    name="app.workers.ingest_tasks.process_ingest_item",
    bind=True,
    max_retries=2,
    soft_time_limit=900,
    time_limit=960,
)
def process_ingest_item(self, item_id: str) -> str:
    """Parse one ingest item into an entry, or into a terminal status."""
    start = time.monotonic()
    try:
        status = run_async(_process(item_id))
    except SoftTimeLimitExceeded:
        # The item row is the error report; mark it rather than leaving "parsing" behind.
        run_async(_mark_timed_out(item_id))
        CELERY_TASKS_TOTAL.labels(task_name="process_ingest_item", status="error").inc()
        return "failed"
    except Exception as exc:
        # Infrastructure trouble (DB/Redis unreachable): retry; a parse error
        # never reaches here because process_item turns it into a status.
        CELERY_TASKS_TOTAL.labels(task_name="process_ingest_item", status="retry").inc()
        raise self.retry(exc=exc, countdown=30)
    CELERY_TASKS_TOTAL.labels(task_name="process_ingest_item", status="success").inc()
    CELERY_TASK_DURATION_SECONDS.labels(task_name="process_ingest_item").observe(time.monotonic() - start)
    return status


async def _process(item_id: str) -> str:
    from app.services.ingest_batches import process_item

    async with _get_worker_session() as db:
        await warm_settings_cache(db)
        item = await process_item(db, uuid.UUID(item_id))
        return item.status


async def _mark_timed_out(item_id: str) -> None:
    from datetime import UTC, datetime

    from app.models.ingest_batch import ITEM_FAILED, ITEM_PARSING
    from app.services.ingest_batches import _broadcast_item, get_item

    async with _get_worker_session() as db:
        item = await get_item(db, uuid.UUID(item_id))
        if item is None or item.status != ITEM_PARSING:
            return
        item.status = ITEM_FAILED
        item.error = "Parsing ran past the time limit"
        item.finished_at = datetime.now(UTC)
        await db.commit()
        _broadcast_item(item)
