"""The enrichment dispatcher: runs due rows of the enrichment job queue.

Routed to the ``enrichment`` queue, which only celery-worker-enrichment reads,
at concurrency 1: ticks run one after another and never hold a slot on the
default worker while a source makes them wait.
"""

import logging
import time

from app.core.metrics import CELERY_TASK_DURATION_SECONDS, CELERY_TASKS_TOTAL
from app.workers.celery_app import celery_app
from app.workers.db import run_async, worker_session

logger = logging.getLogger(__name__)


def _get_worker_session():
    return worker_session()


@celery_app.task(
    name="app.workers.enrichment_dispatch_tasks.dispatch_enrichment_jobs", soft_time_limit=90, time_limit=120
)
def dispatch_enrichment_jobs():
    """Every 30s: run due enrichment jobs for up to TICK_SECONDS."""
    start = time.monotonic()
    try:
        stats = run_async(_dispatch_enrichment_jobs())
        if stats:
            logger.info("Enrichment dispatch: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="dispatch_enrichment_jobs", status="success").inc()
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="dispatch_enrichment_jobs", status="error").inc()
        logger.exception("Enrichment dispatch failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="dispatch_enrichment_jobs").observe(time.monotonic() - start)


async def _dispatch_enrichment_jobs() -> dict[str, int]:
    from app.enrichment.queue import dispatch_due

    async with _get_worker_session() as db:
        return await dispatch_due(db)


@celery_app.task(name="app.workers.enrichment_dispatch_tasks.sync_enrichment_pause", soft_time_limit=30, time_limit=60)
def sync_enrichment_pause():
    """Every minute, on the default worker: copy the stored enrichment pause
    onto the gateways' Redis flag, so a Redis that lost it is corrected even
    while the enrichment worker (whose dispatcher also syncs it) is down.
    Returns {"restored": True} only when the flag had been lost."""
    restored = run_async(_sync_enrichment_pause())
    return {"restored": True} if restored else None


async def _sync_enrichment_pause() -> bool:
    from app.enrichment.pause import reassert_pause

    async with _get_worker_session() as db:
        _, restored = await reassert_pause(db)
        return restored
