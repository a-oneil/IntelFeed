"""The edge sweep's Celery task (app/services/relationship_sweep.py).

Runs on the ai queue (celery-worker-ai, concurrency 1) every 30 minutes from
the job registry's ``review-relationships`` entry. One run at a time: a
manual dispatch and the schedule can coincide.
"""

from __future__ import annotations

import logging
import time

import redis

from app.config import settings
from app.core.metrics import CELERY_TASK_DURATION_SECONDS, CELERY_TASKS_TOTAL
from app.workers.celery_app import celery_app
from app.workers.db import run_async, worker_session

logger = logging.getLogger(__name__)


@celery_app.task(
    name="app.workers.relationship_sweep_tasks.sweep_relationships",
    soft_time_limit=1800,
    time_limit=1860,
)
def sweep_relationships(limit: int | None = None) -> dict:
    from app.services.relationship_sweep import LOCK_KEY, LOCK_TTL_SECONDS

    r = redis.from_url(settings.redis_url)
    if not r.set(LOCK_KEY, "1", nx=True, ex=LOCK_TTL_SECONDS):
        r.close()
        return {"status": "locked"}
    start = time.monotonic()
    try:
        stats = run_async(_sweep(limit))
        CELERY_TASKS_TOTAL.labels(task_name="sweep_relationships", status="success").inc()
        logger.info("sweep_relationships: %s", stats)
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="sweep_relationships", status="error").inc()
        logger.exception("sweep_relationships failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="sweep_relationships").observe(time.monotonic() - start)
        try:
            r.delete(LOCK_KEY)
            r.close()
        except Exception:
            pass


async def _sweep(limit: int | None) -> dict:
    from app.services.relationship_sweep import sweep
    from app.services.system_settings import _ensure_cache, invalidate_cache

    async with worker_session() as db:
        # Workers don't share the API's settings cache.
        invalidate_cache()
        await _ensure_cache(db)
        return await sweep(db, limit)
