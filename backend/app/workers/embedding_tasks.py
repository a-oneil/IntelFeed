"""Entry embedding sweeper.

Runs on the **default** queue, not the `ai` queue. The ai worker is a
concurrency-1 serializer that exists to pace one GPU through generative calls
and to hold the CLI credentials volume; embedding needs neither, and parking a
multi-thousand-entry backfill behind a nightly enrichment run would starve both.

The sweep is idempotent and bounded — it embeds up to
``embedding_backfill_limit`` entries per run, newest first, and does nothing at
all until ``embeddings_enabled`` is switched on.
"""

import logging
import time

from app.config import settings
from app.core.metrics import CELERY_TASK_DURATION_SECONDS, CELERY_TASKS_TOTAL
from app.services.system_settings import warm_settings_cache
from app.workers.celery_app import celery_app
from app.workers.db import run_async, worker_session

logger = logging.getLogger(__name__)


@celery_app.task(name="app.workers.embedding_tasks.embed_pending_entries", soft_time_limit=1800, time_limit=1860)
def embed_pending_entries(limit: int | None = None):
    """Embed the next slice of entries that have no current vector."""
    start = time.monotonic()
    try:
        stats = run_async(_embed_pending_entries(limit))
        logger.info("Embedding sweep: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="embed_pending_entries", status="success").inc()
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="embed_pending_entries", status="error").inc()
        logger.exception("Embedding sweep failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="embed_pending_entries").observe(time.monotonic() - start)


async def _embed_pending_entries(limit: int | None = None) -> dict:
    from app.services.embeddings import sweep

    async with worker_session() as db:
        # Warm before reading any knob: settings.get() on a cold cache silently
        # returns the env default and the DB override never applies.
        await warm_settings_cache(db)
        if not settings.get("embeddings_enabled"):
            return {"status": "disabled", "embedded": 0}
        return await sweep(db, limit=limit)
