"""Story thread sweeper and narrator.

``rebuild_story_threads`` is pure SQL over pgvector and runs on the default
queue. ``narrate_story_threads`` calls a model and is routed to the serialized
``ai`` worker in celery_app's task_routes.
"""

import logging
import time

from sqlalchemy import text

from app.config import settings
from app.core.metrics import CELERY_TASK_DURATION_SECONDS, CELERY_TASKS_TOTAL
from app.services.system_settings import warm_settings_cache
from app.workers.celery_app import celery_app
from app.workers.db import run_async, worker_session

logger = logging.getLogger(__name__)


@celery_app.task(name="app.workers.thread_tasks.rebuild_story_threads", soft_time_limit=1200, time_limit=1260)
def rebuild_story_threads(limit: int | None = None):
    """Attach new articles to the stories they continue; seed the ones that broke."""
    start = time.monotonic()
    try:
        stats = run_async(_rebuild_story_threads(limit))
        logger.info("Story threads: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="rebuild_story_threads", status="success").inc()
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="rebuild_story_threads", status="error").inc()
        logger.exception("Story thread sweep failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="rebuild_story_threads").observe(time.monotonic() - start)


async def _rebuild_story_threads(limit: int | None = None) -> dict:
    from app.intelligence.story_threads import assign_entries
    from app.services.thread_narrative import ensure_spine

    async with worker_session() as db:
        await warm_settings_cache(db)
        stats = await assign_entries(db, limit=int(limit or settings.get("thread_sweep_limit") or 1500))
        # Hand the changed threads to the scorer. Popped rather than returned:
        # the id list is plumbing, and job_runs records this dict verbatim.
        changed = stats.pop("touched_thread_ids", [])
        # Every thread renders from beats, so a thread without them is invisible.
        # This fills the gap immediately; the nightly pass rewrites them properly.
        stale = (
            (
                await db.execute(
                    text(
                        """
                    SELECT t.id FROM story_threads t
                    LEFT JOIN story_thread_beats b ON b.thread_id = t.id
                    WHERE t.narrative_hash IS NULL OR b.id IS NULL
                    GROUP BY t.id
                    LIMIT 200
                    """
                    )
                )
            )
            .scalars()
            .all()
        )
        for thread_id in stale:
            await ensure_spine(db, thread_id, allow_ai=False)
        stats["spined"] = len(stale)
        # Membership just moved, so "confirmed by another outlet" may have too.
        from app.services.info_rating import sync_corroboration

        stats["info_ratings_changed"] = await sync_corroboration(db)
        await db.commit()

    # Outside the session: the rescore reads committed membership.
    if changed:
        from app.workers.signal_tasks import dispatch_thread_rescore

        dispatch_thread_rescore(changed)
        stats["rescore_threads"] = len(changed)
    return stats


@celery_app.task(name="app.workers.thread_tasks.narrate_story_threads", soft_time_limit=1800, time_limit=1860)
def narrate_story_threads(limit: int | None = None):
    """Write the AI spine for threads that changed since the last narration."""
    start = time.monotonic()
    try:
        stats = run_async(_narrate_story_threads(limit))
        logger.info("Story thread narration: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="narrate_story_threads", status="success").inc()
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="narrate_story_threads", status="error").inc()
        logger.exception("Story thread narration failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="narrate_story_threads").observe(time.monotonic() - start)


async def _narrate_story_threads(limit: int | None = None) -> dict:
    from app.services.thread_narrative import ensure_spine

    stats: dict[str, int] = {}
    async with worker_session() as db:
        await warm_settings_cache(db)
        cap = int(limit or settings.get("thread_narrate_limit") or 10)
        # Only threads that need a spine, busiest live ones first: a story nobody
        # is still writing about does not need a fresh spine tonight, and a
        # thread whose written spine still describes its members does not need
        # one at all. Selecting by recency alone spent the whole nightly budget
        # on threads that immediately returned "cached" while a hundred others
        # kept their day-grouped headlines.
        rows = (
            (
                await db.execute(
                    text(
                        """
                    SELECT t.id FROM story_threads t
                    LEFT JOIN LATERAL (
                        SELECT bool_or(b.is_ai) AS has_ai
                        FROM story_thread_beats b WHERE b.thread_id = t.id
                    ) b ON true
                    WHERE t.status = 'open'
                      AND (
                            COALESCE(b.has_ai, false) IS NOT TRUE
                         OR t.narrated_at IS NULL
                         -- refresh_thread() bumps updated_at whenever the
                         -- member set changes: the spine is out of date.
                         OR t.updated_at > t.narrated_at
                      )
                    ORDER BY t.last_seen DESC NULLS LAST, t.entry_count DESC
                    LIMIT :cap
                    """
                    ),
                    {"cap": cap},
                )
            )
            .scalars()
            .all()
        )
        for thread_id in rows:
            try:
                result = await ensure_spine(db, thread_id, allow_ai=True)
            except Exception:
                logger.exception("Spine generation failed for thread %s", thread_id)
                stats["errored"] = stats.get("errored", 0) + 1
                continue
            key = result.get("status", "skipped")
            stats[key] = stats.get(key, 0) + 1
    return stats
