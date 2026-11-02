"""Async database session factory and event loop helper for Celery workers.

Celery's prefork pool reuses worker processes across tasks. We keep a
persistent per-process event loop and create/dispose engines per task to
prevent both connection leaks and 'Event loop is closed' errors.
"""

import asyncio
import functools
import logging
import sys
import threading
from contextlib import asynccontextmanager

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.config import settings

logger = logging.getLogger(__name__)

# Per-process persistent event loop (thread-local for safety in edge cases)
_local = threading.local()


def run_async(coro):
    """Run an async coroutine using a persistent per-process event loop.

    Safe for Celery prefork workers: the loop is created once per forked
    process and reused across tasks, avoiding 'Event loop is closed' errors.
    """
    loop = getattr(_local, "loop", None)
    if loop is None or loop.is_closed():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        _local.loop = loop
    return loop.run_until_complete(coro)


@asynccontextmanager
async def worker_session():
    """Create a short-lived engine + session for a single worker task.

    Creates a fresh engine bound to the current event loop and properly
    disposes connections when done. This prevents connection pool exhaustion
    by ensuring each task gets its own pool that is cleaned up after use.
    """
    engine = create_async_engine(
        settings.database_url,
        pool_size=settings.worker_db_pool_size,
        max_overflow=settings.worker_db_max_overflow,
        pool_pre_ping=True,
        pool_recycle=1800,
    )
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    try:
        async with session_factory() as session:
            yield session
    finally:
        await engine.dispose()


#: What a source's job returns when the source is switched off.
SOURCE_DISABLED = {"skipped": "source disabled"}


def source_job(source_type: str, *, lane: str | None = None):
    """Skip the decorated job body while its enrichment source is switched off.

    Wraps the async body of a scheduled job in a worker module and reads the
    source's row through that module's ``_get_worker_session``, the one tests
    replace. A source with no row yet (before the startup seed) counts as on.

    Before the body runs it re-asserts the enrichment pause flag from the
    database (``app/enrichment/pause.py``), so a Redis that lost the flag is
    corrected by any worker running a source job, not only the dispatcher.

    ``lane="backfill"`` declares a bulk catch-up job, one that works through
    every entity the source hasn't answered yet: every gateway request the
    body makes runs in the backfill lane, so it stops (``BackfillShareUsed``,
    a ``BudgetExhausted``) once the source has used BACKFILL_SHARE of its
    daily budget, the same share the queue's backfill rows get.
    """

    def wrap(fn):
        @functools.wraps(fn)
        async def run(*args, **kwargs):
            from app.enrichment.gateway import in_lane
            from app.enrichment.pause import sync_pause
            from app.models.enrichment import EnrichmentSource

            async with sys.modules[fn.__module__]._get_worker_session() as db:
                try:
                    await sync_pause(db)
                except Exception:
                    logger.warning("Could not sync the enrichment pause flag", exc_info=True)
                    await db.rollback()
                enabled = await db.scalar(
                    select(EnrichmentSource.is_enabled).where(EnrichmentSource.source_type == source_type)
                )
            if enabled is False:
                logger.info("%s skipped: source %s is disabled", fn.__name__.lstrip("_"), source_type)
                return dict(SOURCE_DISABLED)
            with in_lane(lane):
                return await fn(*args, **kwargs)

        run.source_type = source_type
        run.lane = lane
        return run

    return wrap
