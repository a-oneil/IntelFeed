"""Async database session factory and event loop helper for Celery workers.

Celery's prefork pool reuses worker processes across tasks. We keep a
persistent per-process event loop and create/dispose engines per task to
prevent both connection leaks and 'Event loop is closed' errors.
"""

import asyncio
import threading
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.config import settings

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
