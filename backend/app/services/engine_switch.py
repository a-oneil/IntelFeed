"""The engine switch: stop and start all background work at once.

The ``engine_stopped`` setting, stored in Postgres, is the switch, and every
process that does background work reads it from there:

- Celery workers stop taking tasks off their queues, and beat stops sending
  scheduled jobs (``app/workers/engine_gate.py``).
- The enrichment gateway refuses outside requests, as if enrichment were
  paused (``app/enrichment/pause.py``).
- The Telegram listener stops sending fetches.

Queued work waits in Redis and runs once the engine starts. Nothing about
the switch lives in Redis, so losing Redis can't start a stopped engine.

A new background process that doesn't run as a Celery task should check
``is_stopped()`` (or ``is_stopped_async()``) before it does work.
"""

import asyncio
import logging
import os
import time
from contextlib import suppress

import asyncpg
from redis.exceptions import RedisError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.services.redis_client import get_redis_bytes

logger = logging.getLogger(__name__)

SETTING = "engine_stopped"
#: How long a process trusts its last read of the setting: the longest a
#: worker that has already taken a task goes on before it notices a stop.
CACHE_SECONDS = 10.0
#: Seconds a connect or a read may take before it is given up.
READ_TIMEOUT = 1.0

_cached: tuple[float, bool] | None = None

#: The process's one connection for reading the setting, and the (pid, loop)
#: it was opened on: a connection belongs to the loop that opened it, and a
#: forked child must not use its parent's.
_conn: asyncpg.Connection | None = None
_conn_owner: tuple[int, asyncio.AbstractEventLoop] | None = None
#: The loop ``is_stopped`` runs on in code with no loop of its own.
_loop: asyncio.AbstractEventLoop | None = None
_loop_pid: int | None = None


def _dsn() -> str:
    return settings.database_url.replace("+asyncpg", "", 1)


def _from_cache(fresh: bool) -> bool | None:
    if fresh or _cached is None or time.monotonic() - _cached[0] >= CACHE_SECONDS:
        return None
    return _cached[1]


def disconnect() -> None:
    """Drop the process's connection; the next read opens a new one."""
    global _conn, _conn_owner
    if _conn is not None:
        with suppress(Exception):
            _conn.terminate()
    _conn = _conn_owner = None


async def _read_setting() -> bool | None:
    """The stored setting, over the process's connection (opened or reopened
    as needed). On any error the connection is dropped and the error raised."""
    global _conn, _conn_owner
    owner = (os.getpid(), asyncio.get_running_loop())
    if _conn is None or _conn.is_closed() or _conn_owner != owner:
        disconnect()
        _conn = await asyncpg.connect(_dsn(), timeout=READ_TIMEOUT)
        _conn_owner = owner
    try:
        return await _conn.fetchval(
            "SELECT (settings ->> $1)::boolean FROM system_settings WHERE id = 1",
            SETTING,
            timeout=READ_TIMEOUT,
        )
    except Exception:
        disconnect()
        raise


async def is_stopped_async(*, fresh: bool = False) -> bool:
    """Whether the engine is stopped, read from the database. Cached for
    ``CACHE_SECONDS`` unless ``fresh``. If the database can't be reached, the
    last answer stands; with none yet, the engine is taken to be running."""
    global _cached
    cached = _from_cache(fresh)
    if cached is not None:
        return cached
    try:
        stored = await _read_setting()
        stopped = settings.engine_stopped if stored is None else stored
    except (OSError, asyncpg.PostgresError, asyncpg.InterfaceError) as e:
        logger.warning("Could not read the engine switch: %s", e)
        stopped = _cached[1] if _cached else False
    _cached = (time.monotonic(), stopped)
    return stopped


def is_stopped(*, fresh: bool = False) -> bool:
    """``is_stopped_async`` for code with no event loop running (workers, beat).
    Runs on a loop of this module's own, kept for the life of the process, so
    it never touches the one a task uses and the connection stays open."""
    global _loop, _loop_pid
    cached = _from_cache(fresh)
    if cached is not None:
        return cached
    if _loop is None or _loop_pid != os.getpid():
        _loop, _loop_pid = asyncio.new_event_loop(), os.getpid()
    return _loop.run_until_complete(is_stopped_async(fresh=True))


async def set_stopped(db: AsyncSession, stopped: bool) -> None:
    """Save the setting and commit, then copy it onto the enrichment pause."""
    global _cached
    from app.enrichment.pause import sync_pause
    from app.services.system_settings import update_settings

    await update_settings(db, {SETTING: stopped})
    await db.commit()
    _cached = None
    await sync_pause(db)
    logger.warning("Engine %s", "stopped" if stopped else "started")


def worker_queues() -> list[str]:
    """Every queue a worker serves: the default plus each one a task is routed to."""
    from app.workers.celery_app import celery_app

    routes = celery_app.conf.task_routes or {}
    return sorted({celery_app.conf.task_default_queue, *(r["queue"] for r in routes.values())})


async def queue_depths() -> dict[str, int | None]:
    """Tasks waiting on each queue; None for every queue when Redis can't be asked."""
    queues = worker_queues()
    try:
        r = await get_redis_bytes()
        async with r.pipeline(transaction=False) as pipe:
            for queue in queues:
                pipe.llen(queue)
            counts = await pipe.execute()
    except (RedisError, OSError):
        counts = [None] * len(queues)
    return dict(zip(queues, counts, strict=True))
