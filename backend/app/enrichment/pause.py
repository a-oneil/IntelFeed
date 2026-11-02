"""The global enrichment pause.

The system setting ``enrichment_paused`` is the durable switch (a stopped
engine, ``app/services/engine_switch.py``, pauses enrichment too); a Redis flag
(``gateway.paused_key()``) is what the gateways read, inside the same script
that takes a token, so a pause reaches every worker on its next request with
no extra round trip. ``set_paused`` commits the setting, then runs
``sync_pause``, which copies the stored setting onto the flag; the enrichment
dispatcher runs it every tick too, so a Redis restart or a change made on the
Settings page is picked up within 30 seconds.

Redis can lose the flag (a restart without persistence, a FLUSHALL) while the
enrichment worker is down. So every sync also writes a marker
(``gateway.pause_synced_key()``), and the flag is re-asserted from the
database by more than the dispatcher: every scheduled source job before it
runs (``app/workers/db.py``), and the ``enrichment-pause-sync`` job on the
default worker every minute. Until one of them runs, a gateway that finds no
marker reads the pause from the settings cache before it sends anything.

``sync_pause`` reads the setting from its row, not the settings cache, under a
share lock it holds until the flag is written. A change being saved holds the
row until it commits, so a sync either finishes before that change commits or
reads it: it never puts the old value back on the flag. ``set_paused`` writes
what it reads, not its argument, so two quick toggles leave the flag at the
last one committed.

The flag write gives up after FLAG_TIMEOUT seconds, so a hung Redis holds the
share lock (and any change waiting on it) only that long. The lock stays
until the write ends rather than being released first: released early, a
sync that read the old value could still write it after a newer change.
"""

import asyncio
import logging

from redis.exceptions import RedisError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.enrichment import gateway
from app.models.system_setting import SystemSettings
from app.services.redis_client import get_redis_bytes
from app.services.system_settings import get_setting, update_settings

logger = logging.getLogger(__name__)

SETTING = "enrichment_paused"
#: Seconds a flag write may take before it is given up.
FLAG_TIMEOUT = 5


async def is_paused(db: AsyncSession) -> bool:
    return bool(await get_setting(SETTING, db))


async def _write_flag(paused: bool) -> bool:
    """Write the flag and the synced marker together. Returns whether the
    marker was missing, i.e. Redis had lost them since the last sync."""
    try:
        async with asyncio.timeout(FLAG_TIMEOUT):
            r = await get_redis_bytes()
            async with r.pipeline(transaction=True) as pipe:
                pipe.exists(gateway.pause_synced_key())
                if paused:
                    pipe.set(gateway.paused_key(), b"1")
                else:
                    pipe.delete(gateway.paused_key())
                pipe.set(gateway.pause_synced_key(), b"1")
                had_marker, *_ = await pipe.execute()
            return not had_marker
    except (RedisError, OSError) as e:  # TimeoutError is an OSError
        # Unreachable Redis already refuses every request (the gateway fails
        # closed); the next sync writes the flag.
        logger.warning("Could not write the enrichment pause flag: %s", e)
        return False


async def set_paused(db: AsyncSession, paused: bool) -> None:
    """Store the setting and commit, then copy the stored setting onto the flag."""
    await update_settings(db, {SETTING: paused})
    await db.commit()
    await sync_pause(db)


async def sync_pause(db: AsyncSession) -> bool:
    """Make the gateways' flag match the stored setting, and commit. Returns
    whether paused."""
    paused, _ = await reassert_pause(db)
    return paused


async def reassert_pause(db: AsyncSession) -> tuple[bool, bool]:
    """``sync_pause``, also saying whether the flag had been lost: returns
    (paused, restored)."""
    stored = await db.scalar(select(SystemSettings.settings).where(SystemSettings.id == 1).with_for_update(read=True))
    stored = stored or {}
    # A stopped engine pauses enrichment too, without touching the setting.
    paused = bool(stored.get(SETTING, settings.enrichment_paused)) or bool(
        stored.get("engine_stopped", settings.engine_stopped)
    )
    restored = await _write_flag(paused)
    await db.commit()
    if restored:
        logger.warning("Enrichment pause flag was missing from Redis; restored it (paused=%s)", paused)
    return paused, restored
