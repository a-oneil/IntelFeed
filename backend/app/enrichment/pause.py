"""The global enrichment pause.

The system setting ``enrichment_paused`` is the durable switch; a Redis flag
(``gateway.paused_key()``) is what the gateways read, inside the same script
that takes a token, so a pause reaches every worker on its next request with
no extra round trip. ``set_paused`` writes both; ``sync_pause`` copies the
setting onto the flag, and the enrichment dispatcher runs it every tick, so a
Redis restart or a change made on the Settings page is picked up within 30
seconds.
"""

import logging

from redis.exceptions import RedisError
from sqlalchemy.ext.asyncio import AsyncSession

from app.enrichment import gateway
from app.services.redis_client import get_redis_bytes
from app.services.system_settings import get_setting, update_settings

logger = logging.getLogger(__name__)

SETTING = "enrichment_paused"


async def is_paused(db: AsyncSession) -> bool:
    return bool(await get_setting(SETTING, db))


async def _write_flag(paused: bool) -> None:
    try:
        r = await get_redis_bytes()
        if paused:
            await r.set(gateway.paused_key(), b"1")
        else:
            await r.delete(gateway.paused_key())
    except (RedisError, OSError) as e:
        # Unreachable Redis already refuses every request (the gateway fails
        # closed); the next sync writes the flag.
        logger.warning("Could not write the enrichment pause flag: %s", e)


async def set_paused(db: AsyncSession, paused: bool) -> None:
    await update_settings(db, {SETTING: paused})
    await _write_flag(paused)


async def sync_pause(db: AsyncSession) -> bool:
    """Make the gateways' flag match the setting. Returns whether paused."""
    paused = await is_paused(db)
    await _write_flag(paused)
    return paused
