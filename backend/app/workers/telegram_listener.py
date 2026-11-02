"""Long-lived Telegram listener — push-style ingestion via Telethon NewMessage events.

Run as a dedicated container (docker-compose service `telegram-listener`). NOT a Celery
task: it holds a persistent MTProto connection per session, registers per-channel event
handlers, and on each new message dispatches `fetch_feed.delay(feed_id)` so the existing
polling pipeline picks up the message.

Why the indirection: the polling pipeline already does dedup, sanitization, content-hash
collision checks, EntryMedia creation, auto-attribution, autolink dispatch, and SSE
broadcast. Reproducing all of that here would double the surface area and risk drift.

Coexists with polling. Polling stays as the safety net — if the listener dies, entries
still arrive on the normal 30-min cadence. The listener writes a Redis heartbeat so the
UI can show its status.

Operator opt-in: only feeds with `adapter_config.realtime = true` are subscribed.
"""

from __future__ import annotations

import asyncio
import logging
import signal
import time as _time
from typing import Any

import structlog
from sqlalchemy import select

from app.config import settings
from app.models.feed import Feed

logger = structlog.get_logger("app.telegram_listener")

HEARTBEAT_KEY = "intelfeed:telegram_listener:heartbeat"
SUBSCRIPTIONS_KEY = "intelfeed:telegram_listener:subscriptions"
HEARTBEAT_INTERVAL_SECONDS = 30
RESYNC_INTERVAL_SECONDS = 300  # re-poll DB for added/removed realtime feeds every 5 min
DEBOUNCE_SECONDS = 1.5  # if multiple messages land for one channel within this window, coalesce


class _ChannelDispatcher:
    """Coalesce rapid bursts of NewMessage events for one channel into one fetch_feed call."""

    def __init__(self) -> None:
        self._pending: dict[str, asyncio.TimerHandle] = {}
        self._lock = asyncio.Lock()

    async def schedule(self, feed_id: str) -> None:
        async with self._lock:
            handle = self._pending.pop(feed_id, None)
            if handle:
                handle.cancel()
            loop = asyncio.get_running_loop()
            self._pending[feed_id] = loop.call_later(
                DEBOUNCE_SECONDS, lambda: asyncio.create_task(self._dispatch(feed_id))
            )

    async def _dispatch(self, feed_id: str) -> None:
        # Drop the pending entry so a follow-up burst can re-register
        async with self._lock:
            self._pending.pop(feed_id, None)
        try:
            from app.services.engine_switch import is_stopped_async
            from app.workers.feed_tasks import fetch_feed

            if await is_stopped_async():
                # The feed's own poll picks the messages up after the start.
                logger.info("dispatch_skipped_engine_stopped", feed_id=feed_id)
                return
            fetch_feed.delay(feed_id)
            logger.info("dispatched_fetch", feed_id=feed_id)
        except Exception as exc:
            logger.warning("dispatch_failed", feed_id=feed_id, error=str(exc))


async def _load_realtime_feeds() -> list[Feed]:
    """Return all telegram feeds with adapter_config.realtime == true."""
    from app.workers.db import worker_session

    async with worker_session() as db:
        result = await db.execute(
            select(Feed).where(Feed.feed_type == "telegram").where(Feed.is_active == True)  # noqa: E712
        )
        feeds = result.scalars().all()
    return [f for f in feeds if (f.adapter_config or {}).get("realtime") is True]


def _session_name_for(feed: Feed) -> str:
    return ((feed.adapter_config or {}).get("session_name") or "").strip()


def _channel_ref_for(feed: Feed) -> Any:
    # Prefer username/link over numeric channel_id — numeric IDs require an (id, hash)
    # pair in the session entity cache, which StringSession doesn't always carry across
    # process restarts. Username resolves server-side without needing the cache.
    from app.adapters.telegram import normalize_channel_handle

    cfg = feed.adapter_config or {}
    ref = cfg.get("channel") or cfg.get("channel_username") or cfg.get("channel_id")
    return normalize_channel_handle(ref)


class _ListenerState:
    def __init__(self) -> None:
        # session_name -> TelegramClient
        self.clients: dict[str, Any] = {}
        # feed_id -> (session_name, channel_id_int, handler_obj)
        self.subscriptions: dict[str, tuple[str, int, Any]] = {}
        self.dispatcher = _ChannelDispatcher()
        self.shutdown = asyncio.Event()


async def _ensure_client(state: _ListenerState, session_name: str):
    if session_name in state.clients:
        return state.clients[session_name]
    from telethon import TelegramClient  # noqa: F401  (sanity import)

    from app.adapters.telegram import TelegramAdapter

    adapter = TelegramAdapter()
    client = await adapter._get_client(session_name=session_name)
    state.clients[session_name] = client
    logger.info("client_ready", session=session_name or "(default)")
    return client


async def _subscribe_feed(state: _ListenerState, feed: Feed) -> None:
    """Register a NewMessage handler for one feed."""
    feed_id = str(feed.id)
    if feed_id in state.subscriptions:
        return  # already wired

    session_name = _session_name_for(feed)
    try:
        client = await _ensure_client(state, session_name)
    except Exception:
        logger.warning("session_init_failed", feed_id=feed_id, session=session_name, exc_info=True)
        return

    channel_ref = _channel_ref_for(feed)
    if channel_ref is None:
        logger.warning("feed_missing_channel", feed_id=feed_id)
        return

    try:
        entity = await client.get_entity(channel_ref)
    except Exception:
        logger.warning("entity_resolve_failed", feed_id=feed_id, channel=channel_ref, exc_info=True)
        return

    channel_id = int(getattr(entity, "id", 0))

    from telethon import events

    async def _on_new_message(event):
        await state.dispatcher.schedule(feed_id)

    handler = client.add_event_handler(_on_new_message, events.NewMessage(chats=entity))
    state.subscriptions[feed_id] = (session_name, channel_id, handler)
    logger.info(
        "subscribed",
        feed_id=feed_id,
        session=session_name or "(default)",
        channel_id=channel_id,
    )


async def _unsubscribe_feed(state: _ListenerState, feed_id: str) -> None:
    sub = state.subscriptions.pop(feed_id, None)
    if sub is None:
        return
    session_name, _channel_id, handler = sub
    client = state.clients.get(session_name)
    if client is not None:
        try:
            client.remove_event_handler(handler)
        except Exception:
            logger.warning("handler_remove_failed", feed_id=feed_id, exc_info=True)
    logger.info("unsubscribed", feed_id=feed_id)


async def _resync(state: _ListenerState) -> None:
    """Reconcile subscriptions against the current set of realtime-enabled telegram feeds."""
    feeds = await _load_realtime_feeds()
    desired_ids = {str(f.id) for f in feeds}
    current_ids = set(state.subscriptions.keys())

    # Remove feeds that no longer want realtime
    for feed_id in current_ids - desired_ids:
        await _unsubscribe_feed(state, feed_id)

    # Add new ones
    feeds_by_id = {str(f.id): f for f in feeds}
    for feed_id in desired_ids - current_ids:
        await _subscribe_feed(state, feeds_by_id[feed_id])

    # Update redis subscription count
    try:
        from app.services.redis_client import get_redis

        r = await get_redis()
        await r.set(SUBSCRIPTIONS_KEY, str(len(state.subscriptions)))
    except Exception:
        pass


async def _heartbeat_loop(state: _ListenerState) -> None:
    while not state.shutdown.is_set():
        try:
            from app.services.redis_client import get_redis

            r = await get_redis()
            await r.set(HEARTBEAT_KEY, str(_time.time()), ex=HEARTBEAT_INTERVAL_SECONDS * 4)
        except Exception:
            logger.warning("heartbeat_failed", exc_info=True)
        try:
            await asyncio.wait_for(state.shutdown.wait(), timeout=HEARTBEAT_INTERVAL_SECONDS)
        except TimeoutError:
            pass


async def _resync_loop(state: _ListenerState) -> None:
    while not state.shutdown.is_set():
        try:
            await _resync(state)
        except Exception:
            logger.warning("resync_failed", exc_info=True)
        try:
            await asyncio.wait_for(state.shutdown.wait(), timeout=RESYNC_INTERVAL_SECONDS)
        except TimeoutError:
            pass


async def main() -> None:
    state = _ListenerState()

    # Graceful shutdown handlers — needed in both the configured and unconfigured paths.
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, state.shutdown.set)
        except NotImplementedError:
            pass

    if not settings.telegram_api_id or not settings.telegram_api_hash:
        # Unconfigured: idle until SIGTERM rather than exit-and-restart-loop. This keeps
        # the container "Up" so the operator can `docker compose restart telegram-listener`
        # after they bootstrap a session, without a tight restart-loop polluting logs.
        logger.info("telegram_not_configured_idling")
        await state.shutdown.wait()
        return

    # Initial sync — register all currently-enabled realtime feeds
    await _resync(state)
    if not state.subscriptions:
        logger.info("no_realtime_feeds_yet")

    # Heartbeat + periodic resync run alongside the long-lived clients
    heartbeat_task = asyncio.create_task(_heartbeat_loop(state))
    resync_task = asyncio.create_task(_resync_loop(state))

    if not state.clients:
        # Nothing to listen to — just wait for either a feed to appear or shutdown
        logger.info("waiting_for_realtime_feeds")
        await state.shutdown.wait()
    else:
        # run_until_disconnected for every active client; shutdown signal disconnects them
        async def _run_with_disconnect(client):
            shutdown_waiter = asyncio.create_task(state.shutdown.wait())
            run_waiter = asyncio.create_task(client.run_until_disconnected())
            done, pending = await asyncio.wait([shutdown_waiter, run_waiter], return_when=asyncio.FIRST_COMPLETED)
            if shutdown_waiter in done:
                try:
                    await client.disconnect()
                except Exception:
                    pass
            for t in pending:
                t.cancel()

        try:
            await asyncio.gather(
                *(_run_with_disconnect(c) for c in state.clients.values()),
                return_exceptions=True,
            )
        finally:
            heartbeat_task.cancel()
            resync_task.cancel()
            for t in (heartbeat_task, resync_task):
                try:
                    await t
                except (asyncio.CancelledError, Exception):
                    pass

    logger.info("listener_shutdown_complete")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
