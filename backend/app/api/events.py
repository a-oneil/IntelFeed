import asyncio
import json
import logging
import secrets

import redis as sync_redis
import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, Query
from sse_starlette.sse import EventSourceResponse

from app.config import settings
from app.core.exceptions import AppError
from app.core.security import get_current_user
from app.models.user import User

logger = logging.getLogger(__name__)
router = APIRouter()

SSE_CHANNEL_PREFIX = "sse:"
SSE_TICKET_PREFIX = "sse_ticket:"
SSE_TICKET_TTL = 30  # seconds — short-lived, single-use


def publish_event(user_id: str, event_type: str, data: dict) -> None:
    """Publish an SSE event via Redis pub/sub.

    Uses sync Redis so it can be called from any context (API server, Celery worker).
    """
    payload = json.dumps({"event": event_type, "data": data})
    try:
        r = sync_redis.from_url(settings.redis_url, decode_responses=True)
        r.publish(f"{SSE_CHANNEL_PREFIX}{user_id}", payload)
        r.close()
    except Exception:
        logger.debug("Failed to publish SSE event for user %s", user_id, exc_info=True)


def broadcast_event(event_type: str, data: dict) -> None:
    """Publish an SSE event to the broadcast channel (all connected clients).

    Convenience wrapper around publish_event for system-wide notifications.
    """
    publish_event("broadcast", event_type, data)


@router.post("/ticket")
async def create_sse_ticket(user: User = Depends(get_current_user)):
    """Issue a short-lived, single-use ticket for SSE connection.

    This avoids putting the JWT in the EventSource query string where it
    would leak into browser history, server logs, and referer headers.
    """
    ticket = secrets.token_urlsafe(32)
    r = aioredis.from_url(settings.redis_url, decode_responses=True)
    try:
        await r.set(f"{SSE_TICKET_PREFIX}{ticket}", str(user.id), ex=SSE_TICKET_TTL)
    finally:
        await r.aclose()
    return {"ticket": ticket}


@router.get("")
async def event_stream(
    ticket: str = Query(..., description="Single-use SSE ticket obtained from POST /api/events/ticket"),
):
    """SSE endpoint. Authenticates via a short-lived ticket from POST /ticket."""
    r = aioredis.from_url(settings.redis_url, decode_responses=True)
    try:
        key = f"{SSE_TICKET_PREFIX}{ticket}"
        user_id = await r.get(key)
        if not user_id:
            raise AppError(code="unauthorized", message="Invalid or expired ticket", status_code=401)
        # Single-use: delete after claim
        await r.delete(key)
    finally:
        await r.aclose()

    return EventSourceResponse(_subscribe(user_id))


async def _subscribe(user_id: str):
    """Async generator that subscribes to user + broadcast Redis channels and yields SSE events."""
    r = aioredis.from_url(settings.redis_url, decode_responses=True)
    pubsub = r.pubsub()
    user_channel = f"{SSE_CHANNEL_PREFIX}{user_id}"
    broadcast_channel = f"{SSE_CHANNEL_PREFIX}broadcast"
    await pubsub.subscribe(user_channel, broadcast_channel)

    try:
        while True:
            try:
                message = await asyncio.wait_for(
                    pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0),
                    timeout=30.0,
                )
                if message and message["type"] == "message":
                    payload = json.loads(message["data"])
                    yield {
                        "event": payload["event"],
                        "data": json.dumps(payload["data"]),
                    }
            except TimeoutError:
                # Send keepalive ping every 30s
                yield {"event": "ping", "data": ""}
    finally:
        await pubsub.unsubscribe(user_channel, broadcast_channel)
        await pubsub.aclose()
        await r.aclose()
