"""Celery task that runs a global-copilot CLI turn on the dedicated
``claude_code`` worker and streams its events back to the api over Redis.

Why this exists (prod topology): the interactive copilot drives the Claude Code
CLI, which needs OAuth credentials at ``~/.claude/.credentials.json``. Only
``celery-worker-ai`` owns that credentials volume (it is the single writer that
rotates the tokens). The api container must NOT mount that volume — concurrent
OAuth refresh would corrupt it. So the api dispatches the CLI run here, and this
task publishes each streamed event onto a short-lived Redis list that the api's
``/api/ai/copilot/stream`` endpoint drains and relays as SSE.

This task is a thin shim: it owns NO business logic. Prompt construction,
fence-splitting, conversation persistence, and action staging all stay in the
api (which has the DB). The task only runs ``ClaudeCodeProvider.stream_agent``
and forwards its raw ``{"kind": ...}`` events, verbatim, plus a terminal
sentinel.

Transport = a Redis list ``copilot:stream:{run_id}`` (RPUSH here, BLPOP in the
api). A list (not pub/sub) avoids the subscribe-before-publish race and buffers
events if the api briefly falls behind. A TTL cleans up orphaned runs where the
api never drains (e.g. client disconnected before dispatch).
"""

from __future__ import annotations

import json
import logging
import uuid

import redis.asyncio as aioredis

from app.config import settings
from app.workers.celery_app import celery_app
from app.workers.db import run_async

logger = logging.getLogger(__name__)

# Redis list key namespace + how long an undrained run's buffer survives.
_STREAM_KEY_PREFIX = "copilot:stream:"
_STREAM_TTL_SECONDS = 300

# Terminal sentinels the api consumer keys off (never surfaced to the client).
_END = {"kind": "__end__"}


def _stream_key(run_id: str) -> str:
    return f"{_STREAM_KEY_PREFIX}{run_id}"


async def _run_async(
    run_id: str,
    prompt: str,
    system: str | None,
    model: str,
    allowed_tools: list[str] | None,
    timeout_seconds: float | None,
    provider_config: dict,
    env: dict[str, str] | None,
    agent_user_id: str | None = None,
    agent_conversation_id: str | None = None,
    agent_turn_id: str | None = None,
) -> int:
    """Run one CLI agent turn and push every event onto the run's Redis list.

    Returns the number of events forwarded (excluding the terminal sentinel).
    A fresh Redis client is created bound to the current worker event loop and
    closed at the end, avoiding any cross-loop coupling with the api's pool.
    """
    from app.ai.providers.claude_code_provider import ClaudeCodeProvider

    key = _stream_key(run_id)
    r = aioredis.from_url(settings.redis_url, decode_responses=True)
    forwarded = 0
    first = True

    async def _push(ev: dict) -> None:
        nonlocal first
        await r.rpush(key, json.dumps(ev))
        if first:
            # Bound the buffer's lifetime the moment it exists.
            await r.expire(key, _STREAM_TTL_SECONDS)
            first = False

    try:
        provider = ClaudeCodeProvider(config=provider_config or {})
        try:
            async for ev in provider.stream_agent(
                prompt=prompt,
                system=system,
                model=model,
                allowed_tools=allowed_tools,
                timeout_seconds=timeout_seconds,
                heartbeat_label=f"copilot worker {run_id[:8]}",
                env=env,
                agent_user_id=uuid.UUID(agent_user_id) if agent_user_id else None,
                agent_conversation_id=uuid.UUID(agent_conversation_id) if agent_conversation_id else None,
                agent_turn_id=uuid.UUID(agent_turn_id) if agent_turn_id else None,
            ):
                await _push(ev)
                forwarded += 1
        except Exception as e:  # CLI/provider failure (e.g. quota, missing creds)
            logger.warning("copilot worker %s: stream_agent failed: %s", run_id[:8], e)
            await _push({"kind": "__error__", "message": str(e)})
        finally:
            # Always terminate the stream so the api consumer never hangs.
            await _push(_END)
    finally:
        await r.aclose()

    return forwarded


@celery_app.task(
    name="app.workers.copilot_tasks.run_copilot_stream",
    bind=True,
    soft_time_limit=300,
    time_limit=360,
)
def run_copilot_stream(
    self,
    run_id: str,
    prompt: str,
    system: str | None = None,
    model: str = "sonnet",
    allowed_tools: list[str] | None = None,
    timeout_seconds: float | None = None,
    provider_config: dict | None = None,
    env: dict[str, str] | None = None,
    agent_user_id: str | None = None,
    agent_conversation_id: str | None = None,
    agent_turn_id: str | None = None,
) -> dict:
    """Entry point invoked on the ``ai`` queue. See module docstring."""
    try:
        forwarded = run_async(
            _run_async(
                run_id=run_id,
                prompt=prompt,
                system=system,
                model=model,
                allowed_tools=allowed_tools,
                timeout_seconds=timeout_seconds,
                provider_config=provider_config or {},
                env=env,
                agent_user_id=agent_user_id,
                agent_conversation_id=agent_conversation_id,
                agent_turn_id=agent_turn_id,
            )
        )
        return {"status": "ok", "run_id": run_id, "events": forwarded}
    except Exception as e:  # last-resort: ensure the api consumer gets a terminator
        logger.error("copilot worker %s crashed: %s", run_id[:8], e)
        try:
            run_async(_emergency_terminate(run_id, str(e)))
        except Exception:
            pass
        return {"status": "error", "run_id": run_id, "message": str(e)}


async def _emergency_terminate(run_id: str, message: str) -> None:
    """Push an error + end sentinel if the main path died before terminating."""
    r = aioredis.from_url(settings.redis_url, decode_responses=True)
    try:
        key = _stream_key(run_id)
        await r.rpush(key, json.dumps({"kind": "__error__", "message": message}))
        await r.rpush(key, json.dumps(_END))
        await r.expire(key, _STREAM_TTL_SECONDS)
    finally:
        await r.aclose()
