"""Admin API to inspect and refresh the Claude Code CLI OAuth session.

The copilot authenticates via an OAuth session the ``claude`` CLI stores on the
``celery-worker-ai`` volume. When it expires the copilot silently 401s, so this
router exposes a health snapshot plus an in-app re-auth flow that drives
``claude auth login`` on that worker (see app/workers/copilot_auth_tasks.py).

Flow: ``POST /start`` dispatches the worker task and returns a ``session_id``;
the worker publishes the browser authorization URL to Redis; the client polls
``GET /session/{id}`` until it sees ``awaiting_code`` + the URL, opens it, and
``POST /session/{id}/code`` relays the pasted code back to the worker, which
finishes the exchange and flips the session to ``success``.
"""

from __future__ import annotations

import json
import uuid

from fastapi import APIRouter, Depends, Path
from pydantic import BaseModel, ConfigDict

from app.core.exceptions import AppError
from app.core.security import get_admin_user
from app.models.user import User
from app.services.redis_client import get_redis
from app.workers.celery_app import celery_app

router = APIRouter()

_SESSION_PREFIX = "copilot:auth:session:"
_CODE_PREFIX = "copilot:auth:code:"
_STATUS_KEY = "copilot:auth:status"
_LOCK_KEY = "copilot:auth:lock"
_SESSION_TTL = 900
_LOCK_TTL = 900
_CANCEL_TOKEN = "__cancel__"

_REFRESH_TASK = "app.workers.copilot_auth_tasks.refresh_claude_auth_status"
_RUN_TASK = "app.workers.copilot_auth_tasks.run_claude_auth"


class StartResponse(BaseModel):
    session_id: str


class CodeRequest(BaseModel):
    code: str

    model_config = ConfigDict(json_schema_extra={"example": {"code": "ac_1kX9pQz7RtLmB4vN8wYs2Del6FgHj0K#a3f9c2e1"}})


@router.get("/status")
async def get_status(user: User = Depends(get_admin_user)) -> dict:
    """Return the cached copilot-credential health snapshot.

    If nothing is cached yet (fresh deploy), kick a refresh so the card fills in
    on the next poll and return an ``unknown`` placeholder now.
    """
    r = await get_redis()
    raw = await r.get(_STATUS_KEY)
    if raw is None:
        celery_app.send_task(_REFRESH_TASK, queue="ai")
        return {"state": "unknown"}
    return json.loads(raw)


@router.post("/refresh")
async def refresh_status(user: User = Depends(get_admin_user)) -> dict:
    """Force a re-read of the credential health snapshot on the CLI worker."""
    celery_app.send_task(_REFRESH_TASK, queue="ai")
    return {"ok": True}


@router.post("/start", response_model=StartResponse)
async def start_reauth(user: User = Depends(get_admin_user)) -> StartResponse:
    """Begin an interactive re-authentication on the CLI worker.

    Only one run is allowed at a time — the CLI worker is concurrency-1 and each
    run spawns a real ``setup-token`` against Claude's OAuth endpoint, so letting
    clicks stack up would pile tasks onto the worker and trip OAuth rate limits.
    """
    session_id = str(uuid.uuid4())
    r = await get_redis()
    if not await r.set(_LOCK_KEY, session_id, nx=True, ex=_LOCK_TTL):
        raise AppError(
            code="reauth_in_progress",
            message="A re-authentication is already in progress. Finish or cancel it first.",
            status_code=409,
        )
    await r.set(f"{_SESSION_PREFIX}{session_id}", json.dumps({"state": "starting"}), ex=_SESSION_TTL)
    celery_app.send_task(_RUN_TASK, kwargs={"session_id": session_id}, queue="ai")
    return StartResponse(session_id=session_id)


@router.get("/session/{session_id}")
async def get_session(
    session_id: str = Path(..., description="Re-authentication session ID returned by /start"),
    user: User = Depends(get_admin_user),
) -> dict:
    """Poll the state of an in-flight re-authentication."""
    r = await get_redis()
    raw = await r.get(f"{_SESSION_PREFIX}{session_id}")
    if raw is None:
        return {"state": "expired"}
    return json.loads(raw)


@router.post("/session/{session_id}/code")
async def submit_code(
    session_id: str = Path(..., description="Re-authentication session ID returned by /start"),
    body: CodeRequest = ...,
    user: User = Depends(get_admin_user),
) -> dict:
    """Relay the browser authorization code back to the waiting CLI worker."""
    code = body.code.strip()
    if not code:
        raise AppError(code="invalid_code", message="Authorization code is required", status_code=400)
    r = await get_redis()
    if not await r.exists(f"{_SESSION_PREFIX}{session_id}"):
        raise AppError(code="session_expired", message="Re-authentication session expired", status_code=404)
    await r.rpush(f"{_CODE_PREFIX}{session_id}", code)
    await r.expire(f"{_CODE_PREFIX}{session_id}", 120)
    return {"ok": True}


@router.post("/session/{session_id}/cancel")
async def cancel(
    session_id: str = Path(..., description="Re-authentication session ID returned by /start"),
    user: User = Depends(get_admin_user),
) -> dict:
    """Cancel a waiting re-authentication (unblocks the worker immediately)."""
    r = await get_redis()
    await r.rpush(f"{_CODE_PREFIX}{session_id}", _CANCEL_TOKEN)
    await r.expire(f"{_CODE_PREFIX}{session_id}", 120)
    # Free the single-run lock directly so the user can immediately restart even
    # if the worker is wedged and never releases it itself.
    if await r.get(_LOCK_KEY) == session_id:
        await r.delete(_LOCK_KEY)
    return {"ok": True}
