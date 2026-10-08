"""Adjudicate stage worker: the per-entry post-analysis AI review.

One task per entry, dispatched by services/entry_adjudication after the
one-pass analysis has been stored and committed. Runs on the `ai` queue
(celery-worker-ai, concurrency 1) so it never competes with the analysis
itself for the GPU. Wrapped with @pipeline_stage so the Engine matrix gets a
column and the verdict counts land in the run's `detail`.

The task is idempotent and re-checks every gate: a retry, a manual re-run
from the matrix, or an entry whose mode was switched off meanwhile all end
in a recorded status rather than a duplicate review.
"""

from __future__ import annotations

import logging
import time
import uuid
from datetime import UTC, datetime

import redis
from celery.exceptions import MaxRetriesExceededError, Retry

from app.config import settings
from app.core.metrics import CELERY_TASK_DURATION_SECONDS, CELERY_TASKS_TOTAL
from app.workers.celery_app import celery_app
from app.workers.db import run_async, worker_session
from app.workers.pipeline_logging import pipeline_stage

logger = logging.getLogger(__name__)

_LOCK_TTL = 900


@celery_app.task(
    name="app.workers.adjudication_tasks.adjudicate_entry_task",
    bind=True,
    max_retries=3,
    soft_time_limit=600,
    time_limit=660,
)
@pipeline_stage("adjudicate")
def adjudicate_entry_task(self, entry_id: str) -> dict:
    """Review one entry. Returns the run detail (stored by @pipeline_stage)."""
    start = time.monotonic()
    try:
        detail = run_async(_adjudicate_entry(uuid.UUID(entry_id)))
        if detail.get("status") == "provider_paused":
            countdown = 3600
            pause_until = detail.get("pause_until")
            if pause_until:
                try:
                    until = datetime.fromisoformat(pause_until)
                    countdown = max(60, min(3600, int((until - datetime.now(UTC)).total_seconds()) + 30))
                except ValueError:
                    pass
            CELERY_TASKS_TOTAL.labels(task_name="adjudicate_entry_task", status="provider_paused").inc()
            raise self.retry(countdown=countdown, max_retries=24)
        CELERY_TASKS_TOTAL.labels(task_name="adjudicate_entry_task", status="success").inc()
        return detail
    except Retry:
        raise
    except MaxRetriesExceededError:
        CELERY_TASKS_TOTAL.labels(task_name="adjudicate_entry_task", status="error").inc()
        raise
    except Exception as exc:
        CELERY_TASKS_TOTAL.labels(task_name="adjudicate_entry_task", status="retry").inc()
        raise self.retry(exc=exc, countdown=min(300, 60 * (self.request.retries + 1)))
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="adjudicate_entry_task").observe(time.monotonic() - start)


async def _adjudicate_entry(entry_id: uuid.UUID) -> dict:
    from app.ai.engine import run_task
    from app.ai.providers.claude_code_provider import QuotaExhaustedError
    from app.models.entry import Entry
    from app.services.entry_adjudication import (
        COMPLETED,
        FAILED,
        SKIPPED_OFF,
        TARGET_TYPE,
        TASK_NAME,
        _current_analysis,
        _request_row,
        _settings,
        _validate_verdicts,
        apply_verdicts,
        build_variables,
    )
    from app.services.system_settings import _ensure_cache, invalidate_cache
    from app.services.system_user import get_system_user_id

    redis_client = redis.from_url(settings.redis_url, decode_responses=True)
    lock_key = f"adjudication:entry:{entry_id}"
    if not redis_client.set(lock_key, "1", nx=True, ex=_LOCK_TTL):
        return {"skipped": "locked"}

    try:
        async with worker_session() as db:
            # Workers don't share the API's settings cache; warm it so DB
            # overrides (mode, budget) are what this run sees.
            invalidate_cache()
            await _ensure_cache(db)
            cfg = await _settings(db)
            row = await _request_row(db, entry_id)

            async def _finish(status: str, detail: dict) -> dict:
                row.adjudication_status = status
                row.adjudicated_at = datetime.now(UTC)
                db.add(row)
                await db.commit()
                return detail

            if cfg["mode"] == "off":
                return await _finish(SKIPPED_OFF, {"skipped": "off", "mode": "off"})

            entry = await db.get(Entry, entry_id)
            if entry is None:
                return await _finish(FAILED, {"skipped": "missing_entry"})

            _result, parsed = await _current_analysis(db, entry_id)
            if parsed is None:
                return await _finish(FAILED, {"skipped": "no_analysis"})

            items, variables = await build_variables(db, entry, parsed, cfg)
            if not items:
                return await _finish(COMPLETED, {"skipped": "nothing_to_review", "mode": cfg["mode"], "items": 0})

            user_id = await get_system_user_id(db)
            if user_id is None:
                return await _finish(FAILED, {"skipped": "no_system_user"})

            try:
                result = await run_task(
                    db=db,
                    user_id=user_id,
                    task_name=TASK_NAME,
                    variables=variables,
                    target_type=TARGET_TYPE,
                    target_id=entry.id,
                    force=True,
                )
            except QuotaExhaustedError as e:
                pause_until = getattr(e, "reset_at", None) or getattr(e, "pause_until", None)
                await db.commit()
                return {"status": "provider_paused", "pause_until": pause_until.isoformat() if pause_until else None}

            if not result:
                return await _finish(FAILED, {"skipped": "no_assignment", "items": len(items)})
            status = result.get("_extraction_status")
            if status == "provider_paused":
                await db.commit()
                return {"status": "provider_paused", "pause_until": result.get("_pause_until")}
            if status not in (None, "success"):
                logger.warning("adjudicate %s: AI returned %r; nothing written", entry_id, status)
                return await _finish(FAILED, {"skipped": f"ai_{status}", "items": len(items)})

            verdicts, stats = _validate_verdicts(result, items)
            detail = await apply_verdicts(db, entry, verdicts, parsed, cfg)
            detail["unknown_ids"] = stats["unknown"]
            if stats["duplicate"]:
                detail["skipped"] = "ai_bad_shape"
            return await _finish(COMPLETED, detail)
    finally:
        try:
            redis_client.delete(lock_key)
        except Exception:
            pass
