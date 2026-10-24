"""Adjudicate stage worker: the per-entry post-analysis AI review.

One task per entry, dispatched by services/entry_adjudication after the
one-pass analysis has been stored and committed. Runs on the `ai` queue
(celery-worker-ai, concurrency 1) so a review and the analysis it reviews
never hold the provider at once. Wrapped with @pipeline_stage so the Engine matrix gets a
column and the verdict counts land in the run's `detail`.

The task re-checks the master switch only: the plan, trigger, score and
budget gates were decided at enqueue time (``enqueue_adjudication``), and a
manual re-run from the matrix deliberately bypasses them. An entry whose
mode was switched off meanwhile, a lost lock, or a missing analysis all end
in a recorded status rather than a review. A review that exhausts its
retries records ``failed`` so the resweep can tell it from a queued one.
"""

from __future__ import annotations

import logging
import time
import uuid
from datetime import UTC, datetime

import redis
from celery.exceptions import Retry

from app.ai.caller import Caller
from app.config import settings
from app.core.metrics import CELERY_TASK_DURATION_SECONDS, CELERY_TASKS_TOTAL
from app.workers.celery_app import celery_app
from app.workers.db import run_async, worker_session
from app.workers.pipeline_logging import pipeline_stage

logger = logging.getLogger(__name__)

_LOCK_TTL = 900
_redis_client: redis.Redis | None = None


def _redis() -> redis.Redis:
    """One sync client per worker process (the lock is a two-call affair)."""
    global _redis_client
    if _redis_client is None:
        _redis_client = redis.from_url(settings.redis_url, decode_responses=True)
    return _redis_client


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
        if detail.get("skipped") == "provider_paused":
            CELERY_TASKS_TOTAL.labels(task_name="adjudicate_entry_task", status="provider_paused").inc()
        else:
            CELERY_TASKS_TOTAL.labels(task_name="adjudicate_entry_task", status="success").inc()
        return detail
    except Retry:
        raise
    except Exception as exc:
        if self.request.retries >= self.max_retries:
            CELERY_TASKS_TOTAL.labels(task_name="adjudicate_entry_task", status="error").inc()
            run_async(_record_failure(uuid.UUID(entry_id), exc))
            raise
        CELERY_TASKS_TOTAL.labels(task_name="adjudicate_entry_task", status="retry").inc()
        raise self.retry(exc=exc, countdown=min(300, 60 * (self.request.retries + 1)))
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="adjudicate_entry_task").observe(time.monotonic() - start)


async def _record_failure(entry_id: uuid.UUID, exc: BaseException) -> None:
    """Retries exhausted: leave `failed` on the row, not a `pending` the sweep
    would wait STALE_PENDING_HOURS to notice."""
    from app.services.entry_adjudication import FAILED, _request_row

    try:
        async with worker_session() as db:
            row = await _request_row(db, entry_id)
            row.adjudication_status = FAILED
            row.adjudicated_at = datetime.now(UTC)
            db.add(row)
            await db.commit()
    except Exception:
        logger.warning("adjudicate %s: could not record the failure (%s)", entry_id, exc, exc_info=True)


async def _adjudicate_entry(entry_id: uuid.UUID) -> dict:
    from app.ai.engine import run_task
    from app.ai.providers.claude_code_provider import QuotaExhaustedError
    from app.models.entry import Entry
    from app.services.entry_adjudication import (
        COMPLETED,
        FAILED,
        SKIPPED_OFF,
        SKIPPED_PAUSED,
        TARGET_TYPE,
        TASK_NAME,
        _current_analysis,
        _request_row,
        _settings,
        _validate_verdicts,
        apply_verdicts,
        build_variables,
        supersede_legacy_proposals,
    )
    from app.services.system_settings import _ensure_cache, invalidate_cache
    from app.services.system_user import get_system_user_id

    redis_client = _redis()
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

            # A duplicate dispatch — the resweep re-queued a row whose first
            # task was still waiting its turn — must not re-run the model: the
            # first task's verdicts already landed. A fresh analysis always
            # resets the row to `pending` before it dispatches, so `completed`
            # here can only mean "already done".
            if row.adjudication_status == COMPLETED:
                return {"skipped": "already_reviewed", "mode": cfg["mode"], "items": 0}

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

            # Legacy rows are taken here, before the model runs, so the
            # reviewer's own freshly written rows are never superseded.
            dropped: list = []
            items, variables, legacy_rows = await build_variables(db, entry, parsed, cfg, dropped_out=dropped)
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
                    caller=Caller.system(user_id),
                )
            except QuotaExhaustedError as e:
                # The provider is paused: park the row like an over-budget
                # one; the resweep re-enqueues it when a new hour starts.
                pause_until = getattr(e, "reset_at", None) or getattr(e, "pause_until", None)
                return await _finish(
                    SKIPPED_PAUSED,
                    {"skipped": "provider_paused", "pause_until": pause_until.isoformat() if pause_until else None},
                )

            if not result:
                return await _finish(FAILED, {"skipped": "no_assignment", "items": len(items)})
            status = result.get("_extraction_status")
            if status == "provider_paused":
                return await _finish(
                    SKIPPED_PAUSED, {"skipped": "provider_paused", "pause_until": result.get("_pause_until")}
                )
            if status not in (None, "success"):
                logger.warning("adjudicate %s: AI returned %r; nothing written", entry_id, status)
                return await _finish(FAILED, {"skipped": f"ai_{status}", "items": len(items)})

            verdicts, stats = _validate_verdicts(result, items)
            detail = await apply_verdicts(db, entry, verdicts, parsed, cfg)
            detail["superseded"] = await supersede_legacy_proposals(db, legacy_rows)
            detail["unknown_ids"] = stats["unknown"]
            detail["coerced_verdicts"] = stats["coerced"]
            for kind, key in (("link", "uncapped_links"), ("edge", "uncapped_edges")):
                if n := sum(1 for it in dropped if it.kind == kind):
                    detail[key] = n
            if stats["duplicate"]:
                detail["skipped"] = "ai_bad_shape"
            return await _finish(COMPLETED, detail)
    finally:
        try:
            redis_client.delete(lock_key)
        except Exception:
            pass


@celery_app.task(
    name="app.workers.adjudication_tasks.backfill_entry_adjudications",
    soft_time_limit=600,
    time_limit=660,
)
def backfill_entry_adjudications(limit: int = 500, since_days: int | None = None) -> dict:
    """One-off walk: queue every analysed entry the stage has not decided on,
    newest first, through the normal gates. Backfill draws on its share of
    each hour's budget only (live entries keep the rest); the ones that do
    not fit wait as `skipped_budget` and the resweep drains them, newest
    first. Not scheduled — dispatch it once per rollout, like
    backfill_entry_scores:

        celery -A app.workers.celery_app call \\
            app.workers.adjudication_tasks.backfill_entry_adjudications
    """
    start = time.monotonic()
    try:
        stats = run_async(_backfill(limit, since_days))
        logger.info("adjudication backfill: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="backfill_entry_adjudications", status="success").inc()
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="backfill_entry_adjudications", status="error").inc()
        logger.exception("adjudication backfill failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="backfill_entry_adjudications").observe(time.monotonic() - start)


async def _backfill(limit: int, since_days: int | None) -> dict:
    from app.services.entry_adjudication import (
        PENDING,
        SKIPPED_BUDGET,
        _current_analysis,
        dispatch_adjudication,
        enqueue_adjudication,
        select_backfill_entries,
    )
    from app.services.system_settings import _ensure_cache, invalidate_cache

    async with worker_session() as db:
        invalidate_cache()
        await _ensure_cache(db)
        entry_ids = await select_backfill_entries(db, limit=limit, since_days=since_days)
        stats = {"candidates": len(entry_ids), "queued": 0, "waiting": 0, "skipped": 0}
        for i, entry_id in enumerate(entry_ids):
            _result, parsed = await _current_analysis(db, entry_id)
            status = await enqueue_adjudication(db, entry_id, None, parsed, backfill=True)
            if status == PENDING:
                stats["queued"] += 1
                # Spread the queue so live reviews interleave with backfill.
                dispatch_adjudication(entry_id, countdown=30 + i * 2)
            elif status == SKIPPED_BUDGET:
                stats["waiting"] += 1
            else:
                stats["skipped"] += 1
        await db.commit()
        return stats
