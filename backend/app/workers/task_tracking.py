"""Celery signal handlers that persist job_runs rows for scheduled (registry) tasks.

Filtered to JOB_REGISTRY tasks only — per-entry pipeline tasks would produce
~100k rows/day and are covered by entry_pipeline_runs instead (phase 5). Every
handler swallows its own errors: run tracking must never break a task.

Wired by importing this module in celery_app.py.
"""

import logging
import time
from datetime import UTC, datetime

from celery.signals import task_failure, task_postrun, task_prerun, task_retry

from app.workers.job_registry import JOB_REGISTRY

logger = logging.getLogger(__name__)

# task path -> registry job key
KNOWN_JOB_TASKS: dict[str, str] = {job["task"]: key for key, job in JOB_REGISTRY.items()}

_STARTED_ATTR = "_intelfeed_job_run_started"


def _clip(value, depth: int = 0):
    """JSON-safe, size-bounded rendering of task args/results for JobRun.detail."""
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value if len(value) <= 200 else value[:200] + "…"
    if isinstance(value, dict) and depth < 2:
        clipped = {str(k)[:60]: _clip(v, depth + 1) for k, v in list(value.items())[:20]}
        if len(value) > 20:
            clipped["…"] = f"+{len(value) - 20} more keys"
        return clipped
    if isinstance(value, (list, tuple, set)) and depth < 2:
        items = list(value)
        clipped = [_clip(v, depth + 1) for v in items[:10]]
        if len(items) > 10:
            clipped.append(f"… +{len(items) - 10} more")
        return clipped
    return str(value)[:200]


def _task_detail(args, kwargs, retval) -> dict | None:
    """Clipped {"args", "kwargs", "result"} — what the job ran against and what it did."""
    detail: dict = {}
    try:
        if args:
            detail["args"] = _clip(list(args))
        if kwargs:
            detail["kwargs"] = _clip(dict(kwargs))
        if retval is not None:
            detail["result"] = _clip(retval)
    except Exception:
        logger.debug("job_run detail capture failed", exc_info=True)
    return detail or None


def _record_run(
    task_name: str,
    task_id: str | None,
    status: str,
    started: float | None,
    error: str | None,
    detail: dict | None = None,
) -> None:
    from app.models.job_run import JobRun
    from app.workers.db import run_async, worker_session

    now = datetime.now(UTC)
    duration_ms = int((time.monotonic() - started) * 1000) if started else None

    async def _write():
        async with worker_session() as db:
            db.add(
                JobRun(
                    task_name=task_name,
                    job_key=KNOWN_JOB_TASKS.get(task_name),
                    celery_task_id=task_id,
                    status=status,
                    started_at=now,  # approximate; duration_ms carries the precise timing
                    finished_at=now,
                    duration_ms=duration_ms,
                    error=(error or None) and str(error)[:4000],
                    detail=detail,
                )
            )
            await db.commit()

    run_async(_write())


@task_prerun.connect
def _job_run_prerun(task_id=None, task=None, **_kwargs):
    try:
        if task is not None and task.name in KNOWN_JOB_TASKS:
            setattr(task.request, _STARTED_ATTR, time.monotonic())
    except Exception:
        logger.debug("job_run prerun tracking failed", exc_info=True)


@task_postrun.connect
def _job_run_postrun(task_id=None, task=None, state=None, args=None, kwargs=None, retval=None, **_kwargs):
    try:
        if task is None or task.name not in KNOWN_JOB_TASKS:
            return
        started = getattr(task.request, _STARTED_ATTR, None)
        # FAILURE is recorded by the task_failure handler (it has the exception)
        if state == "FAILURE":
            return
        status = "success" if state == "SUCCESS" else (state or "success").lower()
        _record_run(task.name, task_id, status, started, None, detail=_task_detail(args, kwargs, retval))
    except Exception:
        logger.debug("job_run postrun tracking failed", exc_info=True)


@task_failure.connect
def _job_run_failure(task_id=None, exception=None, sender=None, args=None, kwargs=None, **_kwargs):
    try:
        if sender is None or sender.name not in KNOWN_JOB_TASKS:
            return
        started = getattr(sender.request, _STARTED_ATTR, None)
        _record_run(sender.name, task_id, "error", started, repr(exception), detail=_task_detail(args, kwargs, None))
    except Exception:
        logger.debug("job_run failure tracking failed", exc_info=True)


@task_retry.connect
def _job_run_retry(request=None, reason=None, sender=None, **_kwargs):
    try:
        if sender is None or sender.name not in KNOWN_JOB_TASKS:
            return
        _record_run(sender.name, getattr(request, "id", None), "retry", None, repr(reason))
    except Exception:
        logger.debug("job_run retry tracking failed", exc_info=True)
