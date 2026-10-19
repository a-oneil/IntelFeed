"""@pipeline_stage — terminal-write run logging for per-entry pipeline tasks.

Wraps the sync Celery task functions (INSIDE the @celery_app.task decorator)
and records one EntryPipelineRun row when the stage completes. Deliberately
does NOT touch the tasks' existing Prometheus metric boilerplate — the plan
wanted the decorator to subsume it, but doing both would double-count
CELERY_TASKS_TOTAL, so metrics stay where they are (deviation noted in
planning/engine-progress.md).

Never raises: run logging failing must not break a task. Gated by the
pipeline_run_logging_enabled kill switch.
"""

import functools
import logging
import time
import uuid

logger = logging.getLogger(__name__)


def _extract_entry_id(args, kwargs) -> str | None:
    """entry_id kwarg, else first UUID-parseable positional (skips `self` on bind tasks)."""
    candidates = [kwargs.get("entry_id"), *args[:2]]
    for candidate in candidates:
        if candidate is None:
            continue
        try:
            return str(uuid.UUID(str(candidate)))
        except (ValueError, TypeError):
            continue
    return None


def _record_stage_run(
    entry_id: str,
    stage: str,
    status: str,
    duration_ms: int,
    error: str | None,
    detail: dict | None = None,
) -> None:
    from app.models.entry_pipeline_run import EntryPipelineRun
    from app.services.system_settings import get_setting
    from app.workers.db import run_async, worker_session

    async def _write():
        async with worker_session() as db:
            if not bool(await get_setting("pipeline_run_logging_enabled", db)):
                return
            db.add(
                EntryPipelineRun(
                    entry_id=uuid.UUID(entry_id),
                    stage=stage,
                    status=status,
                    duration_ms=duration_ms,
                    error=(error or None) and str(error)[:4000],
                    detail=detail or {},
                )
            )
            await db.commit()

    try:
        run_async(_write())
    except Exception:
        logger.debug("pipeline run logging failed for %s/%s", entry_id, stage, exc_info=True)


def pipeline_stage(stage: str):
    """Decorate a sync Celery task body; records an EntryPipelineRun on completion.

    A task that returns a dict gets it stored as the run's ``detail`` (the
    adjudicate stage returns its verdict counts this way); other return values
    are ignored. Apply BELOW @celery_app.task:

        @celery_app.task(name=..., ...)
        @pipeline_stage("autolink")
        def autolink_entry_task(entry_id: str): ...
    """

    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            start = time.monotonic()
            status, error = "success", None
            detail: dict | None = None
            try:
                result = fn(*args, **kwargs)
                if isinstance(result, dict):
                    detail = result
                return result
            except Exception as exc:
                from celery.exceptions import Retry

                status = "retry" if isinstance(exc, Retry) else "error"
                error = repr(exc)
                raise
            finally:
                entry_id = _extract_entry_id(args, kwargs)
                if entry_id:
                    duration_ms = int((time.monotonic() - start) * 1000)
                    _record_stage_run(entry_id, stage, status, duration_ms, error, detail)

        return wrapper

    return decorator
