"""Bulk "Apply all" for the Proposals lens, off the request thread.

One task per click. It drains the chosen queue in batches of
``BATCH_SIZE`` through the same appliers the per-row buttons use, commits
after every batch, and publishes progress to Redis so the console can show
"Applying 1,240 / 5,249" and know when it is done. Runs on the default
queue: nothing here calls an AI provider.

Failed rows are reported and excluded from later batches, so a stuck row
cannot pin the loop; the loop also stops when a batch selects nothing or the
caller's ``limit`` is reached.
"""

from __future__ import annotations

import logging
import time
import uuid
from datetime import UTC, datetime

from app.workers.celery_app import celery_app
from app.workers.db import run_async, worker_session

logger = logging.getLogger(__name__)

# Even the largest prod backlog (~12k rows at ~100 ms each) fits well inside this.
_SOFT_LIMIT = 3 * 60 * 60


@celery_app.task(
    name="app.workers.proposal_apply_tasks.bulk_apply_proposals",
    bind=True,
    max_retries=0,
    soft_time_limit=_SOFT_LIMIT,
    time_limit=_SOFT_LIMIT + 60,
)
def bulk_apply_proposals(
    self,
    job_id: str,
    kind: str,
    action: str | None = None,
    entity_type: str | None = None,
    mode: str = "apply",
    limit: int | None = None,
    domain: str | None = None,
) -> dict:
    return run_async(
        _bulk_apply(job_id, kind, action=action, entity_type=entity_type, mode=mode, limit=limit, domain=domain)
    )


async def _bulk_apply(
    job_id: str,
    kind: str,
    *,
    action: str | None,
    entity_type: str | None,
    mode: str,
    limit: int | None,
    domain: str | None = None,
) -> dict:
    from app.services import proposal_apply as svc

    progress = await svc.read_progress(job_id)
    if progress is None:
        # The request that queued us always writes the initial record; a
        # missing one means it expired (2 h) before a worker picked this up.
        logger.warning("bulk apply %s: no progress record, starting fresh", job_id)
        progress = svc.new_progress(job_id, kind=kind, scope={"action": action, "entity_type": entity_type}, total=0)
    progress["status"] = "running"
    svc.write_progress_sync(progress)

    started = time.monotonic()
    failed_ids: set[uuid.UUID] = set()
    remaining = limit
    # "all" (the Review tab's one button) is the adjudicator's queue and then
    # the reclassify advisories, under the same action/domain filters. The
    # advisories only run when the filters do not exclude them.
    wanted = svc.parse_actions(action)
    phases = [kind] if kind != "all" else ["adjudication", "advisories"]
    if kind == "all" and ((domain and domain != "entities") or (wanted and "needs_reclassification" not in wanted)):
        phases = ["adjudication"]
    try:
        for phase in phases:
            while True:
                batch_limit = svc.BATCH_SIZE if remaining is None else min(svc.BATCH_SIZE, remaining)
                if batch_limit <= 0:
                    break
                async with worker_session() as db:
                    if phase == "adjudication":
                        out = await svc.apply_adjudication_batch(
                            db, action=action, domain=domain, limit=batch_limit, exclude_ids=failed_ids
                        )
                    elif phase == "advisories":
                        out = await svc.apply_advisory_batch(
                            db, entity_type=entity_type, mode=mode, limit=batch_limit, exclude_ids=failed_ids
                        )
                    else:
                        raise ValueError(f"unknown bulk apply kind: {kind}")
                    await db.commit()

                failed_ids |= out["failed_ids"]
                progress["processed"] += out["processed"]
                progress["applied"] += out["applied"]
                progress["skipped"] += out["skipped"]
                progress["error_count"] += len(out["errors"])
                progress["errors"] = (progress["errors"] + out["errors"])[: svc.MAX_ERRORS_KEPT]
                svc.write_progress_sync(progress)

                if remaining is not None:
                    remaining -= out["processed"]
                if out["processed"] == 0:
                    break
                # Shadow-mode advisories are never consumed, so one pass is the job.
                if phase == "advisories" and mode != "apply":
                    break
        progress["status"] = "done"
    except Exception as exc:  # the record must say why it stopped
        logger.exception("bulk apply %s failed", job_id)
        progress["status"] = "error"
        progress["message"] = str(exc)[:300]
    finally:
        progress["finished_at"] = datetime.now(UTC).isoformat()
        progress["duration_ms"] = int((time.monotonic() - started) * 1000)
        svc.write_progress_sync(progress)

    return {k: progress[k] for k in ("status", "processed", "applied", "skipped", "error_count")}
