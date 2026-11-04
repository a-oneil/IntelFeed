"""Bulk "Apply all" for the Review tab, off the request thread.

One task per click. It reads the groups the tab's filters select once, then
walks them a chunk at a time: each chunk's rows are applied in batches of
``BATCH_SIZE`` through the same appliers a row's Apply uses
(``app.api.hygiene.apply_review_rows``), committing after every batch, and
progress goes to Redis so the console can show "Applying 1,240 / 5,249" and
know when it is done. Runs on the default queue: nothing here calls an AI
provider.

Every row is tried once, so a row that fails or has nothing to do cannot pin
the loop. Proposals filed after the job started wait for the next run.
"""

from __future__ import annotations

import logging
import time
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
def bulk_apply_proposals(self, job_id: str, scope: dict, limit: int | None = None) -> dict:
    return run_async(_bulk_apply(job_id, scope, limit=limit))


async def _bulk_apply(job_id: str, scope: dict, *, limit: int | None) -> dict:
    from app.api.hygiene import (
        _GROUPS_PER_CHUNK,
        ReviewScope,
        _appliable,
        _chunks,
        _group_rows,
        _scope_match,
        apply_review_rows,
        review_scope_groups,
    )
    from app.services import proposal_apply as svc

    progress = await svc.read_progress(job_id)
    if progress is None:
        # The request that queued us always writes the initial record; a
        # missing one means it expired (2 h) before a worker picked this up.
        logger.warning("bulk apply %s: no progress record, starting fresh", job_id)
        progress = svc.new_progress(job_id, scope=scope, total=0)
    progress["status"] = "running"
    svc.write_progress_sync(progress)

    review_scope = ReviewScope(**scope)
    started = time.monotonic()
    left = limit
    try:
        match = _scope_match(review_scope)
        async with worker_session() as db:
            groups = await review_scope_groups(db, review_scope)
        for chunk in _chunks(groups, _GROUPS_PER_CHUNK):
            if left is not None and left <= 0:
                break
            async with worker_session() as db:
                refs = _appliable(await _group_rows(db, chunk, match), include_reclassify=True)
                if left is not None:
                    refs = refs[:left]
                for batch in _chunks(refs, svc.BATCH_SIZE):
                    out = await apply_review_rows(db, batch, None)
                    await db.commit()
                    progress["processed"] += out["processed"]
                    progress["applied"] += out["applied"]
                    progress["skipped"] += out["skipped"]
                    progress["error_count"] += out["failed"]
                    progress["errors"] = (progress["errors"] + out["errors"])[: svc.MAX_ERRORS_KEPT]
                    svc.write_progress_sync(progress)
                if left is not None:
                    left -= len(refs)
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
