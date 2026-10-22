"""Bulk application of hygiene proposals, in batches, with progress.

The Proposals lens offers "Apply all" over queues that can hold thousands of
rows (the adjudicator files one proposal per link it wants gone). Applying
them inside one HTTP request hit the browser's 15 s client timeout long
before the server was done, so the UI reported a failure while the work kept
landing. The batch functions here are the unit of work: a request may call
one once for a small, synchronous apply, and the Celery task in
``app.workers.proposal_apply_tasks`` loops them until the queue is drained,
committing per batch and publishing progress to Redis for the UI to poll.

Two queues, two batch functions:

* ``apply_adjudication_batch`` — the adjudicate stage's pending proposals:
  entity-maintenance rows (unlink / reclassify / veto / merge / demote /
  drop) through ``apply_adjudication_row``, and its link-removal proposals
  through ``apply_link_removal_row``. Assessment flags are informational
  and skipped.
* ``apply_advisory_batch`` — the link validator's ``needs_reclassification``
  advisories, promoted into reclassify operations (deduped per entity).

A row that raises is reported and *excluded from later batches* of the same
job (``exclude_ids``); without that a stuck row would be re-selected forever.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

import redis as sync_redis
from sqlalchemy import func, select
from sqlalchemy import update as sql_update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.exceptions import AppError
from app.models.ai_result import AIResult
from app.models.ai_task import AITask
from app.models.entity_link_validation_log import EntityLinkValidationLog
from app.models.entity_maintenance import EntityMaintenanceLog
from app.services.entry_adjudication import (
    ACTION_ASSESSMENT,
    ADJUDICATION_PROPOSAL_ACTIONS,
    apply_adjudication_row,
)
from app.services.entry_adjudication import TASK_NAME as ADJUDICATION_TASK_NAME

BULK_APPLY_KINDS = ("adjudication", "advisories")
PROGRESS_TTL_SECONDS = 2 * 60 * 60
BATCH_SIZE = 50
MAX_ERRORS_KEPT = 25


def _progress_key(job_id: str) -> str:
    return f"intelfeed:hygiene:bulk_apply:{job_id}"


# ---------------------------------------------------------------------------
# Row appliers
# ---------------------------------------------------------------------------


async def apply_link_removal_row(db: AsyncSession, row: EntityLinkValidationLog) -> bool:
    """Promote one shadow_remove row into the junction deletion (+ `removed`
    audit row). Returns True when the junction was already gone."""
    from app.intelligence.link_validation_apply import ENTITY_TYPES

    if row.action != "shadow_remove":
        raise AppError(code="invalid", message=f"can only apply shadow_remove rows (got {row.action})", status_code=400)
    spec = ENTITY_TYPES.get(row.entity_type)
    if not spec:
        raise AppError(code="invalid", message=f"unsupported entity_type: {row.entity_type}", status_code=400)
    jmodel, emodel, fk_attr = spec
    junction = (
        await db.execute(
            select(jmodel).where(jmodel.entry_id == row.entry_id, getattr(jmodel, fk_attr) == row.entity_id)
        )
    ).scalar_one_or_none()
    if junction is None:
        db.add(
            EntityLinkValidationLog(
                entry_id=row.entry_id,
                entity_type=row.entity_type,
                entity_id=row.entity_id,
                entity_name_snapshot=row.entity_name_snapshot,
                action="removed",
                reason="Promoted from proposal; junction was already absent.",
                ai_result_id=row.ai_result_id,
            )
        )
        await db.flush()
        return True
    db.add(
        EntityLinkValidationLog(
            entry_id=row.entry_id,
            entity_type=row.entity_type,
            entity_id=row.entity_id,
            entity_name_snapshot=row.entity_name_snapshot,
            action="removed",
            reason=f"Promoted from proposal {row.id}: " + (row.reason or "")[:400],
            original_source=junction.source,
            original_confidence=junction.confidence,
            original_matched_names=list(junction.matched_names or []),
            original_paragraph_indices=list(junction.paragraph_indices or []),
            original_extracted_at=junction.extracted_at,
            ai_result_id=row.ai_result_id,
        )
    )
    await db.delete(junction)
    await db.execute(
        sql_update(emodel)
        .where(emodel.id == row.entity_id)
        .values(article_count=func.greatest(emodel.article_count - 1, 0))
    )
    await db.flush()
    return False


# ---------------------------------------------------------------------------
# Scope helpers
# ---------------------------------------------------------------------------


def adjudication_maint_actions(action: str | None) -> list[str]:
    """The entity-maintenance actions a bulk apply covers for ``action``.

    ``None`` means every applyable kind; ``shadow_remove`` means the link log
    only (so no maintenance actions); anything else must be one applyable
    adjudication action.
    """
    applyable = sorted(ADJUDICATION_PROPOSAL_ACTIONS - {ACTION_ASSESSMENT})
    if action is None:
        return applyable
    if action == "shadow_remove":
        return []
    if action not in applyable:
        raise AppError(code="invalid", message=f"not an applyable adjudication action: {action}", status_code=400)
    return [action]


def _adjudicator_results():
    return select(AIResult.id).where(
        AIResult.task_id == select(AITask.id).where(AITask.name == ADJUDICATION_TASK_NAME).scalar_subquery()
    )


async def count_adjudication_pending(db: AsyncSession, action: str | None = None) -> int:
    """How many proposals ``apply_adjudication_batch`` would work through."""
    total = 0
    maint = adjudication_maint_actions(action)
    if maint:
        total += (
            await db.execute(
                select(func.count())
                .select_from(EntityMaintenanceLog)
                .where(EntityMaintenanceLog.action.in_(maint), EntityMaintenanceLog.applied.is_(False))
            )
        ).scalar_one()
    if action in (None, "shadow_remove"):
        total += (
            await db.execute(
                select(func.count())
                .select_from(EntityLinkValidationLog)
                .where(
                    EntityLinkValidationLog.action == "shadow_remove",
                    EntityLinkValidationLog.ai_result_id.in_(_adjudicator_results()),
                )
            )
        ).scalar_one()
    return int(total)


async def count_advisories_pending(db: AsyncSession, entity_type: str | None = None) -> int:
    q = (
        select(func.count())
        .select_from(EntityLinkValidationLog)
        .where(
            EntityLinkValidationLog.action == "needs_reclassification",
            EntityLinkValidationLog.suggested_entity_type.is_not(None),
        )
    )
    if entity_type:
        q = q.where(EntityLinkValidationLog.entity_type == entity_type)
    return int((await db.execute(q)).scalar_one())


# ---------------------------------------------------------------------------
# Batches
# ---------------------------------------------------------------------------


async def apply_adjudication_batch(
    db: AsyncSession,
    *,
    action: str | None = None,
    limit: int = BATCH_SIZE,
    exclude_ids: set[uuid.UUID] | None = None,
) -> dict[str, Any]:
    """Apply up to ``limit`` pending adjudicator proposals, oldest first.

    Each row is its own savepoint, so one failure is reported and the rest
    still apply. Returns ``{"applied", "skipped", "errors", "processed",
    "failed_ids"}``; ``processed`` is how many rows were selected, so a
    caller looping over batches stops when it comes back 0.
    """
    exclude_ids = exclude_ids or set()
    applied = skipped = processed = 0
    errors: list[dict] = []
    failed_ids: set[uuid.UUID] = set()
    budget = limit

    maint_actions = adjudication_maint_actions(action)
    if maint_actions:
        q = (
            select(EntityMaintenanceLog)
            .where(EntityMaintenanceLog.action.in_(maint_actions), EntityMaintenanceLog.applied.is_(False))
            .order_by(EntityMaintenanceLog.created_at.asc())
            .limit(budget)
        )
        if exclude_ids:
            q = q.where(EntityMaintenanceLog.id.notin_(exclude_ids))
        rows = (await db.execute(q)).scalars().all()
        for row in rows:
            try:
                async with db.begin_nested():
                    outcome = await apply_adjudication_row(db, row)
            except Exception as exc:  # one bad row must not sink the batch
                errors.append({"log_id": str(row.id), "action": row.action, "error": str(exc)[:300]})
                failed_ids.add(row.id)
                continue
            if outcome.get("applied"):
                applied += 1
            else:
                skipped += 1
        processed += len(rows)
        budget -= len(rows)

    if budget > 0 and action in (None, "shadow_remove"):
        q = (
            select(EntityLinkValidationLog)
            .where(
                EntityLinkValidationLog.action == "shadow_remove",
                EntityLinkValidationLog.ai_result_id.in_(_adjudicator_results()),
            )
            .order_by(EntityLinkValidationLog.created_at.asc())
            .limit(budget)
        )
        if exclude_ids:
            q = q.where(EntityLinkValidationLog.id.notin_(exclude_ids))
        link_rows = (await db.execute(q)).scalars().all()
        for row in link_rows:
            try:
                async with db.begin_nested():
                    await apply_link_removal_row(db, row)
            except Exception as exc:
                errors.append({"log_id": str(row.id), "action": row.action, "error": str(exc)[:300]})
                failed_ids.add(row.id)
                continue
            applied += 1
        processed += len(link_rows)

    await db.flush()
    return {"applied": applied, "skipped": skipped, "errors": errors, "processed": processed, "failed_ids": failed_ids}


async def apply_advisory_batch(
    db: AsyncSession,
    *,
    entity_type: str | None = None,
    mode: str = "apply",
    limit: int = BATCH_SIZE,
    exclude_ids: set[uuid.UUID] | None = None,
) -> dict[str, Any]:
    """Promote up to ``limit`` ``needs_reclassification`` advisories.

    Same shape as ``apply_adjudication_batch``. In ``shadow`` mode the
    advisories stay in place, so a loop over this function must stop after
    one batch (the task does).
    """
    # Lazy: the advisory promoter lives beside the reclassify endpoint it
    # drives, and that module imports this one.
    from app.api.hygiene import _apply_advisory_rows

    exclude_ids = exclude_ids or set()
    q = (
        select(EntityLinkValidationLog)
        .where(
            EntityLinkValidationLog.action == "needs_reclassification",
            EntityLinkValidationLog.suggested_entity_type.is_not(None),
        )
        .order_by(EntityLinkValidationLog.created_at.desc())
        .limit(limit)
    )
    if entity_type:
        q = q.where(EntityLinkValidationLog.entity_type == entity_type)
    if exclude_ids:
        q = q.where(EntityLinkValidationLog.id.notin_(exclude_ids))
    advisories = list((await db.execute(q)).scalars().all())
    result = await _apply_advisory_rows(db, advisories, mode)

    # Advisories whose reclassify failed stay in the log; keep them out of the
    # next batch. Every advisory for a failed (type, id) tuple is excluded.
    failed_keys = {(e.get("source_type"), e.get("source_id")) for e in result.errors}
    failed_ids = {a.id for a in advisories if (a.entity_type, str(a.entity_id)) in failed_keys}
    # Rows the promoter ignores outright (same-type or unknown-type advisories)
    # are never deleted either, so they must not be re-selected forever.
    for a in advisories:
        if a.entity_type == a.suggested_entity_type:
            failed_ids.add(a.id)
    return {
        "applied": result.applied,
        "skipped": result.skipped + result.failed,
        "errors": list(result.errors),
        "processed": len(advisories),
        "failed_ids": failed_ids,
    }


# ---------------------------------------------------------------------------
# Progress (Redis)
# ---------------------------------------------------------------------------


def new_progress(job_id: str, *, kind: str, scope: dict[str, Any], total: int) -> dict[str, Any]:
    return {
        "job_id": job_id,
        "kind": kind,
        "scope": scope,
        "status": "queued",  # queued | running | done | error
        "total": total,
        "processed": 0,
        "applied": 0,
        "skipped": 0,
        "errors": [],
        "error_count": 0,
        "started_at": datetime.now(UTC).isoformat(),
        "finished_at": None,
        "message": None,
    }


async def write_progress(progress: dict[str, Any]) -> None:
    from app.services.redis_client import get_redis

    r = await get_redis()
    await r.set(_progress_key(progress["job_id"]), json.dumps(progress), ex=PROGRESS_TTL_SECONDS)


async def read_progress(job_id: str) -> dict[str, Any] | None:
    from app.services.redis_client import get_redis

    r = await get_redis()
    raw = await r.get(_progress_key(job_id))
    return json.loads(raw) if raw else None


def write_progress_sync(progress: dict[str, Any]) -> None:
    """The worker's copy of ``write_progress`` (its Redis client is synchronous)."""
    r = sync_redis.from_url(settings.redis_url, decode_responses=True)
    try:
        r.set(_progress_key(progress["job_id"]), json.dumps(progress), ex=PROGRESS_TTL_SECONDS)
    finally:
        r.close()
