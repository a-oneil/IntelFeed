"""Admin endpoints for the AI-driven entity-link validator.

Routes:
  GET    /api/admin/link-validation/stats          — overview cards data
  GET    /api/admin/link-validation/log            — paginated audit log
  POST   /api/admin/link-validation/log/{id}/restore — re-create a removed junction row
  POST   /api/admin/link-validation/run            — manual trigger (one entry or N oldest)
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, Path, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import and_, exists, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.exceptions import AppError
from app.core.security import get_admin_user
from app.database import get_db
from app.models.entity_link_validation_log import EntityLinkValidationLog
from app.models.entry import Entry
from app.models.user import User
from app.workers.link_validation_tasks import (
    ENTITY_TYPES,
    JUNCTION_SPECS,
    enqueue_pending_link_validations,
    restore_from_log,
    validate_single_entry_links,
)

router = APIRouter()


# --------------------------------------------------------------- stats


@router.get("/stats")
async def get_stats(
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Overview counts for the Settings UI cards."""
    from app.services.system_settings import get_setting

    mode_val = await get_setting("link_validation_mode", db)
    mode = (str(mode_val) if mode_val else "shadow").lower()
    recheck_days_val = await get_setting("link_validation_recheck_days", db)
    recheck_days = int(recheck_days_val if recheck_days_val is not None else 30)
    cutoff = datetime.now(UTC) - timedelta(days=recheck_days)

    # Pending entries: have auto_link rows AND aren't recently validated.
    exists_clauses = [
        exists().where(and_(jmodel.entry_id == Entry.id, jmodel.source == "auto_link"))
        for jmodel, _, _, _ in JUNCTION_SPECS
    ]
    pending_q = (
        select(func.count())
        .select_from(Entry)
        .where(
            or_(
                Entry.last_link_validation_at.is_(None),
                Entry.last_link_validation_at < cutoff,
            ),
            or_(*exists_clauses),
        )
    )
    pending_count = (await db.execute(pending_q)).scalar_one()

    now = datetime.now(UTC)
    last_24h = now - timedelta(hours=24)
    last_7d = now - timedelta(days=7)

    validated_24h_q = select(func.count()).select_from(Entry).where(Entry.last_link_validation_at >= last_24h)
    validated_24h = (await db.execute(validated_24h_q)).scalar_one()

    removed_24h_q = (
        select(func.count())
        .select_from(EntityLinkValidationLog)
        .where(
            EntityLinkValidationLog.action == "removed",
            EntityLinkValidationLog.created_at >= last_24h,
        )
    )
    removed_24h = (await db.execute(removed_24h_q)).scalar_one()

    removed_7d_q = (
        select(func.count())
        .select_from(EntityLinkValidationLog)
        .where(
            EntityLinkValidationLog.action == "removed",
            EntityLinkValidationLog.created_at >= last_7d,
        )
    )
    removed_7d = (await db.execute(removed_7d_q)).scalar_one()

    shadow_7d_q = (
        select(func.count())
        .select_from(EntityLinkValidationLog)
        .where(
            EntityLinkValidationLog.action == "shadow_remove",
            EntityLinkValidationLog.created_at >= last_7d,
        )
    )
    shadow_removed_7d = (await db.execute(shadow_7d_q)).scalar_one()

    restored_7d_q = (
        select(func.count())
        .select_from(EntityLinkValidationLog)
        .where(
            EntityLinkValidationLog.action == "restored",
            EntityLinkValidationLog.created_at >= last_7d,
        )
    )
    restored_7d = (await db.execute(restored_7d_q)).scalar_one()

    # Apply and dismiss both delete needs_reclassification rows, so every
    # surviving row is a pending advisory — count them all, no time window,
    # so the attention chip always matches the reviewable queue.
    reclassify_pending_q = (
        select(func.count())
        .select_from(EntityLinkValidationLog)
        .where(EntityLinkValidationLog.action == "needs_reclassification")
    )
    reclassify_pending = (await db.execute(reclassify_pending_q)).scalar_one()

    last_run_q = select(func.max(Entry.last_link_validation_at))
    last_run_at = (await db.execute(last_run_q)).scalar_one()

    return {
        "mode": mode,
        "pending_count": pending_count,
        "validated_24h": validated_24h,
        "removed_24h": removed_24h,
        "removed_7d": removed_7d,
        "shadow_removed_7d": shadow_removed_7d,
        "restored_7d": restored_7d,
        "reclassify_pending": reclassify_pending,
        "last_run_at": last_run_at.isoformat() if last_run_at else None,
        "recheck_days": recheck_days,
    }


# ------------------------------------------------------------- log list


def _serialize_log(row: EntityLinkValidationLog) -> dict[str, Any]:
    return {
        "id": str(row.id),
        "entry_id": str(row.entry_id),
        "entity_type": row.entity_type,
        "entity_id": str(row.entity_id),
        "entity_name_snapshot": row.entity_name_snapshot,
        "action": row.action,
        "reason": row.reason,
        "original_source": row.original_source,
        "original_confidence": row.original_confidence,
        "original_matched_names": list(row.original_matched_names or []),
        "original_paragraph_indices": list(row.original_paragraph_indices or []),
        "original_extracted_at": row.original_extracted_at.isoformat() if row.original_extracted_at else None,
        "suggested_entity_type": row.suggested_entity_type,
        "ai_result_id": str(row.ai_result_id) if row.ai_result_id else None,
        "created_at": row.created_at.isoformat(),
    }


@router.get("/log")
async def list_log(
    entity_type: str | None = Query(None, description="Filter by entity type (threat_actor, malware, cve, ttp, ...)"),
    entity_id: uuid.UUID | None = Query(None, description="Filter by entity UUID"),
    entry_id: uuid.UUID | None = Query(None, description="Filter by entry UUID"),
    action: str | None = Query(
        None, description="Filter by action (removed, shadow_remove, restored, needs_reclassification)"
    ),
    limit: int = Query(50, ge=1, le=500, description="Rows per page"),
    offset: int = Query(0, ge=0, description="Rows to skip for pagination"),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Paginated audit log with optional filters."""
    stmt = select(EntityLinkValidationLog)
    count_stmt = select(func.count()).select_from(EntityLinkValidationLog)

    filters: list = []
    if entity_type:
        filters.append(EntityLinkValidationLog.entity_type == entity_type)
    if entity_id:
        filters.append(EntityLinkValidationLog.entity_id == entity_id)
    if entry_id:
        filters.append(EntityLinkValidationLog.entry_id == entry_id)
    if action:
        filters.append(EntityLinkValidationLog.action == action)
    if filters:
        stmt = stmt.where(and_(*filters))
        count_stmt = count_stmt.where(and_(*filters))

    total = (await db.execute(count_stmt)).scalar_one()
    stmt = stmt.order_by(EntityLinkValidationLog.created_at.desc()).offset(offset).limit(limit)
    rows = (await db.execute(stmt)).scalars().all()

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": [_serialize_log(r) for r in rows],
    }


# ----------------------------------------------------------------- restore


@router.post("/log/{log_id}/restore")
async def restore_link(
    log_id: uuid.UUID = Path(..., description="Log row UUID of a 'removed' action to undo"),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Re-create a junction row from a removed log entry (and the entity's article_count)."""
    ok, message = await restore_from_log(db, log_id)
    if not ok:
        raise AppError(code="restore_failed", message=message, status_code=400)
    await db.commit()
    return {"restored": True, "message": message, "log_id": str(log_id)}


@router.post("/log/{log_id}/apply-removal")
async def apply_proposed_removal(
    log_id: uuid.UUID = Path(..., description="Log row UUID of a 'shadow_remove' advisory to promote"),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Promote a shadow_remove advisory into an actual junction deletion.

    Re-fetches the original junction row, deletes it, decrements the entity's
    article_count, and writes a new `removed` log row (the original
    `shadow_remove` row stays as proposal history). Idempotent: if the
    junction is already gone, returns success with `already_removed=True`.
    """
    from sqlalchemy import update as sql_update

    row = (
        await db.execute(select(EntityLinkValidationLog).where(EntityLinkValidationLog.id == log_id))
    ).scalar_one_or_none()
    if not row:
        raise AppError(code="not_found", message="advisory not found", status_code=404)
    if row.action != "shadow_remove":
        raise AppError(
            code="invalid",
            message=f"can only apply rows with action='shadow_remove' (got {row.action})",
            status_code=400,
        )
    spec = ENTITY_TYPES.get(row.entity_type)
    if not spec:
        raise AppError(
            code="invalid",
            message=f"unsupported entity_type: {row.entity_type}",
            status_code=400,
        )
    jmodel, emodel, fk_attr = spec
    fk_col = getattr(jmodel, fk_attr)

    junction = (
        await db.execute(select(jmodel).where(jmodel.entry_id == row.entry_id, fk_col == row.entity_id))
    ).scalar_one_or_none()

    if junction is None:
        # Already gone — just record the resolution.
        db.add(
            EntityLinkValidationLog(
                entry_id=row.entry_id,
                entity_type=row.entity_type,
                entity_id=row.entity_id,
                entity_name_snapshot=row.entity_name_snapshot,
                action="removed",
                reason="Promoted from proposed; junction was already absent.",
                ai_result_id=row.ai_result_id,
            )
        )
        await db.commit()
        return {"applied": True, "already_removed": True, "log_id": str(log_id)}

    db.add(
        EntityLinkValidationLog(
            entry_id=row.entry_id,
            entity_type=row.entity_type,
            entity_id=row.entity_id,
            entity_name_snapshot=row.entity_name_snapshot,
            action="removed",
            reason=f"Promoted from proposal {log_id}: " + (row.reason or "")[:400],
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
    await db.commit()
    return {"applied": True, "already_removed": False, "log_id": str(log_id)}


# --------------------------------------------------------- manual trigger


class RunRequest(BaseModel):
    entry_id: uuid.UUID | None = None
    limit: int | None = None
    all_pending: bool = False

    model_config = ConfigDict(json_schema_extra={"example": {"limit": 200, "all_pending": False}})


@router.post("/run")
async def run_validation(
    body: RunRequest | None = None,
    entry_id: uuid.UUID | None = Query(None, description="Validate just this one entry"),
    limit: int | None = Query(None, description="Enqueue up to this many pending entries (no upper cap)"),
    all_pending: bool = Query(False, description="Enqueue every entry currently due, ignoring the batch cap"),
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Manually enqueue per-entry validation.

    Modes (in priority order):
      - entry_id provided → enqueue just that one entry
      - all_pending=true → enqueue every entry currently due for validation,
        ignoring the scheduled-job batch cap. Useful for an initial bulk pass.
      - limit provided → enqueue up to that many (caller's choice, no upper limit)
      - default → enqueue settings.link_validation_entries_per_run (matches the
        scheduled-job behavior; safe for a quick smoke test)
    """
    target_entry_id = (body and body.entry_id) or entry_id
    requested_limit = (body and body.limit) or limit
    want_all = bool((body and body.all_pending) or all_pending)

    if target_entry_id is not None:
        validate_single_entry_links.apply_async(args=[str(target_entry_id)], queue="ai")
        return {"enqueued": 1, "entry_id": str(target_entry_id)}

    recheck_days = int(settings.get("link_validation_recheck_days") or 30)
    if want_all:
        cap = 100_000
    elif requested_limit is not None:
        cap = int(requested_limit)
    else:
        cap = int(settings.get("link_validation_entries_per_run") or 200)

    # Quick count so the UI can show an estimate without waiting on the fan-out.
    cutoff = datetime.now(UTC) - timedelta(days=recheck_days)
    exists_clauses = [
        exists().where(and_(jmodel.entry_id == Entry.id, jmodel.source == "auto_link"))
        for jmodel, _, _, _ in JUNCTION_SPECS
    ]
    pending_q = (
        select(func.count())
        .select_from(Entry)
        .where(
            or_(Entry.last_link_validation_at.is_(None), Entry.last_link_validation_at < cutoff),
            or_(*exists_clauses),
        )
    )
    pending_count = (await db.execute(pending_q)).scalar_one()
    estimated = min(int(pending_count), cap)

    enqueue_pending_link_validations.apply_async(args=[cap, recheck_days])
    return {"enqueued": estimated, "scheduled": True}
