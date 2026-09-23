"""AI reviewer for pending entity-hygiene proposals.

Upstream hygiene jobs (link validator, merge engine, name normalizer, alias
scanner, vendor autolinker, id scanners) leave *proposals* behind — advisory
rows in entity_link_validation_log (needs_reclassification) and unapplied rows
in entity_maintenance_log. This module adds the judgment layer on top:

  review_hygiene_proposals       — kickoff. Collects every pending, unreviewed
                                   proposal from both log tables, fans out
                                   batches to the `ai` queue.

  review_hygiene_proposal_batch  — judges one batch via the
                                   hygiene_proposal_review AI task and writes
                                   approve/reject/unsure verdicts back onto the
                                   log rows. When hygiene_review_auto_apply is
                                   enabled, approved proposals are applied (and
                                   rejected ones dismissed) with no human in
                                   the loop — the fully-automatic hygiene mode.

Verdicts surface in the workbench Hygiene tab (badge + reason per row) and
gate the "Apply AI-approved" bulk action there.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.engine import run_task
from app.config import settings
from app.core.metrics import CELERY_TASK_DURATION_SECONDS, CELERY_TASKS_TOTAL
from app.models.entity_link_validation_log import EntityLinkValidationLog
from app.models.entity_maintenance import EntityMaintenanceLog
from app.models.user import User
from app.workers.celery_app import celery_app
from app.workers.db import run_async, worker_session

logger = logging.getLogger(__name__)

# Maintenance actions that represent pending (unapplied) proposals worth
# judging. Mirrors _MAINTENANCE_PROPOSAL_ACTIONS in app/api/hygiene.py, plus
# shadow orphan prunes and stale-entity flags (review-only rows the AI can
# still vouch for or veto).
REVIEWABLE_MAINTENANCE_ACTIONS = {
    "merge_cluster_summary",
    "normalize_name",
    "alias_collision",
    "vendor_autolink",
    "ttp_malformed_id",
    "cve_malformed_id",
    "cve_withdrawn",
    "stale_entity_review",
}

VALID_DECISIONS = {"approve", "reject", "unsure"}


async def _resolve_system_user(db: AsyncSession) -> User | None:
    from app.services.system_user import get_system_user

    return await get_system_user(db)


# --------------------------------------------------------------------------- kickoff


@celery_app.task(
    name="app.workers.hygiene_review_tasks.review_hygiene_proposals",
    soft_time_limit=300,
    time_limit=360,
)
def review_hygiene_proposals(limit: int | None = None) -> dict:
    """Kickoff: gather pending unreviewed proposals, fan out review batches."""
    start = time.monotonic()
    try:
        stats = run_async(_kickoff_async(limit))
        CELERY_TASKS_TOTAL.labels(task_name="review_hygiene_proposals", status="success").inc()
        logger.info("review_hygiene_proposals kickoff: %s", stats)
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="review_hygiene_proposals", status="error").inc()
        logger.exception("review_hygiene_proposals kickoff failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="review_hygiene_proposals").observe(time.monotonic() - start)


async def _kickoff_async(limit: int | None) -> dict:
    batch_size = max(1, int(settings.get("hygiene_review_batch_size") or 20))

    async with worker_session() as db:
        items = await collect_pending_proposals(db, limit)

    if not items:
        return {"status": "no_pending_proposals", "proposals": 0, "batches": 0}

    batches = 0
    for i in range(0, len(items), batch_size):
        review_hygiene_proposal_batch.apply_async(args=[items[i : i + batch_size]], queue="ai")
        batches += 1

    return {"status": "dispatched", "proposals": len(items), "batches": batches, "batch_size": batch_size}


async def collect_pending_proposals(db: AsyncSession, limit: int | None = None) -> list[dict]:
    """Serialize every pending, unreviewed proposal into a compact review item.

    Item shape: {proposal_id, kind, summary, reason, context}. proposal_id is
    "{source}:{row_id}" — the same composite id the hygiene feed uses — so
    verdicts route back to the right table.
    """
    # Subject formatters live in the API layer; import lazily to avoid a
    # module-level cycle (api.hygiene dispatches our kickoff task).
    from app.api.hygiene import _link_subject, _maint_subject

    items: list[dict] = []

    link_q = (
        select(EntityLinkValidationLog)
        .where(
            EntityLinkValidationLog.action == "needs_reclassification",
            EntityLinkValidationLog.review_decision.is_(None),
        )
        .order_by(EntityLinkValidationLog.created_at.asc())
    )
    if limit:
        link_q = link_q.limit(limit)
    for row in (await db.execute(link_q)).scalars().all():
        items.append(
            {
                "proposal_id": f"link_validator:{row.id}",
                "kind": "needs_reclassification",
                "summary": _link_subject(row),
                "reason": (row.reason or "")[:300],
                "context": {
                    "current_type": row.entity_type,
                    "suggested_type": row.suggested_entity_type,
                    "matched_names": list(row.original_matched_names or [])[:5],
                },
            }
        )

    maint_q = (
        select(EntityMaintenanceLog)
        .where(
            EntityMaintenanceLog.action.in_(sorted(REVIEWABLE_MAINTENANCE_ACTIONS)),
            EntityMaintenanceLog.applied.is_(False),
            EntityMaintenanceLog.review_decision.is_(None),
        )
        .order_by(EntityMaintenanceLog.created_at.asc())
    )
    if limit:
        maint_q = maint_q.limit(limit)
    for row in (await db.execute(maint_q)).scalars().all():
        items.append(
            {
                "proposal_id": f"entity_maintenance:{row.id}",
                "kind": row.action,
                "summary": _maint_subject(row),
                "reason": (row.reasoning or "")[:300],
                "context": _maint_context(row),
            }
        )

    if limit:
        items = items[:limit]
    return items


def _maint_context(row: EntityMaintenanceLog) -> dict:
    """Pick the decision-relevant fields out of the row's before/after blobs."""
    before = row.before or {}
    after = row.after or {}
    ctx: dict = {"entity_type": row.entity_type}

    ent = before.get("entity") if isinstance(before.get("entity"), dict) else {}
    if ent:
        ctx["entity"] = {
            "name": ent.get("name"),
            "aliases": (ent.get("aliases") or [])[:8],
            "article_count": ent.get("article_count"),
        }

    if row.action == "merge_cluster_summary":
        ctx["merges"] = [
            {
                "source": m.get("source_name"),
                "target": m.get("target_name"),
                "reasoning": (m.get("reasoning") or "")[:200],
            }
            for m in (after.get("merges") or [])[:8]
            if isinstance(m, dict)
        ]
        ctx["reclassifies"] = [
            {
                "source": r.get("source_name"),
                "source_type": r.get("source_type"),
                "target": r.get("target_name"),
                "target_type": r.get("target_type"),
                "reasoning": (r.get("reasoning") or "")[:200],
            }
            for r in (after.get("reclassifies") or [])[:8]
            if isinstance(r, dict)
        ]
    else:
        for key in (
            "kind",
            "proposed_name",
            "bad_alias",
            "matches_entity_name",
            "proposed_vendor_name",
            "current_id",
            "proposed_id",
            "vuln_status",
            "article_count",
            "age_days",
        ):
            if after.get(key) is not None:
                ctx[key] = after[key]
    return ctx


# --------------------------------------------------------------------------- batch


@celery_app.task(
    name="app.workers.hygiene_review_tasks.review_hygiene_proposal_batch",
    bind=True,
    soft_time_limit=420,
    time_limit=480,
    autoretry_for=(TimeoutError,),
    max_retries=2,
)
def review_hygiene_proposal_batch(self, items: list[dict]) -> dict:
    """Judge one batch of proposals. Runs on the ai queue."""
    start = time.monotonic()
    try:
        stats = run_async(_review_batch_async(items))
        status = stats.get("status", "unknown")
        if status == "provider_paused":
            pause_until_str = stats.get("pause_until")
            countdown = 3600
            if pause_until_str:
                try:
                    pause_until = datetime.fromisoformat(pause_until_str)
                    countdown = max(60, min(3600, int((pause_until - datetime.now(UTC)).total_seconds()) + 30))
                except ValueError:
                    pass
            CELERY_TASKS_TOTAL.labels(task_name="review_hygiene_proposal_batch", status="provider_paused").inc()
            raise self.retry(countdown=countdown, max_retries=24)
        CELERY_TASKS_TOTAL.labels(
            task_name="review_hygiene_proposal_batch",
            status="success" if status == "reviewed" else "error",
        ).inc()
        return stats
    except self.MaxRetriesExceededError:
        CELERY_TASKS_TOTAL.labels(task_name="review_hygiene_proposal_batch", status="error").inc()
        raise
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="review_hygiene_proposal_batch", status="error").inc()
        logger.exception("review_hygiene_proposal_batch failed for %d proposals", len(items))
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="review_hygiene_proposal_batch").observe(time.monotonic() - start)


def _render_proposals_block(items: list[dict]) -> str:
    lines = []
    for item in items:
        lines.append(
            f"- proposal_id={item['proposal_id']}  kind={item['kind']}\n"
            f"  proposal: {item.get('summary') or '(no summary)'}\n"
            f"  proposer's reasoning: {item.get('reason') or '(none)'}\n"
            f"  context: {json.dumps(item.get('context') or {}, separators=(',', ':'), default=str)}"
        )
    return "\n".join(lines)


async def _review_batch_async(items: list[dict]) -> dict:
    from app.ai.providers.claude_code_provider import QuotaExhaustedError

    if not items:
        return {"status": "reviewed", "reviewed": 0}

    async with worker_session() as db:
        from app.services.system_settings import _ensure_cache, invalidate_cache

        invalidate_cache()
        await _ensure_cache(db)

        system_user = await _resolve_system_user(db)
        if not system_user:
            return {"status": "no_admin_user"}

        variables = {
            "proposal_count": len(items),
            "proposals_block": _render_proposals_block(items),
        }
        try:
            result = await run_task(
                db=db,
                user_id=system_user.id,
                task_name="hygiene_proposal_review",
                variables=variables,
                target_type="hygiene_review_batch",
                target_id=uuid.uuid4(),
                force=True,
            )
        except QuotaExhaustedError as e:
            pause_until = getattr(e, "reset_at", None) or getattr(e, "pause_until", None)
            return {
                "status": "provider_paused",
                "pause_until": pause_until.isoformat() if pause_until else None,
            }

        if not result:
            return {"status": "no_assignment"}
        if result.get("_extraction_status") == "provider_paused":
            return {"status": "provider_paused", "pause_until": result.get("_pause_until")}
        if result.get("_extraction_status") not in (None, "success"):
            logger.warning(
                "hygiene review batch: AI returned status=%r; no verdicts written",
                result.get("_extraction_status"),
            )
            return {"status": "ai_no_success", "ai_status": result.get("_extraction_status")}

        reviews = result.get("reviews")
        if not isinstance(reviews, list):
            return {"status": "ai_bad_shape"}

        input_ids = {item["proposal_id"] for item in items}
        now = datetime.now(UTC)
        written = 0
        unknown = 0
        for review in reviews:
            if not isinstance(review, dict):
                continue
            pid = str(review.get("proposal_id") or "")
            decision = review.get("decision")
            if pid not in input_ids or decision not in VALID_DECISIONS:
                unknown += 1
                continue
            row = await _fetch_proposal_row(db, pid)
            if row is None:
                continue
            row.review_decision = decision
            row.review_reason = (review.get("reason") or "")[:500] or None
            row.reviewed_at = now
            written += 1
        await db.commit()

        auto_applied: dict | None = None
        if settings.get("hygiene_review_auto_apply"):
            # Full-automation mode: apply everything approved. We deliberately
            # DO NOT delete rejected rows here (dismiss_rejected=False) — a wrong
            # AI rejection would otherwise silently erase a valid proposal with
            # no audit trail. Rejected rows stay in the feed (excluded from the
            # bulk-apply buttons and their counts) until a human explicitly
            # clears them via "Apply + clear rejected". The sweep covers all
            # reviewed-pending rows, not just this batch — idempotent, and
            # claude_code runs batches serially anyway.
            from app.api.hygiene import apply_ai_reviewed_proposals

            try:
                auto_applied = await apply_ai_reviewed_proposals(db, system_user, dismiss_rejected=False)
                await db.commit()
            except Exception:
                logger.exception("hygiene review auto-apply sweep failed")
                await db.rollback()

        stats = {
            "status": "reviewed",
            "batch_size": len(items),
            "reviewed": written,
            "unknown_ids": unknown,
        }
        if auto_applied is not None:
            stats["auto_applied"] = auto_applied
        return stats


async def _fetch_proposal_row(
    db: AsyncSession, proposal_id: str
) -> EntityLinkValidationLog | EntityMaintenanceLog | None:
    source, _, raw_id = proposal_id.partition(":")
    try:
        row_id = uuid.UUID(raw_id)
    except ValueError:
        return None
    if source == "link_validator":
        return (
            await db.execute(select(EntityLinkValidationLog).where(EntityLinkValidationLog.id == row_id))
        ).scalar_one_or_none()
    if source == "entity_maintenance":
        return (
            await db.execute(select(EntityMaintenanceLog).where(EntityMaintenanceLog.id == row_id))
        ).scalar_one_or_none()
    return None
