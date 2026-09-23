"""Scheduled AI-driven entity-link validator (recheck/backfill).

Re-judges autolinker entity↔entry links and removes obvious false-positives.
Ingest-time judgment now happens inside the one-pass ``entry_analysis`` call
(services/entry_analysis.py); this job covers what that misses: the historical
backlog, entries that never got an AI pass, links added after analysis, and
periodic rechecks. It skips entries with a fresh ``last_link_validation_at``.

The ``entity_link_validation`` task is pure prompt→JSON — no tool calling — so
it runs on whatever provider its assignment points at (Anthropic API, Ollama,
or the Claude Code CLI). With a non-CLI provider set
``link_validation_batch_size = 1``: batching exists only to amortize CLI
subprocess startup, and the per-entry path is the standard ``run_task`` route.

Two Celery tasks:

  validate_entity_links         — beat-scheduled kickoff. Picks the next batch
                                  of entries, runs a canary, fans out per-entry
                                  sub-tasks to the `ai` queue.

  validate_single_entry_links   — per-entry: fetches all 5 dictionary junction
                                  rows (source = 'auto_link'), slices article
                                  text by paragraph_indices, calls Claude via
                                  run_task, validates response, applies
                                  decisions (or shadow-logs in shadow mode).

Runs on the dedicated `celery-worker-ai` service (--concurrency=1).
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

import redis
from sqlalchemy import and_, exists, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.engine import (
    _get_provider_instance,
    get_active_prompt,
    get_task_assignment,
    render_prompt,
    run_task,
)
from app.ai.providers.base import AIResponse
from app.ai.providers.claude_code_provider import QuotaExhaustedError
from app.config import settings
from app.core.metrics import (
    AI_REQUEST_DURATION_SECONDS,
    AI_REQUESTS_TOTAL,
    CELERY_TASK_DURATION_SECONDS,
    CELERY_TASKS_TOTAL,
)
from app.intelligence.autolinker import split_into_paragraphs
from app.intelligence.link_validation_apply import (
    ENTITY_TYPES,
    JUNCTION_SPECS,
    LinkRow,
)
from app.intelligence.link_validation_apply import (
    apply_removal as _apply_removal,
)
from app.intelligence.link_validation_apply import (
    fetch_auto_links as _fetch_auto_links,
)
from app.intelligence.link_validation_apply import (
    log_reclassification as _log_reclassification,
)
from app.intelligence.link_validation_apply import (
    log_shadow_removal as _log_shadow_removal,
)
from app.models.ai_provider import AIProvider as AIProviderModel
from app.models.ai_result import AIResult
from app.models.entity_link_validation_log import EntityLinkValidationLog
from app.models.entry import Entry
from app.models.feed import Feed
from app.workers.celery_app import celery_app
from app.workers.db import run_async, worker_session

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- kickoff


@celery_app.task(
    name="app.workers.link_validation_tasks.validate_entity_links",
    soft_time_limit=600,
    time_limit=660,
)
def validate_entity_links() -> dict:
    """Kickoff: select N oldest-validated entries, canary 3 inline, fan out the rest."""
    start = time.monotonic()
    try:
        stats = run_async(_kickoff_async())
        CELERY_TASKS_TOTAL.labels(task_name="validate_entity_links", status="success").inc()
        logger.info("validate_entity_links kickoff: %s", stats)
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="validate_entity_links", status="error").inc()
        logger.exception("validate_entity_links kickoff failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="validate_entity_links").observe(time.monotonic() - start)


async def _kickoff_async() -> dict:
    """Select candidate entries; run canary inline; enqueue the rest in batches."""
    entries_per_run = int(settings.get("link_validation_entries_per_run") or 200)
    recheck_days = int(settings.get("link_validation_recheck_days") or 30)
    canary_count = int(settings.get("link_validation_kickoff_canary_count") or 3)
    batch_size = max(1, int(settings.get("link_validation_batch_size") or 10))

    async with worker_session() as db:
        system_user_id = await _resolve_system_user(db)
        if not system_user_id:
            logger.warning("validate_entity_links: no admin user found; skipping run")
            return {"enqueued": 0, "skipped": "no_admin_user"}

        entry_ids = await _select_candidate_entries(db, entries_per_run, recheck_days)
        if not entry_ids:
            return {"enqueued": 0, "reason": "no_pending_entries"}

    # Run the canary entries inline (synchronously) to catch systemic failures.
    # Canaries stay single-entry on purpose: they're meant to detect auth / CLI /
    # prompt regressions independent of the batching wrapper.
    canary_ids = entry_ids[:canary_count]
    rest = entry_ids[canary_count:]
    failures = 0
    successes = 0
    for entry_id in canary_ids:
        try:
            result = await _validate_single_entry_async(entry_id)
            if result.get("status") in {"validated", "shadow_validated", "no_links"}:
                successes += 1
            else:
                failures += 1
                logger.warning("Canary entry %s returned non-success: %s", entry_id, result)
        except Exception as e:
            failures += 1
            logger.exception("Canary entry %s raised: %s", entry_id, e)

    if failures >= max(2, (canary_count // 2) + 1):
        logger.error(
            "validate_entity_links canary failed (%s/%s); aborting batch of %s remaining",
            failures,
            canary_count,
            len(rest),
        )
        return {
            "enqueued": 0,
            "canary_successes": successes,
            "canary_failures": failures,
            "skipped": "canary_failed",
            "remaining_unsent": len(rest),
        }

    # Fan out the rest in chunks. batch_size=1 preserves the legacy single-entry
    # path (one Celery task per entry); >1 dispatches batched tasks that amortize
    # CLI startup overhead across N entries per call.
    batches = 0
    if batch_size <= 1:
        for entry_id in rest:
            validate_single_entry_links.apply_async(args=[str(entry_id)], queue="ai")
        batches = len(rest)
    else:
        for chunk in _chunked(list(rest), batch_size):
            validate_batch_entry_links.apply_async(args=[[str(e) for e in chunk]], queue="ai")
            batches += 1

    return {
        "canary_successes": successes,
        "canary_failures": failures,
        "enqueued": len(rest),
        "batches": batches,
        "batch_size": batch_size,
        "total_candidates": len(entry_ids),
    }


async def _resolve_system_user(db: AsyncSession) -> uuid.UUID | None:
    from app.services.system_user import get_system_user_id

    return await get_system_user_id(db)


async def _select_candidate_entries(
    db: AsyncSession,
    limit: int,
    recheck_days: int,
) -> list[uuid.UUID]:
    """Return entry IDs that have at least one auto_link junction row and are due for validation."""
    # Clamp to [0, 36500] (≈100 years). Operators sometimes set absurd values
    # like 999999 to effectively disable rechecks — that overflows
    # `datetime - timedelta(days=N)` when the result lands before year 1.
    recheck_days = max(0, min(recheck_days, 36500))
    cutoff = datetime.now(UTC) - timedelta(days=recheck_days)

    # An entry qualifies if any of its junctions across 5 tables has source = 'auto_link'.
    exists_clauses = [
        exists().where(and_(jmodel.entry_id == Entry.id, jmodel.source == "auto_link"))
        for jmodel, _, _, _ in JUNCTION_SPECS
    ]

    stmt = (
        select(Entry.id)
        .where(
            or_(
                Entry.last_link_validation_at.is_(None),
                Entry.last_link_validation_at < cutoff,
            ),
            or_(*exists_clauses),
        )
        .order_by(
            Entry.last_link_validation_at.asc().nullsfirst(),
            Entry.created_at.desc(),
        )
        .limit(limit)
    )
    result = await db.execute(stmt)
    return list(result.scalars().all())


# --------------------------------------------------------------------------- per-entry


@celery_app.task(
    name="app.workers.link_validation_tasks.validate_single_entry_links",
    bind=True,
    soft_time_limit=240,
    time_limit=300,
    autoretry_for=(TimeoutError,),
    max_retries=2,
)
def validate_single_entry_links(self, entry_id: str) -> dict:
    """Per-entry validation. Runs on the ai queue (--concurrency=1)."""
    start = time.monotonic()
    try:
        stats = run_async(_validate_single_entry_async(uuid.UUID(entry_id)))
        status = stats.get("status", "unknown")
        # Provider auto-paused — reschedule for after the pause window lifts.
        # Cap countdown at 1h to keep retries observable; max_retries on Celery
        # bound for self.retry ensures we don't loop forever on a stuck provider.
        if status == "provider_paused":
            pause_until_str = stats.get("pause_until")
            countdown = 3600
            if pause_until_str:
                try:
                    pause_until = datetime.fromisoformat(pause_until_str)
                    delta = (pause_until - datetime.now(UTC)).total_seconds()
                    countdown = max(60, min(3600, int(delta) + 30))
                except ValueError:
                    pass
            logger.info(
                "validate_single_entry_links: provider paused, retrying entry %s in %ds",
                entry_id,
                countdown,
            )
            CELERY_TASKS_TOTAL.labels(
                task_name="validate_single_entry_links",
                status="provider_paused",
            ).inc()
            raise self.retry(countdown=countdown, max_retries=24)
        CELERY_TASKS_TOTAL.labels(
            task_name="validate_single_entry_links",
            status="success" if status in {"validated", "shadow_validated", "no_links", "locked"} else "error",
        ).inc()
        return stats
    except self.MaxRetriesExceededError:
        CELERY_TASKS_TOTAL.labels(task_name="validate_single_entry_links", status="error").inc()
        logger.exception("validate_single_entry_links exhausted retries for %s", entry_id)
        raise
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="validate_single_entry_links", status="error").inc()
        logger.exception("validate_single_entry_links failed for %s", entry_id)
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="validate_single_entry_links").observe(time.monotonic() - start)


@celery_app.task(
    name="app.workers.link_validation_tasks.enqueue_pending_link_validations",
    soft_time_limit=600,
    time_limit=660,
)
def enqueue_pending_link_validations(cap: int, recheck_days: int) -> dict:
    """Coordinator: select up to `cap` pending entries and fan out per-entry validation.

    Decouples the slow per-entry apply_async loop from the HTTP request so the
    admin endpoint returns immediately. Runs on the default queue; the per-entry
    tasks it dispatches go to the `ai` queue (concurrency=1).
    """
    start = time.monotonic()
    try:
        entry_ids = run_async(_select_pending_async(cap, recheck_days))
        batch_size = max(1, int(settings.get("link_validation_batch_size") or 10))
        batches = 0
        if batch_size <= 1:
            for eid in entry_ids:
                validate_single_entry_links.apply_async(args=[str(eid)], queue="ai")
            batches = len(entry_ids)
        else:
            for chunk in _chunked(list(entry_ids), batch_size):
                validate_batch_entry_links.apply_async(args=[[str(e) for e in chunk]], queue="ai")
                batches += 1
        logger.info(
            "enqueue_pending_link_validations: fanned out %d entries in %d batch(es) of up to %d",
            len(entry_ids),
            batches,
            batch_size,
        )
        CELERY_TASKS_TOTAL.labels(task_name="enqueue_pending_link_validations", status="success").inc()
        return {"enqueued": len(entry_ids), "batches": batches, "batch_size": batch_size}
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="enqueue_pending_link_validations", status="error").inc()
        logger.exception("enqueue_pending_link_validations failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="enqueue_pending_link_validations").observe(
            time.monotonic() - start
        )


async def _select_pending_async(cap: int, recheck_days: int) -> list[uuid.UUID]:
    async with worker_session() as db:
        return await _select_candidate_entries(db, cap, recheck_days)


async def _validate_single_entry_async(entry_id: uuid.UUID) -> dict:
    redis_client = redis.from_url(settings.redis_url, decode_responses=True)
    lock_key = f"link_validation:entry:{entry_id}"
    have_lock = redis_client.set(lock_key, "1", nx=True, ex=120)
    if not have_lock:
        return {"status": "locked", "entry_id": str(entry_id)}

    try:
        async with worker_session() as db:
            # Warm the system_settings cache so settings.get() reads DB overrides.
            # Workers don't share the API's in-process cache, so without this the
            # synchronous settings.get() falls back to env defaults.
            from app.services.system_settings import _ensure_cache, invalidate_cache

            invalidate_cache()
            await _ensure_cache(db)

            mode = (settings.get("link_validation_mode") or "shadow").lower()
            if mode not in {"shadow", "apply"}:
                logger.warning("Unknown link_validation_mode=%r; defaulting to shadow", mode)
                mode = "shadow"
            max_chars = int(settings.get("link_validation_content_max_chars") or 3000)
            breaker_pct = float(settings.get("link_validation_circuit_breaker_pct") or 0.4)
            skip_confidence = settings.get("link_validation_skip_confidence") or None

            entry = await _fetch_entry(db, entry_id)
            if not entry:
                return {"status": "missing_entry", "entry_id": str(entry_id)}

            feed_name = await _fetch_feed_name(db, entry.feed_id)
            links = await _fetch_auto_links(db, entry_id, skip_confidence=skip_confidence)
            if not links:
                entry.last_link_validation_at = datetime.now(UTC)
                await db.commit()
                return {"status": "no_links", "entry_id": str(entry_id)}

            system_user_id = await _resolve_system_user(db)
            if not system_user_id:
                return {"status": "no_admin_user", "entry_id": str(entry_id)}

            variables = _build_prompt_variables(entry, feed_name, links, max_chars)
            try:
                result = await run_task(
                    db=db,
                    user_id=system_user_id,
                    task_name="entity_link_validation",
                    variables=variables,
                    target_type="entry_validation",
                    target_id=entry.id,
                    force=True,
                )
            except Exception as e:
                logger.exception("run_task threw for entry %s: %s", entry_id, e)
                entry.last_link_validation_at = datetime.now(UTC)
                await db.commit()
                return {"status": "ai_error", "entry_id": str(entry_id), "error": str(e)}

            # Provider auto-paused (quota hit). Don't stamp last_link_validation_at —
            # we want this entry re-picked on the next kickoff once the pause lifts.
            # Surface the pause_until so the outer wrapper can self-retry with countdown.
            if result and result.get("_extraction_status") == "provider_paused":
                await db.commit()
                return {
                    "status": "provider_paused",
                    "entry_id": str(entry_id),
                    "pause_until": result.get("_pause_until"),
                }

            if not result or result.get("_extraction_status") != "success":
                logger.warning(
                    "validate %s: AI returned non-success status=%r; no removals applied",
                    entry_id,
                    (result or {}).get("_extraction_status"),
                )
                entry.last_link_validation_at = datetime.now(UTC)
                await db.commit()
                return {
                    "status": "ai_no_success",
                    "entry_id": str(entry_id),
                    "ai_status": (result or {}).get("_extraction_status"),
                }

            decisions = _validate_decisions(result, links)
            if decisions is None:
                logger.warning(
                    "validate %s: AI response shape was invalid; treating all as KEEP",
                    entry_id,
                )
                entry.last_link_validation_at = datetime.now(UTC)
                await db.commit()
                return {"status": "ai_bad_shape", "entry_id": str(entry_id)}

            removals = [d for d in decisions if d["decision"] == "REMOVE"]
            reclassifies = [d for d in decisions if d["decision"] == "RECLASSIFY"]
            keep_count = sum(1 for d in decisions if d["decision"] == "KEEP")
            removal_pct = (len(removals) / len(decisions)) if decisions else 0.0
            if removal_pct > breaker_pct:
                logger.warning(
                    "validate %s: circuit-breaker tripped (%.0f%% removal); proceeding but flagging",
                    entry_id,
                    removal_pct * 100,
                )

            # Resolve ai_result_id (engine ensures one current result per (target, task))
            ai_result_id = await _resolve_current_ai_result_id(db, entry.id)

            applied = 0
            shadowed = 0
            reclassified = 0
            for decision in removals:
                link = decision["link"]
                reason = decision["reason"]
                if mode == "apply":
                    ok = await _apply_removal(db, entry_id, link, reason, ai_result_id)
                    if ok:
                        applied += 1
                else:
                    await _log_shadow_removal(db, entry_id, link, reason, ai_result_id)
                    shadowed += 1

            # RECLASSIFY decisions never touch the junction in either mode —
            # they're informational, surfaced via the audit log for the operator
            # to action (move the entity to the suggested entity_type).
            for decision in reclassifies:
                await _log_reclassification(
                    db,
                    entry_id,
                    decision["link"],
                    decision["reason"],
                    decision["suggested_type"],
                    ai_result_id,
                )
                reclassified += 1

            entry.last_link_validation_at = datetime.now(UTC)
            await db.commit()

            return {
                "status": "validated" if mode == "apply" else "shadow_validated",
                "entry_id": str(entry_id),
                "mode": mode,
                "total_links": len(decisions),
                "kept": keep_count,
                "removed": applied,
                "shadow_removed": shadowed,
                "reclassified": reclassified,
                "circuit_breaker": removal_pct > breaker_pct,
            }
    finally:
        try:
            redis_client.delete(lock_key)
        except Exception:
            pass


# ------------------------------------------------------------- data assembly


async def _fetch_entry(db: AsyncSession, entry_id: uuid.UUID) -> Entry | None:
    result = await db.execute(select(Entry).where(Entry.id == entry_id))
    return result.scalar_one_or_none()


async def _fetch_feed_name(db: AsyncSession, feed_id: uuid.UUID) -> str | None:
    result = await db.execute(select(Feed.title).where(Feed.id == feed_id))
    return result.scalar_one_or_none()


# -------------------------------------------------------- paragraph slicing


def select_paragraphs_for_links(
    title: str,
    summary: str | None,
    content_text: str | None,
    paragraph_indices: list[int],
    max_chars: int,
) -> str:
    """Render only the paragraphs that contain entity matches, ±1 for context.

    Always includes paragraphs 0 (title) and 1 (summary) since they carry
    the article's topical framing. Inserts `[...]` between gaps to make
    discontinuity visible to the model.
    """
    paragraphs = split_into_paragraphs(title, summary or "", content_text or "")
    if not paragraphs:
        return ""
    total_paragraphs = len(paragraphs)
    max_index = total_paragraphs - 1

    # Always include title (0) and summary (1 if present)
    selected: set[int] = {0}
    if total_paragraphs > 1:
        selected.add(1)
    # Add matched paragraphs ± 1
    for idx in paragraph_indices:
        if 0 <= idx <= max_index:
            selected.add(idx)
            if idx - 1 >= 0:
                selected.add(idx - 1)
            if idx + 1 <= max_index:
                selected.add(idx + 1)

    ordered = sorted(selected)
    rendered_parts: list[str] = []
    last_idx: int | None = None
    for idx in ordered:
        if last_idx is not None and idx > last_idx + 1:
            rendered_parts.append("[...]")
        # Each paragraph is (index, text) tuple per autolinker.split_into_paragraphs
        rendered_parts.append(paragraphs[idx][1])
        last_idx = idx
    rendered = "\n\n".join(rendered_parts)

    # Hard cap. If over, truncate the longest *middle* paragraph first.
    if len(rendered) > max_chars:
        rendered = _truncate_rendered(rendered_parts, max_chars)
    return rendered


def _truncate_rendered(parts: list[str], max_chars: int) -> str:
    """Truncate paragraphs (longest first, except the first part) until under cap."""
    # Keep parts[0] intact (title); shrink others. Use bytes-of-string proxy = len().
    while True:
        joined = "\n\n".join(parts)
        if len(joined) <= max_chars:
            return joined
        # Find longest non-first non-marker part
        idx_to_trim = None
        max_len = 0
        for i in range(1, len(parts)):
            if parts[i] == "[...]":
                continue
            if len(parts[i]) > max_len:
                max_len = len(parts[i])
                idx_to_trim = i
        if idx_to_trim is None:
            # Nothing left to shrink; hard-truncate the whole thing.
            return joined[: max_chars - 1] + "…"
        # Shrink that paragraph by half.
        new_len = max(80, max_len // 2)
        new_part = parts[idx_to_trim][:new_len].rstrip() + " […]"
        # Forward-progress guard: if the "shrunk" part is the same length or
        # longer than what we had (happens when max_len is between ~82-90 chars,
        # since new_len floors at 80 and we append 5 chars of " […]"), no
        # iteration will ever shrink the total. Hard-truncate to avoid spinning.
        if len(new_part) >= len(parts[idx_to_trim]):
            return joined[: max_chars - 1] + "…"
        parts[idx_to_trim] = new_part


def _build_prompt_variables(
    entry: Entry,
    feed_name: str | None,
    links: list[LinkRow],
    max_chars: int,
) -> dict:
    para_idx_union: list[int] = sorted({i for link in links for i in link.paragraph_indices})
    rendered_paragraphs = select_paragraphs_for_links(
        title=entry.title or "",
        summary=entry.summary,
        content_text=entry.content_text,
        paragraph_indices=para_idx_union,
        max_chars=max_chars,
    )
    return {
        "entry_title": entry.title or "(no title)",
        "entry_feed_name": feed_name or "(unknown feed)",
        "entry_published_at": entry.published_at.isoformat() if entry.published_at else "",
        "entry_summary": entry.summary or "",
        "entry_language": entry.language or "",
        "entry_paragraphs": rendered_paragraphs,
        "linked_entities": [
            {
                "entity_key": link.entity_key,
                "entity_type": link.entity_type,
                "name": link.name,
                "matched_names": link.matched_names,
                "confidence": link.confidence or "",
                "previously_restored": link.previously_restored,
            }
            for link in links
        ],
    }


# ----------------------------------------------------- response validation


def _validate_decisions(result: dict, links: list[LinkRow]) -> list[dict[str, Any]] | None:
    """Cross-check Claude's response against the input link list.

    Returns a list of {decision, reason, link} dicts in input order, or None
    if the response shape is unusable (in which case caller treats as KEEP all).
    """
    validations = result.get("validations")
    if not isinstance(validations, list):
        return None

    valid_decisions = {"KEEP", "REMOVE", "RECLASSIFY"}
    valid_suggested_types = {"threat_actor", "malware", "vendor", "product", "country"}

    by_key: dict[str, dict] = {}
    for v in validations:
        if not isinstance(v, dict):
            continue
        key = v.get("entity_key")
        decision = v.get("decision")
        reason = v.get("reason", "")
        suggested_type = v.get("suggested_type")
        if not key or decision not in valid_decisions:
            continue
        # RECLASSIFY requires a suggested_type. Without one, downgrade to KEEP
        # (safe default — we don't know what type to suggest).
        if decision == "RECLASSIFY" and suggested_type not in valid_suggested_types:
            logger.warning(
                "AI returned RECLASSIFY for %s without valid suggested_type=%r; downgrading to KEEP",
                key,
                suggested_type,
            )
            decision = "KEEP"
            suggested_type = None
        if key in by_key:
            logger.warning("AI returned duplicate decision for %s; treating as bad shape", key)
            return None
        by_key[key] = {"decision": decision, "reason": reason, "suggested_type": suggested_type}

    # Allow missing keys (default to KEEP), but disallow extra/unknown keys.
    input_keys = {link.entity_key for link in links}
    extra = set(by_key.keys()) - input_keys
    if extra:
        logger.warning("AI returned %d unknown entity_keys: %s", len(extra), list(extra)[:5])
        return None

    decisions: list[dict] = []
    missing = 0
    for link in links:
        v = by_key.get(link.entity_key)
        if v is None:
            missing += 1
            decisions.append(
                {"decision": "KEEP", "reason": "(no decision returned)", "suggested_type": None, "link": link}
            )
        else:
            decisions.append(
                {
                    "decision": v["decision"],
                    "reason": v["reason"],
                    "suggested_type": v["suggested_type"],
                    "link": link,
                }
            )

    if missing:
        logger.info("AI omitted decisions for %d/%d links; defaulting them to KEEP", missing, len(links))
    return decisions


async def _resolve_current_ai_result_id(db: AsyncSession, entry_id: uuid.UUID) -> uuid.UUID | None:
    result = await db.execute(
        select(AIResult.id)
        .join(AIResult.task)
        .where(
            AIResult.target_type == "entry_validation",
            AIResult.target_id == entry_id,
            AIResult.is_current.is_(True),
        )
        .order_by(AIResult.created_at.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


# ------------------------------------------------------------------ restore


async def restore_from_log(db: AsyncSession, log_id: uuid.UUID) -> tuple[bool, str]:
    """Re-create a junction row from a previously-removed log entry.

    Returns (success, message). Only `removed` rows can be restored.
    """
    result = await db.execute(select(EntityLinkValidationLog).where(EntityLinkValidationLog.id == log_id))
    log_row = result.scalar_one_or_none()
    if log_row is None:
        return False, "log entry not found"
    if log_row.action != "removed":
        return False, f"cannot restore action={log_row.action}"
    spec = ENTITY_TYPES.get(log_row.entity_type)
    if spec is None:
        return False, f"unknown entity_type {log_row.entity_type}"
    jmodel, emodel, fk_attr = spec

    # Re-check entity still exists
    ent_result = await db.execute(select(emodel.id).where(emodel.id == log_row.entity_id))
    if ent_result.scalar_one_or_none() is None:
        return False, "entity no longer exists"

    # Check we don't re-insert a duplicate (composite PK)
    fk_col = getattr(jmodel, fk_attr)
    dup_result = await db.execute(
        select(jmodel).where(jmodel.entry_id == log_row.entry_id, fk_col == log_row.entity_id)
    )
    if dup_result.scalar_one_or_none() is not None:
        return False, "link already exists"

    junction_kwargs = {
        "entry_id": log_row.entry_id,
        fk_attr: log_row.entity_id,
        "confidence": log_row.original_confidence,
        "source": log_row.original_source or "auto_link",
        "matched_names": list(log_row.original_matched_names or []),
        "paragraph_indices": list(log_row.original_paragraph_indices or []),
    }
    if log_row.original_extracted_at is not None:
        junction_kwargs["extracted_at"] = log_row.original_extracted_at
    db.add(jmodel(**junction_kwargs))
    # Reverse the article_count decrement
    await db.execute(
        update(emodel).where(emodel.id == log_row.entity_id).values(article_count=emodel.article_count + 1)
    )
    # Record the restore as its own audit row
    db.add(
        EntityLinkValidationLog(
            entry_id=log_row.entry_id,
            entity_type=log_row.entity_type,
            entity_id=log_row.entity_id,
            entity_name_snapshot=log_row.entity_name_snapshot,
            action="restored",
            reason=f"restored from {log_row.id}",
            original_source=log_row.original_source,
            original_confidence=log_row.original_confidence,
            original_matched_names=log_row.original_matched_names,
            original_paragraph_indices=log_row.original_paragraph_indices,
            original_extracted_at=log_row.original_extracted_at,
            ai_result_id=log_row.ai_result_id,
        )
    )
    return True, "restored"


# --------------------------------------------------------------------------- batched validation
#
# Validates N entries in one CLI call. Each `claude -p` invocation has 1-2s of
# bun/auth overhead, so batching amortizes that across N entries and gives a
# 10-20x throughput improvement at batch_size=10 — verified against prod data
# by scripts/dev/local_link_validator.py before being ported here.

# Per-model + per-batch-size timeout floors. Mirrors local_link_validator.py:
# the single-entry MODEL_TIMEOUTS scaled by `1 + 0.5 * (batch - 1)`, capped at
# 600s. Used as the per-call override sent to ClaudeCodeProvider.complete().
_BATCH_MODEL_TIMEOUTS: dict[str, float] = {
    "haiku": 90.0,
    "sonnet": 180.0,
    "opus": 300.0,
    "claude-haiku-4-5-20251001": 90.0,
    "claude-sonnet-4-6": 180.0,
    "claude-opus-4-6": 300.0,
}
_BATCH_TIMEOUT_DEFAULT = 180.0
_BATCH_TIMEOUT_CEILING = 600.0


def _batched_timeout(model: str, batch_size: int) -> float:
    """Compute the per-call CLI timeout for a batched validation request."""
    base = _BATCH_MODEL_TIMEOUTS.get(model, _BATCH_TIMEOUT_DEFAULT)
    if batch_size <= 1:
        return base
    return min(_BATCH_TIMEOUT_CEILING, base * (1.0 + 0.5 * (batch_size - 1)))


def build_batched_prompt(rendered_entries: list[tuple[uuid.UUID, str]]) -> str:
    """Wrap N rendered single-entry user prompts in a batching envelope.

    The per-entry template (loaded from ai_prompt_templates) tells Claude to
    output `{"validations": [...]}` for one entry. The wrapper here re-targets
    that to ONE combined `{"entries": [{"entry_id": ..., "validations": [...]}]}`
    output, keyed by the UUID in each `=== ENTRY <uuid> START ===` marker.
    """
    n = len(rendered_entries)
    envelope = (
        "# BATCHED VALIDATION REQUEST\n\n"
        f"Below are {n} independent entry-validation tasks. Each task's instructions "
        'describe outputting a JSON object like `{"validations": [...]}`.\n\n'
        "**Do NOT output that per-task. Instead, output ONE combined JSON object** "
        "with this exact shape:\n\n"
        "```json\n"
        '{"entries": [\n'
        '  {"entry_id": "<uuid-from-marker>", "validations": [...per task instructions...]},\n'
        '  {"entry_id": "<uuid-from-marker>", "validations": [...per task instructions...]}\n'
        "]}\n"
        "```\n\n"
        "Each task below is delimited by `=== ENTRY <uuid> START ===` and "
        "`=== ENTRY <uuid> END ===` markers. Use the UUID from the START marker "
        "as the `entry_id`. Follow each task's per-entity decision rules exactly — "
        f"only the outer wrapping is different. Include exactly one entries[] item "
        f"per input task ({n} total), in the same order as the inputs.\n\n"
        "---\n"
    )
    parts = [envelope]
    for entry_id, rendered in rendered_entries:
        parts.append(f"\n=== ENTRY {entry_id} START ===\n")
        parts.append(rendered)
        parts.append(f"\n=== ENTRY {entry_id} END ===\n")
    return "".join(parts)


def batched_schema(single_schema: dict | None) -> dict | None:
    """Wrap the per-entry validations JSON schema in `{entries: [{entry_id, validations}]}`.

    Returns None when the input schema doesn't expose a `validations` property —
    in that case the provider falls back to unstructured output and we parse
    JSON from response text.
    """
    if not single_schema or not isinstance(single_schema, dict):
        return None
    props = single_schema.get("properties") or {}
    validations_def = props.get("validations")
    if not validations_def:
        return None
    return {
        "type": "object",
        "properties": {
            "entries": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "entry_id": {"type": "string"},
                        "validations": validations_def,
                    },
                    "required": ["entry_id", "validations"],
                    "additionalProperties": False,
                },
            }
        },
        "required": ["entries"],
        "additionalProperties": False,
    }


def split_batched_response(
    parsed: dict | None,
    rendered_entries: list[tuple[uuid.UUID, str]],
) -> dict[str, list] | None:
    """Map a batched response back to per-entry validations[].

    Returns {entry_id_str: validations_list}. None if the shape is unusable.
    Tolerates the degenerate single-entry case where the model returned the
    un-batched `{"validations": [...]}` shape — common when batch_size=1.
    """
    if not isinstance(parsed, dict):
        return None
    entries = parsed.get("entries")
    if not isinstance(entries, list):
        # Single-entry fallback — the model may return the un-batched shape.
        if len(rendered_entries) == 1 and isinstance(parsed.get("validations"), list):
            return {str(rendered_entries[0][0]): parsed["validations"]}
        return None
    out: dict[str, list] = {}
    for item in entries:
        if not isinstance(item, dict):
            continue
        eid = item.get("entry_id")
        vals = item.get("validations")
        if eid and isinstance(vals, list):
            out[str(eid)] = vals
    return out


def _chunked(seq: list, n: int):
    for i in range(0, len(seq), n):
        yield seq[i : i + n]


@celery_app.task(
    name="app.workers.link_validation_tasks.validate_batch_entry_links",
    bind=True,
    # Worst-case: model=sonnet, batch=10 → 990s per-call timeout (capped at 600s
    # by _batched_timeout). 1200s soft / 1320s hard leaves room for DB ops and
    # AI result writes after the CLI returns. cli_retries=1 in provider config
    # could double the CLI wallclock if the first attempt times out — operators
    # using opus + large batches should keep batch_size ≤ 5 to stay under the
    # hard limit.
    soft_time_limit=1200,
    time_limit=1320,
    autoretry_for=(TimeoutError,),
    max_retries=2,
)
def validate_batch_entry_links(self, entry_ids: list[str]) -> dict:
    """Validate up to N entries in a single Claude call. Runs on the ai queue."""
    start = time.monotonic()
    try:
        stats = run_async(_validate_batch_async([uuid.UUID(e) for e in entry_ids]))
        status = stats.get("status", "unknown")
        # Whole-batch provider pause — re-queue with the same batch after the window lifts.
        if status == "provider_paused":
            pause_until_str = stats.get("pause_until")
            countdown = 3600
            if pause_until_str:
                try:
                    pause_until = datetime.fromisoformat(pause_until_str)
                    delta = (pause_until - datetime.now(UTC)).total_seconds()
                    countdown = max(60, min(3600, int(delta) + 30))
                except ValueError:
                    pass
            logger.info(
                "validate_batch_entry_links: provider paused, retrying batch of %d in %ds",
                len(entry_ids),
                countdown,
            )
            CELERY_TASKS_TOTAL.labels(
                task_name="validate_batch_entry_links",
                status="provider_paused",
            ).inc()
            raise self.retry(countdown=countdown, max_retries=24)
        CELERY_TASKS_TOTAL.labels(
            task_name="validate_batch_entry_links",
            status="success" if status in {"batch_done"} else "error",
        ).inc()
        return stats
    except self.MaxRetriesExceededError:
        CELERY_TASKS_TOTAL.labels(task_name="validate_batch_entry_links", status="error").inc()
        logger.exception("validate_batch_entry_links exhausted retries for %d entries", len(entry_ids))
        raise
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="validate_batch_entry_links", status="error").inc()
        logger.exception("validate_batch_entry_links failed for %d entries", len(entry_ids))
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="validate_batch_entry_links").observe(time.monotonic() - start)


async def _validate_batch_async(entry_ids: list[uuid.UUID]) -> dict:
    """Run one batched CLI call across N entries. See module docstring for layout."""
    if not entry_ids:
        return {"status": "batch_done", "results": {}}

    redis_client = redis.from_url(settings.redis_url, decode_responses=True)
    # Lock TTL must outlive the worst-case batch latency. _BATCH_TIMEOUT_CEILING
    # (600s) + DB ops + cli_retries on timeout → 1800s gives margin.
    lock_ttl_s = 1800
    locks: dict[uuid.UUID, str] = {}
    try:
        for eid in entry_ids:
            key = f"link_validation:entry:{eid}"
            if redis_client.set(key, "1", nx=True, ex=lock_ttl_s):
                locks[eid] = key

        if not locks:
            return {
                "status": "batch_done",
                "results": {str(e): {"status": "locked"} for e in entry_ids},
            }

        async with worker_session() as db:
            from app.services.system_settings import _ensure_cache, invalidate_cache

            invalidate_cache()
            await _ensure_cache(db)

            mode = (settings.get("link_validation_mode") or "shadow").lower()
            if mode not in {"shadow", "apply"}:
                logger.warning("Unknown link_validation_mode=%r; defaulting to shadow", mode)
                mode = "shadow"
            max_chars = int(settings.get("link_validation_content_max_chars") or 3000)
            breaker_pct = float(settings.get("link_validation_circuit_breaker_pct") or 0.4)
            skip_confidence = settings.get("link_validation_skip_confidence") or None

            system_user_id = await _resolve_system_user(db)
            if not system_user_id:
                return {
                    "status": "batch_done",
                    "results": {str(e): {"status": "no_admin_user"} for e in entry_ids},
                }

            # Phase 1: fetch bundles for every locked entry. Stamp + skip the
            # ones with no auto-links (free pass — no AI call needed).
            results: dict[str, dict] = {str(e): {"status": "locked"} for e in entry_ids if e not in locks}
            bundles: dict[uuid.UUID, tuple[Entry, str | None, list[LinkRow]]] = {}
            for eid in list(locks.keys()):
                entry = await _fetch_entry(db, eid)
                if not entry:
                    results[str(eid)] = {"status": "missing_entry"}
                    continue
                feed_name = await _fetch_feed_name(db, entry.feed_id)
                links = await _fetch_auto_links(db, eid, skip_confidence=skip_confidence)
                if not links:
                    entry.last_link_validation_at = datetime.now(UTC)
                    await db.commit()
                    results[str(eid)] = {"status": "no_links"}
                    continue
                bundles[eid] = (entry, feed_name, links)

            if not bundles:
                return {"status": "batch_done", "results": results}

            # Phase 2: resolve assignment + prompt + provider once for the batch.
            assignment_data = await get_task_assignment(db, system_user_id, "entity_link_validation")
            if not assignment_data:
                for eid in bundles:
                    results[str(eid)] = {"status": "no_assignment"}
                return {"status": "batch_done", "results": results}
            assignment, task, provider_model = assignment_data
            system_template, user_template = await get_active_prompt(db, task.id)
            single_schema = task.effective_output_schema

            # Phase 3: render per-entry user prompts; build batched envelope.
            rendered_entries: list[tuple[uuid.UUID, str]] = []
            per_entry_rendered_user: dict[uuid.UUID, str] = {}
            for eid, (entry, feed_name, links) in bundles.items():
                variables = _build_prompt_variables(entry, feed_name, links, max_chars)
                rendered_user = render_prompt(user_template, variables)
                per_entry_rendered_user[eid] = rendered_user
                rendered_entries.append((eid, rendered_user))

            # System prompt is entry-agnostic in practice. Render with the
            # first entry's variables to satisfy any {{entry_*}} references.
            first_eid = rendered_entries[0][0]
            first_entry, first_feed, first_links = bundles[first_eid]
            first_vars = _build_prompt_variables(first_entry, first_feed, first_links, max_chars)
            rendered_system = render_prompt(system_template, first_vars) if system_template else None

            batched_prompt = build_batched_prompt(rendered_entries)
            batched_sch = batched_schema(single_schema)

            # Phase 4: provider call. Provider applies its own MODEL_TIMEOUTS
            # default when timeout_seconds is unset; we override here based on
            # batch size to give the model proportionally more time.
            provider = _get_provider_instance(provider_model, extra_config=assignment.config)
            effective_timeout = _batched_timeout(assignment.model_name, len(rendered_entries))
            batch_run_id = str(uuid.uuid4())

            ai_start = time.monotonic()
            try:
                response: AIResponse = await provider.complete(
                    prompt=batched_prompt,
                    system=rendered_system,
                    response_format=batched_sch,
                    model=assignment.model_name,
                    timeout_seconds=effective_timeout,
                    heartbeat_label=f"link-validation batch of {len(rendered_entries)} entries",
                )
            except QuotaExhaustedError as e:
                pause_until = e.reset_at or (datetime.now(UTC) + timedelta(hours=1))
                await db.execute(
                    update(AIProviderModel)
                    .where(AIProviderModel.id == provider_model.id)
                    .values(paused_until=pause_until, paused_reason=str(e)[:500])
                )
                await db.commit()
                logger.warning(
                    "Provider %s auto-paused until %s after quota hit during batch of %d: %s",
                    provider_model.name,
                    pause_until.isoformat(),
                    len(rendered_entries),
                    str(e)[:200],
                )
                # Don't stamp last_link_validation_at — entries should be
                # re-picked once the pause window lifts. Surface to the wrapper
                # so it can self-retry with countdown.
                return {
                    "status": "provider_paused",
                    "pause_until": pause_until.isoformat(),
                    "batch_size": len(rendered_entries),
                }
            except Exception as e:
                # Any other CLI failure (subprocess error, auth, timeout after
                # cli_retries). Stamp every entry so we don't infinite-retry,
                # and write per-entry AIResult rows so the audit log records
                # the attempt.
                logger.exception(
                    "validate_batch_entry_links: provider call raised for batch of %d",
                    len(rendered_entries),
                )
                for eid in bundles:
                    entry = bundles[eid][0]
                    entry.last_link_validation_at = datetime.now(UTC)
                    db.add(
                        AIResult(
                            entry_id=eid,
                            target_type="entry_validation",
                            target_id=eid,
                            is_current=True,
                            task_id=task.id,
                            provider_id=provider_model.id,
                            model_name=assignment.model_name,
                            prompt_used=per_entry_rendered_user[eid],
                            raw_response=str(e),
                            parsed_result={
                                "_error": str(e),
                                "_extraction_status": "provider_error",
                                "_batch_run_id": batch_run_id,
                                "_batch_size": len(rendered_entries),
                            },
                            tokens_input=0,
                            tokens_output=0,
                            cost_estimate=Decimal("0"),
                        )
                    )
                    results[str(eid)] = {"status": "ai_error", "error": str(e)[:300]}
                await db.commit()
                return {"status": "batch_done", "results": results, "batch_run_id": batch_run_id}

            ai_duration = time.monotonic() - ai_start
            AI_REQUESTS_TOTAL.labels(provider=provider_model.provider_type, task="entity_link_validation").inc()
            AI_REQUEST_DURATION_SECONDS.labels(
                provider=provider_model.provider_type, task="entity_link_validation"
            ).observe(ai_duration)

            # Phase 5: parse + route response per entry.
            try:
                parsed_batch = json.loads(response.content)
            except json.JSONDecodeError:
                content = response.content.strip()
                if "```json" in content:
                    content = content.split("```json", 1)[1].split("```", 1)[0].strip()
                elif content.startswith("```"):
                    content = content.split("```", 1)[1].split("```", 1)[0].strip()
                try:
                    parsed_batch = json.loads(content)
                except json.JSONDecodeError:
                    parsed_batch = None

            per_entry = split_batched_response(parsed_batch, rendered_entries)
            # Even share of the wallclock — OAuth doesn't expose per-entry cost.
            per_entry_latency_ms = int((ai_duration * 1000) / max(1, len(rendered_entries)))

            # Phase 6: mark prior AIResults for these entries as not-current
            # (force=True semantics from engine.run_task).
            for eid in bundles:
                await db.execute(
                    update(AIResult)
                    .where(
                        AIResult.target_type == "entry_validation",
                        AIResult.target_id == eid,
                        AIResult.task_id == task.id,
                        AIResult.is_current == True,  # noqa: E712
                    )
                    .values(is_current=False)
                )

            # Phase 7: apply decisions per entry. Each entry gets its own
            # AIResult row tagged with the per-entry rendered prompt + per-entry
            # response slice so the audit log → AI result pivot still works.
            for eid, (entry, _feed_name, links) in bundles.items():
                eid_str = str(eid)
                vals = (per_entry or {}).get(eid_str)
                if vals is None:
                    # No slice for this entry → either bad batched shape or
                    # missing from the model's output. Stamp + record + move on.
                    entry.last_link_validation_at = datetime.now(UTC)
                    db.add(
                        AIResult(
                            entry_id=eid,
                            target_type="entry_validation",
                            target_id=eid,
                            is_current=True,
                            task_id=task.id,
                            provider_id=provider_model.id,
                            model_name=response.model or assignment.model_name,
                            prompt_used=per_entry_rendered_user[eid],
                            raw_response=response.content[:8000],
                            parsed_result={
                                "_extraction_status": "ai_bad_shape",
                                "_batch_run_id": batch_run_id,
                                "_batch_size": len(rendered_entries),
                            },
                            tokens_input=0,
                            tokens_output=0,
                            cost_estimate=Decimal("0"),
                            processing_time_ms=per_entry_latency_ms,
                        )
                    )
                    results[eid_str] = {"status": "ai_bad_shape"}
                    continue

                decisions = _validate_decisions({"validations": vals}, links)
                if decisions is None:
                    entry.last_link_validation_at = datetime.now(UTC)
                    db.add(
                        AIResult(
                            entry_id=eid,
                            target_type="entry_validation",
                            target_id=eid,
                            is_current=True,
                            task_id=task.id,
                            provider_id=provider_model.id,
                            model_name=response.model or assignment.model_name,
                            prompt_used=per_entry_rendered_user[eid],
                            raw_response=json.dumps({"validations": vals}, separators=(",", ":")),
                            parsed_result={
                                "_extraction_status": "ai_bad_shape",
                                "_batch_run_id": batch_run_id,
                                "_batch_size": len(rendered_entries),
                            },
                            tokens_input=0,
                            tokens_output=0,
                            cost_estimate=Decimal("0"),
                            processing_time_ms=per_entry_latency_ms,
                        )
                    )
                    results[eid_str] = {"status": "ai_bad_shape"}
                    continue

                removals = [d for d in decisions if d["decision"] == "REMOVE"]
                reclassifies = [d for d in decisions if d["decision"] == "RECLASSIFY"]
                keep_count = sum(1 for d in decisions if d["decision"] == "KEEP")
                removal_pct = (len(removals) / len(decisions)) if decisions else 0.0
                cb_tripped = removal_pct > breaker_pct
                if cb_tripped:
                    logger.warning(
                        "validate %s (batch): circuit-breaker tripped (%.0f%% removal)",
                        eid,
                        removal_pct * 100,
                    )

                # Write the per-entry AIResult BEFORE applying decisions so we
                # can attach ai_result_id to each log row.
                ai_result = AIResult(
                    entry_id=eid,
                    target_type="entry_validation",
                    target_id=eid,
                    is_current=True,
                    task_id=task.id,
                    provider_id=provider_model.id,
                    model_name=response.model or assignment.model_name,
                    prompt_used=per_entry_rendered_user[eid],
                    raw_response=json.dumps({"validations": vals}, separators=(",", ":")),
                    parsed_result={
                        "validations": vals,
                        "_extraction_status": "success",
                        "_batch_run_id": batch_run_id,
                        "_batch_size": len(rendered_entries),
                    },
                    tokens_input=0,
                    tokens_output=0,
                    cost_estimate=Decimal("0"),
                    processing_time_ms=per_entry_latency_ms,
                )
                db.add(ai_result)
                await db.flush()
                ai_result_id = ai_result.id

                applied = 0
                shadowed = 0
                reclassified = 0
                for d in removals:
                    if mode == "apply":
                        ok = await _apply_removal(db, eid, d["link"], d["reason"], ai_result_id)
                        if ok:
                            applied += 1
                    else:
                        await _log_shadow_removal(db, eid, d["link"], d["reason"], ai_result_id)
                        shadowed += 1
                for d in reclassifies:
                    await _log_reclassification(db, eid, d["link"], d["reason"], d["suggested_type"], ai_result_id)
                    reclassified += 1

                entry.last_link_validation_at = datetime.now(UTC)
                results[eid_str] = {
                    "status": "validated" if mode == "apply" else "shadow_validated",
                    "mode": mode,
                    "total_links": len(decisions),
                    "kept": keep_count,
                    "removed": applied,
                    "shadow_removed": shadowed,
                    "reclassified": reclassified,
                    "circuit_breaker": cb_tripped,
                }

            await db.commit()
            return {
                "status": "batch_done",
                "batch_run_id": batch_run_id,
                "batch_size": len(rendered_entries),
                "results": results,
            }
    finally:
        # Release every lock we acquired.
        for key in locks.values():
            try:
                redis_client.delete(key)
            except Exception:
                pass
