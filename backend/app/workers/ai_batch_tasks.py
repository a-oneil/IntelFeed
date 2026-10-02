"""One-pass entry_analysis batch orchestration (engine phase 4).

submit_analysis_batches (hourly beat):
  self-heal missed enqueues → budget check → priority-ordered pending slice →
  Anthropic Message Batches submission (50% discount) or per-entry sequential
  fallback when the provider can't use Batches (OAuth token / disabled).

poll_analysis_batches (10-min beat):
  ingest ended batches via ai.engine.store_external_result + the
  store_entry_analysis fan-out. Idempotent: jobs are claimed by flipping
  status to 'ingesting' before streaming results.
"""

import logging
import time
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select, update

from app.core.metrics import CELERY_TASK_DURATION_SECONDS, CELERY_TASKS_TOTAL
from app.workers.celery_app import celery_app
from app.workers.db import run_async, worker_session

logger = logging.getLogger(__name__)

TASK_NAME = "entry_analysis"
# Rough per-request cost guess used only for budget clamping (Haiku, batch rate)
EST_COST_PER_REQUEST = 0.0024  # fallback for ai_est_cost_per_request


def _get_worker_session():
    return worker_session()


async def _system_user_id(db) -> uuid.UUID | None:
    from app.services.system_user import get_system_user_id

    return await get_system_user_id(db)


async def _spent_today(db, task_id: uuid.UUID) -> float:
    from app.models.ai_result import AIResult

    day_start = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    spent = (
        await db.execute(
            select(func.coalesce(func.sum(AIResult.cost_estimate), 0)).where(
                AIResult.task_id == task_id, AIResult.created_at >= day_start
            )
        )
    ).scalar_one()
    return float(spent)


def _provider_supports_batches(provider_model, api_key: str | None, use_batches: bool) -> bool:
    if not use_batches:
        return False
    if provider_model.provider_type != "claude":
        return False
    if (provider_model.config or {}).get("batches_unsupported"):
        return False
    if api_key and api_key.startswith("sk-ant-oat"):
        return False  # OAuth subscription tokens can't use /v1/messages/batches
    return True


async def _prepare_request(db, task, user_id, entry) -> tuple[str | None, str]:
    """(rendered_system, rendered_user) for one entry."""
    from app.ai.engine import get_active_prompt, render_prompt
    from app.services.entry_analysis import build_analysis_variables

    system_template, user_template = await get_active_prompt(db, task.id)
    entry_vars = await build_analysis_variables(db, entry)
    rendered_system = render_prompt(system_template, entry_vars) if system_template else None
    rendered_user = render_prompt(user_template, entry_vars)
    return rendered_system, rendered_user


@celery_app.task(
    name="app.workers.ai_batch_tasks.submit_analysis_batches",
    soft_time_limit=600,
    time_limit=660,
)
def submit_analysis_batches():
    start = time.monotonic()
    try:
        stats = run_async(_submit_analysis_batches())
        if stats:
            logger.info("Analysis batch submit: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="submit_analysis_batches", status="success").inc()
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="submit_analysis_batches", status="error").inc()
        logger.exception("Analysis batch submission failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="submit_analysis_batches").observe(time.monotonic() - start)


async def _submit_analysis_batches() -> dict | None:
    from app.ai.engine import get_task_assignment
    from app.models.ai_analysis import AIAnalysisRequest
    from app.models.entry import Entry
    from app.services.entry_analysis import enqueue_entry_analysis
    from app.services.system_settings import get_setting

    async with _get_worker_session() as db:
        if not bool(await get_setting("ai_one_pass_enabled", db)):
            return None
        user_id = await _system_user_id(db)
        if user_id is None:
            return None
        assignment_row = await get_task_assignment(db, user_id, TASK_NAME)
        if assignment_row is None:
            logger.warning("entry_analysis has no enabled assignment — skipping batch submit")
            return None
        assignment, task, provider_model = assignment_row

        # Self-healing sweep: entries whose score task failed before enqueueing
        stale_cutoff = datetime.now(UTC) - timedelta(hours=2)
        missed = (
            (
                await db.execute(
                    select(Entry.id)
                    .outerjoin(AIAnalysisRequest, AIAnalysisRequest.entry_id == Entry.id)
                    .where(
                        AIAnalysisRequest.id.is_(None),
                        Entry.fetched_at < stale_cutoff,
                        Entry.fetched_at >= datetime.now(UTC) - timedelta(days=3),
                        Entry.scored_at.isnot(None),
                    )
                    .limit(200)
                )
            )
            .scalars()
            .all()
        )
        for eid in missed:
            await enqueue_entry_analysis(db, eid)

        # Budget clamp (backstop, not a gate — pending rows simply wait)
        budget = float(await get_setting("ai_daily_budget_usd", db) or 2.0)
        spent = await _spent_today(db, task.id)
        remaining = max(0.0, budget - spent)
        max_batch = int(await get_setting("ai_batch_max_requests", db) or 500)
        est_cost = float(await get_setting("ai_est_cost_per_request", db) or EST_COST_PER_REQUEST)
        max_requests = min(int(remaining / est_cost), max_batch) if est_cost > 0 else max_batch
        if max_requests <= 0:
            await db.commit()
            return {"submitted": 0, "reason": "budget_exhausted", "spent_today": spent}

        # Priority-ordered pending slice (score read at submit time so late
        # KEV/EPSS signals reorder the queue for free). Eager-load the feed so
        # _prepare_request can read entry.feed.title without triggering a lazy
        # load outside the async greenlet (MissingGreenlet).
        from sqlalchemy.orm import selectinload

        pending = (
            await db.execute(
                select(AIAnalysisRequest, Entry)
                .join(Entry, Entry.id == AIAnalysisRequest.entry_id)
                .options(selectinload(Entry.feed))
                .where(AIAnalysisRequest.status == "pending")
                .order_by(Entry.priority_score.desc().nullslast(), AIAnalysisRequest.created_at.asc())
                .limit(max_requests)
            )
        ).all()
        if not pending:
            await db.commit()
            return {"submitted": 0, "swept": len(missed)}

        from app.core.encryption import decrypt_value

        api_key = None
        if provider_model.api_key_encrypted:
            try:
                api_key = decrypt_value(provider_model.api_key_encrypted)
            except Exception:
                logger.warning("Failed to decrypt provider API key for batch submit")

        use_batches = bool(await get_setting("ai_use_batches", db))
        if _provider_supports_batches(provider_model, api_key, use_batches):
            submitted = await _submit_via_batches_api(db, task, assignment, provider_model, user_id, pending)
            await db.commit()
            return {"submitted": submitted, "mode": "batches", "swept": len(missed)}

        # Sequential fallback: per-entry run_task calls (prompt caching on the
        # shared system block recovers most of the batch discount)
        for request_row, _entry in pending:
            run_entry_analysis_task.delay(str(request_row.entry_id))
            request_row.status = "submitted"
            request_row.submitted_at = datetime.now(UTC)
            db.add(request_row)
        await db.commit()
        return {"submitted": len(pending), "mode": "sequential", "swept": len(missed)}


async def _submit_via_batches_api(db, task, assignment, provider_model, user_id, pending) -> int:
    from anthropic.types.message_create_params import MessageCreateParamsNonStreaming
    from anthropic.types.messages.batch_create_params import Request

    from app.ai.engine import _get_provider_instance
    from app.models.ai_analysis import AIBatchJob

    provider = _get_provider_instance(provider_model, extra_config=assignment.config)
    client = provider._build_client()
    output_config = provider._build_output_config(task.effective_output_schema)
    merged_config = {**(provider_model.config or {}), **(assignment.config or {})}
    # Fallback matches run_task's default (engine.py) — at 2048 the payload's
    # trailing link_validations/relationships keys get truncated off.
    max_tokens = int(merged_config.get("max_tokens", 4096))

    requests = []
    for request_row, entry in pending:
        rendered_system, rendered_user = await _prepare_request(db, task, user_id, entry)
        params: dict = {
            "model": assignment.model_name,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": rendered_user}],
        }
        if rendered_system:
            params["system"] = [{"type": "text", "text": rendered_system, "cache_control": {"type": "ephemeral"}}]
        if output_config:
            params["output_config"] = output_config
        requests.append(
            Request(custom_id=f"ea-{request_row.entry_id}", params=MessageCreateParamsNonStreaming(**params))
        )

    try:
        batch = await client.messages.batches.create(requests=requests)
    except Exception as e:
        status_code = getattr(e, "status_code", None)
        if status_code is not None and 400 <= int(status_code) < 500:
            # Provider can't do batches (e.g. OAuth) — mark it and fall back next run
            config = dict(provider_model.config or {})
            config["batches_unsupported"] = True
            provider_model.config = config
            db.add(provider_model)
            logger.warning("Batches API rejected (%s) — provider marked batches_unsupported", status_code)
            return 0
        raise

    now = datetime.now(UTC)
    for request_row, _entry in pending:
        request_row.status = "submitted"
        request_row.batch_id = batch.id
        request_row.submitted_at = now
        db.add(request_row)
    db.add(
        AIBatchJob(
            provider_batch_id=batch.id,
            provider_id=provider_model.id,
            status="in_progress",
            request_count=len(pending),
        )
    )
    return len(pending)


@celery_app.task(
    name="app.workers.ai_batch_tasks.poll_analysis_batches",
    soft_time_limit=540,
    time_limit=600,
)
def poll_analysis_batches():
    start = time.monotonic()
    try:
        stats = run_async(_poll_analysis_batches())
        if stats:
            logger.info("Analysis batch poll: %s", stats)
        CELERY_TASKS_TOTAL.labels(task_name="poll_analysis_batches", status="success").inc()
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="poll_analysis_batches", status="error").inc()
        logger.exception("Analysis batch polling failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="poll_analysis_batches").observe(time.monotonic() - start)


async def _poll_analysis_batches() -> dict | None:
    from app.ai.engine import _get_provider_instance, get_task_assignment
    from app.models.ai_analysis import AIBatchJob

    async with _get_worker_session() as db:
        jobs = (await db.execute(select(AIBatchJob).where(AIBatchJob.status == "in_progress"))).scalars().all()
        if not jobs:
            return None
        user_id = await _system_user_id(db)
        assignment_row = await get_task_assignment(db, user_id, TASK_NAME) if user_id else None
        if assignment_row is None:
            return None
        assignment, task, provider_model = assignment_row
        provider = _get_provider_instance(provider_model, extra_config=assignment.config)
        client = provider._build_client()

        stats = {"ended": 0, "succeeded": 0, "errored": 0, "expired": 0}
        for job in jobs:
            try:
                remote = await client.messages.batches.retrieve(job.provider_batch_id)
            except Exception:
                logger.warning("Failed to retrieve batch %s", job.provider_batch_id, exc_info=True)
                continue
            if remote.processing_status != "ended":
                continue

            # Claim: idempotency guard against overlapping poll runs
            claimed = await db.execute(
                update(AIBatchJob)
                .where(AIBatchJob.id == job.id, AIBatchJob.status == "in_progress")
                .values(status="ingesting")
            )
            if not claimed.rowcount:
                continue
            await db.commit()

            counts = await _ingest_batch_results(db, client, job, task, provider_model)
            for k in ("succeeded", "errored", "expired"):
                stats[k] += counts[k]
            stats["ended"] += 1
        return stats


async def _ingest_batch_results(db, client, job, task, provider_model) -> dict:
    from app.ai.engine import store_external_result
    from app.models.ai_analysis import AIAnalysisRequest, AIBatchJob
    from app.services.entry_analysis import store_entry_analysis

    counts = {"succeeded": 0, "errored": 0, "expired": 0}
    now = datetime.now(UTC)
    any_links = False

    results = await client.messages.batches.results(job.provider_batch_id)
    async for item in results:
        entry_id_str = item.custom_id.removeprefix("ea-")
        try:
            entry_id = uuid.UUID(entry_id_str)
        except ValueError:
            continue
        request_row = (
            await db.execute(select(AIAnalysisRequest).where(AIAnalysisRequest.entry_id == entry_id))
        ).scalar_one_or_none()

        kind = item.result.type
        if kind == "succeeded":
            message = item.result.message
            content = "".join(block.text for block in message.content if getattr(block, "text", None))
            parsed = await store_external_result(
                db,
                task=task,
                provider_model=provider_model,
                entry_id=entry_id,
                content=content,
                tokens_input=message.usage.input_tokens,
                tokens_output=message.usage.output_tokens,
                model_name=message.model,
                batch=True,
            )
            if isinstance(parsed, dict) and parsed.get("_extraction_status") == "success":
                stored = await store_entry_analysis(db, entry_id, parsed)
                any_links = any_links or bool(stored)
            if request_row:
                request_row.status = "completed"
                request_row.completed_at = now
                db.add(request_row)
            counts["succeeded"] += 1
        elif kind == "errored":
            err = str(getattr(item.result, "error", ""))[:2000]
            if request_row:
                transient = "invalid_request" not in err
                request_row.attempts += 1
                if transient and request_row.attempts < 3:
                    request_row.status = "pending"
                    request_row.batch_id = None
                else:
                    request_row.status = "failed"
                request_row.error = err
                db.add(request_row)
            counts["errored"] += 1
        elif kind == "expired":
            if request_row:
                request_row.status = "pending"
                request_row.batch_id = None
                db.add(request_row)
            counts["expired"] += 1
        await db.commit()

    await db.execute(
        update(AIBatchJob)
        .where(AIBatchJob.id == job.id)
        .values(
            status="ended",
            succeeded=counts["succeeded"],
            errored=counts["errored"],
            expired=counts["expired"],
            ended_at=now,
        )
    )
    await db.commit()

    if any_links:
        try:
            from app.workers.intel_feed_tasks import sync_entity_search_indexes

            sync_entity_search_indexes.apply_async(countdown=30)
        except Exception:
            logger.debug("Failed to dispatch entity index sync after batch ingest", exc_info=True)
    return counts


@celery_app.task(
    name="app.workers.ai_batch_tasks.run_entry_analysis_task",
    bind=True,
    max_retries=2,
    # Long research write-ups now reach the model with their indicator
    # appendix and a 16k-token output budget; the provider timeout is 900 s,
    # so the worker limit must not cut the run first.
    soft_time_limit=900,
    time_limit=960,
)
def run_entry_analysis_task(self, entry_id: str, force: bool = False):
    """Sequential fallback: one run_task call per entry (no Batches API).

    ``force`` re-runs an entry that already has a current analysis (the
    engine's dedup guard otherwise returns the stored result untouched) —
    the re-analysis of articles whose earlier run never saw their IOC
    section goes through here.
    """
    start = time.monotonic()
    try:
        run_async(_run_entry_analysis(entry_id, force=force))
        CELERY_TASKS_TOTAL.labels(task_name="run_entry_analysis_task", status="success").inc()
    except Exception as exc:
        CELERY_TASKS_TOTAL.labels(task_name="run_entry_analysis_task", status="retry").inc()
        raise self.retry(exc=exc, countdown=min(300, 30 * (self.request.retries + 1)))
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="run_entry_analysis_task").observe(time.monotonic() - start)


async def _run_entry_analysis(entry_id_str: str, force: bool = False):
    from app.ai.engine import run_task
    from app.models.ai_analysis import AIAnalysisRequest
    from app.models.entry import Entry
    from app.services.entry_analysis import build_analysis_variables, store_entry_analysis

    entry_id = uuid.UUID(entry_id_str)
    async with _get_worker_session() as db:
        user_id = await _system_user_id(db)
        entry = await db.get(Entry, entry_id)
        if entry is None or user_id is None:
            return

        result = await run_task(
            db=db,
            user_id=user_id,
            task_name=TASK_NAME,
            variables=await build_analysis_variables(db, entry),
            entry_id=entry_id,
            target_type="entry",
            target_id=entry_id,
            force=force,
        )
        request_row = (
            await db.execute(select(AIAnalysisRequest).where(AIAnalysisRequest.entry_id == entry_id))
        ).scalar_one_or_none()
        now = datetime.now(UTC)
        if isinstance(result, dict) and result.get("_extraction_status") == "success":
            await store_entry_analysis(db, entry_id, result)
            if request_row:
                request_row.status = "completed"
                request_row.completed_at = now
                db.add(request_row)
        elif request_row:
            request_row.attempts += 1
            request_row.status = "failed" if request_row.attempts >= 3 else "pending"
            request_row.error = (result or {}).get("_error") if isinstance(result, dict) else None
            db.add(request_row)
        await db.commit()
