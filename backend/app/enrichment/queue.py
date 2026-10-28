"""Enrichment job queue — pending lookups, kept in ``enrichment_jobs``.

Triggers call ``enqueue``, which writes one row per applicable source. The
dispatcher (``dispatch_due``, run every 30s on the ``enrichment`` Celery queue)
claims due rows by lane priority, then due_at, runs each through the pipeline
for its one source, writes the results onto the entity, and settles the row by
the outcome:

==============================================  =================================
outcome                                         row
==============================================  =================================
success, cached, skipped_low_confidence,        deleted
source no longer applies
rate_limited, breaker_open                      due again after ``retry_after``
budget_exhausted                                due at the next UTC midnight
paused                                          due again in PAUSE_DEFER; the tick ends
gateway_unavailable                             put back as it was; the tick ends
error                                           attempts + 1, exponential backoff;
                                                ``failed`` after MAX_ATTEMPTS
==============================================  =================================

A backfill-lane job runs only while its source has spent less than
BACKFILL_SHARE of its ``daily_budget`` today, so bulk catch-up never starves
new entities or a person's request; past that it waits for the next UTC day.

While enrichment is paused (``app/enrichment/pause.py``) a tick claims
nothing. A ``running`` row whose claim is older than LEASE is claimable again,
so a worker that dies mid-tick strands nothing.
"""

import logging
import time
import uuid
from collections import Counter
from datetime import UTC, datetime, timedelta

from sqlalchemy import and_, case, delete, func, or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.enrichment.gateway import GatewayUnavailable
from app.enrichment.registry import ADAPTER_REGISTRY
from app.models.enrichment import EnrichmentJob, EnrichmentSource

logger = logging.getLogger(__name__)

#: Lane → priority. Lower runs first.
LANES = {"manual": 0, "new": 1, "refresh": 2, "backfill": 3}

#: Gateway refusals worth retrying; the manual enrich endpoint queues these.
RETRYABLE = frozenset({"rate_limited", "breaker_open", "budget_exhausted", "gateway_unavailable", "paused"})

TICK_SECONDS = 25
CLAIM_BATCH = 10
LEASE = timedelta(minutes=10)
MAX_ATTEMPTS = 5
#: Seconds before the first retry of an error; doubles per attempt.
ERROR_BACKOFF = 300
BACKFILL_SHARE = 0.6
#: Seconds a job waits when it met the pause; no attempt is counted.
PAUSE_DEFER = 60
#: Rows per INSERT when queueing a backfill.
ENQUEUE_CHUNK = 1000

_DONE = frozenset({"success", "cached", "skipped_low_confidence", "unsupported"})


def next_utc_midnight(now: datetime) -> datetime:
    return (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)


async def enqueue(
    db: AsyncSession,
    entity_type: str,
    entity_id: uuid.UUID | str,
    entity_value: str,
    *,
    lane: str = "new",
    source_types: list[str] | None = None,
    requested_by: uuid.UUID | None = None,
    entity_confidence: str | None = None,
    entity_base_confidence: float | None = None,
    due_at: datetime | None = None,
) -> list[str]:
    """Queue lookups of one entity, one row per applicable source. Returns the
    source types queued.

    Applicable: enabled and supporting the entity type; for the ``new`` lane,
    also ``trigger_mode='auto'``. Other lanes may name ``source_types``. Outside
    the ``manual`` lane the entity must also be in the source's scope (its
    kinds and ``scope`` values, ``Source.scope_filter``).

    Enqueueing an entity/source pair again upserts its row: it keeps the
    higher-priority lane (and that lane's requester) and the earlier due_at,
    and revives a ``failed`` row. Runs in a savepoint, so a failure here never
    costs the caller its transaction.
    """
    query = select(EnrichmentSource.source_type).where(EnrichmentSource.is_enabled == True)  # noqa: E712
    if lane == "new":
        query = query.where(EnrichmentSource.trigger_mode == "auto")
    elif source_types:
        query = query.where(EnrichmentSource.source_type.in_(source_types))

    try:
        async with db.begin_nested():
            applicable = [
                st
                for st in (await db.execute(query)).scalars()
                if st in ADAPTER_REGISTRY and entity_type in ADAPTER_REGISTRY[st].applies_to
            ]
            if lane != "manual":
                applicable = [st for st in applicable if await _in_scope(db, st, entity_type, entity_id)]
            if not applicable:
                return []
            due = due_at or datetime.now(UTC)
            await _upsert(
                db,
                [
                    _row(
                        entity_type,
                        entity_id,
                        entity_value,
                        st,
                        lane,
                        due,
                        requested_by=requested_by,
                        entity_confidence=entity_confidence,
                        entity_base_confidence=entity_base_confidence,
                    )
                    for st in applicable
                ],
            )
    except SQLAlchemyError:
        logger.exception("Could not queue enrichment for %s/%s", entity_type, entity_value)
        return []
    return applicable


async def _in_scope(db: AsyncSession, source_type: str, entity_type: str, entity_id) -> bool:
    from app.enrichment.entity_updater import _get_model_map

    model = _get_model_map().get(entity_type)
    scope = ADAPTER_REGISTRY[source_type].scope_filter(entity_type, model) if model else None
    if scope is None:
        return True
    found = await db.scalar(select(model.id).where(model.id == uuid.UUID(str(entity_id)), scope))
    return found is not None


def _row(
    entity_type,
    entity_id,
    entity_value,
    source_type,
    lane,
    due,
    *,
    requested_by=None,
    entity_confidence=None,
    entity_base_confidence=None,
) -> dict:
    return {
        "id": uuid.uuid4(),
        "entity_type": entity_type,
        "entity_id": uuid.UUID(str(entity_id)),
        "entity_value": entity_value,
        "source_type": source_type,
        "lane": lane,
        "priority": LANES[lane],
        "status": "queued",
        "due_at": due,
        "attempts": 0,
        "requested_by": requested_by,
        "entity_confidence": entity_confidence,
        "entity_base_confidence": entity_base_confidence,
    }


async def _upsert(db: AsyncSession, rows: list[dict]) -> None:
    """Insert job rows; a pair already queued keeps the higher-priority lane
    (and its requester) and the earlier due_at, and a failed one is revived."""
    stmt = pg_insert(EnrichmentJob).values(rows)
    new, job = stmt.excluded, EnrichmentJob
    upgrade = new.priority < job.priority
    revive = job.status == "failed"
    await db.execute(
        stmt.on_conflict_do_update(
            constraint="uq_enrichment_jobs_entity_source",
            set_={
                "priority": func.least(job.priority, new.priority),
                "lane": case((upgrade, new.lane), else_=job.lane),
                "requested_by": case((upgrade, new.requested_by), else_=job.requested_by),
                "due_at": func.least(job.due_at, new.due_at),
                "entity_value": new.entity_value,
                "entity_confidence": func.coalesce(new.entity_confidence, job.entity_confidence),
                "entity_base_confidence": func.coalesce(new.entity_base_confidence, job.entity_base_confidence),
                "status": case((revive, "queued"), else_=job.status),
                "attempts": case((revive, 0), else_=job.attempts),
                "updated_at": func.now(),
            },
        )
    )


async def enqueue_many(
    db: AsyncSession,
    entity_type: str,
    source_type: str,
    entities: list[tuple[uuid.UUID, str]],
    *,
    lane: str = "backfill",
) -> int:
    """Queue lookups of many ``(entity_id, entity_value)`` pairs at one source,
    ENQUEUE_CHUNK rows per INSERT, upserting as ``enqueue`` does. The caller
    has checked that the source applies. Returns the pairs queued."""
    now = datetime.now(UTC)
    for i in range(0, len(entities), ENQUEUE_CHUNK):
        chunk = entities[i : i + ENQUEUE_CHUNK]
        await _upsert(db, [_row(entity_type, eid, value, source_type, lane, now) for eid, value in chunk])
    return len(entities)


# ── Dispatcher ───────────────────────────────────────────────────────


async def claim(db: AsyncSession, limit: int = CLAIM_BATCH) -> list:
    """Mark up to ``limit`` due jobs running and return them, highest lane
    first. SKIP LOCKED lets two dispatchers claim side by side."""
    now = datetime.now(UTC)
    due = or_(
        and_(EnrichmentJob.status == "queued", EnrichmentJob.due_at <= now),
        and_(EnrichmentJob.status == "running", EnrichmentJob.claimed_at < now - LEASE),
    )
    ids = (
        (
            await db.execute(
                select(EnrichmentJob.id)
                .where(due)
                .order_by(EnrichmentJob.priority, EnrichmentJob.due_at)
                .limit(limit)
                .with_for_update(skip_locked=True)
            )
        )
        .scalars()
        .all()
    )
    if not ids:
        await db.commit()
        return []
    jobs = (
        await db.execute(
            update(EnrichmentJob)
            .where(EnrichmentJob.id.in_(ids))
            .values(status="running", claimed_at=now)
            .returning(
                EnrichmentJob.id,
                EnrichmentJob.entity_type,
                EnrichmentJob.entity_id,
                EnrichmentJob.entity_value,
                EnrichmentJob.source_type,
                EnrichmentJob.lane,
                EnrichmentJob.priority,
                EnrichmentJob.due_at,
                EnrichmentJob.attempts,
                EnrichmentJob.requested_by,
                EnrichmentJob.entity_confidence,
                EnrichmentJob.entity_base_confidence,
            )
            .execution_options(synchronize_session=False)
        )
    ).all()
    await db.commit()
    return sorted(jobs, key=lambda j: (j.priority, j.due_at))


async def _settle(db: AsyncSession, job, status: str, *, retry_after: float | None = None, error: str | None = None):
    """Delete or reschedule a claimed job by its outcome, and commit."""
    now = datetime.now(UTC)
    if status in _DONE:
        await db.execute(delete(EnrichmentJob).where(EnrichmentJob.id == job.id))
        await db.commit()
        return
    values: dict = {"status": "queued", "claimed_at": None, "last_status": status}
    if status in ("rate_limited", "breaker_open"):
        values["due_at"] = now + timedelta(seconds=max(1.0, retry_after or 0))
    elif status == "paused":
        values["due_at"] = now + timedelta(seconds=PAUSE_DEFER)
    elif status in ("budget_exhausted", "backfill_share"):
        values["due_at"] = next_utc_midnight(now)
    elif status != "gateway_unavailable":
        attempts = job.attempts + 1
        values.update(
            attempts=attempts,
            last_error=error,
            status="failed" if attempts >= MAX_ATTEMPTS else "queued",
            due_at=now + timedelta(seconds=ERROR_BACKOFF * 2 ** (attempts - 1)),
        )
    await db.execute(
        update(EnrichmentJob)
        .where(EnrichmentJob.id == job.id)
        .values(**values)
        .execution_options(synchronize_session=False)
    )
    await db.commit()


async def _backfill_allowed(db: AsyncSession, job) -> bool:
    """Whether the job's source is under its backfill share of today's budget.
    Raises GatewayUnavailable when the count can't be read."""
    from app.enrichment.pipeline import resolve_api_key
    from app.enrichment.registry import source_gateway

    source = (
        await db.execute(select(EnrichmentSource).where(EnrichmentSource.source_type == job.source_type))
    ).scalar_one_or_none()
    if source is None or not source.daily_budget:
        return True
    gateway = source_gateway(source, await resolve_api_key(source, job.requested_by, db))
    return await gateway.used_today() < BACKFILL_SHARE * source.daily_budget


async def _run(db: AsyncSession, job, held: dict) -> str:
    """Run one claimed job and settle it. Returns the outcome status.

    ``held`` maps (source_type, requester) to the (until, status) of a refusal
    earlier in this tick, so the rest of that credential's jobs are deferred
    without asking the gateway again.
    """
    from app.enrichment.entity_updater import apply_enrichment_results_to_entity
    from app.enrichment.pipeline import enrich_entity

    key = (job.source_type, job.requested_by)
    now = datetime.now(UTC)
    if key in held and held[key][0] > now:
        until, status = held[key]
        await _settle(db, job, status, retry_after=(until - now).total_seconds())
        return status

    try:
        if job.lane == "backfill" and not await _backfill_allowed(db, job):
            await _settle(db, job, "backfill_share")
            return "backfill_share"
        results = await enrich_entity(
            entity_type=job.entity_type,
            entity_id=job.entity_id,
            entity_value=job.entity_value,
            db=db,
            user_id=job.requested_by,
            # Only the new lane is subject to the source's confidence threshold;
            # a person or a backfill asked for this one by name.
            trigger="auto" if job.lane == "new" else "manual",
            source_types=[job.source_type],
            entity_confidence=job.entity_confidence,
            entity_base_confidence=job.entity_base_confidence,
        )
        await apply_enrichment_results_to_entity(db, job.entity_type, job.entity_id, results)
    except GatewayUnavailable:
        await db.rollback()
        await _settle(db, job, "gateway_unavailable")
        return "gateway_unavailable"
    except Exception as e:
        logger.exception("Enrichment job %s/%s at %s failed", job.entity_type, job.entity_value, job.source_type)
        await db.rollback()
        await _settle(db, job, "error", error=str(e)[:2000])
        return "error"

    outcome = results[0] if results else {"status": "unsupported"}
    status = outcome["status"]
    if status in ("rate_limited", "breaker_open"):
        held[key] = (now + timedelta(seconds=max(1.0, outcome.get("retry_after") or 0)), status)
    elif status == "budget_exhausted":
        held[key] = (next_utc_midnight(now), status)
    await _settle(db, job, status, retry_after=outcome.get("retry_after"), error=outcome.get("error"))
    return status


async def dispatch_due(db: AsyncSession, budget_seconds: float = TICK_SECONDS) -> dict[str, int]:
    """One dispatcher tick: run due jobs until the queue is drained or
    ``budget_seconds`` pass. Returns a count per outcome, or ``{"paused": 1}``
    when enrichment is paused."""
    from app.enrichment.pause import sync_pause

    if await sync_pause(db):
        return {"paused": 1}
    deadline = time.monotonic() + budget_seconds
    stats: Counter[str] = Counter()
    held: dict = {}
    while time.monotonic() < deadline:
        jobs = await claim(db)
        if not jobs:
            break
        for i, job in enumerate(jobs):
            if time.monotonic() >= deadline:
                await _release(db, jobs[i:])
                return dict(stats)
            status = await _run(db, job, held)
            stats[status] += 1
            if status == "gateway_unavailable":
                # Redis is down: every other lookup would be refused too.
                await _release(db, jobs[i + 1 :])
                return dict(stats)
            if status == "paused":
                # Paused since the tick began: the rest wait as this one does.
                for rest in jobs[i + 1 :]:
                    await _settle(db, rest, "paused")
                    stats["paused"] += 1
                return dict(stats)
    return dict(stats)


async def _release(db: AsyncSession, jobs: list) -> None:
    """Hand claimed jobs back untouched, for the next tick."""
    if not jobs:
        return
    await db.execute(
        update(EnrichmentJob)
        .where(EnrichmentJob.id.in_([j.id for j in jobs]))
        .values(status="queued", claimed_at=None)
        .execution_options(synchronize_session=False)
    )
    await db.commit()
