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
needs_key, source no longer applies
rate_limited, breaker_open                      due again after ``retry_after``
budget_exhausted, backfill_share                due at the next UTC midnight
auth_failed                                     due again in AUTH_DEFER; no attempt
source_disabled                                 put back as it was
paused                                          due again in PAUSE_DEFER; the tick ends
gateway_unavailable                             put back as it was; the tick ends
error                                           attempts + 1, exponential backoff;
                                                ``failed`` after MAX_ATTEMPTS
==============================================  =================================

A refusal (rate_limited, breaker_open, budget_exhausted, auth_failed) holds the source for
that credential, its (source, requester), for the rest of the tick: one UPDATE
moves all its other due rows past the refusal, spaced one request interval of
the source's rate apart so they come due one at a time rather than together,
and the tick claims none of its rows again while the hold lasts.

A row enqueued again while it runs (a person asks for it mid-run) goes back to
queued as that enqueue left it (the higher-priority lane and its requester)
instead of being deleted or rescheduled: the upsert stamps ``updated_at`` with the clock, the claim stamps
``claimed_at`` and ``updated_at`` with its transaction time, and settling
compares the two.

A backfill-lane job runs only while its source has spent less than
BACKFILL_SHARE of its ``daily_budget`` today, so bulk catch-up never starves
new entities or a person's request; past that it waits for the next UTC day.
Its requests run in the gateway's backfill lane (``gateway.in_lane``), so the
share holds per request too, the same cap scheduled backfill jobs get.

A disabled source's rows wait: the dispatcher claims only rows of enabled
sources, and a row whose source is switched off mid-run goes back to the
queue as it was. Switching the source back on picks them up again.

Sources that send an observable to a third party (``Egress.SHARES_IOC``) are
queued on the automatic lanes (``new``, ``refresh``) only when an admin set
their row to ``trigger_mode='auto'``; their rows are seeded ``manual``.

A ``manual``-lane job runs with ``refresh``: it exists because a person asked
for a lookup and the source refused it, so the stored result is not the answer.

While enrichment is paused (``app/enrichment/pause.py``) a tick claims
nothing. A ``running`` row whose claim is older than LEASE is claimable again,
so a worker that dies mid-tick strands nothing. A claim takes a batch, but a
job is marked ``started`` only when its run begins, so a reclaim counts an
attempt only for a job that had started; the rest of a dead worker's batch is
claimed again as it was. A job whose lease expires on its MAX_ATTEMPTS-th try
is marked ``failed`` (``last_status`` ``lease_expired``), so a job that kills
its worker stops coming back.
"""

import logging
import time
import uuid
from collections import Counter
from datetime import UTC, datetime, timedelta

from sqlalchemy import DateTime, Interval, and_, case, delete, func, literal, not_, or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.enrichment.gateway import GatewayUnavailable, in_lane
from app.enrichment.manifest import Egress
from app.enrichment.registry import ADAPTER_REGISTRY
from app.models.enrichment import EnrichmentJob, EnrichmentSource

logger = logging.getLogger(__name__)

#: Lane → priority. Lower runs first.
LANES = {"manual": 0, "new": 1, "refresh": 2, "backfill": 3}

#: Gateway refusals worth retrying; the manual enrich endpoint queues these.
RETRYABLE = frozenset({"rate_limited", "breaker_open", "budget_exhausted", "gateway_unavailable", "paused"})

TICK_SECONDS = 25
CLAIM_BATCH = 10
#: Claims a tick retries when every row it took was failed by the lease limit.
CLAIM_ROUNDS = 5
LEASE = timedelta(minutes=10)
MAX_ATTEMPTS = 5
#: Seconds before the first retry of an error; doubles per attempt.
ERROR_BACKOFF = 300
#: Seconds a job waits when its credential's key was rejected. The refusal
#: costs no request, so it is checked again soon: a fixed key is picked up.
AUTH_DEFER = 3600
#: Lanes nobody asked for by name: a SHARES_IOC source needs trigger_mode='auto'.
AUTOMATIC_LANES = frozenset({"new", "refresh"})
#: Seconds a job waits when it met the pause; no attempt is counted.
PAUSE_DEFER = 60
#: Rows per INSERT when queueing a backfill.
ENQUEUE_CHUNK = 1000
#: ``last_status`` of a claimed job whose run has begun.
STARTED = "started"
LEASE_EXPIRED = f"The run did not finish within its {LEASE.total_seconds() / 60:.0f}-minute lease"

_DONE = frozenset({"success", "cached", "skipped_low_confidence", "needs_key", "unsupported"})
#: Outcomes that put a row off until the source can take it: asking again
#: doesn't bring it forward, the source would only refuse it again.
DEFERRALS = ("rate_limited", "breaker_open", "budget_exhausted", "backfill_share", "auth_failed", "paused")
#: Refusals that hold the rest of a credential's jobs for the tick.
_HOLDS = frozenset({"rate_limited", "breaker_open", "budget_exhausted", "auth_failed"})


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
    also ``trigger_mode='auto'``. Any lane may narrow to ``source_types``. A
    source that shares IOCs (``Egress.SHARES_IOC``) is queued on an automatic
    lane only with ``trigger_mode='auto'``. Outside the ``manual`` lane the
    entity must also be in the source's scope (its kinds and ``scope``
    values, ``Source.scope_filter``).

    Enqueueing an entity/source pair again upserts its row: it keeps the
    higher-priority lane (and that lane's requester) and the earlier due_at,
    and revives a ``failed`` row. Runs in a savepoint, so a failure here never
    costs the caller its transaction.
    """
    query = select(EnrichmentSource.source_type, EnrichmentSource.trigger_mode).where(
        EnrichmentSource.is_enabled == True  # noqa: E712
    )
    if lane == "new":
        query = query.where(EnrichmentSource.trigger_mode == "auto")
    if source_types:
        query = query.where(EnrichmentSource.source_type.in_(source_types))

    try:
        async with db.begin_nested():
            applicable = [
                st
                for st, mode in (await db.execute(query)).all()
                if st in ADAPTER_REGISTRY
                and entity_type in ADAPTER_REGISTRY[st].applies_to
                and not (lane in AUTOMATIC_LANES and mode != "auto" and shares_ioc(st))
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


def shares_ioc(source_type: str) -> bool:
    """Whether the source sends an observable's value to a third party."""
    cls = ADAPTER_REGISTRY.get(source_type)
    return cls is not None and cls.egress == Egress.SHARES_IOC


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
    (and its requester) and the earlier due_at, and a failed one is revived.
    A row the source put off (``DEFERRALS``) keeps its due_at: a budget
    refusal waits for midnight however often the entity is queued again."""
    stmt = pg_insert(EnrichmentJob).values(rows)
    new, job = stmt.excluded, EnrichmentJob
    upgrade = new.priority < job.priority
    revive = job.status == "failed"
    deferred = and_(job.status == "queued", job.last_status.in_(DEFERRALS))
    await db.execute(
        stmt.on_conflict_do_update(
            constraint="uq_enrichment_jobs_entity_source",
            set_={
                "priority": func.least(job.priority, new.priority),
                "lane": case((upgrade, new.lane), else_=job.lane),
                "requested_by": case((upgrade, new.requested_by), else_=job.requested_by),
                "due_at": case((deferred, job.due_at), else_=func.least(job.due_at, new.due_at)),
                "entity_value": new.entity_value,
                "entity_confidence": func.coalesce(new.entity_confidence, job.entity_confidence),
                "entity_base_confidence": func.coalesce(new.entity_base_confidence, job.entity_base_confidence),
                "status": case((revive, "queued"), else_=job.status),
                "attempts": case((revive, 0), else_=job.attempts),
                # The clock, not the transaction start, so a row claimed while
                # this transaction ran still reads as asked for again.
                "updated_at": func.clock_timestamp(),
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


def _credential(source_type: str, requested_by: uuid.UUID | None):
    """Rows of one (source_type, requester)."""
    return and_(
        EnrichmentJob.source_type == source_type,
        EnrichmentJob.requested_by.is_not_distinct_from(requested_by),
    )


async def claim(db: AsyncSession, limit: int = CLAIM_BATCH, held: frozenset = frozenset()) -> list:
    """Mark up to ``limit`` due jobs running and return them, highest lane
    first, skipping the (source_type, requester) pairs in ``held``. SKIP
    LOCKED lets two dispatchers claim side by side.

    A row reclaimed past its lease counts an attempt only when its run had
    started; one that reaches MAX_ATTEMPTS that way is marked failed and not
    returned. When every row a claim took failed that way, it claims again,
    up to CLAIM_ROUNDS times, so failed rows never end a tick with work due."""
    for _ in range(CLAIM_ROUNDS):
        found, jobs = await _claim_once(db, limit, held)
        if jobs or not found:
            return jobs
    return []


async def _claim_once(db: AsyncSession, limit: int, held: frozenset) -> tuple[bool, list]:
    """One claim: whether it found due rows, and the ones it marked running."""
    now = datetime.now(UTC)
    due = or_(
        and_(EnrichmentJob.status == "queued", EnrichmentJob.due_at <= now),
        and_(EnrichmentJob.status == "running", EnrichmentJob.claimed_at < now - LEASE),
    )
    # A disabled source's rows wait for it to be switched back on.
    due = and_(
        due,
        EnrichmentJob.source_type.in_(
            select(EnrichmentSource.source_type).where(EnrichmentSource.is_enabled == True)  # noqa: E712
        ),
    )
    if held:
        due = and_(due, not_(or_(*(_credential(st, by) for st, by in held))))
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
        return False, []
    # A reclaimed row whose run began; one still waiting in a dead worker's
    # batch never ran, and costs nothing.
    expired = and_(EnrichmentJob.status == "running", EnrichmentJob.last_status == STARTED)
    jobs = (
        await db.execute(
            update(EnrichmentJob)
            .where(EnrichmentJob.id.in_(ids))
            .values(
                status=case((and_(expired, EnrichmentJob.attempts + 1 >= MAX_ATTEMPTS), "failed"), else_="running"),
                attempts=case((expired, EnrichmentJob.attempts + 1), else_=EnrichmentJob.attempts),
                last_status=case((expired, "lease_expired"), else_=EnrichmentJob.last_status),
                last_error=case((expired, LEASE_EXPIRED), else_=EnrichmentJob.last_error),
                # Transaction time for both, so _settle can tell a row enqueued
                # again since (see _upsert).
                claimed_at=func.now(),
                updated_at=func.now(),
            )
            .returning(
                EnrichmentJob.id,
                EnrichmentJob.status,
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
    return True, sorted((j for j in jobs if j.status == "running"), key=lambda j: (j.priority, j.due_at))


async def _start(db: AsyncSession, job) -> None:
    """Mark a claimed job's run begun, and commit, so a lease reclaim counts
    its attempt. ``updated_at`` stays as it was: it tells _settle whether the
    row was enqueued again since the claim."""
    await db.execute(
        update(EnrichmentJob)
        .where(EnrichmentJob.id == job.id)
        .values(last_status=STARTED, updated_at=EnrichmentJob.updated_at)
        .execution_options(synchronize_session=False)
    )
    await db.commit()


async def _settle(db: AsyncSession, job, status: str, *, retry_after: float | None = None, error: str | None = None):
    """Delete or reschedule a claimed job by its outcome, and commit. A row
    enqueued again since its claim goes back to queued as that enqueue left it
    (lane, requester, due_at) instead."""
    now = datetime.now(UTC)
    unchanged = EnrichmentJob.updated_at <= EnrichmentJob.claimed_at
    if status in _DONE:
        deleted = await db.execute(delete(EnrichmentJob).where(EnrichmentJob.id == job.id, unchanged))
        if not deleted.rowcount:
            await db.execute(
                update(EnrichmentJob)
                .where(EnrichmentJob.id == job.id)
                .values(status="queued", claimed_at=None, last_status=status)
                .execution_options(synchronize_session=False)
            )
        await db.commit()
        return
    values: dict = {"status": "queued", "claimed_at": None, "last_status": status}
    if status in ("rate_limited", "breaker_open"):
        values["due_at"] = now + timedelta(seconds=max(1.0, retry_after or 0))
    elif status == "paused":
        values["due_at"] = now + timedelta(seconds=PAUSE_DEFER)
    elif status in ("budget_exhausted", "backfill_share"):
        values["due_at"] = next_utc_midnight(now)
    elif status == "auth_failed":
        values["due_at"] = now + timedelta(seconds=AUTH_DEFER)
    elif status not in ("gateway_unavailable", "source_disabled"):
        attempts = job.attempts + 1
        values.update(
            attempts=attempts,
            last_error=error,
            status="failed" if attempts >= MAX_ATTEMPTS else "queued",
            due_at=now + timedelta(seconds=ERROR_BACKOFF * 2 ** (attempts - 1)),
        )
    # A row asked for again mid-run keeps what that enqueue set.
    rescheduled = {k: case((unchanged, v), else_=getattr(EnrichmentJob, k)) for k, v in values.items()}
    rescheduled.update(status=case((unchanged, values["status"]), else_="queued"), claimed_at=None)
    await db.execute(
        update(EnrichmentJob)
        .where(EnrichmentJob.id == job.id)
        .values(**rescheduled)
        .execution_options(synchronize_session=False)
    )
    await db.commit()


async def _gateway(db: AsyncSession, job) -> tuple:
    """The job's source row and the gateway it runs through; (None, None)
    without a row."""
    from app.enrichment.pipeline import resolve_api_key
    from app.enrichment.registry import source_gateway

    source = (
        await db.execute(select(EnrichmentSource).where(EnrichmentSource.source_type == job.source_type))
    ).scalar_one_or_none()
    if source is None:
        return None, None
    return source, source_gateway(source, await resolve_api_key(source, job.requested_by, db))


async def _backfill_allowed(db: AsyncSession, job) -> bool:
    """Whether the job's source is under its backfill share of today's budget.
    Raises GatewayUnavailable when the count can't be read."""
    source, gateway = await _gateway(db, job)
    if source is None or not source.daily_budget:
        return True
    return await gateway.used_today() < gateway.backfill_cap()


async def _source_enabled(db: AsyncSession, source_type: str) -> bool:
    enabled = await db.scalar(select(EnrichmentSource.is_enabled).where(EnrichmentSource.source_type == source_type))
    return bool(enabled)


async def _hold(db: AsyncSession, job, until: datetime, status: str, claimed: list) -> None:
    """Defer the other due rows of a refused job's credential, in one UPDATE:
    the ``claimed`` rows of this batch and every queued one, the n-th due n
    request intervals (at the source's rate) after ``until``."""
    _, gateway = await _gateway(db, job)
    interval = gateway.period / gateway.capacity if gateway else 1.0
    waiting = or_(
        and_(EnrichmentJob.status == "queued", EnrichmentJob.due_at <= datetime.now(UTC)),
        EnrichmentJob.id.in_([j.id for j in claimed]),
    )
    ranked = (
        select(
            EnrichmentJob.id,
            func.row_number().over(order_by=(EnrichmentJob.priority, EnrichmentJob.due_at)).label("position"),
        )
        .where(_credential(job.source_type, job.requested_by), waiting)
        .subquery()
    )
    offset = func.make_interval(0, 0, 0, 0, 0, 0, ranked.c.position * interval, type_=Interval)
    await db.execute(
        update(EnrichmentJob)
        # ``waiting`` again on the row itself: after a lock wait Postgres
        # re-checks only this WHERE, so a row another dispatcher claimed
        # meanwhile is left to it.
        .where(EnrichmentJob.id == ranked.c.id, waiting)
        .values(
            status="queued",
            claimed_at=None,
            last_status=status,
            due_at=literal(until, DateTime(timezone=True)) + offset,
        )
        .execution_options(synchronize_session=False)
    )
    await db.commit()


async def _run(db: AsyncSession, job, held: dict) -> str:
    """Run one claimed job and settle it. Returns the outcome status.

    A refusal in _HOLDS records its (until, status) in ``held`` under the
    job's (source_type, requester), for the dispatcher to hold.
    """
    from app.enrichment.entity_updater import apply_enrichment_results_to_entity
    from app.enrichment.pipeline import enrich_entity

    key = (job.source_type, job.requested_by)
    now = datetime.now(UTC)
    await _start(db, job)
    try:
        if job.lane == "backfill" and not await _backfill_allowed(db, job):
            await _settle(db, job, "backfill_share")
            return "backfill_share"
        with in_lane(job.lane):
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
                # A person asked for this lookup and the source refused it.
                refresh=job.lane == "manual",
            )
        if not results and not await _source_enabled(db, job.source_type):
            # Switched off since the claim: the row waits for it.
            await _settle(db, job, "source_disabled")
            return "source_disabled"
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
    elif status == "auth_failed":
        held[key] = (now + timedelta(seconds=AUTH_DEFER), status)
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
        now = datetime.now(UTC)
        jobs = await claim(db, held=frozenset(k for k, (until, _) in held.items() if until > now))
        if not jobs:
            break
        deferred: set = set()
        for i, job in enumerate(jobs):
            if job.id in deferred:
                continue
            if time.monotonic() >= deadline:
                await _release(db, [j for j in jobs[i:] if j.id not in deferred])
                return dict(stats)
            status = await _run(db, job, held)
            stats[status] += 1
            if status in _HOLDS:
                key = (job.source_type, job.requested_by)
                rest = [j for j in jobs[i + 1 :] if (j.source_type, j.requested_by) == key]
                await _hold(db, job, held[key][0], status, rest)
                deferred.update(j.id for j in rest)
                stats[status] += len(rest)
            elif status == "gateway_unavailable":
                # Redis is down: every other lookup would be refused too.
                await _release(db, [j for j in jobs[i + 1 :] if j.id not in deferred])
                return dict(stats)
            elif status == "paused":
                # Paused since the tick began: the rest wait as this one does.
                for rest in jobs[i + 1 :]:
                    if rest.id not in deferred:
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


async def retry_failed(db: AsyncSession, source_type: str | None = None) -> int:
    """Queue again the lookups that gave up after MAX_ATTEMPTS errors (at one
    source, or at every source), with their attempts reset. Returns how many."""
    stmt = (
        update(EnrichmentJob)
        .where(EnrichmentJob.status == "failed")
        .values(status="queued", attempts=0, last_status=None, last_error=None, due_at=func.now(), claimed_at=None)
    )
    if source_type:
        stmt = stmt.where(EnrichmentJob.source_type == source_type)
    return (await db.execute(stmt)).rowcount or 0
