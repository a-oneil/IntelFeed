"""Signal engine Celery tasks: per-entry scoring, nightly rate recompute, rescore sweeps."""

import logging
import time
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.metrics import CELERY_TASK_DURATION_SECONDS, CELERY_TASKS_TOTAL
from app.workers.celery_app import celery_app
from app.workers.db import run_async, worker_session
from app.workers.pipeline_logging import pipeline_stage

logger = logging.getLogger(__name__)


def _get_worker_session():
    return worker_session()


async def _engine_enabled(db) -> bool:
    """DB-override-aware flag check (codebase pattern: get_setting inside the task session)."""
    from app.services.system_settings import get_setting

    return bool(await get_setting("signal_engine_shadow", db)) or bool(await get_setting("signal_engine_surface", db))


@celery_app.task(
    name="app.workers.signal_tasks.score_entry_task",
    bind=True,
    max_retries=2,
    soft_time_limit=60,
    time_limit=90,
)
@pipeline_stage("score")
def score_entry_task(self, *_args, entry_id: str = "", **_kwargs):
    """Compute signals + priority score for one entry (chord callback after post-processing).

    Accepts positional args because it runs as a chord callback (Celery passes
    the header results as the first argument).
    """
    start = time.monotonic()
    try:
        run_async(_score_entry(entry_id))
        CELERY_TASKS_TOTAL.labels(task_name="score_entry_task", status="success").inc()
    except Exception as exc:
        CELERY_TASKS_TOTAL.labels(task_name="score_entry_task", status="retry").inc()
        raise self.retry(exc=exc, countdown=30)
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="score_entry_task").observe(time.monotonic() - start)


async def _score_entry(entry_id: str) -> float | None:
    from app.services.system_settings import get_setting

    async with _get_worker_session() as db:
        if not await _engine_enabled(db):
            return None
        score = await score_entry(db, uuid.UUID(entry_id))
        try:
            from app.services.entry_analysis import enqueue_entry_analysis

            await enqueue_entry_analysis(db, uuid.UUID(entry_id))
        except Exception:
            logger.warning("entry_analysis enqueue failed for %s", entry_id, exc_info=True)
        await db.commit()
        surface = bool(await get_setting("signal_engine_surface", db))
        has_scored_rules = False
        if score is not None:
            from app.models.automation_rule import AutomationRule

            has_scored_rules = (
                await db.execute(
                    select(AutomationRule.id)
                    .where(AutomationRule.is_enabled.is_(True), AutomationRule.trigger_type == "on_entry_scored")
                    .limit(1)
                )
            ).scalar_one_or_none() is not None
    if has_scored_rules:
        try:
            from app.workers.automation_tasks import run_scored_entry_automations

            run_scored_entry_automations.delay(entry_id)
        except Exception:
            logger.warning("on_entry_scored dispatch failed for %s", entry_id, exc_info=True)
    if surface and score is not None:
        try:
            from app.api.events import broadcast_event

            broadcast_event("entry_scored", {"entry_id": entry_id, "priority_score": score})
        except Exception:
            logger.debug("entry_scored SSE broadcast failed", exc_info=True)
    return score


async def score_entry(db: AsyncSession, entry_id: uuid.UUID) -> float | None:
    """Compute + persist signals and priority score for an entry. Returns the score."""
    from sqlalchemy.orm import selectinload

    from app.intelligence.signals import (
        compute_entry_signals,
        compute_priority_score,
        get_family_multipliers,
        get_feedback_nudges,
        get_signal_rates,
    )
    from app.models.entry import Entry
    from app.models.entry_signal import EntrySignal

    entry = (
        await db.execute(select(Entry).options(selectinload(Entry.feed)).where(Entry.id == entry_id))
    ).scalar_one_or_none()
    if entry is None:
        logger.warning("score_entry: entry %s not found", entry_id)
        return None

    hits = await compute_entry_signals(db, entry)
    rates = await get_signal_rates()
    multipliers = await get_family_multipliers()
    nudges = await get_feedback_nudges()
    if nudges:
        multipliers = {k: v * nudges.get(k, 1.0) for k, v in multipliers.items()}
    score = compute_priority_score(hits, rates, multipliers)
    now = datetime.now(UTC)

    fired_types = [h.signal_type for h in hits]
    # Remove signals that no longer fire (re-score), then upsert the rest.
    stale = delete(EntrySignal).where(EntrySignal.entry_id == entry_id)
    if fired_types:
        stale = stale.where(EntrySignal.signal_type.notin_(fired_types))
    await db.execute(stale)
    for hit in hits:
        stmt = pg_insert(EntrySignal).values(
            id=uuid.uuid4(),
            entry_id=entry_id,
            signal_type=hit.signal_type,
            score=hit.score,
            explanation=hit.explanation,
            payload=hit.payload,
            created_at=now,
        )
        stmt = stmt.on_conflict_do_update(
            constraint="uq_entry_signals_entry_type",
            set_={
                "score": stmt.excluded.score,
                "explanation": stmt.excluded.explanation,
                "payload": stmt.excluded.payload,
                "created_at": stmt.excluded.created_at,
            },
        )
        await db.execute(stmt)

    entry.priority_score = score
    entry.scored_at = now
    db.add(entry)
    return score


@celery_app.task(
    name="app.workers.signal_tasks.recompute_signal_rates",
    soft_time_limit=120,
    time_limit=180,
)
def recompute_signal_rates():
    """Nightly: recompute 30-day per-signal firing rates → redis (IDF self-tuning)."""
    start = time.monotonic()
    try:
        rates = run_async(_recompute_signal_rates())
        logger.info("Signal firing rates recomputed: %s", rates)
        CELERY_TASKS_TOTAL.labels(task_name="recompute_signal_rates", status="success").inc()
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="recompute_signal_rates", status="error").inc()
        logger.exception("Signal rate recompute failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="recompute_signal_rates").observe(time.monotonic() - start)


async def _recompute_signal_rates() -> dict[str, float]:
    import json

    from app.intelligence.signals import RATES_REDIS_KEY
    from app.models.entry import Entry
    from app.models.entry_signal import EntrySignal
    from app.services.redis_client import get_redis

    cutoff = datetime.now(UTC) - timedelta(days=30)
    async with _get_worker_session() as db:
        # Denominator = entries scored in the window (same population as the
        # numerator's signals) — NOT entries fetched, which diverges whenever a
        # backfill scores older entries.
        total_entries = (
            await db.execute(select(func.count()).select_from(Entry).where(Entry.scored_at >= cutoff))
        ).scalar_one()
        if not total_entries:
            return {}
        rows = (
            await db.execute(
                select(EntrySignal.signal_type, func.count(func.distinct(EntrySignal.entry_id)))
                .where(EntrySignal.created_at >= cutoff)
                .group_by(EntrySignal.signal_type)
            )
        ).all()
        # Auto radar threshold: p95 of scores over the trailing 7 days
        p95 = (
            await db.execute(
                select(func.percentile_cont(0.95).within_group(Entry.priority_score.asc())).where(
                    Entry.scored_at >= datetime.now(UTC) - timedelta(days=7),
                    Entry.priority_score.isnot(None),
                )
            )
        ).scalar_one_or_none()

        # Radar feedback → bounded per-family nudge (±10%): each thumb counts
        # toward the entry's top-contributing signal, not every family present.
        from app.models.entry_signal_feedback import EntrySignalFeedback

        feedback_rows = (
            await db.execute(
                select(
                    EntrySignalFeedback.id,
                    EntrySignalFeedback.verdict,
                    EntrySignal.signal_type,
                    EntrySignal.score,
                )
                .join(EntrySignal, EntrySignal.entry_id == EntrySignalFeedback.entry_id)
                .where(EntrySignalFeedback.created_at >= cutoff)
            )
        ).all()

        from app.services.system_settings import get_setting

        min_samples = int(await get_setting("signal_feedback_min_samples", db) or 0)

    from app.intelligence.signals import attribute_feedback_votes

    rates = {signal_type: round(count / total_entries, 5) for signal_type, count in rows}
    family_votes = attribute_feedback_votes(feedback_rows, rates)
    # Families below the sample floor keep a neutral 1.0 nudge — a handful of
    # votes shouldn't swing scoring as hard as a season of feedback would.
    skipped = sorted(f for f, votes in family_votes.items() if len(votes) < min_samples)
    if skipped:
        logger.info("Feedback nudges skipped for %s (< %d verdicts in window)", skipped, min_samples)
    nudges = {
        family: round(1.0 + 0.1 * (sum(votes) / len(votes)), 4)
        for family, votes in family_votes.items()
        if len(votes) >= min_samples
    }

    from app.intelligence.signals import FEEDBACK_NUDGE_REDIS_KEY, THRESHOLD_REDIS_KEY

    r = await get_redis()
    await r.set(RATES_REDIS_KEY, json.dumps(rates))
    if p95 is not None:
        await r.set(THRESHOLD_REDIS_KEY, str(round(float(p95), 4)))
    # Always write (even {}) so families that fall below the sample floor — or
    # lose all feedback — reset to neutral instead of keeping a stale nudge.
    await r.set(FEEDBACK_NUDGE_REDIS_KEY, json.dumps(nudges))
    return rates


@celery_app.task(
    name="app.workers.signal_tasks.rescore_recent_entries",
    soft_time_limit=600,
    time_limit=660,
)
def rescore_recent_entries(hours: int = 72, limit: int = 500):
    """Re-score recent entries so late severity changes (KEV adds, EPSS jumps) propagate.

    Also sweeps up never-scored entries in the window (scoring failed all
    retries, or the engine was enabled after ingest) so they can't silently
    stay out of Radar forever.
    """
    start = time.monotonic()
    try:
        count, healed = run_async(_rescore_recent(hours=hours, limit=limit))
        logger.info("Rescored %d recent entries (%d previously unscored)", count, healed)
        CELERY_TASKS_TOTAL.labels(task_name="rescore_recent_entries", status="success").inc()
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="rescore_recent_entries", status="error").inc()
        logger.exception("Recent-entry rescore failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="rescore_recent_entries").observe(time.monotonic() - start)


@celery_app.task(
    name="app.workers.signal_tasks.rescore_entries_for_cve",
    soft_time_limit=300,
    time_limit=360,
)
def rescore_entries_for_cve(cve_id: str, days: int = 14, limit: int = 200):
    """Re-score recent entries linking a CVE whose severity state changed.

    Dispatched by enrichment when KEV addition, significant EPSS change, CVSS
    escalation, or exploit-availability change lands — severity arrives days
    after ingest, so waiting for the 72h sweep would miss most entries.
    """
    start = time.monotonic()
    try:
        count = run_async(_rescore_entries_for_cve(cve_id, days=days, limit=limit))
        if count:
            logger.info("Rescored %d entries after CVE %s state change", count, cve_id)
        CELERY_TASKS_TOTAL.labels(task_name="rescore_entries_for_cve", status="success").inc()
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="rescore_entries_for_cve", status="error").inc()
        logger.exception("CVE-triggered rescore failed for %s", cve_id)
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="rescore_entries_for_cve").observe(time.monotonic() - start)


async def _rescore_entries_for_cve(cve_id: str, days: int, limit: int) -> int:
    from app.models.cve import EntryCVE
    from app.models.entry import Entry

    cutoff = datetime.now(UTC) - timedelta(days=days)
    async with _get_worker_session() as db:
        if not await _engine_enabled(db):
            return 0
        entry_ids = (
            (
                await db.execute(
                    select(EntryCVE.entry_id)
                    .join(Entry, Entry.id == EntryCVE.entry_id)
                    .where(EntryCVE.cve_id == uuid.UUID(cve_id), Entry.published_at >= cutoff)
                    .order_by(Entry.published_at.desc())
                    .limit(limit)
                )
            )
            .scalars()
            .all()
        )
        for eid in entry_ids:
            await score_entry(db, eid)
        await db.commit()
    return len(entry_ids)


@celery_app.task(
    name="app.workers.signal_tasks.rescore_entries_for_threads",
    soft_time_limit=600,
    time_limit=660,
)
def rescore_entries_for_threads(thread_ids: list[str], limit: int = 1000):
    """Re-score the articles in story threads whose membership just changed.

    Threading runs up to 30 minutes behind ingest, so an article is always
    scored before the platform knows which story it belongs to — the echo
    verdict and the outlet count simply are not knowable yet. This is the
    second look, and it covers the whole thread rather than the new arrival:
    one more outlet on a story is one more point of corroboration for every
    article already in it.
    """
    start = time.monotonic()
    try:
        count = run_async(_rescore_entries_for_threads(thread_ids, limit=limit))
        if count:
            logger.info("Rescored %d entries across %d changed threads", count, len(thread_ids))
        CELERY_TASKS_TOTAL.labels(task_name="rescore_entries_for_threads", status="success").inc()
        return {"threads": len(thread_ids), "rescored": count}
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="rescore_entries_for_threads", status="error").inc()
        logger.exception("Thread-triggered rescore failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="rescore_entries_for_threads").observe(time.monotonic() - start)


async def _rescore_entries_for_threads(thread_ids: list[str], limit: int) -> int:
    from app.models.story_thread import StoryThreadEntry

    ids = [uuid.UUID(str(t)) for t in (thread_ids or [])]
    if not ids:
        return 0
    async with _get_worker_session() as db:
        if not await _engine_enabled(db):
            return 0
        # Membership is re-read rather than passed in: the task is then
        # idempotent and self-healing if it runs late or twice.
        entry_ids = (
            (
                await db.execute(
                    select(StoryThreadEntry.entry_id)
                    .where(StoryThreadEntry.thread_id.in_(ids))
                    .order_by(StoryThreadEntry.added_at.desc())
                    .limit(limit)
                )
            )
            .scalars()
            .all()
        )
        if len(entry_ids) >= limit:
            # Newest memberships first, so what is dropped is the tail of large
            # threads — say so rather than reporting a clean number.
            logger.warning(
                "Thread rescore hit its %d-entry cap across %d threads; older members keep their previous score",
                limit,
                len(ids),
            )
        for eid in entry_ids:
            await score_entry(db, eid)
        await db.commit()
    return len(entry_ids)


def dispatch_thread_rescore(thread_ids) -> None:
    """Fire-and-forget rescore for the sweeper. Never breaks the sweep."""
    ids = [str(t) for t in (thread_ids or [])]
    if not ids:
        return
    try:
        rescore_entries_for_threads.apply_async(args=[ids], countdown=5)
    except Exception:
        logger.warning("Thread rescore dispatch failed for %d threads", len(ids), exc_info=True)


def dispatch_cve_rescore(cve_uuid) -> None:
    """Fire-and-forget rescore dispatch for enrichment call sites.

    countdown lets the enclosing enrichment transaction commit before the
    worker reads CVE state; failures never break the enrichment sweep.
    """
    try:
        rescore_entries_for_cve.apply_async(args=[str(cve_uuid)], countdown=60)
    except Exception:
        logger.warning("CVE rescore dispatch failed for %s", cve_uuid, exc_info=True)


async def _rescore_recent(hours: int, limit: int) -> tuple[int, int]:
    from app.models.entry import Entry

    cutoff = datetime.now(UTC) - timedelta(hours=hours)
    async with _get_worker_session() as db:
        if not await _engine_enabled(db):
            return 0, 0
        # Unscored entries first so self-healing wins when the limit truncates.
        rows = (
            await db.execute(
                select(Entry.id, Entry.scored_at)
                .where(Entry.published_at >= cutoff)
                .order_by(Entry.scored_at.is_(None).desc(), Entry.published_at.desc())
                .limit(limit)
            )
        ).all()
        healed = sum(1 for _, scored_at in rows if scored_at is None)
        for eid, _ in rows:
            await score_entry(db, eid)
        await db.commit()
    return len(rows), healed


@celery_app.task(
    name="app.workers.signal_tasks.backfill_entry_scores",
    soft_time_limit=3600,
    time_limit=3660,
)
def backfill_entry_scores(days: int = 14, batch_size: int = 500):
    """One-shot: score historical entries so shadow mode has data to evaluate.

    Dispatch manually (Job Schedules → run now, or celery call) after enabling
    signal_engine_shadow. Never scheduled.
    """
    start = time.monotonic()
    try:
        count = run_async(_backfill_scores(days=days, batch_size=batch_size))
        logger.info("Backfilled scores for %d entries", count)
        CELERY_TASKS_TOTAL.labels(task_name="backfill_entry_scores", status="success").inc()
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="backfill_entry_scores", status="error").inc()
        logger.exception("Score backfill failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="backfill_entry_scores").observe(time.monotonic() - start)


async def _backfill_scores(days: int, batch_size: int) -> int:
    from app.models.entry import Entry

    cutoff = datetime.now(UTC) - timedelta(days=days)
    total = 0
    async with _get_worker_session() as db:
        if not await _engine_enabled(db):
            logger.warning("backfill_entry_scores skipped: signal engine disabled")
            return 0
        while True:
            entry_ids = (
                (
                    await db.execute(
                        select(Entry.id)
                        .where(Entry.published_at >= cutoff, Entry.scored_at.is_(None))
                        .order_by(Entry.published_at.desc())
                        .limit(batch_size)
                    )
                )
                .scalars()
                .all()
            )
            if not entry_ids:
                break
            for eid in entry_ids:
                await score_entry(db, eid)
            await db.commit()
            total += len(entry_ids)
            logger.info("Score backfill progress: %d entries", total)
    return total


@celery_app.task(
    name="app.workers.signal_tasks.rescore_all_entries",
    soft_time_limit=7200,
    time_limit=7260,
)
def rescore_all_entries(batch_size: int = 500):
    """One-shot full rescore of every already-scored entry.

    Heals stored signals/explanations across the whole corpus after a scoring
    logic change (e.g. new explanation copy). Manual-only — dispatch from Job
    Schedules → run now; never beat-scheduled (see job_registry enabled_by_default).
    """
    start = time.monotonic()
    try:
        count = run_async(_rescore_all(batch_size=batch_size))
        logger.info("Full rescore healed %d entries", count)
        CELERY_TASKS_TOTAL.labels(task_name="rescore_all_entries", status="success").inc()
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="rescore_all_entries", status="error").inc()
        logger.exception("Full rescore failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="rescore_all_entries").observe(time.monotonic() - start)


async def _rescore_all(batch_size: int) -> int:
    """Keyset-paginate over all scored entries, re-scoring each. A fresh session
    per batch keeps transactions short over a corpus-wide sweep."""
    from app.models.entry import Entry

    async with _get_worker_session() as db:
        if not await _engine_enabled(db):
            logger.warning("rescore_all_entries skipped: signal engine disabled")
            return 0

    last = None
    total = 0
    while True:
        async with _get_worker_session() as db:
            q = select(Entry.id).where(Entry.scored_at.is_not(None))
            if last is not None:
                q = q.where(Entry.id > last)
            q = q.order_by(Entry.id).limit(batch_size)
            entry_ids = (await db.execute(q)).scalars().all()
            if not entry_ids:
                break
            for eid in entry_ids:
                await score_entry(db, eid)
            await db.commit()
            last = entry_ids[-1]
            total += len(entry_ids)
            logger.info("Full rescore progress: %d entries", total)
    return total


@celery_app.task(
    name="app.workers.signal_tasks.fit_user_signal_weights",
    soft_time_limit=180,
    time_limit=240,
)
def fit_user_signal_weights():
    """Nightly: fit per-user signal-family weights from each analyst's own Radar thumbs.

    The sibling recompute_signal_rates job pools every user's votes into one
    global nudge baked into Entry.priority_score. This one keeps the votes
    separate so each analyst's Radar can diverge from the house ranking at read
    time, without touching a stored score.
    """
    start = time.monotonic()
    try:
        stats = run_async(_fit_user_signal_weights())
        logger.info(
            "Fitted personal signal weights: %d users, %d families (%d rows cleared)",
            stats["users"],
            stats["families"],
            stats["cleared"],
        )
        CELERY_TASKS_TOTAL.labels(task_name="fit_user_signal_weights", status="success").inc()
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="fit_user_signal_weights", status="error").inc()
        logger.exception("Personal signal weight fit failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="fit_user_signal_weights").observe(time.monotonic() - start)


async def _fit_user_signal_weights() -> dict:
    from app.intelligence.signals import attribute_feedback_votes, fit_personal_weight, get_signal_rates
    from app.models.entry_signal import EntrySignal
    from app.models.entry_signal_feedback import EntrySignalFeedback
    from app.models.user_signal_weight import UserSignalWeight
    from app.services.system_settings import get_setting

    rates = await get_signal_rates()
    async with _get_worker_session() as db:
        window_days = int(await get_setting("radar_personalization_window_days", db) or 90)
        min_samples = int(await get_setting("radar_personalization_min_samples", db) or 5)
        cutoff = datetime.now(UTC) - timedelta(days=window_days)

        # Same join as the global nudge, but carrying the voter so verdicts stay
        # separated per analyst instead of being pooled.
        rows = (
            await db.execute(
                select(
                    EntrySignalFeedback.created_by,
                    EntrySignalFeedback.id,
                    EntrySignalFeedback.verdict,
                    EntrySignal.signal_type,
                    EntrySignal.score,
                )
                .join(EntrySignal, EntrySignal.entry_id == EntrySignalFeedback.entry_id)
                .where(EntrySignalFeedback.created_at >= cutoff)
            )
        ).all()

        by_user: dict[uuid.UUID, list[tuple]] = {}
        for user_id, fb_id, verdict, signal_type, score in rows:
            by_user.setdefault(user_id, []).append((fb_id, verdict, signal_type, score))

        users = 0
        families_written = 0
        keep: set[tuple] = set()
        for user_id, user_rows in by_user.items():
            # attribute_feedback_votes credits each thumb to the single signal
            # that contributed most to that entry's score — reused verbatim so
            # personal and global weights are fitted from identical attribution.
            family_votes = attribute_feedback_votes(user_rows, rates)
            qualifying = {f: v for f, v in family_votes.items() if len(v) >= min_samples}
            if qualifying:
                users += 1
            keep.update((user_id, family) for family in qualifying)
            for family, votes in qualifying.items():
                weight = fit_personal_weight(votes)
                stmt = pg_insert(UserSignalWeight).values(
                    id=uuid.uuid4(),
                    user_id=user_id,
                    family=family,
                    weight=weight,
                    up_votes=sum(1 for v in votes if v > 0),
                    down_votes=sum(1 for v in votes if v < 0),
                    sample_count=len(votes),
                )
                stmt = stmt.on_conflict_do_update(
                    constraint="uq_user_signal_weights_user_family",
                    set_={
                        "weight": stmt.excluded.weight,
                        "up_votes": stmt.excluded.up_votes,
                        "down_votes": stmt.excluded.down_votes,
                        "sample_count": stmt.excluded.sample_count,
                        "updated_at": datetime.now(UTC),
                    },
                )
                await db.execute(stmt)
                families_written += 1

        # Drop rows whose evidence aged out of the window or fell below the
        # floor, so a stale weight can't outlive the votes that justified it.
        existing = (
            await db.execute(select(UserSignalWeight.id, UserSignalWeight.user_id, UserSignalWeight.family))
        ).all()
        stale_ids = [row_id for row_id, user_id, family in existing if (user_id, family) not in keep]
        cleared = 0
        if stale_ids:
            await db.execute(delete(UserSignalWeight).where(UserSignalWeight.id.in_(stale_ids)))
            cleared = len(stale_ids)

        await db.commit()
    return {"users": users, "families": families_written, "cleared": cleared}
