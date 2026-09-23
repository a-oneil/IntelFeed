"""Celery task: pre-generate the shared daily divider summary.

Reuses the exact generation + cache path behind the manual "Summarize day"
button (POST /entries/daily-summary). The default, unfiltered daily briefing is
identical for every user, so this generates it *once* for *yesterday* and writes
it to the shared (sentinel-keyed) AIResult cache the GET /entries/daily-summary
endpoint reads — so when any analyst opens Triage in the morning, yesterday's day
divider already shows its summary. A briefing of what came in yesterday is far
more useful than one for a day that has barely started.

The generation itself lives in ``app.services.daily_briefing`` because the
automation ``use_daily_summary`` action shares it: whichever of the two runs
first pays for the LLM call and the other reads the same cache row.

Idempotent: skips if a fresh shared summary is already cached for that day, and
skips gracefully when no AI provider is assigned to the ``daily_summary`` task.
The job is enabled by default and can be turned off in Settings → Jobs.
"""

import logging
import time

from app.core.metrics import CELERY_TASK_DURATION_SECONDS, CELERY_TASKS_TOTAL
from app.services.daily_briefing import ensure_daily_summary, yesterday_key
from app.workers.celery_app import celery_app
from app.workers.db import run_async, worker_session

logger = logging.getLogger(__name__)


@celery_app.task(
    name="app.workers.daily_summary_tasks.generate_daily_summaries",
    soft_time_limit=1800,
    time_limit=1980,
)
def generate_daily_summaries():
    """Pre-generate yesterday's shared Triage daily summary (all users)."""
    start = time.monotonic()
    try:
        result = run_async(_generate_daily_summaries())
        logger.info("Generate daily summaries result: %s", result)
        CELERY_TASKS_TOTAL.labels(task_name="generate_daily_summaries", status="success").inc()
        return result
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="generate_daily_summaries", status="error").inc()
        logger.exception("Generate daily summaries failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="generate_daily_summaries").observe(time.monotonic() - start)


async def _generate_daily_summaries() -> dict:
    # Yesterday's UTC day — a morning briefing summarizes the day that just
    # ended, not the one that has barely started. Celery runs with
    # timezone=UTC/enable_utc.
    async with worker_session() as db:
        result = await ensure_daily_summary(db, yesterday_key())
        parsed_days = await _backfill_narrative_themes(db)

    # The markdown itself is only useful to callers that push it somewhere; the
    # job's job is to warm the cache, so keep the task result small.
    out = {k: v for k, v in result.items() if k != "summary"}
    if parsed_days:
        out["themes_backfilled"] = parsed_days
    return out


#: How far back the nightly run looks for briefings whose grouping was never
#: parsed. Only matters for the first few nights after this ships (and after any
#: stretch where the parse was switched off) — steady state finds nothing.
_THEME_BACKFILL_DAYS = 14


async def _backfill_narrative_themes(db) -> int:
    """Parse the grouping out of any recent briefing that still lacks one.

    Reads cached markdown only: no provider call, no generation. Silent when
    the feature is off.
    """
    from datetime import UTC, datetime, timedelta

    from app.intelligence.narrative_themes import themes_enabled
    from app.models.narrative_theme import NarrativeBriefing
    from app.services.daily_briefing import get_cached_daily_summary, record_themes

    if not themes_enabled():
        return 0

    from sqlalchemy import select

    today = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    day_keys = [(today - timedelta(days=n)).strftime("%Y-%m-%d") for n in range(1, _THEME_BACKFILL_DAYS + 1)]
    done = set(
        (await db.execute(select(NarrativeBriefing.day_key).where(NarrativeBriefing.day_key.in_(day_keys))))
        .scalars()
        .all()
    )

    parsed = 0
    for day_key in day_keys:
        if day_key in done:
            continue
        markdown = await get_cached_daily_summary(db, day_key)
        if not markdown:
            continue
        await record_themes(db, day_key, markdown, force=True)
        parsed += 1
    return parsed
