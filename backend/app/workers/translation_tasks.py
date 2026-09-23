"""Auto-translate entries on ingest via the LibreTranslate sidecar.

Queued from `feed_tasks` for each new entry on feeds whose `adapter_config.auto_translate`
is enabled. Best-effort: failures log a warning but never block ingestion.
"""

from __future__ import annotations

import logging
import time as _time
from datetime import UTC

from sqlalchemy import select

from app.core.metrics import CELERY_TASK_DURATION_SECONDS, CELERY_TASKS_TOTAL
from app.models.entry import Entry
from app.services import translation
from app.workers.celery_app import celery_app
from app.workers.db import run_async, worker_session
from app.workers.pipeline_logging import pipeline_stage

logger = logging.getLogger(__name__)

# Skip translation past this many characters of HTML — keeps the LibreTranslate
# sidecar from being pinned by occasional novel-sized RSS articles. Telegram
# messages are well under this; long RSS bodies fall through and stay original.
_MAX_TRANSLATE_CHARS = 50_000


@celery_app.task(
    name="app.workers.translation_tasks.translate_entry_task",
    soft_time_limit=60,
    time_limit=90,
)
@pipeline_stage("translate")
def translate_entry_task(entry_id: str, target_lang: str = "en", requeue_autolink: bool = True) -> str | None:
    """requeue_autolink=False when running as the pipeline prologue — autolink
    hasn't run yet and follows in the same chain, so re-queueing would double it."""
    start = _time.monotonic()
    try:
        result = run_async(_translate_one(entry_id, target_lang, requeue_autolink=requeue_autolink))
        CELERY_TASKS_TOTAL.labels(task_name="translate_entry_task", status="success").inc()
        return result
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="translate_entry_task", status="error").inc()
        logger.exception("translate_entry_task failed for entry %s", entry_id)
        return None
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="translate_entry_task").observe(_time.monotonic() - start)


async def _translate_one(entry_id: str, target_lang: str, requeue_autolink: bool = True) -> str | None:
    target_lang = (target_lang or "en").lower()
    async with worker_session() as db:
        result = await db.execute(select(Entry).where(Entry.id == entry_id))
        entry = result.scalar_one_or_none()
        if entry is None:
            return None
        # Only treat as cached when BOTH body and title are already translated.
        # A partial translation (body succeeded but title call failed/returned
        # untranslated) must be allowed to re-run and fix the title.
        title_needs_translation = bool(entry.title and entry.title.strip())
        title_already_done = not title_needs_translation or (
            entry.translated_title and entry.translated_title.strip() != entry.title.strip()
        )
        if entry.translated_html and entry.translation_target_language == target_lang and title_already_done:
            return "cached"

        source_html = entry.content_html or (f"<p>{entry.summary}</p>" if entry.summary else "")
        if not source_html.strip():
            return "empty"
        if len(source_html) > _MAX_TRANSLATE_CHARS:
            logger.info(
                "translate_entry_task skipping oversized entry %s (%d chars)",
                entry_id,
                len(source_html),
            )
            return "oversized"

        # LibreTranslate's /detect is unreliable on shorter strings — it returns
        # ("en", 0.0) for clearly non-English text. Only short-circuit on
        # already-target when we either have a stored language tag or got a
        # confident detection; otherwise let /translate auto-detect on the server.
        detected = entry.language
        if not detected:
            sample = (entry.content_text or entry.title or "")[:2000]
            if sample.strip():
                try:
                    cand, conf = await translation.detect_language(sample)
                    if conf >= 0.5:
                        detected = cand
                except translation.TranslationError:
                    detected = None

        if detected and detected.lower() == target_lang:
            # Persist the detected language so the retry sweep can tell a
            # correctly-skipped same-language entry (language set) apart from one
            # skipped only because the sidecar was down (language stays NULL).
            if not entry.language:
                entry.language = detected.lower()
                db.add(entry)
                await db.commit()
            return "already_target"

        try:
            translated, body_detected = await translation.translate_html(
                source_html, source=detected or "auto", target=target_lang
            )
        except translation.TranslationError as exc:
            logger.warning("translate_entry_task service error for %s: %s", entry_id, exc)
            return "service_error"

        # Prefer the source language LibreTranslate identified from the long body
        # over short-text auto-detect on the title — titles are often a single
        # line with brand names mixed in and auto-detect frequently misfires.
        title_source = detected or body_detected or "auto"

        translated_title: str | None = None
        if entry.title and entry.title.strip():
            try:
                translated_title, _ = await translation.translate_text(
                    entry.title, source=title_source, target=target_lang
                )
            except translation.TranslationError as exc:
                logger.warning("translate_entry_task title error for %s: %s", entry_id, exc)

            # If LibreTranslate returned the title unchanged (common when source
            # was "auto" on short non-Latin text), retry once with an explicit
            # source language if we have one.
            if (
                translated_title is not None
                and translated_title.strip() == entry.title.strip()
                and title_source == "auto"
                and body_detected
                and body_detected.lower() != target_lang
            ):
                try:
                    retried, _ = await translation.translate_text(entry.title, source=body_detected, target=target_lang)
                    if retried and retried.strip() != entry.title.strip():
                        translated_title = retried
                        title_source = body_detected
                except translation.TranslationError as exc:
                    logger.warning("translate_entry_task title retry error for %s: %s", entry_id, exc)

        from datetime import datetime

        effective_source = detected or body_detected
        entry.translated_html = translated
        if translated_title:
            entry.translated_title = translated_title
        entry.translation_source_language = effective_source or "auto"
        entry.translation_target_language = target_lang
        entry.translated_at = datetime.now(UTC)
        if effective_source and not entry.language:
            entry.language = effective_source
        db.add(entry)
        await db.commit()

    # Re-run autolink on the translated text so entity mentions in non-Latin
    # source languages get linked once their English form is available. Skipped
    # for pipeline-prologue runs where autolink follows in the same chain.
    if requeue_autolink:
        try:
            from app.workers.intel_feed_tasks import autolink_entry_task

            autolink_entry_task.delay(entry_id)
        except Exception:
            logger.warning("Failed to re-queue autolink after translation for %s", entry_id, exc_info=True)
    return "translated"


# Backfill sweep. LibreTranslate runs off-by-default (the `translate` compose
# profile), so on ingest an auto-translate feed's entries may be skipped while
# the sidecar is down. This sweep re-queues those once it's back up.
#
# Convergence: a candidate is an untranslated entry (translated_html IS NULL)
# whose language isn't already the target. translate_entry_task resolves every
# candidate into a terminal state that removes it from the set — a real
# translation sets translated_html; a same-language entry gets its language
# persisted (see the already_target branch above). Genuinely un-translatable
# ones (oversized/empty) simply age out of the lookback window.
_RETRY_LOOKBACK_DAYS = 14
_RETRY_MAX_PER_SWEEP = 500  # global budget; drains over successive ticks


@celery_app.task(
    name="app.workers.translation_tasks.retry_untranslated_entries",
    soft_time_limit=120,
    time_limit=150,
)
def retry_untranslated_entries() -> dict:
    """Re-queue translations missed while the LibreTranslate sidecar was off.

    Cheap no-op when the sidecar is unreachable — it pings /languages first and
    bails without queueing anything — so it's safe to schedule frequently.
    """
    start = _time.monotonic()
    try:
        result = run_async(_retry_untranslated())
        CELERY_TASKS_TOTAL.labels(task_name="retry_untranslated_entries", status="success").inc()
        return result
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="retry_untranslated_entries", status="error").inc()
        logger.exception("retry_untranslated_entries failed")
        return {"dispatched": 0, "error": True}
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="retry_untranslated_entries").observe(_time.monotonic() - start)


async def _retry_untranslated() -> dict:
    from datetime import datetime, timedelta

    from sqlalchemy import func as safunc

    from app.config import settings
    from app.models.feed import Feed

    # Gate on reachability: if LibreTranslate is off, don't flood the queue with
    # tasks that would all fail — just wait for the next tick.
    try:
        await translation.supported_languages()
    except translation.TranslationError:
        logger.info("retry_untranslated_entries: LibreTranslate unreachable, skipping sweep")
        return {"dispatched": 0, "skipped": "sidecar_unreachable"}

    cutoff = datetime.now(UTC) - timedelta(days=_RETRY_LOOKBACK_DAYS)
    dispatched = 0
    async with worker_session() as db:
        feeds = (await db.execute(select(Feed))).scalars().all()
        targets = {
            feed.id: (
                (feed.adapter_config or {}).get("translation_target")
                or settings.get("translation_default_target")
                or "en"
            ).lower()
            for feed in feeds
            if (feed.adapter_config or {}).get("auto_translate")
        }
        if not targets:
            return {"dispatched": 0}

        for feed_id, target_lang in targets.items():
            if dispatched >= _RETRY_MAX_PER_SWEEP:
                break
            remaining = _RETRY_MAX_PER_SWEEP - dispatched
            stmt = (
                select(Entry.id)
                .where(
                    Entry.feed_id == feed_id,
                    Entry.translated_html.is_(None),
                    Entry.created_at >= cutoff,
                    (Entry.language.is_(None)) | (safunc.lower(Entry.language) != target_lang),
                )
                .order_by(Entry.created_at.desc())
                .limit(remaining)
            )
            ids = (await db.execute(stmt)).scalars().all()
            for eid in ids:
                translate_entry_task.delay(str(eid), target_lang)
                dispatched += 1

    if dispatched:
        logger.info("retry_untranslated_entries dispatched %d entries", dispatched)
    return {"dispatched": dispatched}
