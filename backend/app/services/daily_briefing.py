"""Shared generation + lookup for the daily briefing.

One day gets one briefing. The beat job (06:00 UTC) and the automation
``use_daily_summary`` action (13:00 UTC on weekdays) both come through here, and
both key on the same shared sentinel cache row, so whichever runs first pays for
the generation and the other reads it back. That is what keeps the Slack push
and the Triage day divider from being two separate LLM calls over the same day.

``ensure_daily_summary`` is the write path (generate-if-missing);
``get_cached_daily_summary`` is the read-only path.
"""

import logging
import re
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.caller import Caller
from app.config import settings

logger = logging.getLogger(__name__)

# A day-divider summary is only offered when the day has at least this many
# entries (mirrors the frontend's `dayCount < 2` guard in DayDividerSummary).
MIN_ENTRIES = 2


def day_window(day_key: str) -> tuple[datetime, datetime]:
    """UTC start/end bounds for a YYYY-MM-DD day key.

    The GET path keys the cache on day_key alone (not the window bounds), so
    this stays consistent with whatever local window the frontend later computes
    for that same date.
    """
    start = datetime.strptime(day_key, "%Y-%m-%d").replace(tzinfo=UTC)
    return start, start + timedelta(days=1) - timedelta(microseconds=1)


def yesterday_key(now: datetime | None = None) -> str:
    """Day key for yesterday (UTC) — a briefing summarizes the day that ended."""
    now = now or datetime.now(UTC)
    return (now.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=1)).strftime("%Y-%m-%d")


def today_key(now: datetime | None = None) -> str:
    """Day key for today (UTC) — a partial day, still accumulating entries."""
    return (now or datetime.now(UTC)).strftime("%Y-%m-%d")


def _global_request(day_key: str, force: bool = False):
    """The default, unfiltered briefing request for a day — every filter unset,
    which is what resolves to the shared sentinel cache key."""
    from app.api.entries import DailySummaryRequest

    since, before = day_window(day_key)
    return DailySummaryRequest(day_key=day_key, since=since, before=before, dedup=True, force=force)


async def get_cached_daily_summary(db: AsyncSession, day_key: str) -> str | None:
    """Return the shared briefing markdown for a day, or None if not cached."""
    from app.api.entries import GLOBAL_SUMMARY_USER, _daily_summary_target_id, _filters_for_cache_key
    from app.models.ai_result import AIResult
    from app.models.ai_task import AITask

    task_id = (await db.execute(select(AITask.id).where(AITask.name == "daily_summary"))).scalar_one_or_none()
    if task_id is None:
        return None

    target_id = _daily_summary_target_id(GLOBAL_SUMMARY_USER, day_key, _filters_for_cache_key(_global_request(day_key)))
    row = (
        await db.execute(
            select(AIResult)
            .where(
                AIResult.target_type == "daily_summary",
                AIResult.target_id == target_id,
                AIResult.task_id == task_id,
                AIResult.is_current == True,  # noqa: E712
            )
            .order_by(AIResult.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if row is None or not isinstance(row.parsed_result, dict):
        return None
    summary = row.parsed_result.get("summary")
    return summary if isinstance(summary, str) and summary.strip() else None


async def ensure_daily_summary(db: AsyncSession, day_key: str, *, force: bool = False) -> dict:
    """Generate the shared briefing for ``day_key`` unless it is already cached.

    Returns a status dict: ``{"status", "day", "generated", ...}``. ``generated``
    is 1 when this call made the LLM request, 0 when it reused the cache or had
    nothing to do. ``summary`` carries the markdown whenever one is available —
    freshly generated or cached — so callers can push it somewhere.

    Never raises for the ordinary "can't produce one" cases (no AI provider, too
    few entries, upstream AI error); those come back as a status the caller logs.
    """
    # Imported here to keep worker boot cheap and avoid an import cycle at
    # module load. These are the *same* helpers the API endpoint uses, so the
    # cache key and entry projection are guaranteed identical.
    from app.ai.engine import run_task
    from app.api.entries import (
        GLOBAL_SUMMARY_USER,
        _daily_summary_target_id,
        _fetch_day_entries,
        _filters_for_cache_key,
    )
    from app.models.ai_task import AITask

    # The AITask row must exist for cache lookups (and for run_task to find an
    # assignment). If it's missing, nothing to do.
    task_id = (await db.execute(select(AITask.id).where(AITask.name == "daily_summary"))).scalar_one_or_none()
    if task_id is None:
        return {"status": "skipped", "day": day_key, "generated": 0, "reason": "daily_summary task not configured"}

    if not force:
        cached = await get_cached_daily_summary(db, day_key)
        if cached is not None:
            logger.info("Daily summary already cached for %s — skipping", day_key)
            await record_themes(db, day_key, cached)
            return {"status": "ok", "day": day_key, "generated": 0, "reason": "already_cached", "summary": cached}

    req = _global_request(day_key, force=force)
    filters_dict = _filters_for_cache_key(req)
    target_id = _daily_summary_target_id(GLOBAL_SUMMARY_USER, day_key, filters_dict)

    # Global briefing ignores per-user state (hidden/read/…): user=None.
    entry_payloads = await _fetch_day_entries(db, None, req)
    if len(entry_payloads) < MIN_ENTRIES:
        logger.info("Daily summary for %s skipped — only %d entries", day_key, len(entry_payloads))
        return {"status": "ok", "day": day_key, "generated": 0, "reason": "no_entries"}

    parsed = await run_task(
        db,
        GLOBAL_SUMMARY_USER,
        task_name="daily_summary",
        variables={
            "entries": entry_payloads,
            "entry_count": len(entry_payloads),
            "date_label": day_key,
            "scope_label": "",
        },
        target_type="daily_summary",
        target_id=target_id,
        force=force,
        caller=Caller.system(),
    )

    if parsed is None:
        logger.warning("Daily summary for %s skipped — no AI provider assigned", day_key)
        return {"status": "ok", "day": day_key, "generated": 0, "reason": "no_ai"}
    if isinstance(parsed, dict) and parsed.get("_error"):
        logger.warning("Daily summary AI error for %s: %s", day_key, parsed.get("_error"))
        return {"status": "error", "day": day_key, "generated": 0, "error": parsed.get("_error")}

    await db.commit()
    await _pregenerate_tts(db, day_key, filters_dict)

    summary = parsed.get("summary") if isinstance(parsed, dict) else None
    await record_themes(db, day_key, summary, force=True)
    logger.info("Daily summary generated for %s (%d entries)", day_key, len(entry_payloads))
    return {
        "status": "ok",
        "day": day_key,
        "generated": 1,
        "entry_count": len(entry_payloads),
        "summary": summary,
    }


async def record_themes(db: AsyncSession, day_key: str, markdown: str | None, *, force: bool = False) -> None:
    """Keep the briefing's own `### Theme` grouping of the day's articles.

    Best-effort in the same sense as the TTS pre-generation below: this reads
    markdown that already exists, so nothing about the briefing itself should
    fail because the parse did. Skips days already parsed unless the briefing
    was just re-generated.
    """
    try:
        from app.intelligence.narrative_themes import record_briefing_themes, themes_enabled

        if not markdown or not themes_enabled():
            return
        if not force:
            from app.models.narrative_theme import NarrativeBriefing

            already = (
                await db.execute(select(NarrativeBriefing.id).where(NarrativeBriefing.day_key == day_key))
            ).scalar_one_or_none()
            if already is not None:
                return
        result = await record_briefing_themes(db, day_key, markdown)
        logger.info("Narrative themes for %s: %s", day_key, result)
    except Exception:
        logger.warning("Narrative theme parse failed for %s", day_key, exc_info=True)


async def _pregenerate_tts(db: AsyncSession, day_key: str, filters_dict: dict) -> None:
    """Pre-generate read-aloud audio so "Listen" on the summary is instant.

    Best-effort: never let TTS failure break summary generation. Same server-side
    text derivation as the on-click path → cache-key match.
    """
    try:
        if not settings.tts_enabled:
            return
        from app.services.tts import get_or_enqueue, resolve_summary_speech_text

        speech_text = await resolve_summary_speech_text(db, day_key, filters_dict, None)
        if speech_text:
            await get_or_enqueue(db, source="summary", ref_id=day_key, text=speech_text)
            logger.info("Enqueued daily-summary TTS pre-generation for %s", day_key)
    except Exception as e:  # noqa: BLE001
        logger.warning("Daily-summary TTS pre-gen for %s failed: %s", day_key, e)


# ---------------------------------------------------------------------------
# In-app links → original article links
# ---------------------------------------------------------------------------
# The briefing is generated once and read from two very different places. In the
# app (Triage day divider, reader) the markdown links point at `/?entry=<id>` so
# a click opens IntelFeed's own reader. Pushed outside the app (Discord, Slack, a
# custom webhook) that link is useless — the reader is behind auth and the reader
# may not even have an account — so the same markdown gets rewritten to each
# article's original source URL before it goes out.

_ENTRY_LINK_RE = re.compile(
    r"(?:https?://[^\s)\]]*?)?/\?entry=(?P<id>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"
)


async def externalize_entry_links(db: AsyncSession, markdown: str | None) -> str:
    """Rewrite in-app reader deep links to the entries' original article URLs.

    Every ``/?entry=<uuid>`` (relative, or already absolutised with
    PUBLIC_BASE_URL) becomes the source article's own URL. An entry with no
    source URL — or one that has since been deleted — keeps its in-app link,
    absolutised when PUBLIC_BASE_URL is set so it is at least clickable from
    Discord/Slack.

    Best-effort: any failure returns the markdown unchanged rather than losing
    the briefing.
    """
    if not markdown:
        return markdown or ""

    try:
        import uuid as _uuid

        from app.models.entry import Entry

        ids: set[_uuid.UUID] = set()
        for m in _ENTRY_LINK_RE.finditer(markdown):
            try:
                ids.add(_uuid.UUID(m.group("id")))
            except ValueError:  # pragma: no cover - regex already shapes this
                continue
        if not ids:
            return markdown

        rows = (await db.execute(select(Entry.id, Entry.url).where(Entry.id.in_(ids)))).all()
        url_by_id = {str(eid): url for eid, url in rows if url}
        base = (settings.public_base_url or "").rstrip("/")

        def _replace(match: re.Match[str]) -> str:
            entry_id = match.group("id")
            external = url_by_id.get(entry_id)
            if external:
                return external
            # No source URL to fall back to — keep the in-app link, absolute if
            # we know the public origin.
            return f"{base}/?entry={entry_id}" if base else match.group(0)

        return _ENTRY_LINK_RE.sub(_replace, markdown)
    except Exception as e:  # noqa: BLE001
        logger.warning("Externalizing daily-summary links failed: %s", e)
        return markdown
