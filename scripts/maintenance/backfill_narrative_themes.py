"""Parse every cached daily briefing into its `### Theme` groupings.

The briefing already sorted each day's articles into themes and linked them by
entry id. That structure was rendered once and discarded; narrative_themes.py
reads it back. Nothing here calls an AI provider — it re-reads markdown that was
generated and cached months ago.

The nightly generate-daily-summaries job only looks 14 days back, so this sweep
exists to cover the whole history in one pass the first time.

Days are resolved the way the app resolves them — by asking
``get_cached_daily_summary`` for each date in range. A briefing's own row cannot
be read backwards (its target_id is a hash of the day plus the filter set, and
the nightly job writes *yesterday's* briefing today, so the row's timestamp is
a day ahead of the day it covers).

Idempotent on (day_key, entry_id, theme): re-running re-parses the same
briefings and overwrites their bookkeeping counts rather than accumulating rows.
Citations of entries that retention has since pruned are dropped and counted.

Run inside the api container:
    docker compose -f docker-compose.dev.yml exec api python scripts/maintenance/backfill_narrative_themes.py --dry-run
    docker compose -f docker-compose.dev.yml exec api python scripts/maintenance/backfill_narrative_themes.py
"""

import argparse
import asyncio
import sys
from datetime import UTC, datetime, timedelta

sys.path.insert(0, "/app")

import app.models  # noqa: E402,F401 — register all mappers (Entry relationships)
from app.database import async_session  # noqa: E402
from app.intelligence.narrative_themes import (  # noqa: E402
    parse_briefing,
    record_briefing_themes,
    themes_enabled,
)
from app.models.ai_result import AIResult  # noqa: E402
from app.models.ai_task import AITask  # noqa: E402
from app.models.narrative_theme import NarrativeBriefing  # noqa: E402
from app.services.daily_briefing import get_cached_daily_summary  # noqa: E402
from sqlalchemy import func, select  # noqa: E402


async def main(dry_run: bool, force: bool, days: int | None) -> None:
    async with async_session() as db:
        from app.services.system_settings import _ensure_cache

        await _ensure_cache(db)
        if not themes_enabled() and not dry_run:
            print("narrative_themes_enabled is off — turn it on in Engine > Maintenance first")
            return

        task_id = (await db.execute(select(AITask.id).where(AITask.name == "daily_summary"))).scalar_one_or_none()
        if task_id is None:
            print("No daily_summary AI task — nothing to parse")
            return

        # How far back to look: the oldest cached briefing, unless capped.
        oldest = (
            await db.execute(
                select(func.min(AIResult.created_at)).where(
                    AIResult.task_id == task_id,
                    AIResult.target_type == "daily_summary",
                )
            )
        ).scalar_one_or_none()
        if oldest is None:
            print("No cached daily briefings — nothing to parse")
            return

        today = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
        span = (today - oldest.astimezone(UTC).replace(hour=0, minute=0, second=0, microsecond=0)).days + 1
        if days:
            span = min(span, days)
        print(f"Oldest cached briefing: {oldest:%Y-%m-%d} — checking {span} day(s) back from today")

        done = set((await db.execute(select(NarrativeBriefing.day_key))).scalars().all())

        parsed = themes = citations = dropped = skipped = missing = 0

        for n in range(0, span + 1):
            day_key = (today - timedelta(days=n)).strftime("%Y-%m-%d")
            if day_key in done and not force:
                skipped += 1
                continue

            markdown = await get_cached_daily_summary(db, day_key)
            if not markdown:
                missing += 1
                continue

            if dry_run:
                cites = parse_briefing(markdown)
                day_themes = {t for _, t, _ in cites if t}
                print(f"  {day_key}  citations={len(cites):3d}  themes={len(day_themes)}")
                parsed += 1
                themes += len(day_themes)
                citations += len(cites)
                continue

            result = await record_briefing_themes(db, day_key, markdown)
            if result.get("status") != "ok":
                print(f"  {day_key}  {result.get('status')}")
                continue
            parsed += 1
            themes += result["themes"]
            citations += result["citations"]
            dropped += result.get("dropped", 0)
            print(f"  {day_key}  citations={result['citations']:3d}  themes={result['themes']}")

        verb = "would parse" if dry_run else "parsed"
        print(f"\n{verb}: {parsed} briefings, {themes} themes, {citations} citations")
        if skipped:
            print(f"skipped (already parsed, use --force to redo): {skipped}")
        if missing:
            print(f"days with no cached briefing: {missing}")
        if dropped:
            print(f"citations dropped (article no longer exists): {dropped}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true", help="report what would be parsed, write nothing")
    ap.add_argument("--force", action="store_true", help="re-parse days that already have rows")
    ap.add_argument("--days", type=int, help="only look this many days back (default: to the oldest briefing)")
    args = ap.parse_args()
    asyncio.run(main(args.dry_run, args.force, args.days))
