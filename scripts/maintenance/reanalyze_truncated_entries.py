"""Re-run the one-pass analysis for research articles whose earlier analysis
never saw their indicator section.

Before the indicator-aware window (``services/analysis_window.py``) the prompt
was a plain head slice of ``ai_analysis_content_max_chars``; a write-up longer
than that with its IOC appendix at the end produced an analysis with no
indicators. This selects entries whose rendered body exceeds the old cap AND
carries an indicator section, and queues ``run_entry_analysis_task`` for each
(the ``ai`` queue, one at a time — pace it with ``--limit``).

Runs in the api container (needs the broker):
    docker compose -f docker-compose.dev.yml exec api \\
        python scripts/maintenance/reanalyze_truncated_entries.py --days 90 --min-chars 15000 --dry-run
"""

import argparse
import asyncio
import sys
from datetime import UTC, datetime, timedelta

sys.path.insert(0, "/app")

from sqlalchemy import func, select  # noqa: E402

import app.models  # noqa: E402,F401
from app.database import async_session  # noqa: E402
from app.models.entry import Entry  # noqa: E402
from app.models.feed import Feed  # noqa: E402
from app.services.analysis_window import find_indicator_section, html_to_analysis_text  # noqa: E402


async def main(days: int, min_chars: int, limit: int, feed_like: str | None, dry_run: bool) -> None:
    since = datetime.now(UTC) - timedelta(days=days)
    async with async_session() as db:
        q = (
            select(Entry.id, Entry.title, Entry.content_html, Entry.content_text, Feed.title)
            .join(Feed, Feed.id == Entry.feed_id)
            .where(
                Entry.published_at >= since,
                func.coalesce(Entry.metadata_["content_type"].astext, "") != "ioc_list",
                func.length(func.coalesce(Entry.content_text, "")) > min_chars,
            )
            .order_by(Entry.published_at.desc())
        )
        if feed_like:
            q = q.where(Feed.title.ilike(f"%{feed_like}%"))
        chosen: list[tuple] = []
        for eid, title, html, text, feed_title in (await db.execute(q)).all():
            body = html_to_analysis_text(html) if html else (text or "")
            if len(body) <= min_chars:
                continue
            section = find_indicator_section(body)
            if section is None:
                continue
            chosen.append((eid, title, feed_title, len(body)))
            if len(chosen) >= limit:
                break
    by_feed: dict[str, int] = {}
    for _, _, feed_title, _ in chosen:
        by_feed[feed_title] = by_feed.get(feed_title, 0) + 1
    print(f"{len(chosen)} entries over {min_chars} chars with an indicator section (last {days} days)")
    for feed_title, n in sorted(by_feed.items(), key=lambda kv: -kv[1]):
        print(f"  {n:4d}  {feed_title}")
    if dry_run:
        for eid, title, feed_title, n in chosen[:25]:
            print(f"  {eid}  {n:6d}  {title[:70]}")
        return
    from app.workers.ai_batch_tasks import run_entry_analysis_task

    # force=True: these entries already have a current analysis, and the
    # engine's dedup guard would otherwise hand it back untouched.
    for eid, *_ in chosen:
        run_entry_analysis_task.delay(str(eid), force=True)
    print(f"queued {len(chosen)} forced analyses on the ai queue")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=90)
    ap.add_argument("--min-chars", type=int, default=15000, help="the old prompt cap")
    ap.add_argument("--limit", type=int, default=300)
    ap.add_argument("--feed-like", default=None, help="restrict to feeds whose title contains this")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    asyncio.run(main(a.days, a.min_chars, a.limit, a.feed_like, a.dry_run))
