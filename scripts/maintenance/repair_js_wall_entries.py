"""Repair RSS entries whose stored body is a "Please enable JavaScript" or bot-check page.

Full-text extraction used to save the notice a JavaScript-only site (NCSC,
Europol, MSRC) or a bot wall (FortiGuard's "Just a moment") serves in place of
the article, overwriting the feed's own description. The extractor now rejects
those pages; this repairs the entries stored before that.

For each matching entry (rss/atom feeds only) the body is replaced by, in order:
  1. the stored RSS summary, when it is not itself truncated;
  2. the item's description from a fresh fetch of the feed (one fetch per feed);
  3. the stored summary even if truncated;
  4. a fresh full-text fetch of the article (which now rejects wall pages).
Entries none of these can fix are listed and left alone. Each repaired entry is
re-indexed in Meilisearch (content fields only), and its analysis is re-queued
on the ai queue only when the feed's AI is on (ai_one_pass_enabled, the feed's
ai_analysis_enabled, and a mode other than "none").

Dry-run by default (no network, no writes). Runs in the api container:
    docker compose -f docker-compose.prod.yml exec api python scripts/maintenance/repair_js_wall_entries.py
    docker compose -f docker-compose.prod.yml exec api python scripts/maintenance/repair_js_wall_entries.py --apply
    # one feed, no analysis re-queue:
    docker compose -f docker-compose.prod.yml exec api \\
        python scripts/maintenance/repair_js_wall_entries.py --feed-id <uuid> --apply --no-analysis
"""

import argparse
import asyncio
import sys
import uuid
from collections import defaultdict
from dataclasses import dataclass, field

sys.path.insert(0, "/app")

from sqlalchemy import func, select  # noqa: E402

import app.models  # noqa: E402,F401
from app.models.entry import Entry  # noqa: E402
from app.models.feed import Feed  # noqa: E402
from app.services.dedup import compute_content_hash  # noqa: E402
from app.services.js_wall import MAX_WALL_TEXT_CHARS, SQL_PREFILTER, looks_like_js_wall  # noqa: E402
from app.services.sanitizer import html_to_text, sanitize_html  # noqa: E402

# Wall pages are short; leave room for whitespace html_to_text keeps.
CANDIDATE_MAX_CHARS = MAX_WALL_TEXT_CHARS * 3


@dataclass
class Report:
    found: dict = field(default_factory=lambda: defaultdict(int))  # feed title -> count
    repaired: dict = field(default_factory=lambda: defaultdict(int))  # source -> count
    unresolved: list = field(default_factory=list)  # (feed title, entry id, url)
    reindexed: int = 0
    analysis_queued: int = 0


def _usable(content: str | None) -> bool:
    return bool(content and html_to_text(content).strip() and not looks_like_js_wall(content))


def _summary_truncated(summary: str) -> bool:
    # The RSS adapter clips summaries over 500 chars to 497 + "...".
    return len(summary) >= 500 and summary.endswith("...")


async def fetch_feed_items(feed: Feed) -> dict[str, str]:
    """guid -> item content_html from a fresh fetch of the feed."""
    from app.adapters import get_adapter
    from app.config import settings
    from app.core.safe_http import safe_async_client

    async with safe_async_client(
        follow_redirects=True,
        timeout=20.0,
        headers={"User-Agent": str(settings.get("user_agent") or settings.user_agent)},
    ) as client:
        resp = await client.get(feed.url)
    if resp.status_code != 200:
        return {}
    _, parsed = get_adapter(feed.feed_type).parse_entries(feed.url, resp.text)
    return {p.guid: p.content_html or "" for p in parsed}


async def fetch_article(url: str, feed_id) -> str | None:
    from app.workers.feed_tasks import _extract_full_text

    content, _ = await _extract_full_text(url, feed_id=feed_id)
    return content


def reindex_content(entry: Entry) -> None:
    """Partial Meilisearch update: only the fields this script rewrites."""
    from app.services.meilisearch_client import INDEX_NAME, _get_client

    _get_client().index(INDEX_NAME).update_documents(
        [
            {
                "id": str(entry.id),
                "content_text": (entry.content_text or "")[:50000],
                "summary": entry.summary or "",
                "word_count": entry.word_count or 0,
            }
        ]
    )


def queue_analysis(entry_id: uuid.UUID) -> None:
    from app.workers.ai_batch_tasks import run_entry_analysis_task

    # force: the entry already has an analysis — of the wall text.
    run_entry_analysis_task.delay(str(entry_id), force=True)


async def find_candidates(db, feed_id: uuid.UUID | None = None) -> list[tuple[Entry, Feed]]:
    q = (
        select(Entry, Feed)
        .join(Feed, Feed.id == Entry.feed_id)
        .where(
            Feed.feed_type.in_(("rss", "atom")),
            Entry.content_text.op("~*")(SQL_PREFILTER),
            func.length(Entry.content_text) <= CANDIDATE_MAX_CHARS,
        )
        .order_by(Feed.title, Entry.published_at.desc())
    )
    if feed_id:
        q = q.where(Entry.feed_id == feed_id)
    rows = (await db.execute(q)).all()
    return [(e, f) for e, f in rows if looks_like_js_wall(e.content_html or e.content_text)]


async def repair(
    db,
    *,
    apply: bool,
    feed_id: uuid.UUID | None = None,
    limit: int | None = None,
    requeue_analysis: bool = True,
    fetch_feed_items=fetch_feed_items,
    fetch_article=fetch_article,
    reindex=reindex_content,
    enqueue=queue_analysis,
) -> Report:
    from app.services.system_settings import get_setting

    report = Report()
    candidates = await find_candidates(db, feed_id)
    if limit:
        candidates = candidates[:limit]
    for entry, feed in candidates:
        report.found[feed.title] += 1
    if not apply:
        return report

    ai_globally_on = bool(await get_setting("ai_one_pass_enabled", db))
    feed_items: dict[uuid.UUID, dict[str, str]] = {}

    for entry, feed in candidates:
        summary = entry.summary or ""
        new_html, source = None, None
        if _usable(summary) and not _summary_truncated(summary):
            new_html, source = summary, "summary"
        if new_html is None:
            if feed.id not in feed_items:
                try:
                    feed_items[feed.id] = await fetch_feed_items(feed)
                except Exception as exc:
                    print(f"  feed fetch failed for {feed.title}: {exc}")
                    feed_items[feed.id] = {}
            item_html = feed_items[feed.id].get(entry.guid)
            if _usable(item_html):
                new_html, source = item_html, "feed"
        if new_html is None and _usable(summary):
            new_html, source = summary, "summary"
        if new_html is None and entry.url:
            try:
                article = await fetch_article(entry.url, feed.id)
            except Exception as exc:
                print(f"  article fetch failed for {entry.url}: {exc}")
                article = None
            if _usable(article):
                new_html, source = article, "article"
        if new_html is None:
            report.unresolved.append((feed.title, entry.id, entry.url))
            continue

        content_text = html_to_text(new_html)
        entry.content_html = sanitize_html(new_html)
        entry.content_text = content_text
        entry.word_count = len(content_text.split()) if content_text else None
        entry.content_hash = compute_content_hash(entry.title, content_text)
        await db.commit()
        report.repaired[source] += 1

        try:
            reindex(entry)
            report.reindexed += 1
        except Exception as exc:
            print(f"  re-index failed for {entry.id}: {exc}")

        feed_ai_on = feed.ai_analysis_enabled and feed.intel_extraction_mode != "none"
        if requeue_analysis and ai_globally_on and feed_ai_on:
            enqueue(entry.id)
            report.analysis_queued += 1

    return report


def print_report(report: Report, apply: bool) -> None:
    total = sum(report.found.values())
    print(f"{total} entries whose body is a JavaScript-only or bot-check page")
    for title, n in sorted(report.found.items(), key=lambda kv: -kv[1]):
        print(f"  {n:5d}  {title}")
    if not apply:
        print("dry run: nothing changed. Re-run with --apply to repair.")
        return
    for source, n in sorted(report.repaired.items()):
        print(f"repaired from {source}: {n}")
    print(f"re-indexed: {report.reindexed}; analyses queued: {report.analysis_queued}")
    if report.unresolved:
        print(f"unresolved (left as is): {len(report.unresolved)}")
        for title, eid, url in report.unresolved[:50]:
            print(f"  {eid}  {title}  {url}")


async def main(args) -> None:
    from app.database import async_session

    async with async_session() as db:
        report = await repair(
            db,
            apply=args.apply,
            feed_id=uuid.UUID(args.feed_id) if args.feed_id else None,
            limit=args.limit,
            requeue_analysis=not args.no_analysis,
        )
    print_report(report, args.apply)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--apply", action="store_true", help="write changes (default is a dry run)")
    ap.add_argument("--feed-id", default=None, help="only this feed")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--no-analysis", action="store_true", help="don't re-queue AI analysis")
    asyncio.run(main(ap.parse_args()))
