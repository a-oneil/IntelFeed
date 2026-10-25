"""Measure what word-start keyword matching does to the relevance gates, per feed.

The relevance score gates two things against one threshold
(``ai_analysis_relevance_threshold``): autolinking on ``selective`` feeds, and
the AI junk gate on every feed the AI analyses. This scores recent entries
with the old substring scorer (``kw in text``, so "laptop" hit ``apt``) and
the word-start scorer in ``app/intelligence/relevance_filter.py``, and prints
per feed: entries, how many score under the threshold with each, and sample
titles that newly fall under. Read-only: nothing is written.

Text is the same the gates score at ingest (title, summary, content, plus any
translation). Feeds with mode ``none`` are listed too but neither gate runs on
them; the ``ai`` column says whether the junk gate applies.

Run inside the api container (``docker compose -f docker-compose.dev.yml exec api``):
    python scripts/maintenance/measure_relevance_filter.py
    python scripts/maintenance/measure_relevance_filter.py --days 60 --samples 5 --only-changed
    python scripts/maintenance/measure_relevance_filter.py --threshold 0.2
"""

import argparse
import asyncio
import sys
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

sys.path.insert(0, "/app")

from sqlalchemy import select  # noqa: E402

import app.models  # noqa: E402,F401
from app.database import async_session  # noqa: E402
from app.intelligence import relevance_filter as rf  # noqa: E402
from app.intelligence.relevance_filter import get_relevance_threshold, score_relevance  # noqa: E402
from app.models.entry import Entry  # noqa: E402
from app.models.feed import Feed  # noqa: E402
from app.services.sanitizer import entry_text_with_translation  # noqa: E402

BATCH = 500

# Keywords added together with word-start matching. Substring matching used to
# reach most of them by accident ("hacker" never hit, "ddos" hit via "dos");
# the old scorer below leaves them out so it reproduces the old lists exactly.
ADDED_KEYWORDS = frozenset(
    {
        "vulnerabilities",
        "vulnerable",
        "prompt injection",
        "hijack",
        "cyber threat",
        "advisories",
        "security flaw",
        "bug bounty",
        "ddos",
        "unpatched",
        "malicious",
        "hack",
        "hacked",
        "hacker",
        "hacking",
        "cyberattack",
        "data theft",
        "spearphishing",
        "cybercriminal",
        "cyberespionage",
    }
)
_OLD_CATEGORIES = [(keywords - ADDED_KEYWORDS, weight) for keywords, weight in rf._KEYWORD_CATEGORIES]


def score_relevance_substring(title: str, summary: str | None, content_text: str | None) -> float:
    """The scorer before word-start matching: plain ``kw in text``, old keyword lists."""
    combined = " ".join(filter(None, [title, summary, content_text])).lower()
    if not combined.strip():
        return 0.0
    score = 0.0
    for keywords, weight in _OLD_CATEGORIES:
        hits = sum(1 for kw in keywords if kw in combined)
        if hits > 0:
            score += weight * min(1.0, 0.6 + 0.2 * hits)
    if rf._CVE_PATTERN.search(combined):
        score += 0.4
    if rf._TTP_PATTERN.search(combined):
        score += 0.3
    if rf._IOC_LIKE_PATTERN.search(combined):
        score += 0.2
    title_lower = (title or "").lower()
    if title_lower and any(kw in title_lower for cat, _ in _OLD_CATEGORIES for kw in cat):
        score += 0.15
    return min(1.0, score)


async def measure(days: int, threshold: float | None, samples: int) -> tuple[float, dict]:
    since = datetime.now(UTC) - timedelta(days=days)
    stats: dict = defaultdict(
        lambda: {"entries": 0, "old_under": 0, "new_under": 0, "newly_under": [], "newly_over": 0}
    )
    async with async_session() as db:
        if threshold is None:
            threshold = await get_relevance_threshold(db)
        feeds = {
            f.id: f
            for f in (
                await db.execute(select(Feed.id, Feed.title, Feed.intel_extraction_mode, Feed.ai_analysis_enabled))
            ).all()
        }
        last_id = None
        while True:
            q = (
                select(
                    Entry.id,
                    Entry.feed_id,
                    Entry.title,
                    Entry.summary,
                    Entry.content_text,
                    Entry.translated_title,
                    Entry.translated_html,
                )
                .where(Entry.created_at >= since)
                .order_by(Entry.id)
                .limit(BATCH)
            )
            if last_id is not None:
                q = q.where(Entry.id > last_id)
            rows = (await db.execute(q)).all()
            if not rows:
                break
            last_id = rows[-1].id
            for row in rows:
                title, text = entry_text_with_translation(SimpleNamespace(**row._mapping))
                old = score_relevance_substring(title, row.summary or "", text)
                new = score_relevance(title, row.summary or "", text)
                s = stats[row.feed_id]
                s["entries"] += 1
                s["old_under"] += old < threshold
                s["new_under"] += new < threshold
                if new < threshold <= old:
                    if len(s["newly_under"]) < samples:
                        s["newly_under"].append(f"{old:.2f}->{new:.2f}  {(row.title or '')[:110]}")
                    s.setdefault("newly_under_n", 0)
                    s["newly_under_n"] += 1
                elif old < threshold <= new:
                    s["newly_over"] += 1
    return threshold, {fid: (feeds.get(fid), s) for fid, s in stats.items()}


def report(threshold: float, days: int, by_feed: dict, only_changed: bool) -> None:
    print(f"Relevance threshold {threshold:.2f}; entries created in the last {days} days.\n")
    rows = sorted(by_feed.values(), key=lambda fs: (-fs[1].get("newly_under_n", 0), -fs[1]["entries"]))
    header = (
        f"{'feed':<44} {'mode':<9} {'ai':<3} {'entries':>7} {'old<thr':>7} {'new<thr':>7} {'+under':>6} {'-under':>6}"
    )
    print(header)
    print("-" * len(header))
    totals = defaultdict(int)
    for feed, s in rows:
        newly = s.get("newly_under_n", 0)
        for k in ("entries", "old_under", "new_under", "newly_over"):
            totals[k] += s[k]
        totals["newly_under"] += newly
        if only_changed and not newly and not s["newly_over"]:
            continue
        name = (feed.title if feed else "(deleted feed)")[:44]
        mode = feed.intel_extraction_mode if feed else "?"
        ai = ("yes" if feed.ai_analysis_enabled and mode != "none" else "no") if feed else "?"
        print(
            f"{name:<44} {mode:<9} {ai:<3} {s['entries']:>7} {s['old_under']:>7} {s['new_under']:>7}"
            f" {newly:>6} {s['newly_over']:>6}"
        )
        for sample in s["newly_under"]:
            print(f"    {sample}")
    print("-" * len(header))
    print(
        f"{'TOTAL':<58} {totals['entries']:>7} {totals['old_under']:>7} {totals['new_under']:>7}"
        f" {totals['newly_under']:>6} {totals['newly_over']:>6}"
    )
    print("\n+under: newly below the threshold (word-start drops them); -under: newly above it.")


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--days", type=int, default=60, help="Look back this many days by ingest time (default 60)")
    parser.add_argument("--threshold", type=float, default=None, help="Override the live threshold setting")
    parser.add_argument("--samples", type=int, default=5, help="Sample titles per feed that newly fall under")
    parser.add_argument("--only-changed", action="store_true", help="Hide feeds where nothing moves")
    args = parser.parse_args()

    threshold, by_feed = await measure(args.days, args.threshold, args.samples)
    report(threshold, args.days, by_feed, args.only_changed)


if __name__ == "__main__":
    asyncio.run(main())
