"""Collapse copies of one article that a feed stored under churning guids.

Some feeds give the same post a new guid on every fetch (CrowdStrike's RSS
mints a random ``?p=`` guid per render), so the guid check alone stores a row
per fetch. The fetcher also dedups on link + title within a feed; this script
removes copies already in the database. Per feed it groups rows by the same item key the fetcher uses
(normalised link without tracking parameters or fragment, normalised title,
and enclosure path), keeps the earliest row of each group, moves everything
that references a copy onto it — tags, notes, story-thread membership, read /
starred state, entity links, campaign and requirement matches, AI results,
detection rules, shares, report and relationship evidence ids — then deletes
the copies and drops them from Meilisearch. See app/services/entry_merge.py
for what moves and how collisions resolve.

Podcast episodes are only merged when title AND audio match, so CyberWire
episodes that share a show-notes URL stay separate; the report counts those
rows under "same URL, different title/enclosure (kept)".

Dry run is the default. Run inside the api container:

    # preview the five feeds the feed audit found (default when no --feed is given)
    docker compose -f docker-compose.prod.yml exec api \
        python scripts/maintenance/merge_same_url_entries.py
    # preview every feed
    docker compose -f docker-compose.prod.yml exec api \
        python scripts/maintenance/merge_same_url_entries.py --all-feeds
    # apply to named feeds (id or exact title, repeatable)
    docker compose -f docker-compose.prod.yml exec api \
        python scripts/maintenance/merge_same_url_entries.py --apply \
        --feed CrowdStrike --feed "Microsoft Security Blog"

--ignore-title merges non-podcast rows on the link alone, for a feed that
retitles posts; check the "different title" count in the dry run first.
"""

import argparse
import asyncio
import sys
import uuid

sys.path.insert(0, "/app")

from sqlalchemy import func, select

from app.database import async_session
from app.models.feed import Feed
from app.services.entry_merge import batch_by_keeper, merge_entries, plan_same_url_merges

# The feeds the 2026-10 feed audit found repeating URLs, by title.
DEFAULT_FEEDS = (
    "CrowdStrike",
    "CyberWire Daily",
    "Microsoft Security Blog",
    "Threat intelligence | Microsoft Security Blog",
    "SOCRadar® Cyber Intelligence Inc.",
)


async def resolve_feeds(db, names: list[str], all_feeds: bool) -> list[Feed]:
    if all_feeds:
        return list((await db.execute(select(Feed).order_by(Feed.title))).scalars().all())
    feeds = []
    for name in names:
        try:
            feed = await db.get(Feed, uuid.UUID(name))
        except ValueError:
            matches = (await db.execute(select(Feed).where(func.lower(Feed.title) == name.lower()))).scalars().all()
            if len(matches) > 1:
                print(f"  ! '{name}' matches {len(matches)} feeds; pass the id instead")
                continue
            feed = matches[0] if matches else None
        if feed is None:
            print(f"  ! no feed '{name}'")
            continue
        feeds.append(feed)
    return feeds


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--feed", action="append", default=[], help="Feed id or exact title (repeatable)")
    parser.add_argument("--all-feeds", action="store_true", help="Every feed (use with the dry run to survey)")
    parser.add_argument("--ignore-title", action="store_true", help="Merge non-podcast rows on the link alone")
    parser.add_argument("--apply", action="store_true", help="Write the merge (default is a dry run)")
    parser.add_argument("--batch-size", type=int, default=500, help="Copies per transaction (default 500)")
    args = parser.parse_args()

    names = args.feed or list(DEFAULT_FEEDS)
    async with async_session() as db:
        feeds = await resolve_feeds(db, names, args.all_feeds)
        feed_refs = [(f.id, f.title, f.feed_type) for f in feeds]

    mode = "APPLY" if args.apply else "DRY RUN"
    print(f"{mode}: {len(feed_refs)} feed(s)\n")
    total_deleted = 0
    for feed_id, title, feed_type in feed_refs:
        async with async_session() as db:
            plan = await plan_same_url_merges(db, feed_id, ignore_title=args.ignore_title)
            if not plan.mapping and not plan.rows_sharing_url_not_merged:
                if not args.all_feeds:
                    print(f"{title} ({feed_id}): {plan.rows:,} rows, no copies")
                continue
            print(f"{title} ({feed_id}, {feed_type})")
            print(f"  rows:                          {plan.rows:,}")
            print(f"  articles with copies:          {plan.groups:,}")
            print(f"  copies to delete:              {len(plan.mapping):,}")
            print(f"  rows after:                    {plan.rows - len(plan.mapping):,}")
            if plan.rows_sharing_url_not_merged:
                print(
                    f"  same URL, different title/enclosure (kept): {plan.rows_sharing_url_not_merged:,} rows"
                    f" in {plan.distinct_items_sharing_url:,} distinct items"
                )
            if not args.apply or not plan.mapping:
                print()
                continue

            from app.services import meilisearch_client
            from app.services.entry_tags import sync_entry_tags_to_search

            # Each deleted entry fires ~40 FK triggers, a few on unindexed
            # columns (automation_logs, cves.created_from_entry_id …), so a
            # delete costs tens of milliseconds. Commit per batch to keep each
            # transaction short; a keeper and its copies stay in one batch.
            totals: dict[str, int] = {}
            done = 0
            for batch in batch_by_keeper(plan.mapping, args.batch_size):
                stats = await merge_entries(db, batch)
                await db.commit()
                meilisearch_client.delete_entries_batch(list(batch))
                await sync_entry_tags_to_search(db, sorted(set(batch.values())))
                for key, value in stats.items():
                    totals[key] = totals.get(key, 0) + value
                done += len(batch)
                print(f"    merged {done:,}/{len(plan.mapping):,}", flush=True)
            for key, value in totals.items():
                print(f"    {key}: {value:,}")
            total_deleted += totals.get("entries.deleted", 0)
            print()

    if args.apply:
        print(f"Deleted {total_deleted:,} copies.")
    else:
        print("Dry run: nothing written. Re-run with --apply.")


if __name__ == "__main__":
    asyncio.run(main())
