"""Delete orphan documents from the Meilisearch entries index.

An orphan is a document whose ``feed_id`` no longer exists in the ``feeds``
table — usually the result of a failed cascade cleanup when a feed was
deleted. Run inside the API container:

    docker compose -f docker-compose.prod.yml exec api python scripts/maintenance/reconcile_search_index.py
    docker compose -f docker-compose.prod.yml exec api python scripts/maintenance/reconcile_search_index.py --dry-run
    # --yes skips the threshold prompt
    docker compose -f docker-compose.prod.yml exec api python scripts/maintenance/reconcile_search_index.py --yes
"""

import argparse
import asyncio
import sys

sys.path.insert(0, "/app")

from sqlalchemy import select

from app.database import async_session
from app.models.feed import Feed
from app.services.meilisearch_client import INDEX_NAME, _get_client

ABORT_THRESHOLD = 1000


async def fetch_db_feed_ids() -> set[str]:
    async with async_session() as db:
        result = await db.execute(select(Feed.id))
        return {str(fid) for fid in result.scalars().all()}


def fetch_index_feed_ids() -> dict[str, int]:
    """Return {feed_id: doc_count} for every feed_id present in the index."""
    client = _get_client()
    index = client.index(INDEX_NAME)
    # facetDistribution gives us counts per feed_id without scanning all docs
    res = index.search("", {"limit": 0, "facets": ["feed_id"]})
    return res.get("facetDistribution", {}).get("feed_id", {})


def delete_orphan(feed_id: str) -> int:
    client = _get_client()
    index = client.index(INDEX_NAME)
    task = index.delete_documents(filter=f'feed_id = "{feed_id}"')
    return task.task_uid


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="report only, do not delete")
    parser.add_argument(
        "--yes",
        action="store_true",
        help=f"skip confirmation when orphan count exceeds {ABORT_THRESHOLD}",
    )
    args = parser.parse_args()

    db_ids = await fetch_db_feed_ids()
    index_counts = fetch_index_feed_ids()

    orphans = {fid: count for fid, count in index_counts.items() if fid not in db_ids}

    print(f"feeds in DB:       {len(db_ids)}")
    print(f"feed_ids in index: {len(index_counts)}")
    print(f"orphan feed_ids:   {len(orphans)}")

    if not orphans:
        print("nothing to reconcile")
        return 0

    total_docs = sum(orphans.values())
    print(f"orphan documents:  {total_docs}")
    for fid, count in sorted(orphans.items(), key=lambda kv: -kv[1])[:20]:
        print(f"  {fid}  {count}")
    if len(orphans) > 20:
        print(f"  ... and {len(orphans) - 20} more")

    if args.dry_run:
        print("\n--dry-run set, exiting without deleting")
        return 0

    if total_docs > ABORT_THRESHOLD and not args.yes:
        print(
            f"\norphan document count ({total_docs}) exceeds threshold "
            f"({ABORT_THRESHOLD}). Re-run with --yes to proceed.",
            file=sys.stderr,
        )
        return 2

    print()
    for fid in orphans:
        task_uid = delete_orphan(fid)
        print(f"queued delete for {fid} (task {task_uid})")

    print(f"\nqueued {len(orphans)} delete tasks. Meilisearch will process them asynchronously.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
