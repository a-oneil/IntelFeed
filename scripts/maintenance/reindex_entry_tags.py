"""Re-push every tagged entry's tag fields to the Meilisearch entries index.

Migration y6q8s0u2w4y6 moved shared tag assignments to per-user rows. Index
documents written before it still carry those names in ``tags`` (the field
everyone searches and facets on) instead of in ``user_tags`` (one
``"<user_id>:<name>"`` token per personal assignment), so until this runs,
``tag:`` search and the Tags facet show pre-migration shared tags to everyone.
Run once after deploying that migration, inside the *new* API container (the
script imports app code from the image, so wait for `docker compose ps` to show
the rebuilt api healthy):

    docker compose -f docker-compose.prod.yml exec api python scripts/maintenance/reindex_entry_tags.py --all
    docker compose -f docker-compose.prod.yml exec api python scripts/maintenance/reindex_entry_tags.py --all --dry-run
    # without --all: only entries that currently carry a tag row (skips clearing
    # stale fields on entries that lost their last tag)
    docker compose -f docker-compose.prod.yml exec api python scripts/maintenance/reindex_entry_tags.py

Safe to re-run: it recomputes from Postgres and overwrites only the two tag
fields on each document.
"""

import argparse
import asyncio
import sys

sys.path.insert(0, "/app")

from sqlalchemy import select

from app.database import async_session
from app.models.entry import Entry
from app.models.tag import EntryTag
from app.services.entry_tags import sync_entry_tags_to_search
from app.services.meilisearch_client import INDEX_NAME, _get_client


def check_index_reachable() -> None:
    """Fail loudly up front: the per-batch push is best-effort and only warns."""
    try:
        _get_client().index(INDEX_NAME).get_stats()
    except Exception as exc:  # noqa: BLE001 — any failure here means "don't start"
        print(f"Meilisearch is not reachable ({exc}); nothing re-pushed.", file=sys.stderr)
        sys.exit(2)


async def entry_ids(db, include_untagged: bool) -> list:
    """Every entry id to re-push, ordered so a re-run after a crash is resumable by eye."""
    if include_untagged:
        stmt = select(Entry.id).order_by(Entry.id)
    else:
        stmt = select(EntryTag.entry_id).distinct().order_by(EntryTag.entry_id)
    result = await db.execute(stmt)
    return [row[0] for row in result.all()]


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--dry-run", action="store_true", help="Count what would be re-pushed; change nothing")
    parser.add_argument("--all", action="store_true", help="Every entry, not only those with a tag row")
    parser.add_argument("--batch-size", type=int, default=1000, help="Entries per index update (default 1000)")
    args = parser.parse_args()

    async with async_session() as db:
        ids = await entry_ids(db, include_untagged=args.all)
    scope = "entries" if args.all else "tagged entries"
    print(f"{len(ids):,} {scope} to re-push in batches of {args.batch_size}")
    if args.dry_run or not ids:
        return

    check_index_reachable()
    done = 0
    async with async_session() as db:
        for start in range(0, len(ids), args.batch_size):
            batch = ids[start : start + args.batch_size]
            await sync_entry_tags_to_search(db, batch)
            done += len(batch)
            print(f"  {done:,}/{len(ids):,}", flush=True)
    print("Done. Meilisearch applies the updates asynchronously; give it a moment before checking a tag: search.")


if __name__ == "__main__":
    asyncio.run(main())
