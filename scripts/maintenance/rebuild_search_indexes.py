"""Rebuild every Meilisearch index from the database.

Covers both halves of the search state, which live in separate code paths:
the ``entries`` index (rebuilt from scratch, with per-user read/star/bookmark
fields baked in for one user) and the entity indexes plus ``rules``
(re-synced by ``sync_all_entities``).

The usual reason to run this is after restoring a dump from another
environment — ``scripts/ops/sync_prod_to_dev.sh`` calls it for exactly that
reason. The index is keyed by document ids from whichever database wrote it,
so after a restore it is not merely stale but pointing at rows that no longer
exist. Run inside the API container:

    docker compose -f docker-compose.dev.yml exec api python scripts/maintenance/rebuild_search_indexes.py
    # bake per-user entry state for a specific account instead of the first admin
    docker compose -f docker-compose.dev.yml exec api python scripts/maintenance/rebuild_search_indexes.py --user aoneil
    # do half the job
    docker compose -f docker-compose.dev.yml exec api python scripts/maintenance/rebuild_search_indexes.py --entries-only
    docker compose -f docker-compose.dev.yml exec api python scripts/maintenance/rebuild_search_indexes.py --entities-only

Runs inline rather than queueing the equivalent Celery tasks, so the exit code
reflects whether search actually works when it returns.
"""

import argparse
import asyncio
import sys

sys.path.insert(0, "/app")

from sqlalchemy import select

from app.database import async_session
from app.models.user import User


async def _resolve_user_id(username: str | None) -> str:
    """The entries index bakes per-user state, so the rebuild needs an owner.

    Defaults to the oldest active admin — on a normal install that is the first
    account created, which is the one whose read state matters in dev.
    """
    async with async_session() as db:
        stmt = select(User).where(User.is_active.is_(True))
        if username:
            stmt = stmt.where(User.username == username)
        else:
            stmt = stmt.where(User.role == "admin")
        user = (await db.execute(stmt.order_by(User.created_at))).scalars().first()

    if user is None:
        if username:
            raise SystemExit(f"ERROR: no active user named {username!r}")
        raise SystemExit("ERROR: no active admin user found — pass --user <username>")
    return str(user.id)


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--user", help="username whose entry state is baked into the entries index")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--entries-only", action="store_true", help="skip entity and rule indexes")
    group.add_argument("--entities-only", action="store_true", help="skip the entries index")
    args = parser.parse_args()

    failed = False

    if not args.entities_only:
        # Imported from the worker module so this shares one implementation with
        # the rebuild_search_index Celery task rather than reimplementing it.
        from app.workers.intel_feed_tasks import _rebuild_search_index

        user_id = await _resolve_user_id(args.user)
        print(f"[reindex] Rebuilding entries index (per-user state for {user_id})...")
        stats = await _rebuild_search_index(user_id)
        print(f"[reindex] entries: {stats}")
        # rebuild_index() returning False is reported in-band, not raised.
        if stats.get("status") == "error":
            print(f"[reindex] ERROR: entries rebuild failed: {stats.get('message')}", file=sys.stderr)
            failed = True

    if not args.entries_only and not failed:
        from app.services.entity_indexer import sync_all_entities

        print("[reindex] Syncing entity and rule indexes...")
        async with async_session() as db:
            counts = await sync_all_entities(db)
        for name, count in sorted(counts.items()):
            print(f"[reindex]   {name}: {count}")

    if failed:
        return 1
    print("[reindex] Done.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
