"""Seed curated starter feeds, for installs that are built by script rather than clicked through.

A fresh install has zero feeds, so nothing ingests and every downstream surface
— entity profiles, the priority queue, story threads, the threats board — sits
empty. The onboarding wizard offers the same packs with checkboxes; this is the
headless path to the identical result.

Run inside the api container:
    docker compose -f docker-compose.dev.yml exec api python scripts/seed/seed_feeds.py --list
    docker compose -f docker-compose.dev.yml exec api python scripts/seed/seed_feeds.py --dry-run
    docker compose -f docker-compose.dev.yml exec api python scripts/seed/seed_feeds.py
    docker compose -f docker-compose.dev.yml exec api python scripts/seed/seed_feeds.py --packs core,github-rules
    docker compose -f docker-compose.dev.yml exec api python scripts/seed/seed_feeds.py --all

Defaults to the `core` pack alone — the same thing the wizard pre-selects.
Idempotent: feeds are matched on URL, so re-running adds only what is missing
and never duplicates. Categories are reused by name across packs.

Deliberately NOT part of `seed_all.py`. Everything in there is reference data —
a closed vocabulary the autolinker matches against, the same on every install.
Feeds are editorial: which sources an instance polls is the owner's call, and
`seed_all.py` running it would mean every scripted install silently starts
hitting three dozen third-party servers.
"""

import argparse
import asyncio
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

# `/app` in the container, `<repo>/backend` from a host venv — the app package
# sits in a different place in each, so look rather than assume.
for _candidate in ("/app", Path(__file__).resolve().parents[2] / "backend"):
    if (Path(_candidate) / "app" / "__init__.py").exists():
        sys.path.insert(0, str(_candidate))
        break

from sqlalchemy import select

from app.api.opml import _import_opml_tree
from app.database import async_session
from app.feed_packs import get_pack, load_packs
from app.models.user import User


async def main(args: argparse.Namespace) -> None:
    packs = load_packs()
    if not packs:
        sys.exit("No starter packs found in app/data/feed_packs/.")

    if args.list:
        width = max(len(p.id) for p in packs)
        for p in packs:
            flags = " (recommended)" if p.recommended else ""
            print(f"  {p.id:<{width}}  {p.feed_count:>3} feeds  {p.title}{flags}")
            if p.requires:
                print(f"  {'':<{width}}  needs: {p.requires}")
        return

    chosen = [p.id for p in packs] if args.all else args.packs
    if unknown := [pid for pid in chosen if get_pack(pid) is None]:
        sys.exit(f"Unknown pack(s): {', '.join(unknown)}. Try --list.")

    async with async_session() as db:
        # Categories are created_by a user, and with per-user subscriptions on
        # the importer subscribes that user to what it adds. The instance owner
        # is the only sensible choice for a headless seed.
        owner = (
            await db.execute(select(User).where(User.role == "admin").order_by(User.created_at).limit(1))
        ).scalar_one_or_none()
        if owner is None:
            sys.exit("No admin user exists yet. Register the first account, then re-run.")

        totals = {"feeds_added": 0, "feeds_skipped": 0, "categories_created": 0}
        new_ids: list[str] = []
        for pack_id in dict.fromkeys(chosen):
            pack = get_pack(pack_id)
            root = ET.fromstring(pack.path().read_text())
            stats = await _import_opml_tree(root, owner, db, queue_fetches=False)
            for key in totals:
                totals[key] += stats[key]
            new_ids.extend(stats["new_feed_ids"])
            print(f"  {pack.id:<22} +{stats['feeds_added']:>3} added, {stats['feeds_skipped']:>3} already present")

        if args.dry_run:
            await db.rollback()
            print(
                f"\nWould add {totals['feeds_added']} feeds in "
                f"{totals['categories_created']} new categories "
                f"({totals['feeds_skipped']} already present). Dry run — nothing written."
            )
            return

        await db.commit()

    # After the commit, never before: a worker that picks the task up first
    # would go looking for a feed row that no transaction has published yet.
    if new_ids and not args.no_fetch:
        from app.workers.feed_tasks import fetch_feed

        for feed_id in new_ids:
            fetch_feed.delay(feed_id)

    print(
        f"\nSeeded {totals['feeds_added']} feeds in {totals['categories_created']} new categories "
        f"({totals['feeds_skipped']} already present)."
        + (f" Queued an initial fetch for {len(new_ids)}." if new_ids and not args.no_fetch else "")
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--list", action="store_true", help="Show the available packs and exit.")
    parser.add_argument(
        "--packs",
        type=lambda s: [p.strip() for p in s.split(",") if p.strip()],
        default=["core"],
        help="Comma-separated pack ids to seed (default: core).",
    )
    parser.add_argument("--all", action="store_true", help="Seed every pack.")
    parser.add_argument("--dry-run", action="store_true", help="Report what would change without writing.")
    parser.add_argument(
        "--no-fetch",
        action="store_true",
        help="Create the feeds but don't queue an initial fetch (they'll be picked up by the scheduler).",
    )
    asyncio.run(main(parser.parse_args()))
