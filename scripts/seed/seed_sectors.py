"""Seed the sectors table from the controlled vocabulary in app.intelligence.sectors.

Run inside the api container:
    docker compose -f docker-compose.dev.yml exec api python scripts/seed/seed_sectors.py
    docker compose -f docker-compose.dev.yml exec api python scripts/seed/seed_sectors.py --dry-run

Idempotent: inserts any slug that is missing, refreshes aliases/description on the
rows that exist, never deletes. Ids are deterministic (sector_uuid), so a fresh
install and a long-lived one end up with identical rows. Sectors are never
autolinked, so unlike seed_countries.py this does not rebuild the autolinker
vocabulary.
"""

import argparse
import asyncio
import sys

sys.path.insert(0, "/app")

from sqlalchemy import select

from app.database import async_session
from app.intelligence.sectors import seed_rows
from app.models.sector import Sector


async def main(dry_run: bool) -> None:
    async with async_session() as db:
        existing = {
            s.slug: s for s in (await db.execute(select(Sector))).scalars().all()
        }
        created = updated = 0
        for row in seed_rows():
            current = existing.get(row["slug"])
            if current is None:
                db.add(Sector(**row))
                created += 1
                continue
            if (
                list(current.aliases or []) != row["aliases"]
                or current.description != row["description"]
            ):
                current.aliases = row["aliases"]
                current.description = row["description"]
                updated += 1

        if dry_run:
            await db.rollback()
            print(
                f"Would create {created} and refresh {updated} sectors. Dry run — nothing written."
            )
            return

        await db.commit()
        print(
            f"Seeded {created} new sectors, refreshed {updated}; {len(existing) + created} total."
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report what would change without writing.",
    )
    asyncio.run(main(parser.parse_args().dry_run))
