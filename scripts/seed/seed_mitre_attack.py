"""Hydrate the full MITRE ATT&CK catalog (Enterprise + Mobile + ICS).

Downloads the official STIX 2.1 bundles from mitre-attack/attack-stix-data and
upserts techniques (names, tactics, platforms, data sources, parent linkage,
deprecation flags, matrix domain), mitigations, and TTP-mitigation links.

Idempotent — updates existing rows in place, so it also backfills stub TTP
rows created by regex extraction (technique_name == technique_id).

Run inside the api container:
    docker compose -f docker-compose.dev.yml exec api python scripts/seed/seed_mitre_attack.py
    docker compose -f docker-compose.dev.yml exec api python scripts/seed/seed_mitre_attack.py --dry-run

--dry-run still downloads and parses the bundles (there is no other way to know
what would change), but rolls the database write back.
"""

import argparse
import asyncio
import sys

sys.path.insert(0, "/app")

from sqlalchemy import func, select  # noqa: E402

import app.models  # noqa: E402,F401 — register all mappers (Entry relationships)
from app.database import async_session  # noqa: E402
from app.intelligence.attack_catalog import (  # noqa: E402
    fetch_attack_bundles,
    hydrate_attack_catalog,
    hydrate_attack_entity_attributes,
    parse_attack_bundle,
    refresh_attack_catalog,
)
from app.models.ttp import TTP  # noqa: E402


async def main(dry_run: bool) -> None:
    async with async_session() as db:
        print("Downloading ATT&CK STIX bundles (enterprise, mobile, ics)...")
        if dry_run:
            # refresh_attack_catalog() commits, so a caller-level rollback could not
            # undo it. Run its three steps inline instead: hydrate only flushes, so
            # the stats below are real and the rollback discards every write.
            bundles = await fetch_attack_bundles(db)
            parsed = [parse_attack_bundle(bundle, domain) for domain, bundle in bundles.items()]
            stats = await hydrate_attack_catalog(db, parsed)
            stats["entity_attributes"] = await hydrate_attack_entity_attributes(db, parsed)
        else:
            stats = await refresh_attack_catalog(db)

        for domain, domain_stats in stats.items():
            print(f"[{domain}]")
            for key, value in domain_stats.items():
                print(f"  {key}: {value}")

        broken = await db.execute(select(func.count()).select_from(TTP).where(TTP.technique_name == TTP.technique_id))
        total = await db.execute(select(func.count()).select_from(TTP))
        hydrated = await db.execute(select(func.count()).select_from(TTP).where(TTP.matrix_domain.is_not(None)))
        print(f"\nttps rows total: {total.scalar()}")
        print(f"ttps rows hydrated from catalog: {hydrated.scalar()}")
        print(f"ttps rows still named by their ID (unknown to ATT&CK): {broken.scalar()}")

        if dry_run:
            await db.rollback()
            print("\nDry run — nothing written. (Counts above are post-hydration, pre-rollback.)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Download and parse the bundles, report what would change, then roll back.",
    )
    asyncio.run(main(parser.parse_args().dry_run))
