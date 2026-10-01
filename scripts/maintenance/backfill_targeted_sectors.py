"""Fold the legacy free-text ``targeted_sectors`` arrays into the target-sector junctions.

Actors and malware families carry a ``targeted_sectors`` ARRAY(Text) that six
write paths filled over two years: ~435 distinct strings for a 21-slug
vocabulary — canonical labels, near duplicates, geography, asset classes and
single-character fragments. The sector entity makes the junction tables
(``threat_actor_target_sectors`` / ``malware_target_sectors``) the source of
truth and the array a cache, so this one-shot pass:

1. classifies every stored value (app.intelligence.sector_backfill.classify);
2. writes a ``source="seed"`` junction row for each value that maps to a sector
   (the rollup never prunes seed rows; an analyst can);
3. optionally rehomes values that are really a *country* onto
   ``threat_actor_target_countries`` (``--rehome-countries``, actors only);
4. rebuilds the array cache from the junction, so the free text is gone by
   construction and every chip is one of the 21 labels;
5. writes a CSV of every distinct value, its count, the decision and the target
   it mapped to, so the drops can be reviewed.

Idempotent: a second run finds the junction rows already present and the cache
already clean. Run it in prod, not dev, and read the dry-run report first:

    docker compose -f docker-compose.prod.yml exec api python scripts/maintenance/backfill_targeted_sectors.py \\
        --dry-run --report /app/scripts/backfill_sectors.csv
    docker compose -f docker-compose.prod.yml exec api python scripts/maintenance/backfill_targeted_sectors.py \\
        --rehome-countries --report /app/scripts/backfill_sectors.csv
"""

import argparse
import asyncio
import csv
import sys
from collections import Counter

sys.path.insert(0, "/app")

from sqlalchemy import func, select  # noqa: E402

import app.models  # noqa: E402,F401 — register all mappers
from app.database import async_session  # noqa: E402
from app.intelligence.sector_backfill import Decision, classify  # noqa: E402
from app.intelligence.sectors import sector_uuid  # noqa: E402
from app.models.country import Country  # noqa: E402
from app.models.country_junction import ThreatActorTargetCountry  # noqa: E402
from app.models.malware_family import MalwareFamily  # noqa: E402
from app.models.threat_actor import ThreatActor  # noqa: E402
from app.services.sector_links import add_target_sector, refresh_targeted_sectors_cache  # noqa: E402


async def _country_index(db) -> tuple[set[str], dict[str, object]]:
    """Lowercased country names and aliases -> country id."""
    rows = (
        await db.execute(
            select(Country.id, Country.name, Country.iso_code, Country.aliases)
        )
    ).all()
    by_name: dict[str, object] = {}
    for cid, name, iso, aliases in rows:
        by_name[name.lower()] = cid
        # Bare ISO codes ("FR", "RU") were stored as sectors too.
        if iso:
            by_name.setdefault(iso.lower(), cid)
        for alias in aliases or []:
            by_name.setdefault(alias.lower(), cid)
    return set(by_name), by_name


async def main(dry_run: bool, report: str | None, rehome_countries: bool) -> None:
    async with async_session() as db:
        names, country_ids = await _country_index(db)
        decisions: dict[str, Decision] = {}
        counts: Counter = Counter()
        outcome: Counter = Counter()
        junction_rows = 0
        country_rows = 0
        entities_touched = 0

        for entity_type, model in (
            ("threat_actor", ThreatActor),
            ("malware", MalwareFamily),
        ):
            rows = (
                (
                    await db.execute(
                        select(model).where(
                            func.cardinality(model.targeted_sectors) > 0
                        )
                    )
                )
                .scalars()
                .all()
            )
            for entity in rows:
                mapped_slugs: list[str] = []
                rehome: list[object] = []
                for value in entity.targeted_sectors or []:
                    if not isinstance(value, str):
                        continue
                    counts[value] += 1
                    d = decisions.get(value)
                    if d is None:
                        d = decisions[value] = classify(value, names)
                    outcome[d.kind] += 1
                    if d.kind == "mapped" and d.slug:
                        mapped_slugs.append(d.slug)
                    elif (
                        d.kind == "rehomed_country"
                        and d.country
                        and rehome_countries
                        and entity_type == "threat_actor"
                    ):
                        rehome.append(country_ids[d.country])

                for slug in dict.fromkeys(mapped_slugs):
                    if await add_target_sector(
                        db, entity_type, entity.id, sector_uuid(slug), "seed"
                    ):
                        junction_rows += 1
                for cid in dict.fromkeys(rehome):
                    exists = await db.execute(
                        select(ThreatActorTargetCountry).where(
                            ThreatActorTargetCountry.threat_actor_id == entity.id,
                            ThreatActorTargetCountry.country_id == cid,
                        )
                    )
                    if exists.scalar_one_or_none() is None:
                        db.add(
                            ThreatActorTargetCountry(
                                threat_actor_id=entity.id, country_id=cid
                            )
                        )
                        country_rows += 1
                before = list(entity.targeted_sectors or [])
                after = await refresh_targeted_sectors_cache(db, entity_type, entity)
                if before != after:
                    entities_touched += 1

        if report:
            with open(report, "w", newline="") as fh:
                w = csv.writer(fh)
                w.writerow(["value", "count", "decision", "target"])
                for value, n in counts.most_common():
                    d = decisions[value]
                    w.writerow([value, n, d.kind, d.slug or d.country or ""])
            print(f"Report: {report} ({len(counts)} distinct values)")

        print(f"Distinct values: {len(counts)}; cells: {sum(counts.values())}")
        for kind, n in sorted(outcome.items(), key=lambda kv: -kv[1]):
            print(f"  {kind:17} {n}")
        print(
            f"Junction rows added: {junction_rows}; country rows rehomed: {country_rows}"
        )
        print(f"Entities whose sector cache changed: {entities_touched}")

        if dry_run:
            await db.rollback()
            print("Dry run — nothing written.")
            return
        await db.commit()
        print("Committed.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Classify and report without writing."
    )
    parser.add_argument(
        "--report", help="Write a CSV of every distinct value and its decision here."
    )
    parser.add_argument(
        "--rehome-countries",
        action="store_true",
        help="Move values that name a country onto threat_actor_target_countries instead of dropping them.",
    )
    args = parser.parse_args()
    asyncio.run(main(args.dry_run, args.report, args.rehome_countries))
