"""Seed log_type_alias and telemetry_sources.log_types_canonical.

telemetry_sources.log_types is vendor free text — 864 distinct strings over
1,124 assignments, 721 of them used exactly once — so "authentication",
"authentication_event", "login_event" and "login_success" name one behaviour
and match four different sets of products. This flattens every raw string onto
the canonical behaviour axis in app/services/detection_coverage.py, writes the
map into log_type_alias, and stores each source's ids on
log_types_canonical so the matcher reads them instead of re-deriving them.

The mapping is a deterministic table + keyword rules, not a model call: the
matcher canonicalises rule-side tokens with the same function, and the two
sides can only agree if the answer is reproducible. Edit the table in
detection_coverage.py and re-run; rows whose canonical id changed are updated,
hand-added rows for strings the table doesn't know are left alone.

Run inside the api container:
    docker compose -f docker-compose.dev.yml exec api python scripts/seed/seed_log_type_aliases.py --dry-run
    docker compose -f docker-compose.dev.yml exec api python scripts/seed/seed_log_type_aliases.py
"""

import argparse
import asyncio
import sys

sys.path.insert(0, "/app")

from sqlalchemy import select

from app.api.telemetry_sources import DATA_SOURCE_CATALOG
from app.database import async_session
from app.models.log_type_alias import LogTypeAlias
from app.models.telemetry_source import TelemetrySource
from app.services.detection_coverage import canonical_log_type


def _raw_strings(sources: list[TelemetrySource]) -> set[str]:
    """Every log-type string worth an alias row.

    The catalog is included as well as the inventory so a fresh install seeds
    the full vocabulary before anyone ticks a box.
    """
    raws = {lt.strip() for s in sources for lt in (s.log_types or []) if lt and lt.strip()}
    raws |= {lt.strip() for item in DATA_SOURCE_CATALOG for lt in item.get("log_types", []) if lt and lt.strip()}
    return raws


async def main(dry_run: bool) -> None:
    async with async_session() as db:
        sources = (await db.execute(select(TelemetrySource))).scalars().all()
        existing = {a.raw: a for a in (await db.execute(select(LogTypeAlias))).scalars().all()}

        raws = _raw_strings(sources)
        unmapped = sorted(r for r in raws if not canonical_log_type(r))

        created = updated = unchanged = 0
        for raw in sorted(raws):
            canonical = canonical_log_type(raw)
            if not canonical:
                continue
            row = existing.get(raw)
            if row is None:
                db.add(LogTypeAlias(raw=raw[:120], canonical=canonical))
                created += 1
            elif row.canonical != canonical:
                row.canonical = canonical
                updated += 1
            else:
                unchanged += 1

        print(f"Aliases: {created} created, {updated} updated, {unchanged} unchanged ({len(raws)} raw strings).")
        if unmapped:
            # An unmapped string is an invisible source: nothing a rule asks for
            # will ever reach it through the behaviour axis.
            print(f"\nNo canonical id for {len(unmapped)} string(s) — add them to _LOG_TYPE_EXACT:")
            for raw in unmapped:
                print(f"  {raw}")

        # Re-derive every source's ids from its own raw strings, including rows
        # a hand-curated alias covers that the table does not.
        by_raw = {**{r: canonical_log_type(r) for r in raws}, **{k: v.canonical for k, v in existing.items()}}
        touched = 0
        for source in sources:
            ids = sorted({c for lt in (source.log_types or []) if (c := by_raw.get(lt.strip()))})
            if ids != list(source.log_types_canonical or []):
                source.log_types_canonical = ids
                touched += 1
        print(f"\nlog_types_canonical rewritten on {touched} / {len(sources)} telemetry sources.")

        if dry_run:
            await db.rollback()
            print("Dry run — nothing written.")
        else:
            await db.commit()
            print("Done.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="Report changes without writing.")
    args = parser.parse_args()
    asyncio.run(main(args.dry_run))
