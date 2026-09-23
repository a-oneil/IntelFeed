#!/usr/bin/env python3
"""Move the do-not-recreate list between environments.

The list is two pieces of state that have to travel together:

  * ``entity_name_denylist`` rows — what the extract stage refuses to mint.
  * the names inside the ``autolinker_false_positive_names`` setting — what the
    autolinker refuses to match.

Deleting an entity with "don't re-create it" writes both, so a dev instance and
prod drift apart the moment you curate in one of them. Export from the instance
you curated in, import into the other.

    # in the source instance
    docker compose -f docker-compose.dev.yml exec -T api \
        python scripts/maintenance/sync_denylist.py --export /app/scripts/denylist.json

    # in the target instance
    docker compose -f docker-compose.prod.yml exec -T api \
        python scripts/maintenance/sync_denylist.py --import /app/scripts/denylist.json

Import is additive and never deletes: a name the target has and the source
doesn't is left alone. Rows upsert on (entity_type, normalized_name), and an
analyst ``do_not_recreate`` row upgrades a migration-seeded ``cleanup_2026_08``
one (that decision is stronger) but never the reverse.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, "/app")

from sqlalchemy import select  # noqa: E402
from sqlalchemy.dialects.postgresql import insert as pg_insert  # noqa: E402

from app.database import async_session  # noqa: E402
from app.intelligence.entity_resolution import (  # noqa: E402
    DO_NOT_RECREATE_SOURCE,
    sync_fp_names,
)
from app.models.entity_index import EntityNameDenylist  # noqa: E402
from app.services.system_settings import get_setting  # noqa: E402


async def export_list(path: Path) -> dict:
    async with async_session() as db:
        rows = (await db.execute(select(EntityNameDenylist).where(EntityNameDenylist.active.is_(True)))).scalars().all()
        raw = str(await get_setting("autolinker_false_positive_names", db) or "")

    payload = {
        "denylist": [
            {
                "entity_type": r.entity_type,
                "normalized_name": r.normalized_name,
                "display_name": r.display_name,
                "reason": r.reason,
                "source": r.source,
            }
            for r in sorted(rows, key=lambda r: (r.entity_type, r.normalized_name))
        ],
        "fp_names": sorted({n.strip().lower() for n in raw.split(",") if n.strip()}),
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False))
    return payload


async def import_list(path: Path, dry_run: bool) -> dict:
    payload = json.loads(path.read_text())
    incoming = payload.get("denylist", [])
    fp_names = payload.get("fp_names", [])

    async with async_session() as db:
        existing = {
            (r.entity_type, r.normalized_name): r
            for r in (await db.execute(select(EntityNameDenylist))).scalars().all()
        }

        added, upgraded, unchanged = 0, 0, 0
        for row in incoming:
            key = (row["entity_type"], row["normalized_name"])
            current = existing.get(key)
            if current is None:
                added += 1
            elif row["source"] == DO_NOT_RECREATE_SOURCE and current.source != DO_NOT_RECREATE_SOURCE:
                upgraded += 1
            else:
                unchanged += 1
                continue  # never downgrade an analyst row back to a seeded one

            if dry_run:
                continue
            stmt = pg_insert(EntityNameDenylist).values(
                entity_type=row["entity_type"],
                normalized_name=row["normalized_name"],
                display_name=row["display_name"],
                reason=row["reason"],
                source=row["source"],
                active=True,
            )
            await db.execute(
                stmt.on_conflict_do_update(
                    constraint="uq_entity_name_denylist",
                    set_={
                        "display_name": stmt.excluded.display_name,
                        "reason": stmt.excluded.reason,
                        "source": stmt.excluded.source,
                        "active": True,
                    },
                )
            )

        before = {
            n.strip().lower()
            for n in str(await get_setting("autolinker_false_positive_names", db) or "").split(",")
            if n.strip()
        }
        new_names = sorted(set(fp_names) - before)
        if not dry_run and new_names:
            await sync_fp_names(db, add=new_names)

        if dry_run:
            await db.rollback()
        else:
            await db.commit()
            # The vocabulary is built from live entities + the FP list; rebuild so
            # the new exclusions apply without waiting for the next sync.
            from app.intelligence.autolinker import refresh_vocabulary

            await refresh_vocabulary(db)

    return {
        "rows_added": added,
        "rows_upgraded": upgraded,
        "rows_unchanged": unchanged,
        "fp_names_added": new_names,
    }


async def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--export", metavar="FILE", help="Write this instance's list to FILE.")
    mode.add_argument("--import", dest="import_", metavar="FILE", help="Merge FILE into this instance.")
    ap.add_argument("--dry-run", action="store_true", help="Report what an import would change, then roll back.")
    args = ap.parse_args()

    if args.export:
        payload = await export_list(Path(args.export))
        print(f"Exported {len(payload['denylist'])} rows, {len(payload['fp_names'])} FP names -> {args.export}")
        return

    result = await import_list(Path(args.import_), args.dry_run)
    prefix = "[dry-run] would apply" if args.dry_run else "Applied"
    print(
        f"{prefix}: {result['rows_added']} new rows, {result['rows_upgraded']} upgraded to "
        f"{DO_NOT_RECREATE_SOURCE}, {result['rows_unchanged']} already current."
    )
    if result["fp_names_added"]:
        print(f"  FP names added ({len(result['fp_names_added'])}): {', '.join(result['fp_names_added'])}")
    else:
        print("  FP names already in sync.")


if __name__ == "__main__":
    asyncio.run(main())
