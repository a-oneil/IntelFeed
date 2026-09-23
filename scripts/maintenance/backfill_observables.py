"""Backfill the observables ledger from the two pre-curated sources.

There is deliberately NO regex sweep over article prose here — that is what
killed IOC v1. The two safe directions are:

1. EntryTTP.observable_value rows — already AI-extracted in context, one value
   per technique claim. Upserted with their technique link kept.
2. ioc_list feed entries (C2-Tracker, C2IntelFeeds) — curated indicator lists
   whose raw bodies sit unparsed in entry.metadata["raw_content"].

Idempotent on (kind, value) + (entry, observable), so safe to re-run.

Run inside the api container:
    docker compose -f docker-compose.dev.yml exec api python scripts/maintenance/backfill_observables.py
    docker compose -f docker-compose.dev.yml exec api python scripts/maintenance/backfill_observables.py --dry-run
    docker compose -f docker-compose.dev.yml exec api python scripts/maintenance/backfill_observables.py --only ttp
"""

import argparse
import asyncio
import sys

sys.path.insert(0, "/app")

from sqlalchemy import func, select  # noqa: E402

import app.models  # noqa: E402,F401 — register all mappers (Entry relationships)
from app.database import async_session  # noqa: E402
from app.intelligence.observables import (  # noqa: E402
    ioc_list_path_allowed,
    ioc_list_path_tag,
    kind_for_ttp_observable,
    parse_ioc_list_body,
    store_ioc_list_observables,
    sync_observables_from_entry_ttps,
)
from app.models.entry import Entry  # noqa: E402
from app.models.observable import Observable  # noqa: E402
from app.models.ttp import EntryTTP  # noqa: E402


async def backfill_ttp_observables(db, dry_run: bool) -> None:
    total = (
        await db.execute(select(func.count()).select_from(EntryTTP).where(EntryTTP.observable_value.isnot(None)))
    ).scalar_one()
    if dry_run:
        rows = (
            await db.execute(
                select(EntryTTP.observable_type, EntryTTP.observable_value).where(EntryTTP.observable_value.isnot(None))
            )
        ).all()
        mappable = sum(1 for t, v in rows if kind_for_ttp_observable(t, v))
        print(f"[ttp] {total} EntryTTP rows carry an observable; {mappable} map onto ledger kinds (dry run)")
        return
    stored = await sync_observables_from_entry_ttps(db)
    await db.commit()
    print(f"[ttp] {total} junction observables scanned -> {stored} sightings upserted")


async def backfill_ioc_list_entries(db, dry_run: bool) -> None:
    rows = (
        await db.execute(
            select(Entry.id, Entry.metadata_, Entry.published_at).where(
                Entry.metadata_["content_type"].astext == "ioc_list"
            )
        )
    ).all()
    print(f"[ioc_list] {len(rows)} ioc_list entries found")
    stored = 0
    skipped_files: set[str] = set()
    for entry_id, metadata, published_at in rows:
        body = (metadata or {}).get("raw_content") or ""
        file_path = (metadata or {}).get("file_path")
        if not body:
            continue
        # Same gate order as the ingest worker: a tagged dual-use file ingests
        # (tagged) even when a deny fragment also matches its path.
        if ioc_list_path_tag(file_path) is None and not ioc_list_path_allowed(file_path):
            skipped_files.add(file_path or "?")
            continue
        if dry_run:
            stored += len(parse_ioc_list_body(body))
            continue
        # seen_at = the entry's publish date: a historical backfill must not
        # stamp every old indicator fresh and reset its decay clock.
        stored += await store_ioc_list_observables(db, entry_id, body, file_path=file_path, seen_at=published_at)
        await db.commit()
    if skipped_files:
        print(f"[ioc_list] skipped {len(skipped_files)} non-indicator files (whitelist/unverified/aggregate):")
        for f in sorted(skipped_files):
            print(f"  - {f}")
    verb = "would create/sight" if dry_run else "created/sighted"
    print(f"[ioc_list] {verb} {stored} observables")


async def main(dry_run: bool, only: str | None) -> None:
    async with async_session() as db:
        if only in (None, "ttp"):
            await backfill_ttp_observables(db, dry_run)
        if only in (None, "ioc_list"):
            await backfill_ioc_list_entries(db, dry_run)
        total = (await db.execute(select(func.count()).select_from(Observable))).scalar_one()
        print(f"[done] ledger now holds {total} observables")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="Count without writing")
    parser.add_argument("--only", choices=["ttp", "ioc_list"], help="Run a single source")
    args = parser.parse_args()
    asyncio.run(main(args.dry_run, args.only))
