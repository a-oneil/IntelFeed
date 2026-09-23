"""Re-derive cve_weaknesses rows from every stored nvd_data blob.

The NVD `weaknesses` block has been collected on every CVE since enrichment
began but was never parsed — only the first CWE string was ever read, and only
for display. This sweep turns all of it into rows.

Idempotent on (cve_id, cwe_ref), so it is safe to re-run: rows that already
exist get their FK filled if the catalog has since gained the entry, and a
Primary assignment is never demoted.

Run inside the api container (seed the catalog first, or refs land unresolved
and you will need a second pass):
    docker compose -f docker-compose.dev.yml exec api python scripts/seed/seed_cwe_catalog.py
    docker compose -f docker-compose.dev.yml exec api python scripts/maintenance/backfill_cve_weaknesses.py
    docker compose -f docker-compose.dev.yml exec api python scripts/maintenance/backfill_cve_weaknesses.py --dry-run
"""

import argparse
import asyncio
import sys

sys.path.insert(0, "/app")

from sqlalchemy import func, select  # noqa: E402

import app.models  # noqa: E402,F401 — register all mappers (Entry relationships)
from app.database import async_session  # noqa: E402
from app.intelligence.cve import build_cwe_index, parse_nvd_weaknesses, sync_cve_weaknesses  # noqa: E402
from app.models.cve import CVE  # noqa: E402
from app.models.cwe import CVEWeakness  # noqa: E402

BATCH = 500


async def main(dry_run: bool, limit: int | None) -> None:
    async with async_session() as db:
        index = await build_cwe_index(db)
        if not index:
            print("cwes is empty — run scripts/seed/seed_cwe_catalog.py first")
            return
        print(f"Catalog index: {len(index)} entries")

        total_cves = (await db.execute(select(func.count()).select_from(CVE))).scalar_one()
        print(f"Scanning {total_cves} CVEs in batches of {BATCH}...")

        scanned = rows_written = with_weakness = unresolved = 0
        offset = 0
        while True:
            batch = (
                await db.execute(select(CVE.id, CVE.nvd_data).order_by(CVE.cve_id).offset(offset).limit(BATCH))
            ).all()
            if not batch:
                break
            for cve_pk, nvd_data in batch:
                scanned += 1
                parsed = parse_nvd_weaknesses(nvd_data or {})
                if not parsed:
                    continue
                with_weakness += 1
                unresolved += sum(1 for p in parsed if p["cwe_ref"] not in index)
                rows_written += await sync_cve_weaknesses(db, cve_pk, parsed, index)
            await db.flush()
            offset += BATCH
            if offset % 5000 == 0:
                print(f"  {offset}/{total_cves} scanned, {rows_written} links written")
            if limit and scanned >= limit:
                break

        print(f"\nScanned:            {scanned}")
        print(f"CVEs with weakness: {with_weakness}")
        print(f"Links written:      {rows_written}")
        print(f"Unresolved refs:    {unresolved}  (NVD-CWE-noinfo/Other, or ids MITRE has not published)")

        if dry_run:
            await db.rollback()
            print("\n[dry-run] rolled back")
            return

        await db.commit()

        stored = (await db.execute(select(func.count()).select_from(CVEWeakness))).scalar_one()
        resolved = (
            await db.execute(select(func.count()).select_from(CVEWeakness).where(CVEWeakness.cwe_id_fk.isnot(None)))
        ).scalar_one()
        print(f"\ncve_weaknesses: {stored} rows, {resolved} resolved to a catalog entry")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true", help="parse and report, then roll back")
    ap.add_argument("--limit", type=int, help="stop after N CVEs (smoke test)")
    args = ap.parse_args()
    asyncio.run(main(args.dry_run, args.limit))
