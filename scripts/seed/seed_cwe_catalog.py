"""Hydrate the full MITRE CWE catalog (weaknesses + categories).

Downloads cwec_latest.xml.zip from cwe.mitre.org and upserts every entry into
`cwes`: name, abstraction (Pillar/Class/Base/Variant/Compound), ChildOf parent
from research view 1000, mapping usage, alternate terms, CAPEC ids,
consequences, mitigations and detection methods.

Categories are seeded alongside weaknesses on purpose. NVD tagged CVEs with
category ids for years and MITRE marks every category `Prohibited` for mapping,
so a resolved link is what lets the UI say "this was never a valid mapping
target" instead of showing a dangling string.

Idempotent — re-running refreshes catalog fields in place and leaves
article_count / first_seen_at / last_seen_at alone. It also re-resolves any
cve_weaknesses rows whose ref had no catalog row when the backfill ran.

Run inside the api container:
    docker compose -f docker-compose.dev.yml exec api python scripts/seed/seed_cwe_catalog.py
    docker compose -f docker-compose.dev.yml exec api python scripts/seed/seed_cwe_catalog.py --dry-run
"""

import argparse
import asyncio
import sys

sys.path.insert(0, "/app")

from sqlalchemy import func, select  # noqa: E402

import app.models  # noqa: E402,F401 — register all mappers (Entry relationships)
from app.database import async_session  # noqa: E402
from app.intelligence.cwe_catalog import (  # noqa: E402
    fetch_cwe_catalog,
    hydrate_cwe_catalog,
    parse_cwe_catalog,
    resolve_cve_weakness_refs,
)
from app.models.cwe import CWE  # noqa: E402


async def main(dry_run: bool) -> None:
    async with async_session() as db:
        print("Downloading MITRE CWE catalog (cwec_latest.xml.zip)...")
        xml_bytes = await fetch_cwe_catalog(db)
        parsed = parse_cwe_catalog(xml_bytes)
        print(f"Parsed {len(parsed)} entries ({sum(1 for p in parsed if p.kind == 'weakness')} weaknesses)")

        stats = await hydrate_cwe_catalog(db, parsed)
        await db.flush()
        stats["refs_resolved"] = await resolve_cve_weakness_refs(db)

        for key, value in stats.items():
            print(f"  {key}: {value}")

        if dry_run:
            await db.rollback()
            print("\n[dry-run] rolled back")
            return

        await db.commit()

        total = (await db.execute(select(func.count()).select_from(CWE))).scalar_one()
        by_abstraction = (
            await db.execute(
                select(CWE.abstraction, func.count())
                .where(CWE.kind == "weakness")
                .group_by(CWE.abstraction)
                .order_by(func.count().desc())
            )
        ).all()
        print(f"\ncwes: {total} rows")
        for abstraction, count in by_abstraction:
            print(f"  {abstraction or '(none)'}: {count}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true", help="parse and report, then roll back")
    args = ap.parse_args()
    asyncio.run(main(args.dry_run))
