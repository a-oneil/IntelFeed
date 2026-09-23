"""Link existing entries to catalog weaknesses by scanning for CWE ids.

New entries get their CWE links from the autolinker's regex pass at ingest.
This sweep does the same for everything already in the corpus, so the entity
has article counts on day one instead of accumulating them over months.

Matches the id pattern only — the same rule the autolinker follows, and for the
same reason: the catalog's alternate terms ("UAF", "Type Confusion", "SQL
Injection") are exactly the dictionary words that caused the 2026-07 false
positive epidemic.

Ids that aren't in the catalog are skipped, never stubbed. Run the catalog
seeder first.

Run inside the api container:
    docker compose -f docker-compose.dev.yml exec api python scripts/maintenance/backfill_entry_cwes.py
    docker compose -f docker-compose.dev.yml exec api python scripts/maintenance/backfill_entry_cwes.py --dry-run
"""

import argparse
import asyncio
import sys
from collections import Counter

sys.path.insert(0, "/app")

from sqlalchemy import func, select  # noqa: E402
from sqlalchemy.dialects.postgresql import insert as pg_insert  # noqa: E402

import app.models  # noqa: E402,F401 — register all mappers (Entry relationships)
from app.database import async_session  # noqa: E402
from app.intelligence.autolinker import CWE_PATTERN, split_into_paragraphs  # noqa: E402
from app.models.cwe import CWE, EntryCWE  # noqa: E402
from app.models.entry import Entry  # noqa: E402

BATCH = 500


async def main(dry_run: bool, limit: int | None) -> None:
    async with async_session() as db:
        catalog = {row[0]: row[1] for row in (await db.execute(select(CWE.cwe_id, CWE.id))).all()}
        if not catalog:
            print("cwes is empty — run scripts/seed/seed_cwe_catalog.py first")
            return
        print(f"Catalog index: {len(catalog)} entries")

        total_entries = (await db.execute(select(func.count()).select_from(Entry))).scalar_one()
        print(f"Scanning {total_entries} entries in batches of {BATCH}...")

        scanned = matched_entries = links = 0
        unknown: Counter[str] = Counter()
        per_cwe: Counter[str] = Counter()
        offset = 0
        while True:
            batch = (
                await db.execute(
                    select(Entry.id, Entry.title, Entry.summary, Entry.content_text)
                    .order_by(Entry.created_at)
                    .offset(offset)
                    .limit(BATCH)
                )
            ).all()
            if not batch:
                break

            for entry_id, title, summary, content_text in batch:
                scanned += 1
                paragraphs = split_into_paragraphs(title or "", summary or "", content_text or "")
                # cwe_id -> paragraph indices, so a weakness named in three
                # places still yields one link carrying all three positions
                # (proximity scoring reads them).
                hits: dict[str, list[int]] = {}
                for para_idx, para_text in paragraphs:
                    for m in CWE_PATTERN.finditer(para_text):
                        hits.setdefault(m.group(), []).append(para_idx)
                if not hits:
                    continue

                wrote = False
                for cwe_ref, indices in hits.items():
                    cwe_pk = catalog.get(cwe_ref)
                    if cwe_pk is None:
                        unknown[cwe_ref] += 1
                        continue
                    result = await db.execute(
                        pg_insert(EntryCWE)
                        .values(
                            entry_id=entry_id,
                            cwe_id=cwe_pk,
                            confidence="high",
                            source="auto_link",
                            paragraph_indices=sorted(set(indices)),
                        )
                        .on_conflict_do_nothing()
                        .returning(EntryCWE.entry_id)
                    )
                    if result.scalar_one_or_none() is not None:
                        links += 1
                        per_cwe[cwe_ref] += 1
                        wrote = True
                if wrote:
                    matched_entries += 1

            await db.flush()
            offset += BATCH
            if offset % 10000 == 0:
                print(f"  {offset}/{total_entries} scanned, {links} links written")
            if limit and scanned >= limit:
                break

        print(f"\nScanned:          {scanned}")
        print(f"Entries matched:  {matched_entries}")
        print(f"Links written:    {links}")
        if unknown:
            print(f"Unknown ids:      {sum(unknown.values())} mentions of {len(unknown)} ids not in the catalog")
            print(f"  {', '.join(f'{k}×{v}' for k, v in unknown.most_common(8))}")
        print("\nTop weaknesses by article:")
        for cwe_ref, n in per_cwe.most_common(10):
            print(f"  {cwe_ref:10} {n}")

        if dry_run:
            await db.rollback()
            print("\n[dry-run] rolled back")
            return

        # article_count is the profile's headline number, so recompute it from
        # the junction rather than incrementing as we go — that way a re-run is
        # idempotent instead of doubling every count.
        await db.execute(
            CWE.__table__.update().values(
                article_count=select(func.count())
                .select_from(EntryCWE.__table__)
                .where(EntryCWE.cwe_id == CWE.id)
                .scalar_subquery()
            )
        )
        await db.commit()

        linked = (await db.execute(select(func.count()).select_from(CWE).where(CWE.article_count > 0))).scalar_one()
        print(f"\nentry_cwes: {links} new links · {linked} weaknesses now have articles")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true", help="scan and report, then roll back")
    ap.add_argument("--limit", type=int, help="stop after N entries (smoke test)")
    args = ap.parse_args()
    asyncio.run(main(args.dry_run, args.limit))
