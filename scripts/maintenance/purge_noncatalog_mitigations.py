"""Reduce the mitigations table to the ATT&CK catalog.

Only catalog mitigations (``mitigations.is_catalog``, set by the ATT&CK
import) are entities: ``store_mitigations`` in ``app/intelligence/mitigation.py``
links an article to the catalog mitigation its advice falls under and keeps
the article's wording on the link (``entry_mitigations.detail``), and the
autolinker no longer matches mitigation names. Rows written before that — one
per AI recommendation ("Upgrade Lara Dashboard to 1.3.2"), generic phrases the
autolinker matched everywhere ("Patch", "monitoring"), invented M-IDs, the old
"<technique> Mitigation" rows — are still on file. This script:

    1. moves       AI / regex / manual links of a non-catalog row whose name is
                   exactly a catalog name onto that catalog row, keeping the old
                   name as the link's detail when it says more
    2. deletes     every non-catalog row, with its links and relationships,
                   through the review surfaces' own path
                   (``delete_named_entity``). No denylist rows: nothing creates
                   non-catalog mitigations any more, so there is nothing to block
    3. unlinks     ``auto_link`` links on catalog rows (name matches)
    4. relinks     catalog rows by explicit M-ID mention in existing articles
                   (the same backlink a new entity gets), unless --no-relink

Afterwards run ``recount_article_counts.py --type mitigation --apply``.

Dry run by default; nothing is written without ``--apply``. Run inside the api
container:

    docker compose -f docker-compose.prod.yml exec -T api \\
        python scripts/maintenance/purge_noncatalog_mitigations.py
    docker compose -f docker-compose.prod.yml exec -T api \\
        python scripts/maintenance/purge_noncatalog_mitigations.py --apply
"""

import argparse
import asyncio
import sys
from collections import Counter

sys.path.insert(0, "/app")

from sqlalchemy import delete, func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.api.extraction import delete_named_entity
from app.database import async_session
from app.intelligence.autolinker import (
    link_entity_to_existing_entries,
    refresh_vocabulary,
)
from app.models.mitigation import EntryMitigation, Mitigation

BATCH = 500


async def _catalog(db) -> tuple[list[Mitigation], dict[str, Mitigation]]:
    """Every catalog row, and lowercased name -> row with Enterprise (M1xxx)
    winning a name it shares with ICS ("Audit" is M1047 and M0947)."""
    rows = (
        (await db.execute(select(Mitigation).where(Mitigation.is_catalog.is_(True))))
        .scalars()
        .all()
    )
    by_name: dict[str, Mitigation] = {}
    for m in sorted(
        rows, key=lambda r: (not (r.mitre_id or "").startswith("M1"), r.mitre_id or "")
    ):
        by_name.setdefault(m.name.lower(), m)
    return list(rows), by_name


async def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--apply", action="store_true", help="write the changes (default: dry run)"
    )
    parser.add_argument(
        "--no-relink",
        action="store_true",
        help="skip the M-ID backlink of catalog rows",
    )
    args = parser.parse_args()

    async with async_session() as db:
        catalog_rows, catalog = await _catalog(db)
        if not catalog_rows:
            raise SystemExit(
                "ERROR: no catalog mitigations (is_catalog) — run the ATT&CK import first"
            )

        link_counts = dict(
            (
                await db.execute(
                    select(EntryMitigation.mitigation_id, func.count()).group_by(
                        EntryMitigation.mitigation_id
                    )
                )
            ).all()
        )
        doomed = (
            (
                await db.execute(
                    select(Mitigation).where(Mitigation.is_catalog.is_(False))
                )
            )
            .scalars()
            .all()
        )
        mapped = [
            (m, catalog[m.name.lower()]) for m in doomed if m.name.lower() in catalog
        ]
        auto_on_catalog = await db.scalar(
            select(func.count())
            .select_from(EntryMitigation)
            .join(Mitigation, Mitigation.id == EntryMitigation.mitigation_id)
            .where(
                Mitigation.is_catalog.is_(True), EntryMitigation.source == "auto_link"
            )
        )

        print(f"catalog mitigations:          {len(catalog_rows)}")
        print(
            f"non-catalog rows to delete:   {len(doomed)} "
            f"({sum(link_counts.get(m.id, 0) for m in doomed)} entry links)"
        )
        print(
            f"  name-matched to the catalog: {len(mapped)} (their non-autolink links move)"
        )
        print(f"auto_link links on catalog:   {auto_on_catalog}")
        top = Counter({m.name: link_counts.get(m.id, 0) for m in doomed}).most_common(
            15
        )
        print("largest rows going:", ", ".join(f"{n} ({c})" for n, c in top))
        if not args.apply:
            print("\ndry run — pass --apply to write")
            return 0

        moved = 0
        for old, target in mapped:
            links = (
                await db.execute(
                    select(EntryMitigation).where(
                        EntryMitigation.mitigation_id == old.id,
                        EntryMitigation.source != "auto_link",
                    )
                )
            ).scalars()
            for link in links:
                detail = link.detail or (old.description or None)
                result = await db.execute(
                    pg_insert(EntryMitigation)
                    .values(
                        entry_id=link.entry_id,
                        mitigation_id=target.id,
                        confidence=link.confidence,
                        source=link.source,
                        paragraph_indices=link.paragraph_indices,
                        detail=detail[:500] if detail else None,
                    )
                    .on_conflict_do_nothing()
                    .returning(EntryMitigation.entry_id)
                )
                moved += result.scalar_one_or_none() is not None
        await db.commit()
        print(f"moved {moved} links onto catalog rows")

        deleted = 0
        for m in doomed:
            await delete_named_entity(
                db, "mitigation", m, deny=False, reason="Non-catalog mitigation"
            )
            deleted += 1
            if deleted % BATCH == 0:
                await db.commit()
                print(f"  deleted {deleted}/{len(doomed)}", flush=True)
        await db.commit()
        print(f"deleted {deleted} non-catalog rows")

        result = await db.execute(
            delete(EntryMitigation)
            .where(EntryMitigation.source == "auto_link")
            .where(
                EntryMitigation.mitigation_id.in_(
                    select(Mitigation.id).where(Mitigation.is_catalog.is_(True))
                )
            )
        )
        await db.commit()
        print(f"removed {result.rowcount} auto_link links on catalog rows")

        if not args.no_relink:
            relinked = 0
            for m in catalog_rows:
                stats = await link_entity_to_existing_entries(db, "mitigation", m.id)
                relinked += stats.get("linked", 0)
            await db.commit()
            print(f"relinked {relinked} links by explicit M-ID mention")

        await refresh_vocabulary(db)
    print(
        "next: python scripts/maintenance/recount_article_counts.py --type mitigation --apply"
    )
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
