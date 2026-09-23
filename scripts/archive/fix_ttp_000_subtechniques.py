"""Merge/rename invalid ".000" TTP sub-techniques into their parent technique.

Valid ATT&CK sub-techniques are .001+; a bare technique has no suffix. A ".000"
row is always an extraction artefact.

Historical: TTP extraction now rejects ".000" at the source
(app/intelligence/ttp.py), so this only matters for a database that predates
that fix. Idempotent — a no-op once clean.

Run inside the api container:
    docker compose -f docker-compose.dev.yml exec api \
        python scripts/archive/fix_ttp_000_subtechniques.py --dry-run
    docker compose -f docker-compose.dev.yml exec api \
        python scripts/archive/fix_ttp_000_subtechniques.py
"""

import argparse
import asyncio
import sys

sys.path.insert(0, "/app")

from sqlalchemy import text

from app.database import async_session


async def main(dry_run: bool) -> None:
    async with async_session() as db:
        rows = (await db.execute(text(r"SELECT id, technique_id FROM ttps WHERE technique_id ~ '\.000$'"))).all()
        print(f"Found {len(rows)} TTP(s) with an invalid .000 suffix")

        merged = renamed = 0
        for ttp_id, technique_id in rows:
            parent_technique_id = technique_id[:-4]
            parent = (
                await db.execute(
                    text("SELECT id FROM ttps WHERE technique_id = :tid"),
                    {"tid": parent_technique_id},
                )
            ).scalar_one_or_none()

            if parent:
                print(f"Merging {technique_id} into existing {parent_technique_id}")
                merged += 1
                if dry_run:
                    continue
                # Move entry links to the parent, skipping entries already linked.
                await db.execute(
                    text("""
                        INSERT INTO entry_ttps
                            (entry_id, ttp_id, confidence, source_text, extracted_at, paragraph_indices)
                        SELECT entry_id, :parent, confidence, source_text, extracted_at, paragraph_indices
                        FROM entry_ttps WHERE ttp_id = :old
                        ON CONFLICT (entry_id, ttp_id) DO NOTHING
                    """),
                    {"parent": parent, "old": ttp_id},
                )
                # Move mitigation links to the parent.
                await db.execute(
                    text("""
                        INSERT INTO ttp_mitigations (ttp_id, mitigation_id, created_at)
                        SELECT :parent, mitigation_id, created_at
                        FROM ttp_mitigations WHERE ttp_id = :old
                        ON CONFLICT (ttp_id, mitigation_id) DO NOTHING
                    """),
                    {"parent": parent, "old": ttp_id},
                )
                # Widen the parent's seen window to cover the merged TTP.
                await db.execute(
                    text("""
                        UPDATE ttps SET
                            first_seen_at = LEAST(ttps.first_seen_at, sub.first_seen_at),
                            last_seen_at = GREATEST(ttps.last_seen_at, sub.last_seen_at)
                        FROM (SELECT first_seen_at, last_seen_at FROM ttps WHERE id = :old) AS sub
                        WHERE ttps.id = :parent
                    """),
                    {"parent": parent, "old": ttp_id},
                )
                # Drop the .000 row (cascades its remaining junctions), then
                # recompute the parent's article_count from actual entry links.
                await db.execute(text("DELETE FROM ttps WHERE id = :old"), {"old": ttp_id})
                await db.execute(
                    text("""
                        UPDATE ttps
                        SET article_count = (SELECT COUNT(*) FROM entry_ttps WHERE ttp_id = :parent)
                        WHERE id = :parent
                    """),
                    {"parent": parent},
                )
            else:
                print(f"Renaming {technique_id} -> {parent_technique_id}")
                renamed += 1
                if dry_run:
                    continue
                await db.execute(
                    text("""
                        UPDATE ttps SET
                            technique_id = :new,
                            technique_name = CASE WHEN technique_name = :old_tid THEN :new ELSE technique_name END,
                            is_subtechnique = FALSE,
                            mitre_url = CASE WHEN mitre_url LIKE '%/000%' THEN NULL ELSE mitre_url END
                        WHERE id = :id
                    """),
                    {"new": parent_technique_id, "old_tid": technique_id, "id": ttp_id},
                )

        print(f"Merged into existing parent: {merged}")
        print(f"Renamed to parent technique: {renamed}")

        if dry_run:
            await db.rollback()
            print("Dry run — no changes committed.")
        else:
            await db.commit()
            print("Done.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="Report changes without writing.")
    asyncio.run(main(parser.parse_args().dry_run))
