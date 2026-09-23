"""Purge EntityRelationship rows that violate the semantic relationship matrix.

Dry-run by default — prints what would happen, grouped by (source_type,
relationship_type, target_type, source). Pass --apply to execute.

Rules:
- Rows with a legacy/unknown entity type on either side are
  deleted regardless of source.
- Machine rows (co_occurrence / auto_extracted) whose triple is outside
  ALLOWED_RELATIONSHIPS:
    * related_to rows whose flipped orientation IS allowed (ttp->cve,
      tool->malware) are flipped to the canonical direction; if the canonical
      row already exists, evidence is merged into it and the duplicate deleted.
    * everything else is deleted.
- Analyst rows (analyst_created / analyst_confirmed / analyst_rejected /
  external_feed) are never touched; violations are reported only.
- On --apply, all intelfeed:corr:* cache keys are flushed at the end.

Run inside the api container:
    docker compose -f docker-compose.prod.yml exec api \
        python scripts/maintenance/purge_invalid_relationships.py [--apply]
"""

import asyncio
import sys
from collections import Counter

sys.path.insert(0, "/app")

from sqlalchemy import delete, select

from app.database import async_session
from app.intelligence.relationship_matrix import ALLOWED_RELATIONSHIPS, is_allowed_relationship
from app.models.entity_relationship import EntityRelationship

MACHINE_SOURCES = {"co_occurrence", "auto_extracted"}
KNOWN_TYPES = (
    {st for st, _, _ in ALLOWED_RELATIONSHIPS}
    | {tt for _, _, tt in ALLOWED_RELATIONSHIPS}
    | {
        "country",
        "ttp",
        "mitigation",
    }
)

_CONFIDENCE_RANK = {"possible": 0, "probable": 1, "confirmed": 2}


async def main(apply: bool):
    deleted = Counter()
    flipped = Counter()
    merged = Counter()
    analyst_violations = Counter()

    async with async_session() as db:
        rows = (await db.execute(select(EntityRelationship))).scalars().all()
        print(f"Loaded {len(rows)} relationships")

        by_key = {
            (r.source_type, str(r.source_id), r.target_type, str(r.target_id), r.relationship_type): r for r in rows
        }
        to_delete: list[EntityRelationship] = []

        for rel in rows:
            combo = (rel.source_type, rel.relationship_type, rel.target_type, rel.source)

            if rel.source_type not in KNOWN_TYPES or rel.target_type not in KNOWN_TYPES:
                to_delete.append(rel)
                deleted[combo] += 1
                continue

            if is_allowed_relationship(rel.source_type, rel.relationship_type, rel.target_type):
                continue

            if rel.source not in MACHINE_SOURCES:
                analyst_violations[combo] += 1
                continue

            flippable = rel.relationship_type == "related_to" and is_allowed_relationship(
                rel.target_type, rel.relationship_type, rel.source_type
            )
            if not flippable:
                to_delete.append(rel)
                deleted[combo] += 1
                continue

            canonical_key = (
                rel.target_type,
                str(rel.target_id),
                rel.source_type,
                str(rel.source_id),
                rel.relationship_type,
            )
            existing = by_key.get(canonical_key)
            if existing is not None and existing.id != rel.id:
                # Merge evidence + confidence into the canonical row, drop this one
                ev = list(existing.evidence_entry_ids or [])
                ev += [e for e in (rel.evidence_entry_ids or []) if e not in ev]
                existing.evidence_entry_ids = ev
                if _CONFIDENCE_RANK.get(rel.confidence or "", 0) > _CONFIDENCE_RANK.get(existing.confidence or "", 0):
                    existing.confidence = rel.confidence
                to_delete.append(rel)
                merged[combo] += 1
            else:
                del by_key[
                    (rel.source_type, str(rel.source_id), rel.target_type, str(rel.target_id), rel.relationship_type)
                ]
                rel.source_type, rel.target_type = rel.target_type, rel.source_type
                rel.source_id, rel.target_id = rel.target_id, rel.source_id
                by_key[
                    (rel.source_type, str(rel.source_id), rel.target_type, str(rel.target_id), rel.relationship_type)
                ] = rel
                flipped[combo] += 1

        def report(title: str, counter: Counter):
            if not counter:
                return
            print(f"\n{title} ({sum(counter.values())} rows):")
            for (st, rt, tt, src), n in counter.most_common():
                print(f"  {n:>6}  {st} -> {rt} -> {tt}  [{src}]")

        report("DELETE", deleted)
        report("FLIP to canonical direction", flipped)
        report("MERGE into existing canonical row", merged)
        report("ANALYST-OWNED VIOLATIONS (left untouched)", analyst_violations)
        total_removed = sum(deleted.values()) + sum(merged.values())
        print(f"\nTotal: {total_removed} removed, {sum(flipped.values())} flipped, {len(rows) - total_removed} remain")

        if not apply:
            print("\nDRY RUN — no changes made. Re-run with --apply to execute.")
            return

        if to_delete:
            ids = [r.id for r in to_delete]
            for i in range(0, len(ids), 5000):
                await db.execute(delete(EntityRelationship).where(EntityRelationship.id.in_(ids[i : i + 5000])))
        await db.commit()
        print("Committed.")

    from app.services.redis_client import get_redis

    r = await get_redis()
    n = 0
    async for key in r.scan_iter(match="intelfeed:corr:*", count=500):
        await r.delete(key)
        n += 1
    print(f"Flushed {n} correlation cache keys.")


if __name__ == "__main__":
    asyncio.run(main(apply="--apply" in sys.argv))
