"""Delete machine-made relationship edges that nobody judged before the adjudicator existed.

The adjudicator reviews an edge only when an article that is evidence for it
goes through review (``_edge_items`` in ``app/services/entry_adjudication.py``).
Two groups therefore never get a verdict and sit in Review's Relationships lens
for good:

    * edges with no article evidence at all (the profile import's
      ``--extract-relationships`` pass, 2026-07-10)
    * edges created before the adjudication stage shipped (2026-10-19) whose
      articles were never reviewed

This deletes ``auto_extracted`` / ``co_occurrence`` edges with no verdict,
created before ``--before`` (default 2026-10-19), plus every such edge with no
evidence regardless of date. An edge the reviewer kept at least once is left
alone, as is anything an analyst, the MITRE import or enrichment made. The
rows are deleted, not rejected, so a real relationship comes back the next
time an article asserts it.

Dry run by default; nothing is written without ``--apply``. Run inside the api
container:

    docker compose -f docker-compose.prod.yml exec -T api \\
        python scripts/maintenance/purge_unjudged_relationships.py
    docker compose -f docker-compose.prod.yml exec -T api \\
        python scripts/maintenance/purge_unjudged_relationships.py --apply
"""

import argparse
import asyncio
import sys
from datetime import UTC, datetime

sys.path.insert(0, "/app")

from sqlalchemy import delete, func, or_, select

from app.database import async_session
from app.models.entity_relationship import EntityRelationship
from app.services.entry_adjudication import REVIEWABLE_EDGE_SOURCES

BATCH = 5000


async def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--apply", action="store_true", help="write the changes (default: dry run)"
    )
    parser.add_argument(
        "--before",
        default="2026-10-19",
        help="delete unjudged edges created before this date (YYYY-MM-DD; default: the adjudicator's release)",
    )
    args = parser.parse_args()
    before = datetime.fromisoformat(args.before).replace(tzinfo=UTC)

    evidence_n = func.coalesce(
        func.array_length(EntityRelationship.evidence_entry_ids, 1), 0
    )
    kept_n = func.coalesce(
        func.array_length(EntityRelationship.reviewer_kept_entry_ids, 1), 0
    )
    no_evidence = evidence_n == 0
    condition = (
        EntityRelationship.source.in_(REVIEWABLE_EDGE_SOURCES)
        & EntityRelationship.adjudication_verdict.is_(None)
        & (kept_n == 0)
        & or_(no_evidence, EntityRelationship.created_at < before)
    )

    async with async_session() as db:
        rows = (
            await db.execute(
                select(
                    EntityRelationship.source,
                    no_evidence.label("no_evidence"),
                    func.count(),
                )
                .where(condition)
                .group_by(EntityRelationship.source, no_evidence)
                .order_by(EntityRelationship.source)
            )
        ).all()
        total = sum(n for *_, n in rows)
        print(
            f"unjudged machine edges to delete (no evidence, or created before {args.before}): {total}"
        )
        for source, none, n in rows:
            print(
                f"  {n:>6}  {source:<15} {'no article evidence' if none else 'older, never reviewed'}"
            )
        if not args.apply:
            print("\ndry run — pass --apply to write")
            return 0

        ids = (
            (await db.execute(select(EntityRelationship.id).where(condition)))
            .scalars()
            .all()
        )
        for i in range(0, len(ids), BATCH):
            await db.execute(
                delete(EntityRelationship).where(
                    EntityRelationship.id.in_(ids[i : i + BATCH])
                )
            )
            await db.commit()
            print(f"  deleted {min(i + BATCH, len(ids))}/{len(ids)}", flush=True)

    from app.services.redis_client import get_redis

    r = await get_redis()
    n = 0
    async for key in r.scan_iter(match="intelfeed:corr:*", count=500):
        await r.delete(key)
        n += 1
    print(f"flushed {n} correlation cache keys")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
