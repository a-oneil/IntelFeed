"""Recount every entity's stored ``article_count`` from its entry links.

``article_count`` is a cached number: each write path bumps or decrements it
by one, and any path that forgot (alias edits, bulk unlinks, merges, an
autolinker that linked the same entry twice) leaves it wrong for good. This
script counts the distinct entries in each type's junction table and writes
that number back where the two disagree.

It also refreshes what copies the number: the Meilisearch entity documents of
the rows it changed (vendor and product have none), and the cached pivots and
graphs (``intelfeed:corr:*``).

Observables are left out: their ``article_count`` mirrors the sighting count,
which the nightly ``reconcile_observable_counters`` task keeps. CVEs store no
count.

Dry-run by default; pass --apply to write. Idempotent.

Run inside the api container:

    docker compose -f docker-compose.prod.yml exec -T api \\
        python scripts/maintenance/recount_article_counts.py
    docker compose -f docker-compose.prod.yml exec -T api \\
        python scripts/maintenance/recount_article_counts.py --apply
    # one type, or one entity (UUID or exact name, case-insensitive)
    docker compose -f docker-compose.prod.yml exec -T api \\
        python scripts/maintenance/recount_article_counts.py --type tool --entity TerminalFix --apply
"""

import argparse
import asyncio
import sys
import uuid

sys.path.insert(0, "/app")

from sqlalchemy import func, or_, select, update

import app.models  # noqa: F401  (register every mapper)
from app.database import async_session
from app.intelligence.correlation import ENTITY_CONFIG

BATCH_SIZE = 1000
# Types whose count has another owner (see the docstring).
SKIPPED_TYPES = {"observable"}


def countable_types() -> list[str]:
    """Entity types with a stored article_count and an entry junction."""
    return [
        etype
        for etype, (model, _junction, _fk) in ENTITY_CONFIG.items()
        if etype not in SKIPPED_TYPES and hasattr(model, "article_count")
    ]


def _label_column(model):
    for attr in ("name", "technique_id", "cwe_id", "value"):
        if hasattr(model, attr):
            return getattr(model, attr)
    return model.id


def _entity_filter(model, entity: str):
    try:
        return model.id == uuid.UUID(entity)
    except ValueError:
        label = _label_column(model)
        return func.lower(label) == entity.lower()


async def drift_for_type(db, etype: str, entity: str | None) -> list[tuple[uuid.UUID, str, int, int]]:
    """(id, label, stored, live) for every row of ``etype`` whose count is wrong."""
    model, junction, fk_col = ENTITY_CONFIG[etype]
    live = (
        select(fk_col.label("eid"), func.count(func.distinct(junction.entry_id)).label("cnt"))
        .group_by(fk_col)
        .subquery()
    )
    live_cnt = func.coalesce(live.c.cnt, 0)
    q = (
        select(model.id, _label_column(model), model.article_count, live_cnt)
        .outerjoin(live, live.c.eid == model.id)
        .where(or_(model.article_count.is_(None), model.article_count != live_cnt))
    )
    if entity:
        q = q.where(_entity_filter(model, entity))
    rows = (await db.execute(q)).all()
    return [(r[0], str(r[1]), int(r[2] or 0), int(r[3])) for r in rows]


async def fix_type(db, etype: str, ids: list[uuid.UUID]) -> int:
    """Write the live count onto ``ids``, a batch at a time. Counted in SQL at
    write time, so a link added since the scan is not lost."""
    model, junction, fk_col = ENTITY_CONFIG[etype]
    live = (
        select(func.count(func.distinct(junction.entry_id)))
        .where(fk_col == model.id)
        .correlate(model)
        .scalar_subquery()
    )
    changed = 0
    for i in range(0, len(ids), BATCH_SIZE):
        chunk = ids[i : i + BATCH_SIZE]
        res = await db.execute(update(model).where(model.id.in_(chunk)).values(article_count=live))
        changed += res.rowcount or 0
        await db.commit()
    return changed


async def refresh_copies(db, changed: dict[str, list[uuid.UUID]]) -> None:
    from app.services.entity_indexer import index_entities

    try:
        n = await index_entities(db, changed)
        print(f"Re-indexed {n} search documents.")
    except Exception as e:  # search is best effort; the DB fix stands
        print(f"Search re-index failed ({e}); run rebuild_search_indexes.py --entities-only.")
    try:
        from app.services.redis_client import get_redis

        r = await get_redis()
        n = 0
        async for key in r.scan_iter(match="intelfeed:corr:*", count=500):
            await r.delete(key)
            n += 1
        print(f"Flushed {n} correlation cache keys.")
    except Exception as e:
        print(f"Correlation cache flush failed ({e}); it expires on its own.")


async def main(types: list[str], entity: str | None, apply: bool, top: int) -> None:
    changed: dict[str, list[uuid.UUID]] = {}
    total = 0
    async with async_session() as db:
        for etype in types:
            drift = await drift_for_type(db, etype, entity)
            if not drift:
                print(f"{etype:13} ok")
                continue
            over = sum(1 for _, _, stored, live in drift if stored > live)
            print(f"{etype:13} {len(drift)} wrong ({over} too high, {len(drift) - over} too low)")
            drift.sort(key=lambda d: -abs(d[2] - d[3]))
            for _eid, label, stored, live in drift[:top]:
                print(f"    {stored:>7} -> {live:<7} {label}")
            total += len(drift)
            if apply:
                ids = [d[0] for d in drift]
                await fix_type(db, etype, ids)
                changed[etype] = ids

        print(f"\nTotal: {total} entities with a wrong article_count.")
        if not apply:
            print("DRY RUN — nothing written. Re-run with --apply to fix.")
            return
        print(f"Fixed {total}.")
        if changed:
            await refresh_copies(db, changed)


def cli() -> None:
    types = countable_types()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apply", action="store_true", help="Write the corrected counts (default: report only).")
    ap.add_argument("--type", choices=types, help="Only this entity type.")
    ap.add_argument("--entity", help="Only this entity: UUID or exact name (needs --type).")
    ap.add_argument("--top", type=int, default=15, help="Show this many of the worst rows per type.")
    args = ap.parse_args()
    if args.entity and not args.type:
        ap.error("--entity needs --type")
    asyncio.run(main([args.type] if args.type else types, args.entity, args.apply, args.top))


if __name__ == "__main__":
    cli()
