"""One-shot backfill: coerce free-text tool_type / malware_type to the controlled vocab.

The F12 fix (entity-creation guardrails, 2026-08-16) coerces types on NEW
writes only; this script fixes the stock — 1,544 of 1,705 prod tool rows had
free-text types across 1,040 distinct values. Original values are preserved in
``metadata_["raw_tool_type"]`` / ``metadata_["raw_malware_type"]``. Changed
rows are re-indexed into Meilisearch (their docs carry the type field).

Run inside the api container from repo root:

    docker compose -f docker-compose.dev.yml exec api python scripts/archive/backfill_type_vocab.py            # dry run
    docker compose -f docker-compose.dev.yml exec api python scripts/archive/backfill_type_vocab.py --apply

Idempotent: rows whose type is already a valid slug are untouched.
"""

import argparse
import asyncio
from collections import Counter

from sqlalchemy import select

from app.database import async_session
from app.intelligence.entity_resolution import coerce_malware_type, coerce_tool_type
from app.models.malware_family import MALWARE_TYPES, MalwareFamily
from app.models.tool import TOOL_TYPES, Tool
from app.services.entity_indexer import index_single_entity


async def _backfill(db, model, vocab, coerce, type_attr: str, meta_key: str, index_type: str, apply: bool):
    rows = (await db.execute(select(model).where(getattr(model, type_attr).isnot(None)))).scalars().all()
    changed = 0
    mapping: Counter = Counter()
    samples: dict[str, list[str]] = {}
    for row in rows:
        raw = getattr(row, type_attr)
        if raw in vocab:
            continue
        coerced, original = coerce(raw)
        mapping[f"{raw!r} -> {coerced}"] += 1
        samples.setdefault(coerced, []).append(raw)
        changed += 1
        if apply:
            setattr(row, type_attr, coerced)
            if original:
                row.metadata_ = {**(row.metadata_ or {}), meta_key: original}
            await index_single_entity(index_type, row)
    if apply:
        await db.commit()
    return len(rows), changed, mapping, samples


async def main(apply: bool):
    async with async_session() as db:
        for label, model, vocab, coerce, attr, meta_key, index_type in (
            ("tools", Tool, TOOL_TYPES, coerce_tool_type, "tool_type", "raw_tool_type", "tool"),
            (
                "malware",
                MalwareFamily,
                MALWARE_TYPES,
                coerce_malware_type,
                "malware_type",
                "raw_malware_type",
                "malware",
            ),
        ):
            total, changed, mapping, samples = await _backfill(
                db, model, vocab, coerce, attr, meta_key, index_type, apply
            )
            mode = "APPLIED" if apply else "DRY RUN"
            print(f"\n=== {label}: {changed}/{total} typed rows coerced [{mode}] ===")
            dist = Counter()
            for key, n in mapping.items():
                dist[key.split(" -> ")[1]] += n
            for slug, n in dist.most_common():
                ex = ", ".join(repr(s) for s in samples.get(slug, [])[:4])
                print(f"  {slug:<18} {n:>5}   e.g. {ex}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true", help="write changes (default: dry run)")
    args = parser.parse_args()
    asyncio.run(main(args.apply))
