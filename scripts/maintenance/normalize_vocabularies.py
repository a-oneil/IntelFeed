"""Fold stored vocabulary columns onto their canonical spellings.

Two columns that the search grammar treats as vocabularies were written by
several paths that each picked their own casing, so the facets listed the same
value more than once and a filter for one spelling missed the others:

    detection_rules.mitre_tactics   Persistence / persistence / CommandAndControl
    threat_actors.motivation        Financial Extortion / financial extortion

The write paths now normalize at the model, so this is a one-shot catch-up for
rows written before that. It is idempotent — a second run reports zero changes.

Unrecognized values are kept, not dropped: a motivation of "terrorism" is an
analyst's wording, and the
point of this sweep is to collapse duplicate spellings, not to prune the
vocabulary. They are listed under "unmapped" so someone can fold them by hand.

Run inside the api container:
    docker compose -f docker-compose.dev.yml exec api python scripts/maintenance/normalize_vocabularies.py --dry-run
    docker compose -f docker-compose.dev.yml exec api python scripts/maintenance/normalize_vocabularies.py
"""

import argparse
import asyncio
import sys
from collections import Counter

sys.path.insert(0, "/app")

from sqlalchemy import select  # noqa: E402

import app.models  # noqa: E402,F401 — register all mappers (Entry relationships)
from app.database import async_session  # noqa: E402
from app.intelligence.actor_attributes import MOTIVATIONS, normalize_country, normalize_motivation  # noqa: E402
from app.intelligence.platforms import CANONICAL_PLATFORMS, canonical_platforms, is_not_a_platform  # noqa: E402
from app.intelligence.tactics import CANONICAL_TACTICS, canonical_tactics  # noqa: E402
from app.models.detection_rule import DetectionRule  # noqa: E402
from app.models.threat_actor import ThreatActor  # noqa: E402
from app.models.tool import Tool  # noqa: E402

BATCH = 500


async def _representatives(db, columns, fold, key, is_canonical) -> dict[str, str]:
    """Pick one spelling per value the vocabulary doesn't cover.

    Folding collapses duplicates inside a single row's list, but a facet is
    built across rows: one malware family storing "Linux Systems" and another
    storing "Linux systems" still produces two dropdown entries. For values the
    vocabulary can place that's moot — they all fold to the same label — so
    this only decides between spellings of the values it can't, and it decides
    by popularity rather than by imposing a case style on an analyst's wording.
    Ties break alphabetically so repeated runs agree.
    """
    counts: dict[str, Counter] = {}
    for column in columns:
        for stored in (await db.execute(select(column))).scalars().all():
            for value in fold(stored or []):
                if is_canonical(value):
                    continue
                counts.setdefault(key(value), Counter())[value] += 1
    return {
        group: sorted(spellings.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
        for group, spellings in counts.items()
        if len(spellings) > 1
    }


async def _fold_column(db, model, attr, fold, label, unmapped_test):
    """Rewrite one column in batches, reporting what moved and what didn't."""
    changed = scanned = 0
    unmapped: Counter = Counter()
    offset = 0
    while True:
        rows = (await db.execute(select(model).order_by(model.id).offset(offset).limit(BATCH))).scalars().all()
        if not rows:
            break
        for row in rows:
            scanned += 1
            before = getattr(row, attr)
            after = fold(before)
            for value in after if isinstance(after, list) else [after]:
                if value is not None and unmapped_test(value):
                    unmapped[value] += 1
            if after != before:
                # Assigning through the ORM runs the same validator the write
                # paths now use, so the stored result and a fresh write agree.
                setattr(row, attr, after)
                db.add(row)
                changed += 1
        await db.flush()
        offset += BATCH

    print(f"\n{label}")
    print(f"  scanned: {scanned}")
    print(f"  changed: {changed}")
    if unmapped:
        print(f"  unmapped ({len(unmapped)} distinct, kept as written):")
        for value, count in unmapped.most_common(15):
            print(f"    {count:5}  {value}")
        if len(unmapped) > 15:
            print(f"    ... and {len(unmapped) - 15} more")
    return changed


async def main(dry_run: bool) -> None:
    async with async_session() as db:
        total = 0
        total += await _fold_column(
            db,
            DetectionRule,
            "mitre_tactics",
            lambda v: canonical_tactics(v or []),
            "detection_rules.mitre_tactics",
            lambda v: v not in CANONICAL_TACTICS,
        )
        total += await _fold_column(
            db,
            ThreatActor,
            "motivation",
            normalize_motivation,
            "threat_actors.motivation",
            lambda v: v not in MOTIVATIONS,
        )
        # targeted_sectors is no longer folded here: the column is a cache rebuilt
        # from the target-sector junctions (app/services/sector_links.py), and the
        # one-time free-text cleanup is scripts/maintenance/backfill_targeted_sectors.py.

        pruned: Counter = Counter()

        def _prune_and_fold(stored):
            kept = []
            for value in stored or []:
                if is_not_a_platform(value):
                    pruned[value] += 1
                    continue
                kept.append(value)
            return canonical_platforms(kept)

        # Same cross-row pass as the sectors: "Cross-Platform" and
        # "Cross-platform" are one platform written twice.
        plat_reps = await _representatives(
            db,
            (Tool.platforms,),
            _prune_and_fold,
            str.casefold,
            lambda v: v in CANONICAL_PLATFORMS,
        )
        pruned.clear()  # the representative pass counted every row once already
        print(f"\nplatform spellings folded across rows: {len(plat_reps)}")

        def fold_platforms(stored):
            return [plat_reps.get(v.casefold(), v) for v in _prune_and_fold(stored)]

        total += await _fold_column(
            db,
            Tool,
            "platforms",
            fold_platforms,
            "tools.platforms",
            lambda v: v not in CANONICAL_PLATFORMS,
        )
        if pruned:
            print(f"  pruned ({len(pruned)} distinct — answers to a different question, removed):")
            for value, count in pruned.most_common(20):
                print(f"    {count:5}  {value}")
            if len(pruned) > 20:
                print(f"    ... and {len(pruned) - 20} more")

        total += await _fold_column(
            db,
            ThreatActor,
            "country",
            normalize_country,
            "threat_actors.country",
            lambda _v: False,
        )

        print(f"\nRows changed: {total}")

        if dry_run:
            await db.rollback()
            print("[dry-run] rolled back")
            return
        await db.commit()
        print("committed")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true", help="fold and report, then roll back")
    args = ap.parse_args()
    asyncio.run(main(args.dry_run))
