"""Re-check existing co-occurrence edges against today's builder rule.

``create_cooccurrence_relationships`` (app/intelligence/correlation.py) only
counts an article as evidence for an edge when both names sit in the same
body paragraph, that paragraph is not boilerplate (``_BOILERPLATE_PARAGRAPH``:
"Related:", references, analytic-story lines ...), it names fewer than
``_CROWDED_PARAGRAPH_ENTITIES`` entities, and the article has no more than
``_MAX_ENTITIES_PER_ENTRY`` links. A link with no recorded paragraph does not
count. Edges built before that rule cite articles that no longer qualify.

For every ``source = 'co_occurrence'`` edge, each evidence article is checked
against the article's current links:

    keep        the pair still qualifies, or the adjudicate stage kept the edge
                on that article (``reviewer_kept_entry_ids``)
    drop        it no longer qualifies: removed from ``evidence_entry_ids``
    reject      no evidence is left: ``source`` becomes ``analyst_rejected``,
                exactly what POST /api/entity-relationships/{id}/reject does.
                The row stays, so co-occurrence never re-creates it.

A trimmed edge at ``probable`` is checked against the builder's promotion
rule again (``relationship_evidence_promote_count`` evidence articles, two or
more feeds, the story and theme floors). If it no longer passes, it goes back
to ``possible``. ``confirmed`` edges keep their confidence.

No other source is touched (external_feed, auto_extracted, enrichment and the
analyst sources).

Every change is written to a CSV, which is also the undo record:
``--undo <csv> --apply`` puts the dropped evidence back, un-rejects the
rejected edges (only those still ``analyst_rejected``) and restores a demoted
confidence (only where it is still the demoted value).

Dry-run by default; --apply writes. Idempotent: a second run finds nothing.

Run inside the api container (scripts/ is read-only in prod, so the CSV goes
to /tmp there — the path is printed; copy it out with `docker compose cp`):

    docker compose -f docker-compose.prod.yml exec -T api \\
        python scripts/maintenance/sweep_cooccurrence_edges.py
    docker compose -f docker-compose.prod.yml exec -T api \\
        python scripts/maintenance/sweep_cooccurrence_edges.py --apply
    docker compose -f docker-compose.prod.yml exec -T api \\
        python scripts/maintenance/sweep_cooccurrence_edges.py --undo /tmp/cooccurrence_sweep.csv --apply
"""

import argparse
import asyncio
import csv
import os
import sys
import uuid
from collections import Counter, defaultdict
from datetime import UTC, datetime

sys.path.insert(0, "/app")

from sqlalchemy import select

import app.models  # noqa: F401  (register every mapper)
from app.database import async_session
from app.intelligence.correlation import (
    _CROWDED_PARAGRAPH_ENTITIES,
    _MAX_ENTITIES_PER_ENTRY,
    _RELATABLE_TYPES,
    ENTITY_CONFIG,
    _passes_story_floor,
    _passes_theme_floor,
    boilerplate_indices,
)
from app.models.entity_relationship import EntityRelationship
from app.models.entry import Entry

SOURCE = "co_occurrence"
REJECTED = "analyst_rejected"
ENTRY_BATCH = 500
WRITE_BATCH = 500
DEFAULT_CSV = "cooccurrence_sweep.csv"
FIELDS = [
    "edge_id",
    "change",
    "relationship",
    "source",
    "target",
    "dropped_entry_ids",
    "kept",
    "confidence_before",
    "confidence_after",
    "swept_at",
]

EntityKey = tuple[str, uuid.UUID]


# --------------------------------------------------------------------------- pure rule
# The builder's rule, restated over plain data so it can be tested without a
# database. Constants and boilerplate_indices are imported, not copied.


def entry_profile(
    refs: list[tuple[str, uuid.UUID, list[int] | None]], boilerplate: set[int]
) -> tuple[dict[EntityKey, set[int]], set[int]] | None:
    """(placed paragraphs per entity, crowded paragraphs) for one article,
    or None when the builder would skip the article entirely."""
    if len(refs) < 2 or len(refs) > _MAX_ENTITIES_PER_ENTRY:
        return None
    placed: dict[EntityKey, set[int]] = {}
    for etype, eid, paras in refs:
        body = set(paras or []) - boilerplate
        if body:
            placed.setdefault((etype, eid), set()).update(body)
    per_paragraph: Counter = Counter()
    for paras in placed.values():
        per_paragraph.update(paras)
    crowded = {p for p, n in per_paragraph.items() if n >= _CROWDED_PARAGRAPH_ENTITIES}
    return placed, crowded


def pair_qualifies(profile, a: EntityKey, b: EntityKey) -> bool:
    """Would the builder count this article as evidence for the a–b edge?"""
    if profile is None or a[0] == b[0]:
        return False
    placed, crowded = profile
    pa, pb = placed.get(a), placed.get(b)
    if not pa or not pb:
        return False
    return bool((pa & pb) - crowded)


def judge_edge(
    evidence: list[uuid.UUID], kept: list[uuid.UUID], qualifies
) -> tuple[list[uuid.UUID], list[uuid.UUID], bool]:
    """(remaining, dropped, reject) for one edge. ``qualifies(entry_id)`` says
    whether that article still counts; reviewer-kept articles always stay."""
    kept_set = set(kept or [])
    remaining, dropped = [], []
    for eid in evidence or []:
        (remaining if eid in kept_set or qualifies(eid) else dropped).append(eid)
    return remaining, dropped, not remaining


def keeps_probable(evidence_count: int, promote_count: int, feed_count: int, story_ok: bool, theme_ok: bool) -> bool:
    """The builder's possible→probable rule: does a trimmed edge still earn it?"""
    return evidence_count >= promote_count and feed_count >= 2 and story_ok and theme_ok


def _promote_count() -> int:
    from app.config import settings as env_settings

    return int(env_settings.get("relationship_evidence_promote_count") or 3)


async def _still_probable(db, evidence: list[uuid.UUID], promote_count: int) -> bool:
    from sqlalchemy import func

    if len(evidence) < promote_count:
        return False  # cheap exit: no need to ask the floors
    feeds = (
        await db.execute(select(func.count(func.distinct(Entry.feed_id))).where(Entry.id.in_(evidence)))
    ).scalar() or 0
    if feeds < 2:
        return False
    return keeps_probable(
        len(evidence),
        promote_count,
        feeds,
        await _passes_story_floor(db, evidence),
        await _passes_theme_floor(db, evidence),
    )


# --------------------------------------------------------------------------- db


def _csv_path(given: str | None) -> str:
    if given:
        return given
    here = os.path.dirname(os.path.abspath(__file__))
    out = os.path.join(os.path.dirname(here), "out")
    try:
        os.makedirs(out, exist_ok=True)
        probe = os.path.join(out, ".w")
        open(probe, "w").close()
        os.remove(probe)
        return os.path.join(out, DEFAULT_CSV)
    except OSError:
        return os.path.join("/tmp", DEFAULT_CSV)


async def _profiles(db, entry_ids: list[uuid.UUID]) -> dict[uuid.UUID, object]:
    refs: dict[uuid.UUID, list] = defaultdict(list)
    for etype, (_model, junction, fk_col) in ENTITY_CONFIG.items():
        if etype not in _RELATABLE_TYPES:
            continue
        rows = await db.execute(
            select(junction.entry_id, fk_col, junction.paragraph_indices).where(junction.entry_id.in_(entry_ids))
        )
        for entry_id, eid, paras in rows.all():
            refs[entry_id].append((etype, eid, paras))
    texts = await db.execute(
        select(Entry.id, Entry.title, Entry.summary, Entry.content_text).where(Entry.id.in_(entry_ids))
    )
    out: dict[uuid.UUID, object] = {}
    for entry_id, title, summary, content in texts.all():
        out[entry_id] = entry_profile(refs.get(entry_id, []), boilerplate_indices(title, summary, content))
    return out  # entries that no longer exist are absent → never qualify


async def scan(db) -> list[dict]:
    edges = (
        await db.execute(
            select(
                EntityRelationship.id,
                EntityRelationship.source_type,
                EntityRelationship.source_id,
                EntityRelationship.target_type,
                EntityRelationship.target_id,
                EntityRelationship.relationship_type,
                EntityRelationship.evidence_entry_ids,
                EntityRelationship.reviewer_kept_entry_ids,
                EntityRelationship.confidence,
            ).where(EntityRelationship.source == SOURCE)
        )
    ).all()
    print(f"Loaded {len(edges)} co-occurrence edges")

    by_entry: dict[uuid.UUID, list[int]] = defaultdict(list)
    for i, e in enumerate(edges):
        for eid in set(e.evidence_entry_ids or []) - set(e.reviewer_kept_entry_ids or []):
            by_entry[eid].append(i)
    qualified: set[tuple[int, uuid.UUID]] = set()
    entry_ids = list(by_entry)
    for start in range(0, len(entry_ids), ENTRY_BATCH):
        chunk = entry_ids[start : start + ENTRY_BATCH]
        profiles = await _profiles(db, chunk)
        for entry_id in chunk:
            profile = profiles.get(entry_id)
            for i in by_entry[entry_id]:
                e = edges[i]
                if pair_qualifies(profile, (e.source_type, e.source_id), (e.target_type, e.target_id)):
                    qualified.add((i, entry_id))
        if (start // ENTRY_BATCH) % 20 == 19:
            print(f"  checked {min(start + ENTRY_BATCH, len(entry_ids))}/{len(entry_ids)} evidence articles")

    plan = []
    promote_count = _promote_count()
    for i, e in enumerate(edges):
        remaining, dropped, reject = judge_edge(
            list(e.evidence_entry_ids or []),
            list(e.reviewer_kept_entry_ids or []),
            lambda eid, i=i: (i, eid) in qualified,
        )
        if not dropped and not reject:
            continue
        after = e.confidence
        if not reject and e.confidence == "probable" and not await _still_probable(db, remaining, promote_count):
            after = "possible"
        plan.append(
            {
                "edge_id": e.id,
                "change": "reject" if reject else "drop_evidence",
                "relationship": e.relationship_type,
                "source": f"{e.source_type}:{e.source_id}",
                "target": f"{e.target_type}:{e.target_id}",
                "dropped": dropped,
                "kept": len(remaining),
                "confidence_before": e.confidence,
                "confidence_after": after,
                "label": f"{e.source_type} -> {e.relationship_type} -> {e.target_type}",
            }
        )
    return plan


async def apply_plan(db, plan: list[dict]) -> Counter:
    """Write the plan in batches, re-reading each row so evidence added since
    the scan stays and rows an analyst has since taken over are skipped."""
    done: Counter = Counter()
    promote_count = _promote_count()
    for start in range(0, len(plan), WRITE_BATCH):
        chunk = plan[start : start + WRITE_BATCH]
        rows = {
            r.id: r
            for r in (
                await db.execute(
                    select(EntityRelationship).where(EntityRelationship.id.in_([p["edge_id"] for p in chunk]))
                )
            ).scalars()
        }
        for p in chunk:
            rel = rows.get(p["edge_id"])
            if rel is None or rel.source != SOURCE:
                done["skipped"] += 1
                continue
            drop = set(p["dropped"])
            left = [eid for eid in (rel.evidence_entry_ids or []) if eid not in drop]
            p["confidence_before"] = p["confidence_after"] = rel.confidence
            if left:
                rel.evidence_entry_ids = left
                done["drop_evidence"] += 1
                if rel.confidence == "probable" and not await _still_probable(db, left, promote_count):
                    rel.confidence = p["confidence_after"] = "possible"
                    done["demoted"] += 1
            else:
                rel.source = REJECTED  # evidence stays as it was, for the record
                done["reject"] += 1
        await db.commit()
    return done


async def flush_corr_cache() -> None:
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


def report(plan: list[dict]) -> None:
    rejects: Counter = Counter()
    drops: Counter = Counter()
    dropped_refs = demoted = 0
    for p in plan:
        (rejects if p["change"] == "reject" else drops)[p["label"]] += 1
        dropped_refs += len(p["dropped"])
        demoted += p["confidence_after"] != p["confidence_before"]
    labels = sorted(set(rejects) | set(drops), key=lambda k: -(rejects[k] + drops[k]))
    print(f"\n{'reject':>8} {'trim':>8}  relationship")
    for k in labels:
        print(f"{rejects[k]:>8} {drops[k]:>8}  {k}")
    print(
        f"\nTotal: {sum(rejects.values())} edges rejected, {sum(drops.values())} trimmed, "
        f"{dropped_refs} evidence references dropped, {demoted} probable edges back to possible."
    )


def write_csv(path: str, plan: list[dict]) -> None:
    now = datetime.now(UTC).isoformat(timespec="seconds")
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        for p in plan:
            w.writerow(
                {
                    "edge_id": str(p["edge_id"]),
                    "change": p["change"],
                    "relationship": p["label"],
                    "source": p["source"],
                    "target": p["target"],
                    "dropped_entry_ids": "|".join(str(e) for e in p["dropped"]),
                    "kept": p["kept"],
                    "confidence_before": p["confidence_before"],
                    "confidence_after": p["confidence_after"],
                    "swept_at": now,
                }
            )


async def undo(path: str, apply: bool) -> None:
    with open(path, newline="") as fh:
        rows = list(csv.DictReader(fh))
    done: Counter = Counter()
    async with async_session() as db:
        for start in range(0, len(rows), WRITE_BATCH):
            chunk = rows[start : start + WRITE_BATCH]
            rels = {
                r.id: r
                for r in (
                    await db.execute(
                        select(EntityRelationship).where(
                            EntityRelationship.id.in_([uuid.UUID(c["edge_id"]) for c in chunk])
                        )
                    )
                ).scalars()
            }
            for c in chunk:
                rel = rels.get(uuid.UUID(c["edge_id"]))
                if rel is None:
                    done["gone"] += 1
                    continue
                if c["change"] == "reject":
                    if rel.source != REJECTED:
                        done["not_rejected_any_more"] += 1
                        continue
                    rel.source = SOURCE
                    done["unrejected"] += 1
                else:
                    if rel.source != SOURCE:
                        done["source_changed"] += 1
                        continue
                    have = list(rel.evidence_entry_ids or [])
                    back = [uuid.UUID(e) for e in c["dropped_entry_ids"].split("|") if e and uuid.UUID(e) not in have]
                    if back:
                        rel.evidence_entry_ids = have + back
                        done["evidence_restored"] += 1
                    else:
                        done["already_restored"] += 1
                    before, after = c.get("confidence_before"), c.get("confidence_after")
                    if before and after and before != after and rel.confidence == after:
                        rel.confidence = before
                        done["confidence_restored"] += 1
            if apply:
                await db.commit()
        if not apply:
            await db.rollback()
    print("Undo:", ", ".join(f"{k} {n}" for k, n in sorted(done.items())) or "nothing to do")
    if not apply:
        print("DRY RUN — nothing written. Re-run with --apply.")
    else:
        await flush_corr_cache()


async def main(apply: bool, csv_path: str) -> None:
    async with async_session() as db:
        plan = await scan(db)
        report(plan)
        if not plan:
            return
        write_csv(csv_path, plan)
        print(f"Plan written to {csv_path} (keep it: it is the undo record).")
        if not apply:
            print("DRY RUN — nothing written. Re-run with --apply.")
            return
        done = await apply_plan(db, plan)
        write_csv(csv_path, plan)  # again, with the confidences actually written
        print("Applied:", ", ".join(f"{k} {n}" for k, n in sorted(done.items())))
    await flush_corr_cache()


def cli() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apply", action="store_true", help="Write the changes (default: report only).")
    ap.add_argument("--csv", help="Where to write the plan/undo CSV (default scripts/out/, or /tmp when read-only).")
    ap.add_argument("--undo", metavar="CSV", help="Reverse a previous sweep from its CSV.")
    args = ap.parse_args()
    if args.undo:
        asyncio.run(undo(args.undo, args.apply))
    else:
        asyncio.run(main(args.apply, _csv_path(args.csv)))


if __name__ == "__main__":
    cli()
