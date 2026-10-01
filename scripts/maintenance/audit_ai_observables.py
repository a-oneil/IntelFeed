"""Dump what the one-pass analysis AI has judged as observables, for hand review.

Writes one CSV row per item from every current ``entry_analysis`` result's
``iocs`` / ``scripts`` arrays (role, evidence, confidence, feed, title) plus
every AI-origin candidate still staged on an entry. Label the ``verdict``
column by hand (ok / junk / wrong_kind / wrong_role) and keep the file: it is
the precision record that gates ``observables_ai_capture_mode``.

Run inside the api container (``docker compose -f docker-compose.dev.yml exec api``):
    python scripts/maintenance/audit_ai_observables.py --since 2026-09-20 --out /app/scripts/ai_observables_audit.csv
    python scripts/maintenance/audit_ai_observables.py --sample 150
"""

import argparse
import asyncio
import csv
import random
import sys
from datetime import datetime

sys.path.insert(0, "/app")

from sqlalchemy import select  # noqa: E402

import app.models  # noqa: E402,F401
from app.database import async_session  # noqa: E402
from app.intelligence.observables import validate_kind_value  # noqa: E402
from app.models.ai_result import AIResult  # noqa: E402
from app.models.ai_task import AITask  # noqa: E402
from app.models.entry import Entry  # noqa: E402
from app.models.feed import Feed  # noqa: E402

FIELDS = [
    "source",
    "entry_id",
    "feed",
    "title",
    "published_at",
    "kind",
    "value",
    "role",
    "confidence",
    "defanged",
    "passes_validator",
    "evidence",
    "verdict",
    "note",
]


async def collect(since: datetime | None) -> list[dict]:
    rows: list[dict] = []
    async with async_session() as db:
        task_id = (await db.execute(select(AITask.id).where(AITask.name == "entry_analysis"))).scalar_one_or_none()
        if task_id is None:
            return rows
        q = (
            select(AIResult.parsed_result, Entry.id, Entry.title, Entry.published_at, Feed.title)
            .join(Entry, Entry.id == AIResult.entry_id)
            .join(Feed, Feed.id == Entry.feed_id)
            .where(AIResult.task_id == task_id, AIResult.is_current.is_(True))
        )
        if since:
            q = q.where(AIResult.created_at >= since)
        for parsed, eid, title, published, feed in (await db.execute(q)).all():
            parsed = parsed or {}
            base = {"entry_id": str(eid), "feed": feed, "title": (title or "")[:120], "published_at": published}
            for item in parsed.get("iocs") or []:
                if not isinstance(item, dict):
                    continue
                kind = (item.get("kind") or "").strip()
                value = (item.get("value") or "").strip()
                rows.append(
                    {
                        **base,
                        "source": "ai_result.iocs",
                        "kind": kind,
                        "value": value,
                        "role": item.get("role") or "",
                        "confidence": item.get("confidence") or "",
                        "defanged": item.get("defanged"),
                        "passes_validator": bool(kind and value and validate_kind_value(kind, value)),
                        "evidence": (item.get("evidence") or "")[:300],
                        "verdict": "",
                        "note": "",
                    }
                )
            for item in parsed.get("scripts") or []:
                if not isinstance(item, dict):
                    continue
                rows.append(
                    {
                        **base,
                        "source": "ai_result.scripts",
                        "kind": "script",
                        "value": (item.get("code") or "")[:200].replace("\n", "\\n"),
                        "role": item.get("label") or "",
                        "confidence": item.get("confidence") or "",
                        "defanged": "",
                        "passes_validator": len((item.get("code") or "").strip()) >= 40,
                        "evidence": item.get("language") or "",
                        "verdict": "",
                        "note": "",
                    }
                )
        q2 = (
            select(Entry.id, Entry.title, Entry.published_at, Feed.title, Entry.observable_candidates)
            .join(Feed, Feed.id == Entry.feed_id)
            .where(Entry.observable_candidates.isnot(None))
        )
        if since:
            q2 = q2.where(Entry.published_at >= since)
        for eid, title, published, feed, cands in (await db.execute(q2)).all():
            for c in cands or []:
                if not isinstance(c, dict) or c.get("origin") != "ai":
                    continue
                rows.append(
                    {
                        "source": "entry.candidates(ai)",
                        "entry_id": str(eid),
                        "feed": feed,
                        "title": (title or "")[:120],
                        "published_at": published,
                        "kind": c.get("kind") or "",
                        "value": c.get("value") or "",
                        "role": c.get("role") or "",
                        "confidence": c.get("confidence") or "",
                        "defanged": c.get("was_defanged"),
                        "passes_validator": bool(validate_kind_value(c.get("kind") or "", c.get("value") or "")),
                        "evidence": (c.get("evidence") or "")[:300],
                        "verdict": "",
                        "note": "",
                    }
                )
    return rows


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--since", type=lambda s: datetime.fromisoformat(s), default=None)
    ap.add_argument("--sample", type=int, default=0, help="also write a stratified random sample of this size")
    ap.add_argument("--out", default="ai_observables_audit.csv")
    args = ap.parse_args()
    rows = await collect(args.since)
    with open(args.out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    by_kind: dict[str, int] = {}
    for r in rows:
        by_kind[r["kind"]] = by_kind.get(r["kind"], 0) + 1
    print(f"wrote {len(rows)} rows to {args.out}")
    for k, n in sorted(by_kind.items(), key=lambda kv: -kv[1]):
        print(f"  {k:12s} {n}")
    if args.sample and rows:
        random.seed(7)
        per_kind = max(1, args.sample // max(1, len(by_kind)))
        sample: list[dict] = []
        for k in by_kind:
            pool = [r for r in rows if r["kind"] == k]
            sample.extend(random.sample(pool, min(per_kind, len(pool))))
        out = args.out.replace(".csv", f".sample{len(sample)}.csv")
        with open(out, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=FIELDS)
            w.writeheader()
            w.writerows(sample)
        print(f"wrote stratified sample of {len(sample)} to {out}")


if __name__ == "__main__":
    asyncio.run(main())
