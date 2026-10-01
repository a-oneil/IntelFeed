"""Replay stored one-pass analyses through the observables AI doors.

``shadow`` mode threw the AI's judgment away: a confirmed indicator became a
bare candidate with no role, evidence or confidence. The judgment is still in
``ai_results.parsed_result`` (``iocs`` / ``scripts`` / ``ttps`` /
``relationships``), so the right backfill after flipping
``observables_ai_capture_mode`` is to re-apply those payloads through the
same ``apply_ai_observables`` ingest uses — identical validators, identical
per-kind capture list — and then re-assert the actor/malware → observable
relationships that were dropped because no row existed.

Idempotent on ``(kind, value)`` + ``(entry, observable)``; sightings carry
``seen_at = entry.published_at`` so a replay never stamps rows fresh.

Run inside the api container (``docker compose -f docker-compose.dev.yml exec api``):
    python scripts/maintenance/replay_ai_observables.py --since 2026-09-20 --dry-run
    python scripts/maintenance/replay_ai_observables.py --since 2026-09-20
    python scripts/maintenance/replay_ai_observables.py --since 2026-09-20 --mode capture \
        --kinds ipv4,domain,url,sha256,md5
"""

import argparse
import asyncio
import sys
from datetime import datetime

sys.path.insert(0, "/app")

from sqlalchemy import select  # noqa: E402

import app.models  # noqa: E402,F401
from app.database import async_session  # noqa: E402
from app.models.ai_result import AIResult  # noqa: E402
from app.models.ai_task import AITask  # noqa: E402
from app.models.entry import Entry  # noqa: E402


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--since", type=lambda s: datetime.fromisoformat(s), default=None)
    ap.add_argument("--mode", choices=["setting", "capture", "shadow"], default="setting")
    ap.add_argument(
        "--kinds",
        default=None,
        help="comma list overriding observables_ai_capture_kinds",
    )
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    from app.intelligence.enrichment import store_ai_relationships
    from app.services.entry_analysis import apply_ai_observables

    mode = None if args.mode == "setting" else args.mode
    kinds = {k.strip() for k in args.kinds.split(",")} if args.kinds else None

    async with async_session() as db:
        task_id = (await db.execute(select(AITask.id).where(AITask.name == "entry_analysis"))).scalar_one_or_none()
        if task_id is None:
            raise SystemExit("no entry_analysis task")
        q = (
            select(AIResult.entry_id, AIResult.parsed_result, Entry.published_at)
            .join(Entry, Entry.id == AIResult.entry_id)
            .where(AIResult.task_id == task_id, AIResult.is_current.is_(True))
            .order_by(AIResult.created_at)
        )
        if args.since:
            q = q.where(AIResult.created_at >= args.since)
        if args.limit:
            q = q.limit(args.limit)
        rows = (await db.execute(q)).all()
        with_items = [
            r
            for r in rows
            if isinstance(r.parsed_result, dict) and (r.parsed_result.get("iocs") or r.parsed_result.get("scripts"))
        ]
        print(
            f"current analyses: {len(rows)}; with iocs/scripts: {len(with_items)}; "
            f"mode={args.mode} kinds={args.kinds or 'setting'}"
        )
        if args.dry_run:
            kinds_seen: dict[str, int] = {}
            for r in with_items:
                for i in r.parsed_result.get("iocs") or []:
                    k = (i.get("kind") or "?") if isinstance(i, dict) else "?"
                    kinds_seen[k] = kinds_seen.get(k, 0) + 1
            for k, n in sorted(kinds_seen.items(), key=lambda kv: -kv[1]):
                print(f"  {k:16s} {n}")
            return
        totals: dict[str, int] = {}
        done = 0
        for r in with_items:
            try:
                counts = await apply_ai_observables(
                    db, r.entry_id, r.parsed_result, mode=mode, capture_kinds=kinds, fire_automations=False
                )
                rels = r.parsed_result.get("relationships") or []
                if rels:
                    counts["relationships"] = await store_ai_relationships(db, rels, r.entry_id, r.parsed_result)
                await db.commit()
            except Exception as exc:
                await db.rollback()
                print(f"  ! {r.entry_id}: {exc}")
                continue
            for k, v in counts.items():
                totals[k] = totals.get(k, 0) + int(v or 0)
            done += 1
            if done % 100 == 0:
                print(f"  replayed {done}/{len(with_items)} {totals}")
        print(f"replayed {done} analyses: {totals}")


if __name__ == "__main__":
    asyncio.run(main())
