"""Purge regex-origin host-kind candidates and re-run the observables scan.

The code-block candidate scanner used to nominate every preformatted bulletin
line as a ``cmdline`` (AusCERT alone staged 12k of them). This clears every
scan-origin cmdline/path/registry candidate from every entry — AI-origin
stagings are kept — and optionally re-runs the observables stage scan
in-process for recent non-indicator-list entries so the tightened scanner
re-nominates the real commands.

Run inside the api container (``docker compose -f docker-compose.dev.yml exec api``):
    python scripts/maintenance/rescan_observable_candidates.py --dry-run
    python scripts/maintenance/rescan_observable_candidates.py
    python scripts/maintenance/rescan_observable_candidates.py --rescan-days 90
"""

import argparse
import asyncio
import sys

sys.path.insert(0, "/app")

from sqlalchemy import func, select, text  # noqa: E402

import app.models  # noqa: E402,F401
from app.database import async_session  # noqa: E402
from app.models.entry import Entry  # noqa: E402

PURGE_KINDS = ("cmdline", "path", "registry")


async def purge(dry_run: bool) -> int:
    async with async_session() as db:
        count_sql = text(
            """
            select count(*) from entries e, jsonb_array_elements(e.observable_candidates) c
            where coalesce(c->>'origin','scan') <> 'ai' and c->>'kind' = any(:kinds)
            """
        )
        n = (await db.execute(count_sql, {"kinds": list(PURGE_KINDS)})).scalar_one()
        print(f"scan-origin host-kind candidates: {n}")
        if dry_run or not n:
            return n
        await db.execute(
            text(
                """
                update entries e set observable_candidates = coalesce((
                    select jsonb_agg(c) from jsonb_array_elements(e.observable_candidates) c
                    where not (coalesce(c->>'origin','scan') <> 'ai' and c->>'kind' = any(:kinds))
                ), '[]'::jsonb)
                where exists (
                    select 1 from jsonb_array_elements(e.observable_candidates) c
                    where coalesce(c->>'origin','scan') <> 'ai' and c->>'kind' = any(:kinds)
                )
                """
            ),
            {"kinds": list(PURGE_KINDS)},
        )
        await db.commit()
        print(f"purged {n} candidates")
        return n


async def purge_all_scan(dry_run: bool) -> int:
    """Drop every scan-origin candidate of every kind (AI stagings stay) so a
    rescan under today's rules rebuilds the tier from scratch."""
    async with async_session() as db:
        n = (
            await db.execute(
                text(
                    "select count(*) from entries e, jsonb_array_elements(e.observable_candidates) c "
                    "where coalesce(c->>'origin','scan') <> 'ai'"
                )
            )
        ).scalar_one()
        print(f"scan-origin candidates (all kinds): {n}")
        if dry_run or not n:
            return n
        await db.execute(
            text(
                """
                update entries e set observable_candidates = coalesce((
                    select jsonb_agg(c) from jsonb_array_elements(e.observable_candidates) c
                    where coalesce(c->>'origin','scan') = 'ai'
                ), '[]'::jsonb)
                where exists (
                    select 1 from jsonb_array_elements(e.observable_candidates) c
                    where coalesce(c->>'origin','scan') <> 'ai'
                )
                """
            )
        )
        await db.commit()
        print(f"purged {n} scan-origin candidates")
        return n


async def purge_invalid(dry_run: bool) -> int:
    """Drop candidates of any origin that today's validators reject — staged
    under older, looser rules, they could never be promoted."""
    import json

    from app.intelligence.observables import validate_kind_value
    from app.models.observable import ALL_KINDS

    async with async_session() as db:
        rows = (
            await db.execute(
                select(Entry.id, Entry.observable_candidates).where(
                    func.jsonb_array_length(Entry.observable_candidates) > 0
                )
            )
        ).all()
        dropped = 0
        touched = 0
        for eid, cands in rows:
            kept = [
                c
                for c in cands
                if isinstance(c, dict)
                and c.get("kind") in ALL_KINDS
                and c.get("value")
                and validate_kind_value(c["kind"], c["value"]) is not None
            ]
            if len(kept) != len(cands):
                dropped += len(cands) - len(kept)
                touched += 1
                if not dry_run:
                    await db.execute(
                        text("update entries set observable_candidates = cast(:c as jsonb) where id = :id"),
                        {"c": json.dumps(kept), "id": eid},
                    )
        if not dry_run:
            await db.commit()
        print(f"invalid candidates: {dropped} across {touched} entries{' (dry run)' if dry_run else ' — purged'}")
        return dropped


async def rescan(days: int, dry_run: bool) -> int:
    from app.workers.intel_feed_tasks import _scan_entry_observables

    async with async_session() as db:
        ids = (
            (
                await db.execute(
                    select(Entry.id)
                    .where(
                        *([Entry.published_at >= func.now() - text(f"interval '{int(days)} days'")] if days else []),
                        Entry.content_html.isnot(None),
                    )
                    .order_by(Entry.published_at.desc())
                )
            )
            .scalars()
            .all()
        )
    print(f"entries to rescan ({'all' if not days else f'last {days} days'}): {len(ids)}")
    if dry_run:
        return 0
    done = 0
    for eid in ids:
        try:
            await _scan_entry_observables(str(eid))
        except Exception as exc:  # keep going; one bad entry must not stop the sweep
            print(f"  ! {eid}: {exc}")
            continue
        done += 1
        if done % 200 == 0:
            print(f"  rescanned {done}/{len(ids)}")
    print(f"rescanned {done} entries")
    return done


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--rescan-days", type=int, default=0, help="re-run the observables scan for entries this recent")
    ap.add_argument("--skip-purge", action="store_true")
    ap.add_argument("--purge-all-scan", action="store_true", help="drop scan-origin candidates of every kind")
    ap.add_argument("--purge-invalid", action="store_true", help="drop candidates today's validators reject")
    ap.add_argument("--rescan-all", action="store_true", help="re-run the scan for every entry with HTML")
    args = ap.parse_args()
    if args.purge_all_scan:
        await purge_all_scan(args.dry_run)
    elif not args.skip_purge:
        await purge(args.dry_run)
    if args.purge_invalid:
        await purge_invalid(args.dry_run)
    if args.rescan_all:
        await rescan(0, args.dry_run)
    elif args.rescan_days:
        await rescan(args.rescan_days, args.dry_run)


if __name__ == "__main__":
    asyncio.run(main())
