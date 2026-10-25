"""Resolve held dictionary-word matches on entries the AI will never read.

The autolinker holds actor/malware/tool/country matches whose only surface
forms are common English words ("Play", "Royal", "Hive") in
`pending_autolink_matches` until the one-pass AI analysis confirms them. On a
feed whose AI is off (or whose extraction mode is "none") that analysis never
runs, so the rows sit unresolved until the 14-day expiry. The autolinker drops
those matches at ingest; this script clears the ones held before it did.

It uses the same check AI queueing uses (app.services.ai_eligibility): the
instance `ai_one_pass_enabled` switch, the feed's `ai_analysis_enabled`, and a
mode other than "none". Matching rows get `resolution = 'dropped_ai_off'` and
`resolved_at = now()`; the engine-tables prune job deletes them after 30 days
like any other resolved row. Nothing is linked.

Dry run (the default) prints open rows per feed that would be resolved:

    docker compose -f docker-compose.prod.yml exec api \\
        python scripts/maintenance/resolve_pending_ai_off.py

Then apply:

    docker compose -f docker-compose.prod.yml exec api \\
        python scripts/maintenance/resolve_pending_ai_off.py --apply

Idempotent: a second run finds nothing.
"""

import argparse
import asyncio
import sys

sys.path.insert(0, "/app")

from sqlalchemy import func, select, update

from app.database import async_session
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.pending_autolink import PendingAutolinkMatch
from app.services.ai_eligibility import feed_ai_skip_status
from app.services.system_settings import get_setting

RESOLUTION = "dropped_ai_off"


async def resolve(db, apply: bool) -> dict:
    """Print open held matches per failing feed; resolve them when ``apply``. Returns counts."""
    instance_ai = bool(await get_setting("ai_one_pass_enabled", db))
    rows = (
        await db.execute(
            select(
                Feed.id,
                Feed.title,
                Feed.intel_extraction_mode,
                Feed.ai_analysis_enabled,
                func.count(PendingAutolinkMatch.id),
            )
            .join(Entry, Entry.feed_id == Feed.id)
            .join(PendingAutolinkMatch, PendingAutolinkMatch.entry_id == Entry.id)
            .where(PendingAutolinkMatch.resolution.is_(None))
            .group_by(
                Feed.id,
                Feed.title,
                Feed.intel_extraction_mode,
                Feed.ai_analysis_enabled,
            )
            .order_by(func.count(PendingAutolinkMatch.id).desc())
        )
    ).all()

    if not instance_ai:
        print(
            "Instance AI (ai_one_pass_enabled) is OFF: every open held match fails the check."
        )

    failing = []
    kept = 0
    for feed_id, title, mode, ai_on, n in rows:
        reason = (
            "instance AI off" if not instance_ai else feed_ai_skip_status(mode, ai_on)
        )
        if reason is None:
            kept += n
            continue
        failing.append((feed_id, title, reason, n))

    total = sum(n for *_, n in failing)
    print(f"{'open rows':>9}  {'reason':<18}  feed")
    for _feed_id, title, reason, n in failing:
        print(f"{n:>9}  {reason:<18}  {title}")
    print(
        f"\n{total} open held match(es) on {len(failing)} feed(s) to resolve as '{RESOLUTION}'."
    )
    print(f"{kept} open held match(es) on feeds the AI reads are left alone.")

    resolved = 0
    if apply and failing:
        result = await db.execute(
            update(PendingAutolinkMatch)
            .where(
                PendingAutolinkMatch.resolution.is_(None),
                PendingAutolinkMatch.entry_id.in_(
                    select(Entry.id).where(Entry.feed_id.in_([f[0] for f in failing]))
                ),
            )
            .values(resolution=RESOLUTION, resolved_at=func.now())
            .execution_options(synchronize_session=False)
        )
        resolved = result.rowcount
        print(f"\nResolved {resolved} row(s).")
    elif not apply:
        print("\nDry run, nothing changed. Re-run with --apply to resolve them.")
    return {"to_resolve": total, "kept": kept, "resolved": resolved}


async def main(apply: bool) -> int:
    async with async_session() as db:
        await resolve(db, apply)
        if apply:
            await db.commit()
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--apply", action="store_true", help="Resolve the rows (default is a dry run)."
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Print counts only (the default)."
    )
    args = parser.parse_args()
    sys.exit(asyncio.run(main(apply=args.apply and not args.dry_run)))
