"""One-time: give existing indicator-feed observables the role their feed file implies.

The feed door now fills ``role`` on creation from the file path (C2 lists ->
``c2``, scanner lists -> ``scanning``, phish-sim -> ``phishing``; dual-use
VPN/RMM/KVM files carry none). Rows written before that landed with
``role = NULL`` — this walks every ``ioc_list`` row with no role, looks at the
feed files that sighted it, and sets the first role any of them implies.
Fill-only: a role already set (by the AI, an analyst, a publisher file) is
never overwritten.

Runs in the api container:
    docker compose -f docker-compose.dev.yml exec api python scripts/maintenance/backfill_feed_observable_roles.py [--dry-run]
"""

import argparse
import asyncio
import sys

sys.path.insert(0, "/app")

from sqlalchemy import select  # noqa: E402

import app.models  # noqa: E402,F401
from app.database import async_session  # noqa: E402
from app.intelligence.observables import ioc_list_path_role  # noqa: E402
from app.models.entry import Entry  # noqa: E402
from app.models.observable import EntryObservable, Observable  # noqa: E402


async def main(dry_run: bool) -> None:
    async with async_session() as db:
        rows = (
            await db.execute(
                select(Observable.id, Observable.infra_tag, Entry.metadata_["file_path"].astext)
                .join(EntryObservable, EntryObservable.observable_id == Observable.id)
                .join(Entry, Entry.id == EntryObservable.entry_id)
                .where(
                    Observable.role.is_(None),
                    Observable.is_denied.is_(False),
                    EntryObservable.source == "feed",
                )
            )
        ).all()
        chosen: dict = {}
        for oid, infra_tag, file_path in rows:
            if oid in chosen:
                continue
            role = ioc_list_path_role(file_path, infra_tag)
            if role:
                chosen[oid] = role
        by_role: dict[str, int] = {}
        for role in chosen.values():
            by_role[role] = by_role.get(role, 0) + 1
        print(
            f"feed-sighted rows without a role: {len({r[0] for r in rows})}; roles derivable: {len(chosen)} {by_role}"
        )
        if dry_run or not chosen:
            return
        for oid, role in chosen.items():
            obs = await db.get(Observable, oid)
            if obs is not None and obs.role is None:
                obs.role = role
        await db.commit()
        print(f"updated {len(chosen)} rows")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    asyncio.run(main(args.dry_run))
