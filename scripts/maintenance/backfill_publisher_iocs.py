"""Run the publisher IOC-file door over articles already in the corpus.

Talos, Bitdefender Labs and Datadog Security Labs link their authoritative
indicator files from the article; the observables stage fetches them at
ingest from now on, but every article ingested before this door existed never
had its file read. This walks the corpus for articles linking an allow-listed
repository and runs the same door, sighted on the article with
``seen_at = published_at`` (idempotent on ``(kind, value)`` + ``(entry, observable)``).

Run inside the api container (``docker compose -f docker-compose.dev.yml exec api``):
    python scripts/maintenance/backfill_publisher_iocs.py --dry-run
    python scripts/maintenance/backfill_publisher_iocs.py --days 365
"""

import argparse
import asyncio
import sys

sys.path.insert(0, "/app")

from sqlalchemy import or_, select, text  # noqa: E402

import app.models  # noqa: E402,F401
from app.database import async_session  # noqa: E402
from app.intelligence.publisher_iocs import (
    PUBLISHER_IOC_SOURCES,
    publisher_ioc_links,
    store_publisher_observables,
)  # noqa: E402
from app.models.entry import Entry  # noqa: E402

#: Substrings that pre-filter candidate articles in SQL; the door itself
#: re-checks every link against PUBLISHER_IOC_SOURCES.
_REPO_FRAGMENTS = (
    "github.com/Cisco-Talos/IOCs",
    "github.com/bitdefender/malware-ioc",
    "github.com/DataDog/indicators-of-compromise",
)
assert PUBLISHER_IOC_SOURCES


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--days",
        type=int,
        default=0,
        help="only articles published this recently (0 = all)",
    )
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()
    async with async_session() as db:
        q = select(Entry).where(or_(*[Entry.content_html.ilike(f"%{frag}%") for frag in _REPO_FRAGMENTS]))
        if args.days:
            q = q.where(Entry.published_at >= text(f"now() - interval '{int(args.days)} days'"))
        q = q.order_by(Entry.published_at.desc())
        if args.limit:
            q = q.limit(args.limit)
        entries = (await db.execute(q)).scalars().all()
        print(f"articles linking a publisher IOC repository: {len(entries)}")
        total = 0
        for e in entries:
            links = publisher_ioc_links(e.content_html)
            if args.dry_run:
                print(f"  {str(e.published_at)[:10]} {e.title[:70]!r}: {[u for u, _ in links]}")
                continue
            try:
                n = await store_publisher_observables(db, e, seen_at=e.published_at)
                await db.commit()
            except Exception as exc:
                await db.rollback()
                print(f"  ! {e.id}: {exc}")
                continue
            total += n
            print(f"  {str(e.published_at)[:10]} {e.title[:70]!r}: {n} indicators")
        if not args.dry_run:
            print(f"sighted {total} publisher indicators across {len(entries)} articles")


if __name__ == "__main__":
    asyncio.run(main())
