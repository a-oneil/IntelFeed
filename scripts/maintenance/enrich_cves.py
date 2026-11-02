"""One-shot CVE enrichment backfill: EPSS scores, CISA KEV flags, NVD data.

Populates epss_score/epss_percentile, is_kev/kev_date_added/kev_due_date/
exploit_availability, and cvss_score/severity/description/affected_products/
references_ for all existing CVEs. Batched and resumable — the NVD phase only
selects CVEs still missing data, so re-running picks up where it left off.

Run inside the API container:
    docker compose -f docker-compose.dev.yml exec api python scripts/maintenance/enrich_cves.py
    docker compose -f docker-compose.dev.yml exec api python scripts/maintenance/enrich_cves.py --phase epss
    docker compose -f docker-compose.dev.yml exec api python scripts/maintenance/enrich_cves.py --phase nvd --limit 200
"""

import argparse
import asyncio
import sys

sys.path.insert(0, "/app")

from sqlalchemy import func as sa_func
from sqlalchemy import select

from app.database import async_session
from app.models.cve import CVE


async def backfill_epss() -> None:
    """Bulk-load EPSS scores for every CVE in the database (the epss-bulk-sync job)."""
    from app.workers.enrichment_tasks import _run_epss_bulk_sync

    print("[epss] downloading EPSS daily CSV...")
    stats = await _run_epss_bulk_sync()
    print(f"[epss] done: {stats}")


async def backfill_kev() -> None:
    """Run the full KEV sync (creates/updates KEV CVEs, sets flags + dates)."""
    from app.intelligence.external_feeds import KEV_REDIS_KEY, sync_kev_feed
    from app.services.redis_client import get_redis

    # Clear the catalog-version cache so the sync doesn't short-circuit
    try:
        r = await get_redis()
        await r.delete(KEV_REDIS_KEY)
    except Exception as e:  # noqa: BLE001
        print(f"[kev] warning: could not clear redis version key: {e}")

    print("[kev] syncing CISA KEV catalog...")
    async with async_session() as db:
        stats = await sync_kev_feed(db)
    print(f"[kev] done: {stats}")


async def backfill_nvd(limit: int | None) -> None:
    """Enrich CVEs missing CVSS/description from NVD (resumable). The NVD
    gateway paces the requests; ``delay`` only sizes the time estimate."""
    from app.enrichment.gateway import JOB_TOKEN_WAIT, SOURCE_REFUSALS
    from app.intelligence.cve import apply_nvd, enrich_from_nvd, nvd_gateway, nvd_request_pace

    async with async_session() as db:
        gateway, api_key = await nvd_gateway(db, max_wait=JOB_TOKEN_WAIT)
        delay = nvd_request_pace(api_key)

        # Only valid-format CVEs still missing authoritative data (resumable)
        query = (
            select(CVE)
            .where(
                CVE.description.is_(None) | CVE.cvss_score.is_(None),
                sa_func.length(sa_func.split_part(CVE.cve_id, "-", 3)) <= 5,
            )
            .order_by(CVE.cve_id)
        )
        if limit:
            query = query.limit(limit)
        result = await db.execute(query)
        cves = result.scalars().all()
        total = len(cves)
        print(f"[nvd] {total} CVEs to enrich (delay={delay}s, ~{total * delay / 60:.0f} min)")

        enriched = failed = 0
        for i, cve in enumerate(cves):
            try:
                nvd = await enrich_from_nvd(cve.cve_id, gateway, api_key)
            except SOURCE_REFUSALS as e:
                print(f"[nvd] stopping at {i}/{total}: {e} (re-run to resume)")
                break
            if nvd:
                # Same path as the NVD jobs: field map ranks, claims, context.
                await apply_nvd(db, cve, nvd, via="script")
                enriched += 1
            else:
                failed += 1

            if (i + 1) % 50 == 0:
                await db.commit()
                print(f"[nvd] progress: {enriched} enriched, {failed} failed ({i + 1}/{total})")

        await db.commit()
    print(f"[nvd] done: {enriched} enriched, {failed} failed")


async def main() -> None:
    parser = argparse.ArgumentParser(description="Backfill CVE enrichment data")
    parser.add_argument(
        "--phase",
        choices=["all", "epss", "kev", "nvd"],
        default="all",
        help="Which enrichment phase to run (default: all)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Max CVEs for the NVD phase (it resumes on re-run)",
    )
    args = parser.parse_args()

    if args.phase in ("all", "epss"):
        await backfill_epss()
    if args.phase in ("all", "kev"):
        await backfill_kev()
    if args.phase in ("all", "nvd"):
        await backfill_nvd(args.limit)


if __name__ == "__main__":
    asyncio.run(main())
