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
import gzip
import sys
from datetime import UTC, datetime

sys.path.insert(0, "/app")

import httpx
from sqlalchemy import func as sa_func
from sqlalchemy import select

from app.database import async_session
from app.models.cve import CVE

EPSS_CSV_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
BATCH_SIZE = 200


async def backfill_epss() -> None:
    """Bulk-load EPSS scores for every CVE in the database."""
    from app.workers.enrichment_tasks import parse_epss_csv

    print("[epss] downloading EPSS daily CSV...")
    async with httpx.AsyncClient(timeout=120.0, follow_redirects=True) as client:
        resp = await client.get(EPSS_CSV_URL)
        resp.raise_for_status()
    epss_data = parse_epss_csv(gzip.decompress(resp.content).decode("utf-8"))
    print(f"[epss] parsed {len(epss_data)} scores")

    now = datetime.now(UTC)
    updated = 0
    async with async_session() as db:
        result = await db.execute(select(CVE))
        cves = result.scalars().all()
        for i, cve in enumerate(cves):
            scores = epss_data.get(cve.cve_id)
            if not scores:
                continue
            cve.epss_score = scores["epss_score"]
            cve.epss_percentile = scores["percentile"]
            cve.epss_updated_at = now
            db.add(cve)
            updated += 1
            if updated % BATCH_SIZE == 0:
                await db.commit()
                print(f"[epss] {updated} updated ({i + 1}/{len(cves)} scanned)")
        await db.commit()
    print(f"[epss] done: {updated}/{len(cves)} CVEs updated")


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
    """Enrich CVEs missing CVSS/description from NVD (rate-limit aware, resumable)."""
    from app.intelligence.cve import enrich_from_nvd
    from app.services.system_settings import get_setting

    async with async_session() as db:
        api_key = await get_setting("nvd_api_key", db)
        delay = 0.7 if api_key else 6.0

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
            nvd = await enrich_from_nvd(cve.cve_id)
            if nvd:
                if nvd.get("cvss_score") is not None:
                    cve.cvss_score = nvd["cvss_score"]
                if nvd.get("severity"):
                    cve.severity = nvd["severity"]
                if nvd.get("description") and not cve.description:
                    cve.description = nvd["description"]
                cve.affected_products = nvd.get("affected_products", cve.affected_products)
                cve.references_ = nvd.get("references", cve.references_)
                cve.nvd_data = nvd.get("nvd_data", cve.nvd_data)
                db.add(cve)
                enriched += 1
            else:
                failed += 1

            if (i + 1) % 50 == 0:
                await db.commit()
                print(f"[nvd] progress: {enriched} enriched, {failed} failed ({i + 1}/{total})")

            await asyncio.sleep(delay)

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
