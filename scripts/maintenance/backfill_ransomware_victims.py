"""Backfill `victim_disclosures` from ransomware.live's per-year history.

The live sync only reads /recentvictims, so a fresh install holds just the latest
victims. This script feeds the same resolver and dedup path the per-year history
endpoint instead, so the Landscape dashboard has trend data from `--start-year` on.

Run inside the API container (`./scripts` is bind-mounted at /app/scripts):

    docker compose -f docker-compose.dev.yml exec api \
        python scripts/maintenance/backfill_ransomware_victims.py --start-year 2022

Repeatable: the (source, guid) unique constraint means a re-run skips rows it
already holds and only adds what is new.
"""

import argparse
import asyncio
import logging
from datetime import UTC, datetime

import httpx

from app.adapters.base import ParsedEntry, ParsedFeedMeta
from app.adapters.ransomware_live import RansomwareLiveAdapter
from app.intelligence.ransomware_sync import sync_ransomware_victims
from app.workers.db import worker_session

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("backfill_ransomware_victims")

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_YEAR_URL = "https://api.ransomware.live/v2/victims/{year}"


class _HistoryAdapter(RansomwareLiveAdapter):
    """Fetches full history via the per-year endpoint, reusing _parse_victim."""

    def __init__(self, years: list[int]):
        self.years = years

    async def fetch_entries(
        self, config: dict, since: datetime | None = None
    ) -> tuple[ParsedFeedMeta, list[ParsedEntry]]:
        cutoff = since or _EPOCH
        meta = self.get_feed_meta(config)
        entries: list[ParsedEntry] = []
        headers = {"User-Agent": "IntelFeed/1.0", "Accept": "application/json"}
        async with httpx.AsyncClient(timeout=120.0, headers=headers) as client:
            for year in self.years:
                try:
                    resp = await client.get(_YEAR_URL.format(year=year))
                except httpx.HTTPError as exc:
                    logger.warning("year %s fetch failed: %s", year, exc)
                    continue
                if resp.status_code != 200:
                    logger.warning("year %s returned %s", year, resp.status_code)
                    continue
                rows = resp.json()
                if not isinstance(rows, list):
                    rows = rows.get("victims", rows.get("data", []))
                parsed = [e for raw in rows if (e := self._parse_victim(raw, cutoff)) is not None]
                logger.info("year %s: %d/%d postings parsed", year, len(parsed), len(rows))
                entries.extend(parsed)
        return meta, entries


async def main(start_year: int, end_year: int) -> None:
    years = list(range(start_year, end_year + 1))
    logger.info("Backfilling ransomware.live history for years %s", years)
    async with worker_session() as db:
        # since=_EPOCH so nothing is filtered as "already seen"; guid uniqueness dedups.
        stats = await sync_ransomware_victims(db, since=_EPOCH, adapters=[_HistoryAdapter(years)])
    logger.info("Backfill complete: %s", {k: v for k, v in stats.items() if not k.endswith("_ids")})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Backfill ransomware.live victim history")
    parser.add_argument("--start-year", type=int, default=2022)
    parser.add_argument("--end-year", type=int, default=datetime.now(UTC).year)
    args = parser.parse_args()
    asyncio.run(main(args.start_year, args.end_year))
