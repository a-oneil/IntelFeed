"""Fill entity_context from the enrichment results already stored.

Lookups write a profile's source context as they run. Entities enriched before
the table existed have results but no context until their sources look again;
this writes context from each entity's latest successful result per source,
dated by that result (so a result past its expiry shows as stale).

Idempotent: each run rewrites the same rows.

Run inside the api container:
    docker compose -f docker-compose.dev.yml exec api python scripts/maintenance/backfill_entity_context.py --dry-run
    docker compose -f docker-compose.dev.yml exec api python scripts/maintenance/backfill_entity_context.py
"""

import argparse
import asyncio
import sys

sys.path.insert(0, "/app")

from sqlalchemy import select  # noqa: E402

import app.models  # noqa: E402,F401 — register all mappers
from app.database import async_session  # noqa: E402
from app.enrichment.context import contexts_for, store_context  # noqa: E402
from app.enrichment.registry import SOURCE_REGISTRY  # noqa: E402
from app.models.enrichment import EnrichmentResult  # noqa: E402

BATCH = 500


async def main(dry_run: bool) -> None:
    sources = [st for st, cls in SOURCE_REGISTRY.items() if any(contexts_for(cls, t) for t in cls.applies_to)]
    latest = (
        select(EnrichmentResult)
        .where(EnrichmentResult.status == "success", EnrichmentResult.source_type.in_(sources))
        .distinct(EnrichmentResult.entity_type, EnrichmentResult.entity_id, EnrichmentResult.source_type)
        .order_by(
            EnrichmentResult.entity_type,
            EnrichmentResult.entity_id,
            EnrichmentResult.source_type,
            EnrichmentResult.enriched_at.desc(),
        )
    )
    written = 0
    async with async_session() as db:
        while results := (await db.execute(latest.offset(written).limit(BATCH))).scalars().all():
            for result in results:
                if not dry_run:
                    await store_context(
                        db,
                        result.entity_type,
                        result.entity_id,
                        result.source_type,
                        result.parsed_data,
                        observed_at=result.enriched_at,
                        expires_at=result.expires_at,
                    )
            written += len(results)
            if not dry_run:
                await db.commit()
    print(f"{'Would write' if dry_run else 'Wrote'} context from {written} results ({', '.join(sorted(sources))})")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dry-run", action="store_true", help="Count the results without writing")
    asyncio.run(main(parser.parse_args().dry_run))
