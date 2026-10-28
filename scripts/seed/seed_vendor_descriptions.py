"""Re-fetch and reformat Wikipedia descriptions for all vendors and products.

Replaces existing raw-text descriptions with properly formatted markdown.
Also attempts to fetch descriptions for entities that were missed on first pass.

Run inside the api container:
    docker compose -f docker-compose.dev.yml exec api python scripts/seed/seed_vendor_descriptions.py
    docker compose -f docker-compose.dev.yml exec api python scripts/seed/seed_vendor_descriptions.py --dry-run

--dry-run reports how many vendors and products would be processed without
querying Wikipedia. The fetch goes through the wikipedia source's gateway, whose
bucket paces it, so a real run over the full catalog takes a while; the dry run
returns immediately. A run the gateway refuses (rate limited, budget spent)
stops and keeps what it fetched; re-run it later.
"""

import argparse
import asyncio
import sys

sys.path.insert(0, "/app")
sys.path.insert(0, "backend")

from sqlalchemy import select

from app.database import async_session
from app.enrichment.gateway import JOB_TOKEN_WAIT, SOURCE_REFUSALS
from app.enrichment.pipeline import gateway_for
from app.enrichment.wikipedia_helper import fetch_wikipedia
from app.models.product import Product
from app.models.vendor import Vendor


async def main(dry_run: bool) -> None:
    async with async_session() as db:
        vendors = (await db.execute(select(Vendor).order_by(Vendor.name))).scalars().all()
        products = (await db.execute(select(Product).order_by(Product.name))).scalars().all()

        print(f"Processing {len(vendors)} vendors and {len(products)} products...")
        print()

        if dry_run:
            # Every row is re-fetched unconditionally, so scope is simply the row
            # count. Querying Wikipedia here would cost minutes to learn nothing.
            missing_v = sum(1 for v in vendors if not v.wikipedia_url)
            missing_p = sum(1 for p in products if not p.wikipedia_url)
            print(f"Would query Wikipedia for {len(vendors) + len(products)} entities and rewrite")
            print("their description, wikipedia_url and wikipedia_content.")
            print(f"  vendors with no wikipedia_url yet:  {missing_v} of {len(vendors)}")
            print(f"  products with no wikipedia_url yet: {missing_p} of {len(products)}")
            print("\nDry run — nothing written, and Wikipedia was not queried.")
            return

        gateway, _ = await gateway_for(db, "wikipedia", max_wait=JOB_TOKEN_WAIT)

        async def fetch(name: str, entity_type: str) -> dict | None:
            return await fetch_wikipedia(name, entity_type, transport=gateway.transport())

        updated = 0
        fetched = 0
        failed = 0

        for v in vendors:
            print(f"  Vendor: {v.name}...", end=" ", flush=True)
            try:
                result = await fetch(v.name, "vendor")
            except SOURCE_REFUSALS as e:
                print(f"stopping: {e}")
                await db.commit()
                return
            if result:
                v.description = result["content"]
                v.wikipedia_url = result["url"]
                v.wikipedia_content = result["content"]
                updated += 1
                fetched += 1
                print(f"OK ({len(result['content'])} chars)")
            else:
                failed += 1
                print("no article found")

        await db.commit()
        print(f"\nVendors: {updated} updated, {failed} no article found")

        updated_p = 0
        failed_p = 0
        for p in products:
            print(f"  Product: {p.name}...", end=" ", flush=True)
            try:
                result = await fetch(p.name, "product")
            except SOURCE_REFUSALS as e:
                print(f"stopping: {e}")
                break
            if result:
                p.description = result["content"]
                p.wikipedia_url = result["url"]
                p.wikipedia_content = result["content"]
                updated_p += 1
                fetched += 1
                print(f"OK ({len(result['content'])} chars)")
            else:
                failed_p += 1
                print("no article found")

        await db.commit()
        print(f"\nProducts: {updated_p} updated, {failed_p} no article found")
        print(f"\nTotal Wikipedia descriptions fetched: {fetched}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report how many entities would be processed, without querying Wikipedia.",
    )
    asyncio.run(main(parser.parse_args().dry_run))
