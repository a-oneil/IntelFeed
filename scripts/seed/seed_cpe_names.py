"""Seed metadata_["cpe_names"] on vendors/products so NVD CPE pairs resolve.

cpe_names is a resolver-only curation list (see intelligence/cpe_resolver.py) —
it is deliberately separate from `aliases`, which feed the autolinker vocab.
Entries ending in "*" are prefix rules (products only).

Idempotent: merges into any existing cpe_names, never removes entries. Skips
entities that don't exist (match-only policy — we don't create entities here).

Run inside the api container:
    python scripts/seed/seed_cpe_names.py [--dry-run]
Then trigger the re-resolution sweep (or wait for the nightly beat):
    celery -A app.workers.celery_app call app.workers.maintenance.resolve_cve_affected
"""

import argparse
import asyncio
import sys

sys.path.insert(0, "/app")

from sqlalchemy import select  # noqa: E402

from app.models.product import Product  # noqa: E402
from app.models.vendor import Vendor  # noqa: E402
from app.workers.db import worker_session  # noqa: E402

# (entity_name, cpe_names) — names must match existing entities exactly.
PRODUCT_SEEDS: list[tuple[str, list[str]]] = [
    (
        "Citrix NetScaler",
        ["netscaler", "netscaler*", "application_delivery_controller"],
    ),
    ("Linux", ["linux_kernel"]),
    ("VirtualBox", ["vm_virtualbox"]),
    (
        "Windows",
        ["windows_10*", "windows_11*", "windows_server*", "windows_7", "windows_8*", "windows_vista", "windows_xp"],
    ),
]

VENDOR_SEEDS: list[tuple[str, list[str]]] = [
    ("Linux Foundation", ["linux"]),
]


async def seed(dry_run: bool) -> None:
    async with worker_session() as db:
        for model, seeds in ((Product, PRODUCT_SEEDS), (Vendor, VENDOR_SEEDS)):
            kind = model.__name__.lower()
            for name, cpe_names in seeds:
                entity = (await db.execute(select(model).where(model.name == name))).scalar_one_or_none()
                if entity is None:
                    print(f"SKIP  {kind} {name!r} — no such entity (create it first, then re-run)")
                    continue
                metadata = dict(entity.metadata_ or {})
                existing = list(metadata.get("cpe_names") or [])
                added = [c for c in cpe_names if c not in existing]
                if not added:
                    print(f"OK    {kind} {name!r} — already seeded")
                    continue
                metadata["cpe_names"] = existing + added
                if not dry_run:
                    entity.metadata_ = metadata
                print(f"SEED  {kind} {name!r} += {added}")
        if dry_run:
            print("(dry run — nothing written)")
        else:
            await db.commit()
            print("Committed. Run resolve_cve_affected to attach existing CVE pairs.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    asyncio.run(seed(parser.parse_args().dry_run))
