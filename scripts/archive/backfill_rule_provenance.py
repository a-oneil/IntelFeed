"""Backfill provenance/reuse fields on existing detection_rules.

Populates license, upstream_updated_at, references (from the already-stored
`metadata` blob) and source_products (from linked CVEs via cve_affected) for
rules that were imported before the research-redesign phase-1 fields existed.

Run inside the API container:
    docker compose -f docker-compose.dev.yml exec api python scripts/archive/backfill_rule_provenance.py
Idempotent: re-running only rewrites the four derived fields.
"""

import asyncio
import sys

sys.path.insert(0, "/app")

from sqlalchemy import func, select

from app.database import async_session
from app.models.cve import CVE
from app.models.cve_affected import CVEAffected
from app.models.detection_rule import DetectionRule
from app.models.product import Product
from app.services.github_rule_import import (
    _license_for,
    _parse_iso_dt,
    _references_from_meta,
)

BATCH_SIZE = 500


def _cve_strings(source_cves) -> list[str]:
    """Normalize a rule's source_cves (list of str or dicts) to CVE-ID strings."""
    out: list[str] = []
    for c in source_cves or []:
        if isinstance(c, str):
            out.append(c.strip().upper())
        elif isinstance(c, dict):
            cid = c.get("cve_id") or c.get("id") or c.get("cve")
            if cid:
                out.append(str(cid).strip().upper())
    return [c for c in out if c.startswith("CVE-")]


async def _products_for_cves(db, cve_ids: list[str]) -> list[str]:
    """Distinct affected product names (resolved) / raw CPE products for the given CVEs."""
    if not cve_ids:
        return []
    rows = await db.execute(
        select(func.coalesce(Product.name, CVEAffected.cpe_product))
        .select_from(CVEAffected)
        .join(CVE, CVE.id == CVEAffected.cve_id)
        .outerjoin(Product, Product.id == CVEAffected.product_id)
        .where(CVE.cve_id.in_(cve_ids))
    )
    names = {r[0] for r in rows.all() if r[0]}
    return sorted(names)


async def main() -> None:
    async with async_session() as db:
        total = (await db.execute(select(func.count(DetectionRule.id)))).scalar() or 0
        print(f"Backfilling provenance for {total} detection rules...")

        processed = 0
        updated = 0
        offset = 0
        while True:
            result = await db.execute(
                select(DetectionRule).order_by(DetectionRule.created_at).limit(BATCH_SIZE).offset(offset)
            )
            rules = list(result.scalars().all())
            if not rules:
                break

            for rule in rules:
                meta = rule.metadata_ or {}
                license_ = _license_for(meta.get("owner"), meta.get("repo"))
                upstream = _parse_iso_dt(meta.get("commit_date"))
                refs = _references_from_meta(meta)
                products = await _products_for_cves(db, _cve_strings(rule.source_cves))

                changed = (
                    rule.license != license_
                    or rule.upstream_updated_at != upstream
                    or list(rule.references or []) != refs
                    or list(rule.source_products or []) != products
                )
                if changed:
                    rule.license = license_
                    rule.upstream_updated_at = upstream
                    rule.references = refs
                    rule.source_products = products
                    updated += 1

            await db.commit()
            processed += len(rules)
            offset += BATCH_SIZE
            print(f"  {processed}/{total} processed, {updated} updated")

        print(f"Done. {updated} rules updated.")


if __name__ == "__main__":
    asyncio.run(main())
