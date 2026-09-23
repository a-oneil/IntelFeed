"""Promote `metadata.rule_conversions` blobs into real sibling detection rules.

Until now a converted rule lived as a JSON blob on its parent: invisible to
/detection-rules/search, absent from detection_rule_versions, not exportable on
its own, and deleted with the parent. `detection_rules.derived_from` makes it a
row instead. This moves what already exists.

The blob is left in place. It is user data, some of it hand-edited, and the
panel prefers a sibling wherever one exists — so keeping it costs nothing and
losing it is unrecoverable. Pass --prune to strip it after a verified run.

Run inside the API container:
    docker compose -f docker-compose.dev.yml exec api \
        python /app/scripts/maintenance/backfill_rule_conversions.py --dry-run
    docker compose -f docker-compose.dev.yml exec api \
        python /app/scripts/maintenance/backfill_rule_conversions.py
"""

import argparse
import asyncio
import sys

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, "/app")

from app.config import settings
from app.models.detection_rule import DetectionRule
from app.services.entity_indexer import index_rules

# Mirrors RULE_TYPE_LABELS in app/api/intelligence.py. Duplicated rather than
# imported so the script does not drag the whole API module (and its AI engine
# imports) into a maintenance run.
RULE_TYPE_LABELS = {
    "sigma": "SIGMA",
    "splunk_spl": "Splunk SPL",
    "kql": "KQL",
    "elastic_ql": "Elastic QL",
    "crowdstrike_ql": "CrowdStrike QL",
    "snort_suricata": "Snort/Suricata",
    "yara": "YARA",
    "nuclei": "Nuclei",
    "panther": "Panther",
}


async def backfill(dry_run: bool, prune: bool) -> dict:
    engine = create_async_engine(settings.database_url, echo=False)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    stats = {"parents": 0, "conversions": 0, "created": 0, "existing": 0, "skipped": 0, "pruned": 0, "indexed": 0}
    created: list[DetectionRule] = []
    try:
        async with async_session() as db:
            before = (await db.execute(sa.select(sa.func.count()).select_from(DetectionRule))).scalar() or 0
            siblings_before = (
                await db.execute(
                    sa.select(sa.func.count()).select_from(DetectionRule).where(DetectionRule.derived_from.isnot(None))
                )
            ).scalar() or 0

            parents = (
                (
                    await db.execute(
                        sa.select(DetectionRule)
                        .where(DetectionRule.metadata_.has_key("rule_conversions"))
                        .order_by(DetectionRule.created_at)
                    )
                )
                .scalars()
                .all()
            )
            print(f"detection_rules: {before} rows, {siblings_before} already derived")
            print(f"rules carrying metadata.rule_conversions: {len(parents)}")

            for parent in parents:
                conversions = (parent.metadata_ or {}).get("rule_conversions") or {}
                if not isinstance(conversions, dict):
                    print(f"  ! {parent.id} rule_conversions is {type(conversions).__name__}, not an object — skipped")
                    continue
                stats["parents"] += 1

                existing = {
                    r.rule_type: r
                    for r in (
                        (await db.execute(sa.select(DetectionRule).where(DetectionRule.derived_from == parent.id)))
                        .scalars()
                        .all()
                    )
                }

                for target_type, blob in conversions.items():
                    stats["conversions"] += 1
                    content = (blob or {}).get("content") if isinstance(blob, dict) else None
                    if not content or not str(content).strip():
                        print(f"  - {parent.id} → {target_type}: empty content, skipped")
                        stats["skipped"] += 1
                        continue
                    if target_type in existing:
                        print(f"  = {parent.id} → {target_type}: sibling {existing[target_type].id} already exists")
                        stats["existing"] += 1
                        continue

                    label = RULE_TYPE_LABELS.get(target_type, target_type)
                    sibling = DetectionRule(
                        entry_id=parent.entry_id,
                        # The conversion was run by whoever owned the parent; there
                        # is no per-conversion author recorded in the blob.
                        created_by=parent.created_by,
                        derived_from=parent.id,
                        rule_type=target_type,
                        title=f"{parent.title} ({label})",
                        description=parent.description,
                        rule_content=content,
                        severity=parent.severity,
                        tags=list(parent.tags or []),
                        source_ttps=list(parent.source_ttps or []),
                        source_cves=list(parent.source_cves or []),
                        is_draft=True,
                        mitre_tactics=list(parent.mitre_tactics or []),
                        source_entries=list(parent.source_entries or []),
                        source_actors=list(parent.source_actors or []),
                        source_campaigns=list(parent.source_campaigns or []),
                        references=list(parent.references or []),
                        license=parent.license,
                        metadata_={
                            "conversion": {
                                "converted_from": str(parent.id),
                                "source_type": parent.rule_type,
                                "converted_at": blob.get("converted_at"),
                                "model": blob.get("model"),
                                "tokens_used": blob.get("tokens_used"),
                                "cost": blob.get("cost"),
                                "backfilled": True,
                            }
                        },
                    )
                    print(f"  + {parent.id} → {target_type}: {sibling.title!r} ({len(content)} chars)")
                    stats["created"] += 1
                    if not dry_run:
                        db.add(sibling)
                        await db.flush()
                        existing[target_type] = sibling
                        created.append(sibling)

                if prune and not dry_run:
                    meta = dict(parent.metadata_ or {})
                    meta.pop("rule_conversions", None)
                    parent.metadata_ = meta
                    stats["pruned"] += 1

            if dry_run:
                await db.rollback()
                print("\n-- dry run, nothing written --")
            else:
                await db.commit()
                after = (await db.execute(sa.select(sa.func.count()).select_from(DetectionRule))).scalar() or 0
                siblings_after = (
                    await db.execute(
                        sa.select(sa.func.count())
                        .select_from(DetectionRule)
                        .where(DetectionRule.derived_from.isnot(None))
                    )
                ).scalar() or 0
                print(f"\ndetection_rules: {before} -> {after} rows, {siblings_before} -> {siblings_after} derived")

                # /detection-rules/search reads Meilisearch, so a row that is
                # never indexed is still invisible — the whole point of the
                # promotion. Indexed after the commit so a failed write cannot
                # leave the index ahead of the database.
                if created:
                    await index_rules(db, created)
                    stats["indexed"] = len(created)
                    print(f"indexed {len(created)} sibling rules into Meilisearch")
    finally:
        await engine.dispose()

    print(f"stats: {stats}")
    return stats


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true", help="Report what would be created, write nothing")
    ap.add_argument(
        "--prune",
        action="store_true",
        help="Strip metadata.rule_conversions from parents after promoting them (destructive)",
    )
    args = ap.parse_args()
    asyncio.run(backfill(dry_run=args.dry_run, prune=args.prune))


if __name__ == "__main__":
    main()
