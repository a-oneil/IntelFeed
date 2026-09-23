"""Backfill detection rule metadata → structured fields (mitre_tactics, source_ttps).

Re-extracts metadata from rule content and syncs tactics/techniques to the
rule's mitre_tactics and source_ttps fields. Normalizes tactic names to
snake_case to match the frontend format.

Run inside the API container:
    docker compose -f docker-compose.dev.yml exec api python scripts/archive/backfill_rule_metadata.py
"""

import asyncio
import sys

sys.path.insert(0, "/app")

from sqlalchemy import func, select

from app.database import async_session
from app.intelligence.rule_metadata import extract_rule_metadata, map_metadata_to_fields
from app.models.detection_rule import DetectionRule

BATCH_SIZE = 100


async def main():
    async with async_session() as db:
        total = await db.scalar(select(func.count(DetectionRule.id)))
        print(f"Processing {total} detection rules...")

        updated = 0
        skipped = 0
        offset = 0

        while offset < total:
            result = await db.execute(
                select(DetectionRule).order_by(DetectionRule.created_at).offset(offset).limit(BATCH_SIZE)
            )
            rules = result.scalars().all()
            if not rules:
                break

            for rule in rules:
                # Re-extract metadata from rule content
                metadata = extract_rule_metadata(rule.rule_type, rule.rule_content)

                # Also check existing stored metadata
                existing_meta = rule.metadata_ or {}
                meta = metadata or existing_meta

                if not meta:
                    skipped += 1
                    continue

                mapped = map_metadata_to_fields(meta)
                changed = False

                # Sync mitre_tactics (normalized to snake_case)
                new_tactics = mapped.get("mitre_tactics", [])
                if new_tactics and (not rule.mitre_tactics or set(rule.mitre_tactics) != set(new_tactics)):
                    rule.mitre_tactics = new_tactics
                    changed = True

                # Sync source_ttps from ATT&CK technique IDs
                new_ttps = mapped.get("source_ttps", [])
                if new_ttps:
                    existing_ttps = set(rule.source_ttps or [])
                    merged_ttps = list(existing_ttps | set(new_ttps))
                    if set(merged_ttps) != existing_ttps:
                        rule.source_ttps = merged_ttps
                        changed = True

                # Update stored metadata if we re-extracted
                if metadata and metadata != existing_meta:
                    # Preserve internal keys
                    preserved = {k: v for k, v in existing_meta.items() if k in ("ai_chat_history", "rule_conversions")}
                    rule.metadata_ = {**metadata, **preserved}
                    changed = True

                if changed:
                    db.add(rule)
                    updated += 1
                else:
                    skipped += 1

            await db.commit()
            offset += BATCH_SIZE
            print(f"  Processed {min(offset, total)}/{total} rules ({updated} updated, {skipped} skipped)")

        print(f"\nDone! Updated {updated} rules, skipped {skipped}.")


if __name__ == "__main__":
    asyncio.run(main())
