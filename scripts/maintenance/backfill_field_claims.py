"""Seed entity_field_claims from provenance IntelFeed already recorded elsewhere.

Field-level provenance started being written at the point of edit, so every
fact already on a profile arrived before the table existed. Three stores hold
recoverable evidence about where those facts came from, and this sweep turns
each into claims:

  actor_description_history   every description change, with its source
                              ('ai_refresh' | 'manual' | 'initial_extraction')
                              and the AIResult behind it
  enrichment_results          what wikipedia / mitre_attack / malpedia actually
                              returned per entity — only claimed where the
                              stored value still matches the column, so a stale
                              cached response can't manufacture a citation
  created_via + created_from_entry_id
                              AI-extracted entities name the article they were
                              minted from; their populated tracked fields are
                              attributed to that article

Nothing is inferred beyond those records. A field whose origin is genuinely
unrecoverable stays unattributed, which is the honest answer and is what the
profile reports.

Idempotent — claims collapse on claim_key, so re-running refreshes recency
rather than duplicating.

Run inside the api container:
    docker compose -f docker-compose.dev.yml exec api python scripts/maintenance/backfill_field_claims.py --dry-run
    docker compose -f docker-compose.dev.yml exec api python scripts/maintenance/backfill_field_claims.py
"""

import argparse
import asyncio
import sys

sys.path.insert(0, "/app")

from sqlalchemy import func, select  # noqa: E402

import app.models  # noqa: E402,F401 — register all mappers
from app import entity_types  # noqa: E402
from app.database import async_session  # noqa: E402
from app.models.enrichment import EnrichmentResult  # noqa: E402
from app.models.entity_field_claim import EntityFieldClaim  # noqa: E402
from app.models.entity_maintenance import ActorDescriptionHistory  # noqa: E402
from app.services.claim_provenance import PROVENANCE_FIELDS, record_claim, render_value  # noqa: E402
from app.services.entity_summary import ENTITY_MODEL_MAP  # noqa: E402

BATCH = 500

# ActorDescriptionHistory.source -> claim source_kind.
_HISTORY_KIND = {
    "ai_refresh": "ai_assessment",
    "manual": "analyst",
    "initial_extraction": "ai_extraction",
}

# enrichment_results.source_type -> the parsed_data keys worth claiming, mapped
# onto the entity column each one fills.
_ENRICHMENT_FIELDS = {
    "wikipedia": {"first_paragraph": "description"},
    "mitre_attack": {"description": "description", "mitre_id": "mitre_id", "external_id": "mitre_id"},
    "malpedia": {"description": "description", "country": "country"},
}


async def backfill_description_history(db, dry_run: bool) -> int:
    """Every recorded description change becomes a claim by whoever made it."""
    ThreatActor = ENTITY_MODEL_MAP[entity_types.THREAT_ACTOR][0]
    written = 0
    offset = 0
    while True:
        rows = (
            (
                await db.execute(
                    select(ActorDescriptionHistory)
                    .where(ActorDescriptionHistory.new_text.is_not(None))
                    .order_by(ActorDescriptionHistory.created_at)
                    .offset(offset)
                    .limit(BATCH)
                )
            )
            .scalars()
            .all()
        )
        if not rows:
            break
        actor_ids = {r.actor_id for r in rows}
        known = set((await db.execute(select(ThreatActor.id).where(ThreatActor.id.in_(actor_ids)))).scalars().all())
        for row in rows:
            if row.actor_id not in known:
                continue  # actor merged or deleted since
            if dry_run:
                written += 1
                continue
            if await record_claim(
                db,
                entity_type=entity_types.THREAT_ACTOR,
                entity_id=row.actor_id,
                field="description",
                value=row.new_text,
                source_kind=_HISTORY_KIND.get(row.source, "ai_assessment"),
                source_ref=row.source,
                quote=row.change_reason,
                ai_result_id=row.ai_result_id,
            ):
                written += 1
        if not dry_run:
            await db.commit()
        offset += BATCH
    return written


async def backfill_enrichment(db, dry_run: bool) -> int:
    """Claim what an adapter returned, but only where it still matches the column."""
    written = 0
    for source_type, field_map in _ENRICHMENT_FIELDS.items():
        offset = 0
        while True:
            rows = (
                (
                    await db.execute(
                        select(EnrichmentResult)
                        .where(
                            EnrichmentResult.source_type == source_type,
                            EnrichmentResult.status.in_(("success", "cached")),
                        )
                        .order_by(EnrichmentResult.enriched_at)
                        .offset(offset)
                        .limit(BATCH)
                    )
                )
                .scalars()
                .all()
            )
            if not rows:
                break
            for row in rows:
                model_entry = ENTITY_MODEL_MAP.get(row.entity_type)
                if not model_entry:
                    continue
                model_cls = model_entry[0]
                entity = (await db.execute(select(model_cls).where(model_cls.id == row.entity_id))).scalar_one_or_none()
                if entity is None:
                    continue
                tracked = PROVENANCE_FIELDS.get(row.entity_type, ())
                for key, field in field_map.items():
                    if field not in tracked:
                        continue
                    value = (row.parsed_data or {}).get(key)
                    if not value:
                        continue
                    # Only claim it if the adapter's value is what the profile
                    # actually shows — otherwise this is a response that lost,
                    # and citing it would attribute a value nobody wrote.
                    if render_value(value).casefold() != render_value(getattr(entity, field, None)).casefold():
                        continue
                    if dry_run:
                        written += 1
                        continue
                    if await record_claim(
                        db,
                        entity_type=row.entity_type,
                        entity_id=row.entity_id,
                        field=field,
                        value=value,
                        source_kind="enrichment",
                        source_ref=source_type,
                    ):
                        written += 1
            if not dry_run:
                await db.commit()
            offset += BATCH
    return written


async def backfill_extraction_origins(db, dry_run: bool) -> int:
    """AI-extracted entities name the article they were minted from."""
    written = 0
    for entity_type, (model_cls, _junction, _fk) in ENTITY_MODEL_MAP.items():
        tracked = PROVENANCE_FIELDS.get(entity_type, ())
        if not tracked or not hasattr(model_cls, "created_from_entry_id"):
            continue
        offset = 0
        while True:
            rows = (
                (
                    await db.execute(
                        select(model_cls)
                        .where(
                            model_cls.created_via == "ai_extraction",
                            model_cls.created_from_entry_id.is_not(None),
                        )
                        .order_by(model_cls.id)
                        .offset(offset)
                        .limit(BATCH)
                    )
                )
                .scalars()
                .all()
            )
            if not rows:
                break
            for entity in rows:
                for field in tracked:
                    value = getattr(entity, field, None)
                    if not render_value(value):
                        continue
                    if dry_run:
                        written += 1
                        continue
                    if await record_claim(
                        db,
                        entity_type=entity_type,
                        entity_id=entity.id,
                        field=field,
                        value=value,
                        source_kind="ai_extraction",
                        entry_id=entity.created_from_entry_id,
                        confidence=getattr(entity, "created_confidence", None),
                    ):
                        written += 1
            if not dry_run:
                await db.commit()
            offset += BATCH
    return written


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="Count what would be written, write nothing")
    parser.add_argument(
        "--only",
        choices=("history", "enrichment", "extraction"),
        help="Run a single pass instead of all three",
    )
    args = parser.parse_args()

    async with async_session() as db:
        before = (await db.execute(select(func.count()).select_from(EntityFieldClaim))).scalar_one()
        print(f"entity_field_claims before: {before:,}")

        if args.only in (None, "history"):
            n = await backfill_description_history(db, args.dry_run)
            print(f"  description history : {n:,}")
        if args.only in (None, "enrichment"):
            n = await backfill_enrichment(db, args.dry_run)
            print(f"  enrichment results  : {n:,}")
        if args.only in (None, "extraction"):
            n = await backfill_extraction_origins(db, args.dry_run)
            print(f"  extraction origins  : {n:,}")

        after = (await db.execute(select(func.count()).select_from(EntityFieldClaim))).scalar_one()
        print(f"entity_field_claims after:  {after:,} ({after - before:+,})")
        if args.dry_run:
            print("(dry run — nothing written)")


if __name__ == "__main__":
    asyncio.run(main())
