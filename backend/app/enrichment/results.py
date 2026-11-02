"""Overwriting a source's one result row for an entity.

Scheduled jobs store answers through ``app.enrichment.pipeline.apply_source_result``,
which adds a row only when the answer changed and otherwise re-dates the
latest one; the EPSS sync does the same set-based. This helper is for a writer
that wants exactly one row per (entity, source) whatever the answer.

Not for the wikipedia writer: it stores long-lived ``user_cleared`` marker rows
whose semantics an upsert would clobber.
"""

import uuid
from datetime import UTC, datetime

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.enrichment import EnrichmentResult


async def upsert_enrichment_result(
    db: AsyncSession,
    *,
    entity_type: str,
    entity_id: uuid.UUID,
    source_type: str,
    raw_response: dict,
    parsed_data: dict,
    expires_at: datetime,
    status: str = "success",
    enriched_at: datetime | None = None,
) -> None:
    """Overwrite the existing result row for (entity, source), inserting if absent."""
    now = enriched_at or datetime.now(UTC)
    result = await db.execute(
        update(EnrichmentResult)
        .where(
            EnrichmentResult.entity_type == entity_type,
            EnrichmentResult.entity_id == entity_id,
            EnrichmentResult.source_type == source_type,
        )
        .values(
            raw_response=raw_response,
            parsed_data=parsed_data,
            enriched_at=now,
            expires_at=expires_at,
            status=status,
        )
    )
    if result.rowcount == 0:
        db.add(
            EnrichmentResult(
                entity_type=entity_type,
                entity_id=entity_id,
                source_type=source_type,
                raw_response=raw_response,
                parsed_data=parsed_data,
                enriched_at=now,
                expires_at=expires_at,
                status=status,
            )
        )
