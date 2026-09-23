"""Shared helper to fetch telemetry sources for AI prompt injection."""

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.telemetry_source import TelemetrySource


async def get_telemetry_for_prompt(db: AsyncSession, user_id: uuid.UUID) -> list[dict]:
    """Fetch enabled telemetry sources formatted for Jinja2 prompt templates."""
    result = await db.execute(
        select(TelemetrySource)
        .where(
            TelemetrySource.enabled == True,  # noqa: E712
        )
        .order_by(TelemetrySource.category)
    )
    return [
        {
            "name": ts.name,
            "category": ts.category,
            "vendor": ts.vendor or "",
            "product": ts.product or "",
            "log_types": ts.log_types or [],
            "ingested_into": ts.ingested_into or "",
        }
        for ts in result.scalars().all()
    ]
