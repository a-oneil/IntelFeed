"""Shared helper to fetch telemetry sources for AI prompt injection."""

import uuid

from sqlalchemy import func, select
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


# Budgets for analysts' notes in a prompt: enough to carry "the EC2 fleet has no
# GuardDuty agent", not enough to crowd out the article.
NOTE_CHARS_PER_SOURCE = 600
NOTE_CHARS_TOTAL = 3000


async def get_telemetry_notes_for_prompt(db: AsyncSession) -> list[dict]:
    """What analysts wrote about the enabled sources, for the ``telemetry_notes`` variable.

    [{source, notes: [str]}], newest note first. Only notes with text: a bare
    saved link tells a model nothing it can use. A link's quoted passage is
    included with its note. Trimmed to NOTE_CHARS_PER_SOURCE per source and
    NOTE_CHARS_TOTAL overall.
    """
    from app.models.telemetry_source_note import TelemetrySourceNote

    enabled = select(func.lower(TelemetrySource.name)).where(TelemetrySource.enabled == True)  # noqa: E712
    rows = (
        await db.execute(
            select(TelemetrySourceNote)
            .where(
                func.lower(TelemetrySourceNote.source_name).in_(enabled),
                TelemetrySourceNote.content.is_not(None),
            )
            .order_by(TelemetrySourceNote.source_name, TelemetrySourceNote.created_at.desc())
        )
    ).scalars()
    by_source: dict[str, list[str]] = {}
    used: dict[str, int] = {}
    total = 0
    for note in rows:
        text = " ".join(note.content.split())
        if note.quote:
            text = f'{text} (quoting the docs: "{" ".join(note.quote.split())}")'
        room = min(NOTE_CHARS_PER_SOURCE - used.get(note.source_name, 0), NOTE_CHARS_TOTAL - total)
        if room < 40:
            continue
        if len(text) > room:
            text = text[: room - 1].rstrip() + "…"
        by_source.setdefault(note.source_name, []).append(text)
        used[note.source_name] = used.get(note.source_name, 0) + len(text)
        total += len(text)
    return [{"source": name, "notes": notes} for name, notes in by_source.items()]
