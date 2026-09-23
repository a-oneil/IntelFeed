"""Export tools."""

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ttp import TTP
from app.tools import _tool


@_tool(
    name="export_attack_layer",
    description=(
        "Export MITRE ATT&CK Navigator layer JSON for visualization. With entry_id, uses the entry's linked "
        "techniques with real tactic and per-link confidence/source text; without it, covers observed techniques "
        "(linked to at least one entry, non-deprecated, top 500 by article count)."
    ),
    input_schema={
        "properties": {
            "entry_id": {"type": "string", "description": "Optional: scope to TTPs from a specific entry"},
            "title": {"type": "string", "default": "IntelFeed ATT&CK Layer"},
        },
    },
)
async def _export_attack_layer(
    db: AsyncSession, user_id: uuid.UUID, entry_id: str | None = None, title: str = "IntelFeed ATT&CK Layer"
) -> dict:
    from app.intelligence.ttp import generate_navigator_layer
    from app.models.ttp import EntryTTP

    if entry_id:
        # Mirrors the /entries/{id}/ttps/navigator endpoint: real tactic + per-link confidence.
        result = await db.execute(
            select(TTP, EntryTTP.confidence, EntryTTP.source_text)
            .join(EntryTTP, EntryTTP.ttp_id == TTP.id)
            .where(EntryTTP.entry_id == uuid.UUID(entry_id))
        )
        ttps = [
            {
                "technique_id": t.technique_id,
                "technique_name": t.technique_name,
                "tactic": t.tactic or "",
                "confidence": c,
                "source_text": s,
            }
            for t, c, s in result.all()
        ]
    else:
        # Observed techniques only — the full seeded ATT&CK catalog would drown the layer.
        result = await db.execute(
            select(TTP)
            .where(
                TTP.is_deprecated.is_(False),
                TTP.id.in_(select(EntryTTP.ttp_id).distinct()),
            )
            .order_by(TTP.article_count.desc())
            .limit(500)
        )
        ttps = [
            {"technique_id": t.technique_id, "technique_name": t.technique_name, "tactic": t.tactic or ""}
            for t in result.scalars()
        ]
    layer = generate_navigator_layer(ttps, title=title)
    return {"layer": layer, "technique_count": len(ttps)}
