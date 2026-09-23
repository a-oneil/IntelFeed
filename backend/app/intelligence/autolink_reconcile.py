"""Reconcile pending autolink matches against one-pass AI analysis results.

The autolinker holds dictionary-word matches ("Royal" in "Royal Navy", "Inc"
in a copyright footer) in ``pending_autolink_matches`` instead of linking
instantly. When the one-pass ``entry_analysis`` payload lands, this module
compares each pending entity's name/aliases against the entities the AI read
out of the article:

- **Promoted** — the AI extracted a matching name: the junction row is created
  through the normal ``store_autolink_matches`` path (identical confidence
  weighting, article_count/last_seen_at bumps).
- **Rejected** — the AI analyzed the article and did not mention the entity:
  the row is marked rejected and a ``FalsePositiveRecord`` with
  ``extraction_source="ai_reconcile"`` records the contextual verdict for the
  hygiene tooling.

Entries that never get an AI pass leave their pending rows unresolved; the
engine-tables prune job expires them.
"""

import logging
import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

# AI payload keys checked per pending entity type. Actor/malware/tool share one
# pool — the AI routinely files ransomware brands under threat_actors while the
# vocabulary has them as malware (or vice versa), and a cross-slot mention is
# still positive evidence the article discusses the entity.
_PAYLOAD_KEYS_BY_TYPE: dict[str, tuple[str, ...]] = {
    "threat_actor": ("threat_actors", "malware", "tools"),
    "malware": ("threat_actors", "malware", "tools"),
    "tool": ("threat_actors", "malware", "tools"),
    "country": ("countries",),
}


def _payload_names(parsed: dict, keys: tuple[str, ...]) -> set[str]:
    names: set[str] = set()
    for key in keys:
        for item in parsed.get(key) or []:
            if isinstance(item, dict):
                candidates = [item.get("name") or ""] + list(item.get("aliases") or [])
            elif isinstance(item, str):
                candidates = [item]
            else:
                continue
            for candidate in candidates:
                form = (candidate or "").strip().lower()
                if form:
                    names.add(form)
    return names


async def reconcile_pending_autolinks(db: AsyncSession, entry_id: uuid.UUID, parsed: dict) -> dict:
    """Promote or reject unresolved pending matches for an entry. Returns counts."""
    from app.intelligence.autolinker import store_autolink_matches
    from app.models.country import Country
    from app.models.malware_family import MalwareFamily
    from app.models.pending_autolink import PendingAutolinkMatch
    from app.models.threat_actor import ThreatActor
    from app.models.tool import Tool

    entity_models = {
        "threat_actor": ThreatActor,
        "malware": MalwareFamily,
        "tool": Tool,
        "country": Country,
    }

    rows = (
        (
            await db.execute(
                select(PendingAutolinkMatch).where(
                    PendingAutolinkMatch.entry_id == entry_id,
                    PendingAutolinkMatch.resolved_at.is_(None),
                )
            )
        )
        .scalars()
        .all()
    )
    counts = {"promoted": 0, "rejected": 0}
    if not rows:
        return counts

    now = datetime.now(UTC)
    marker_user_id = None
    for row in rows:
        model = entity_models.get(row.entity_type)
        entity = await db.get(model, row.entity_id) if model else None
        if entity is None:
            # Entity deleted/merged since the scan — nothing to link, no verdict.
            row.resolution = "rejected"
            row.resolved_at = now
            counts["rejected"] += 1
            continue

        entity_names = {(entity.name or "").strip().lower(), (row.canonical_name or "").strip().lower()}
        entity_names.update((a or "").strip().lower() for a in (getattr(entity, "aliases", None) or []))
        entity_names.discard("")
        ai_names = _payload_names(parsed, _PAYLOAD_KEYS_BY_TYPE.get(row.entity_type, ()))

        if entity_names & ai_names:
            match = {
                "entity_type": row.entity_type,
                "entity_id": str(row.entity_id),
                "canonical_name": row.canonical_name,
                "surface_form": (row.matched_names or [row.canonical_name])[0],
                "surface_forms": list(row.matched_names or []),
                "confidence": row.confidence or "medium",
                "source": "auto_link",
                "paragraph_indices": list(row.paragraph_indices or []),
            }
            await store_autolink_matches(
                db,
                entry_id,
                [match],
                source_confidence_weight=row.source_weight or 1.0,
                allow_provisional=True,
            )
            row.resolution = "promoted"
            row.resolved_at = now
            counts["promoted"] += 1
        else:
            row.resolution = "rejected"
            row.resolved_at = now
            counts["rejected"] += 1
            marker_user_id = marker_user_id or await _system_user_id(db)
            if marker_user_id:
                from app.models.false_positive_record import FalsePositiveRecord

                db.add(
                    FalsePositiveRecord(
                        entity_type=row.entity_type,
                        entity_id=row.entity_id,
                        entity_value=row.canonical_name,
                        source_entry_id=entry_id,
                        reason="AI analysis did not identify this entity in the article context",
                        marked_by=marker_user_id,
                        extraction_source="ai_reconcile",
                    )
                )

    if counts["promoted"] or counts["rejected"]:
        logger.info(
            "Reconciled pending autolinks for entry %s: %d promoted, %d rejected",
            entry_id,
            counts["promoted"],
            counts["rejected"],
        )
    return counts


async def _system_user_id(db: AsyncSession) -> uuid.UUID | None:
    from app.services.system_user import get_system_user_id

    return await get_system_user_id(db)
