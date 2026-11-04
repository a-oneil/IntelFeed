"""Settle held autolink matches against the article's one-pass analysis.

The autolinker holds dictionary-word matches ("Royal" in "Royal Navy", "Inc"
in a copyright footer) in ``pending_autolink_matches`` instead of linking
them. The analysis settles each one by comparing the held entity's name and
aliases with the entities it read out of the article:

- **Promoted** — the analysis named it: the junction row is created through
  the normal ``store_autolink_matches`` path (same confidence weighting,
  article_count/last_seen_at bumps).
- **Rejected** — the analysis read the article and did not name it. A
  ``FalsePositiveRecord`` with ``extraction_source="ai_reconcile"`` records
  the call.

This runs when the analysis lands (``store_entry_analysis``) and, for matches
held on an article whose analysis already ran (a re-scan after a new entity
or alias), from ``settle_held_on_analysed_entries`` against the stored
payload. The adjudicator then checks both outcomes: a promoted match is an
ordinary link it may propose removing; a rejected one is a ``held`` review
item it may propose linking (``entry_adjudication``).

Matches on an article that never gets an analysis stay unresolved; the
engine-tables prune job expires them.
"""

import logging
import uuid
from datetime import UTC, datetime

from sqlalchemy import func, select
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


def _held_models() -> dict:
    """The entity types the autolinker holds matches for, and their models."""
    from app.models.country import Country
    from app.models.malware_family import MalwareFamily
    from app.models.threat_actor import ThreatActor
    from app.models.tool import Tool

    return {
        "threat_actor": ThreatActor,
        "malware": MalwareFamily,
        "tool": Tool,
        "country": Country,
    }


async def reconcile_pending_autolinks(db: AsyncSession, entry_id: uuid.UUID, parsed: dict) -> dict:
    """Promote or reject unresolved pending matches for an entry. Returns counts."""
    from app.models.pending_autolink import PendingAutolinkMatch

    entity_models = _held_models()

    rows = (
        (
            await db.execute(
                select(PendingAutolinkMatch)
                .where(
                    PendingAutolinkMatch.entry_id == entry_id,
                    PendingAutolinkMatch.resolved_at.is_(None),
                )
                # The analysis and the 30-minute settle can reach the same
                # article at once; whichever locks a row first settles it.
                .with_for_update(skip_locked=True)
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
            # Entity deleted/merged since the scan — nothing to link, no
            # verdict, and nothing for the adjudicator to check.
            row.resolution = "rejected"
            row.resolved_at = now
            row.reviewed_at = now
            counts["rejected"] += 1
            continue

        entity_names = {(entity.name or "").strip().lower(), (row.canonical_name or "").strip().lower()}
        entity_names.update((a or "").strip().lower() for a in (getattr(entity, "aliases", None) or []))
        entity_names.discard("")
        ai_names = _payload_names(parsed, _PAYLOAD_KEYS_BY_TYPE.get(row.entity_type, ()))

        if entity_names & ai_names:
            await promote_held(db, row, now)
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


async def promote_held(db: AsyncSession, row, now: datetime | None = None) -> None:
    """Link a held match: create its junction row and mark it promoted. A
    reject recorded for it earlier (the analysis's false-positive marker on
    this article) is removed, since the call it recorded no longer stands."""
    from sqlalchemy import delete

    from app.intelligence.autolinker import store_autolink_matches
    from app.models.false_positive_record import FalsePositiveRecord

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
        row.entry_id,
        [match],
        source_confidence_weight=row.source_weight or 1.0,
        allow_provisional=True,
    )
    if row.resolution == "rejected":
        await db.execute(
            delete(FalsePositiveRecord).where(
                FalsePositiveRecord.entity_type == row.entity_type,
                FalsePositiveRecord.entity_id == row.entity_id,
                FalsePositiveRecord.source_entry_id == row.entry_id,
                FalsePositiveRecord.extraction_source == "ai_reconcile",
            )
        )
    row.resolution = "promoted"
    row.resolved_at = now or datetime.now(UTC)


async def settle_held_on_analysed_entries(db: AsyncSession, limit: int = 200) -> dict:
    """Settle matches held on articles that already have an analysis.

    A match is usually held before the article is analysed, and the analysis
    settles it when it lands. A re-scan (a new entity or alias, a backfill)
    holds matches on articles analysed long ago, which nothing would settle,
    so this runs them against the stored payload instead. Each article it
    touches has its adjudication reopened, so the adjudicator checks the new
    links and rejects, and nothing else. Runs every 30 minutes from
    ``submit_analysis_batches``.
    Returns counts."""
    from app.models.ai_result import AIResult
    from app.models.ai_task import AITask
    from app.models.pending_autolink import PendingAutolinkMatch
    from app.services.entry_adjudication import reopen_adjudication

    analysed = select(AIResult.target_id).where(
        AIResult.target_type == "entry",
        AIResult.is_current.is_(True),
        AIResult.task_id == select(AITask.id).where(AITask.name == "entry_analysis").scalar_subquery(),
    )
    entry_ids = list(
        (
            await db.execute(
                select(PendingAutolinkMatch.entry_id)
                .where(PendingAutolinkMatch.resolved_at.is_(None), PendingAutolinkMatch.entry_id.in_(analysed))
                .group_by(PendingAutolinkMatch.entry_id)
                .order_by(func.min(PendingAutolinkMatch.created_at))
                .limit(limit)
            )
        ).scalars()
    )
    if not entry_ids:
        return {"entries": 0, "promoted": 0, "rejected": 0}

    from app.services.entry_analysis import _current_analysis_result

    since = datetime.now(UTC)
    totals = {"entries": 0, "promoted": 0, "rejected": 0}
    for entry_id in entry_ids:
        result, _task = await _current_analysis_result(db, entry_id)
        if result is None or not isinstance(result.parsed_result, dict):
            continue
        counts = await reconcile_pending_autolinks(db, entry_id, result.parsed_result)
        if counts["promoted"] or counts["rejected"]:
            totals["entries"] += 1
            totals["promoted"] += counts["promoted"]
            totals["rejected"] += counts["rejected"]
            await reopen_adjudication(db, entry_id, since)
    await db.flush()
    return totals


async def move_held_matches(
    db: AsyncSession,
    entity_type: str,
    entity_id: uuid.UUID,
    successor: tuple[str, uuid.UUID] | None = None,
) -> int:
    """Carry an entity's unresolved held matches over to the entity that
    replaced it (merge keeper, or its converted self), or delete them when
    nothing did. Called when the entity is deleted, merged away or converted,
    so a held row never points at an id that no longer exists. A row is
    deleted instead when the successor can't hold matches or already has one
    for that article. Returns the rows moved or deleted."""
    from sqlalchemy import delete

    from app.models.pending_autolink import PendingAutolinkMatch

    open_rows = (
        (
            await db.execute(
                select(PendingAutolinkMatch).where(
                    PendingAutolinkMatch.entity_type == entity_type,
                    PendingAutolinkMatch.entity_id == entity_id,
                    PendingAutolinkMatch.resolved_at.is_(None),
                )
            )
        )
        .scalars()
        .all()
    )
    if not open_rows:
        return 0
    model = _held_models().get(successor[0]) if successor else None
    keeper = await db.get(model, successor[1]) if model else None
    if keeper is None:
        await db.execute(delete(PendingAutolinkMatch).where(PendingAutolinkMatch.id.in_([r.id for r in open_rows])))
        return len(open_rows)
    taken = set(
        (
            await db.execute(
                select(PendingAutolinkMatch.entry_id).where(
                    PendingAutolinkMatch.entity_type == successor[0],
                    PendingAutolinkMatch.entity_id == successor[1],
                    PendingAutolinkMatch.entry_id.in_([r.entry_id for r in open_rows]),
                )
            )
        ).scalars()
    )
    for row in open_rows:
        if row.entry_id in taken:
            await db.delete(row)
            continue
        row.entity_type, row.entity_id, row.canonical_name = successor[0], successor[1], keeper.name
    await db.flush()
    return len(open_rows)
