"""Per-entity cleanup decisions: clear every proposal about an entity at once,
and remember a dismissal so the next article doesn't file it again.

A reclassify proposal is filed once per article that mentions the entity, in
one of two logs (the link log's ``needs_reclassification`` for linkable types,
the maintenance log's ``adjudication_reclassify`` for the rest). The analyst's
decision is about the entity, not the article, so apply and dismiss act on
every row for it.
"""

from __future__ import annotations

import uuid

from sqlalchemy import String, and_, cast, delete, or_, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.entity_link_validation_log import EntityLinkValidationLog
from app.models.entity_maintenance import EntityMaintenanceLog
from app.models.proposal_dismissal import KIND_NOT_DUPLICATE, KIND_RECLASSIFY, KIND_VERDICT, ProposalDismissal

LINK_RECLASSIFY = "needs_reclassification"
MAINT_RECLASSIFY = "adjudication_reclassify"


async def reclassify_dismissed(db: AsyncSession, entity_type: str, entity_id: uuid.UUID) -> bool:
    """True when an analyst said to stop proposing a type change for this entity."""
    return (
        await db.execute(
            select(ProposalDismissal.id).where(
                ProposalDismissal.kind == KIND_RECLASSIFY,
                ProposalDismissal.entity_type == entity_type,
                ProposalDismissal.entity_id == entity_id,
            )
        )
    ).first() is not None


async def clear_reclassify_proposals(db: AsyncSession, entity_type: str, entity_id: uuid.UUID) -> int:
    """Delete every pending reclassify proposal about the entity, in both logs."""
    n = (
        await db.execute(
            delete(EntityLinkValidationLog).where(
                EntityLinkValidationLog.action == LINK_RECLASSIFY,
                EntityLinkValidationLog.entity_type == entity_type,
                EntityLinkValidationLog.entity_id == entity_id,
            )
        )
    ).rowcount or 0
    n += (
        await db.execute(
            delete(EntityMaintenanceLog).where(
                EntityMaintenanceLog.action == MAINT_RECLASSIFY,
                EntityMaintenanceLog.applied.is_(False),
                EntityMaintenanceLog.entity_type == entity_type,
                EntityMaintenanceLog.entity_id == entity_id,
            )
        )
    ).rowcount or 0
    return n


async def dismiss_reclassify(
    db: AsyncSession, entity_type: str, entity_id: uuid.UUID, user_id: uuid.UUID | None
) -> int:
    """Clear the entity's reclassify proposals and keep new ones from being filed."""
    await db.execute(
        pg_insert(ProposalDismissal)
        .values(
            id=uuid.uuid4(),
            kind=KIND_RECLASSIFY,
            entity_type=entity_type,
            entity_id=entity_id,
            other_key="",
            created_by=user_id,
        )
        .on_conflict_do_nothing(constraint="uq_proposal_dismissal")
    )
    return await clear_reclassify_proposals(db, entity_type, entity_id)


async def remember_verdict_dismissals(
    db: AsyncSession,
    verdicts: list[tuple[str, str, uuid.UUID, uuid.UUID]],
    user_id: uuid.UUID | None,
) -> None:
    """Record that an analyst dismissed these verdicts, each an (action,
    entity type, entity id, article), so a later review of the article
    neither files nor applies them again."""
    for chunk in (verdicts[i : i + 1000] for i in range(0, len(verdicts), 1000)):
        await db.execute(
            pg_insert(ProposalDismissal)
            .values(
                [
                    {
                        "id": uuid.uuid4(),
                        "kind": KIND_VERDICT,
                        "entity_type": etype,
                        "entity_id": eid,
                        "other_key": f"{entry_id}:{action}",
                        "created_by": user_id,
                    }
                    for action, etype, eid, entry_id in chunk
                ]
            )
            .on_conflict_do_nothing(constraint="uq_proposal_dismissal")
        )


async def dismissed_verdicts(db: AsyncSession, entry_id: uuid.UUID) -> set[tuple[str, str, uuid.UUID]]:
    """(action, entity_type, entity_id) of every verdict dismissed for this article."""
    rows = (
        await db.execute(
            select(ProposalDismissal.other_key, ProposalDismissal.entity_type, ProposalDismissal.entity_id).where(
                ProposalDismissal.kind == KIND_VERDICT,
                ProposalDismissal.other_key.like(f"{entry_id}:%"),
            )
        )
    ).all()
    return {(key.split(":", 1)[1], etype, eid) for key, etype, eid in rows}


def _pair(a: uuid.UUID, b: uuid.UUID) -> tuple[uuid.UUID, str]:
    lo, hi = sorted((a, b), key=str)
    return lo, str(hi)


async def mark_not_duplicate(
    db: AsyncSession, entity_type: str, a: uuid.UUID, b: uuid.UUID, user_id: uuid.UUID | None
) -> None:
    """Record that two same-type entities are different things."""
    lo, hi = _pair(a, b)
    await db.execute(
        pg_insert(ProposalDismissal)
        .values(
            id=uuid.uuid4(),
            kind=KIND_NOT_DUPLICATE,
            entity_type=entity_type,
            entity_id=lo,
            other_key=hi,
            created_by=user_id,
        )
        .on_conflict_do_nothing(constraint="uq_proposal_dismissal")
    )


# The retired link validator's proposals: anything in the link log that the
# adjudicate stage did not file. Nothing re-judges them (the adjudication
# backfill walks entries, not these rows), so past this age they only pad the
# Review badge.
LEGACY_LINK_PROPOSAL_MAX_AGE_DAYS = 30
EXPIRE_LEGACY_LINK_PROPOSALS_SQL = """
DELETE FROM entity_link_validation_log l
WHERE l.action IN ('shadow_remove', 'needs_reclassification')
  AND l.created_at < now() - make_interval(days => :days)
  AND NOT EXISTS (
    SELECT 1 FROM ai_results r JOIN ai_tasks t ON t.id = r.task_id
    WHERE r.id = l.ai_result_id AND t.name = 'entry_adjudication'
  )
"""


async def expire_legacy_link_proposals(db: AsyncSession, days: int = LEGACY_LINK_PROPOSAL_MAX_AGE_DAYS) -> int:
    """Delete the retired validator's pending link proposals older than ``days``."""
    return (await db.execute(text(EXPIRE_LEGACY_LINK_PROPOSALS_SQL).bindparams(days=days))).rowcount or 0


async def purge_gone_entity_proposals(db: AsyncSession) -> int:
    """Delete every pending proposal, both logs, whose entity no longer exists
    (deleted by a veto, a merge, a purge, an analyst). The Review queue hides
    these groups as soon as the entity is gone; this is the nightly sweep that
    drops the rows. Applied rows stay as history. Pseudo types (relationship,
    entry) have no model and are left alone."""
    from app.services.entry_adjudication import _ENDPOINT_MODELS, _model_for

    n = 0
    for etype in _ENDPOINT_MODELS:
        model = _model_for(etype)
        if model is None:
            continue
        for log, pending in (
            (EntityLinkValidationLog, EntityLinkValidationLog.action.in_(["shadow_remove", LINK_RECLASSIFY])),
            (EntityMaintenanceLog, EntityMaintenanceLog.applied.is_(False)),
        ):
            alive = select(model.id).where(model.id == log.entity_id).exists()
            n += (
                await db.execute(
                    delete(log).where(pending, log.entity_type == etype, log.entity_id.isnot(None), ~alive)
                )
            ).rowcount or 0
    # A vendor link to a vendor that is gone (deleted, merged, now a product).
    n += (
        await db.execute(
            delete(EntityMaintenanceLog).where(
                EntityMaintenanceLog.action == VENDOR_AUTOLINK,
                EntityMaintenanceLog.applied.is_(False),
                ~_proposed_vendor_exists(),
            )
        )
    ).rowcount or 0
    return n


VENDOR_AUTOLINK = "vendor_autolink"


def _proposed_vendor_exists():
    """SQL: a vendor_autolink row's proposed vendor still exists. Compared as
    text so a malformed id is simply "gone", never a query error."""
    from app.models.vendor import Vendor

    return (
        select(Vendor.id)
        .where(cast(Vendor.id, String) == EntityMaintenanceLog.after["proposed_vendor_id"].astext)
        .exists()
    )


def entity_alive_clause(log):
    """SQL predicate: the log row's entity still exists, or the row has no
    catalogue entity (a pseudo type such as an edge, or no entity id). For the
    maintenance log, a vendor link also needs its proposed vendor.

    The Review list drops groups whose entity is gone; the pending feed and
    the counts use this so they agree with it."""
    from app.services.entry_adjudication import _ENDPOINT_MODELS, _model_for

    parts = [log.entity_id.is_(None), log.entity_type.notin_(sorted(_ENDPOINT_MODELS))]
    for etype in _ENDPOINT_MODELS:
        model = _model_for(etype)
        if model is not None:
            parts.append(and_(log.entity_type == etype, select(model.id).where(model.id == log.entity_id).exists()))
    clause = or_(*parts)
    if log is EntityMaintenanceLog:
        clause = and_(clause, or_(log.action != VENDOR_AUTOLINK, _proposed_vendor_exists()))
    return clause


# Maintenance-log fields that name a second entity: a proposal that points at
# an entity is moot once that entity is gone.
_POINTER_KEYS = ("target_id", "merge_target_id", "matches_entity_id", "proposed_vendor_id")


def _pointer_type(row: EntityMaintenanceLog, key: str) -> str | None:
    after = row.after or {}
    if key == "proposed_vendor_id":
        return "vendor"
    if key == "target_id":
        return after.get("target_type") or row.entity_type
    return row.entity_type


async def settle_gone_entity(
    db: AsyncSession,
    entity_type: str,
    entity_id: uuid.UUID | None,
    *,
    successor: tuple[str, uuid.UUID] | None = None,
    gone: bool = False,
) -> int:
    """Close the pending proposals of an entity that was just deleted, merged
    away or reclassified, so they don't linger in the Review count.

    Deletes every pending proposal about it (both logs) and every pending
    proposal that points at it (a merge into it, a vendor link to it, an alias
    clash with it). A merge into it is moved to ``successor`` (the merge
    keeper) instead, when that is a different entity of the same type. Its
    held autolink matches move to ``successor``, or are deleted.
    Does nothing while the entity still exists, unless ``gone`` says the
    caller just deleted it (types the adjudicator has no model for).
    Applied rows stay as history. Flushes first, so the caller's own row,
    marked applied, is never caught. Returns the rows closed."""
    from app.services.entry_adjudication import ACTION_MERGE, _model_for

    if entity_id is None:
        return 0
    await db.flush()
    if not gone:
        model = _model_for(entity_type)
        if model is None or (await db.execute(select(model.id).where(model.id == entity_id))).first() is not None:
            return 0
    n = await clear_entity_proposals(db, entity_type, entity_id)
    # Held autolink matches aren't proposals (not counted), but must not keep
    # pointing at the gone id: Link on one would fail.
    from app.intelligence.autolink_reconcile import move_held_matches

    await move_held_matches(db, entity_type, entity_id, successor)

    sid = str(entity_id)
    rows = (
        await db.execute(
            select(EntityMaintenanceLog).where(
                EntityMaintenanceLog.applied.is_(False),
                or_(*(EntityMaintenanceLog.after[k].astext == sid for k in _POINTER_KEYS)),
            )
        )
    ).scalars()
    successor_name = None
    if successor is not None:
        smodel = _model_for(successor[0])
        if smodel is not None and hasattr(smodel, "name"):
            successor_name = (await db.execute(select(smodel.name).where(smodel.id == successor[1]))).scalar()
    for row in list(rows):
        after = dict(row.after or {})
        keys = [k for k in _POINTER_KEYS if after.get(k) == sid and _pointer_type(row, k) == entity_type]
        if not keys:
            continue
        if (
            keys == ["target_id"]
            and row.action == ACTION_MERGE
            and successor is not None
            and successor[0] == entity_type
            and successor[1] != row.entity_id
        ):
            after["target_id"] = str(successor[1])
            if successor_name:
                after["merge_into"] = successor_name
            row.after = after
            continue
        await db.delete(row)
        n += 1
    await db.flush()
    return n


async def clear_entity_proposals(db: AsyncSession, entity_type: str, entity_id: uuid.UUID) -> int:
    """Delete every pending proposal about an entity that no longer exists —
    both logs, every action. Called when an analyst deletes the entity from a
    review queue, so its rows do not linger as "gone" lines to dismiss by hand.
    Applied rows stay: they are history and undo records."""
    n = (
        await db.execute(
            delete(EntityLinkValidationLog).where(
                EntityLinkValidationLog.action.in_(["shadow_remove", LINK_RECLASSIFY]),
                EntityLinkValidationLog.entity_type == entity_type,
                EntityLinkValidationLog.entity_id == entity_id,
            )
        )
    ).rowcount or 0
    n += (
        await db.execute(
            delete(EntityMaintenanceLog).where(
                EntityMaintenanceLog.applied.is_(False),
                EntityMaintenanceLog.entity_type == entity_type,
                EntityMaintenanceLog.entity_id == entity_id,
            )
        )
    ).rowcount or 0
    return n
