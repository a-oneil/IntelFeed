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

from sqlalchemy import delete, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.entity_link_validation_log import EntityLinkValidationLog
from app.models.entity_maintenance import EntityMaintenanceLog
from app.models.proposal_dismissal import KIND_NOT_DUPLICATE, KIND_RECLASSIFY, ProposalDismissal

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
