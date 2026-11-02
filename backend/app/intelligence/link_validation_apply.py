"""Shared apply/audit helpers for entity-link verdicts.

The adjudicate stage (``services/entry_adjudication.py``) judges every link
on an entry after the one-pass analysis has landed and acts on the verdicts
through these primitives: the junction specs, the ``LinkRow`` snapshot
shape, and the mutation/audit writes into ``entity_link_validation_log``.
``restore_from_log`` is the undo for a ``removed`` row, used by the Proposals
queue and the entry drawer.
"""

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.country import Country, EntryCountry
from app.models.entity_link_validation_log import EntityLinkValidationLog
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.product import EntryProduct, Product
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.vendor import EntryVendor, Vendor

logger = logging.getLogger(__name__)

# (junction_model, entity_model, junction_entity_fk_attr, entity_type_label)
JUNCTION_SPECS: list[tuple[type, type, str, str]] = [
    (EntryThreatActor, ThreatActor, "threat_actor_id", "threat_actor"),
    (EntryMalware, MalwareFamily, "malware_family_id", "malware"),
    (EntryVendor, Vendor, "vendor_id", "vendor"),
    (EntryProduct, Product, "product_id", "product"),
    (EntryCountry, Country, "country_id", "country"),
]
ENTITY_TYPES = {label: (jmodel, emodel, fk) for jmodel, emodel, fk, label in JUNCTION_SPECS}


@dataclass
class LinkRow:
    entity_key: str
    entity_type: str
    entity_id: uuid.UUID
    name: str
    matched_names: list[str]
    confidence: str | None
    source: str | None
    paragraph_indices: list[int]
    extracted_at: datetime | None
    previously_restored: bool = False


async def apply_removal(
    db: AsyncSession,
    entry_id: uuid.UUID,
    link: LinkRow,
    reason: str,
    ai_result_id: uuid.UUID | None,
) -> bool:
    """Re-fetch junction row; if extracted_at unchanged, delete + decrement count + audit."""
    jmodel, emodel, fk_attr = ENTITY_TYPES[link.entity_type]
    fk_col = getattr(jmodel, fk_attr)
    result = await db.execute(
        select(jmodel).where(
            jmodel.entry_id == entry_id,
            fk_col == link.entity_id,
        )
    )
    junction = result.scalar_one_or_none()
    if junction is None:
        logger.debug(
            "skip removal: junction gone for entry=%s entity=%s/%s",
            entry_id,
            link.entity_type,
            link.entity_id,
        )
        return False
    # Concurrency guard: someone re-linked while we were thinking.
    if junction.extracted_at and link.extracted_at and junction.extracted_at > link.extracted_at:
        logger.debug(
            "skip removal: junction extracted_at newer than snapshot for entry=%s entity=%s/%s",
            entry_id,
            link.entity_type,
            link.entity_id,
        )
        return False

    # Snapshot then delete
    log_row = EntityLinkValidationLog(
        entry_id=entry_id,
        entity_type=link.entity_type,
        entity_id=link.entity_id,
        entity_name_snapshot=link.name,
        action="removed",
        reason=reason[:500] if reason else None,
        original_source=junction.source,
        original_confidence=junction.confidence,
        original_matched_names=list(junction.matched_names or []),
        original_paragraph_indices=list(junction.paragraph_indices or []),
        original_extracted_at=junction.extracted_at,
        ai_result_id=ai_result_id,
    )
    db.add(log_row)
    await db.delete(junction)
    # Floor-at-0 decrement on the entity's article_count
    await db.execute(
        update(emodel)
        .where(emodel.id == link.entity_id)
        .values(article_count=func.greatest(emodel.article_count - 1, 0))
    )
    return True


async def log_shadow_removal(
    db: AsyncSession,
    entry_id: uuid.UUID,
    link: LinkRow,
    reason: str,
    ai_result_id: uuid.UUID | None,
) -> None:
    # One pending proposal per link: a re-review of the same entry (a resweep,
    # a re-analysis) must not file the same removal again.
    pending = await db.scalar(
        select(EntityLinkValidationLog.id)
        .where(
            EntityLinkValidationLog.entry_id == entry_id,
            EntityLinkValidationLog.entity_type == link.entity_type,
            EntityLinkValidationLog.entity_id == link.entity_id,
            EntityLinkValidationLog.action == "shadow_remove",
        )
        .limit(1)
    )
    if pending is not None:
        return
    db.add(
        EntityLinkValidationLog(
            entry_id=entry_id,
            entity_type=link.entity_type,
            entity_id=link.entity_id,
            entity_name_snapshot=link.name,
            action="shadow_remove",
            reason=reason[:500] if reason else None,
            original_source=link.source,
            original_confidence=link.confidence,
            original_matched_names=list(link.matched_names),
            original_paragraph_indices=list(link.paragraph_indices),
            original_extracted_at=link.extracted_at,
            ai_result_id=ai_result_id,
        )
    )


async def log_reclassification(
    db: AsyncSession,
    entry_id: uuid.UUID,
    link: LinkRow,
    reason: str,
    suggested_type: str | None,
    ai_result_id: uuid.UUID | None,
) -> None:
    """Audit-log a RECLASSIFY decision. The junction row is left intact.
    Skipped when an analyst dismissed reclassifying this entity."""
    from app.services.proposal_dismissals import reclassify_dismissed

    if suggested_type == link.entity_type or await reclassify_dismissed(db, link.entity_type, link.entity_id):
        return
    db.add(
        EntityLinkValidationLog(
            entry_id=entry_id,
            entity_type=link.entity_type,
            entity_id=link.entity_id,
            entity_name_snapshot=link.name,
            action="needs_reclassification",
            reason=reason[:500] if reason else None,
            original_source=link.source,
            original_confidence=link.confidence,
            original_matched_names=list(link.matched_names),
            original_paragraph_indices=list(link.paragraph_indices),
            original_extracted_at=link.extracted_at,
            suggested_entity_type=suggested_type,
            ai_result_id=ai_result_id,
        )
    )


async def restore_from_log(db: AsyncSession, log_id: uuid.UUID) -> tuple[bool, str]:
    """Re-create a junction row from a previously-removed log entry.

    Returns (success, message). Only `removed` rows can be restored.
    """
    result = await db.execute(select(EntityLinkValidationLog).where(EntityLinkValidationLog.id == log_id))
    log_row = result.scalar_one_or_none()
    if log_row is None:
        return False, "log entry not found"
    if log_row.action != "removed":
        return False, f"cannot restore action={log_row.action}"
    spec = ENTITY_TYPES.get(log_row.entity_type)
    if spec is None:
        return False, f"unknown entity_type {log_row.entity_type}"
    jmodel, emodel, fk_attr = spec

    # Re-check entity still exists
    ent_result = await db.execute(select(emodel.id).where(emodel.id == log_row.entity_id))
    if ent_result.scalar_one_or_none() is None:
        return False, "entity no longer exists"

    # Check we don't re-insert a duplicate (composite PK)
    fk_col = getattr(jmodel, fk_attr)
    dup_result = await db.execute(
        select(jmodel).where(jmodel.entry_id == log_row.entry_id, fk_col == log_row.entity_id)
    )
    if dup_result.scalar_one_or_none() is not None:
        return False, "link already exists"

    junction_kwargs = {
        "entry_id": log_row.entry_id,
        fk_attr: log_row.entity_id,
        "confidence": log_row.original_confidence,
        "source": log_row.original_source or "auto_link",
        "matched_names": list(log_row.original_matched_names or []),
        "paragraph_indices": list(log_row.original_paragraph_indices or []),
    }
    if log_row.original_extracted_at is not None:
        junction_kwargs["extracted_at"] = log_row.original_extracted_at
    db.add(jmodel(**junction_kwargs))
    # Reverse the article_count decrement
    await db.execute(
        update(emodel).where(emodel.id == log_row.entity_id).values(article_count=emodel.article_count + 1)
    )
    # Record the restore as its own audit row
    db.add(
        EntityLinkValidationLog(
            entry_id=log_row.entry_id,
            entity_type=log_row.entity_type,
            entity_id=log_row.entity_id,
            entity_name_snapshot=log_row.entity_name_snapshot,
            action="restored",
            reason=f"restored from {log_row.id}",
            original_source=log_row.original_source,
            original_confidence=log_row.original_confidence,
            original_matched_names=log_row.original_matched_names,
            original_paragraph_indices=log_row.original_paragraph_indices,
            original_extracted_at=log_row.original_extracted_at,
            ai_result_id=log_row.ai_result_id,
        )
    )
    return True, "restored"
