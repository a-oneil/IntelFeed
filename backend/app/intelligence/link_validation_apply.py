"""Shared apply/audit helpers for AI entity-link validation.

Two callers judge autolinker links and act on the verdicts:

- the scheduled recheck job (``workers/link_validation_tasks.py``) via the
  standalone ``entity_link_validation`` AI task, and
- the ingest-time one-pass path (``services/entry_analysis.py``), which folds
  the same KEEP/REMOVE/RECLASSIFY judgment into the ``entry_analysis`` call.

Both share the junction specs, the ``LinkRow`` snapshot shape, the fetch that
annotates analyst-restore feedback, and the mutation/audit primitives so a
removal looks identical in ``entity_link_validation_log`` regardless of which
path produced it.
"""

import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

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

# Lookback window for the "previously_restored" feedback signal — if an
# analyst restored this exact (entry, entity) pair within this many days,
# the prompt is told to treat it as a strong KEEP signal.
PREVIOUSLY_RESTORED_LOOKBACK_DAYS = 90


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


def entity_relationship_name(jmodel: type) -> str:
    """Map a junction model to the attribute name of its entity-side relationship.

    These are ORM attribute names, not entity_type slugs — EntryMalware's
    relationship is still ``malware_family`` (see MalwareFamily.entry_malware's
    back_populates) even though the type's slug is ``malware``.
    """
    return {
        EntryThreatActor: "threat_actor",
        EntryMalware: "malware_family",
        EntryVendor: "vendor",
        EntryProduct: "product",
        EntryCountry: "country",
    }[jmodel]


async def fetch_auto_links(
    db: AsyncSession,
    entry_id: uuid.UUID,
    skip_confidence: str | None = None,
) -> list[LinkRow]:
    """Fetch all dictionary-entity auto_link junction rows for the entry.

    Also looks up which links have been explicitly restored by an analyst in
    the recent past — that's the analyst-feedback signal fed into the prompt
    so the model treats those links as known-correct.
    """
    rows: list[LinkRow] = []
    for jmodel, _emodel, fk_attr, entity_type in JUNCTION_SPECS:
        stmt = (
            select(jmodel)
            .where(jmodel.entry_id == entry_id, jmodel.source == "auto_link")
            .options(selectinload(getattr(jmodel, entity_relationship_name(jmodel))))
        )
        if skip_confidence:
            stmt = stmt.where(or_(jmodel.confidence.is_(None), jmodel.confidence != skip_confidence))
        result = await db.execute(stmt)
        for jrow in result.scalars().all():
            entity = getattr(jrow, entity_relationship_name(jmodel))
            if entity is None:
                continue
            entity_id = getattr(jrow, fk_attr)
            rows.append(
                LinkRow(
                    entity_key=f"{entity_type}:{entity_id}",
                    entity_type=entity_type,
                    entity_id=entity_id,
                    name=entity.name,
                    matched_names=list(jrow.matched_names or []),
                    confidence=jrow.confidence,
                    source=jrow.source,
                    paragraph_indices=list(jrow.paragraph_indices or []),
                    extracted_at=jrow.extracted_at,
                )
            )

    # Annotate links with previously_restored = True if an analyst has
    # restored this exact (entry, entity_type, entity_id) tuple within the
    # lookback window. One query covers all links for the entry.
    if rows:
        cutoff = datetime.now(UTC) - timedelta(days=PREVIOUSLY_RESTORED_LOOKBACK_DAYS)
        restored_q = await db.execute(
            select(EntityLinkValidationLog.entity_type, EntityLinkValidationLog.entity_id).where(
                EntityLinkValidationLog.entry_id == entry_id,
                EntityLinkValidationLog.action == "restored",
                EntityLinkValidationLog.created_at >= cutoff,
            )
        )
        restored_set = {(t, eid) for t, eid in restored_q.all()}
        for row in rows:
            if (row.entity_type, row.entity_id) in restored_set:
                row.previously_restored = True
    return rows


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
    """Audit-log a RECLASSIFY decision. The junction row is left intact."""
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
