"""Alias-aware entity resolution to prevent duplicate profiles.

Looks up an existing entity by matching an incoming name (and optional incoming
aliases) against BOTH the canonical ``name`` column and the ``aliases`` array of
stored records.

This exists because merging two profiles moves the loser's name and aliases into
the survivor's ``aliases`` array (see ``app/api/entity_merge.py``). Any lookup
that only checks the ``name`` column will therefore miss a merged profile when an
entry references it by one of those aliases, and a duplicate profile gets created.
All alias-bearing entities (ThreatActor, MalwareFamily, Tool, Vendor,
Product, Country) share the same ``name`` + ``aliases`` shape, so one helper
serves them all.
"""

import uuid
from datetime import UTC, datetime

from sqlalchemy import Text, bindparam, func, or_, select
from sqlalchemy import text as sa_text
from sqlalchemy.dialects.postgresql import ARRAY as PG_ARRAY
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

# entity_type slug -> (model, junction model, junction FK attribute). Mirrors
# ENTITY_TYPE_REGISTRY in app/api/entity_merge.py; kept local to avoid importing
# the API layer into the intelligence layer (circular import).
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.product import EntryProduct, Product
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.tool import EntryTool, Tool
from app.models.vendor import EntryVendor, Vendor

_TYPE_JUNCTION: dict[str, tuple] = {
    "threat_actor": (ThreatActor, EntryThreatActor, "threat_actor_id"),
    "malware": (MalwareFamily, EntryMalware, "malware_family_id"),
    "tool": (Tool, EntryTool, "tool_id"),
    "vendor": (Vendor, EntryVendor, "vendor_id"),
    "product": (Product, EntryProduct, "product_id"),
}


def _norm(name: str | None, aliases: list[str] | None = None) -> list[str]:
    """Normalize a name + aliases into a deduped list of lowercased search terms."""
    terms: set[str] = set()
    if name and name.strip():
        terms.add(name.strip().lower())
    for alias in aliases or []:
        if alias and alias.strip():
            terms.add(alias.strip().lower())
    return list(terms)


async def _match(db: AsyncSession, model, terms: list[str]):
    """Return the best existing ``model`` row whose name or aliases match any term.

    Exact canonical-name matches are preferred over alias-only matches so that, in
    the presence of pre-existing duplicate data, the lookup resolves deterministically.
    """
    if not terms:
        return None
    name_match = func.lower(model.name).in_(terms)
    alias_match = sa_text("EXISTS (SELECT 1 FROM unnest(aliases) AS a WHERE lower(a) = ANY(:terms))").bindparams(
        bindparam("terms", value=terms, type_=PG_ARRAY(Text))
    )
    result = await db.execute(select(model).where(or_(name_match, alias_match)).order_by(name_match.desc()))
    return result.scalars().first()


async def find_entity_by_name_or_alias(
    db: AsyncSession,
    model,
    name: str | None,
    incoming_aliases: list[str] | None = None,
):
    """Find an existing entity matching ``name`` (preferred) or any incoming alias.

    Matching is case-insensitive and checks both the stored ``name`` column and the
    stored ``aliases`` array. The incoming canonical ``name`` is tried first; only
    if it finds nothing do the incoming aliases get used as fallback search terms,
    so a hallucinated incoming alias cannot shadow a strong name match. Returns the
    ORM instance, or ``None`` if no match.
    """
    hit = await _match(db, model, _norm(name))
    if hit is not None:
        return hit
    alias_terms = _norm(None, incoming_aliases)
    if alias_terms:
        return await _match(db, model, alias_terms)
    return None


async def find_entity_id_by_name_or_alias(
    db: AsyncSession,
    model,
    name: str | None,
    incoming_aliases: list[str] | None = None,
) -> uuid.UUID | None:
    """Like :func:`find_entity_by_name_or_alias` but returns just the entity id."""
    hit = await find_entity_by_name_or_alias(db, model, name, incoming_aliases)
    return hit.id if hit is not None else None


async def find_reclassify_tombstone(
    db: AsyncSession,
    creating_type: str,
    name: str | None,
    incoming_aliases: list[str] | None = None,
):
    """Return an active tombstone if ``name`` (or an incoming alias) was folded
    out of ``creating_type`` via a cross-type reclassify.

    ``creating_type`` is the ENTITY_TYPE_REGISTRY slug of the entity a caller is
    about to create (e.g. ``"malware"``). A hit means that name belongs to
    the canonical entity recorded in ``target_type`` / ``target_id`` and the
    caller should link/merge into it rather than recreating a shadow. The
    canonical name is tried first so a stray incoming alias can't shadow it.
    """
    from app.models.entity_maintenance import EntityReclassifyTombstone

    async def _lookup(terms: list[str]):
        if not terms:
            return None
        result = await db.execute(
            select(EntityReclassifyTombstone).where(
                EntityReclassifyTombstone.source_type == creating_type,
                EntityReclassifyTombstone.active.is_(True),
                func.lower(EntityReclassifyTombstone.normalized_name).in_(terms),
            )
        )
        return result.scalars().first()

    hit = await _lookup(_norm(name))
    if hit is not None:
        return hit
    return await _lookup(_norm(None, incoming_aliases))


async def link_entry_to_entity(
    db: AsyncSession,
    entry_id: uuid.UUID,
    entity_type: str,
    entity_id: uuid.UUID,
    *,
    source: str = "ai",
    matched_name: str | None = None,
) -> None:
    """Idempotently link an entry to a canonical entity of ``entity_type``.

    Used when a shadow-entity creation is suppressed by a reclassify tombstone:
    the association still needs to reach the surviving entity, which lives in a
    different table than the one the caller was creating in. Bumps the survivor's
    ``article_count`` / ``last_seen_at`` only when a new link row is inserted.
    """
    spec = _TYPE_JUNCTION.get(entity_type)
    if spec is None:
        return
    _model, junction, fk_attr = spec
    values: dict = {"entry_id": entry_id, fk_attr: entity_id, "source": source}
    if matched_name and hasattr(junction, "matched_names"):
        values["matched_names"] = [matched_name]
    result = await db.execute(pg_insert(junction).values(**values).on_conflict_do_nothing())
    if result.rowcount:
        survivor = (await db.execute(select(_model).where(_model.id == entity_id))).scalar_one_or_none()
        if survivor is not None:
            if hasattr(survivor, "article_count"):
                survivor.article_count = (survivor.article_count or 0) + 1
            if hasattr(survivor, "last_seen_at"):
                survivor.last_seen_at = datetime.now(UTC)
