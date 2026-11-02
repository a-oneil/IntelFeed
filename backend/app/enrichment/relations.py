"""Relation outputs: a source's claims that an entity is connected to others.

A source declares a ``Relation`` (``app/enrichment/manifest.py``): a list in
its parsed_data whose items name other entities. Each time the source answers
for an entity, every named target is resolved to an entity IntelFeed already
has — exact name or alias, a technique or CVE id, a sector's vocabulary — and never
created. Then:

- a resolved target whose triple the relationship matrix allows becomes a
  connection, kept where IntelFeed keeps that kind of fact: a target sector in
  the target-sector junction (source ``enrichment``), anything else in
  ``entity_relationships`` (a new row is source ``enrichment``, ``probable``:
  reported by one curated source, not corroborated);
- a target that matches nothing, or more than one entity, is held: stored
  with no target, counted on the Enrichment console, and resolved by a later
  answer once the entity exists (unless the output doesn't ``hold``: then it
  is dropped);
- a target the source no longer names is withdrawn: its claim is deleted, and
  the connection with it when no other source's claim holds it, it is one
  this path made, and it is still at the ``probable`` this path gave it.

Each name is one ``entity_relation_claims`` row per source, so a re-run
changes nothing and one source's withdrawal never touches another's claim.

The claim always runs from the entity the source answered for; the connection
runs the way the matrix stores it. An observable's source claims the malware
family behind it, and the connection is the family's: ``malware
communicates_with observable``.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app import entity_types
from app.enrichment.manifest import Relation
from app.intelligence.relationship_matrix import is_allowed_relationship, orient_relationship
from app.models.enrichment import EntityRelationClaim
from app.models.entity_index import ALIAS_INDEXED_TABLES
from app.models.entity_relationship import EntityRelationship

#: The ``entity_relationships.source`` of a connection this path made.
EDGE_SOURCE = "enrichment"

_TECHNIQUE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")


def _allowed(entity_type: str, relation: str, target_type: str) -> bool:
    """The matrix allows the triple, either way round."""
    return orient_relationship(entity_type, relation, target_type) is not None


def relations_for(cls, entity_type: str) -> tuple[Relation, ...]:
    """The source's Relation outputs whose triple the matrix allows from ``entity_type``."""
    if cls is None or entity_type not in cls.applies_to:
        return ()
    return tuple(r for r in cls.relations() if any(_allowed(entity_type, r.relation, t) for t in r.target_types))


def target_key(name: str) -> str:
    """One claim per target name, however the source spaces or cases it."""
    return re.sub(r"\s+", " ", name.strip().casefold())[:255]


def _listed(relation: Relation, value) -> list[tuple[str, str | None, tuple[str, ...]]]:
    """(name, evidence, other names) for each item of a Relation's parsed_data
    list. The item's ``aliases`` key, when the Relation maps one, lists other
    names the source gives the same target."""
    name_key = (relation.item or {}).get("name")
    evidence_key = (relation.item or {}).get("evidence")
    aliases_key = (relation.item or {}).get("aliases")
    items = []
    for row in value if isinstance(value, list) else []:
        aliases: tuple[str, ...] = ()
        if isinstance(row, dict):
            name, evidence = row.get(name_key), row.get(evidence_key) if evidence_key else None
            if aliases_key and isinstance(row.get(aliases_key), list):
                aliases = tuple(a.strip() for a in row[aliases_key] if isinstance(a, str) and a.strip())
        else:
            name, evidence = row, None
        if isinstance(name, str) and name.strip():
            text = evidence.strip() if isinstance(evidence, str) else ""
            items.append((name.strip(), text or None, aliases))
    return items


def _lookup(data: dict, key: str):
    for part in key.split("."):
        data = data.get(part) if isinstance(data, dict) else None
    return data


# ── Resolving a target (never creating one) ──────────────────────────


async def _ids(db: AsyncSession, target_type: str, name: str) -> list[uuid.UUID]:
    """The ids of existing ``target_type`` entities ``name`` names exactly."""
    from app.intelligence.entity_resolution import normalize_entity_name
    from app.models.entity_index import EntityAliasIndex

    if target_type == entity_types.TTP:
        from app.models.ttp import TTP

        code = name.strip().upper()
        if not _TECHNIQUE_ID.match(code):
            return []
        return list((await db.execute(select(TTP.id).where(TTP.technique_id == code))).scalars())
    if target_type == entity_types.CVE:
        from app.models.cve import CVE

        code = name.strip().upper()
        if not _CVE_ID.match(code):
            return []
        return list((await db.execute(select(CVE.id).where(CVE.cve_id == code))).scalars())
    if target_type == entity_types.SECTOR:
        from app.intelligence.sectors import normalize_sector
        from app.models.sector import Sector

        slug = normalize_sector(name)
        if slug is None:
            return []
        return list((await db.execute(select(Sector.id).where(Sector.slug == slug))).scalars())
    if target_type == entity_types.COUNTRY:
        from app.enrichment.entity_updater import existing_country

        country = await existing_country(db, name)
        return [country.id] if country else []
    if target_type in ALIAS_INDEXED_TABLES:
        norm = normalize_entity_name(name, target_type).norm_exact
        if not norm:
            return []
        rows = await db.execute(
            select(EntityAliasIndex.entity_id)
            .where(EntityAliasIndex.entity_type == target_type, EntityAliasIndex.normalized == norm)
            .distinct()
        )
        return list(rows.scalars())
    raise ValueError(f"no resolver for {target_type} targets")


async def resolve_target(
    db: AsyncSession, target_types: tuple[str, ...], name: str
) -> tuple[tuple[str, uuid.UUID] | None, str | None]:
    """The one existing entity ``name`` names among ``target_types``, or the
    reason it is held: ``unknown`` (none does) or ``ambiguous`` (several do,
    in one type or across them, like a tool and a malware family sharing it)."""
    hits = [(t, i) for t in target_types for i in await _ids(db, t, name)]
    if len(hits) == 1:
        return hits[0], None
    return None, "ambiguous" if hits else "unknown"


# ── Where a connection lives ─────────────────────────────────────────


def _in_sector_junction(entity_type: str, relation: str, target_type: str) -> bool:
    from app.services.sector_links import TARGET_SECTOR_ENTITY_TYPES

    return target_type == entity_types.SECTOR and relation == "targets" and entity_type in TARGET_SECTOR_ENTITY_TYPES


def _ends(claim: EntityRelationClaim) -> tuple[tuple[str, uuid.UUID], tuple[str, uuid.UUID]]:
    """The claim's connection as the matrix stores it: (source, target) ends."""
    here, there = (claim.entity_type, claim.entity_id), (claim.target_type, claim.target_id)
    if is_allowed_relationship(claim.entity_type, claim.relation, claim.target_type):
        return here, there
    return there, here


async def _edge(db: AsyncSession, claim: EntityRelationClaim) -> EntityRelationship | None:
    (source_type, source_id), (target_type, target_id) = _ends(claim)
    return (
        await db.execute(
            select(EntityRelationship).where(
                EntityRelationship.source_type == source_type,
                EntityRelationship.source_id == source_id,
                EntityRelationship.target_type == target_type,
                EntityRelationship.target_id == target_id,
                EntityRelationship.relationship_type == claim.relation,
            )
        )
    ).scalar_one_or_none()


async def _sector_row(db: AsyncSession, claim: EntityRelationClaim):
    from app.services.sector_links import junction_for

    _, junction, fk_attr = junction_for(claim.entity_type)
    return (
        await db.execute(
            select(junction).where(getattr(junction, fk_attr) == claim.entity_id, junction.sector_id == claim.target_id)
        )
    ).scalar_one_or_none()


async def _refresh_sector_chips(db: AsyncSession, claim: EntityRelationClaim) -> None:
    from app.services.sector_links import junction_for, refresh_targeted_sectors_cache

    entity = await db.get(junction_for(claim.entity_type)[0], claim.entity_id)
    if entity is not None:  # a pruned claim's entity is gone
        await refresh_targeted_sectors_cache(db, claim.entity_type, entity)


async def _assert(db: AsyncSession, claim: EntityRelationClaim, label: str) -> bool:
    """Make the claim's connection exist. Returns whether anything changed.

    A new row is ``enrichment`` / ``probable``, described by the claim's
    evidence or the source's name. A co-occurrence row the claim matches is
    taken over and lifted to ``probable`` only while it is still ``possible``
    with no verdict, and keeps its own description, so ``_retract`` can hand
    it back exactly as it was. Any other row is left as it is: one
    corroboration or the adjudicator already raised (or ruled coincidental),
    and AI, MITRE, analyst and rejected rows."""
    from app.services.sector_links import add_target_sector

    if _in_sector_junction(claim.entity_type, claim.relation, claim.target_type):
        if not await add_target_sector(db, claim.entity_type, claim.entity_id, claim.target_id, EDGE_SOURCE):
            return False
        await _refresh_sector_chips(db, claim)
        return True

    edge = await _edge(db, claim)
    if edge is None:
        (source_type, source_id), (target_type, target_id) = _ends(claim)
        db.add(
            EntityRelationship(
                source_type=source_type,
                source_id=source_id,
                target_type=target_type,
                target_id=target_id,
                relationship_type=claim.relation,
                confidence="probable",
                source=EDGE_SOURCE,
                description=claim.evidence or label,
                evidence_entry_ids=[],
            )
        )
        return True
    if edge.source != "co_occurrence" or edge.confidence != "possible" or edge.adjudication_verdict is not None:
        return False
    edge.source, edge.confidence = EDGE_SOURCE, "probable"
    return True


async def _retract(db: AsyncSession, claim: EntityRelationClaim) -> bool:
    """Undo the claim's connection once no other claim holds it. Only what this
    path made goes: a sector row it asserted (back to the rollup's when the
    entity's own articles carry the sector), an ``enrichment`` row still at
    ``probable`` (back to co-occurrence when articles back it). One a review
    has since raised to ``confirmed`` stays as it is: a withdrawal never
    lowers what someone else raised. Returns whether anything changed."""
    from app.services.sector_links import remove_target_sector

    def claims_from(end, other):
        return and_(
            EntityRelationClaim.entity_type == end[0],
            EntityRelationClaim.entity_id == end[1],
            EntityRelationClaim.target_type == other[0],
            EntityRelationClaim.target_id == other[1],
        )

    # Another claim on the same connection, made from either end.
    here, there = (claim.entity_type, claim.entity_id), (claim.target_type, claim.target_id)
    others = (
        await db.execute(
            select(func.count()).where(
                EntityRelationClaim.relation == claim.relation,
                or_(claims_from(here, there), claims_from(there, here)),
                ~(
                    (EntityRelationClaim.entity_type == claim.entity_type)
                    & (EntityRelationClaim.entity_id == claim.entity_id)
                    & (EntityRelationClaim.source_type == claim.source_type)
                    & (EntityRelationClaim.output == claim.output)
                    & (EntityRelationClaim.target_key == claim.target_key)
                ),
            )
        )
    ).scalar_one()
    if others:
        return False

    if _in_sector_junction(claim.entity_type, claim.relation, claim.target_type):
        row = await _sector_row(db, claim)
        if row is None or row.source != EDGE_SOURCE:
            return False
        if row.article_count:
            row.source = "rollup"
            await db.flush()
        else:
            await remove_target_sector(db, claim.entity_type, claim.entity_id, claim.target_id)
        await _refresh_sector_chips(db, claim)
        return True

    edge = await _edge(db, claim)
    if edge is None or edge.source != EDGE_SOURCE or edge.confidence != "probable":
        return False
    if edge.evidence_entry_ids:
        edge.source, edge.confidence = "co_occurrence", "possible"
    else:
        await db.delete(edge)
    return True


# ── Applying a source's answer ───────────────────────────────────────


async def apply_relations(
    db: AsyncSession, entity_type: str, entity_id: uuid.UUID, source_type: str, parsed_data: dict
) -> bool:
    """Make the source's claims for the entity what ``parsed_data`` lists: new
    names claimed, every name re-resolved, names it no longer lists withdrawn.
    Returns whether a connection changed."""
    from app.enrichment.registry import SOURCE_REGISTRY

    cls = SOURCE_REGISTRY.get(source_type)
    relations = relations_for(cls, entity_type)
    if not relations:
        return False

    listed: dict[tuple[str, str], tuple[Relation, str, str | None, tuple[str, ...]]] = {}
    for relation in relations:
        for name, evidence, aliases in _listed(relation, _lookup(parsed_data or {}, relation.key)):
            listed.setdefault((relation.key, target_key(name)), (relation, name, evidence, aliases))

    claims = {
        (c.output, c.target_key): c
        for c in (
            await db.execute(
                select(EntityRelationClaim).where(
                    EntityRelationClaim.entity_type == entity_type,
                    EntityRelationClaim.entity_id == entity_id,
                    EntityRelationClaim.source_type == source_type,
                )
            )
        ).scalars()
    }

    now = datetime.now(UTC)
    changed = False
    touched: set[tuple[str, uuid.UUID]] = set()
    for (output, key), (relation, name, evidence, aliases) in listed.items():
        target, held = await resolve_target(db, relation.target_types, name)
        # A name nothing matches may match by another name the source gives
        # it. The claim stays under the first name either way.
        for alias in aliases if held == "unknown" else ():
            found, why = await resolve_target(db, relation.target_types, alias)
            if why != "unknown":
                target, held = found, why
                break
        claim = claims.pop((output, key), None)
        allowed = target and _allowed(entity_type, relation.relation, target[0])
        if (target and (not allowed or target == (entity_type, entity_id))) or (not target and not relation.hold):
            # Resolved to an entity the matrix doesn't connect this way, or to
            # nothing in a list that doesn't hold names: no claim.
            if claim is not None:
                changed |= await _withdraw(db, claim, touched)
            continue
        if claim is None:
            claim = EntityRelationClaim(
                entity_type=entity_type,
                entity_id=entity_id,
                source_type=source_type,
                output=output,
                relation=relation.relation,
                target_key=key,
                first_seen_at=now,
            )
            db.add(claim)
        elif claim.target_id is not None and (claim.target_type, claim.target_id) != target:
            # The name now resolves elsewhere, or nowhere: let go of the old target.
            touched.add((claim.target_type, claim.target_id))
            changed |= await _retract(db, claim)
        claim.target_name, claim.evidence, claim.last_seen_at = name, evidence, now
        claim.target_type, claim.target_id = target or (None, None)
        claim.held_reason = held
        await db.flush()
        if target and await _assert(db, claim, cls.display_name):
            changed = True
            touched.add(target)

    for claim in claims.values():
        changed |= await _withdraw(db, claim, touched)

    await db.flush()
    if touched:
        await _invalidate(entity_type, entity_id, touched)
    return changed


async def _withdraw(db: AsyncSession, claim: EntityRelationClaim, touched: set) -> bool:
    await db.delete(claim)
    await db.flush()
    if claim.target_id is None:
        return False
    touched.add((claim.target_type, claim.target_id))
    return await _retract(db, claim)


async def _invalidate(entity_type: str, entity_id: uuid.UUID, targets: set[tuple[str, uuid.UUID]]) -> None:
    """Both ends' cached pivots and graphs, so the change shows now."""
    from app.intelligence.correlation_cache import invalidate_entity_cache

    for etype, eid in {(entity_type, entity_id), *targets}:
        await invalidate_entity_cache(etype, str(eid))


async def claim_counts(db: AsyncSession, source_type: str) -> dict[str, dict[str, int]]:
    """Per Relation output key, how many of the source's claims are linked and held."""
    rows = await db.execute(
        select(
            EntityRelationClaim.output,
            func.count().filter(EntityRelationClaim.target_id.isnot(None)),
            func.count().filter(EntityRelationClaim.target_id.is_(None)),
        )
        .where(EntityRelationClaim.source_type == source_type)
        .group_by(EntityRelationClaim.output)
    )
    return {output: {"linked": linked, "held": held} for output, linked, held in rows.all()}


async def rehome_claims(db: AsyncSession, old_type: str, old_id: uuid.UUID, new_type: str, new_id: uuid.UUID) -> None:
    """Move the claims made by or naming an entity being merged away, before
    its connections move with it (``entity_merge._repoint_entity_relationships``),
    so a later answer can still withdraw them.

    Into an entity of the same type, a claim follows its connection; one the
    survivor already makes, or one that would name the survivor itself, is
    dropped. Into another type, the claim no longer fits its source's output:
    it is withdrawn by ``_retract``'s rules while the connection is still
    where the claim put it, and the source's next answer for the survivor
    claims afresh."""
    made = and_(EntityRelationClaim.entity_type == old_type, EntityRelationClaim.entity_id == old_id)
    named = and_(EntityRelationClaim.target_type == old_type, EntityRelationClaim.target_id == old_id)
    claims = (await db.execute(select(EntityRelationClaim).where(or_(made, named)))).scalars().all()
    survivor = (new_type, new_id)
    for claim in claims:
        if old_type != new_type:
            await _withdraw(db, claim, set())
        elif claim.entity_id == old_id:
            key = (new_type, new_id, claim.source_type, claim.output, claim.target_key)
            if (claim.target_type, claim.target_id) == survivor or await db.get(EntityRelationClaim, key):
                await db.delete(claim)
            else:
                claim.entity_id = new_id
        elif (claim.entity_type, claim.entity_id) == survivor:
            await db.delete(claim)
        else:
            claim.target_id = new_id
    await db.flush()


async def prune_orphan_claims(db: AsyncSession) -> int:
    """Withdraw claims whose entity is gone (deleted without a merge moving
    them), by ``_retract``'s rules, so no connection outlives the claim that
    made it. Returns the count."""
    from app.enrichment.entity_updater import _get_model_map

    pruned = 0
    for entity_type in (await db.execute(select(EntityRelationClaim.entity_type).distinct())).scalars().all():
        model = _get_model_map().get(entity_type)
        if model is None:
            continue
        orphans = (
            await db.execute(
                select(EntityRelationClaim).where(
                    EntityRelationClaim.entity_type == entity_type,
                    ~select(model.id).where(model.id == EntityRelationClaim.entity_id).exists(),
                )
            )
        ).scalars()
        for claim in orphans.all():
            await _withdraw(db, claim, set())
            pruned += 1
    return pruned
