"""Target-sector links: the claims layer behind an actor's or family's sector chips.

Two tables carry "X targets sector S" — ``threat_actor_target_sectors`` and
``malware_target_sectors`` — and every writer goes through here:

- the nightly rollup (``source="rollup"``), which derives rows from the victim
  sectors on an entity's own articles and owns *only* its own rows;
- reference-feed enrichment (``enrichment``), the one-time free-text backfill
  (``seed``), and analysts (``analyst``), none of which the rollup ever removes.

The legacy ``targeted_sectors`` ARRAY columns on actors and malware stay as a
read cache rebuilt by ``refresh_targeted_sectors_cache`` and nothing else, so
the dozen existing readers (profile chips, search payloads, AI context) keep
working while the junction is the source of truth. Anything that still writes
the array directly is a bug.
"""

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.malware_family import MalwareFamily
from app.models.sector import MalwareTargetSector, Sector, ThreatActorTargetSector
from app.models.threat_actor import ThreatActor

#: Who may assert a target-sector row, lowest to highest precedence. A row keeps
#: the strongest source that ever asserted it: an analyst confirming a rolled-up
#: sector upgrades the row; the rollup never downgrades an analyst's.
SOURCE_PRECEDENCE: dict[str, int] = {"rollup": 0, "enrichment": 1, "seed": 2, "analyst": 3}

#: How many labels the cache column carries. The header shows four; the rest
#: back the ``threat_actor.sector:`` filter and the AI context.
CACHE_LIMIT = 12

_SPECS: dict[str, tuple[type, type, str]] = {
    "threat_actor": (ThreatActor, ThreatActorTargetSector, "threat_actor_id"),
    "malware": (MalwareFamily, MalwareTargetSector, "malware_family_id"),
}

TARGET_SECTOR_ENTITY_TYPES = frozenset(_SPECS)


def junction_for(entity_type: str) -> tuple[type, type, str]:
    """(entity model, junction model, junction FK attribute) for a type that can target sectors."""
    try:
        return _SPECS[entity_type]
    except KeyError:
        raise ValueError(f"{entity_type} cannot target sectors") from None


async def list_target_sectors(db: AsyncSession, entity_type: str, entity_id: uuid.UUID) -> list[dict]:
    """The entity's target sectors, strongest evidence first."""
    _, junction, fk_attr = junction_for(entity_type)
    fk = getattr(junction, fk_attr)
    rows = await db.execute(
        select(junction, Sector.slug, Sector.name)
        .join(Sector, Sector.id == junction.sector_id)
        .where(fk == entity_id)
        .order_by(junction.article_count.desc(), Sector.name.asc())
    )
    return [
        {
            "sector_id": str(row.sector_id),
            "slug": slug,
            "name": name,
            "source": row.source,
            "article_count": row.article_count,
            "added_at": row.added_at.isoformat() if row.added_at else None,
        }
        for row, slug, name in rows.all()
    ]


async def add_target_sector(
    db: AsyncSession,
    entity_type: str,
    entity_id: uuid.UUID,
    sector_id: uuid.UUID,
    source: str,
    article_count: int = 0,
) -> bool:
    """Assert that the entity targets the sector. Returns whether anything changed.

    An existing row is upgraded to a stronger source or a higher evidence count;
    it is never weakened.
    """
    if source not in SOURCE_PRECEDENCE:
        raise ValueError(f"unknown target-sector source: {source}")
    _, junction, fk_attr = junction_for(entity_type)
    fk = getattr(junction, fk_attr)
    existing = (
        await db.execute(select(junction).where(fk == entity_id, junction.sector_id == sector_id))
    ).scalar_one_or_none()
    if existing is None:
        db.add(junction(**{fk_attr: entity_id}, sector_id=sector_id, source=source, article_count=article_count))
        await db.flush()
        return True
    changed = False
    if SOURCE_PRECEDENCE[source] > SOURCE_PRECEDENCE[existing.source]:
        existing.source = source
        changed = True
    if article_count and article_count != existing.article_count:
        existing.article_count = article_count
        changed = True
    if changed:
        await db.flush()
    return changed


async def remove_target_sector(db: AsyncSession, entity_type: str, entity_id: uuid.UUID, sector_id: uuid.UUID) -> bool:
    _, junction, fk_attr = junction_for(entity_type)
    fk = getattr(junction, fk_attr)
    existing = (
        await db.execute(select(junction).where(fk == entity_id, junction.sector_id == sector_id))
    ).scalar_one_or_none()
    if existing is None:
        return False
    await db.delete(existing)
    await db.flush()
    return True


async def set_rollup_sectors(
    db: AsyncSession, entity_type: str, entity_id: uuid.UUID, observed: dict[uuid.UUID, int]
) -> bool:
    """Make the rollup's view of the entity equal ``observed`` ({sector_id: article_count}).

    Rollup-owned rows that fell out of ``observed`` are deleted; rows asserted
    by any other source are kept and only have their evidence count refreshed.
    Returns whether anything changed.
    """
    _, junction, fk_attr = junction_for(entity_type)
    fk = getattr(junction, fk_attr)
    rows = (await db.execute(select(junction).where(fk == entity_id))).scalars().all()
    changed = False
    seen: set[uuid.UUID] = set()
    for row in rows:
        seen.add(row.sector_id)
        count = observed.get(row.sector_id)
        if count is None:
            if row.source == "rollup":
                await db.delete(row)
                changed = True
            elif row.article_count:
                # Evidence has gone — a curated claim stays, but without a count it can't back.
                row.article_count = 0
                changed = True
        elif row.article_count != count:
            row.article_count = count
            changed = True
    for sector_id, count in observed.items():
        if sector_id not in seen:
            db.add(junction(**{fk_attr: entity_id}, sector_id=sector_id, source="rollup", article_count=count))
            changed = True
    if changed:
        await db.flush()
    return changed


async def refresh_targeted_sectors_cache(db: AsyncSession, entity_type: str, entity) -> list[str]:
    """Rebuild the legacy ``targeted_sectors`` label array from the junction.

    The only writer of that column. Order is the junction's: most article
    evidence first, then alphabetical, capped at ``CACHE_LIMIT``.
    """
    rows = await list_target_sectors(db, entity_type, entity.id)
    labels = [r["name"] for r in rows][:CACHE_LIMIT]
    if list(entity.targeted_sectors or []) != labels:
        entity.targeted_sectors = labels
        db.add(entity)
        await db.flush()
    return labels
