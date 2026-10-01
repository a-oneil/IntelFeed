"""Threat-surface matching for exposure reports.

Given an intel profile's scope — regions (country ids) × verticals (canonical
sector slugs) — find the actors and malware families the corpus says are
active against that scope, each carrying *why it matched* so the analyst can
curate with evidence instead of trusting a silent query.

Match sources, per entity:
- co-occurrence: entries in the window that link the entity AND a scope
  country / a scope sector (entry_countries / entry_sectors junctions)
- claims: threat_actor_target_countries rows and the target-sector junctions
  (threat_actor_target_sectors / malware_target_sectors, any source)
- victims: ransomware victim disclosures by the group in scope countries /
  sectors inside the window

Nothing here writes — this is a read-model for the exposure builder's
keep/drop step.
"""

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import and_, exists, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.intelligence.sectors import normalize_sector, sector_label
from app.models.country import Country, EntryCountry
from app.models.country_junction import ThreatActorTargetCountry
from app.models.entry import Entry
from app.models.entry_sector import EntrySector
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.ransomware import VictimDisclosure
from app.models.sector import MalwareTargetSector, Sector, ThreatActorTargetSector
from app.models.threat_actor import EntryThreatActor, ThreatActor

# Candidates with only one matched dimension still surface (ranked lower,
# with the gap stated) — the analyst decides, not the query.
_MAX_CANDIDATES_PER_TYPE = 200


async def _claimed_sectors(db: AsyncSession, junction, fk, sectors: list[str]) -> dict[uuid.UUID, set[str]]:
    """entity_id -> scope slugs it is asserted to target (any claim source)."""
    out: dict[uuid.UUID, set[str]] = {}
    if not sectors:
        return out
    rows = await db.execute(
        select(fk, Sector.slug).join(Sector, Sector.id == junction.sector_id).where(Sector.slug.in_(sectors))
    )
    for entity_id, slug in rows.all():
        out.setdefault(entity_id, set()).add(slug)
    return out


async def _cooccurrence(
    db: AsyncSession,
    link_model,
    link_entity_col,
    cutoff: datetime,
    country_ids: list[uuid.UUID],
    sectors: list[str],
) -> tuple[dict[uuid.UUID, set[str]], dict[uuid.UUID, set[str]]]:
    """(entity_id -> matched country names, entity_id -> matched sector slugs)."""
    region_hits: dict[uuid.UUID, set[str]] = {}
    sector_hits: dict[uuid.UUID, set[str]] = {}

    if country_ids:
        rows = await db.execute(
            select(link_entity_col, Country.name)
            .join(EntryCountry, EntryCountry.entry_id == link_model.entry_id)
            .join(Country, Country.id == EntryCountry.country_id)
            .join(Entry, Entry.id == link_model.entry_id)
            .where(EntryCountry.country_id.in_(country_ids), Entry.published_at >= cutoff)
            .distinct()
        )
        for entity_id, country_name in rows.all():
            region_hits.setdefault(entity_id, set()).add(country_name)

    if sectors:
        rows = await db.execute(
            select(link_entity_col, EntrySector.sector)
            .join(EntrySector, EntrySector.entry_id == link_model.entry_id)
            .join(Entry, Entry.id == link_model.entry_id)
            .where(EntrySector.sector.in_(sectors), Entry.published_at >= cutoff)
            .distinct()
        )
        for entity_id, sector in rows.all():
            sector_hits.setdefault(entity_id, set()).add(sector)

    return region_hits, sector_hits


def _scope_entry_filter(link_model, country_ids: list[uuid.UUID], sectors: list[str]):
    """Entries counted as evidence must themselves touch the scope."""
    clauses = []
    if country_ids:
        clauses.append(
            exists(
                select(EntryCountry.entry_id).where(
                    EntryCountry.entry_id == link_model.entry_id, EntryCountry.country_id.in_(country_ids)
                )
            )
        )
    if sectors:
        clauses.append(
            exists(
                select(EntrySector.entry_id).where(
                    EntrySector.entry_id == link_model.entry_id, EntrySector.sector.in_(sectors)
                )
            )
        )
    return or_(*clauses) if clauses else None


async def _entry_evidence(
    db: AsyncSession,
    link_model,
    link_entity_col,
    candidate_ids: set[uuid.UUID],
    cutoff: datetime,
    country_ids: list[uuid.UUID],
    sectors: list[str],
) -> tuple[dict[uuid.UUID, int], dict[uuid.UUID, dict]]:
    """Per candidate: distinct in-scope entry count and the latest such entry."""
    if not candidate_ids:
        return {}, {}
    scope = _scope_entry_filter(link_model, country_ids, sectors)
    base_where = [link_entity_col.in_(candidate_ids), Entry.published_at >= cutoff]
    if scope is not None:
        base_where.append(scope)

    counts_rows = await db.execute(
        select(link_entity_col, func.count(func.distinct(link_model.entry_id)))
        .join(Entry, Entry.id == link_model.entry_id)
        .where(and_(*base_where))
        .group_by(link_entity_col)
    )
    counts = dict(counts_rows.all())

    latest_rows = await db.execute(
        select(link_entity_col, Entry.id, Entry.title, Entry.published_at)
        .join(Entry, Entry.id == link_model.entry_id)
        .where(and_(*base_where))
        .order_by(link_entity_col, Entry.published_at.desc())
        .distinct(link_entity_col)
    )
    latest = {
        entity_id: {
            "id": str(entry_id),
            "title": title,
            "published_at": published_at.isoformat() if published_at else None,
        }
        for entity_id, entry_id, title, published_at in latest_rows.all()
    }
    return counts, latest


def _assemble(
    entity,
    entity_type: str,
    cooc_regions: set[str],
    cooc_sectors: set[str],
    claim_regions: set[str],
    claim_sectors: set[str],
    victim_count: int,
    entry_count: int,
    latest_entry: dict | None,
) -> dict:
    region_hit = bool(cooc_regions or claim_regions)
    sector_hit = bool(cooc_sectors or claim_sectors or victim_count)
    # Both dimensions beat either alone; corpus evidence and victim volume
    # break ties inside each band.
    score = (2.0 if region_hit else 0.0) + (2.0 if sector_hit else 0.0)
    score += min(entry_count, 20) / 10.0 + min(victim_count, 20) / 10.0

    return {
        "id": str(entity.id),
        "entity_type": entity_type,
        "name": entity.name,
        "aliases": (entity.aliases or [])[:4],
        "subtype": getattr(entity, "actor_type", None) or getattr(entity, "malware_type", None),
        "matched_regions": sorted(cooc_regions | claim_regions),
        "matched_sectors": sorted({sector_label(s) for s in cooc_sectors | claim_sectors}),
        "region_sources": sorted((["reporting"] if cooc_regions else []) + (["claim"] if claim_regions else [])),
        "sector_sources": sorted(
            (["reporting"] if cooc_sectors else [])
            + (["claim"] if claim_sectors else [])
            + (["victims"] if victim_count else [])
        ),
        "victim_count": victim_count,
        "entry_count": entry_count,
        "latest_entry": latest_entry,
        "region_hit": region_hit,
        "sector_hit": sector_hit,
        "partial": region_hit != sector_hit,
        "score": round(score, 2),
    }


async def build_threat_surface(
    db: AsyncSession,
    country_ids: list[uuid.UUID],
    sectors: list[str],
    window_days: int = 90,
    limit: int = 25,
) -> dict:
    """Match actors and malware against a scope. Returns
    {"actors": [...], "malware": [...], "window_days": N, "cutoff": iso}."""
    sectors = [s for s in (normalize_sector(v) for v in sectors) if s]
    cutoff = datetime.now(UTC) - timedelta(days=window_days)

    # --- actors ---
    actor_cooc_regions, actor_cooc_sectors = await _cooccurrence(
        db, EntryThreatActor, EntryThreatActor.threat_actor_id, cutoff, country_ids, sectors
    )

    actor_claim_regions: dict[uuid.UUID, set[str]] = {}
    if country_ids:
        rows = await db.execute(
            select(ThreatActorTargetCountry.threat_actor_id, Country.name)
            .join(Country, Country.id == ThreatActorTargetCountry.country_id)
            .where(ThreatActorTargetCountry.country_id.in_(country_ids))
        )
        for actor_id, country_name in rows.all():
            actor_claim_regions.setdefault(actor_id, set()).add(country_name)

    actor_claim_sectors = await _claimed_sectors(
        db, ThreatActorTargetSector, ThreatActorTargetSector.threat_actor_id, sectors
    )

    actor_victims: dict[uuid.UUID, int] = {}
    victim_filters = []
    if country_ids:
        victim_filters.append(VictimDisclosure.country_id.in_(country_ids))
    if sectors:
        victim_filters.append(VictimDisclosure.sector.in_(sectors))
    if victim_filters:
        rows = await db.execute(
            select(VictimDisclosure.group_id, func.count(func.distinct(VictimDisclosure.victim_id)))
            .where(
                VictimDisclosure.group_id.is_not(None),
                VictimDisclosure.posted_at >= cutoff,
                or_(*victim_filters),
            )
            .group_by(VictimDisclosure.group_id)
        )
        actor_victims = dict(rows.all())

    actor_ids = (
        set(actor_cooc_regions)
        | set(actor_cooc_sectors)
        | set(actor_claim_regions)
        | set(actor_claim_sectors)
        | set(actor_victims)
    )
    actor_counts, actor_latest = await _entry_evidence(
        db, EntryThreatActor, EntryThreatActor.threat_actor_id, actor_ids, cutoff, country_ids, sectors
    )

    actors_by_id = {}
    if actor_ids:
        rows = await db.execute(select(ThreatActor).where(ThreatActor.id.in_(actor_ids)))
        actors_by_id = {a.id: a for a in rows.scalars().all()}

    actor_items = [
        _assemble(
            actors_by_id[aid],
            "threat_actor",
            actor_cooc_regions.get(aid, set()),
            actor_cooc_sectors.get(aid, set()),
            actor_claim_regions.get(aid, set()),
            actor_claim_sectors.get(aid, set()),
            actor_victims.get(aid, 0),
            actor_counts.get(aid, 0),
            actor_latest.get(aid),
        )
        for aid in actor_ids
        if aid in actors_by_id
    ]

    # --- malware ---
    mal_cooc_regions, mal_cooc_sectors = await _cooccurrence(
        db, EntryMalware, EntryMalware.malware_family_id, cutoff, country_ids, sectors
    )

    mal_claim_sectors = await _claimed_sectors(db, MalwareTargetSector, MalwareTargetSector.malware_family_id, sectors)

    mal_ids = set(mal_cooc_regions) | set(mal_cooc_sectors) | set(mal_claim_sectors)
    mal_counts, mal_latest = await _entry_evidence(
        db, EntryMalware, EntryMalware.malware_family_id, mal_ids, cutoff, country_ids, sectors
    )

    malware_by_id = {}
    if mal_ids:
        rows = await db.execute(select(MalwareFamily).where(MalwareFamily.id.in_(mal_ids)))
        malware_by_id = {m.id: m for m in rows.scalars().all()}

    malware_items = [
        _assemble(
            malware_by_id[mid],
            "malware",
            mal_cooc_regions.get(mid, set()),
            mal_cooc_sectors.get(mid, set()),
            set(),
            mal_claim_sectors.get(mid, set()),
            0,
            mal_counts.get(mid, 0),
            mal_latest.get(mid),
        )
        for mid in mal_ids
        if mid in malware_by_id
    ]

    def _rank(items: list[dict]) -> list[dict]:
        items.sort(key=lambda i: (-i["score"], -i["entry_count"], i["name"].lower()))
        return items[: min(limit, _MAX_CANDIDATES_PER_TYPE)]

    return {
        "actors": _rank(actor_items),
        "malware": _rank(malware_items),
        "window_days": window_days,
        "cutoff": cutoff.isoformat(),
    }


async def collect_exposure_entries(
    db: AsyncSession,
    actor_ids: list[uuid.UUID],
    malware_ids: list[uuid.UUID],
    country_ids: list[uuid.UUID],
    sectors: list[str],
    window_days: int = 90,
    limit: int = 200,
) -> list[uuid.UUID]:
    """Entries backing an exposure report: in-window entries linking a kept
    entity AND touching the scope, newest first."""
    sectors = [s for s in (normalize_sector(v) for v in sectors) if s]
    cutoff = datetime.now(UTC) - timedelta(days=window_days)
    entry_ids: list[uuid.UUID] = []
    seen: set[uuid.UUID] = set()

    for link_model, entity_col, ids in (
        (EntryThreatActor, EntryThreatActor.threat_actor_id, actor_ids),
        (EntryMalware, EntryMalware.malware_family_id, malware_ids),
    ):
        if not ids:
            continue
        where = [entity_col.in_(ids), Entry.published_at >= cutoff]
        scope = _scope_entry_filter(link_model, country_ids, sectors)
        if scope is not None:
            where.append(scope)
        rows = await db.execute(
            select(link_model.entry_id, Entry.published_at)
            .join(Entry, Entry.id == link_model.entry_id)
            .where(and_(*where))
            .order_by(Entry.published_at.desc())
            .distinct()
            .limit(limit)
        )
        for eid, _published in rows.all():
            if eid not in seen:
                seen.add(eid)
                entry_ids.append(eid)

    return entry_ids[:limit]
