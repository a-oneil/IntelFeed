"""Infrastructure for an actor, family, campaign or tool — the observables
behind the entity, in two honest tiers.

* **Claimed** — ``entity_relationships`` edges onto the ledger (``uses`` /
  ``communicates_with`` / ``controls``), each born from an evidence sentence
  (the one-pass AI), an analyst, or a tool. These are the graph's edges and
  carry the trust ladder.
* **Reported alongside** — observables sighted by a *reporting* door (never
  the indicator-feed door) in articles that link the entity. This is
  co-occurrence, which the ledger design keeps out of ``entity_relationships``
  on purpose; it is computed at read time, never persisted, and guarded
  against newsletters (an article naming more than two actors or three
  families relates nothing to anything).

The observable side is the mirror: ``claimed_by`` and ``reported_with``.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.campaign import Campaign, CampaignEntry
from app.models.entity_relationship import EntityRelationship
from app.models.entry import Entry
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.observable import EntryObservable, Observable
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.tool import EntryTool, Tool

#: entity_type → (model, junction, junction fk column)
_JUNCTIONS = {
    "threat_actor": (ThreatActor, EntryThreatActor, EntryThreatActor.threat_actor_id),
    "malware": (MalwareFamily, EntryMalware, EntryMalware.malware_family_id),
    "campaign": (Campaign, CampaignEntry, CampaignEntry.campaign_id),
    "tool": (Tool, EntryTool, EntryTool.tool_id),
}
INFRASTRUCTURE_ENTITY_TYPES = frozenset(_JUNCTIONS)

#: Newsletter guard: an article linking more actors/families than this names
#: many things without relating them.
_MAX_ACTORS_PER_ENTRY = 2
_MAX_FAMILIES_PER_ENTRY = 3
#: Observables with only feed sightings are list rows, not reporting.
_REPORTING_SOURCES = ("ai", "ttp", "manual", "sighting", "publisher")


def _dt(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _observable_row(o: Observable) -> dict:
    return {
        "id": str(o.id),
        "kind": o.kind,
        "value": o.value,
        "label": o.label,
        "role": o.role,
        "status": o.status,
        "infra_tag": o.infra_tag,
        "current_confidence": o.current_confidence,
        "report_count": o.report_count or 0,
        "feed_source_count": o.feed_source_count or 0,
        "sighting_count": o.sighting_count or 0,
        "first_seen_at": _dt(o.first_seen_at),
        "last_seen_at": _dt(o.last_seen_at),
        "created_via": o.created_via,
    }


async def _claimed(db: AsyncSession, entity_type: str, entity_id: uuid.UUID, limit: int) -> list[dict]:
    rows = (
        await db.execute(
            select(EntityRelationship, Observable)
            .join(Observable, Observable.id == EntityRelationship.target_id)
            .where(
                EntityRelationship.source_type == entity_type,
                EntityRelationship.source_id == entity_id,
                EntityRelationship.target_type == "observable",
                EntityRelationship.source != "analyst_rejected",
                Observable.is_denied.is_(False),
            )
            .order_by(Observable.last_seen_at.desc())
            .limit(limit)
        )
    ).all()
    out = []
    for rel, obs in rows:
        out.append(
            {
                **_observable_row(obs),
                "relationship_id": str(rel.id),
                "relationship_type": rel.relationship_type,
                "relationship_confidence": rel.confidence,
                "relationship_source": rel.source,
                "adjudication_verdict": rel.adjudication_verdict,
                "evidence_entry_ids": [str(e) for e in (rel.evidence_entry_ids or [])][:10],
                "evidence_count": len(rel.evidence_entry_ids or []),
            }
        )
    return out


def _clean_entries_subquery(entry_ids_q):
    """Entries that are real reporting (not indicator-list files) and not
    newsletters (bounded actor/family fan-out)."""
    actor_counts = (
        select(EntryThreatActor.entry_id, func.count().label("n")).group_by(EntryThreatActor.entry_id).subquery()
    )
    family_counts = select(EntryMalware.entry_id, func.count().label("n")).group_by(EntryMalware.entry_id).subquery()
    return (
        select(Entry.id)
        .outerjoin(actor_counts, actor_counts.c.entry_id == Entry.id)
        .outerjoin(family_counts, family_counts.c.entry_id == Entry.id)
        .where(
            Entry.id.in_(entry_ids_q),
            func.coalesce(Entry.metadata_["content_type"].astext, "") != "ioc_list",
            func.coalesce(actor_counts.c.n, 0) <= _MAX_ACTORS_PER_ENTRY,
            func.coalesce(family_counts.c.n, 0) <= _MAX_FAMILIES_PER_ENTRY,
        )
    )


async def _reported_alongside(
    db: AsyncSession, entity_type: str, entity_id: uuid.UUID, claimed_ids: set[str], limit: int
) -> list[dict]:
    _model, junction, fk_col = _JUNCTIONS[entity_type]
    entity_entries = select(junction.entry_id).where(fk_col == entity_id)
    clean = _clean_entries_subquery(entity_entries)
    agg = (
        select(
            EntryObservable.observable_id.label("observable_id"),
            func.count(func.distinct(EntryObservable.entry_id)).label("articles"),
            func.max(Entry.published_at).label("last_reported_at"),
            func.array_agg(func.distinct(EntryObservable.entry_id)).label("entry_ids"),
        )
        .join(Entry, Entry.id == EntryObservable.entry_id)
        .where(EntryObservable.entry_id.in_(clean), EntryObservable.source.in_(_REPORTING_SOURCES))
        .group_by(EntryObservable.observable_id)
        .subquery()
    )
    rows = (
        await db.execute(
            select(Observable, agg.c.articles, agg.c.last_reported_at, agg.c.entry_ids)
            .join(agg, agg.c.observable_id == Observable.id)
            .where(Observable.is_denied.is_(False))
            .order_by(agg.c.articles.desc(), agg.c.last_reported_at.desc())
            .limit(limit + len(claimed_ids))
        )
    ).all()
    out = []
    for obs, articles, last_reported, entry_ids in rows:
        if str(obs.id) in claimed_ids:
            continue
        out.append(
            {
                **_observable_row(obs),
                "article_count": int(articles or 0),
                "last_reported_at": _dt(last_reported),
                "entry_ids": [str(e) for e in (entry_ids or [])[:5]],
            }
        )
        if len(out) >= limit:
            break
    return out


#: Cached under the pivot key space (variant suffix) so the pivot cache's
#: invalidation hooks — unlink, relationship writes, entry re-links — drop it.
_CACHE_VARIANT = ":infra"


async def get_entity_infrastructure(
    db: AsyncSession, entity_type: str, entity_id: uuid.UUID, *, limit: int = 200, use_cache: bool = True
) -> dict:
    """Claimed + reported-alongside observables for an actor/family/campaign/tool."""
    if entity_type not in _JUNCTIONS:
        raise ValueError(f"no infrastructure view for {entity_type}")
    from app.intelligence.correlation_cache import get_cached_pivot, set_cached_pivot

    variant = f"{_CACHE_VARIANT}:{limit}"
    payload = await get_cached_pivot(entity_type, str(entity_id), variant) if use_cache else None
    if payload is None:
        payload = await _build_entity_infrastructure(db, entity_type, entity_id, limit)
        if use_cache:
            await set_cached_pivot(entity_type, str(entity_id), payload, variant=variant)
    # The staged-candidate count moves with every observables-stage run and
    # candidate promote/dismiss — none of which touch the pivot cache — so it
    # is computed fresh on every read (one indexed count).
    payload = {**payload, "counts": {**payload["counts"]}}
    payload["counts"]["staged_candidate_articles"] = await _staged_candidate_articles(db, entity_type, entity_id)
    return payload


async def _staged_candidate_articles(db: AsyncSession, entity_type: str, entity_id: uuid.UUID) -> int:
    """How many of this entity's articles still carry staged (un-promoted)
    candidates — what the analyst can go and work from an empty panel."""
    _model, junction, fk_col = _JUNCTIONS[entity_type]
    staged = (
        await db.execute(
            select(func.count(func.distinct(Entry.id)))
            .join(junction, junction.entry_id == Entry.id)
            .where(fk_col == entity_id, func.jsonb_array_length(Entry.observable_candidates) > 0)
        )
    ).scalar_one()
    return int(staged or 0)


async def _build_entity_infrastructure(db: AsyncSession, entity_type: str, entity_id: uuid.UUID, limit: int) -> dict:
    claimed = await _claimed(db, entity_type, entity_id, limit)
    claimed_ids = {c["id"] for c in claimed}
    reported = await _reported_alongside(db, entity_type, entity_id, claimed_ids, limit)
    by_kind: dict[str, int] = {}
    for row in claimed + reported:
        by_kind[row["kind"]] = by_kind.get(row["kind"], 0) + 1
    return {
        "entity_type": entity_type,
        "entity_id": str(entity_id),
        "claimed": claimed,
        "reported_alongside": reported,
        "counts": {
            "claimed": len(claimed),
            "reported_alongside": len(reported),
            "by_kind": by_kind,
            "staged_candidate_articles": 0,  # filled fresh by get_entity_infrastructure
        },
    }


async def infrastructure_observable_ids(db: AsyncSession, entity_type: str, entity_id: uuid.UUID) -> list[uuid.UUID]:
    """Every observable behind an entity (claimed + reported alongside), for
    the browser's ``linked_entity`` filter."""
    payload = await get_entity_infrastructure(db, entity_type, entity_id, limit=1000, use_cache=False)
    return [uuid.UUID(r["id"]) for r in payload["claimed"] + payload["reported_alongside"]]


async def get_observable_backlinks(db: AsyncSession, observable_id: uuid.UUID, *, limit: int = 50) -> dict:
    """The mirror for an observable's profile: who claims it, and which
    actors/families its reporting articles name."""
    claimed_by = []
    rows = (
        await db.execute(
            select(EntityRelationship)
            .where(
                EntityRelationship.target_type == "observable",
                EntityRelationship.target_id == observable_id,
                EntityRelationship.source != "analyst_rejected",
            )
            .order_by(EntityRelationship.updated_at.desc())
            .limit(limit)
        )
    ).scalars()
    for rel in rows:
        model = _JUNCTIONS.get(rel.source_type, (None,))[0]
        name = None
        if model is not None:
            name = (await db.execute(select(model.name).where(model.id == rel.source_id))).scalar_one_or_none()
        claimed_by.append(
            {
                "entity_type": rel.source_type,
                "entity_id": str(rel.source_id),
                "name": name,
                "relationship_id": str(rel.id),
                "relationship_type": rel.relationship_type,
                "relationship_confidence": rel.confidence,
                "relationship_source": rel.source,
                "adjudication_verdict": rel.adjudication_verdict,
                "evidence_count": len(rel.evidence_entry_ids or []),
            }
        )
    claimed_keys = {(c["entity_type"], c["entity_id"]) for c in claimed_by}

    reporting_entries = select(EntryObservable.entry_id).where(
        EntryObservable.observable_id == observable_id, EntryObservable.source.in_(_REPORTING_SOURCES)
    )
    clean = _clean_entries_subquery(reporting_entries)
    reported_with = []
    for etype in ("threat_actor", "malware", "campaign", "tool"):
        model, junction, fk_col = _JUNCTIONS[etype]
        agg = (
            await db.execute(
                select(model.id, model.name, func.count(func.distinct(junction.entry_id)).label("articles"))
                .join(junction, fk_col == model.id)
                .where(junction.entry_id.in_(clean))
                .group_by(model.id, model.name)
                .order_by(func.count(func.distinct(junction.entry_id)).desc())
                .limit(limit)
            )
        ).all()
        for eid, name, articles in agg:
            if (etype, str(eid)) in claimed_keys:
                continue
            reported_with.append(
                {"entity_type": etype, "entity_id": str(eid), "name": name, "article_count": int(articles)}
            )
    reported_with.sort(key=lambda r: -r["article_count"])
    return {"observable_id": str(observable_id), "claimed_by": claimed_by, "reported_with": reported_with[:limit]}


def infrastructure_csv_rows(payload: dict) -> list[list[str]]:
    """Flat rows for an export: tier, kind, value, role, trust, articles, last seen."""
    rows: list[list[str]] = [
        ["tier", "kind", "value", "role", "confidence", "relationship", "articles", "last_seen_at"]
    ]
    for c in payload.get("claimed", []):
        rows.append(
            [
                "claimed",
                c["kind"],
                c["value"],
                c.get("role") or "",
                c.get("relationship_confidence") or "",
                c.get("relationship_type") or "",
                str(c.get("evidence_count") or 0),
                c.get("last_seen_at") or "",
            ]
        )
    for r in payload.get("reported_alongside", []):
        rows.append(
            [
                "reported_alongside",
                r["kind"],
                r["value"],
                r.get("role") or "",
                "",
                "",
                str(r.get("article_count") or 0),
                r.get("last_reported_at") or "",
            ]
        )
    return rows


__all__ = [
    "INFRASTRUCTURE_ENTITY_TYPES",
    "infrastructure_observable_ids",
    "get_entity_infrastructure",
    "get_observable_backlinks",
    "infrastructure_csv_rows",
]
