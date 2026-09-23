"""Entity profile builder — aggregates cross-entity relationships into denormalized profile fields."""

import logging
import uuid

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.cve import CVE, EntryCVE
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.ttp import TTP, EntryTTP

logger = logging.getLogger(__name__)


async def rebuild_actor_ttps(actor_id: uuid.UUID, db: AsyncSession) -> int:
    """Aggregate TTPs from entries mentioning this actor."""
    result = await db.execute(
        select(TTP.technique_id, TTP.technique_name, TTP.tactic, func.count().label("count"))
        .join(EntryTTP, EntryTTP.ttp_id == TTP.id)
        .join(EntryThreatActor, EntryThreatActor.entry_id == EntryTTP.entry_id)
        .where(EntryThreatActor.threat_actor_id == actor_id)
        .group_by(TTP.technique_id, TTP.technique_name, TTP.tactic)
        .order_by(func.count().desc())
    )
    ttps = [
        {"technique_id": r.technique_id, "technique_name": r.technique_name, "tactic": r.tactic, "count": r.count}
        for r in result.all()
    ]
    await db.execute(update(ThreatActor).where(ThreatActor.id == actor_id).values(associated_ttps=ttps))
    return len(ttps)


async def rebuild_malware_actors(malware_id: uuid.UUID, db: AsyncSession) -> int:
    """Aggregate threat actors from entries mentioning this malware."""
    result = await db.execute(
        select(
            ThreatActor.id,
            ThreatActor.name,
            ThreatActor.country,
            func.count().label("count"),
        )
        .join(EntryThreatActor, EntryThreatActor.threat_actor_id == ThreatActor.id)
        .join(EntryMalware, EntryMalware.entry_id == EntryThreatActor.entry_id)
        .where(EntryMalware.malware_family_id == malware_id)
        .group_by(ThreatActor.id, ThreatActor.name, ThreatActor.country)
        .order_by(func.count().desc())
    )
    actors = [{"id": str(r.id), "name": r.name, "country": r.country, "count": r.count} for r in result.all()]
    await db.execute(update(MalwareFamily).where(MalwareFamily.id == malware_id).values(associated_actors=actors))
    return len(actors)


async def rebuild_cve_timeline(cve_id: uuid.UUID, db: AsyncSession) -> dict:
    """Rebuild CVE timeline from entry dates and existing metadata."""
    cve = await db.get(CVE, cve_id)
    if not cve:
        return {}

    # Get earliest and latest entry dates referencing this CVE
    result = await db.execute(
        select(
            func.min(EntryCVE.extracted_at).label("first_article"),
            func.max(EntryCVE.extracted_at).label("last_article"),
            func.count(EntryCVE.entry_id).label("article_count"),
        ).where(EntryCVE.cve_id == cve_id)
    )
    row = result.one_or_none()

    timeline = dict(cve.timeline) if cve.timeline else {}
    if row and row.first_article:
        timeline["first_article"] = row.first_article.isoformat()
        timeline["last_article"] = row.last_article.isoformat()
        timeline["article_count"] = row.article_count

    if cve.first_seen_at:
        timeline["first_seen"] = cve.first_seen_at.isoformat()
    if cve.epss_updated_at:
        timeline["epss_updated"] = cve.epss_updated_at.isoformat()

    await db.execute(update(CVE).where(CVE.id == cve_id).values(timeline=timeline))
    return timeline


async def rebuild_all_profiles(db: AsyncSession) -> dict:
    """Rebuild profile fields for all entities. Called by scheduled Celery task."""
    stats = {"actors": 0, "malware": 0, "cves": 0}

    # Rebuild all threat actor TTPs
    actor_ids = (await db.execute(select(ThreatActor.id))).scalars().all()
    for actor_id in actor_ids:
        count = await rebuild_actor_ttps(actor_id, db)
        if count > 0:
            stats["actors"] += 1

    # Rebuild all malware associated actors
    malware_ids = (await db.execute(select(MalwareFamily.id))).scalars().all()
    for malware_id in malware_ids:
        count = await rebuild_malware_actors(malware_id, db)
        if count > 0:
            stats["malware"] += 1

    # Rebuild all CVE timelines
    cve_ids = (await db.execute(select(CVE.id))).scalars().all()
    for cve_id in cve_ids:
        timeline = await rebuild_cve_timeline(cve_id, db)
        if timeline:
            stats["cves"] += 1

    await db.flush()
    logger.info("Profile rebuild complete: %s", stats)
    return stats
