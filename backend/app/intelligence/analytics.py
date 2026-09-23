"""Analytics engine — trending entities, detection coverage, velocity, and density metrics."""

from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.correlation_event import CorrelationEventRecord
from app.models.cve import CVE
from app.models.detection_rule import DetectionRule
from app.models.malware_family import MalwareFamily
from app.models.threat_actor import ThreatActor
from app.models.ttp import TTP


async def entity_trending(
    db: AsyncSession,
    entity_type: str,
    days: int = 30,
    limit: int = 20,
) -> list[dict]:
    """Top entities by article count over the time window."""
    cutoff = datetime.now(UTC) - timedelta(days=days)

    if entity_type == "threat_actor":
        stmt = (
            select(
                ThreatActor.id,
                ThreatActor.name,
                ThreatActor.article_count,
                ThreatActor.first_seen_at,
                ThreatActor.last_seen_at,
            )
            .where(ThreatActor.last_seen_at >= cutoff)
            .order_by(ThreatActor.article_count.desc())
            .limit(limit)
        )
    elif entity_type == "malware":
        stmt = (
            select(
                MalwareFamily.id,
                MalwareFamily.name,
                MalwareFamily.article_count,
                MalwareFamily.first_seen_at,
                MalwareFamily.last_seen_at,
            )
            .where(MalwareFamily.last_seen_at >= cutoff)
            .order_by(MalwareFamily.article_count.desc())
            .limit(limit)
        )
    elif entity_type == "cve":
        stmt = (
            select(
                CVE.id,
                CVE.cve_id,
                CVE.severity,
                CVE.first_seen_at,
            )
            .where(CVE.first_seen_at >= cutoff)
            .order_by(CVE.first_seen_at.desc())
            .limit(limit)
        )
    elif entity_type == "ttp":
        stmt = (
            select(
                TTP.id,
                TTP.technique_id,
                TTP.technique_name,
                TTP.article_count,
                TTP.first_seen_at,
                TTP.last_seen_at,
            )
            .where(TTP.last_seen_at >= cutoff)
            .order_by(TTP.article_count.desc())
            .limit(limit)
        )
    else:
        return []

    result = await db.execute(stmt)
    rows = result.all()

    trending = []
    for row in rows:
        if entity_type in ("threat_actor", "malware"):
            trending.append(
                {
                    "entity_id": str(row[0]),
                    "entity_name": row[1],
                    "article_count": row[2],
                    "first_seen": row[3].isoformat() if row[3] else None,
                    "last_seen": row[4].isoformat() if row[4] else None,
                }
            )
        elif entity_type == "ttp":
            trending.append(
                {
                    "entity_id": str(row[0]),
                    "entity_name": f"{row[1]} — {row[2]}",
                    "technique_id": row[1],
                    "article_count": row[3],
                    "first_seen": row[4].isoformat() if row[4] else None,
                    "last_seen": row[5].isoformat() if row[5] else None,
                }
            )
        elif entity_type == "cve":
            trending.append(
                {
                    "entity_id": str(row[0]),
                    "entity_name": row[1],
                    "severity": row[2],
                    "first_seen": row[3].isoformat() if row[3] else None,
                }
            )

    return trending


async def detection_coverage(db: AsyncSession, include_gaps: bool = True) -> dict:
    """ATT&CK coverage analysis — observed TTPs vs active detection rules."""
    # Get all observed TTPs
    ttp_result = await db.execute(select(TTP.id, TTP.technique_id, TTP.technique_name, TTP.tactic))
    all_ttps = ttp_result.all()

    # Get TTPs that have active detection rules (source_ttps stores technique IDs like "T1059")
    covered_result = await db.execute(
        select(DetectionRule.source_ttps)
        .where(DetectionRule.is_draft.is_(False))
        .where(DetectionRule.source_ttps.isnot(None))
    )
    covered_ttps_raw = covered_result.scalars().all()

    # Flatten source_ttps JSONB arrays into a set of technique IDs
    covered_technique_ids = set()
    for ttps in covered_ttps_raw:
        if isinstance(ttps, list):
            covered_technique_ids.update(ttps)
        elif isinstance(ttps, str):
            covered_technique_ids.add(ttps)

    total = len(all_ttps)
    covered = sum(1 for t in all_ttps if t[1] in covered_technique_ids)
    gaps = []

    if include_gaps:
        gaps = [
            {
                "technique_id": t[1],
                "technique_name": t[2],
                "tactic": t[3],
            }
            for t in all_ttps
            if t[1] not in covered_technique_ids
        ]

    # Group by tactic
    tactic_summary = {}
    for t in all_ttps:
        tactic = t[3] or "unknown"
        if tactic not in tactic_summary:
            tactic_summary[tactic] = {"total": 0, "covered": 0}
        tactic_summary[tactic]["total"] += 1
        if t[1] in covered_technique_ids:
            tactic_summary[tactic]["covered"] += 1

    return {
        "total_ttps": total,
        "covered_ttps": covered,
        "coverage_percentage": round(covered / total * 100, 1) if total > 0 else 0,
        "tactic_summary": tactic_summary,
        "gaps": gaps,
    }


async def intelligence_velocity(db: AsyncSession, days: int = 30) -> dict:
    """New entities per day over time window."""
    cutoff = datetime.now(UTC) - timedelta(days=days)

    entity_models = [
        ("cve", CVE, CVE.first_seen_at),
        ("threat_actor", ThreatActor, ThreatActor.first_seen_at),
        ("malware", MalwareFamily, MalwareFamily.first_seen_at),
        ("ttp", TTP, TTP.first_seen_at),
    ]

    velocity = {}
    for entity_type, model, date_col in entity_models:
        result = await db.execute(
            select(
                func.date(date_col).label("day"),
                func.count().label("count"),
            )
            .where(date_col >= cutoff)
            .group_by(func.date(date_col))
            .order_by(func.date(date_col))
        )
        rows = result.all()
        velocity[entity_type] = [{"date": str(row[0]), "count": row[1]} for row in rows]

    return {"days": days, "velocity": velocity}


async def analytics_overview(db: AsyncSession) -> dict:
    """Combined summary for dashboard — entity counts and recent activity."""
    cve_count = await db.scalar(select(func.count(CVE.id)))
    actor_count = await db.scalar(select(func.count(ThreatActor.id)))
    malware_count = await db.scalar(select(func.count(MalwareFamily.id)))
    ttp_count = await db.scalar(select(func.count(TTP.id)))
    rule_count = await db.scalar(select(func.count(DetectionRule.id)))
    published_rules = await db.scalar(select(func.count(DetectionRule.id)).where(DetectionRule.is_draft.is_(False)))

    # Recent events count (last 7 days)
    cutoff_7d = datetime.now(UTC) - timedelta(days=7)
    recent_events = await db.scalar(
        select(func.count(CorrelationEventRecord.id)).where(CorrelationEventRecord.created_at >= cutoff_7d)
    )
    unread_events = await db.scalar(
        select(func.count(CorrelationEventRecord.id)).where(CorrelationEventRecord.is_read.is_(False))
    )

    return {
        "entity_counts": {
            "cves": cve_count or 0,
            "threat_actors": actor_count or 0,
            "malware": malware_count or 0,
            "ttps": ttp_count or 0,
        },
        "detection": {
            "total_rules": rule_count or 0,
            "published_rules": published_rules or 0,
        },
        "events": {
            "recent_7d": recent_events or 0,
            "unread": unread_events or 0,
        },
    }
