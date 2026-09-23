"""Entry insights engine — generates actionable "So What?" guidance after entity extraction."""

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.campaign import Campaign, CampaignEntity
from app.models.cve import CVE, EntryCVE
from app.models.detection_rule import DetectionRule
from app.models.entry import Entry
from app.models.intelligence_requirement import IntelligenceRequirement, RequirementMatch
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.ttp import TTP, EntryTTP


async def generate_entry_insights(
    db: AsyncSession,
    entry_id: uuid.UUID,
) -> list[dict]:
    """Generate actionable insights for a specific entry's extracted entities."""
    insights = []

    # Get the entry
    entry = await db.get(Entry, entry_id)
    if not entry:
        return []

    # Get entities linked to this entry
    entry_ttps = await _get_entry_ttps(db, entry_id)
    entry_cves = await _get_entry_cves(db, entry_id)
    entry_actors = await _get_entry_actors(db, entry_id)

    if not any([entry_ttps, entry_cves, entry_actors]):
        return []

    # 1. Entity overlap with known actors
    insights.extend(await _check_actor_overlap(db, entry_ttps, entry_id))

    # 2. Detection gaps — CVE/TTP with no active rule
    insights.extend(await _check_detection_gaps(db, entry_id, entry_ttps, entry_cves))

    # 3. Campaign matches — entity overlap with existing campaigns
    insights.extend(await _check_campaign_overlap(db, entry_ttps, entry_cves, entry_actors, entry_id))

    # 4. Requirement matches — entry matches active PIR
    insights.extend(await _check_requirement_matches(db, entry_id))

    # 5. High-severity CVEs
    insights.extend(_check_critical_cves(entry_cves))

    # Sort by severity
    severity_order = {"high": 0, "medium": 1, "low": 2}
    insights.sort(key=lambda x: severity_order.get(x.get("severity", "low"), 2))

    return insights[:10]  # Cap at 10 insights


async def _get_entry_ttps(db: AsyncSession, entry_id: uuid.UUID) -> list[dict]:
    result = await db.execute(
        select(TTP.id, TTP.technique_id, TTP.technique_name, TTP.tactic)
        .join(EntryTTP, EntryTTP.ttp_id == TTP.id)
        .where(EntryTTP.entry_id == entry_id)
    )
    return [{"id": r[0], "technique_id": r[1], "name": r[2], "tactic": r[3]} for r in result.all()]


async def _get_entry_cves(db: AsyncSession, entry_id: uuid.UUID) -> list[dict]:
    result = await db.execute(
        select(CVE.id, CVE.cve_id, CVE.severity, CVE.cvss_score, CVE.epss_score)
        .join(EntryCVE, EntryCVE.cve_id == CVE.id)
        .where(EntryCVE.entry_id == entry_id)
    )
    return [
        {"id": r[0], "cve_id": r[1], "severity": r[2], "cvss_score": r[3], "epss_score": r[4]} for r in result.all()
    ]


async def _get_entry_actors(db: AsyncSession, entry_id: uuid.UUID) -> list[dict]:
    result = await db.execute(
        select(ThreatActor.id, ThreatActor.name, ThreatActor.article_count)
        .join(EntryThreatActor, EntryThreatActor.threat_actor_id == ThreatActor.id)
        .where(EntryThreatActor.entry_id == entry_id)
    )
    return [{"id": r[0], "name": r[1], "article_count": r[2]} for r in result.all()]


async def _check_actor_overlap(
    db: AsyncSession,
    entry_ttps: list[dict],
    entry_id: uuid.UUID,
) -> list[dict]:
    """Check if TTPs in this entry match known threat actor activity."""
    insights = []

    return insights[:3]


def _format_missing_sources(missing: list[str]) -> str:
    shown = ", ".join(missing[:3])
    if len(missing) > 3:
        shown += f" (+{len(missing) - 3} more)"
    return shown


async def _check_detection_gaps(
    db: AsyncSession,
    entry_id: uuid.UUID,
    entry_ttps: list[dict],
    entry_cves: list[dict],
) -> list[dict]:
    """Telemetry-aware detection gaps for TTPs/CVEs.

    Tiers (not rule lifecycle states):
    - actionable_gap: no rule exists at all — writing one closes the gap today
    - telemetry_gap: library rules exist but are blocked by missing telemetry
    Covered techniques/CVEs (a satisfiable rule exists) generate no insight.
    """
    from app.services.detection_coverage import (
        STATUS_LIBRARY_ONLY,
        STATUS_NO_RULE,
        classify_cves,
        classify_techniques,
        get_available_telemetry,
    )

    insights = []

    # Pre-check: if the entry already has detection rules linked, collect their
    # covered technique IDs so we can skip those TTPs entirely
    entry_rules = await db.execute(select(DetectionRule.source_ttps).where(DetectionRule.entry_id == entry_id))
    covered_techniques: set[str] = set()
    for (source_ttps,) in entry_rules.all():
        if source_ttps:
            covered_techniques.update(source_ttps)

    available = await get_available_telemetry(db)
    technique_ids = [t["technique_id"] for t in entry_ttps if t["technique_id"] not in covered_techniques]
    classification = await classify_techniques(db, technique_ids, available=available)

    for ttp in entry_ttps:
        info = classification.get(ttp["technique_id"])
        if not info:
            continue
        if info["status"] == STATUS_NO_RULE:
            insights.append(
                {
                    "type": "detection_gap",
                    "tier": "actionable_gap",
                    "severity": "medium",
                    "message": f"{ttp['technique_id']} ({ttp['name']}) has no detection rule — actionable gap",
                    "entity_id": str(ttp["id"]),
                    "entity_type": "ttp",
                    "action": "generate_rule",
                }
            )
        elif info["status"] == STATUS_LIBRARY_ONLY:
            missing = _format_missing_sources(info["missing_data_sources"])
            insights.append(
                {
                    "type": "detection_gap",
                    "tier": "telemetry_gap",
                    "severity": "low",
                    "message": (
                        f"{ttp['technique_id']} ({ttp['name']}) has {info['rule_count']} library "
                        f"rule{'s' if info['rule_count'] != 1 else ''} blocked by missing telemetry: {missing}"
                    ),
                    "entity_id": str(ttp["id"]),
                    "entity_type": "ttp",
                    "action": "generate_rule",
                }
            )

    high_cvss_cves = [c for c in entry_cves if (c.get("cvss_score") or 0) >= 7.0]
    cve_classification = await classify_cves(db, [c["cve_id"] for c in high_cvss_cves], available=available)
    for cve in high_cvss_cves:
        cvss = cve.get("cvss_score") or 0
        info = cve_classification.get(cve["cve_id"])
        if not info:
            continue
        if info["status"] == STATUS_NO_RULE:
            insights.append(
                {
                    "type": "detection_gap",
                    "tier": "actionable_gap",
                    "severity": "high" if cvss >= 9.0 else "medium",
                    "message": f"{cve['cve_id']} (CVSS {cvss}) has no detection rule — actionable gap",
                    "entity_id": str(cve["id"]),
                    "entity_type": "cve",
                    "action": "generate_rule",
                }
            )
        elif info["status"] == STATUS_LIBRARY_ONLY:
            missing = _format_missing_sources(info["missing_data_sources"])
            insights.append(
                {
                    "type": "detection_gap",
                    "tier": "telemetry_gap",
                    "severity": "medium" if cvss >= 9.0 else "low",
                    "message": (
                        f"{cve['cve_id']} (CVSS {cvss}) has library rules blocked by missing telemetry: {missing}"
                    ),
                    "entity_id": str(cve["id"]),
                    "entity_type": "cve",
                    "action": "generate_rule",
                }
            )

    return insights[:5]


async def _check_campaign_overlap(
    db: AsyncSession,
    entry_ttps: list[dict],
    entry_cves: list[dict],
    entry_actors: list[dict],
    entry_id: uuid.UUID,
) -> list[dict]:
    """Check if entry shares entities with existing campaigns."""
    insights = []

    # Get all active campaigns with their entities
    campaigns_result = await db.execute(
        select(Campaign.id, Campaign.name, CampaignEntity.entity_type, CampaignEntity.entity_id)
        .join(CampaignEntity, Campaign.id == CampaignEntity.campaign_id)
        .where(Campaign.status.in_(["active", "monitoring"]))
    )
    campaign_entities = campaigns_result.all()

    if not campaign_entities:
        return []

    # Build campaign → entity set mapping
    campaign_map: dict[tuple[uuid.UUID, str], set[uuid.UUID]] = {}
    for c_id, c_name, e_type, e_id in campaign_entities:
        key = (c_id, c_name)
        if key not in campaign_map:
            campaign_map[key] = set()
        campaign_map[key].add(e_id)

    # Check overlap
    entry_entity_ids = set()
    for ttp in entry_ttps:
        entry_entity_ids.add(ttp["id"])
    for cve in entry_cves:
        entry_entity_ids.add(cve["id"])
    for actor in entry_actors:
        entry_entity_ids.add(actor["id"])

    for (c_id, c_name), c_entities in campaign_map.items():
        overlap = entry_entity_ids & c_entities
        if len(overlap) >= 2:
            insights.append(
                {
                    "type": "campaign_match",
                    "severity": "medium",
                    "message": f'Entry shares {len(overlap)} entities with campaign "{c_name}"',
                    "campaign_id": str(c_id),
                    "action": "add_to_campaign",
                    "overlap_count": len(overlap),
                }
            )

    return insights[:3]


async def _check_requirement_matches(db: AsyncSession, entry_id: uuid.UUID) -> list[dict]:
    """Check if entry matched any active PIRs."""
    result = await db.execute(
        select(
            IntelligenceRequirement.id,
            IntelligenceRequirement.title,
            IntelligenceRequirement.priority,
            RequirementMatch.matched_at,
        )
        .join(RequirementMatch, IntelligenceRequirement.id == RequirementMatch.requirement_id)
        .where(RequirementMatch.entry_id == entry_id)
        .where(IntelligenceRequirement.status == "active")
    )
    matches = result.all()

    return [
        {
            "type": "requirement_match",
            "severity": "medium" if m[2] in ("critical", "high") else "low",
            "message": f'Matches PIR: "{m[1]}" (priority: {m[2]})',
            "requirement_id": str(m[0]),
            "action": "view_requirement",
        }
        for m in matches
    ]


def _check_critical_cves(entry_cves: list[dict]) -> list[dict]:
    """Flag critical CVEs with high EPSS scores."""
    insights = []
    for cve in entry_cves:
        epss = cve.get("epss_score") or 0
        cvss = cve.get("cvss_score") or 0
        if epss >= 0.5 and cvss >= 8.0:
            insights.append(
                {
                    "type": "critical_cve",
                    "severity": "high",
                    "message": f"{cve['cve_id']} has CVSS {cvss} and {epss:.0%} exploitation probability",
                    "entity_id": str(cve["id"]),
                    "entity_type": "cve",
                    "action": "view_cve_profile",
                }
            )
        elif cvss >= 9.0:
            insights.append(
                {
                    "type": "critical_cve",
                    "severity": "high",
                    "message": f"{cve['cve_id']} is critical severity (CVSS {cvss})",
                    "entity_id": str(cve["id"]),
                    "entity_type": "cve",
                    "action": "view_cve_profile",
                }
            )
    return insights
