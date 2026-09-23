"""Detection engineering summary — gathers full intelligence context and runs AI analysis."""

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.engine import run_task
from app.models.cve import CVE, EntryCVE
from app.models.detection_rule import DetectionRule
from app.models.entry import Entry
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.ttp import TTP, EntryTTP


def _entry_to_dict(entry: Entry) -> dict:
    return {
        "title": entry.title,
        "content_text": entry.content_text or "",
        "content_html": entry.content_html,
        "summary": entry.summary,
        "author": entry.author,
        "url": entry.url,
        "published_at": str(entry.published_at) if entry.published_at else "",
        "feed_title": "",
    }


async def build_detection_summary(
    db: AsyncSession,
    user_id: uuid.UUID,
    entry_ids: list[uuid.UUID],
    rule_formats: list[str],
    focus: str = "campaign",
    include_existing: bool = True,
) -> dict | None:
    """Gather full intelligence context for entries and run detection_engineering_summary AI task."""
    # Fetch entries
    entries = []
    for eid in entry_ids:
        result = await db.execute(select(Entry).where(Entry.id == eid))
        entry = result.scalar_one_or_none()
        if entry:
            entries.append(_entry_to_dict(entry))

    if not entries:
        return None

    variables: dict = {
        "entries": entries,
        "rule_formats": rule_formats,
        "focus": focus,
        "existing_iocs": [],
        "existing_ttps": [],
        "existing_cves": [],
        "threat_actor_profiles": [],
        "malware_profiles": [],
        "existing_detection_rules": [],
    }

    if include_existing:
        # Gather CVEs
        cve_result = await db.execute(
            select(CVE).join(EntryCVE, EntryCVE.cve_id == CVE.id).where(EntryCVE.entry_id.in_(entry_ids)).distinct()
        )
        variables["existing_cves"] = [
            {
                "cve_id": c.cve_id,
                "cvss_score": str(c.cvss_score) if c.cvss_score else None,
                "severity": c.severity,
                "description": c.description or "",
                "affected_products": c.affected_products or [],
                "exploit_status": c.exploit_status,
                "epss_score": c.epss_score,
            }
            for c in cve_result.scalars().all()
        ]

        # Gather TTPs
        ttp_result = await db.execute(
            select(TTP).join(EntryTTP, EntryTTP.ttp_id == TTP.id).where(EntryTTP.entry_id.in_(entry_ids)).distinct()
        )
        variables["existing_ttps"] = [
            {"technique_id": t.technique_id, "technique_name": t.technique_name, "tactic": t.tactic or ""}
            for t in ttp_result.scalars().all()
        ]

        # Gather threat actors
        actor_result = await db.execute(
            select(ThreatActor)
            .join(EntryThreatActor, EntryThreatActor.threat_actor_id == ThreatActor.id)
            .where(EntryThreatActor.entry_id.in_(entry_ids))
            .distinct()
        )
        variables["threat_actor_profiles"] = [
            {"name": a.name, "aliases": a.aliases or [], "country": a.country, "motivation": a.motivation}
            for a in actor_result.scalars().all()
        ]

        # Gather malware
        malware_result = await db.execute(
            select(MalwareFamily)
            .join(EntryMalware, EntryMalware.malware_family_id == MalwareFamily.id)
            .where(EntryMalware.entry_id.in_(entry_ids))
            .distinct()
        )
        variables["malware_profiles"] = [
            {"name": m.name, "aliases": m.aliases or [], "malware_type": m.malware_type or ""}
            for m in malware_result.scalars().all()
        ]

        # Gather existing detection rules for these entries. Column select —
        # select(DetectionRule) would join each rule's full entry row (lazy="joined").
        rule_result = await db.execute(
            select(DetectionRule.rule_type, DetectionRule.title).where(DetectionRule.entry_id.in_(entry_ids))
        )
        variables["existing_detection_rules"] = [
            {"rule_type": r.rule_type, "title": r.title} for r in rule_result.all()
        ]

        # Find related articles that share entities with our input articles
        # by finding entries linked to the same IOCs, TTPs, actors, or malware
        shared_entry_ids: set[uuid.UUID] = set()
        for junction_model, fk_col in [
            (EntryTTP, EntryTTP.ttp_id),
            (EntryCVE, EntryCVE.cve_id),
            (EntryThreatActor, EntryThreatActor.threat_actor_id),
            (EntryMalware, EntryMalware.malware_family_id),
        ]:
            # Get entity IDs linked to our entries
            entity_ids_result = await db.execute(
                select(fk_col).where(junction_model.entry_id.in_(entry_ids)).distinct()
            )
            entity_ids_list = [row[0] for row in entity_ids_result.all()]
            if entity_ids_list:
                # Find other entries linked to those same entities
                other_entries_result = await db.execute(
                    select(junction_model.entry_id)
                    .where(fk_col.in_(entity_ids_list))
                    .where(junction_model.entry_id.notin_(entry_ids))
                    .distinct()
                )
                for row in other_entries_result.all():
                    shared_entry_ids.add(row[0])

        related_articles = []
        if shared_entry_ids:
            related_result = await db.execute(
                select(Entry)
                .where(Entry.id.in_(list(shared_entry_ids)))
                .order_by(Entry.published_at.desc().nullslast())
                .limit(20)
            )
            related_articles = [
                {"title": e.title, "url": e.url, "published_at": str(e.published_at) if e.published_at else ""}
                for e in related_result.scalars().all()
            ]
        variables["related_articles"] = related_articles

        # Gather user's telemetry sources for feasibility assessment
        from app.intelligence.telemetry_context import get_telemetry_for_prompt

        variables["telemetry_sources"] = await get_telemetry_for_prompt(db, user_id)

    # Run the AI task. This runs synchronously inside the API request, so bound
    # the provider call below the gunicorn worker timeout (180s) — otherwise a
    # slow claude_code CLI call (+ its retry) outlasts the worker, which gets
    # killed mid-request and surfaces to the client as a 502. 150s leaves a
    # margin for context gathering above and response handling below.
    parsed = await run_task(
        db=db,
        user_id=user_id,
        task_name="detection_engineering_summary",
        variables=variables,
        entry_id=entry_ids[0] if len(entry_ids) == 1 else None,
        timeout_seconds=150.0,
    )

    return parsed
