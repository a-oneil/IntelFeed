"""Detection rule generation using AI."""

import re
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.caller import Caller
from app.ai.engine import run_task
from app.intelligence.telemetry_context import get_telemetry_for_prompt
from app.models.cve import CVE, EntryCVE
from app.models.detection_rule import DetectionRule
from app.services.entity_indexer import index_rules


def _split_yaml_documents(content: str) -> list[str]:
    """Split multi-document YAML (separated by '---') into individual documents.

    Only splits for YAML-based rule types (SIGMA). Each document must contain
    a 'title:' field to be considered a valid rule.
    """
    # Split on --- that appears on its own line
    parts = re.split(r"\n---\s*\n", content)
    docs = [p.strip() for p in parts if p.strip() and "title:" in p]
    return docs if len(docs) > 1 else [content]


# target_type is VARCHAR(20), so use short abbreviations for the per-rule-type
# dedup target (a cached sigma result must not answer a splunk_spl request).
RULE_TYPE_ABBREV = {
    "sigma": "sig",
    "splunk_spl": "spl",
    "crowdstrike_ql": "cs",
    "elastic_ql": "eql",
    "kql": "kql",
    "yara": "yara",
    "snort_suricata": "snort",
}


async def generate_detection_rules(
    db: AsyncSession,
    user_id: uuid.UUID,
    entry_id: uuid.UUID,
    entry_data: dict,
    ttps: list[dict],
    rule_types: list[str],
    caller: Caller | None = None,
) -> list[DetectionRule]:
    """Generate detection rules for specified formats using AI."""
    # Fetch CVEs linked to this entry for source_cves
    cve_result = await db.execute(
        select(CVE.cve_id).join(EntryCVE, EntryCVE.cve_id == CVE.id).where(EntryCVE.entry_id == entry_id)
    )
    entry_cve_ids = [r[0] for r in cve_result.all()]

    return await _generate_and_store_rules(
        db,
        user_id,
        entry_data=entry_data,
        ttps=ttps,
        rule_types=rule_types,
        entry_id=entry_id,
        target_id=entry_id,
        source_cves=entry_cve_ids,
        caller=caller,
    )


async def _generate_and_store_rules(
    db: AsyncSession,
    user_id: uuid.UUID,
    *,
    entry_data: dict,
    ttps: list[dict],
    rule_types: list[str],
    entry_id: uuid.UUID | None,
    target_id: uuid.UUID,
    source_cves: list[str] | None = None,
    source_actors: list[uuid.UUID] | None = None,
    caller: Caller | None = None,
) -> list[DetectionRule]:
    """Run the detection_rules AI task per format and persist parsed rules.

    Shared by the entry-scoped flow (target = entry) and the entity-scoped flow
    (target = entity; entry_id is the entity's most recent linked entry, kept
    for provenance/pivot linkage, or None).
    """
    telemetry_sources = await get_telemetry_for_prompt(db, user_id)

    rules = []

    for rule_type in rule_types:
        variables = {
            "entry": entry_data,
            "ttps": ttps,
            "rule_type": rule_type,
            "telemetry_sources": telemetry_sources,
        }

        rt_abbrev = RULE_TYPE_ABBREV.get(rule_type, rule_type[:5])
        result = await run_task(
            db=db,
            user_id=user_id,
            task_name="detection_rules",
            variables=variables,
            entry_id=entry_id,
            target_type=f"rule_{rt_abbrev}",
            target_id=target_id,
            caller=caller,
        )

        if result:
            # Support both array format {"rules": [...]} and legacy single-rule format
            rule_dicts = result.get("rules") if isinstance(result.get("rules"), list) else [result]

            for rd in rule_dicts:
                content = rd.get("rule_content", "")
                if not content:
                    continue

                # Split multi-document YAML (e.g. AI returns 2 SIGMA rules
                # concatenated with ---) into separate rule records
                yaml_types = {"sigma"}
                if rule_type in yaml_types:
                    content_parts = _split_yaml_documents(content)
                else:
                    content_parts = [content]

                for part in content_parts:
                    # Dedup: skip if a rule with the same content already exists for this user
                    existing = await db.execute(
                        select(DetectionRule.id)
                        .where(
                            DetectionRule.created_by == user_id,
                            DetectionRule.rule_content == part,
                        )
                        .limit(1)
                    )
                    if existing.scalar_one_or_none() is not None:
                        continue

                    # Extract title from YAML content if we split
                    title = rd.get("title", f"{rule_type} detection rule")
                    if len(content_parts) > 1:
                        title_match = re.search(r"^title:\s*(.+)$", part, re.MULTILINE)
                        if title_match:
                            title = title_match.group(1).strip()

                    rule = DetectionRule(
                        entry_id=entry_id,
                        created_by=user_id,
                        rule_type=rule_type,
                        title=title,
                        description=rd.get("description"),
                        rule_content=part,
                        severity=rd.get("severity"),
                        source_ttps=[t.get("technique_id") for t in ttps[:10]],
                        source_cves=source_cves or [],
                        source_actors=source_actors or [],
                    )
                    db.add(rule)
                    rules.append(rule)

    await db.flush()
    await index_rules(db, rules)
    return rules


# ── Entity-scoped generation ─────────────────────────────────────────

ENTITY_RULE_TYPES = {"threat_actor", "malware", "cve", "ttp"}

_ENTRY_EXCERPT_CHARS = 3000
_MAX_CONTEXT_ENTRIES = 5


def _entity_fact_lines(entity_type: str, entity) -> list[str]:
    """Human-readable facts about the entity for the AI prompt context."""
    lines: list[str] = []
    if entity_type == "threat_actor":
        lines.append(f"- Threat actor: {entity.name}")
        if getattr(entity, "aliases", None):
            lines.append(f"- Aliases: {', '.join(entity.aliases)}")
        if getattr(entity, "country", None):
            lines.append(f"- Attributed origin: {entity.country}")
        if getattr(entity, "motivation", None):
            lines.append(f"- Motivation: {entity.motivation}")
    elif entity_type == "malware":
        lines.append(f"- Malware family: {entity.name}")
        if getattr(entity, "aliases", None):
            lines.append(f"- Aliases: {', '.join(entity.aliases)}")
        if getattr(entity, "malware_type", None):
            lines.append(f"- Type: {entity.malware_type}")
    elif entity_type == "cve":
        lines.append(f"- Vulnerability: {entity.cve_id}")
        if getattr(entity, "severity", None):
            lines.append(f"- Severity: {entity.severity}")
        if getattr(entity, "cvss_score", None) is not None:
            lines.append(f"- CVSS: {entity.cvss_score}")
        if getattr(entity, "exploit_availability", None):
            lines.append(f"- Exploit availability: {entity.exploit_availability}")
        if getattr(entity, "is_kev", False):
            lines.append("- Listed in CISA KEV (known exploited in the wild)")
    elif entity_type == "ttp":
        lines.append(f"- Technique: {entity.technique_id} {entity.technique_name or ''}".rstrip())
        if getattr(entity, "tactic", None):
            lines.append(f"- Tactic: {entity.tactic}")
        if getattr(entity, "platforms", None):
            lines.append(f"- Platforms: {', '.join(entity.platforms)}")
        if getattr(entity, "data_sources", None):
            lines.append(f"- ATT&CK data sources: {', '.join(entity.data_sources)}")
    description = getattr(entity, "description", None)
    if description:
        lines.append(f"- Description: {description[:1500]}")
    return lines


async def generate_entity_detection_rules(
    db: AsyncSession,
    user_id: uuid.UUID,
    entity_type: str,
    entity_id: uuid.UUID,
    rule_types: list[str],
) -> list[DetectionRule] | None:
    """Generate detection rules for an entity (actor / malware / CVE / TTP).

    Thin entity-scoped wrapper over the entry-scoped AI task: builds a synthetic
    "entry" from the entity's facts plus excerpts of its most recent linked
    articles, so the existing detection_rules prompt renders unchanged.
    Returns None when the entity doesn't exist.
    """
    # Local import to keep module import order flexible (correlation is heavy).
    from app.intelligence.correlation import ENTITY_CONFIG, _entity_label
    from app.models.entry import Entry
    from app.models.ttp import TTP, EntryTTP

    if entity_type not in ENTITY_RULE_TYPES:
        raise ValueError(f"Unsupported entity type for rule generation: {entity_type}")

    model, junction, fk_col = ENTITY_CONFIG[entity_type]
    entity = await db.get(model, entity_id)
    if entity is None:
        return None

    label = _entity_label(entity_type, entity)

    # Most recent linked articles give the AI concrete behavior to detect.
    entry_result = await db.execute(
        select(Entry)
        .join(junction, junction.entry_id == Entry.id)
        .where(fk_col == entity_id)
        .order_by(Entry.published_at.desc().nullslast())
        .limit(_MAX_CONTEXT_ENTRIES)
    )
    entries = list(entry_result.scalars().all())
    entry_ids = [e.id for e in entries]

    # Technique context: the TTP itself, or techniques co-reported with the entity.
    if entity_type == "ttp":
        ttps = [
            {
                "technique_id": entity.technique_id,
                "technique_name": entity.technique_name,
                "tactic": entity.tactic,
            }
        ]
    elif entry_ids:
        ttp_result = await db.execute(
            select(TTP)
            .join(EntryTTP, EntryTTP.ttp_id == TTP.id)
            .where(EntryTTP.entry_id.in_(entry_ids))
            .distinct()
            .limit(10)
        )
        ttps = [
            {"technique_id": t.technique_id, "technique_name": t.technique_name, "tactic": t.tactic}
            for t in ttp_result.scalars().all()
        ]
    else:
        ttps = []

    # CVE linkage for source_cves provenance (and the CVE pivot's rule lookup).
    if entity_type == "cve":
        source_cves = [entity.cve_id]
    elif entry_ids:
        cve_result = await db.execute(
            select(CVE.cve_id)
            .join(EntryCVE, EntryCVE.cve_id == CVE.id)
            .where(EntryCVE.entry_id.in_(entry_ids))
            .distinct()
            .limit(10)
        )
        source_cves = [r[0] for r in cve_result.all()]
    else:
        source_cves = []

    # Synthetic "entry" so the entry-shaped detection_rules prompt renders as-is.
    sections = ["## Entity", *_entity_fact_lines(entity_type, entity)]
    if entries:
        sections.append("\n## Recent reporting on this entity")
        for e in entries:
            published = f" ({e.published_at.date()})" if e.published_at else ""
            excerpt = (e.content_text or e.summary or "").strip()[:_ENTRY_EXCERPT_CHARS]
            sections.append(f"### {e.title}{published}\n{excerpt}")
    description = getattr(entity, "description", None) or ""
    entry_data = {
        "title": f"Detection engineering request: {label}",
        "content_text": "\n".join(sections),
        "content_html": None,
        "summary": description[:500],
        "author": "",
        "url": "",
        "published_at": "",
        "feed_title": "",
    }

    return await _generate_and_store_rules(
        db,
        user_id,
        entry_data=entry_data,
        ttps=ttps,
        rule_types=rule_types,
        # Anchor to the freshest linked article so the rule shows in the
        # entity's shared-entry pivot and keeps an article provenance link.
        entry_id=entry_ids[0] if entry_ids else None,
        target_id=entity_id,
        source_cves=source_cves,
        source_actors=[entity_id] if entity_type == "threat_actor" else None,
    )
