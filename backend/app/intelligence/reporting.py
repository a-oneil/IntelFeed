"""Report rendering engine for IntelFeed intelligence reports."""

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.country import Country, EntryCountry
from app.models.cve import CVE, EntryCVE
from app.models.detection_rule import DetectionRule
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.ttp import TTP, EntryTTP

# 6 report templates with section definitions
REPORT_TEMPLATES = {
    # NOTE: the "iocs" data section is the observables ledger (judged rows
    # sighted in the report's sources, defanged, with attribution claims).
    # The name matches the builtin ReportTemplate DB rows seeded in 050 —
    # which carried these sections for months while nothing filled them.
    "flash_alert": {
        "name": "Flash Alert",
        "sections": ["summary", "key_findings", "iocs", "recommended_actions", "references"],
        "description": "Rapid notification of emerging threats requiring immediate attention",
    },
    "actor_profile": {
        "name": "Threat Actor Profile",
        "sections": [
            "overview",
            "aliases_attribution",
            "ttps",
            "target_sectors",
            "infrastructure",
            "iocs",
            "timeline",
            "references",
        ],
        "description": "Comprehensive profile of a threat actor or group",
    },
    "campaign_tracker": {
        "name": "Campaign Tracker",
        "sections": [
            "executive_summary",
            "campaign_overview",
            "attack_chain",
            "iocs",
            "ttps",
            "affected_systems",
            "timeline",
            "recommendations",
        ],
        "description": "Tracking document for an active threat campaign",
    },
    "landscape_report": {
        "name": "Threat Landscape Report",
        "sections": [
            "executive_summary",
            "key_trends",
            "notable_threats",
            "vulnerability_highlights",
            "sector_impact",
            "outlook",
            "appendix",
        ],
        "description": "Periodic overview of the threat landscape",
    },
    "exposure_report": {
        "name": "Threat Exposure Report",
        "sections": [
            "executive_summary",
            "scope",
            "threat_surface",
            "ttps",
            "iocs",
            "outlook",
            "references",
        ],
        "description": (
            "Exposure profile for a saved scope (regions × verticals): the matched threat surface with "
            "why-matched evidence, plus TTPs and indicators from the backing entries"
        ),
    },
    "detection_report": {
        "name": "Detection Engineering Report",
        "sections": [
            "executive_summary",
            "attack_chain",
            "ttps",
            "detection_opportunities",
            "coverage_gaps",
            "iocs",
            "log_source_requirements",
            "recommended_actions",
            "references",
        ],
        "description": (
            "Detection-focused analysis mapping threats to techniques, detection opportunities, coverage gaps, and log "
            "source requirements"
        ),
    },
}


# Report family → tailored section-generation AI task (seeded from
# app/ai/prompts/defaults.py; each shows in Settings > AI > Prompts).
REPORT_SECTION_TASKS: dict[str, str] = {
    "exposure_report": "report_section_exposure",
    "flash_alert": "report_section_flash_alert",
    "actor_profile": "report_section_actor_profile",
    "campaign_tracker": "report_section_campaign_tracker",
    "landscape_report": "report_section_landscape",
    "detection_report": "report_section_detection",
}


async def resolve_report_sources(
    db: AsyncSession,
    source_type: str,
    entry_id: uuid.UUID | None,
    entry_ids: list[uuid.UUID] | None,
    search_query: str | None,
    saved_search_id: uuid.UUID | None,
    user_id: uuid.UUID,
    search_limit: int = 50,
) -> tuple[list[uuid.UUID], dict]:
    """Resolve source into (entry_ids, entity_ids_dict).

    For search/saved_search: execute via Meilisearch, collect hit IDs.
    Then query junction tables to auto-collect entity_ids from the resolved entries.
    """
    resolved_ids: list[uuid.UUID] = []

    if source_type == "entry":
        if entry_id:
            resolved_ids = [entry_id]
    elif source_type == "entries":
        resolved_ids = list(entry_ids or [])
    elif source_type == "search":
        from app.services.meilisearch_client import search_entries

        results = search_entries(query=search_query or "", limit=search_limit, offset=0)
        for hit in results.get("hits", []):
            try:
                resolved_ids.append(uuid.UUID(hit["id"]))
            except (KeyError, ValueError):
                continue
    elif source_type == "saved_search":
        from app.models.saved_search import SavedSearch
        from app.services.meilisearch_client import search_entries

        saved = await db.get(SavedSearch, saved_search_id)
        if not saved:
            return [], {}
        results = search_entries(query=saved.query or "", limit=search_limit, offset=0)
        for hit in results.get("hits", []):
            try:
                resolved_ids.append(uuid.UUID(hit["id"]))
            except (KeyError, ValueError):
                continue

    if not resolved_ids:
        return [], {}

    return resolved_ids, await collect_entity_ids_for_entries(db, resolved_ids)


async def collect_entity_ids_for_entries(db: AsyncSession, entry_ids: list[uuid.UUID]) -> dict[str, list[str]]:
    """Entity ids linked to the given entries, keyed by report entity_ids buckets."""
    entity_ids: dict[str, list[str]] = {}
    if not entry_ids:
        return entity_ids

    from app.models.observable import EntryObservable

    junction_queries = [
        ("ttps", EntryTTP, EntryTTP.ttp_id),
        ("cves", EntryCVE, EntryCVE.cve_id),
        ("actors", EntryThreatActor, EntryThreatActor.threat_actor_id),
        ("malware", EntryMalware, EntryMalware.malware_family_id),
        ("countries", EntryCountry, EntryCountry.country_id),
        # Ledger sightings ride along; denied tombstones are filtered where
        # the rows are fetched (collect_report_observables).
        ("observables", EntryObservable, EntryObservable.observable_id),
    ]

    for key, model, id_col in junction_queries:
        result = await db.execute(select(id_col).where(model.entry_id.in_(entry_ids)).distinct())
        ids = [str(row[0]) for row in result.all()]
        if ids:
            entity_ids[key] = ids

    return entity_ids


async def collect_report_observables(
    db: AsyncSession,
    entry_ids: list[uuid.UUID],
    entity_ids: dict | None = None,
    limit: int = 150,
) -> list[dict]:
    """Ledger rows for a report: every non-denied observable sighted in the
    report's source entries (union any explicitly attached ids), each carrying
    its attribution claims ("Qakbot · communicates_with") from the trust
    ladder. Claimed rows sort first — they're the ones worth leading with.
    """
    from app.models.entity_relationship import EntityRelationship
    from app.models.observable import EntryObservable, Observable

    obs_ids: set[uuid.UUID] = set()
    for raw in (entity_ids or {}).get("observables") or []:
        try:
            obs_ids.add(uuid.UUID(raw) if isinstance(raw, str) else raw)
        except (ValueError, TypeError):
            continue
    if entry_ids:
        rows = await db.execute(
            select(EntryObservable.observable_id).where(EntryObservable.entry_id.in_(entry_ids)).distinct()
        )
        obs_ids.update(rows.scalars())
    if not obs_ids:
        return []

    observables = (
        (
            await db.execute(
                select(Observable)
                .where(Observable.id.in_(obs_ids), Observable.is_denied.is_(False))
                .order_by(Observable.current_confidence.desc(), Observable.kind, Observable.value)
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )
    if not observables:
        return []

    # Attribution claims onto these rows (actor/malware/tool/campaign →
    # uses/communicates_with/controls → observable). Rejected edges stay out.
    rels = (
        (
            await db.execute(
                select(EntityRelationship).where(
                    EntityRelationship.target_type == "observable",
                    EntityRelationship.target_id.in_([o.id for o in observables]),
                    EntityRelationship.source != "analyst_rejected",
                )
            )
        )
        .scalars()
        .all()
    )
    # Resolve claim-source names per type, one query each.
    names: dict[tuple[str, uuid.UUID], str] = {}
    by_type: dict[str, set[uuid.UUID]] = {}
    for r in rels:
        by_type.setdefault(r.source_type, set()).add(r.source_id)
    from app.models.malware_family import MalwareFamily as _Malware
    from app.models.threat_actor import ThreatActor as _Actor
    from app.models.tool import Tool as _Tool

    _NAME_MODELS = {"threat_actor": _Actor, "malware": _Malware, "tool": _Tool}
    try:
        from app.models.campaign import Campaign as _Campaign

        _NAME_MODELS["campaign"] = _Campaign
    except ImportError:
        pass
    for src_type, ids in by_type.items():
        model = _NAME_MODELS.get(src_type)
        if model is None:
            continue
        for row_id, row_name in (await db.execute(select(model.id, model.name).where(model.id.in_(ids)))).all():
            names[(src_type, row_id)] = row_name
    claims: dict[uuid.UUID, list[str]] = {}
    for r in rels:
        name = names.get((r.source_type, r.source_id))
        if not name:
            continue
        label = f"{name} · {r.relationship_type.replace('_', ' ')}"
        if label not in claims.setdefault(r.target_id, []):
            claims[r.target_id].append(label)

    items = [
        {
            "kind": o.kind,
            "value": o.value,
            "label": o.label,
            "role": o.role,
            "confidence": round(o.current_confidence, 2),
            "status": o.status,
            "infra_tag": o.infra_tag,
            "sightings": o.sighting_count or 0,
            "reports": o.report_count or 0,
            "feeds": o.feed_source_count or 0,
            "first_seen": o.first_seen_at.date().isoformat() if o.first_seen_at else None,
            "last_seen": o.last_seen_at.date().isoformat() if o.last_seen_at else None,
            "claimed_by": claims.get(o.id, []),
        }
        for o in observables
    ]
    # Attribution-backed rows lead; then by confidence within kind order.
    items.sort(key=lambda i: (not i["claimed_by"], i["kind"], -i["confidence"]))
    return items


async def generate_report_content(
    template_type: str,
    entry_ids: list[uuid.UUID],
    entity_ids: dict,
    db: AsyncSession,
) -> dict:
    """Generate initial report content from template + linked entities."""
    template = REPORT_TEMPLATES.get(template_type)
    section_names: list[str] | None = list(template["sections"]) if template else None
    if section_names is None:
        # DB template (builtin extras like ioc_bulletin, or user-created):
        # honor ITS section list instead of silently pre-filling flash_alert's.
        from app.models.report_template import ReportTemplate

        row = (
            (await db.execute(select(ReportTemplate).where(ReportTemplate.template_slug == template_type)))
            .scalars()
            .first()
        )
        if row and row.sections:
            section_names = [s.get("name") for s in row.sections if isinstance(s, dict) and s.get("name")]
    if not section_names:
        section_names = list(REPORT_TEMPLATES["flash_alert"]["sections"])

    # Fetch linked entries
    entries = []
    if entry_ids:
        result = await db.execute(select(Entry).where(Entry.id.in_(entry_ids)))
        entries = list(result.scalars().all())

    # Fetch linked entities
    ttps = []
    if entity_ids.get("ttps"):
        result = await db.execute(
            select(TTP).where(TTP.id.in_([uuid.UUID(i) if isinstance(i, str) else i for i in entity_ids["ttps"]]))
        )
        ttps = list(result.scalars().all())

    cves = []
    if entity_ids.get("cves"):
        result = await db.execute(
            select(CVE).where(CVE.id.in_([uuid.UUID(i) if isinstance(i, str) else i for i in entity_ids["cves"]]))
        )
        cves = list(result.scalars().all())

    actors = []
    if entity_ids.get("actors"):
        result = await db.execute(
            select(ThreatActor).where(
                ThreatActor.id.in_([uuid.UUID(i) if isinstance(i, str) else i for i in entity_ids["actors"]])
            )
        )
        actors = list(result.scalars().all())

    rules = []
    if entity_ids.get("detection_rules"):
        result = await db.execute(
            select(DetectionRule).where(
                DetectionRule.id.in_([uuid.UUID(i) if isinstance(i, str) else i for i in entity_ids["detection_rules"]])
            )
        )
        rules = list(result.scalars().all())

    malware = []
    if entity_ids.get("malware"):
        result = await db.execute(
            select(MalwareFamily).where(
                MalwareFamily.id.in_([uuid.UUID(i) if isinstance(i, str) else i for i in entity_ids["malware"]])
            )
        )
        malware = list(result.scalars().all())

    # Build content dict with sections
    content: dict = {
        "sections": {},
        "metadata": {
            "generated_at": datetime.now(UTC).isoformat(),
            "template": template_type,
        },
    }

    for section in section_names:
        if section in ("summary", "executive_summary", "overview"):
            content["sections"][section] = {
                "title": section.replace("_", " ").title(),
                "body": "",
            }
        elif section == "ttps":
            content["sections"][section] = {
                "title": "Tactics, Techniques & Procedures",
                "items": [
                    {
                        "technique_id": ttp.technique_id,
                        "name": ttp.technique_name,
                        "tactic": ttp.tactic,
                    }
                    for ttp in ttps
                ],
            }
        elif section == "references":
            content["sections"][section] = {
                "title": "References",
                "items": [{"title": e.title, "url": e.url} for e in entries],
            }
        elif section == "timeline":
            content["sections"][section] = {
                "title": "Timeline",
                "items": [
                    {
                        "date": e.published_at.isoformat() if e.published_at else None,
                        "title": e.title,
                    }
                    for e in entries
                ],
            }
        elif section == "aliases_attribution":
            content["sections"][section] = {
                "title": "Aliases & Attribution",
                "items": [
                    {
                        "name": a.name,
                        "aliases": a.aliases,
                        "country": a.country,
                        "motivation": a.motivation,
                    }
                    for a in actors
                ],
            }
        elif section == "vulnerability_highlights":
            content["sections"][section] = {
                "title": "Vulnerability Highlights",
                "items": [
                    {
                        "cve_id": c.cve_id,
                        "severity": c.severity,
                        "cvss_score": float(c.cvss_score) if c.cvss_score else None,
                        "description": c.description,
                    }
                    for c in cves
                ],
            }
        elif section == "notable_threats":
            content["sections"][section] = {
                "title": "Notable Threats",
                "items": [
                    {
                        "name": m.name,
                        "malware_type": m.malware_type,
                        "description": m.description,
                    }
                    for m in malware
                ],
            }
        elif section in ("observables", "iocs", "ioc_table"):
            # Judged ledger rows sighted in the report's sources, with their
            # attribution claims. Values render defanged; denied rows never
            # appear. Empty gets an honest note rather than a bare header.
            # ("iocs"/"ioc_table" are the same section under the names some DB
            # templates already use — country_threat_brief predates the ledger.)
            obs_items = await collect_report_observables(db, entry_ids, entity_ids)
            content["sections"][section] = {
                "title": "Observables" if section == "observables" else "Indicators of Compromise",
                "body": "" if obs_items else "No judged observables were captured from this report's sources.",
                "items": obs_items,
            }
        elif section == "detections":
            content["sections"][section] = _detections_section(rules)
        else:
            content["sections"][section] = {
                "title": section.replace("_", " ").title(),
                "body": "",
            }

    # Detections are evidence no template asks for by name: every template
    # predates rule attachment, so gating the section on the template's section
    # list would make attaching rules a silent no-op. The section appears when
    # — and only when — rules are actually attached.
    if rules and "detections" not in content["sections"]:
        content["sections"]["detections"] = _detections_section(rules)

    return content


def _detections_section(rules: list) -> dict:
    """The adopted-rule table: what you would deploy, and under whose licence.

    Attribution is not decoration here. These rules come from SigmaHQ, Elastic
    and Azure-Sentinel under DRL/Elastic/MIT terms, and a report that hands them
    on without naming the repo and licence is passing along someone else's work
    unattributed.
    """
    return {
        "title": "Detections",
        "body": "",
        "items": [
            {
                "rule_id": str(r.id),
                "rule_title": r.title,
                "rule_type": r.rule_type,
                "repo": (r.metadata_ or {}).get("repo") or "local",
                "license": r.license,
                "severity": r.severity,
                "is_draft": r.is_draft,
                "techniques": [t for t in (r.source_ttps or []) if isinstance(t, str)][:4],
            }
            for r in rules
        ],
    }


async def generate_section_content(
    db: AsyncSession,
    user_id: uuid.UUID,
    report,
    section_name: str,
    focus: str | None = None,
    audience: str | None = None,
) -> dict:
    """Generate AI prose for a specific section of an intel report.

    Returns {"content": "..."} or {"error": "..."}.
    """
    from app.ai.engine import run_task

    section_title = section_name.replace("_", " ").title()

    # Gather context from linked entries. source_reliability is the feed's
    # admiralty rating (A–F) so the AI can weigh sources when citing them.
    entries_context = []
    if report.entry_ids:
        result = await db.execute(
            select(
                Entry,
                Feed.title.label("feed_title"),
                Feed.reliability_rating.label("feed_reliability"),
            )
            .outerjoin(Feed, Feed.id == Entry.feed_id)
            .where(Entry.id.in_(report.entry_ids))
        )
        for entry, feed_title, feed_reliability in result.all():
            entries_context.append(
                {
                    "title": entry.title or "",
                    "feed_title": feed_title or "",
                    "source_reliability": feed_reliability or "unrated",
                    "published_at": entry.published_at.isoformat() if entry.published_at else "",
                    "content_text": entry.content_text or entry.summary_text or "",
                }
            )

    # Gather entity context
    entity_ids = report.entity_ids or {}

    ttps_context = []
    if entity_ids.get("ttps"):
        result = await db.execute(
            select(TTP).where(TTP.id.in_([uuid.UUID(i) if isinstance(i, str) else i for i in entity_ids["ttps"]]))
        )
        for ttp in result.scalars().all():
            ttps_context.append(
                {"technique_id": ttp.technique_id, "technique_name": ttp.technique_name, "tactic": ttp.tactic}
            )

    detections_context = []
    if entity_ids.get("detection_rules"):
        result = await db.execute(
            select(DetectionRule).where(
                DetectionRule.id.in_([uuid.UUID(i) if isinstance(i, str) else i for i in entity_ids["detection_rules"]])
            )
        )
        for rule in result.scalars().all():
            detections_context.append(
                {
                    "title": rule.title,
                    "rule_type": rule.rule_type,
                    "repo": (rule.metadata_ or {}).get("repo") or "local",
                    "license": rule.license,
                    "techniques": [t for t in (rule.source_ttps or []) if isinstance(t, str)][:4],
                }
            )

    cves_context = []
    if entity_ids.get("cves"):
        result = await db.execute(
            select(CVE).where(CVE.id.in_([uuid.UUID(i) if isinstance(i, str) else i for i in entity_ids["cves"]]))
        )
        for cve in result.scalars().all():
            cves_context.append(
                {
                    "cve_id": cve.cve_id,
                    "severity": cve.severity,
                    "cvss_score": float(cve.cvss_score) if cve.cvss_score else None,
                    "description": cve.description,
                }
            )

    actors_context = []
    if entity_ids.get("actors"):
        result = await db.execute(
            select(ThreatActor).where(
                ThreatActor.id.in_([uuid.UUID(i) if isinstance(i, str) else i for i in entity_ids["actors"]])
            )
        )
        for actor in result.scalars().all():
            actors_context.append(
                {
                    "name": actor.name,
                    "aliases": actor.aliases or [],
                    "country": actor.country,
                    "motivation": actor.motivation,
                }
            )

    malware_context = []
    if entity_ids.get("malware"):
        result = await db.execute(
            select(MalwareFamily).where(
                MalwareFamily.id.in_([uuid.UUID(i) if isinstance(i, str) else i for i in entity_ids["malware"]])
            )
        )
        for mal in result.scalars().all():
            malware_context.append({"name": mal.name, "malware_type": mal.malware_type, "description": mal.description})

    countries_context = []
    if entity_ids.get("countries"):
        result = await db.execute(
            select(Country).where(
                Country.id.in_([uuid.UUID(i) if isinstance(i, str) else i for i in entity_ids["countries"]])
            )
        )
        for country in result.scalars().all():
            countries_context.append({"name": country.name, "region": country.region, "role": None})

    # Judged indicators sighted in the report's sources, with attribution —
    # so prose sections can reference the infrastructure alongside the actors.
    observables_context = [
        {
            "kind": o["kind"],
            "value": o["value"],
            "role": o["role"],
            "confidence": o["confidence"],
            "claimed_by": o["claimed_by"],
        }
        for o in await collect_report_observables(db, report.entry_ids or [], entity_ids, limit=40)
    ]

    # Collect already-written sections for context
    existing_sections = {}
    content = report.content or {}
    for key, section in content.get("sections", {}).items():
        if key != section_name and isinstance(section, dict):
            body = section.get("body", "")
            if body:
                existing_sections[section.get("title", key)] = body

    # Call AI
    variables = {
        "section_name": section_name,
        "section_title": section_title,
        "template_type": report.template_type,
        "report_title": report.title,
        "existing_sections": existing_sections,
        "entries_context": entries_context,
        "ttps_context": ttps_context,
        "cves_context": cves_context,
        "actors_context": actors_context,
        "malware_context": malware_context,
        "countries_context": countries_context,
        "observables_context": observables_context,
        "detections_context": detections_context,
        "focus": focus or "",
        "audience": audience or "",
    }

    # Exposure reports carry their scope + curated surface into the prompt.
    metadata = content.get("metadata", {}) if isinstance(content, dict) else {}
    variables["profile_name"] = metadata.get("profile_name", "")
    variables["scope"] = metadata.get("scope", {})
    surface_section = content.get("sections", {}).get("threat_surface", {}) if isinstance(content, dict) else {}
    variables["threat_surface"] = (surface_section.get("items") or [])[:25]

    # Tailored prompt per report family (each editable in Settings > AI >
    # Prompts); the generic report_section task is the fallback for custom/DB
    # templates and for families whose tailored task has no assignment yet.
    task_name = REPORT_SECTION_TASKS.get(report.template_type, "report_section")
    result = await run_task(
        db=db,
        user_id=user_id,
        task_name=task_name,
        variables=variables,
        target_type="intel_report",
        target_id=report.id,
        force=True,
    )
    if result is None and task_name != "report_section":
        task_name = "report_section"
        result = await run_task(
            db=db,
            user_id=user_id,
            task_name=task_name,
            variables=variables,
            target_type="intel_report",
            target_id=report.id,
            force=True,
        )

    if result is None:
        return {"error": f"AI task '{task_name}' is not configured. Assign a provider and model in Settings > AI."}

    if isinstance(result, dict) and result.get("_extraction_status") in ("provider_error", "parse_error"):
        return {"error": result.get("_error", "AI generation failed")}

    generated = result.get("content", "") if isinstance(result, dict) else ""
    return {"content": generated}


def _obs_value_cell(item: dict) -> str:
    """A table-safe, share-safe rendering of an observable value: defanged for
    network kinds, code-quoted (values are attacker-controlled strings), pipes
    escaped so the table survives, long values clipped."""
    from app.intelligence.observables import defang

    value = defang(item.get("kind", ""), str(item.get("value", "")))
    if len(value) > 96:
        value = value[:93] + "..."
    value = value.replace("`", "'").replace("|", "\\|")
    label = item.get("label")
    prefix = f"{_escape_md(str(label))} — " if label and item.get("kind") == "script" else ""
    return f"{prefix}`{value}`"


def _render_observables_table(items: list[dict]) -> list[str]:
    lines = [
        "| Kind | Value (defanged) | Role | Confidence | Sightings | Last seen | Attribution |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for item in items:
        role_bits = [b for b in (item.get("role"), item.get("infra_tag") and f"infra: {item['infra_tag']}") if b]
        conf = item.get("confidence")
        conf_cell = f"{round(conf * 100)}%" if isinstance(conf, (int, float)) else ""
        status = item.get("status")
        if status and status != "active":
            conf_cell = f"{conf_cell} ({_escape_md(status)})".strip()
        claimed = "; ".join(_escape_md(c) for c in item.get("claimed_by") or [])
        lines.append(
            "| "
            + " | ".join(
                [
                    _escape_md(str(item.get("kind", ""))),
                    _obs_value_cell(item),
                    _escape_md(", ".join(str(b) for b in role_bits)),
                    conf_cell,
                    str(item.get("sightings", "") or ""),
                    _escape_md(str(item.get("last_seen") or "")),
                    claimed,
                ]
            )
            + " |"
        )
    return lines


def _render_threat_surface_table(items: list[dict]) -> list[str]:
    """Exposure-report threat surface as a markdown matrix."""
    lines = [
        "| Entity | Type | Regions | Verticals | Entries | Victims |",
        "|---|---|---|---|---:|---:|",
    ]
    for item in items:
        name = _escape_md(item.get("name", ""))
        etype = _escape_md((item.get("subtype") or item.get("entity_type") or "").replace("_", " "))
        regions = ", ".join(_escape_md(r) for r in item.get("matched_regions") or []) or "—"
        sectors = ", ".join(_escape_md(s) for s in item.get("matched_sectors") or []) or "—"
        victims = item.get("victim_count") or 0
        lines.append(
            f"| **{name}** | {etype} | {regions} | {sectors} | {item.get('entry_count', 0)} | {victims or '—'} |"
        )
    return lines


def _render_detections_table(items: list[dict]) -> list[str]:
    """Adopted rules as a markdown table, attribution included.

    Licence and source repo are columns rather than a footnote: the rules are
    other people's work, and a report that passes them on has to say whose.
    """
    lines = [
        "| Rule | Format | Source | Licence | ATT&CK |",
        "|---|---|---|---|---|",
    ]
    for item in items:
        title = _escape_md(item.get("rule_title", ""))
        draft = " *(draft)*" if item.get("is_draft") else ""
        fmt = _escape_md(item.get("rule_type", ""))
        repo = _escape_md(item.get("repo", "local"))
        licence = _escape_md(item.get("license") or "unstated")
        techniques = ", ".join(_escape_md(t) for t in item.get("techniques") or []) or "—"
        lines.append(f"| **{title}**{draft} | {fmt} | {repo} | {licence} | {techniques} |")
    return lines


def _escape_md(text: str) -> str:
    """Escape markdown metacharacters in user-supplied text to prevent injection."""
    if not text:
        return text
    # Escape characters that have special meaning in markdown
    for ch in ("\\", "`", "*", "_", "{", "}", "[", "]", "(", ")", "#", "+", "-", ".", "!", "|", "~"):
        text = text.replace(ch, f"\\{ch}")
    return text


def render_markdown(report) -> str:
    """Render an IntelReport to markdown."""
    lines = []

    # TLP banner
    lines.append(f"**{_escape_md(report.tlp_marking)}**")
    lines.append("")
    lines.append(f"# {_escape_md(report.title)}")
    lines.append("")

    if report.summary:
        lines.append(f"*{_escape_md(report.summary)}*")
        lines.append("")

    # Metadata
    lines.append(f"**Template:** {report.template_type.replace('_', ' ').title()}")
    lines.append(f"**Status:** {report.status.title()}")
    lines.append(f"**Version:** {report.version}")
    lines.append(f"**Created:** {report.created_at.strftime('%Y-%m-%d')}")
    if report.published_at:
        lines.append(f"**Published:** {report.published_at.strftime('%Y-%m-%d')}")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Sections — use template ordering if available, fall back to dict order
    content = report.content or {}
    sections = content.get("sections", {})
    template = REPORT_TEMPLATES.get(report.template_type)
    if template:
        ordered_keys = [s for s in template["sections"] if s in sections]
        # Append any extra sections not in the template
        ordered_keys += [k for k in sections if k not in ordered_keys]
    else:
        ordered_keys = list(sections.keys())
    for _key in ordered_keys:
        section = sections[_key]
        if isinstance(section, dict):
            body = section.get("body", "")
            # Only add a section header if the body doesn't already start with one
            if body and body.lstrip().startswith("## "):
                lines.append(body)
            else:
                title = _escape_md(section.get("title", _key.replace("_", " ").title()))
                lines.append(f"## {title}")
                lines.append("")
                if body:
                    lines.append(body)
            lines.append("")

            items = section.get("items") or []
            # Observables render as one table, not line items — kind + value
            # + confidence + attribution read side by side.
            if items and isinstance(items[0], dict) and "kind" in items[0] and "value" in items[0]:
                lines.extend(_render_observables_table(items))
                lines.append("")
                continue

            # Adopted rules render as one table: the format you would deploy in,
            # where it came from and under what terms, side by side.
            if items and isinstance(items[0], dict) and "rule_title" in items[0]:
                lines.extend(_render_detections_table(items))
                lines.append("")
                continue

            # Threat-surface rows (exposure reports) render as one matrix:
            # entity × matched regions/verticals with the evidence counts.
            if items and isinstance(items[0], dict) and "matched_regions" in items[0]:
                lines.extend(_render_threat_surface_table(items))
                lines.append("")
                continue

            if section.get("items"):
                for item in section["items"]:
                    if isinstance(item, dict):
                        if "technique_id" in item:
                            # TTP
                            lines.append(
                                f"- **{_escape_md(item.get('technique_id', ''))}** "
                                f"{_escape_md(item.get('name', ''))} "
                                f"({_escape_md(item.get('tactic', 'N/A'))})"
                            )
                        elif "title" in item and "url" in item:
                            # Reference
                            url = item.get("url", "")
                            lines.append(f"- [{_escape_md(item['title'])}]({url})")
                        elif "date" in item and "title" in item:
                            # Timeline
                            date = _escape_md(item.get("date", "Unknown"))
                            lines.append(f"- **{date}**: {_escape_md(item['title'])}")
                        elif "name" in item and "aliases" in item:
                            # Actor
                            aliases = ", ".join(_escape_md(a) for a in (item.get("aliases") or []))
                            lines.append(f"- **{_escape_md(item['name'])}** (aliases: {aliases})")
                        elif "cve_id" in item:
                            # CVE
                            severity = _escape_md(item.get("severity", "N/A"))
                            cvss = item.get("cvss_score", "N/A")
                            lines.append(f"- **{_escape_md(item['cve_id'])}** (Severity: {severity}, CVSS: {cvss})")
                        elif "name" in item and "malware_type" in item:
                            # Malware
                            mtype = _escape_md(item.get("malware_type", "Unknown"))
                            lines.append(f"- **{_escape_md(item['name'])}** ({mtype})")
                        else:
                            lines.append(f"- {_escape_md(str(item))}")
                lines.append("")

    # Tags
    if report.tags:
        lines.append("---")
        lines.append("")
        lines.append(f"**Tags:** {', '.join(_escape_md(t) for t in report.tags)}")
        lines.append("")

    lines.append("---")
    lines.append("*Generated by IntelFeed*")

    return "\n".join(lines)


def render_html(report) -> str:
    """Render an IntelReport to HTML using proper markdown conversion."""
    import html as html_module

    import markdown as md_lib

    md_text = render_markdown(report)
    body_html = md_lib.markdown(md_text, extensions=["tables", "fenced_code", "codehilite"])

    tlp_colors = {
        "TLP:CLEAR": "#ffffff",
        "TLP:GREEN": "#33ff00",
        "TLP:AMBER": "#ffc000",
        "TLP:AMBER+STRICT": "#ffc000",
        "TLP:RED": "#ff0033",
    }
    tlp_color = tlp_colors.get(report.tlp_marking, "#cccccc")

    return f"""<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<title>{html_module.escape(report.title)}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
       max-width: 800px; margin: 40px auto; padding: 0 20px; color: #1a1a1a; line-height: 1.6; }}
.tlp-banner {{ background: {tlp_color}; color: #000; padding: 8px 16px; font-weight: bold;
               text-align: center; margin-bottom: 24px; border-radius: 4px; }}
h1 {{ border-bottom: 2px solid #333; padding-bottom: 8px; }}
h2 {{ color: #2c3e50; margin-top: 32px; border-bottom: 1px solid #eee; padding-bottom: 4px; }}
h3 {{ color: #34495e; margin-top: 24px; }}
code {{ background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-size: 0.9em; }}
pre {{ background: #f8f9fa; padding: 16px; border-radius: 6px; overflow-x: auto; }}
pre code {{ background: none; padding: 0; }}
table {{ border-collapse: collapse; width: 100%; margin: 16px 0; }}
th, td {{ border: 1px solid #ddd; padding: 8px 12px; text-align: left; }}
th {{ background: #f8f9fa; font-weight: 600; }}
blockquote {{ border-left: 4px solid #ddd; margin: 16px 0; padding: 8px 16px; color: #555; }}
hr {{ border: none; border-top: 1px solid #ddd; margin: 24px 0; }}
a {{ color: #2563eb; }}
</style>
</head><body>
<div class="tlp-banner">{html_module.escape(report.tlp_marking)}</div>
{body_html}
</body></html>"""
