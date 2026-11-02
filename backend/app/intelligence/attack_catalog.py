"""MITRE ATT&CK catalog — STIX bundle parsing, hydration, and technique validation.

Hydrates the ttps/mitigations tables from the official attack-stix-data bundles
(Enterprise + Mobile + ICS) and validates extracted technique IDs against the
hydrated catalog:

- unknown IDs are dropped (no more `technique_name == technique_id` stub rows),
- revoked techniques map to their STIX-provided replacement,
- ICS (T0xxx) techniques are only accepted when the entry context looks ICS/OT
  related (configurable keyword heuristic).

Runs via scripts/seed/seed_mitre_attack.py (one-shot) and the weekly
mitre-attack-sync beat task (app.workers.enrichment_tasks.run_mitre_attack_sync).
"""

import logging
import re
import uuid
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.mitigation import Mitigation, TTPMitigation
from app.models.ttp import TTP

logger = logging.getLogger(__name__)

ATTACK_STIX_URLS: dict[str, str] = {
    "enterprise": (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data"
        "/refs/heads/master/enterprise-attack/enterprise-attack.json"
    ),
    "mobile": (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data"
        "/refs/heads/master/mobile-attack/mobile-attack.json"
    ),
    "ics": (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/ics-attack/ics-attack.json"
    ),
}

_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_MITIGATION_ID_RE = re.compile(r"^M\d{4}$")

# ATT&CK v17 moved detection guidance off attack-pattern. `x_mitre_data_sources`
# and `x_mitre_detection` no longer exist on technique objects; the same
# information now lives in x-mitre-detection-strategy objects (linked to
# techniques by `detects` relationships), each fanning out to x-mitre-analytic
# objects that name their log sources as `x_mitre_log_source_references`.
# Those names are channel-level ("WinEventLog:Sysmon", "auditd:SYSCALL"), which
# is a far better join key for telemetry feasibility than the old coarse
# "Process: Process Creation" data-source strings.
_DETECTION_TEXT_LIMIT = 4000


@dataclass
class ParsedBundle:
    """Catalog objects extracted from one ATT&CK STIX 2.1 domain bundle."""

    domain: str
    techniques: list[dict] = field(default_factory=list)
    mitigations: list[dict] = field(default_factory=list)
    # (mitigation mitre_id, technique_id) pairs from `mitigates` relationships
    mitigates: list[tuple[str, str]] = field(default_factory=list)
    # STIX intrusion-sets (kept so the sync task can map groups to threat actors)
    intrusion_sets: list[dict] = field(default_factory=list)
    # STIX software: stix_id -> {"kind": "malware"|"tool", "name", "aliases"}
    software: dict[str, dict] = field(default_factory=dict)
    # STIX id -> technique_id (attack-patterns), for `uses` edge resolution
    technique_stix: dict[str, str] = field(default_factory=dict)
    # curated `uses` relationships as (source_stix_ref, target_stix_ref)
    uses: list[tuple[str, str]] = field(default_factory=list)
    # technique_id -> {"data_sources": [...], "detection": str | None}, resolved
    # from the v17 detection-strategy / analytic objects
    detection_by_technique: dict[str, dict] = field(default_factory=dict)


def _mitre_external_ref(obj: dict) -> tuple[str | None, str | None]:
    """Return (external_id, url) from an object's mitre-attack external reference."""
    for ref in obj.get("external_references", []):
        source = ref.get("source_name")
        if source in ("mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"):
            return ref.get("external_id"), ref.get("url")
    return None, None


def _first_paragraph(text: str | None) -> str | None:
    if not text:
        return None
    return text.strip().split("\n\n")[0].strip() or None


def _analytic_log_sources(analytic: dict, data_components: dict[str, str]) -> list[str]:
    """Channel-level log-source names an analytic depends on.

    Prefers the reference's own `name` ("WinEventLog:Sysmon"); falls back to the
    referenced data component's display name when the reference is unnamed.
    """
    names: list[str] = []
    for ref in analytic.get("x_mitre_log_source_references") or []:
        if not isinstance(ref, dict):
            continue
        name = (ref.get("name") or "").strip()
        if not name:
            name = (data_components.get(ref.get("x_mitre_data_component_ref") or "") or "").strip()
        if name:
            names.append(name)
    return names


def _compose_detection_text(strategies: list[dict]) -> str | None:
    """Render detection strategies + their analytics as prose.

    Stands in for the retired `x_mitre_detection` field: one block per strategy,
    each listing the analytic guidance MITRE publishes under it.
    """
    blocks: list[str] = []
    for strategy in strategies:
        lines = [strategy["name"]] if strategy.get("name") else []
        for analytic in strategy.get("analytics") or []:
            body = (analytic.get("description") or "").strip()
            if body:
                lines.append(f"- {body}")
        if len(lines) > 1 or (lines and strategy.get("analytics")):
            blocks.append("\n".join(lines))
    if not blocks:
        return None
    text = "\n\n".join(blocks).strip()
    if len(text) > _DETECTION_TEXT_LIMIT:
        text = text[:_DETECTION_TEXT_LIMIT].rsplit("\n", 1)[0].rstrip() + "\n…"
    return text or None


def parse_attack_bundle(bundle: dict, domain: str) -> ParsedBundle:
    """Parse one ATT&CK STIX bundle into catalog technique/mitigation dicts.

    Revoked/deprecated techniques are KEPT (flagged) so extraction can map
    them to replacements; revoked/deprecated mitigations are skipped.
    """
    parsed = ParsedBundle(domain=domain)
    stix_to_technique: dict[str, str] = {}  # STIX id -> technique_id
    stix_to_mitigation: dict[str, str] = {}  # STIX id -> mitre M-id
    revoked_by: dict[str, str] = {}  # STIX id (old) -> STIX id (new)
    # v17 detection model: strategy -> analytics -> log sources
    data_components: dict[str, str] = {}  # STIX id -> component display name
    analytics: dict[str, dict] = {}  # STIX id -> raw analytic object
    strategies: dict[str, dict] = {}  # STIX id -> raw detection-strategy object

    objects = bundle.get("objects", [])

    for obj in objects:
        obj_type = obj.get("type")

        if obj_type == "attack-pattern":
            technique_id, mitre_url = _mitre_external_ref(obj)
            if not technique_id or not _TECHNIQUE_ID_RE.match(technique_id):
                continue
            stix_to_technique[obj["id"]] = technique_id
            tactics = [phase.get("phase_name") for phase in obj.get("kill_chain_phases", []) if phase.get("phase_name")]
            is_subtechnique = bool(obj.get("x_mitre_is_subtechnique")) or "." in technique_id
            parsed.techniques.append(
                {
                    "technique_id": technique_id,
                    "technique_name": obj.get("name") or technique_id,
                    "tactics": tactics,
                    "description": _first_paragraph(obj.get("description")),
                    "platforms": obj.get("x_mitre_platforms") or [],
                    # Legacy pre-v17 keys; empty on current bundles, where the
                    # detection-strategy pass below supplies both instead.
                    "data_sources": obj.get("x_mitre_data_sources") or [],
                    "detection": obj.get("x_mitre_detection"),
                    "mitre_url": mitre_url,
                    "is_subtechnique": is_subtechnique,
                    "parent_technique_id": technique_id.split(".")[0] if "." in technique_id else None,
                    "is_deprecated": bool(obj.get("x_mitre_deprecated")) or bool(obj.get("revoked")),
                    "superseded_by": None,  # filled from revoked-by relationships below
                    "matrix_domain": domain,
                    "_stix_id": obj["id"],
                }
            )

        elif obj_type == "course-of-action":
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue
            mitre_id, mitre_url = _mitre_external_ref(obj)
            if not mitre_id or not _MITIGATION_ID_RE.match(mitre_id):
                continue
            stix_to_mitigation[obj["id"]] = mitre_id
            parsed.mitigations.append(
                {
                    "mitre_id": mitre_id,
                    "name": obj.get("name") or mitre_id,
                    "description": obj.get("description"),
                    "mitre_url": mitre_url,
                }
            )

        elif obj_type == "intrusion-set" and not obj.get("revoked"):
            parsed.intrusion_sets.append(obj)

        elif obj_type in ("malware", "tool") and not obj.get("revoked") and not obj.get("x_mitre_deprecated"):
            name = obj.get("name")
            if name:
                software_id, _ = _mitre_external_ref(obj)
                parsed.software[obj["id"]] = {
                    "kind": obj_type,
                    "name": name,
                    "aliases": [a for a in obj.get("x_mitre_aliases", []) if isinstance(a, str) and a != name],
                    "description": _first_paragraph(obj.get("description")),
                    "platforms": [p for p in obj.get("x_mitre_platforms") or [] if isinstance(p, str)],
                    "mitre_id": software_id,
                }

        elif obj_type == "x-mitre-data-component":
            if obj.get("name"):
                data_components[obj["id"]] = obj["name"]

        elif obj_type == "x-mitre-analytic" and not obj.get("x_mitre_deprecated") and not obj.get("revoked"):
            analytics[obj["id"]] = obj

        elif obj_type == "x-mitre-detection-strategy" and not obj.get("x_mitre_deprecated") and not obj.get("revoked"):
            strategies[obj["id"]] = obj

        elif obj_type == "relationship":
            rel_type = obj.get("relationship_type")
            if rel_type == "revoked-by":
                revoked_by[obj.get("source_ref", "")] = obj.get("target_ref", "")
            elif rel_type == "uses" and not obj.get("revoked") and not obj.get("x_mitre_deprecated"):
                src, tgt = obj.get("source_ref", ""), obj.get("target_ref", "")
                if src and tgt:
                    parsed.uses.append((src, tgt))

    # Second pass over relationships now that STIX-id maps are complete
    strategies_by_technique: dict[str, list[dict]] = {}
    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        rel_type = obj.get("relationship_type")
        if rel_type == "mitigates":
            mitre_id = stix_to_mitigation.get(obj.get("source_ref", ""))
            technique_id = stix_to_technique.get(obj.get("target_ref", ""))
            if mitre_id and technique_id:
                parsed.mitigates.append((mitre_id, technique_id))
        elif rel_type == "detects" and not obj.get("revoked"):
            strategy = strategies.get(obj.get("source_ref", ""))
            technique_id = stix_to_technique.get(obj.get("target_ref", ""))
            if strategy and technique_id:
                strategies_by_technique.setdefault(technique_id, []).append(strategy)

    # Fold each technique's detection strategies into data_sources / detection.
    # Techniques with no strategy keep empty values rather than being wiped —
    # `hydrate_attack_catalog` only overwrites when the bundle has something.
    for technique_id, technique_strategies in strategies_by_technique.items():
        log_sources: list[str] = []
        rendered: list[dict] = []
        for strategy in technique_strategies:
            resolved_analytics = []
            for analytic_ref in strategy.get("x_mitre_analytic_refs") or []:
                analytic = analytics.get(analytic_ref)
                if not analytic:
                    continue
                resolved_analytics.append(analytic)
                log_sources.extend(_analytic_log_sources(analytic, data_components))
            rendered.append({"name": strategy.get("name"), "analytics": resolved_analytics})
        parsed.detection_by_technique[technique_id] = {
            "data_sources": sorted(set(log_sources)),
            "detection": _compose_detection_text(rendered),
        }

    for tech in parsed.techniques:
        derived = parsed.detection_by_technique.get(tech["technique_id"])
        if not derived:
            continue
        if derived["data_sources"]:
            tech["data_sources"] = derived["data_sources"]
        if derived["detection"]:
            tech["detection"] = derived["detection"]

    # Resolve revoked-by STIX refs to replacement technique IDs
    for tech in parsed.techniques:
        replacement_stix = revoked_by.get(tech.pop("_stix_id"))
        if replacement_stix:
            replacement_id = stix_to_technique.get(replacement_stix)
            if replacement_id and replacement_id != tech["technique_id"]:
                tech["superseded_by"] = replacement_id

    parsed.technique_stix = stix_to_technique
    return parsed


async def fetch_attack_bundles(db: AsyncSession, domains: list[str] | None = None) -> dict[str, dict]:
    """Download the official STIX bundles for the given domains through the
    mitre_attack source's gateway."""
    from app.enrichment.gateway import JOB_TOKEN_WAIT
    from app.enrichment.pipeline import gateway_for

    gateway, _ = await gateway_for(db, "mitre_attack", max_wait=JOB_TOKEN_WAIT)
    bundles: dict[str, dict] = {}
    async with gateway.client(timeout=180.0, follow_redirects=True) as client:
        for domain in domains or list(ATTACK_STIX_URLS):
            resp = await client.get(ATTACK_STIX_URLS[domain])
            resp.raise_for_status()
            bundles[domain] = resp.json()
    return bundles


async def hydrate_attack_catalog(db: AsyncSession, parsed_bundles: list[ParsedBundle]) -> dict:
    """Upsert parsed catalog data into ttps / mitigations / ttp_mitigations.

    Idempotent: keyed on technique_id / mitre_id, updates existing rows in
    place (this is what backfills stub rows created before validation existed).
    Catalog fields (name, tactics, platforms, …) are authoritative and always
    overwritten; description is only filled when empty so analyst/AI-written
    descriptions survive.
    """
    stats: dict[str, dict[str, int]] = {}

    ttp_rows = (await db.execute(select(TTP))).scalars().all()
    ttps_by_id = {t.technique_id: t for t in ttp_rows}
    mit_rows = (await db.execute(select(Mitigation).where(Mitigation.mitre_id.is_not(None)))).scalars().all()
    mits_by_id = {m.mitre_id: m for m in mit_rows}

    for parsed in parsed_bundles:
        domain_stats = {
            "techniques_created": 0,
            "techniques_updated": 0,
            "mitigations_created": 0,
            "mitigations_updated": 0,
            "ttp_mitigation_links": 0,
        }

        for tech in parsed.techniques:
            existing = ttps_by_id.get(tech["technique_id"])
            if existing:
                existing.technique_name = tech["technique_name"]
                existing.tactic = tech["tactics"][0] if tech["tactics"] else existing.tactic
                existing.tactics = tech["tactics"]
                if not existing.description and tech["description"]:
                    existing.description = tech["description"]
                existing.platforms = tech["platforms"]
                # Only overwrite when the bundle actually carries values, so a
                # domain bundle without detection strategies can't blank a
                # technique hydrated from one that has them.
                if tech["data_sources"]:
                    existing.data_sources = tech["data_sources"]
                if tech["detection"]:
                    existing.detection = tech["detection"]
                existing.mitre_url = tech["mitre_url"] or existing.mitre_url
                existing.is_subtechnique = tech["is_subtechnique"]
                existing.parent_technique_id = tech["parent_technique_id"]
                existing.is_deprecated = tech["is_deprecated"]
                existing.superseded_by = tech["superseded_by"]
                existing.matrix_domain = tech["matrix_domain"]
                domain_stats["techniques_updated"] += 1
            else:
                ttp = TTP(
                    id=uuid.uuid4(),
                    technique_id=tech["technique_id"],
                    technique_name=tech["technique_name"],
                    tactic=tech["tactics"][0] if tech["tactics"] else None,
                    tactics=tech["tactics"],
                    description=tech["description"],
                    platforms=tech["platforms"],
                    data_sources=tech["data_sources"],
                    detection=tech["detection"],
                    mitre_url=tech["mitre_url"],
                    is_subtechnique=tech["is_subtechnique"],
                    parent_technique_id=tech["parent_technique_id"],
                    is_deprecated=tech["is_deprecated"],
                    superseded_by=tech["superseded_by"],
                    matrix_domain=tech["matrix_domain"],
                    article_count=0,
                )
                db.add(ttp)
                ttps_by_id[tech["technique_id"]] = ttp
                domain_stats["techniques_created"] += 1

        for mit in parsed.mitigations:
            existing_mit = mits_by_id.get(mit["mitre_id"])
            if existing_mit:
                existing_mit.name = mit["name"]
                if not existing_mit.description and mit["description"]:
                    existing_mit.description = mit["description"]
                existing_mit.mitre_url = mit["mitre_url"] or existing_mit.mitre_url
                domain_stats["mitigations_updated"] += 1
            else:
                new_mit = Mitigation(
                    id=uuid.uuid4(),
                    mitre_id=mit["mitre_id"],
                    name=mit["name"],
                    description=mit["description"],
                    mitre_url=mit["mitre_url"],
                    article_count=0,
                )
                db.add(new_mit)
                mits_by_id[mit["mitre_id"]] = new_mit
                domain_stats["mitigations_created"] += 1

        # Flush so newly created rows have IDs before linking
        await db.flush()

        for mitre_id, technique_id in parsed.mitigates:
            ttp = ttps_by_id.get(technique_id)
            mitigation = mits_by_id.get(mitre_id)
            if not ttp or not mitigation:
                continue
            result = await db.execute(
                pg_insert(TTPMitigation)
                .values(ttp_id=ttp.id, mitigation_id=mitigation.id)
                .on_conflict_do_nothing()
                .returning(TTPMitigation.ttp_id)
            )
            if result.scalar_one_or_none():
                domain_stats["ttp_mitigation_links"] += 1

        stats[parsed.domain] = domain_stats

    await db.flush()
    return stats


async def sync_attack_relationships(db: AsyncSession, parsed_bundles: list[ParsedBundle]) -> dict:
    """Import MITRE's curated `uses` relationships as trusted typed edges.

    Maps STIX intrusion-sets / malware / tools / attack-patterns onto EXISTING
    entities only (never creates any), translates each edge through the
    semantic matrix, and upserts EntityRelationship rows with
    source='external_feed', confidence='confirmed'. Existing machine rows for
    the same triple are upgraded in place (evidence kept); analyst_rejected
    rows are never resurrected. Idempotent — safe to re-run weekly.
    """
    from app.intelligence.entity_dedup import find_entity_by_name_or_alias
    from app.intelligence.relationship_matrix import is_allowed_relationship
    from app.models.entity_relationship import EntityRelationship
    from app.models.malware_family import MalwareFamily
    from app.models.threat_actor import ThreatActor
    from app.models.tool import Tool

    # STIX verb → our verb, per (source kind, target kind). Tools relate to
    # techniques (the matrix reserves `uses` for operators), everything else
    # keeps MITRE's `uses`.
    verb_for = {
        ("intrusion-set", "malware"): ("threat_actor", "uses", "malware"),
        ("intrusion-set", "tool"): ("threat_actor", "uses", "tool"),
        ("intrusion-set", "attack-pattern"): ("threat_actor", "uses", "ttp"),
        ("malware", "attack-pattern"): ("malware", "uses", "ttp"),
        ("tool", "attack-pattern"): ("tool", "related_to", "ttp"),
    }

    # Resolve every referenced STIX object to an existing entity id, once.
    resolved: dict[str, tuple[str, str, uuid.UUID] | None] = {}  # stix_id -> (stix_kind, etype, id)

    ttp_rows = (await db.execute(select(TTP.technique_id, TTP.id))).all()
    ttp_by_technique = {row[0]: row[1] for row in ttp_rows}

    async def _resolve(stix_id: str, parsed: ParsedBundle) -> tuple[str, str, uuid.UUID] | None:
        if stix_id in resolved:
            return resolved[stix_id]
        out: tuple[str, str, uuid.UUID] | None = None
        if stix_id.startswith("intrusion-set--"):
            obj = next((o for o in parsed.intrusion_sets if o.get("id") == stix_id), None)
            if obj:
                actor = await find_entity_by_name_or_alias(db, ThreatActor, obj.get("name"), obj.get("aliases", []))
                if actor:
                    out = ("intrusion-set", "threat_actor", actor.id)
        elif stix_id.startswith("attack-pattern--"):
            technique_id = parsed.technique_stix.get(stix_id)
            ttp_id = ttp_by_technique.get(technique_id) if technique_id else None
            if ttp_id:
                out = ("attack-pattern", "ttp", ttp_id)
        elif stix_id in parsed.software:
            sw = parsed.software[stix_id]
            model = MalwareFamily if sw["kind"] == "malware" else Tool
            entity = await find_entity_by_name_or_alias(db, model, sw["name"], sw["aliases"])
            if entity:
                out = (sw["kind"], "malware" if sw["kind"] == "malware" else "tool", entity.id)
        resolved[stix_id] = out
        return out

    stats = {"created": 0, "upgraded": 0, "unchanged": 0, "unresolved": 0, "skipped": 0}
    seen_triples: set[tuple[str, uuid.UUID, str, uuid.UUID, str]] = set()

    # Pass 1: resolve every edge to a concrete triple.
    triples: list[tuple[str, uuid.UUID, str, uuid.UUID, str]] = []
    for parsed in parsed_bundles:
        for src_ref, tgt_ref in parsed.uses:
            src = await _resolve(src_ref, parsed)
            tgt = await _resolve(tgt_ref, parsed)
            if not src or not tgt:
                stats["unresolved"] += 1
                continue
            mapping = verb_for.get((src[0], tgt[0]))
            if not mapping or not is_allowed_relationship(*mapping):
                stats["skipped"] += 1
                continue
            src_type, verb, tgt_type = mapping
            triple = (src_type, src[2], tgt_type, tgt[2], verb)
            if triple in seen_triples:  # domains overlap (enterprise + mobile)
                continue
            seen_triples.add(triple)
            triples.append(triple)

    # Pass 2: prefetch existing rows in chunks instead of one SELECT per edge
    # (enterprise ATT&CK alone carries ~16k resolvable uses edges).
    from sqlalchemy import tuple_ as sa_tuple

    existing_by_triple: dict[tuple, EntityRelationship] = {}
    for i in range(0, len(triples), 500):
        chunk = triples[i : i + 500]
        rows = await db.execute(
            select(EntityRelationship).where(
                sa_tuple(
                    EntityRelationship.source_type,
                    EntityRelationship.source_id,
                    EntityRelationship.target_type,
                    EntityRelationship.target_id,
                    EntityRelationship.relationship_type,
                ).in_(chunk)
            )
        )
        for rel in rows.scalars().all():
            existing_by_triple[
                (rel.source_type, rel.source_id, rel.target_type, rel.target_id, rel.relationship_type)
            ] = rel

    # Pass 3: upsert.
    for triple in triples:
        src_type, src_id, tgt_type, tgt_id, verb = triple
        existing = existing_by_triple.get(triple)
        if existing is not None:
            if existing.source == "analyst_rejected":
                stats["skipped"] += 1
                continue
            changed = False
            if existing.confidence != "confirmed":
                existing.confidence = "confirmed"
                changed = True
            if existing.source in ("co_occurrence", "auto_extracted"):
                existing.source = "external_feed"
                changed = True
            if not existing.description:
                existing.description = "MITRE ATT&CK"
                changed = True
            # Authority supersedes the AI adjudicator: a MITRE-curated edge
            # can't stay marked coincidental (contradictory provenance).
            if existing.adjudication_verdict is not None:
                existing.adjudication_verdict = None
                existing.adjudicated_at = None
                changed = True
            stats["upgraded" if changed else "unchanged"] += 1
        else:
            db.add(
                EntityRelationship(
                    source_type=src_type,
                    source_id=src_id,
                    target_type=tgt_type,
                    target_id=tgt_id,
                    relationship_type=verb,
                    confidence="confirmed",
                    source="external_feed",
                    description="MITRE ATT&CK",
                    evidence_entry_ids=[],
                )
            )
            stats["created"] += 1

    await db.flush()
    return stats


async def refresh_attack_catalog(db: AsyncSession, domains: list[str] | None = None) -> dict:
    """Download all ATT&CK domain bundles and hydrate the catalog. Commits."""
    bundles = await fetch_attack_bundles(db, domains)
    parsed = [parse_attack_bundle(bundle, domain) for domain, bundle in bundles.items()]
    stats = await hydrate_attack_catalog(db, parsed)
    stats["entity_attributes"] = await hydrate_attack_entity_attributes(db, parsed)
    await db.commit()
    logger.info("ATT&CK catalog hydration stats: %s", stats)
    return stats


# --- Extraction validation ---------------------------------------------------


def _get_ics_keywords() -> list[str]:
    """ICS/OT context keywords (DB-overridable setting, defaults in config.py)."""
    raw = str(settings.get("attack_ics_context_keywords") or "")
    return [k.strip().lower() for k in raw.split(",") if k.strip()]


def is_ics_context(text: str | None) -> bool:
    """Heuristic: does the entry text look ICS/OT related?

    Keywords match on word boundaries so short tokens like "ot" don't fire
    inside ordinary words.
    """
    if not text:
        return False
    lowered = text.lower()
    for keyword in _get_ics_keywords():
        if re.search(rf"(?<![a-z0-9]){re.escape(keyword)}(?![a-z0-9])", lowered):
            return True
    return False


async def catalog_is_hydrated(db: AsyncSession) -> bool:
    """True once the ATT&CK catalog has been hydrated at least once."""
    result = await db.execute(select(TTP.id).where(TTP.matrix_domain.is_not(None)).limit(1))
    return result.scalar_one_or_none() is not None


async def resolve_technique_ids(
    db: AsyncSession,
    technique_ids: list[str],
    context_text: str | None = None,
) -> dict[str, str | None]:
    """Validate technique IDs against the hydrated catalog.

    Returns {candidate_id: resolved_id | None}:
    - unknown IDs resolve to None (drop),
    - revoked techniques resolve to their replacement when STIX provides one,
    - ICS-domain techniques resolve to None unless the context looks ICS/OT.

    Fallback: if the catalog has never been hydrated, every ID passes through
    unchanged (pre-hydration installs keep the old behavior).
    """
    if not technique_ids:
        return {}

    if not await catalog_is_hydrated(db):
        logger.warning(
            "ATT&CK catalog not hydrated — skipping technique validation "
            "(run scripts/seed/seed_mitre_attack.py or the mitre-attack-sync task)"
        )
        return {tid: tid for tid in technique_ids}

    # One indexed query covers candidates plus any replacement targets.
    async def _load(ids: set[str]) -> dict[str, TTP]:
        result = await db.execute(select(TTP).where(TTP.technique_id.in_(ids), TTP.matrix_domain.is_not(None)))
        return {t.technique_id: t for t in result.scalars().all()}

    rows = await _load(set(technique_ids))
    replacements = {t.superseded_by for t in rows.values() if t.superseded_by} - set(rows.keys())
    if replacements:
        rows.update(await _load(replacements))

    ics_ok: bool | None = None  # lazy — only evaluate keywords when needed
    resolved: dict[str, str | None] = {}
    for tid in technique_ids:
        row = rows.get(tid)
        if row is None:
            logger.debug("Dropping unknown ATT&CK technique id: %s", tid)
            resolved[tid] = None
            continue
        # Follow revoked -> replacement (single hop; ATT&CK chains are 1 deep)
        if row.superseded_by and rows.get(row.superseded_by) is not None:
            row = rows[row.superseded_by]
        if row.matrix_domain == "ics":
            if ics_ok is None:
                ics_ok = is_ics_context(context_text)
            if not ics_ok:
                logger.debug("Dropping ICS technique %s — entry context is not ICS/OT", tid)
                resolved[tid] = None
                continue
        resolved[tid] = row.technique_id
    return resolved


async def hydrate_attack_entity_attributes(db: AsyncSession, parsed_bundles: list[ParsedBundle]) -> dict:
    """Fill blank profile fields on existing actors / malware / tools from ATT&CK.

    The bundle carries a name, alias list, description, platform list and
    external ID for every intrusion-set, malware and tool object MITRE tracks.
    Until now those objects were parsed only to resolve relationship edges
    (:func:`sync_attack_relationships`), so none of it ever reached the profile
    columns the workbench renders.

    Matches EXISTING entities only — never creates one, so the entity-creation
    gates stay the single door for new rows. Fill-blanks-only: an analyst- or
    AI-written description, a curated alias list, or a manually set type all
    survive a re-run. Aliases are unioned rather than replaced.
    """
    from app.intelligence.autolinker import filter_aliases
    from app.intelligence.entity_dedup import find_entity_by_name_or_alias
    from app.models.malware_family import MalwareFamily
    from app.models.threat_actor import ThreatActor
    from app.models.tool import Tool

    stats = {
        "threat_actor_matched": 0,
        "threat_actor_updated": 0,
        "malware_matched": 0,
        "malware_updated": 0,
        "tool_matched": 0,
        "tool_updated": 0,
        "unmatched": 0,
    }

    def _fill(entity, field: str, value) -> bool:
        """Set ``field`` only when the entity has nothing there."""
        if not value or not hasattr(entity, field):
            return False
        if getattr(entity, field):
            return False
        setattr(entity, field, value)
        return True

    def _merge_aliases(entity, incoming: list[str]) -> bool:
        """Union incoming aliases in, case-insensitively, keeping stored order.

        Runs the junk-alias filter first — these lists feed the autolinker
        vocabulary, so an unfiltered dictionary word here becomes a false-positive
        entry link everywhere.
        """
        if not incoming:
            return False
        name = entity.name or ""
        existing = list(entity.aliases or [])
        seen = {a.casefold() for a in existing} | {name.casefold()}
        added = [a for a in filter_aliases(incoming, name) if a.casefold() not in seen and not seen.add(a.casefold())]
        if not added:
            return False
        entity.aliases = existing + added
        return True

    # One STIX object can appear in several domain bundles (e.g. a group present
    # in both enterprise and mobile) — apply each canonical name once.
    seen_groups: set[str] = set()
    seen_software: set[str] = set()

    for parsed in parsed_bundles:
        for obj in parsed.intrusion_sets:
            name = (obj.get("name") or "").strip()
            if not name or name.casefold() in seen_groups:
                continue
            seen_groups.add(name.casefold())
            aliases = [a for a in obj.get("aliases") or [] if isinstance(a, str) and a != name]
            actor = await find_entity_by_name_or_alias(db, ThreatActor, name, aliases)
            if not actor:
                stats["unmatched"] += 1
                continue
            stats["threat_actor_matched"] += 1
            group_id, _ = _mitre_external_ref(obj)
            changed = _fill(actor, "mitre_id", group_id)
            changed |= _fill(actor, "description", _first_paragraph(obj.get("description")))
            changed |= _merge_aliases(actor, aliases)
            if changed:
                db.add(actor)
                stats["threat_actor_updated"] += 1

        for sw in parsed.software.values():
            key = f"{sw['kind']}:{sw['name'].casefold()}"
            if key in seen_software:
                continue
            seen_software.add(key)
            is_malware = sw["kind"] == "malware"
            model = MalwareFamily if is_malware else Tool
            entity = await find_entity_by_name_or_alias(db, model, sw["name"], sw["aliases"])
            bucket = "malware" if is_malware else "tool"
            if not entity:
                stats["unmatched"] += 1
                continue
            stats[f"{bucket}_matched"] += 1
            changed = _fill(entity, "mitre_id", sw.get("mitre_id"))
            changed |= _fill(entity, "description", sw.get("description"))
            # Only tools carry a platforms column; malware platforms are dropped.
            changed |= _fill(entity, "platforms", sw.get("platforms"))
            changed |= _merge_aliases(entity, sw["aliases"])
            if changed:
                db.add(entity)
                stats[f"{bucket}_updated"] += 1

    await db.flush()
    return stats
