"""Entity indexer — syncs intelligence entities to Meilisearch indexes."""

import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.country import Country
from app.models.cve import CVE
from app.models.cwe import CWE
from app.models.detection_rule import DetectionRule
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.mitigation import Mitigation
from app.models.observable import Observable
from app.models.product import EntryProduct, Product
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.tool import EntryTool, Tool
from app.models.ttp import TTP
from app.models.vendor import EntryVendor, Vendor
from app.services.detection_coverage import telemetry_tokens_from_rule
from app.services.meilisearch_client import _ensure_entity_indexes, bulk_index_entities

logger = logging.getLogger(__name__)


def _cve_to_doc(cve: CVE) -> dict:
    return {
        "id": str(cve.id),
        "cve_id": cve.cve_id,
        "description": (cve.description or "")[:5000],
        "severity": cve.severity or "",
        "first_seen_at": cve.first_seen_at.isoformat() if cve.first_seen_at else "",
        "entity_type": "cve",
    }


def _cwe_to_doc(cwe: CWE) -> dict:
    return {
        "id": str(cwe.id),
        "cwe_id": cwe.cwe_id,
        "name": cwe.name,
        "alternate_terms": ", ".join(cwe.alternate_terms) if cwe.alternate_terms else "",
        "description": (cwe.description or "")[:5000],
        "abstraction": cwe.abstraction or "",
        "kind": cwe.kind,
        "mapping_usage": cwe.mapping_usage or "",
        "is_deprecated": bool(cwe.is_deprecated),
        "article_count": cwe.article_count or 0,
        "first_seen_at": cwe.first_seen_at.isoformat() if cwe.first_seen_at else "",
        "last_seen_at": cwe.last_seen_at.isoformat() if cwe.last_seen_at else "",
        "entity_type": "cwe",
    }


def _observable_to_doc(obs) -> dict:
    return {
        "id": str(obs.id),
        "value": obs.value,
        "label": obs.label or "",
        "kind": obs.kind,
        "role": obs.role or "",
        "status": obs.status or "",
        "created_via": obs.created_via or "",
        "infra_tag": obs.infra_tag or "",
        "current_confidence": float(obs.current_confidence or 0.0),
        "sighting_count": obs.sighting_count or 0,
        "article_count": obs.article_count or 0,
        "first_seen_at": obs.first_seen_at.isoformat() if obs.first_seen_at else "",
        "last_seen_at": obs.last_seen_at.isoformat() if obs.last_seen_at else "",
        "entity_type": "observable",
    }


def _ttp_to_doc(ttp: TTP) -> dict:
    return {
        "id": str(ttp.id),
        "technique_id": ttp.technique_id,
        "technique_name": ttp.technique_name or "",
        "tactic": ttp.tactic or "",
        "article_count": ttp.article_count or 0,
        "first_seen_at": ttp.first_seen_at.isoformat() if ttp.first_seen_at else "",
        "last_seen_at": ttp.last_seen_at.isoformat() if ttp.last_seen_at else "",
        "entity_type": "ttp",
    }


def _actor_to_doc(actor: ThreatActor) -> dict:
    return {
        "id": str(actor.id),
        "name": actor.name,
        "aliases": ", ".join(actor.aliases) if actor.aliases else "",
        "country": actor.country or "",
        "motivation": actor.motivation or "",
        "article_count": actor.article_count or 0,
        "first_seen_at": actor.first_seen_at.isoformat() if actor.first_seen_at else "",
        "last_seen_at": actor.last_seen_at.isoformat() if actor.last_seen_at else "",
        "entity_type": "threat_actor",
    }


def _malware_to_doc(malware: MalwareFamily) -> dict:
    return {
        "id": str(malware.id),
        "name": malware.name,
        "aliases": ", ".join(malware.aliases) if malware.aliases else "",
        "malware_type": malware.malware_type or "",
        "article_count": malware.article_count or 0,
        "first_seen_at": malware.first_seen_at.isoformat() if malware.first_seen_at else "",
        "last_seen_at": malware.last_seen_at.isoformat() if malware.last_seen_at else "",
        "entity_type": "malware",
    }


def _country_to_doc(country: Country) -> dict:
    return {
        "id": str(country.id),
        "name": country.name,
        "aliases": ", ".join(country.aliases) if country.aliases else "",
        "iso_code": country.iso_code or "",
        "region": country.region or "",
        "article_count": country.article_count or 0,
        "first_seen_at": country.first_seen_at.isoformat() if country.first_seen_at else "",
        "last_seen_at": country.last_seen_at.isoformat() if country.last_seen_at else "",
        "entity_type": "country",
    }


def _mitigation_to_doc(m: Mitigation) -> dict:
    return {
        "id": str(m.id),
        "name": m.name,
        "mitre_id": m.mitre_id or "",
        "description": (m.description or "")[:5000],
        "cis_controls": ", ".join(m.cis_controls) if m.cis_controls else "",
        "nist_controls": ", ".join(m.nist_controls) if m.nist_controls else "",
        "article_count": m.article_count or 0,
        "first_seen_at": m.first_seen_at.isoformat() if m.first_seen_at else "",
        "last_seen_at": m.last_seen_at.isoformat() if m.last_seen_at else "",
        "entity_type": "mitigation",
    }


def _tool_to_doc(tool: Tool) -> dict:
    return {
        "id": str(tool.id),
        "name": tool.name,
        "aliases": ", ".join(tool.aliases) if tool.aliases else "",
        "tool_type": tool.tool_type or "",
        "description": (tool.description or "")[:5000],
        "article_count": tool.article_count or 0,
        "first_seen_at": tool.first_seen_at.isoformat() if tool.first_seen_at else "",
        "last_seen_at": tool.last_seen_at.isoformat() if tool.last_seen_at else "",
        "entity_type": "tool",
    }


def _epoch(dt) -> int | None:
    """Meili sorts and range-filters numerically; ISO strings would sort as text."""
    return int(dt.timestamp()) if dt else None


# Entities a rule borrows from its entry: (junction, junction FK, model, doc key).
# Rules carry no columns for these; the entry they hang off is autolinked, and
# that is what lets "APT33" or "Fortinet" in the library box filter the list.
_RULE_BORROWED_ENTITIES = [
    (EntryThreatActor, "threat_actor_id", ThreatActor, "actors"),
    (EntryMalware, "malware_family_id", MalwareFamily, "malware"),
    (EntryTool, "tool_id", Tool, "tools"),
    (EntryVendor, "vendor_id", Vendor, "vendors"),
    (EntryProduct, "product_id", Product, "products"),
]

_BORROWED_KEYS = [key for *_, key in _RULE_BORROWED_ENTITIES]


async def _rule_entity_links(db: AsyncSession, entry_ids: list) -> dict:
    """{entry_id: {"actors": [...], "vendors": [...], ...}} for a batch of entries."""
    ids = [e for e in entry_ids if e]
    if not ids:
        return {}
    out: dict = {}
    for junction, fk, model, key in _RULE_BORROWED_ENTITIES:
        rows = await db.execute(
            select(junction.entry_id, model.name)
            .join(model, model.id == getattr(junction, fk))
            .where(junction.entry_id.in_(ids))
        )
        for entry_id, name in rows.all():
            out.setdefault(entry_id, {k: [] for k in _BORROWED_KEYS})[key].append(name)
    return out


def _rule_to_doc(rule: DetectionRule, links: dict | None = None) -> dict:
    meta = rule.metadata_ or {}
    # `source_products` and `source_cves` are JSONB and have historically held
    # both bare strings and {name: ...} objects; flatten to strings so the facet
    # distribution has one value per product rather than a mix of shapes.
    products = [p.get("name") if isinstance(p, dict) else p for p in (rule.source_products or [])]
    cves = [c.get("cve_id") if isinstance(c, dict) else c for c in (rule.source_cves or [])]
    products = [str(p) for p in products if p]
    cves = [str(c) for c in cves if c]
    techniques = [t.get("technique_id") if isinstance(t, dict) else t for t in (rule.source_ttps or [])]
    techniques = [str(t) for t in techniques if t]
    entity = (links or {}).get(rule.entry_id) or {}
    return {
        "id": str(rule.id),
        "title": rule.title,
        "description": (rule.description or "")[:5000],
        # The detection logic itself. Capped at 50k chars, which keeps 97.5% of
        # the corpus whole and truncates 4 outliers (one 295k YARA bundle)
        # rather than letting them dominate index build time.
        "rule_content": (rule.rule_content or "")[:50_000],
        "tags": list(rule.tags or []),
        "rule_type": rule.rule_type,
        "severity": rule.severity or "",
        "is_draft": bool(rule.is_draft),
        "source_repo": meta.get("repo") or "",
        "source_author": meta.get("commit_author") or meta.get("owner") or "",
        "license": rule.license or "",
        # Derived in Postgres as "no repo in metadata"; precomputed here because
        # Meili cannot express "attribute is absent" as a filter.
        "authored_local": not bool(meta.get("repo")),
        "mitre_tactics": list(rule.mitre_tactics or []),
        "data_sources": list(rule.data_sources or []),
        # What the rule actually needs to fire, across every format: data_sources
        # where declared, else the Sigma log_source triple / the per-format
        # defaults. Indexed so "runnable on my telemetry" can be a filter rather
        # than a post-hydration pass over one page of hits. The verdict itself is
        # NOT indexed — it is computed per request against the live inventory, so
        # ticking a telemetry source changes the answer without a reindex.
        "telemetry_tokens": telemetry_tokens_from_rule(rule),
        "source_products": products,
        "source_cves": cves,
        "has_cve": bool(cves),
        "techniques": techniques,
        # Borrowed from the rule's entry — see _rule_entity_links.
        **{key: sorted(set(entity.get(key) or [])) for key in _BORROWED_KEYS},
        "entry_id": str(rule.entry_id) if rule.entry_id else "",
        "created_at": _epoch(rule.created_at),
        "updated_at": _epoch(rule.updated_at),
        "upstream_updated_at": _epoch(rule.upstream_updated_at),
    }


async def _sync_entity_type(
    db: AsyncSession,
    model,
    index_name: str,
    converter,
    label: str,
    batch_size: int = 500,
) -> int:
    total = 0
    stmt = select(model).execution_options(yield_per=batch_size)
    result = await db.stream_scalars(stmt)
    async for partition in result.partitions(batch_size):
        docs = [converter(row) for row in partition]
        bulk_index_entities(index_name, docs)
        total += len(docs)
    logger.info("Indexed %d %s to Meilisearch", total, label)
    return total


async def sync_rules(db: AsyncSession, batch_size: int = 500) -> int:
    """Full rule sync. Separate from _sync_entity_type because each batch needs a
    second query to resolve the entities its rules borrow from their entries."""
    total = 0
    stmt = select(DetectionRule).execution_options(yield_per=batch_size)
    result = await db.stream_scalars(stmt)
    async for partition in result.partitions(batch_size):
        links = await _rule_entity_links(db, [r.entry_id for r in partition])
        bulk_index_entities("rules", [_rule_to_doc(r, links) for r in partition])
        total += len(partition)
    logger.info("Indexed %d detection rules to Meilisearch", total)
    return total


async def index_rules(db: AsyncSession, rules: list[DetectionRule]) -> None:
    """Index a batch of rules after a write.

    Re-selects the rows first. `created_at`/`updated_at` are server-generated
    (`server_default` / `onupdate`), so flush() expires them; reading one off the
    passed-in instance would attempt sync IO inside the async session and raise
    MissingGreenlet. One select refreshes the whole batch, and one more pair
    resolves the entity links — three queries regardless of batch size.
    """
    ids = [r.id for r in rules if r.id is not None]
    if not ids:
        return
    # Best effort, like index_entity/delete_entity: a search-index hiccup must
    # not fail the write that triggered it. Drift is healed by sync_rules.
    try:
        rows = (await db.execute(select(DetectionRule).where(DetectionRule.id.in_(ids)))).scalars().all()
        if not rows:
            return
        links = await _rule_entity_links(db, [r.entry_id for r in rows])
        bulk_index_entities("rules", [_rule_to_doc(r, links) for r in rows])
    except Exception as e:
        logger.warning("Failed to index %d rule(s): %s", len(ids), e)


async def index_rule(db: AsyncSession, rule: DetectionRule) -> None:
    """Index one rule after create/update. See index_rules for the reload."""
    await index_rules(db, [rule])


async def sync_all_entities(db: AsyncSession) -> dict[str, int]:
    """Full sync of all entity types to Meilisearch indexes.

    Streams rows in partitions so memory stays bounded — a full CVE sync
    otherwise materializes 30k+ ORM rows plus matching dicts in a single worker.
    """
    _ensure_entity_indexes()
    return {
        "cve": await _sync_entity_type(db, CVE, "entities_cve", _cve_to_doc, "CVEs"),
        "cwe": await _sync_entity_type(db, CWE, "entities_cwe", _cwe_to_doc, "weaknesses"),
        "ttp": await _sync_entity_type(db, TTP, "entities_ttp", _ttp_to_doc, "TTPs"),
        "threat_actor": await _sync_entity_type(
            db, ThreatActor, "entities_threat_actor", _actor_to_doc, "threat actors"
        ),
        "malware": await _sync_entity_type(db, MalwareFamily, "entities_malware", _malware_to_doc, "malware families"),
        "country": await _sync_entity_type(db, Country, "entities_country", _country_to_doc, "countries"),
        "mitigation": await _sync_entity_type(db, Mitigation, "entities_mitigation", _mitigation_to_doc, "mitigations"),
        "tool": await _sync_entity_type(db, Tool, "entities_tool", _tool_to_doc, "tools"),
        "observable": await _sync_entity_type(db, Observable, "entities_observable", _observable_to_doc, "observables"),
        "rule": await sync_rules(db),
    }


# Index name, model and doc converter per entity slug. Drives both the
# single-entity and the by-id batch path; detection rules are absent because
# their doc needs the extra entity-link query sync_rules/index_rules do.
_INDEX_BY_TYPE: dict[str, tuple[str, type, object]] = {
    "cve": ("entities_cve", CVE, _cve_to_doc),
    "cwe": ("entities_cwe", CWE, _cwe_to_doc),
    "ttp": ("entities_ttp", TTP, _ttp_to_doc),
    "threat_actor": ("entities_threat_actor", ThreatActor, _actor_to_doc),
    "malware": ("entities_malware", MalwareFamily, _malware_to_doc),
    "country": ("entities_country", Country, _country_to_doc),
    "mitigation": ("entities_mitigation", Mitigation, _mitigation_to_doc),
    "tool": ("entities_tool", Tool, _tool_to_doc),
    "observable": ("entities_observable", Observable, _observable_to_doc),
}


async def index_single_entity(entity_type: str, entity) -> None:
    """Index a single entity after creation or update."""
    spec = _INDEX_BY_TYPE.get(entity_type)
    if not spec:
        return

    index_name, _model, converter = spec
    from app.services.meilisearch_client import index_entity

    index_entity(index_name, converter(entity))


async def index_entities(db: AsyncSession, ids_by_type: dict[str, list]) -> int:
    """Re-index only the named entities — one query and one Meili push per type.

    The targeted alternative to ``sync_all_entities`` for write paths that touch
    a handful of rows. Ingest used to dispatch the full sync after every entry
    that linked so much as one CVE, which re-pushed all ~50k entity documents;
    this refreshes just the docs whose row actually changed.

    Rows are re-selected rather than converted from caller-held instances, for
    the reason ``index_rules`` documents: server-generated timestamps are
    expired by flush, and reading one off a stale instance attempts sync IO
    inside the async session. Best effort — a search hiccup must not fail the
    write that triggered it; drift is healed by the scheduled full sync.
    """
    total = 0
    for entity_type, ids in ids_by_type.items():
        spec = _INDEX_BY_TYPE.get(entity_type)
        if not spec or not ids:
            continue
        index_name, model, converter = spec
        unique = list({i for i in ids if i is not None})
        if not unique:
            continue
        try:
            rows = (await db.execute(select(model).where(model.id.in_(unique)))).scalars().all()
            if rows:
                bulk_index_entities(index_name, [converter(r) for r in rows])
                total += len(rows)
        except Exception as e:
            logger.warning("Failed to index %d %s entity/entities: %s", len(unique), entity_type, e)
    return total


# Accepts every slug spelling in use across the API/merge/reclassify layers.
_DELETE_INDEX_BY_TYPE = {
    "cve": "entities_cve",
    "ttp": "entities_ttp",
    "threat_actor": "entities_threat_actor",
    "malware": "entities_malware",
    "country": "entities_country",
    "mitigation": "entities_mitigation",
    "tool": "entities_tool",
    "observable": "entities_observable",
    "rule": "rules",
}


def delete_entity_document(entity_type: str, entity_id) -> None:
    """Remove an entity's search doc after delete/merge/reclassify (best effort).

    Without this, deleted/merged-away entities linger as stale docs until the
    next full ``sync_all_entities`` rebuild. Unindexed types (vendor/product)
    are a no-op.
    """
    index_name = _DELETE_INDEX_BY_TYPE.get(entity_type)
    if not index_name:
        return
    from app.services.meilisearch_client import delete_entity

    delete_entity(index_name, str(entity_id))
