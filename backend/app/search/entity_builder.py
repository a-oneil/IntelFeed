"""
Entity query builder: converts entity portions of the execution plan
into SQLAlchemy queries against PostgreSQL intelligence models.
"""

from __future__ import annotations

import re

from sqlalchemy import Text, cast, false, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.campaign import Campaign, CampaignEntry
from app.models.country import Country, EntryCountry
from app.models.cve import CVE, EntryCVE
from app.models.cve_affected import CVEAffected
from app.models.cwe import CWE, EntryCWE
from app.models.detection_rule import DetectionRule
from app.models.entity_note import EntityNote
from app.models.entry_sector import EntrySector
from app.models.intel_report import IntelReport
from app.models.intelligence_requirement import IntelligenceRequirement, RequirementMatch
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.mitigation import EntryMitigation, Mitigation
from app.models.note import Note
from app.models.observable import EntryObservable, Observable
from app.models.product import EntryProduct, Product
from app.models.ransomware import RansomwareVictim, VictimDisclosure
from app.models.sector import MalwareTargetSector, Sector, ThreatActorTargetSector
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.tool import EntryTool, Tool
from app.models.ttp import TTP, EntryTTP
from app.models.vendor import EntryVendor, Vendor
from app.search.note_results import fetch_notes
from app.search.query_planner import EntityCondition, EntityFilterGroup

# Maps entity type root to (Model, JunctionModel or None, junction_entity_fk, junction_entry_fk)
ENTITY_TABLE_MAP = {
    "ttp": (TTP, EntryTTP, EntryTTP.ttp_id, EntryTTP.entry_id),
    "cve": (CVE, EntryCVE, EntryCVE.cve_id, EntryCVE.entry_id),
    "cwe": (CWE, EntryCWE, EntryCWE.cwe_id, EntryCWE.entry_id),
    "threat_actor": (ThreatActor, EntryThreatActor, EntryThreatActor.threat_actor_id, EntryThreatActor.entry_id),
    "malware": (MalwareFamily, EntryMalware, EntryMalware.malware_family_id, EntryMalware.entry_id),
    "country": (Country, EntryCountry, EntryCountry.country_id, EntryCountry.entry_id),
    "sector": (Sector, EntrySector, EntrySector.sector_id, EntrySector.entry_id),
    "tool": (Tool, EntryTool, EntryTool.tool_id, EntryTool.entry_id),
    "vendor": (Vendor, EntryVendor, EntryVendor.vendor_id, EntryVendor.entry_id),
    "product": (Product, EntryProduct, EntryProduct.product_id, EntryProduct.entry_id),
    "mitigation": (Mitigation, EntryMitigation, EntryMitigation.mitigation_id, EntryMitigation.entry_id),
    "observable": (Observable, EntryObservable, EntryObservable.observable_id, EntryObservable.entry_id),
    "ioc": (Observable, EntryObservable, EntryObservable.observable_id, EntryObservable.entry_id),
    "campaign": (Campaign, CampaignEntry, CampaignEntry.campaign_id, CampaignEntry.entry_id),
    # Victims come from leak-site sync, not article ingest, so they have no entry
    # junction: searching one surfaces the victim itself, never linked articles.
    "ransomware_victim": (RansomwareVictim, None, None, None),
    "rule": (DetectionRule, None, None, None),  # rules link to entries via entry_id column directly
    # Reports carry their sources in an `entry_ids` column rather than a
    # junction table, so like victims they surface themselves, not articles.
    "intel_report": (IntelReport, None, None, None),
    "pir": (IntelligenceRequirement, RequirementMatch, RequirementMatch.requirement_id, RequirementMatch.entry_id),
    # Notes span two tables, so `Note` here is only the map's admission ticket —
    # `_execute_note_group` takes over before the generic query is built.
    "note": (Note, None, None, None),
}


# Field → (model_attr_name) mapping for each entity type
FIELD_MAP = {
    # TTP
    "ttp": ("technique_id", TTP),  # also search technique_name
    "ttp.tactic": ("tactic", TTP),
    # CVE
    "cve": ("cve_id", CVE),
    "cve.severity": ("severity", CVE),
    "cve.cvss": ("cvss_score", CVE),
    # CWE
    "cwe": ("cwe_id", CWE),  # also search name
    "cwe.abstraction": ("abstraction", CWE),
    "cwe.usage": ("mapping_usage", CWE),
    "cwe.parent": ("parent_cwe_id", CWE),
    "cwe.kind": ("kind", CWE),
    "cwe.deprecated": ("is_deprecated", CWE),
    # Threat Actor
    "threat_actor": ("name", ThreatActor),  # also search aliases
    "threat_actor.country": ("country", ThreatActor),
    # Malware
    "malware": ("name", MalwareFamily),  # also search aliases
    "malware.type": ("malware_type", MalwareFamily),
    # Country
    "country": ("name", Country),  # also search aliases
    "country.region": ("region", Country),
    # Sector — the article's *targeted* industries, written only by the AI door
    "sector": ("name", Sector),  # also search aliases
    "sector.slug": ("slug", Sector),
    # Tool
    "tool": ("name", Tool),  # also search aliases
    "tool.type": ("tool_type", Tool),
    # Vendor
    "vendor": ("name", Vendor),  # also search aliases
    "vendor.type": ("vendor_type", Vendor),
    # Product
    "product": ("name", Product),  # also search aliases
    "product.type": ("product_type", Product),
    # Mitigation
    "mitigation": ("name", Mitigation),  # also search mitre_id
    # Observable (searchable as observable: or the shorter ioc: alias)
    "observable": ("value", Observable),  # also search label
    "observable.kind": ("kind", Observable),
    "observable.role": ("role", Observable),
    "observable.status": ("status", Observable),
    "observable.infra": ("infra_tag", Observable),
    "ioc": ("value", Observable),
    "ioc.kind": ("kind", Observable),
    "ioc.role": ("role", Observable),
    "ioc.status": ("status", Observable),
    "ioc.infra": ("infra_tag", Observable),
    # Campaign
    "campaign": ("name", Campaign),
    "campaign.status": ("status", Campaign),
    # Ransomware victim
    "ransomware_victim": ("name", RansomwareVictim),  # also search aliases
    "ransomware_victim.sector": ("sector", RansomwareVictim),
    "ransomware_victim.domain": ("domain", RansomwareVictim),
    # Detection Rule
    "rule": ("title", DetectionRule),
    "rule.type": ("rule_type", DetectionRule),
    "rule.severity": ("severity", DetectionRule),
    # Intelligence Requirement (PIR)
    "pir": ("title", IntelligenceRequirement),
    "pir.priority": ("priority", IntelligenceRequirement),
    "pir.category": ("category", IntelligenceRequirement),
    # Exploitation signals
    "cve.kev": ("is_kev", CVE),
    "cve.epss": ("epss_score", CVE),
    "cve.epss_percentile": ("epss_percentile", CVE),
    "cve.poc": ("github_poc_count", CVE),
    "cve.exploit": ("exploit_status", CVE),
    # ATT&CK shape
    "ttp.platform": ("platforms", TTP),
    "ttp.data_source": ("data_sources", TTP),
    "ttp.domain": ("matrix_domain", TTP),
    "ttp.subtechnique": ("is_subtechnique", TTP),
    "ttp.deprecated": ("is_deprecated", TTP),
    # Rule content
    "rule.data_source": ("data_sources", DetectionRule),
    "rule.tactic": ("mitre_tactics", DetectionRule),
    "rule.tag": ("tags", DetectionRule),
    "rule.draft": ("is_draft", DetectionRule),
    "rule.license": ("license", DetectionRule),
    # Actor / malware / tool / country attributes
    "threat_actor.motivation": ("motivation", ThreatActor),
    # threat_actor.sector / malware.sector are JOIN_FIELDS (target-sector junction)
    "threat_actor.type": ("actor_type", ThreatActor),
    "threat_actor.mitre": ("mitre_id", ThreatActor),
    "malware.mitre": ("mitre_id", MalwareFamily),
    "tool.platform": ("platforms", Tool),
    "tool.mitre": ("mitre_id", Tool),
    "country.iso": ("iso_code", Country),
    # Notes. The columns named here are the `notes` table's; `_execute_note_group`
    # queries `entity_notes` alongside it rather than through FIELD_MAP.
    "note": ("title", Note),
    "note.tag": ("tags", Note),
    "note.type": ("note_type", EntityNote),
    "note.about": ("entity_type", EntityNote),
    "note.pinned": ("is_pinned", Note),
    # Reports
    "intel_report": ("title", IntelReport),
    "intel_report.status": ("status", IntelReport),
    "intel_report.type": ("template_type", IntelReport),
    "intel_report.tlp": ("tlp_marking", IntelReport),
}

# Catalogue attributes every entity carries. Generated so a new entity type
# picks them up by being added to one tuple rather than eight map entries.
_CATALOGUE_MODELS = {
    "ttp": TTP,
    "threat_actor": ThreatActor,
    "malware": MalwareFamily,
    "country": Country,
    "sector": Sector,
    "tool": Tool,
    "vendor": Vendor,
    "product": Product,
    "mitigation": Mitigation,
    "cwe": CWE,
    "observable": Observable,
    "ioc": Observable,
}
_PROVENANCE_MODELS = {
    "threat_actor": ThreatActor,
    "malware": MalwareFamily,
    "cve": CVE,
    "ttp": TTP,
    "tool": Tool,
}
for _root, _model in _CATALOGUE_MODELS.items():
    FIELD_MAP[f"{_root}.articles"] = ("article_count", _model)
    FIELD_MAP[f"{_root}.seen"] = ("last_seen_at", _model)
    FIELD_MAP[f"{_root}.first_seen"] = ("first_seen_at", _model)
for _root, _model in _PROVENANCE_MODELS.items():
    FIELD_MAP[f"{_root}.review"] = ("needs_review", _model)
    FIELD_MAP[f"{_root}.via"] = ("created_via", _model)

# Postgres ARRAY(Text) columns: matched by substring against the joined
# elements, so `rule.data_source:process` finds "Process Creation".
ARRAY_FIELDS = {
    "rule.data_source",
    "rule.tactic",
    "rule.tag",
    "tool.platform",
}

# JSONB array columns. Same containment semantics, different storage — casting
# to text is enough for a substring filter and avoids a lateral join.
JSON_ARRAY_FIELDS = {"ttp.platform", "ttp.data_source"}

BOOLEAN_FIELDS = {
    "cve.kev",
    "ttp.subtechnique",
    "ttp.deprecated",
    "cwe.deprecated",
    "rule.draft",
} | {f"{root}.review" for root in _PROVENANCE_MODELS}

DATE_FIELDS = {f"{root}.{leaf}" for root in _CATALOGUE_MODELS for leaf in ("seen", "first_seen")}

_TRUTHY = {"true", "yes", "1", "y"}
_FALSY = {"false", "no", "0", "n"}

# Fields that should also search aliases (array columns)
ALIAS_SEARCH_FIELDS = {
    "threat_actor": ThreatActor.aliases,
    "malware": MalwareFamily.aliases,
    "country": Country.aliases,
    "sector": Sector.aliases,
    "tool": Tool.aliases,
    "vendor": Vendor.aliases,
    "product": Product.aliases,
    "ransomware_victim": RansomwareVictim.aliases,
}

# Fields that should also search a secondary column
SECONDARY_SEARCH_FIELDS = {
    "ttp": ("technique_name", TTP),
    "mitigation": ("mitre_id", Mitigation),
    # `ioc:amsi bypass` should find the labeled script row the same way the
    # value itself would.
    "observable": ("label", Observable),
    "ioc": ("label", Observable),
    # `cwe:use after free` should find CWE-416 the same way `ttp:phishing`
    # finds T1566 — the id is the key, the name is how people actually search.
    "cwe": ("name", CWE),
}


def _entity_order(model) -> list:
    """A stable, useful ordering for an entity result page.

    Any ordering would do for determinism, but the page is capped, so the cap
    should keep the entities the user is most likely to have meant: the ones
    the corpus actually talks about. `id` is the tiebreaker that makes repeated
    runs of the same query agree.
    """
    order: list = []
    if hasattr(model, "article_count"):
        order.append(model.article_count.desc().nullslast())
    elif hasattr(model, "created_at"):
        order.append(model.created_at.desc().nullslast())
    order.append(model.id)
    return order


async def execute_entity_queries(
    db: AsyncSession,
    entity_groups: list[EntityFilterGroup],
    limit: int = 50,
    user_id: str | None = None,
) -> tuple[list[dict], set[str]]:
    """Execute entity queries and return results + linked entry IDs.

    Args:
        user_id: Required for user-scoped entity types (e.g. PIR).

    Returns:
        (entity_results, linked_entry_ids) where:
        - entity_results: list of serialized entity dicts
        - linked_entry_ids: set of entry ID strings linked to matching entities
    """
    all_results: list[dict] = []
    all_entry_ids: set[str] = set()

    for group in entity_groups:
        results, entry_ids = await _execute_entity_group(db, group, limit, user_id=user_id)
        all_results.extend(results)
        all_entry_ids.update(entry_ids)

    return all_results, all_entry_ids


async def _execute_entity_group(
    db: AsyncSession,
    group: EntityFilterGroup,
    limit: int,
    user_id: str | None = None,
) -> tuple[list[dict], set[str]]:
    """Execute queries for a single entity type group."""
    entity_type = group.entity_type
    if entity_type not in ENTITY_TABLE_MAP:
        return [], set()

    if entity_type == "note":
        return await _execute_note_group(db, group, limit)

    model, junction, junction_entity_fk, junction_entry_fk = ENTITY_TABLE_MAP[entity_type]

    # Build WHERE conditions. Conditions sharing an or_group are OR'd together
    # (e.g. actor:APT28 OR actor:APT29); everything else ANDs.
    conditions = []
    or_groups: dict[int, list] = {}
    for cond in group.conditions:
        clause = _build_condition(cond, model, entity_type)
        if clause is None:
            continue
        if cond.negated:
            clause = ~clause
        if cond.or_group is not None:
            or_groups.setdefault(cond.or_group, []).append(clause)
        else:
            conditions.append(clause)
    for clauses in or_groups.values():
        conditions.append(clauses[0] if len(clauses) == 1 else or_(*clauses))

    if not conditions:
        return [], set()

    stmt = select(model).where(*conditions)

    # PIR: only show active requirements
    if entity_type == "pir":
        stmt = stmt.where(
            IntelligenceRequirement.status == "active",
        )

    # Which entities the *entries* come from must not depend on which page of
    # entities we happen to show. This subquery is the unlimited match set; the
    # `limit` below only trims what the intelligence panel renders.
    matched_ids = stmt.with_only_columns(model.id).order_by(None).scalar_subquery()

    result = await db.execute(stmt.order_by(*_entity_order(model)).limit(limit))
    entities = result.scalars().all()

    # Linked entries come from every match, not just the displayed page. Deriving
    # them from an unordered `LIMIT 200` is what made the same query return a
    # different number of entries on every run.
    entry_ids: set[str] = set()
    if entity_type == "rule":
        rows = await db.execute(select(DetectionRule.entry_id).where(DetectionRule.id.in_(matched_ids)))
        entry_ids = {str(r[0]) for r in rows.all() if r[0]}
    elif junction is not None and junction_entity_fk is not None and junction_entry_fk is not None:
        junction_stmt = select(junction_entry_fk).where(junction_entity_fk.in_(matched_ids))
        junction_result = await db.execute(junction_stmt)
        entry_ids = {str(row[0]) for row in junction_result.all()}

    if not entities:
        return [], entry_ids

    entity_results = [_serialize_entity(entity_type, entity) for entity in entities]
    return entity_results, entry_ids


# `note.about:` accepts the entity kinds a note can hang off, plus two words for
# the other table: an entry note, and a note attached to nothing at all.
_NOTE_ABOUT_ENTRY = "entry"
_NOTE_ABOUT_STANDALONE = "standalone"


def _note_clause(cond: EntityCondition, table: str):
    """One condition, compiled against one of the two note tables.

    Returns `false()` — not `None` — when the field cannot apply to this table,
    so `note.type:analysis` excludes plain notes instead of silently matching
    all of them, and `-note.type:analysis` still includes them.
    """
    value = cond.value
    like = value.replace("*", "%") if "*" in value else f"%{value}%"
    is_entity_note = table == "entity_note"

    if cond.field == "note":
        if is_entity_note:
            return or_(EntityNote.title.ilike(like), EntityNote.content.ilike(like))
        return or_(Note.title.ilike(like), Note.content_markdown.ilike(like))

    if cond.field == "note.tag":
        column = EntityNote.tags if is_entity_note else Note.tags
        return func.array_to_string(column, " ").ilike(like)

    if cond.field == "note.type":
        # Only entity notes are typed; a plain note has no note_type column.
        return func.lower(EntityNote.note_type) == value.lower() if is_entity_note else false()

    if cond.field == "note.about":
        target = value.lower()
        if target == _NOTE_ABOUT_ENTRY:
            return false() if is_entity_note else Note.entry_id.isnot(None)
        if target == _NOTE_ABOUT_STANDALONE:
            return false() if is_entity_note else Note.entry_id.is_(None)
        return func.lower(EntityNote.entity_type) == target if is_entity_note else false()

    if cond.field == "note.pinned":
        parsed = _parse_bool(value)
        if parsed is None:
            return None
        # Pinning is a `notes` feature; an entity note can never be pinned.
        return Note.is_pinned.is_(parsed) if not is_entity_note else false()

    return None


def _note_conditions(group: EntityFilterGroup, table: str) -> list:
    """Compile a group's conditions for one note table, preserving AND/OR/NOT."""
    conditions = []
    or_groups: dict[int, list] = {}
    for cond in group.conditions:
        clause = _note_clause(cond, table)
        if clause is None:
            continue
        if cond.negated:
            clause = ~clause
        if cond.or_group is not None:
            or_groups.setdefault(cond.or_group, []).append(clause)
        else:
            conditions.append(clause)
    for clauses in or_groups.values():
        conditions.append(clauses[0] if len(clauses) == 1 else or_(*clauses))
    return conditions


async def _execute_note_group(
    db: AsyncSession,
    group: EntityFilterGroup,
    limit: int,
) -> tuple[list[dict], set[str]]:
    """`note:` queries, which span the `notes` and `entity_notes` tables.

    The generic path builds one query against one model; notes need two, so the
    conditions are compiled once per table and handed to the same fetch the
    plain-text sweep uses.
    """
    note_conditions = _note_conditions(group, "note")
    entity_note_conditions = _note_conditions(group, "entity_note")
    if not note_conditions and not entity_note_conditions:
        return [], set()

    # The value of a bare `note:` term is what the snippet centres on; a query
    # made only of property filters has nothing to highlight.
    highlight = next((c.value.lower() for c in group.conditions if c.field == "note" and not c.negated), "")
    return await fetch_notes(db, note_conditions, entity_note_conditions, limit, highlight)


def _parse_bool(value: str) -> bool | None:
    v = value.strip().lower()
    if v in _TRUTHY:
        return True
    if v in _FALSY:
        return False
    return None


def _parse_date(value: str):
    """Accept YYYY-MM-DD or YYYY-MM, the same shapes `date:` takes on entries."""
    from datetime import UTC, datetime

    for fmt in ("%Y-%m-%d", "%Y-%m"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


def _build_join_condition(field: str, cond: EntityCondition):
    """Fields answered by a related table rather than a column on the entity.

    Each returns an EXISTS-style `IN (subquery)` so the surrounding AND/OR and
    negation machinery keeps working unchanged.
    """
    value = cond.value
    pattern = value.replace("*", "%") if "*" in value else f"%{value}%"

    if field == "cve.product":
        # Affected products come from NVD CPE data, which names a vendor and a
        # product separately; a user typing "fortios" means either.
        sub = select(CVEAffected.cve_id).where(
            or_(CVEAffected.cpe_product.ilike(pattern), CVEAffected.cpe_vendor.ilike(pattern))
        )
        return CVE.id.in_(sub)

    if field == "ransomware_victim.group":
        # `group_name_raw` is what the leak site called the group, which is what
        # someone searching a leak site will type.
        sub = select(VictimDisclosure.victim_id).where(VictimDisclosure.group_name_raw.ilike(pattern))
        return RansomwareVictim.id.in_(sub)

    if field == "product.vendor":
        sub = select(Vendor.id).where(Vendor.name.ilike(pattern))
        return Product.vendor_id.in_(sub)

    if field in ("threat_actor.sector", "malware.sector"):
        # Asserted targeting lives on the target-sector junctions; the value is
        # matched against the vocabulary's name, slug and aliases so
        # `threat_actor.sector:banks` finds Financial Services.
        sector_ids = select(Sector.id).where(
            or_(
                Sector.name.ilike(pattern),
                Sector.slug.ilike(pattern),
                func.array_to_string(Sector.aliases, " ").ilike(pattern),
            )
        )
        if field == "threat_actor.sector":
            sub = select(ThreatActorTargetSector.threat_actor_id).where(
                ThreatActorTargetSector.sector_id.in_(sector_ids)
            )
            return ThreatActor.id.in_(sub)
        sub = select(MalwareTargetSector.malware_family_id).where(MalwareTargetSector.sector_id.in_(sector_ids))
        return MalwareFamily.id.in_(sub)

    return None


JOIN_FIELDS = {"cve.product", "ransomware_victim.group", "product.vendor", "threat_actor.sector", "malware.sector"}


def _build_condition(cond: EntityCondition, model, entity_type: str):
    """Build a SQLAlchemy condition from an EntityCondition."""
    field = cond.field

    if field in JOIN_FIELDS:
        return _build_join_condition(field, cond)

    if field not in FIELD_MAP:
        return None

    attr_name, _ = FIELD_MAP[field]
    column = getattr(model, attr_name)
    value = cond.value

    # Booleans: `cve.kev:true`. An unparseable value filters nothing rather
    # than silently matching everything.
    if field in BOOLEAN_FIELDS:
        parsed = _parse_bool(value)
        return None if parsed is None else column.is_(parsed)

    # Array containment, by substring against the joined elements.
    if field in ARRAY_FIELDS or field in JSON_ARRAY_FIELDS:
        joined = cast(column, Text) if field in JSON_ARRAY_FIELDS else func.array_to_string(column, " ")
        return joined.ilike(value.replace("*", "%") if "*" in value else f"%{value}%")

    # Dates take the same comparison grammar as `date:` on entries. A bare
    # value means "on or after", which is what "seen:2026-01" is asking.
    if field in DATE_FIELDS:
        raw = value.lstrip("<>=")
        parsed = _parse_date(raw)
        if parsed is None:
            return None
        if cond.op in ("lt", "lte") or value.startswith("<"):
            return column <= parsed
        return column >= parsed

    # Wildcard → ILIKE
    if cond.op == "contains" and "*" in value:
        sql_pattern = value.replace("*", "%")
        clause = column.ilike(sql_pattern)

        # Also search secondary fields (aliases, technique_name)
        if field in ALIAS_SEARCH_FIELDS:
            alias_col = ALIAS_SEARCH_FIELDS[field]
            # Aliases require word-boundary match so 'fox' doesn't match 'firefox'.
            # Convert the user's '*' wildcards back to regex '.*' after escaping.
            escaped_wildcard = re.escape(value).replace(re.escape("*"), ".*")
            alias_regex = rf"\y{escaped_wildcard}\y"
            clause = or_(clause, func.array_to_string(alias_col, " ").op("~*")(alias_regex))
        if field in SECONDARY_SEARCH_FIELDS:
            sec_attr, sec_model = SECONDARY_SEARCH_FIELDS[field]
            sec_col = getattr(sec_model, sec_attr)
            clause = or_(clause, sec_col.ilike(sql_pattern))

        return clause

    # Exact match or equality
    if cond.op == "eq":
        if cond.exact:
            clause = column == value
            return clause
        else:
            # Bare type roots (`malware:Emotet`) do an ILIKE substring match by
            # default; dotted property fields (`malware.type:`) stay exact.
            if field in ENTITY_TABLE_MAP:
                clause = column.ilike(f"%{value}%")
                if field in ALIAS_SEARCH_FIELDS:
                    alias_col = ALIAS_SEARCH_FIELDS[field]
                    alias_regex = rf"\y{re.escape(value)}\y"
                    clause = or_(clause, func.array_to_string(alias_col, " ").op("~*")(alias_regex))
                if field in SECONDARY_SEARCH_FIELDS:
                    sec_attr, sec_model = SECONDARY_SEARCH_FIELDS[field]
                    sec_col = getattr(sec_model, sec_attr)
                    clause = or_(clause, sec_col.ilike(f"%{value}%"))
            else:
                # Sub-fields like cve.severity → exact match (case-insensitive)
                clause = func.lower(column) == value.lower()
            return clause

    # Range operators (for numeric fields like cve.cvss). A non-numeric value
    # filters nothing rather than raising: `cve.cvss:>bogus` used to reach
    # `column > None` and come back as a 500.
    if cond.op in ("gt", "gte", "lt", "lte"):
        bound = _numeric(value)
        if bound is None:
            return None
        return {
            "gt": column > bound,
            "gte": column >= bound,
            "lt": column < bound,
            "lte": column <= bound,
        }[cond.op]
    if cond.op == "range" and ".." in value:
        parts = value.split("..", 1)
        low = _numeric(parts[0])
        high = _numeric(parts[1])
        if low is not None and high is not None:
            return (column >= low) & (column <= high)

    return None


def _numeric(val: str) -> float | None:
    try:
        return float(val)
    except (ValueError, TypeError):
        return None


_TYPE_TO_API = {"threat_actor": "threat_actor", "rule": "detection_rule", "pir": "pir", "ioc": "observable"}


def _serialize_entity(entity_type: str, entity) -> dict:
    """Serialize an entity to a dict for the API response."""
    base = {
        "id": str(entity.id),
        "type": _TYPE_TO_API.get(entity_type, entity_type),
        # Everything on this path matched an explicit filter — `cve.kev:true`
        # returns the KEV CVEs, which are the answer, not entities that merely
        # mention the query. The free-text path in correlation.py decides
        # direct-vs-mention per row; here it is direct by construction.
        "match_kind": "direct",
    }

    if entity_type == "ttp":
        base.update(
            {
                "technique_id": entity.technique_id,
                "technique_name": entity.technique_name,
                "tactic": entity.tactic,
                "description": entity.description,
                "article_count": entity.article_count,
            }
        )
    elif entity_type == "cve":
        base.update(
            {
                "cve_id": entity.cve_id,
                "cvss_score": float(entity.cvss_score) if entity.cvss_score else None,
                "severity": entity.severity,
                "description": entity.description,
            }
        )
    elif entity_type == "cwe":
        base.update(
            {
                "cwe_id": entity.cwe_id,
                "name": entity.name,
                "kind": entity.kind,
                "abstraction": entity.abstraction,
                "mapping_usage": entity.mapping_usage,
                "parent_cwe_id": entity.parent_cwe_id,
                "is_deprecated": entity.is_deprecated,
                "description": entity.description,
                "alternate_terms": entity.alternate_terms or [],
                "article_count": entity.article_count,
            }
        )
    elif entity_type in ("observable", "ioc"):
        base.update(
            {
                "kind": entity.kind,
                "value": entity.value,
                "name": entity.label or entity.value,
                "label": entity.label,
                "role": entity.role,
                "status": entity.status,
                "current_confidence": entity.current_confidence,
                "description": entity.description,
                "article_count": entity.article_count,
            }
        )
    elif entity_type == "threat_actor":
        base.update(
            {
                "name": entity.name,
                "aliases": entity.aliases or [],
                "country": entity.country,
                "motivation": entity.motivation,
                "description": entity.description,
                "article_count": entity.article_count,
            }
        )
    elif entity_type == "malware":
        base.update(
            {
                "name": entity.name,
                "aliases": entity.aliases or [],
                "malware_type": entity.malware_type,
                "article_count": entity.article_count,
            }
        )
    elif entity_type in ("tool", "vendor", "product"):
        base.update(
            {
                "name": entity.name,
                "aliases": entity.aliases or [],
                "description": entity.description,
                "article_count": entity.article_count,
                f"{entity_type}_type": getattr(entity, f"{entity_type}_type", None),
            }
        )
    elif entity_type == "mitigation":
        base.update(
            {
                "name": entity.name,
                "mitre_id": entity.mitre_id,
                "description": entity.description,
                "article_count": entity.article_count,
            }
        )
    elif entity_type == "ransomware_victim":
        base.update(
            {
                "name": entity.name,
                "aliases": entity.aliases or [],
                "sector": entity.sector,
                "domain": entity.domain,
                "disclosure_count": entity.disclosure_count,
            }
        )
    elif entity_type == "campaign":
        base.update(
            {
                "name": entity.name,
                "status": entity.status,
                "description": entity.description,
            }
        )
    elif entity_type == "country":
        base.update(
            {
                "name": entity.name,
                "aliases": entity.aliases or [],
                "iso_code": entity.iso_code,
                "region": entity.region,
                "description": entity.description,
                "article_count": entity.article_count,
            }
        )
    elif entity_type == "sector":
        base.update(
            {
                "name": entity.name,
                "slug": entity.slug,
                "aliases": entity.aliases or [],
                "description": entity.description,
                "article_count": entity.article_count,
            }
        )
    elif entity_type == "rule":
        base.update(
            {
                "title": entity.title,
                "rule_type": entity.rule_type,
                "severity": entity.severity,
                "description": entity.description,
            }
        )
    # Tools, vendors, products and reports were reachable in ENTITY_TABLE_MAP
    # but had no branch here, so a filter query like `tool.platform:Windows`
    # returned rows carrying only an id — and the UI, having no name to show,
    # rendered the raw UUID.
    elif entity_type == "tool":
        base.update(
            {
                "name": entity.name,
                "aliases": entity.aliases or [],
                "tool_type": entity.tool_type,
                "description": entity.description,
                "article_count": entity.article_count,
            }
        )
    elif entity_type == "vendor":
        base.update(
            {
                "name": entity.name,
                "aliases": entity.aliases or [],
                "vendor_type": entity.vendor_type,
                "description": entity.description,
                "article_count": entity.article_count,
            }
        )
    elif entity_type == "product":
        base.update(
            {
                "name": entity.name,
                "aliases": entity.aliases or [],
                "product_type": entity.product_type,
                "description": entity.description,
                "article_count": entity.article_count,
            }
        )
    elif entity_type == "intel_report":
        base.update(
            {
                "title": entity.title,
                "template_type": entity.template_type,
                "status": entity.status,
                "tlp_marking": entity.tlp_marking,
                "summary": entity.summary,
            }
        )
    elif entity_type == "pir":
        base.update(
            {
                "title": entity.title,
                "priority": entity.priority,
                "category": entity.category,
                "status": entity.status,
                "description": entity.description,
                "match_count": entity.match_count,
            }
        )

    return base


def _dt(dt) -> str | None:
    if dt is None:
        return None
    return dt.isoformat()
