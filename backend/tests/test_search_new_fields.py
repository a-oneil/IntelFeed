"""
Planning-level coverage for the query-language fields added alongside the
/search page.

These assert the *plan*, not the results: the point is that every documented
field is classified into the right half of the engine and reaches a builder.
A field that parses but classifies as bare text silently degrades into a
keyword search — it returns plausible results and nobody notices.
"""

import pytest

from app.search.entity_builder import (
    ARRAY_FIELDS,
    BOOLEAN_FIELDS,
    DATE_FIELDS,
    FIELD_MAP,
    JOIN_FIELDS,
    JSON_ARRAY_FIELDS,
)
from app.search.query_parser import parse_query
from app.search.query_planner import (
    ENTITY_FIELDS,
    ENTRY_FIELDS,
    VALID_SORTS,
    build_execution_plan,
    classify_field,
)

# One representative per family added, with the value shape a user would type.
NEW_ENTITY_QUERIES = [
    "cve.kev:true",
    "cve.epss:>0.5",
    "cve.poc:>0",
    "cve.exploit:kev",
    "cve.product:fortinet",
    "ttp.platform:Windows",
    "ttp.data_source:process",
    "ttp.domain:enterprise",
    "ttp.subtechnique:true",
    "rule.data_source:sysmon",
    "rule.tactic:persistence",
    "rule.tag:attack",
    "rule.draft:false",
    "threat_actor.motivation:espionage",
    "threat_actor.sector:healthcare",
    "threat_actor.type:ransomware",
    "malware.sector:finance",
    "tool.platform:Windows",
    "country.iso:RU",
    "sector:healthcare",
    "sector.slug:financial-services",
    "ransomware_victim.group:lockbit",
    "product.vendor:Cisco",
    "intel_report:quarterly",
    "intel_report.status:draft",
    "threat_actor.articles:>100",
    "malware.seen:>2026-01-01",
    "cve.via:ai_extraction",
]

NEW_ENTRY_QUERIES = [
    "category:Blogs",
    "signal:under_reported",
    "url:github.com",
    "feed.reliability:B",
]


@pytest.mark.parametrize("query", NEW_ENTITY_QUERIES)
def test_new_entity_fields_plan_as_entity_queries(query):
    field = query.split(":", 1)[0]
    assert field in ENTITY_FIELDS, f"{field} is not registered"
    assert classify_field(field) == "entity"

    plan = build_execution_plan(parse_query(query))
    assert plan.has_entity_queries, f"{query} produced no entity query"
    # And it must not have leaked into the text search, which would quietly
    # turn a filter into a keyword match.
    assert plan.meili_query.strip() == ""


@pytest.mark.parametrize("query", NEW_ENTRY_QUERIES)
def test_new_entry_fields_plan_as_postgres_filters(query):
    field = query.split(":", 1)[0]
    assert field in ENTRY_FIELDS, f"{field} is not registered"
    assert classify_field(field) == "entry"

    plan = build_execution_plan(parse_query(query))
    assert plan.pending_entry_filters, f"{query} produced no pending filter"
    assert plan.has_entry_queries
    assert plan.meili_query.strip() == ""


@pytest.mark.parametrize("value", ["muted", "translated", "image"])
def test_new_is_values_resolve_from_postgres(value):
    plan = build_execution_plan(parse_query(f"is:{value}"))
    assert [pf.kind for pf in plan.pending_entry_filters] == [f"is.{value}"]
    assert plan.has_entry_queries


def test_words_filter_becomes_a_meili_range():
    assert "word_count >= 1500" in build_execution_plan(parse_query("words:>=1500")).meili_filters
    assert "word_count > 1500" in build_execution_plan(parse_query("words:>1500")).meili_filters
    plan = build_execution_plan(parse_query("words:500..2000"))
    assert "word_count >= 500" in plan.meili_filters
    assert "word_count <= 2000" in plan.meili_filters


def test_radar_sort_is_an_entry_query_on_its_own():
    """`sort:radar` alone means "the highest-ranked entries", not "no query"."""
    assert "radar" in VALID_SORTS
    plan = build_execution_plan(parse_query("sort:radar"))
    assert plan.sort == "radar"
    # The flag is recomputed after the field handlers run, so this is the
    # assertion that catches it being clobbered back to False.
    assert plan.has_entry_queries


def test_every_registered_entity_field_can_be_built():
    """A field in ENTITY_FIELDS with no builder silently filters nothing."""
    unbuildable = sorted(f for f in ENTITY_FIELDS if f not in FIELD_MAP and f not in JOIN_FIELDS)
    assert unbuildable == []


def test_typed_field_sets_reference_real_fields():
    for name, group in (
        ("ARRAY_FIELDS", ARRAY_FIELDS),
        ("JSON_ARRAY_FIELDS", JSON_ARRAY_FIELDS),
        ("BOOLEAN_FIELDS", BOOLEAN_FIELDS),
        ("DATE_FIELDS", DATE_FIELDS),
    ):
        unknown = sorted(f for f in group if f not in FIELD_MAP)
        assert unknown == [], f"{name} references fields with no column mapping: {unknown}"


def test_entry_id_is_filterable():
    """The entity join constrains entries with `id IN [...]`.

    `id` was absent from the index's filterable attributes, so Meilisearch
    answered 400 and `execute_entry_search` swallowed it — meaning any text term
    combined with an entity filter ("ransomware threat_actor:LockBit") returned
    zero articles while the bare filter returned hundreds. Nothing surfaced the
    failure, which is exactly why this is pinned.
    """
    from app.services.meilisearch_client import FILTERABLE_ATTRIBUTES

    assert "id" in FILTERABLE_ATTRIBUTES
    # `words:` and `category:` filter on these two; both are settings-only, so a
    # removal would fail the same silent way.
    assert "word_count" in FILTERABLE_ATTRIBUTES
    assert "category_id" in FILTERABLE_ATTRIBUTES


def test_entity_filter_results_are_direct_matches():
    """A filter match IS the answer, not an entity that mentions the query."""
    from app.models.threat_actor import ThreatActor
    from app.search.entity_builder import _serialize_entity

    actor = ThreatActor(name="LockBit")
    actor.id = __import__("uuid").uuid4()
    actor.aliases = []
    actor.country = None
    actor.motivation = None
    actor.description = None
    actor.article_count = 0
    assert _serialize_entity("threat_actor", actor)["match_kind"] == "direct"
