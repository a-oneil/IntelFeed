"""The canonical entity-type vocabulary is the single source of truth.

Three spellings (``malware_family``, ``offensive_tool``, ``actor``) were retired
in the 2026-08 unification because the split silently orphaned rows — a
relationship written as ``malware_family`` never joined the ``malware`` ones.
These tests keep them retired, and keep each layer's registry aligned with the
capability set that describes it.
"""

import ast
import inspect
import re
from pathlib import Path

import pytest

from app import entity_types

APP_ROOT = Path(entity_types.__file__).parent
BACKEND_ROOT = APP_ROOT.parent
# Standalone scripts talk to the same API and write the same columns, so they
# have to speak the same vocabulary — they just live outside app/. The repo-root
# scripts/ dir is only visible outside the container (which mounts backend/ alone).
SCRIPT_ROOTS = [BACKEND_ROOT / "scripts", BACKEND_ROOT.parent / "scripts"]

# Occurrences that read like a retired slug but are not entity_type
# discriminators. Each is matched as a literal substring of the offending line,
# so a genuinely new use of a retired slug still fails the test.
_NOT_A_SLUG = {
    # The table, the FK columns, the module and the model class keep their own
    # names — the 2026-08 unification changed only the discriminator string.
    "malware_families": "table name",
    "malware_family_id": "junction FK column",
    "app.models.malware_family": "module path",
    "MalwareFamily": "model class",
    'EntryMalware: "malware_family"': "ORM relationship attribute, not a slug",
    'back_populates="malware_family"': "ORM relationship attribute, not a slug",
    # 'actor' as an English word rather than a type.
    '"actor",\n': "stopword in the merge-suggestion name denylist",
    '"threat_actor": "actor"': "display label map — the UI says 'actor', the slug is threat_actor",
    '"actor": handle': "Bluesky API request parameter",
    '{"actor": row.name': "threat_timeline chart row field, not a type discriminator",
    'card.get("actor")': "ETDA Threat Group Card payload key (the card's title)",
    "_VENDOR_LABEL_KEYS = (": "MalwareBazaar vendor_intel payload keys (Triage's family label)",
    '"campaign", "vulnerability", "malware", "actor"': (
        "detection-summary `focus` angle, not an entity_type — note 'vulnerability', "
        "which is not one of our types either (see the focus pattern in schemas/intelligence.py)"
    ),
    # 'victim' as a payload key or ORM attribute rather than a type.
    'md["victim"]': "ransomware.live payload key",
    'raw.get("victim")': "ransomware.live payload key",
    '"victim": victim': "adapter payload key",
    'back_populates="victim"': "ORM relationship attribute, not a slug",
}
_ALLOWED = set(_NOT_A_SLUG)


def _docstring_lines(tree: ast.AST) -> set[int]:
    """Line numbers covered by module/class/function docstrings.

    Docstrings describe things in prose — "one posting = one 'victim'" is English,
    not a slug. Every other string is still scanned, including AI prompt text,
    where a stale slug would actively mislead the model.
    """
    covered: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        body = getattr(node, "body", None)
        if not body:
            continue
        first = body[0]
        if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
            covered.update(range(first.lineno, (first.end_lineno or first.lineno) + 1))
    return covered


def _slug_hits(pattern: str) -> list[str]:
    """Every quoted use of a retired slug in app/, minus the allowed exceptions."""
    hits = []
    for path in APP_ROOT.rglob("*.py"):
        if path.name == "entity_types.py":
            continue  # the normalizer is where the retired spellings are declared
        text = path.read_text()
        skip = _docstring_lines(ast.parse(text))
        for lineno, line in enumerate(text.splitlines(), 1):
            if lineno in skip:
                continue
            code = line.split("#", 1)[0]  # a comment may legitimately name a retired slug
            if not re.search(pattern, code):
                continue
            if any(allowed.strip() in line for allowed in _ALLOWED):
                continue
            hits.append(f"{path.relative_to(APP_ROOT)}:{lineno}: {line.strip()}")
    return hits


@pytest.mark.parametrize(
    "slug,pattern",
    [
        ("malware_family", r'["\']malware_family["\']'),
        ("offensive_tool", r'["\']offensive_tool["\']'),
        ("actor", r'["\']actor(\.[a-z_]+)?["\']'),
        ("victim", r'["\']victim["\']'),
    ],
)
def test_retired_slug_is_not_used_as_an_entity_type(slug, pattern):
    """Use app.entity_types constants instead of retyping a retired spelling."""
    hits = _slug_hits(pattern)
    assert not hits, f"retired slug '{slug}' used as an entity_type:\n" + "\n".join(hits)


def test_normalize_folds_every_retired_spelling():
    assert entity_types.normalize_entity_type("malware_family") == entity_types.MALWARE
    assert entity_types.normalize_entity_type("offensive_tool") == entity_types.TOOL
    assert entity_types.normalize_entity_type("actor") == entity_types.THREAT_ACTOR
    # Canonical and unknown values pass through untouched.
    assert entity_types.normalize_entity_type("malware") == entity_types.MALWARE
    assert entity_types.normalize_entity_type("campaign") == "campaign"


def test_every_retired_spelling_maps_into_the_canonical_set():
    for retired, canonical in entity_types._RETIRED_SLUGS.items():
        assert canonical in entity_types.ALL, f"{retired} folds onto unknown type {canonical}"


def test_capability_sets_are_subsets_of_all():
    for name in ("AUTOLINKABLE", "NAME_RESOLVED", "RECLASSIFIABLE", "CORRELATABLE", "SEARCHABLE"):
        assert getattr(entity_types, name) <= entity_types.ALL, f"{name} names a type outside ALL"


def test_labels_and_tables_cover_every_type():
    assert set(entity_types.LABELS) == entity_types.ALL
    assert set(entity_types.TABLES) == entity_types.ALL


# --- each layer's registry matches the set that describes it -----------------


def test_autolinkable_matches_the_autolinker():
    from app.intelligence import autolinker

    source = inspect.getsource(autolinker._link_entity_to_existing_entries_inner)
    loader = source.split("unsupported_entity_type")[0]
    assert set(re.findall(r'entity_type == "(\w+)"', loader)) == set(entity_types.AUTOLINKABLE)


def test_correlatable_matches_correlation_config():
    from app.intelligence.correlation import ENTITY_CONFIG

    assert set(ENTITY_CONFIG) == set(entity_types.CORRELATABLE)


def test_name_resolved_matches_the_alias_index():
    from app.models.entity_index import ALIAS_INDEXED_TABLES

    assert set(ALIAS_INDEXED_TABLES) == set(entity_types.NAME_RESOLVED)


def test_reclassifiable_matches_the_merge_registry():
    from app.api.entity_merge import ENTITY_TYPE_REGISTRY

    assert set(ENTITY_TYPE_REGISTRY) == set(entity_types.RECLASSIFIABLE)


def test_name_resolved_matches_the_dedup_registry():
    from app.intelligence.entity_dedup import _TYPE_JUNCTION

    # Dedup covers the reclassifiable types; victims dedup through their own
    # resolver rather than the shared junction map.
    assert set(_TYPE_JUNCTION) == set(entity_types.RECLASSIFIABLE)


def test_searchable_matches_the_search_field_roots():
    from app.search.query_planner import ENTITY_FIELD_ROOTS

    # Detection rules, PIRs, campaigns, reports and notes are searchable objects
    # but not entity types — they have entry links without being first-class
    # intelligence nouns. Reports joined the list when `intel_report:` became a
    # query field, and notes when `note:` did: search already returned them, but
    # nothing could filter them.
    # "ioc" is an alias root for "observable" — one type, two spellings in the
    # search bar — so it is excluded here alongside the non-entity roots.
    non_entity_roots = {"rule", "pir", "campaign", "intel_report", "note", "ioc"}
    assert set(ENTITY_FIELD_ROOTS) - non_entity_roots == set(entity_types.SEARCHABLE)


def test_tables_resolve_to_real_model_tables():
    from app.database import Base

    known = {t.name for t in Base.metadata.tables.values()}
    for slug, table in entity_types.TABLES.items():
        assert table in known, f"{slug} -> {table} is not a mapped table"


def test_standalone_scripts_use_the_canonical_vocabulary():
    """scripts/ writes the same columns as app/ and must not drift from it."""
    hits = []
    scanned = 0
    for root in SCRIPT_ROOTS:
        if not root.exists():
            continue
        for path in root.rglob("*.py"):
            text = path.read_text()
            scanned += 1
            skip = _docstring_lines(ast.parse(text))
            for lineno, line in enumerate(text.splitlines(), 1):
                if lineno in skip:
                    continue
                code = line.split("#", 1)[0]
                if not re.search(r'["\'](malware_family|offensive_tool)["\']', code):
                    continue
                if any(allowed.strip() in line for allowed in _ALLOWED):
                    continue
                hits.append(f"{path}:{lineno}: {line.strip()}")
    assert scanned, f"no scripts found under {[str(r) for r in SCRIPT_ROOTS]} — would pass vacuously"
    assert not hits, "retired slug in scripts/:\n" + "\n".join(hits)
