"""Guards against agent-tool registry drift.

The tool registry (app/tools/) restates platform vocabulary — entity types,
rule formats, TLP markings, automation triggers, adapter types, relationship
verbs — inside tool input schemas. Historically those copies rotted as the
platform moved (a 2026-08 audit found 13 broken tools). These tests pin every
schema enum to its canonical source and catch executor/schema mismatches, so
the registry breaks loudly in CI-time checks instead of silently at runtime.
"""

import ast
import inspect
import re
from pathlib import Path

import pytest

from app import entity_types
from app.adapters import _ADAPTERS, _EXTENDED_ADAPTERS
from app.intelligence.relationship_matrix import ALLOWED_RELATIONSHIPS
from app.intelligence.reporting import REPORT_TEMPLATES
from app.schemas.automation import VALID_TRIGGER_TYPES
from app.schemas.intelligence import RULE_TYPE_PATTERN
from app.schemas.tlp import TLP_VALUES
from app.tools import _TOOL_HANDLERS, MUTATING_TOOLS, TOOL_DEFINITIONS

TOOLS_DIR = Path(__file__).resolve().parent.parent / "app" / "tools"

# The skill CLIs live outside backend/: in the api container they are mounted
# at /app/skill-clis (docker-compose.dev.yml); on a host checkout they sit at
# the repo root. Both generated blocks are guarded below.
_REPO = Path(__file__).resolve().parents[2]
_FULL_CLI_PATHS = (Path("/app/skill-clis/full_cli.py"), _REPO / "intelfeed-skill" / "scripts" / "intelfeed_cli.py")
_LITE_CLI_PATHS = (Path("/app/skill-clis/lite_cli.py"), _REPO / "intelfeed-lite-skill" / "scripts" / "intelfeed_cli.py")


def _cli_assign(paths: tuple[Path, ...], target: str):
    """Parse `target: ... = <literal>` out of the first CLI file that exists."""
    path = next((p for p in paths if p.is_file()), None)
    if path is None:
        pytest.skip(f"skill CLI not available (looked in {[str(p) for p in paths]})")
    tree = ast.parse(path.read_text())
    node = next(
        (n for n in ast.walk(tree) if isinstance(n, ast.AnnAssign) and getattr(n.target, "id", None) == target),
        None,
    )
    assert node is not None, f"{path} has no `{target}` assignment"
    value = node.value
    if isinstance(value, ast.Call) and getattr(value.func, "id", None) == "frozenset":
        value = value.args[0]
    return ast.literal_eval(value)


RULE_TYPES = set(re.sub(r"[\^\$\(\)]", "", RULE_TYPE_PATTERN).split("|"))
MATRIX_VERBS = {verb for _, verb, _ in ALLOWED_RELATIONSHIPS}
MATRIX_ENDPOINT_TYPES = {t for a, _, b in ALLOWED_RELATIONSHIPS for t in (a, b)}
ENTITY_TYPE_UNIVERSE = set(entity_types.ALL) | {"campaign"}
# TLP:WHITE is accepted as a deprecated input alias (normalized to TLP:CLEAR).
TLP_UNIVERSE = set(TLP_VALUES) | {"TLP:WHITE"}


def _enum_params(name_pattern: str):
    """Yield (tool_name, param_name, enum_values) for schema params matching name_pattern."""
    rx = re.compile(name_pattern)
    for tool in TOOL_DEFINITIONS:
        for pname, prop in tool.get("input_schema", {}).get("properties", {}).items():
            if rx.fullmatch(pname) and "enum" in prop:
                yield tool["name"], pname, list(prop["enum"])


def _assert_subset(found, universe, context):
    extra = set(found) - universe
    assert not extra, f"{context}: enum values not in canonical source: {sorted(extra)}"


# delete_entity also deletes non-intel objects; only it may use these extras.
NON_INTEL_DELETABLES = {
    "entry",
    "feed",
    "note",
    "tag",
    "detection_rule",
    "automation_rule",
    "intel_report",
    "intelligence_requirement",
}


def test_entity_type_enums_are_canonical():
    for tool, param, values in _enum_params(r"(entity_type|source_type|target_type)"):
        universe = ENTITY_TYPE_UNIVERSE | (NON_INTEL_DELETABLES if tool == "delete_entity" else set())
        _assert_subset(values, universe, f"{tool}.{param}")


def test_relationship_endpoint_types_cover_matrix():
    for tool, param, values in _enum_params(r"(source_type|target_type)"):
        if tool == "link_entities":
            assert set(values) == MATRIX_ENDPOINT_TYPES, f"{tool}.{param} must match relationship-matrix endpoint types"


def test_relationship_verbs_match_matrix():
    for tool, param, values in _enum_params(r"relationship_type"):
        assert set(values) == MATRIX_VERBS, (
            f"{tool}.{param} must match ALLOWED_RELATIONSHIPS verbs "
            f"(missing: {sorted(MATRIX_VERBS - set(values))}, dead: {sorted(set(values) - MATRIX_VERBS)})"
        )


def test_rule_type_enums_are_canonical():
    found_any = False
    for tool, param, values in _enum_params(r"(rule_type|rule_types)"):
        found_any = True
        _assert_subset(values, RULE_TYPES, f"{tool}.{param}")
    # array-typed rule_types params keep the enum on items
    for tool in TOOL_DEFINITIONS:
        for pname, prop in tool.get("input_schema", {}).get("properties", {}).items():
            items = prop.get("items", {})
            if "rule_type" in pname and "enum" in items:
                found_any = True
                _assert_subset(items["enum"], RULE_TYPES, f"{tool['name']}.{pname}[]")
    assert found_any, "expected at least one rule-type enum in the registry"


def test_tlp_enums_are_canonical():
    found_any = False
    for tool, param, values in _enum_params(r"tlp(_marking)?"):
        found_any = True
        _assert_subset(values, TLP_UNIVERSE, f"{tool}.{param}")
        assert "TLP:CLEAR" in values, f"{tool}.{param} must offer TLP:CLEAR (TLP 2.0)"
    assert found_any, "expected at least one TLP enum in the registry"


def test_trigger_type_enum_matches_platform():
    for tool, param, values in _enum_params(r"trigger_type"):
        assert set(values) == set(VALID_TRIGGER_TYPES), (
            f"{tool}.{param} must equal VALID_TRIGGER_TYPES (rules created with other spellings never fire)"
        )


def test_feed_type_enums_match_adapter_registry():
    for tool, param, values in _enum_params(r"feed_type"):
        _assert_subset(values, set(_ADAPTERS) | set(_EXTENDED_ADAPTERS), f"{tool}.{param}")


def test_report_template_enums_are_registered():
    for tool, param, values in _enum_params(r"(template|template_type)"):
        _assert_subset(values, set(REPORT_TEMPLATES), f"{tool}.{param}")


def test_no_bare_content_key_in_tool_entry_dicts():
    """Prompt templates render {{ entry.content_text }}; a dict built with a bare
    "content" key silently sends title-only text to the AI (the May-2026 bug that
    broke six tools). Keep the key out of the prompt-building modules entirely."""
    offenders = []
    for path in (TOOLS_DIR / "extraction.py", TOOLS_DIR / "detection.py"):
        for i, line in enumerate(path.read_text().splitlines(), 1):
            if re.search(r'"content"\s*:', line):
                offenders.append(f"{path.name}:{i}: {line.strip()}")
    assert not offenders, "use 'content_text' (what prompts render), not 'content':\n" + "\n".join(offenders)


def test_full_cli_write_denylist_covers_all_mutating_tools():
    """The full skill CLI's WRITE_TOOLS frozenset is the INTELFEED_READ_ONLY
    boundary. It is generated by scripts/dev/sync_skill_clis.py from the
    registry's ``mutating`` flags; this pins it so a registry change without a
    CLI regen fails loudly (the 2026-08 expansion left 50 mutating tools
    ungated for weeks)."""
    write_tools = set(_cli_assign(_FULL_CLI_PATHS, "WRITE_TOOLS"))
    ungated = MUTATING_TOOLS - write_tools
    assert not ungated, f"mutating tools missing from CLI WRITE_TOOLS (rerun sync_skill_clis.py): {sorted(ungated)}"
    all_names = {t["name"] for t in TOOL_DEFINITIONS}
    dead = write_tools - all_names
    assert not dead, f"CLI WRITE_TOOLS entries not in registry: {sorted(dead)}"


def test_lite_cli_exposes_no_mutating_tools():
    """The lite skill is read-only by construction — its generated TOOLS dict
    must never pick up a mutating tool."""
    lite_tools = set(_cli_assign(_LITE_CLI_PATHS, "TOOLS"))
    leaked = lite_tools & MUTATING_TOOLS
    assert not leaked, f"mutating tools leaked into the lite CLI: {sorted(leaked)}"


def test_every_tool_has_handler_and_coherent_signature():
    """Every registered tool must have a handler whose signature accepts exactly
    what the schema advertises: all schema properties map to parameters (or a
    **kwargs catch-all), and every required-without-default parameter beyond
    (db, user_id) is declared required in the schema."""
    handler_names = set(_TOOL_HANDLERS)
    for tool in TOOL_DEFINITIONS:
        name = tool["name"]
        assert name in handler_names, f"{name} has no registered handler"
        fn = _TOOL_HANDLERS[name]
        sig = inspect.signature(fn)
        params = sig.parameters
        has_var_kw = any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values())
        schema = tool.get("input_schema", {})
        props = set(schema.get("properties", {}))
        required = set(schema.get("required", []))

        if not has_var_kw:
            missing = props - set(params)
            assert not missing, f"{name}: schema params not accepted by handler: {sorted(missing)}"

        for pname, p in params.items():
            if pname in ("db", "user_id", "self") or p.kind in (
                inspect.Parameter.VAR_KEYWORD,
                inspect.Parameter.VAR_POSITIONAL,
            ):
                continue
            if p.default is inspect.Parameter.empty:
                assert pname in required, f"{name}: handler requires '{pname}' but schema doesn't mark it required"
