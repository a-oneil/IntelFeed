"""MCP handle round-trips using the shipped registry; no API or database imports."""

import importlib.util
import json
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

_MCP_DIR = Path(__file__).resolve().parents[2] / "intelfeed-mcp"
if not (_MCP_DIR / "intelfeed_mcp.py").is_file():
    pytest.skip("intelfeed-mcp/ not available in this checkout", allow_module_level=True)

_spec = importlib.util.spec_from_file_location("mcp_handle_tests", _MCP_DIR / "intelfeed_mcp.py")
m = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = m
_spec.loader.exec_module(m)

UUID_A = "3f2b8c1e-1111-4a2b-9c3d-000000000001"


@pytest.mark.parametrize(
    ("tool", "param", "value", "expected"),
    [
        ("get_observable", "observable", "u1", UUID_A),
        ("get_sector", "sector", "u1", UUID_A),
        ("sector_victims", "sector", "u1", UUID_A),
        ("who_targets_sector", "sector", "u1", UUID_A),
        ("set_target_sector", "sector", "u1", UUID_A),
        ("get_coverage_workspace", "entity_key", "u1", UUID_A),
        ("merge_entities", "keeper", "u1", UUID_A),
        ("merge_entities", "merge", ["u1", "literal name"], [UUID_A, "literal name"]),
        ("remove_entity_aliases", "entity", "u1", UUID_A),
    ],
)
def test_registry_identifier_parameters_resolve_handles(monkeypatch, tool, param, value, expected):
    monkeypatch.setattr(m, "PROPOSE_WRITES", True)
    client = m.IntelFeed(api_url="http://unused", username="", password="")
    client._registry = {t["name"]: t for t in json.loads((_MCP_DIR / "registry.json").read_text())}
    client.execute = Mock(return_value='{"ok": true}')
    server = m.Server(client)
    assert server.handles.short(UUID_A) == "u1"

    required_values = {
        "entity_type": "threat_actor",
        "entity_id": UUID_A,
        "keeper": UUID_A,
        "merge": ["literal name"],
        "aliases": ["literal alias"],
    }
    args = {
        key: required_values[key] for key in client._registry[tool]["input_schema"].get("required", []) if key != param
    }
    args[param] = value
    server.run_registry_tool(tool, args, write=client.is_allowed_write(tool))

    called_tool, called_args = client.execute.call_args.args
    assert called_tool == tool
    assert called_args[param] == expected


def test_handles_preserve_free_text_and_resolve_nested_ids():
    handles = m.Handles()
    handles.short(UUID_A)
    assert handles.resolve({"query": "u1", "tags": ["u99"], "filters": {"feed_id": "u1", "q": "u99"}}) == {
        "query": "u1",
        "tags": ["u99"],
        "filters": {"feed_id": UUID_A, "q": "u99"},
    }


def test_unknown_id_handle_requires_a_new_search():
    with pytest.raises(m.ToolError, match="Unknown id handle"):
        m.Handles().resolve({"entry_id": "u99"})
