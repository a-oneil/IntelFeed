"""Tests for the MCP server in intelfeed-mcp/ (stdlib-only; no DB, no network).

A fake IntelFeed stands in for the API: it serves the real tool registry
(TOOL_DEFINITIONS) and canned tool results, and records every call.
"""

import importlib.util
import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from app.tools import MUTATING_TOOLS, TOOL_DEFINITIONS

_MCP_DIR = Path(__file__).resolve().parents[2] / "intelfeed-mcp"
if not (_MCP_DIR / "intelfeed_mcp.py").is_file():
    # The api container only mounts backend/; the MCP server sits at the repo root.
    pytest.skip("intelfeed-mcp/ not available in this checkout", allow_module_level=True)

_spec = importlib.util.spec_from_file_location("intelfeed_mcp", _MCP_DIR / "intelfeed_mcp.py")
m = importlib.util.module_from_spec(_spec)
sys.modules["intelfeed_mcp"] = m
_spec.loader.exec_module(m)

UUID_A = "3f2b8c1e-1111-4a2b-9c3d-000000000001"
UUID_B = "3f2b8c1e-1111-4a2b-9c3d-000000000002"
UUID_C = "3f2b8c1e-1111-4a2b-9c3d-000000000003"


def approx_tokens(text: str) -> int:
    return len(text) // 4


class FakeIntelFeed(m.IntelFeed):
    """Real registry, canned results, every call recorded."""

    def __init__(self, results: dict | None = None) -> None:
        super().__init__(api_url="http://fake", username="", password="")
        self.calls: list[tuple[str, dict]] = []
        self.results = results or {}
        self._registry = {t["name"]: t for t in TOOL_DEFINITIONS}
        self.registry_source = "test"

    def execute(self, tool: str, args: dict) -> str:
        self.calls.append((tool, args))
        r = self.results.get(tool, {"ok": True})
        r = r(args) if callable(r) else r
        return r if isinstance(r, str) else json.dumps(r)


def new_server(results: dict | None = None):
    fake = FakeIntelFeed(results)
    return m.Server(fake), fake


def search_result(n: int = 3) -> dict:
    return {
        "total": 120,
        "limit": n,
        "offset": 0,
        "entries": [
            {
                "id": f"3f2b8c1e-1111-4a2b-9c3d-{i:012d}",
                "title": f"Qilin hits hospital #{i}",
                "summary": "<p>The <b>Qilin</b> gang &amp; friends claimed another victim.</p>" + " filler" * 60,
                "feed_title": "BleepingComputer",
                "published_at": "2026-09-24T15:44:12.123456+00:00",
                "url": f"https://example.com/{i}",
            }
            for i in range(1, n + 1)
        ],
    }


# --- tool list and skills --------------------------------------------------------


def test_tool_list_is_small():
    server, _ = new_server()
    size = approx_tokens(json.dumps(server.tools))
    assert len(server.tools) <= 10
    # The point of the server: the fixed list stays far below the registry's ~27k tokens.
    assert size < 2600, f"tool list is ~{size} tokens"


def test_load_skill_enum_lists_every_skill():
    server, _ = new_server()
    tool = next(t for t in server.tools if t["name"] == "load_skill")
    assert set(tool["inputSchema"]["properties"]["name"]["enum"]) == set(server.skills)
    for name in server.skills:
        assert name in tool["description"]


def test_writes_hidden_by_default():
    server, _ = new_server()
    assert "write_action" not in [t["name"] for t in server.tools]
    assert "writes" not in server.skills


def test_skills_name_real_tools_and_only_reads():
    registry = {t["name"] for t in TOOL_DEFINITIONS}
    core = {t["name"] for t in m.CORE_TOOLS}
    for skill in m.load_skills().values():
        for tool in skill["tools"]:
            assert tool in core or tool in registry, f"skill {skill['name']}: unknown tool {tool}"
            assert tool not in MUTATING_TOOLS, f"skill {skill['name']} lists write tool {tool}"


def test_writes_skill_and_write_allowlist_are_mutating_tools():
    skills_dir = m.SKILLS_DIR / "writes.md"
    front = skills_dir.read_text().split("---")[1]
    listed = next(line.split(":", 1)[1] for line in front.splitlines() if line.startswith("tools:"))
    assert {t.strip() for t in listed.split(",")} == set(m.DEFAULT_WRITE_TOOLS)
    assert set(m.DEFAULT_WRITE_TOOLS) <= MUTATING_TOOLS


def test_persisting_read_tools_exist():
    registry = {t["name"] for t in TOOL_DEFINITIONS}
    assert m.PERSISTING_READ_TOOLS <= registry, sorted(m.PERSISTING_READ_TOOLS - registry)


def test_core_tools_map_to_registry_params():
    """Core tools forward their arguments to registry tools of the same name; keep the schemas aligned."""
    registry = {t["name"]: t for t in TOOL_DEFINITIONS}
    for core in m.CORE_TOOLS:
        if core["name"] in registry:
            core_props = core["inputSchema"]["properties"]
            reg_props = registry[core["name"]]["input_schema"]["properties"]
            assert set(core_props) <= set(reg_props), f"{core['name']}: {sorted(set(core_props) - set(reg_props))}"
            for pname, spec in core_props.items():
                if "enum" in spec and "enum" in reg_props[pname]:
                    extra = set(spec["enum"]) - set(reg_props[pname]["enum"])
                    assert not extra, f"{core['name']}.{pname}: {sorted(extra)} not accepted by the registry"
    for tool, param in m.PROFILE_TOOLS.values():
        assert param in registry[tool]["input_schema"]["properties"], f"{tool} has no {param}"


def test_skills_stay_small():
    server, _ = new_server()
    for name in server.skills:
        size = approx_tokens(server.load_skill(name))
        assert size < 1100, f"{name} is ~{size} tokens"


def test_skill_shows_signatures():
    server, _ = new_server()
    text = server.load_skill("ransomware")
    assert "get_ransomware_stats(days:int)" in text
    assert "call_tool" in text
    assert "Available:" in server.load_skill("nope")


# --- result shaping --------------------------------------------------------------


def test_search_result_is_compact():
    server, fake = new_server({"search_entries": search_result(3)})
    text, is_error = server.call("search_entries", {"query": "qilin"})
    assert not is_error
    assert UUID_A not in text and "u1" in text  # UUIDs become handles
    assert "2026-09-24 15:44" in text  # dates shortened
    assert "<p>" not in text and "The Qilin gang & friends" in text  # HTML stripped, entities decoded
    assert "example.com" not in text  # urls dropped inside lists
    assert "id | title | summary | feed_title | published_at" in text  # table
    assert fake.calls[0] == ("search_entries", {"query": "qilin", "limit": 10})


def test_handles_round_trip():
    server, fake = new_server(
        {"search_entries": search_result(1), "get_entry": {"id": UUID_A, "title": "x", "content": "body"}}
    )
    server.call("search_entries", {"query": "qilin"})
    server.call("get_entry", {"entry_id": "u1"})
    assert fake.calls[-1] == ("get_entry", {"entry_id": UUID_A})


def test_unknown_handle():
    server, _ = new_server()
    with pytest.raises(m.ToolError, match="search again"):
        server.call("get_entry", {"entry_id": "u99"})


def test_long_article_is_paged():
    long_text = "\n".join(f"Paragraph {i}: " + "word " * 80 for i in range(60))
    entry = {
        "id": UUID_A,
        "title": "Big report",
        "published_at": "2026-09-20 00:00:00",
        "content": long_text,
        "threat_actors": [{"id": UUID_B, "name": "Qilin"}],
        "cves": [],
        "author": None,
    }
    server, _ = new_server({"get_entry": entry})
    text, _ = server.call("get_entry", {"entry_id": UUID_A})
    assert len(text) <= m.RESULT_CHARS + 200
    assert "title: Big report" in text
    assert "published_at: 2026-09-20\n" in text
    assert text.index("Qilin") < text.index("Paragraph 0")  # facts before the long text
    assert "cves" not in text and "author" not in text  # empty values dropped
    assert 'read_more(ref="r1", page=1..' in text
    page2 = server.read_more("r1", 2)
    assert "[page 2/" in page2
    assert "… [+" not in page2  # the stored copy is untrimmed


def test_long_lists_capped():
    rows = [{"id": f"3f2b8c1e-1111-4a2b-9c3d-{i:012d}", "name": f"T{i}"} for i in range(40)]
    server, _ = new_server({"get_trending_entities": {"trending": rows}})
    text, _ = server.call("get_trending_entities", {"entity_type": "malware"})
    assert "(+15 more)" in text


def test_error_result_flagged():
    server, _ = new_server({"get_entry": {"error": "Entry not found"}})
    text, is_error = server.call("get_entry", {"entry_id": UUID_A})
    assert is_error and "Entry not found" in text


def test_entity_search_noise_removed():
    ttp = {
        "id": UUID_A,
        "type": "ttp",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "description": "long " * 200,
        "detection": "detect " * 200,
        "platforms": ["Windows"],
        "mitre_url": "https://attack.mitre.org/techniques/T1059",
        "is_deprecated": False,
        "article_count": 12,
    }
    server, _ = new_server({"search_entities": {"results": [ttp, dict(ttp, id=UUID_B)], "count": 2}})
    text, _ = server.call("search_entities", {"query": "T1059"})
    assert "detect detect" not in text
    assert "mitre.org" not in text
    assert "is_deprecated" not in text
    assert len(text) < 900


def test_nested_render():
    server, _ = new_server()
    text, _ = server.format_result(
        json.dumps(
            {
                "name": "LockBit",
                "counts": {"victims": 12, "sectors": 3},
                "flag": True,
                "rate": 0.123456,
                "rows": [{"a": 1, "b": {"c": "x"}}, {"a": 2, "b": {"c": "y"}}],
            }
        )
    )
    assert "name: LockBit" in text
    assert "flag: yes" in text
    assert "rate: 0.123" in text
    assert "a | b.c" in text


def test_paginate_respects_size():
    text = "\n".join("x" * 50 for _ in range(500))
    pages = m.paginate(text, 1000)
    assert all(len(p) <= 1000 for p in pages)
    assert "\n".join(pages) == text


# --- arguments -------------------------------------------------------------------


def test_missing_required_shows_usage():
    server, _ = new_server()
    with pytest.raises(m.ToolError, match=r"get_ransomware_victim\(victim_id\*:str\)"):
        server.call("call_tool", {"tool": "get_ransomware_victim", "args": {}})


def test_enum_case_and_types_fixed():
    server, fake = new_server()
    server.call("call_tool", {"tool": "get_campaigns", "args": {"status": "ACTIVE", "limit": "5"}})
    assert fake.calls[-1] == ("get_campaigns", {"status": "active", "limit": 5})


def test_args_as_json_string():
    server, fake = new_server()
    server.call("call_tool", {"tool": "get_ransomware_stats", "args": '{"days": 30}'})
    assert fake.calls[-1] == ("get_ransomware_stats", {"days": 30})


def test_unknown_args_ignored_with_note():
    server, fake = new_server()
    text, _ = server.call("call_tool", {"tool": "get_ransomware_stats", "args": {"days": 30, "colour": "red"}})
    assert fake.calls[-1] == ("get_ransomware_stats", {"days": 30})
    assert "ignored unknown argument(s) ['colour']" in text


def test_bad_enum():
    server, _ = new_server()
    with pytest.raises(m.ToolError, match="must be one of"):
        server.call("call_tool", {"tool": "get_campaigns", "args": {"status": "open"}})


# --- safety ----------------------------------------------------------------------


@pytest.mark.parametrize("tool", sorted(MUTATING_TOOLS))
def test_every_mutating_tool_blocked(tool):
    server, fake = new_server()
    with pytest.raises(m.ToolError, match="changes data"):
        server.call("call_tool", {"tool": tool, "args": {}})
    assert fake.calls == []


@pytest.mark.parametrize("tool", sorted(m.PERSISTING_READ_TOOLS))
def test_persisting_ai_tools_blocked(tool):
    server, fake = new_server()
    with pytest.raises(m.ToolError):
        server.call("call_tool", {"tool": tool, "args": {"entry_id": UUID_A}})
    assert fake.calls == []


def test_write_action_unavailable_by_default():
    server, fake = new_server()
    with pytest.raises(m.ToolError):
        server.call("write_action", {"tool": "create_note", "args": {}})
    assert fake.calls == []


def test_unknown_tool():
    server, _ = new_server()
    with pytest.raises(m.ToolError, match="No tool named"):
        server.call("call_tool", {"tool": "get_ransomware", "args": {}})


def test_missing_credentials_message():
    with pytest.raises(m.ToolError, match="credentials are not configured"):
        m.IntelFeed(api_url="http://127.0.0.1:9", username="", password="").execute("get_dashboard_stats", {})


# --- entity resolution -----------------------------------------------------------


def _entities(args):
    q = args["query"].lower()
    rows = [
        {"id": UUID_A, "type": "threat_actor", "name": "APT29", "aliases": ["Cozy Bear", "Midnight Blizzard"]},
        {"id": UUID_B, "type": "threat_actor", "name": "APT29 Subgroup"},
        {"id": UUID_C, "type": "malware", "name": "Cozy Loader"},
    ]
    return {"results": [r for r in rows if q.split()[0] in json.dumps(r).lower()]}


def test_name_resolves_to_id():
    server, fake = new_server({"search_entities": _entities, "get_threat_actor": {"id": UUID_A, "name": "APT29"}})
    server.call("get_profile", {"entity_type": "threat_actor", "id": "APT29"})
    assert fake.calls[-1] == ("get_threat_actor", {"actor_id": UUID_A})


def test_alias_resolves():
    server, fake = new_server({"search_entities": _entities, "get_threat_actor": {"id": UUID_A}})
    server.call("get_profile", {"entity_type": "threat_actor", "id": "midnight blizzard"})
    assert fake.calls[-1] == ("get_threat_actor", {"actor_id": UUID_A})


def test_ambiguous_name_lists_choices():
    server, _ = new_server({"search_entities": _entities})
    with pytest.raises(m.ToolError, match="APT29 Subgroup"):
        server.call("get_profile", {"entity_type": "threat_actor", "id": "apt"})


def test_public_ids_pass_through():
    server, fake = new_server()
    server.call("get_profile", {"entity_type": "cve", "id": "cve-2025-1234"})
    server.call("get_profile", {"entity_type": "ttp", "id": "t1059.001"})
    assert fake.calls == [("get_cve", {"cve_id": "CVE-2025-1234"}), ("get_ttp", {"ttp_id": "T1059.001"})]


def test_pivot_resolves_cve_to_uuid():
    server, fake = new_server(
        {"search_entities": lambda a: {"results": [{"id": UUID_C, "type": "cve", "cve_id": "CVE-2025-1234"}]}}
    )
    server.call("pivot_entity", {"entity_type": "cve", "entity_id": "CVE-2025-1234"})
    tool, args = fake.calls[-1]
    assert tool == "pivot_entity"
    assert args["entity_id"] == UUID_C
    assert args["limit_per_type"] == 8


# --- protocol --------------------------------------------------------------------


def test_handshake():
    server, _ = new_server()
    out = io.StringIO()
    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "ping"},
        {"jsonrpc": "2.0", "id": 4, "method": "bogus"},
    ]
    m.Transport(server, out=out).serve(io.StringIO("\n".join(map(json.dumps, messages)) + "\n"))
    replies = [json.loads(line) for line in out.getvalue().splitlines()]
    assert [r["id"] for r in replies] == [1, 2, 3, 4]
    assert replies[0]["result"]["protocolVersion"] == "2025-03-26"
    assert "tools" in replies[0]["result"]["capabilities"]
    assert len(replies[1]["result"]["tools"]) == len(m.CORE_TOOLS)
    assert replies[3]["error"]["code"] == -32601


@pytest.mark.timeout(60)
def test_stdio_subprocess():
    """The real script over real pipes: only JSON-RPC on stdout, tool errors come back as results."""
    env = dict(os.environ, INTELFEED_USERNAME="", INTELFEED_PASSWORD="", INTELFEED_API_URL="http://127.0.0.1:9")
    msgs = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "load_skill", "arguments": {"name": "iocs"}},
        },
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "search_entries", "arguments": {"query": "x"}},
        },
    ]
    proc = subprocess.run(
        [sys.executable, str(_MCP_DIR / "intelfeed_mcp.py")],
        input="\n".join(map(json.dumps, msgs)) + "\n",
        capture_output=True,
        text=True,
        timeout=50,
        env=env,
    )
    replies = {r["id"]: r for r in map(json.loads, proc.stdout.splitlines())}
    assert set(replies) == {1, 2, 3}
    assert "search_observables" in replies[2]["result"]["content"][0]["text"]  # registry.json fallback
    assert replies[3]["result"]["isError"]
    assert "credentials are not configured" in replies[3]["result"]["content"][0]["text"]
