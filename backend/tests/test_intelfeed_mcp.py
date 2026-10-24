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
    assert "(+30 more)" in text  # cut to the default limit of 10


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


# --- per-tool trimming (shapes taken from a live instance) -------------------------


def _related(i: int, **extra) -> dict:
    return {
        "id": f"3f2b8c1e-2222-4a2b-9c3d-{i:012d}",
        "type": "ttp",
        "technique_id": f"T1{i:03d}",
        "technique_name": f"Technique {i}",
        "description": "Adversaries may " + "abuse things " * 40,
        "detection": "detect " * 100,
        "strength": {"score": 0.5, "tier": "moderate", "articles": 3, "last_seen": "2026-09-10T10:00:00+00:00"},
        "proximity_entries": [{"entry_id": UUID_A, "title": "evidence " * 20}],
        **extra,
    }


def test_pivot_is_one_row_per_related_entity():
    pivot = {
        "entity": {"id": UUID_A, "type": "threat_actor", "name": "APT29", "wikipedia_content": "x " * 900},
        "related_counts": {"ttps": 94},
        "related": {
            "ttps": [_related(i, relationship_type="uses", relationship_confidence="confirmed") for i in range(94)]
        },
    }
    server, _ = new_server({"pivot_entity": pivot})
    text, _ = server.call("pivot_entity", {"entity_type": "threat_actor", "entity_id": UUID_A})
    assert "entity: APT29 (threat_actor)" in text
    assert "id | name | tier | articles | last_seen | relation" in text
    assert "T1000 Technique 0 | moderate | 3 | 2026-09-10 10:00 | uses (confirmed)" in text
    assert f"(+{94 - m.PIVOT_ROWS_PER_TYPE} more)" in text  # the server ignores limit_per_type here
    assert "abuse things" not in text and "evidence" not in text and "wikipedia" not in text
    assert len(text) < 1000


def test_priority_queue_threads_and_entries_share_an_id_column():
    queue = {
        "items": [
            {
                "kind": "thread",
                "score": 9.1,
                "slug": "citrix-zero-day",
                "title": "Citrix",
                "summary": "s",
                "outlets": 15,
                "articles": 21,
                "unread": 21,
                "new_since_opened": 21,
                "folded_articles": 21,
                "url": "/pq?thread=x",
            },
            {
                "kind": "entry",
                "score": 5.3,
                "entry_id": UUID_B,
                "title": "Report",
                "url": "https://x",
                "feed": "CPR",
                "published_at": "2026-09-28 13:55:26+00:00",
                "summary": "<p>text</p>",
                "signals": ["kev_added"],
            },
        ]
        * 14,
        "count": 28,
        "next_cursor": "eyJ" * 30,
        "radar_threshold": 2.1,
    }
    server, _ = new_server({"get_priority_queue": queue})
    text, _ = server.call("call_tool", {"tool": "get_priority_queue", "args": {}})
    header = next(line for line in text.splitlines() if line.strip().startswith("id |"))
    assert header.split(" | ")[:2] == ["  id", "kind"]
    assert "citrix-zero-day | thread" in text and "u1 | entry" in text
    for noise in ("unread", "new_since_opened", "next_cursor", "radar_threshold", "outlets", "https://x"):
        assert noise not in text
    assert "(+18 more)" in text  # cut to the default limit of 10


def test_disclosure_noise_dropped():
    item = {
        "id": UUID_A,
        "victim_id": UUID_B,
        "victim_name": "Knit",
        "group_id": UUID_C,
        "group_name": "Akira",
        "group_color": "akira",
        "sector": "technology",
        "sector_label": "Technology",
        "posted_at": "2026-09-28T14:25:10Z",
        "claimed_data": "We believe " * 30,
        "leak_site_url": "https://www.ransomware.live/id/x",
        "source": "ransomware.live",
        "is_new": True,
    }
    server, _ = new_server(
        {"get_ransomware_disclosures": {"items": [item, dict(item, victim_name="Acme")], "total": 2}}
    )
    text, _ = server.call("call_tool", {"tool": "get_ransomware_disclosures", "args": {"since": 7}})
    assert "victim_id | victim_name | group_id | group_name | sector | posted_at | is_new" in text
    for noise in ("akira |", "Technology", "We believe", "ransomware.live"):
        assert noise not in text


def test_projection_falls_back_on_unexpected_shapes():
    server, _ = new_server({"pivot_entity": {"related": "not a dict"}})
    text, is_error = server.call("pivot_entity", {"entity_type": "threat_actor", "entity_id": UUID_A})
    assert not is_error


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


def test_read_list_matches_registry():
    """READ_ONLY_TOOLS is reviewed by hand; a new registry read tool fails here until someone adds it."""
    registry_reads = {t["name"] for t in TOOL_DEFINITIONS if t.get("mutating") is False} - m.PERSISTING_READ_TOOLS
    assert m.READ_ONLY_TOOLS == registry_reads, (
        f"review, then add to READ_ONLY_TOOLS: {sorted(registry_reads - m.READ_ONLY_TOOLS)}; "
        f"remove (gone or now a write): {sorted(m.READ_ONLY_TOOLS - registry_reads)}"
    )


def test_unreviewed_or_unflagged_tools_blocked():
    server, fake = new_server()
    fake._registry["get_brand_new_thing"] = {"name": "get_brand_new_thing", "mutating": False, "input_schema": {}}
    with pytest.raises(m.ToolError, match="reviewed read-only list"):
        server.call("call_tool", {"tool": "get_brand_new_thing", "args": {}})
    # a reviewed tool still needs an explicit mutating: false from the registry
    fake._registry["get_dashboard_stats"] = {
        k: v for k, v in fake._registry["get_dashboard_stats"].items() if k != "mutating"
    }
    with pytest.raises(m.ToolError):
        server.call("call_tool", {"tool": "get_dashboard_stats", "args": {}})
    assert fake.calls == []


def test_redirects_never_carry_the_token():
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    seen = {}

    class Elsewhere(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            seen["authorization"] = self.headers.get("Authorization")
            self.send_response(200)
            self.end_headers()

    class Api(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", f"http://localhost:{elsewhere.server_port}/collect")
            self.send_header("Content-Length", "0")
            self.end_headers()

    elsewhere = ThreadingHTTPServer(("127.0.0.1", 0), Elsewhere)
    api = ThreadingHTTPServer(("127.0.0.1", 0), Api)
    for srv in (elsewhere, api):
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        client = m.IntelFeed(api_url=f"http://127.0.0.1:{api.server_port}", username="u", password="p")
        client._access = "secret-token"
        with pytest.raises(m.ToolError, match="redirect"):
            client._http("GET", "/api/tools/tools")
        assert "authorization" not in seen
    finally:
        elsewhere.shutdown()
        api.shutdown()


def test_plain_http_to_another_host_is_refused(monkeypatch):
    monkeypatch.delenv("INTELFEED_ALLOW_INSECURE_HTTP", raising=False)
    with pytest.raises(m.ToolError, match="https://"):
        m.IntelFeed(api_url="http://intel.example.com", username="u", password="p").execute("get_dashboard_stats", {})
    for ok in ("https://intel.example.com", "http://localhost:8000", "http://127.0.0.1:8000"):
        assert m.IntelFeed(api_url=ok).config_error == ""
    monkeypatch.setenv("INTELFEED_ALLOW_INSECURE_HTTP", "1")
    assert m.IntelFeed(api_url="http://intel.example.com").config_error == ""


def test_write_list_can_narrow_but_not_extend():
    env = dict(os.environ, INTELFEED_MCP_WRITE_TOOLS="create_note,delete_feed,merge_threat_actors")
    code = "import intelfeed_mcp as m; print(','.join(m.WRITE_TOOLS))"
    proc = subprocess.run(
        [sys.executable, "-c", code], cwd=_MCP_DIR, env=env, capture_output=True, text=True, timeout=30
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "create_note"
    assert "delete_feed" in proc.stderr  # reported, not silently dropped


def test_dotenv_quotes(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("A_QUOTED=\"p#ss word # not a comment\"\nA_PLAIN=abc # a comment\nA_SINGLE='x y'\n")
    for key in ("A_QUOTED", "A_PLAIN", "A_SINGLE"):
        monkeypatch.delenv(key, raising=False)
    m.load_dotenv(env_file)
    assert os.environ["A_QUOTED"] == "p#ss word # not a comment"
    assert os.environ["A_PLAIN"] == "abc"
    assert os.environ["A_SINGLE"] == "x y"


def test_call_log_names_arguments_but_not_values(capsys):
    server, _ = new_server({"search_entries": search_result(1)})
    server.call("search_entries", {"query": "private-investigation-term"})
    err = capsys.readouterr().err
    assert "search_entries(limit, query)" in err
    assert "private-investigation-term" not in err


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
    assert args["limit_per_type"] == m.PIVOT_ROWS_PER_TYPE


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


def test_supplied_token_is_the_whole_credential(monkeypatch):
    """The backend's Claude CLI provider runs this server with a short-lived,
    read-only INTELFEED_TOKEN. It must be used as-is: never refreshed, and never
    swapped for a password login when the API refuses it."""
    monkeypatch.setenv("INTELFEED_TOKEN", "agent-token")
    monkeypatch.setenv("INTELFEED_USERNAME", "admin")
    monkeypatch.setenv("INTELFEED_PASSWORD", "hunter2")
    client = m.IntelFeed(api_url="http://localhost:8000")
    assert client._access == "agent-token"
    with pytest.raises(m.ToolError, match="refused this session's token"):
        client._renew()
