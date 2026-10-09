#!/usr/bin/env python3
"""Regenerate the skill CLIs' TOOLS dicts from the backend agent-tool registry.

The two skill CLIs (intelfeed-skill, intelfeed-lite-skill) carry hand-readable
copies of the backend tool definitions. Historically these were maintained by
hand and drifted badly. This script makes the backend registry the single
source of truth: it fetches the live definitions and rewrites each CLI's
`TOOLS: dict[str, dict] = {...}` block in place, leaving the rest of the file
untouched.

The full CLI gets every registry tool. The lite CLI gets every non-mutating
tool except the compute-heavy ones listed in LITE_EXCLUDE (AI invocation and
document export are outside its read-only retrieval charter).

The full CLI's WRITE_TOOLS denylist (the INTELFEED_READ_ONLY gate) is also
generated here: every registry tool flagged ``mutating``, plus the
EXTRA_WRITE_TOOLS below. Before this it was hand-maintained and silently
missed 50 of 79 mutating tools after the 2026-08 registry expansion.

It also writes intelfeed-mcp/registry.json, the MCP server's offline copy of
the registry (the server reads the live one from /api/tools/tools when it can).

Usage (stack running, creds in env like the CLIs themselves):
    INTELFEED_API_URL=http://localhost:8000 python3 scripts/dev/sync_skill_clis.py
    python3 scripts/dev/sync_skill_clis.py --check   # exit 1 if anything would change
    python3 scripts/dev/sync_skill_clis.py --from-file registry.json
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import sys
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]  # scripts/dev/<this file> -> repo root
FULL_CLI = REPO / "intelfeed-skill" / "scripts" / "intelfeed_cli.py"
LITE_CLI = REPO / "intelfeed-lite-skill" / "scripts" / "intelfeed_cli.py"
MCP_REGISTRY = REPO / "intelfeed-mcp" / "registry.json"

# Read-only tools deliberately excluded from the lite (retrieval-only) skill:
# they invoke AI providers or build export documents rather than retrieve data.
LITE_EXCLUDE = {
    "build_detection_summary",
    "export_attack_layer",
    "export_campaign",
    "extract_cves",
    "extract_malware",
    "extract_threat_actors",
    "extract_ttps",
    "generate_detection_rules",
    "run_ai_task",
    "validate_detection_rule",
}

# Gated in read-only mode even though the registry calls them non-mutating:
# they invoke AI extraction/tasks that persist new or linked entities as a
# side effect, so the read-only copilot must not reach them.
EXTRA_WRITE_TOOLS = {
    "extract_cves",
    "extract_malware",
    "extract_threat_actors",
    "extract_ttps",
    "run_ai_task",
}

TYPE_MAP = {
    "string": "str",
    "integer": "int",
    "number": "float",
    "boolean": "bool",
    "object": "dict",
}


def fetch_registry(api_url: str) -> list[dict]:
    username = os.environ.get("INTELFEED_USERNAME", "")
    password = os.environ.get("INTELFEED_PASSWORD", "")
    if not username or not password:
        sys.exit("Error: INTELFEED_USERNAME and INTELFEED_PASSWORD must be set.")

    def post(path: str, body: dict, headers: dict | None = None) -> dict:
        req = urllib.request.Request(
            f"{api_url}{path}",
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json", **(headers or {})},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read())

    token = post("/api/auth/login", {"username": username, "password": password})["access_token"]
    req = urllib.request.Request(f"{api_url}/api/tools/tools", headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read())


def schema_type(prop: dict) -> str:
    t = prop.get("type", "string")
    if t == "array":
        item_t = TYPE_MAP.get(prop.get("items", {}).get("type", "string"), "str")
        return f"list[{item_t}]"
    return TYPE_MAP.get(t, "str")


def to_cli_params(input_schema: dict) -> dict:
    required = set(input_schema.get("required", []))
    params: dict[str, dict] = {}
    for name, prop in input_schema.get("properties", {}).items():
        p: dict = {"type": schema_type(prop)}
        if name in required:
            p["required"] = True
        else:
            p["default"] = prop.get("default")
        if "enum" in prop:
            p["enum"] = list(prop["enum"])
        params[name] = p
    return params


def fmt(value, indent: int) -> str:
    """Render a value as Python source, wrapping long lists one-per-line."""
    pad = " " * indent
    if isinstance(value, dict):
        if not value:
            return "{}"
        lines = ["{"]
        for k, v in value.items():
            lines.append(f'{pad}    "{k}": {fmt(v, indent + 4)},')
        lines.append(pad + "}")
        return "\n".join(lines)
    if isinstance(value, list):
        one_line = "[" + ", ".join(repr(v) for v in value) + "]"
        if len(one_line) + indent <= 100:
            return one_line
        lines = ["["]
        for v in value:
            lines.append(f"{pad}    {v!r},")
        lines.append(pad + "]")
        return "\n".join(lines)
    if isinstance(value, str) and len(value) + indent > 100:
        # Wrap long descriptions as adjacent string literals.
        words, chunks, cur = value.split(" "), [], ""
        for w in words:
            if len(cur) + len(w) + 1 > 88 and cur:
                chunks.append(cur)
                cur = w
            else:
                cur = f"{cur} {w}".strip()
        if cur:
            chunks.append(cur)
        if len(chunks) == 1:
            return repr(value)
        inner = "\n".join(
            f"{pad}    {json.dumps(c + (' ' if i < len(chunks) - 1 else ''))}" for i, c in enumerate(chunks)
        )
        return "(\n" + inner + "\n" + pad + ")"
    return repr(value)


def build_tools_block(tools: list[dict]) -> str:
    body: dict[str, dict] = {}
    for t in sorted(tools, key=lambda t: t["name"]):
        body[t["name"]] = {
            "description": t.get("description", ""),
            "params": to_cli_params(t.get("input_schema", {})),
        }
    return "TOOLS: dict[str, dict] = " + fmt(body, 0)


def build_write_tools_block(registry: list[dict]) -> str:
    names = {t["name"] for t in registry if t.get("mutating")} | EXTRA_WRITE_TOOLS
    gone = EXTRA_WRITE_TOOLS - {t["name"] for t in registry}
    if gone:
        sys.exit(f"Error: EXTRA_WRITE_TOOLS not in registry (remove them?): {sorted(gone)}")
    lines = ["WRITE_TOOLS: frozenset[str] = frozenset(", "    {"]
    lines += [f'        "{n}",' for n in sorted(names)]
    lines += ["    }", ")"]
    return "\n".join(lines)


def build_mcp_registry(registry: list[dict]) -> str:
    keep = ("name", "description", "input_schema", "mutating")
    tools = [{k: t[k] for k in keep if k in t} for t in sorted(registry, key=lambda t: t["name"])]
    return json.dumps(tools, indent=1, ensure_ascii=False) + "\n"


def write_if_changed(path: Path, text: str, check: bool) -> bool:
    if path.is_file() and path.read_text() == text:
        return False
    if not check:
        path.write_text(text)
    return True


def splice(path: Path, block: str, check: bool, target: str = "TOOLS") -> bool:
    src = path.read_text()
    tree = ast.parse(src)
    node = next(
        (n for n in ast.walk(tree) if isinstance(n, ast.AnnAssign) and getattr(n.target, "id", None) == target),
        None,
    )
    if node is None:
        sys.exit(f"Error: no `{target}: ... = ...` assignment found in {path}")
    lines = src.splitlines(keepends=True)
    new_src = "".join(lines[: node.lineno - 1]) + block + "\n" + "".join(lines[node.end_lineno :])
    if new_src == src:
        return False
    if not check:
        path.write_text(new_src)
    return True


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="report drift, change nothing, exit 1 on drift")
    ap.add_argument("--from-file", help="read registry JSON from a file instead of the API")
    args = ap.parse_args()

    if args.from_file:
        registry = json.loads(Path(args.from_file).read_text())
    else:
        api_url = os.environ.get("INTELFEED_API_URL", "http://localhost:8000").rstrip("/")
        registry = fetch_registry(api_url)

    lite_tools = [t for t in registry if not t.get("mutating") and t["name"] not in LITE_EXCLUDE]

    drift = False
    for path, tools in ((FULL_CLI, registry), (LITE_CLI, lite_tools)):
        changed = splice(path, build_tools_block(tools), args.check)
        drift = drift or changed
        state = "drifted" if (changed and args.check) else ("updated" if changed else "in sync")
        print(f"{path.relative_to(REPO)}: {len(tools)} tools — {state}")

    wt_block = build_write_tools_block(registry)
    changed = splice(FULL_CLI, wt_block, args.check, target="WRITE_TOOLS")
    drift = drift or changed
    state = "drifted" if (changed and args.check) else ("updated" if changed else "in sync")
    print(f"{FULL_CLI.relative_to(REPO)}: WRITE_TOOLS {wt_block.count(',')} tools — {state}")

    changed = write_if_changed(MCP_REGISTRY, build_mcp_registry(registry), args.check)
    drift = drift or changed
    state = "drifted" if (changed and args.check) else ("updated" if changed else "in sync")
    print(f"{MCP_REGISTRY.relative_to(REPO)}: {len(registry)} tools — {state}")

    # Both files must still parse.
    if not args.check:
        for path in (FULL_CLI, LITE_CLI):
            ast.parse(path.read_text())

    if args.check and drift:
        sys.exit(1)


if __name__ == "__main__":
    main()
