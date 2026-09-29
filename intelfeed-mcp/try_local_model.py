#!/usr/bin/env python3
"""Ask a local model questions through intelfeed_mcp.py, the way an MCP host (LM Studio) would.

Starts the MCP server over stdio, hands its tools to a model behind an OpenAI-compatible
/v1/chat/completions endpoint, runs the tool calls the model makes, and prints every call
with the prompt size the model server reports — so you can see what a question costs.

    python3 try_local_model.py "What is Qilin up to this month?"
    python3 try_local_model.py            # a few built-in questions
    python3 try_local_model.py --yes ...  # don't ask before write_action (only exists with writes enabled)

LLM_BASE_URL defaults to LM Studio (http://localhost:1234/v1); Ollama is http://localhost:11434/v1.
LLM_MODEL defaults to the first model LM Studio reports as loaded. Both can go in .env.
Stdlib only.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))


def load_dotenv(path: Path) -> None:
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                os.environ.setdefault(k.strip(), v.split(" #", 1)[0].strip().strip('"').strip("'"))


load_dotenv(HERE / ".env")
BASE = os.environ.get("LLM_BASE_URL", "http://localhost:1234/v1").rstrip("/")
MAX_ROUNDS = 12
QUESTIONS = [
    "What do we know about APT29 lately?",
    "Give me a quick ransomware picture for the last 30 days.",
    "How worried should I be about CVE-2025-53770?",
]


class McpClient:
    def __init__(self) -> None:
        self.proc = subprocess.Popen(
            [sys.executable, str(HERE / "intelfeed_mcp.py")],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
        self._id = 0
        self.log: list[str] = []
        threading.Thread(target=self._drain_stderr, daemon=True).start()
        init = self.request(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "try_local_model", "version": "1"},
            },
        )
        self.instructions = init.get("instructions", "")
        self.notify("notifications/initialized")
        self.tools = self.request("tools/list")["tools"]

    def _drain_stderr(self) -> None:
        for line in self.proc.stderr:
            self.log.append(line.rstrip())

    def notify(self, method: str) -> None:
        self.proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": method}) + "\n")
        self.proc.stdin.flush()

    def request(self, method: str, params: dict | None = None) -> dict:
        self._id += 1
        self.proc.stdin.write(
            json.dumps({"jsonrpc": "2.0", "id": self._id, "method": method, "params": params or {}}) + "\n"
        )
        self.proc.stdin.flush()
        while True:
            msg = json.loads(self.proc.stdout.readline())
            if msg.get("id") == self._id:
                if "error" in msg:
                    raise RuntimeError(msg["error"])
                return msg["result"]

    def call(self, name: str, args: dict) -> tuple[str, bool]:
        r = self.request("tools/call", {"name": name, "arguments": args})
        return r["content"][0]["text"], r.get("isError", False)

    def close(self) -> None:
        self.proc.stdin.close()
        self.proc.wait(timeout=30)


def pick_model() -> str:
    if os.environ.get("LLM_MODEL"):
        return os.environ["LLM_MODEL"]
    try:  # LM Studio lists load state; other servers only list models
        with urllib.request.urlopen(BASE.removesuffix("/v1") + "/api/v0/models", timeout=10) as r:
            for m in json.load(r)["data"]:
                if m.get("state") == "loaded" and m.get("type") in ("llm", "vlm"):
                    return m["id"]
    except (OSError, ValueError, KeyError):
        pass
    try:
        with urllib.request.urlopen(f"{BASE}/models", timeout=10) as r:
            return json.load(r)["data"][0]["id"]
    except (OSError, ValueError, KeyError, IndexError):
        sys.exit(f"No model found at {BASE}: load one, or set LLM_MODEL / LLM_BASE_URL")


def chat(model: str, messages: list[dict], tools: list[dict]) -> dict:
    body = {"model": model, "messages": messages, "tools": tools, "tool_choice": "auto", "temperature": 0.2}
    req = urllib.request.Request(
        f"{BASE}/chat/completions",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=900) as r:
        return json.load(r)


def confirm_write(args: dict) -> bool:
    print(f"\n[confirm] the model wants write_action {args.get('tool', '?')} {json.dumps(args.get('args', {}))}")
    try:
        return input("Proceed? [y/N] ").strip().lower() in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        return False


def ask(client: McpClient, model: str, question: str, auto_confirm: bool = False) -> dict:
    system = (HERE / "system_prompt.md").read_text(encoding="utf-8")
    tools = [
        {
            "type": "function",
            "function": {"name": t["name"], "description": t["description"], "parameters": t["inputSchema"]},
        }
        for t in client.tools
    ]
    messages = [{"role": "system", "content": system}, {"role": "user", "content": question}]
    stats = {"question": question, "calls": [], "prompt_tokens": [], "errors": 0}
    print(f"\n=== {question}")
    started = time.monotonic()
    for _ in range(MAX_ROUNDS):
        resp = chat(model, messages, tools)
        usage = resp.get("usage") or {}
        stats["prompt_tokens"].append(usage.get("prompt_tokens"))
        msg = resp["choices"][0]["message"]
        messages.append({k: v for k, v in msg.items() if k in ("role", "content", "tool_calls")})
        calls = msg.get("tool_calls") or []
        if not calls:
            stats["answer"] = msg.get("content") or ""
            break
        for tc in calls:
            name = tc["function"]["name"]
            try:
                args = json.loads(tc["function"].get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}
            if name == "write_action" and not auto_confirm and not confirm_write(args):
                text, is_error = "Error: the user declined this write.", True
            else:
                text, is_error = client.call(name, args)
            stats["calls"].append(name if name != "call_tool" else f"call_tool:{args.get('tool')}")
            stats["errors"] += int(is_error)
            flag = "ERROR " if is_error else ""
            print(
                f"  [{usage.get('prompt_tokens', '?'):>6} tok] {name}({json.dumps(args)[:140]})"
                f" -> {flag}{len(text)} chars"
            )
            if is_error:
                print(f"           {text[:200]}")
            messages.append({"role": "tool", "tool_call_id": tc.get("id", ""), "content": text})
    else:
        stats["answer"] = "[no final answer within the round limit]"
    stats["seconds"] = round(time.monotonic() - started)
    print(
        f"--- answer ({stats['seconds']} s, peak prompt {max(p or 0 for p in stats['prompt_tokens'])} tokens):\n"
        f"{stats['answer']}"
    )
    return stats


def main() -> None:
    auto_confirm = any(a in ("--yes", "-y") for a in sys.argv[1:])
    questions = [a for a in sys.argv[1:] if a not in ("--yes", "-y")] or QUESTIONS
    model = pick_model()
    client = McpClient()
    print(f"model {model}; {len(client.tools)} MCP tools")
    try:
        results = [ask(client, model, q, auto_confirm) for q in questions]
    finally:
        client.close()
    print("\n=== summary")
    for r in results:
        print(
            f"- {r['question'][:60]!r}: {len(r['calls'])} calls ({r['errors']} errors), "
            f"peak prompt {max(p or 0 for p in r['prompt_tokens'])} tokens, {r['seconds']} s — {' → '.join(r['calls'])}"
        )


if __name__ == "__main__":
    main()
