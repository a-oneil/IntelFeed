"""The Claude CLI provider never hands an agent shell, file or fetch tools.

Prompts on this path carry feed text (article titles, pinned articles,
extracted entity names), so every confined run must: offer no dangerous
built-in, deny them all explicitly, refuse anything not pre-approved, never
skip permissions, keep the worker's secrets out of the subprocess, and give
IntelFeed tools only through the MCP server holding a read-only agent token.
"""

import json
import uuid

import jwt
import pytest
from httpx import AsyncClient

from app.ai.providers import claude_code_provider as ccp
from app.ai.providers.claude_code_provider import ClaudeCodeProvider
from app.config import settings
from app.core.security import create_agent_token
from app.models.user import User
from app.tools import MUTATING_TOOLS

ALL_FLAGS = {k: True for k in ccp._KNOWN_OPTIONAL_FLAGS} | {
    "dangerously_skip_perms": True,
    "dangerously_skip_perms_flag": "--dangerously-skip-permissions",
}


def _opt(argv: list[str], flag: str) -> str | None:
    return argv[argv.index(flag) + 1] if flag in argv else None


def _provider(tmp_path, tools):
    server = tmp_path / "intelfeed_mcp.py"
    server.write_text("# stand-in")
    return ClaudeCodeProvider(config={"allowed_tools": tools, "mcp_server_path": str(server)})


def _assert_confined(argv: list[str]) -> None:
    assert "--dangerously-skip-permissions" not in argv
    assert _opt(argv, "--permission-mode") == "dontAsk"
    assert _opt(argv, "--setting-sources") == "project"
    assert "--strict-mcp-config" in argv
    denied = set(_opt(argv, "--disallowedTools").split(","))
    assert {"Bash", "Read", "Write", "Edit", "WebFetch", "Glob", "Grep", "Task", "Skill"} <= denied


@pytest.mark.parametrize("tools", [["Bash", "Read", "Skill"], ["IntelFeed"], ["*"]])
def test_intelfeed_tasks_get_the_mcp_server_and_nothing_else(tmp_path, tools):
    provider = _provider(tmp_path, tools)
    user_id = uuid.uuid4()
    mcp = provider._mcp_config(user_id, 300)
    argv = provider._build_argv("claude", "sonnet", None, None, ALL_FLAGS, mcp_config=mcp)

    _assert_confined(argv)
    assert _opt(argv, "--tools") == ""
    assert _opt(argv, "--allowedTools") == "mcp__intelfeed"

    server = json.loads(_opt(argv, "--mcp-config"))["mcpServers"]["intelfeed"]
    token = jwt.decode(server["env"]["INTELFEED_TOKEN"], settings.secret_key, algorithms=["HS256"])
    assert token["type"] == "agent" and token["scope"] == "read" and token["sub"] == str(user_id)


def test_streaming_turns_are_confined_the_same_way(tmp_path):
    provider = _provider(tmp_path, [])
    mcp = provider._mcp_config(uuid.uuid4(), 300)
    argv = provider._build_stream_argv("claude", "sonnet", None, ["Bash", "Read", "Skill"], ALL_FLAGS, mcp_config=mcp)
    _assert_confined(argv)
    assert _opt(argv, "--tools") == ""
    assert _opt(argv, "--allowedTools") == "mcp__intelfeed"


def test_web_fetch_is_dropped_and_web_search_kept(tmp_path):
    provider = _provider(tmp_path, ["WebFetch", "WebSearch"])
    argv = provider._build_argv("claude", "sonnet", None, None, ALL_FLAGS)
    _assert_confined(argv)
    assert _opt(argv, "--tools") == "WebSearch"
    assert _opt(argv, "--allowedTools") == "WebSearch"
    assert "WebSearch" not in _opt(argv, "--disallowedTools").split(",")
    assert "--mcp-config" not in argv


def test_schema_tasks_without_tools_are_confined_too(tmp_path):
    """Extraction runs (entry analysis and friends) answer through
    StructuredOutput. They used to pair that allow with skipped permissions,
    which left Bash usable by a prompt-injected article."""
    provider = _provider(tmp_path, [])
    argv = provider._build_argv("claude", "sonnet", None, {"type": "object"}, ALL_FLAGS)
    _assert_confined(argv)
    assert _opt(argv, "--allowedTools") == "StructuredOutput"
    assert "--mcp-config" not in argv


def test_no_tools_without_a_user_to_act_for(tmp_path):
    provider = _provider(tmp_path, ["IntelFeed"])
    assert provider._mcp_config(None, 300) is None
    argv = provider._build_argv("claude", "sonnet", None, None, ALL_FLAGS, mcp_config=None)
    _assert_confined(argv)
    assert "--allowedTools" not in argv


def test_a_cli_that_cannot_confine_gets_no_tools(tmp_path):
    flags = {**ALL_FLAGS, "tools": False}
    provider = _provider(tmp_path, ["Bash", "Read", "Skill"])
    argv = provider._build_argv("claude", "sonnet", None, None, flags, mcp_config="{}")
    assert _opt(argv, "--disallowedTools") == "*"
    assert "--allowedTools" not in argv and "--mcp-config" not in argv


def test_worker_secrets_stay_out_of_the_subprocess(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "s")
    monkeypatch.setenv("ENCRYPTION_KEY", "e")
    monkeypatch.setenv("POSTGRES_PASSWORD", "p")
    monkeypatch.setenv("INTELFEED_PASSWORD", "i")
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "keep")
    env = ccp._scrubbed_env({"EXTRA": "x"})
    assert not {"SECRET_KEY", "ENCRYPTION_KEY", "POSTGRES_PASSWORD", "INTELFEED_PASSWORD"} & set(env)
    assert env["CLAUDE_CODE_OAUTH_TOKEN"] == "keep" and env["EXTRA"] == "x" and "PATH" in env


# ---- the agent token on the API side ----


@pytest.mark.asyncio
async def test_agent_token_runs_read_tools_only(client: AsyncClient, test_user: User):
    headers = {"Authorization": f"Bearer {create_agent_token(test_user.id, 300)}"}

    read = await client.post(
        "/api/tools/execute", json={"tool_name": "get_feeds", "args": {"limit": 1}}, headers=headers
    )
    assert read.status_code == 200
    listed = await client.get("/api/tools/tools", headers=headers)
    assert listed.status_code == 200

    write = await client.post(
        "/api/tools/execute",
        json={"tool_name": "create_note", "args": {"title": "x", "content": "y"}},
        headers=headers,
    )
    assert write.status_code == 403
    assert "create_note" in MUTATING_TOOLS


@pytest.mark.asyncio
async def test_agent_token_is_refused_by_ordinary_routes(client: AsyncClient, test_user: User):
    headers = {"Authorization": f"Bearer {create_agent_token(test_user.id, 300)}"}
    for path in ("/api/auth/me", "/api/feeds"):
        resp = await client.get(path, headers=headers)
        assert resp.status_code == 401, path
