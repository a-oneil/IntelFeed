"""Claude Code CLI provider.

Invokes the locally-installed `claude` binary in non-interactive `-p` (print)
mode and parses JSON output. Auth is OAuth via the user's Max subscription
(no per-token billing) — credentials live in /home/appuser/.claude (mounted as
the `claude_cli` named Docker volume). Falls back to ANTHROPIC_API_KEY env var
if OAuth lapses.

Designed to run on a dedicated Celery worker (`celery-worker-ai`) with
--concurrency=1 to avoid OAuth session-file corruption from concurrent writes
and to respect Max-plan rate limits. Per-call latency: 30-60s typical for a
~2K-char prompt against Sonnet.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import sys
import tempfile
import time
import uuid
from collections.abc import AsyncGenerator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import ClassVar

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaError

from app.ai.providers.base import AIProvider, AIResponse

logger = logging.getLogger(__name__)


class QuotaExhaustedError(RuntimeError):
    """CLI hit the Max-plan usage window (or equivalent rate limit).

    Carries an optional `reset_at` parsed from the CLI's stderr — when
    present, the engine uses it for a precise pause window. When absent,
    the engine falls back to a fixed backoff (1 hour by default).
    """

    def __init__(self, message: str, reset_at: datetime | None = None):
        super().__init__(message)
        self.reset_at = reset_at


# Sentinel substrings that indicate a Max-plan / API rate-limit hit. These are
# matched against lowercased CLI stderr. The list is conservative — false
# positives would needlessly pause the provider, so each entry must be a phrase
# that only appears in true quota errors. Add new sentinels here when new
# wording is observed in the wild (grep ai_results.raw_response for clues).
_QUOTA_SENTINELS = (
    "rate limit",
    "rate-limit",
    "rate_limit",
    "usage limit",
    "5-hour limit",
    "5 hour limit",
    "max plan limit",
    "quota exceeded",
    "too many requests",
    "429",
)


def _parse_reset_hint(stderr: str) -> datetime | None:
    """Best-effort parse of a 'resets at HH:MM UTC' / 'try again in N min' hint.

    Returns None if no parse is possible — caller defaults to a fixed backoff.
    Conservative: when in doubt, return None rather than guess a wrong time.
    """
    if not stderr:
        return None
    now = datetime.now(UTC)
    # "try again in 47 minutes" / "retry in 12m"
    m = re.search(r"(?:try again|retry|reset|available)[^\d]{0,20}(\d{1,3})\s*(minute|min|m\b)", stderr, re.I)
    if m:
        return now + timedelta(minutes=int(m.group(1)))
    m = re.search(r"(?:try again|retry|reset|available)[^\d]{0,20}(\d{1,3})\s*(hour|hr|h\b)", stderr, re.I)
    if m:
        return now + timedelta(hours=int(m.group(1)))
    # Absolute "resets at 14:30 UTC" / "available at 14:30"
    m = re.search(r"(?:reset|available)\w*\s+at\s+(\d{1,2}):(\d{2})\s*(?:utc|z)?", stderr, re.I)
    if m:
        hh, mm = int(m.group(1)), int(m.group(2))
        candidate = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
        if candidate <= now:
            candidate += timedelta(days=1)
        return candidate
    return None


# Default per-model CLI timeouts. Tuned around observed p99 single-entry
# latencies + a comfort margin: opus takes longer to think, haiku is fast.
# Used when neither the per-call `timeout_seconds` override nor the
# provider config has set a timeout. Override via provider config
# `timeout_seconds: <N>` or per-call `timeout_seconds=N`.
_MODEL_TIMEOUTS: dict[str, float] = {
    "haiku": 90.0,
    "sonnet": 180.0,
    "opus": 300.0,
}
_DEFAULT_TIMEOUT_FALLBACK = 180.0

# Heartbeat cadence — every N seconds of an in-flight subprocess wait, log a
# WARNING so silent hangs (bun startup retry, stuck OAuth refresh, network
# blip) are visible in worker logs immediately, not after the timeout fires.
_HEARTBEAT_INTERVAL_SECONDS = 30.0


# Some flags vary between CLI versions. The provider probes once at startup
# and remembers which flags are supported. Falls back gracefully when absent.
_KNOWN_OPTIONAL_FLAGS = {
    "bare": "--bare",
    "no_session_persistence": "--no-session-persistence",
    "json_schema": "--json-schema",
    "max_budget_usd": "--max-budget-usd",
    "disallowed_tools": "--disallowedTools",
    "allowed_tools": "--allowedTools",
    "tools": "--tools",
    "mcp_config": "--mcp-config",
    "strict_mcp_config": "--strict-mcp-config",
    "permission_mode": "--permission-mode",
    "setting_sources": "--setting-sources",
}

# Confinement needs every one of these. A CLI build without them gets the old
# no-tools invocation, and a task that asked for tools runs without them.
_CONFINEMENT_FLAGS = (
    "tools",
    "mcp_config",
    "strict_mcp_config",
    "permission_mode",
    "allowed_tools",
    "disallowed_tools",
    "setting_sources",
)


# ---------------------------------------------------------------- tool policy
#
# Prompts that reach this CLI carry text nobody here wrote: article titles and
# summaries, pinned articles, entity names extracted by an earlier model. So the
# agent never gets the CLI's own shell, file or fetch tools. Each would turn one
# planted instruction into code execution or a fetch inside the AI worker, a
# container holding every secret in .env. What a task can have:
#
# * IntelFeed lookups, through intelfeed-mcp/intelfeed_mcp.py run as an MCP
#   server. It calls the API with an agent token minted for the caller (see
#   create_agent_token), so the model holds no credential. The token is
#   read-only, except on a copilot turn, where it may propose writes: the API
#   stages them and only the user's click runs one, whatever the model is told.
# * WebSearch, which Anthropic runs server-side; nothing leaves this host.
#
# Assignment configs written before this list "Bash"/"Read"/"Skill" (the old
# skill-over-shell route) — those now mean the IntelFeed tools. WebFetch fetches
# from this host, so it is dropped rather than translated.
INTELFEED_TOOL = "IntelFeed"
# Every built-in the CLI ships that can touch this host, the network, other
# agents or the session (names taken from the pinned binary). Denied on every
# confined run; a deny rule wins over any allow, including one in a settings
# file. --tools additionally hides them where no JSON schema is in play.
_DENIED_BUILTIN_TOOLS = (
    "Bash", "BashOutput", "KillShell", "KillBash", "PowerShell", "Monitor",
    "Read", "Write", "Edit", "MultiEdit", "NotebookEdit", "NotebookRead", "Glob", "Grep", "LS", "LSP",
    "WebFetch", "WebSearch",
    "Task", "TaskOutput", "TaskStop", "Agent", "Workflow", "SendMessage", "Skill", "SlashCommand", "ToolSearch",
    "TodoWrite", "AskUserQuestion", "EnterPlanMode", "ExitPlanMode", "EnterWorktree", "ExitWorktree",
    "CronCreate", "RemoteTrigger", "ScheduleWakeup", "PushNotification", "SendUserFile", "Artifact",
    "ListMcpResourcesTool", "ReadMcpResourceTool",
)  # fmt: skip
_INTELFEED_ALIASES = frozenset({INTELFEED_TOOL, "Bash", "Read", "Skill", "Glob", "Grep", "*"})
_SAFE_BUILTIN_TOOLS = frozenset({"WebSearch"})
_MCP_SERVER_NAME = "intelfeed"

# Environment the CLI subprocess may inherit. Everything else in the worker's
# environment (SECRET_KEY, ENCRYPTION_KEY, database and Redis passwords, the
# skill account's password) stays out of reach of the agent.
_ENV_KEEP = frozenset(
    {
        "PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TMPDIR",
        "SSL_CERT_FILE", "SSL_CERT_DIR", "NODE_EXTRA_CA_CERTS",
        "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
    }
)  # fmt: skip
_ENV_KEEP_PREFIXES = ("CLAUDE_", "ANTHROPIC_")


def _scrubbed_env(overlay: dict[str, str] | None = None) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k in _ENV_KEEP or k.startswith(_ENV_KEEP_PREFIXES)}
    if overlay:
        env.update(overlay)
    return env


@dataclass(frozen=True, slots=True)
class _ToolPlan:
    """What one CLI run may use, already reduced to the safe set."""

    builtin: tuple[str, ...]  # passed to --tools
    intelfeed: bool  # attach the IntelFeed MCP server

    @property
    def any(self) -> bool:
        return bool(self.builtin) or self.intelfeed


def _plan_tools(requested: list[str] | None) -> _ToolPlan:
    names = [str(t).strip() for t in (requested or []) if str(t).strip()]
    builtin = tuple(sorted({n for n in names if n in _SAFE_BUILTIN_TOOLS}))
    dropped = sorted({n for n in names if n not in _SAFE_BUILTIN_TOOLS and n not in _INTELFEED_ALIASES})
    if dropped:
        logger.warning("claude-code: tools %s are not offered to the agent (shell/file/fetch tools)", dropped)
    return _ToolPlan(builtin=builtin, intelfeed=any(n in _INTELFEED_ALIASES for n in names))


def _normalize_model(model: str) -> str:
    """Map our internal model identifiers to CLI aliases the binary accepts."""
    aliases = {
        "claude-opus-4-6": "opus",
        "claude-sonnet-4-6": "sonnet",
        "claude-haiku-4-5-20251001": "haiku",
    }
    return aliases.get(model, model)


class ClaudeCodeProvider(AIProvider):
    """Provider that shells out to the Claude Code CLI."""

    # The CLI is a full agent harness — tool calls (Bash/Read/Skill/Web*)
    # execute inside the subprocess, gated by allowed_tools.
    supports_tools: ClassVar[bool] = True

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        config: dict | None = None,
    ):
        super().__init__(base_url=base_url, api_key=api_key, config=config)
        self.cli_path: str = self.config.get("cli_path", "claude")
        # When unset, falls back to _MODEL_TIMEOUTS lookup at call time. When
        # explicitly set in provider config OR task assignment config, this
        # overrides the per-model default. Per-call `timeout_seconds=` on
        # complete() overrides both.
        cfg_timeout = self.config.get("timeout_seconds")
        self.timeout_seconds: float | None = float(cfg_timeout) if cfg_timeout is not None else None
        # Retry the CLI subprocess this many times on TimeoutError before
        # bubbling up. Catches transient hangs (bun startup retry, OAuth
        # refresh blip) without restarting the whole Celery task.
        self.cli_retries: int = int(self.config.get("cli_retries", 1))
        self.max_budget_usd: float = float(self.config.get("max_budget_usd", 1.0))
        self.extra_args: list[str] = list(self.config.get("extra_args", []))
        # Per-task tool access. When unset/empty, ALL tools are disallowed
        # (safe default — extraction tasks run pure prompt-in/json-out).
        # When set, the listed tools are explicitly allowed and --disallowedTools
        # is omitted. Use ["Bash", "Read", "Skill"] for tasks that invoke the
        # intelfeed skill, or ["*"] for full access (avoid).
        self.allowed_tools: list[str] = list(self.config.get("allowed_tools") or [])
        # Where the IntelFeed MCP server lives and how it reaches the API.
        # Compose mounts ./intelfeed-mcp read-only at this path in the AI worker.
        self.mcp_server_path: str = self.config.get("mcp_server_path") or os.environ.get(
            "INTELFEED_MCP_SERVER_PATH", "/opt/intelfeed-mcp/intelfeed_mcp.py"
        )
        self.agent_api_url: str = self.config.get("agent_api_url") or os.environ.get(
            "INTELFEED_AGENT_API_URL", "http://api:8000"
        )
        # Cached at first use — set to a dict of {flag_key: bool}.
        self._supported_flags: dict[str, bool] | None = None

    # ------------------------------------------------------------------ helpers

    def _resolve_cli(self) -> str:
        path = shutil.which(self.cli_path)
        if not path:
            raise FileNotFoundError(
                f"claude binary not found on PATH (looked for '{self.cli_path}'). "
                "Confirm the npm package @anthropic-ai/claude-code is installed in the worker image."
            )
        return path

    def _mcp_config(
        self,
        agent_user_id: uuid.UUID | None,
        ttl_seconds: float,
        *,
        conversation_id: uuid.UUID | None = None,
        turn_id: uuid.UUID | None = None,
    ) -> str | None:
        """--mcp-config JSON for the IntelFeed server, or None when it cannot run.

        The token is minted per run and lives no longer than the run. It is
        read-only, or with ``conversation_id`` a propose token: writes are
        staged on that copilot conversation for the user's click, and the
        server offers them as ``write_action``. It travels in the server's
        environment, which the agent cannot read: the agent has no shell or
        file tools.
        """
        if agent_user_id is None:
            logger.warning("claude-code: IntelFeed tools requested without a user to act for; answering without them")
            return None
        if not os.path.isfile(self.mcp_server_path):
            logger.warning(
                "claude-code: IntelFeed MCP server not found at %s; answering without it", self.mcp_server_path
            )
            return None
        from app.core.security import create_agent_token

        env = {
            "INTELFEED_API_URL": self.agent_api_url,
            "INTELFEED_TOKEN": create_agent_token(
                agent_user_id, ttl_seconds, conversation_id=conversation_id, turn_id=turn_id
            ),
            # Claude reads far more than the small local models the server's
            # 7k default was sized for.
            "INTELFEED_MCP_RESULT_CHARS": "20000",
        }
        if conversation_id:
            env["INTELFEED_MCP_PROPOSE_WRITES"] = "1"
        if self.agent_api_url.startswith("http://"):
            # The api on the compose network; the token never leaves the host.
            env["INTELFEED_ALLOW_INSECURE_HTTP"] = "1"
        return json.dumps(
            {"mcpServers": {_MCP_SERVER_NAME: {"command": sys.executable, "args": [self.mcp_server_path], "env": env}}}
        )

    @staticmethod
    def _can_confine(flags: dict) -> bool:
        return all(flags.get(f) for f in _CONFINEMENT_FLAGS)

    @staticmethod
    def _effective_plan(requested: list[str] | None, flags: dict) -> _ToolPlan:
        plan = _plan_tools(requested)
        if plan.any and not ClaudeCodeProvider._can_confine(flags):
            logger.warning(
                "claude-code: this CLI build lacks %s, so tools cannot be confined; running without tools",
                [f for f in _CONFINEMENT_FLAGS if not flags.get(f)],
            )
            return _ToolPlan(builtin=(), intelfeed=False)
        return plan

    @staticmethod
    def _confined_argv(plan: _ToolPlan, mcp_config: str | None, use_json_schema: bool) -> list[str]:
        """Flags for every run on a CLI that supports confinement, tools or not.

        * Settings come only from the (empty, per-run) working directory, so no
          allow rule from ~/.claude can widen what follows.
        * MCP servers come only from --mcp-config: the IntelFeed one, or none.
        * Every built-in is denied except the ones the plan keeps; deny wins.
        * dontAsk refuses whatever --allowedTools did not pre-approve, and
          permissions are never skipped.
        * --tools hides the denied built-ins outright, except when a JSON schema
          is set: the CLI answers through its StructuredOutput tool then, and
          the deny list does the work instead.
        """
        allowed = list(plan.builtin)
        argv = ["--setting-sources", "project", "--strict-mcp-config"]
        if mcp_config:
            argv += ["--mcp-config", mcp_config]
            allowed.append(f"mcp__{_MCP_SERVER_NAME}")
        if use_json_schema:
            allowed.append("StructuredOutput")
        else:
            argv += ["--tools", ",".join(plan.builtin)]
        denied = [t for t in _DENIED_BUILTIN_TOOLS if t not in plan.builtin]
        argv += ["--disallowedTools", ",".join(denied)]
        if allowed:
            argv += ["--allowedTools", ",".join(allowed)]
        argv += ["--permission-mode", "dontAsk"]
        return argv

    @staticmethod
    def _legacy_no_tools_argv(flags: dict, use_json_schema: bool) -> list[str]:
        """A CLI too old to confine: no tools, as this provider always did."""
        argv: list[str] = []
        if use_json_schema and flags.get("allowed_tools"):
            argv += ["--allowedTools", "StructuredOutput"]
        elif flags.get("disallowed_tools") and not use_json_schema:
            argv += ["--disallowedTools", "*"]
        if flags.get("dangerously_skip_perms"):
            argv += [flags.get("dangerously_skip_perms_flag", "--dangerously-skip-permissions")]
        return argv

    async def _probe_flags(self) -> dict[str, bool]:
        if self._supported_flags is not None:
            return self._supported_flags
        cli = self._resolve_cli()
        try:
            proc = await asyncio.create_subprocess_exec(
                cli,
                "--help",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        except TimeoutError:
            logger.warning("claude --help timed out during flag probe; assuming minimal flag set")
            self._supported_flags = {k: False for k in _KNOWN_OPTIONAL_FLAGS}
            return self._supported_flags
        help_text = out.decode("utf-8", errors="replace")
        self._supported_flags = {key: flag in help_text for key, flag in _KNOWN_OPTIONAL_FLAGS.items()}
        # --dangerously-skip-permissions vs --allow-dangerously-skip-permissions
        if "--dangerously-skip-permissions" in help_text:
            self._supported_flags["dangerously_skip_perms"] = True
            self._supported_flags["dangerously_skip_perms_flag"] = "--dangerously-skip-permissions"
        elif "--allow-dangerously-skip-permissions" in help_text:
            self._supported_flags["dangerously_skip_perms"] = True
            self._supported_flags["dangerously_skip_perms_flag"] = "--allow-dangerously-skip-permissions"
        else:
            self._supported_flags["dangerously_skip_perms"] = False
        logger.info(
            "claude-code provider flag probe: %s",
            {k: v for k, v in self._supported_flags.items() if k != "dangerously_skip_perms_flag"},
        )
        return self._supported_flags

    def _build_argv(
        self,
        cli: str,
        model: str,
        system_prompt: str | None,
        json_schema: dict | None,
        flags: dict,
        mcp_config: str | None = None,
    ) -> list[str]:
        argv: list[str] = [cli, "-p", "--output-format", "json", "--model", _normalize_model(model)]
        if system_prompt:
            argv += ["--append-system-prompt", system_prompt]
        # Tool access: see the tool policy at the top of this module. With a
        # JSON schema the CLI answers through its StructuredOutput tool, which
        # must therefore stay allowed, or the model burns the whole timeout
        # retrying a denied call and the result fails JSON parsing.
        use_json_schema = bool(flags.get("json_schema") and json_schema is not None)
        if self._can_confine(flags):
            plan = self._effective_plan(self.allowed_tools, flags)
            argv += self._confined_argv(plan, mcp_config if plan.intelfeed else None, use_json_schema)
        else:
            argv += self._legacy_no_tools_argv(flags, use_json_schema)
        # --bare is nice for cache-friendliness but it FORCES API key auth
        # ("OAuth and keychain are never read"), which breaks Max-subscription
        # deployments. Only enable when an explicit API key is in play.
        if flags.get("bare") and self.api_key:
            argv += ["--bare"]
        # Don't persist session state across runs.
        if flags.get("no_session_persistence"):
            argv += ["--no-session-persistence"]
        # Hard budget cap (no-op under OAuth but defense-in-depth if ANTHROPIC_API_KEY is set).
        if flags.get("max_budget_usd"):
            argv += ["--max-budget-usd", f"{self.max_budget_usd:.4f}"]
        # Schema-validated structured output if the CLI supports it.
        if flags.get("json_schema") and json_schema is not None:
            argv += ["--json-schema", json.dumps(json_schema, separators=(",", ":"))]
        argv += self.extra_args
        return argv

    @staticmethod
    def _extract_result(stdout: bytes) -> tuple[str, dict | None]:
        """Pull the model response out of `claude -p --output-format json` output.

        Returns ``(result_text, payload)`` where ``payload`` is the parsed
        top-level JSON dict (None when the CLI returned a bare string) so
        callers can also read usage/cost metadata off it.

        When `--json-schema` is passed, the CLI exposes the already-parsed JSON
        as a top-level `structured_output` key. Prefer that — it bypasses any
        markdown fences or chattiness in `result`.
        """
        raw = stdout.decode("utf-8", errors="replace").strip()
        if not raw:
            raise ValueError("claude CLI returned empty stdout")
        # Output may be a single JSON object on one line, or multi-line with trailing newline.
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as e:
            # Sometimes output has a trailing telemetry line — try the last JSON object.
            lines = [line for line in raw.splitlines() if line.strip().startswith("{")]
            if lines:
                try:
                    payload = json.loads(lines[-1])
                except json.JSONDecodeError:
                    raise ValueError(f"claude stdout was not valid JSON: {raw[:500]}") from e
            else:
                raise ValueError(f"claude stdout was not valid JSON: {raw[:500]}") from e
        if isinstance(payload, dict):
            if isinstance(payload.get("structured_output"), (dict, list)):
                return json.dumps(payload["structured_output"], separators=(",", ":")), payload
            if "result" in payload:
                return str(payload["result"]), payload
        if isinstance(payload, str):
            return payload, None
        raise ValueError(f"claude JSON output had no 'result' field: {str(payload)[:300]}")

    @staticmethod
    def _extract_usage(payload: dict | None) -> dict:
        """Pull token usage + CLI-reported cost from a CLI result payload.

        Both `--output-format json` (single payload) and the terminal
        ``{"type": "result"}`` stream-json event carry the same fields:

            {"total_cost_usd": 0.0123,
             "usage": {"input_tokens": N, "output_tokens": N,
                       "cache_creation_input_tokens": N,
                       "cache_read_input_tokens": N}, ...}

        Returns a flat dict with ``tokens_input`` (prompt tokens INCLUDING both
        cache buckets — the full context the call processed), ``tokens_output``,
        the raw cache counters, and ``total_cost_usd`` (None when absent).
        Missing/malformed fields degrade to zeros rather than raising — usage
        capture must never break a call that otherwise succeeded.
        """
        usage = (payload or {}).get("usage")
        usage = usage if isinstance(usage, dict) else {}

        def _int(key: str) -> int:
            val = usage.get(key)
            return int(val) if isinstance(val, (int, float)) else 0

        cache_creation = _int("cache_creation_input_tokens")
        cache_read = _int("cache_read_input_tokens")
        cost = (payload or {}).get("total_cost_usd")
        return {
            "tokens_input": _int("input_tokens") + cache_creation + cache_read,
            "tokens_output": _int("output_tokens"),
            "cache_creation_input_tokens": cache_creation,
            "cache_read_input_tokens": cache_read,
            "total_cost_usd": float(cost) if isinstance(cost, (int, float)) else None,
        }

    @staticmethod
    def _parse_inner_json(text: str) -> str:
        """Strip markdown fences if Claude wrapped its JSON in a code block (mirror engine.py:236-247)."""
        content = text.strip()
        if "```json" in content:
            content = content.split("```json", 1)[1].split("```", 1)[0].strip()
        elif content.startswith("```"):
            content = content.split("```", 1)[1].split("```", 1)[0].strip()
        return content

    def _resolve_timeout(self, model: str, override: float | None) -> float:
        """Pick the effective timeout for one CLI call.

        Precedence: per-call override → provider/assignment config → per-model
        default → fallback. Lets the link-validation batched task scale the
        timeout by batch size without changing provider config.
        """
        if override is not None:
            return float(override)
        if self.timeout_seconds is not None:
            return self.timeout_seconds
        return _MODEL_TIMEOUTS.get(_normalize_model(model), _DEFAULT_TIMEOUT_FALLBACK)

    async def _heartbeat(self, label: str, started: float, interval: float) -> None:
        """Log every `interval` seconds while a subprocess wait is in flight."""
        try:
            while True:
                await asyncio.sleep(interval)
                elapsed = time.monotonic() - started
                logger.warning("claude-code: still waiting on %s — %.0fs elapsed", label, elapsed)
        except asyncio.CancelledError:
            return

    # ---------------------------------------------------------------- AIProvider

    async def complete(
        self,
        prompt: str,
        system: str | None = None,
        temperature: float = 0.0,
        max_tokens: int = 4096,
        response_format: dict | None = None,
        model: str = "sonnet",
        timeout_seconds: float | None = None,
        heartbeat_label: str | None = None,
        agent_user_id: uuid.UUID | None = None,
    ) -> AIResponse:
        """``agent_user_id`` is who IntelFeed tool calls act for (the engine
        passes the task's user); without it a tool-using task runs text-only."""
        # temperature and max_tokens are not exposed by the CLI's -p mode; we
        # accept them for interface compatibility but they have no effect.
        del temperature, max_tokens
        cli = self._resolve_cli()
        flags = await self._probe_flags()
        effective_timeout = self._resolve_timeout(model, timeout_seconds)
        max_attempts = 1 if timeout_seconds is not None else self.cli_retries + 1
        mcp_config = None
        if self._effective_plan(self.allowed_tools, flags).intelfeed:
            mcp_config = self._mcp_config(agent_user_id, effective_timeout * max_attempts + 120)
        argv = self._build_argv(cli, model, system, response_format, flags, mcp_config=mcp_config)

        # Only what the CLI needs to run and authenticate (OAuth under
        # /home/appuser/.claude, or ANTHROPIC_API_KEY / CLAUDE_CODE_OAUTH_TOKEN).
        env = _scrubbed_env()
        workdir = tempfile.TemporaryDirectory(prefix="claude-run-")

        label = heartbeat_label or f"claude {model} call"

        # Retry-on-timeout loop. Many CLI hangs are transient (bun startup
        # retry, OAuth refresh blip, Anthropic API blip) and clear on a second
        # attempt without restarting the whole Celery task. `cli_retries`
        # defaults to 1 — total attempts = cli_retries + 1.
        #
        # Exception: when the caller passes an explicit per-call `timeout_seconds`
        # it's a HARD wall-clock ceiling (e.g. a synchronous request path bounded
        # by the gunicorn worker timeout). Retrying would double the budget and
        # blow past that ceiling, so a per-call timeout forces a single attempt
        # (max_attempts above).
        stdout: bytes | None = None
        stderr: bytes | None = None
        proc: asyncio.subprocess.Process | None = None
        last_timeout: TimeoutError | None = None
        start = time.monotonic()

        for attempt in range(max_attempts):
            attempt_label = label if attempt == 0 else f"{label} (retry {attempt}/{max_attempts - 1})"
            attempt_started = time.monotonic()
            heartbeat = asyncio.create_task(
                self._heartbeat(attempt_label, attempt_started, _HEARTBEAT_INTERVAL_SECONDS)
            )
            try:
                proc = await asyncio.create_subprocess_exec(
                    *argv,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=env,
                    # An empty directory per run: no project CLAUDE.md, settings
                    # or files for the agent to find.
                    cwd=workdir.name,
                )
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(input=prompt.encode("utf-8")),
                    timeout=effective_timeout,
                )
                break  # success — exit retry loop
            except TimeoutError:
                try:
                    if proc is not None:
                        proc.kill()
                        await proc.wait()
                except Exception:
                    pass
                last_timeout = TimeoutError(
                    f"claude CLI exceeded {effective_timeout:.0f}s on attempt "
                    f"{attempt + 1}/{max_attempts} for model={model}"
                )
                logger.warning(str(last_timeout))
                continue
            finally:
                heartbeat.cancel()
                try:
                    await heartbeat
                except (asyncio.CancelledError, Exception):
                    pass
        else:
            # Loop exhausted without breaking — every attempt timed out.
            workdir.cleanup()
            raise last_timeout or TimeoutError(f"claude CLI exceeded {effective_timeout:.0f}s for model={model}")
        workdir.cleanup()

        # Mypy-friendly: success path guarantees stdout / stderr / proc are set.
        assert proc is not None and stdout is not None and stderr is not None

        latency_ms = int((time.monotonic() - start) * 1000)

        if proc.returncode != 0:
            err = stderr.decode("utf-8", errors="replace").strip()
            lower = err.lower()
            # Quota / rate-limit hit — engine catches QuotaExhaustedError and
            # auto-pauses the provider. Check this BEFORE the auth branch
            # because some quota errors mention "auth" generically.
            if any(s in lower for s in _QUOTA_SENTINELS):
                raise QuotaExhaustedError(err[:500], reset_at=_parse_reset_hint(err))
            # Auth failures vs other binary errors for operator clarity.
            if "login" in lower or "auth" in lower or "credentials" in lower:
                raise RuntimeError(
                    "claude CLI auth failed — re-run `claude /login` or `claude setup-token` "
                    f"inside celery-worker-ai. stderr: {err[:500]}"
                )
            raise RuntimeError(f"claude CLI exited {proc.returncode}: {err[:500] or '(no stderr)'}")

        result_text, payload = self._extract_result(stdout)
        usage = self._extract_usage(payload)

        # If a response_format was requested, validate the parsed JSON in
        # Python — both as a sanity check and as a fallback when --json-schema
        # isn't available on the installed CLI.
        if response_format is not None:
            inner = self._parse_inner_json(result_text)
            try:
                parsed = json.loads(inner)
            except json.JSONDecodeError as e:
                raise ValueError(f"claude returned non-JSON content despite JSON request: {result_text[:500]}") from e
            try:
                Draft202012Validator(response_format).validate(parsed)
            except JsonSchemaError as e:
                raise ValueError(f"claude JSON failed schema validation: {e.message} (path={list(e.path)})")
            # Hand the engine a canonical JSON string so its json.loads in
            # engine.py succeeds without re-stripping fences.
            content = json.dumps(parsed, separators=(",", ":"))
        else:
            content = result_text

        return AIResponse(
            content=content,
            raw_response={"stdout": stdout.decode("utf-8", errors="replace")},
            # Token usage + cost from the CLI's result payload. Under OAuth the
            # dollar figure is notional (flat-rate plan) but reflects what the
            # usage would cost at API rates.
            tokens_input=usage["tokens_input"],
            tokens_output=usage["tokens_output"],
            model=model,
            latency_ms=latency_ms,
            cost_usd=usage["total_cost_usd"],
        )

    # ----------------------------------------------------------- agent streaming

    def _build_stream_argv(
        self,
        cli: str,
        model: str,
        system_prompt: str | None,
        allowed_tools: list[str] | None,
        flags: dict,
        mcp_config: str | None = None,
    ) -> list[str]:
        """Argv for a streaming agent turn.

        Uses `--output-format stream-json --verbose --include-partial-messages`
        so the CLI emits token-level `text_delta` events plus tool_use /
        tool_result blocks. Mirrors _build_argv's auth/permission handling but
        keeps the streaming-specific flags and per-call tool allowlist.
        """
        argv: list[str] = [
            cli,
            "-p",
            "--output-format",
            "stream-json",
            "--verbose",
            "--include-partial-messages",
            "--model",
            _normalize_model(model),
        ]
        if system_prompt:
            argv += ["--append-system-prompt", system_prompt]
        # Per-call tool list overrides the provider default; either way it goes
        # through the same tool policy as complete().
        effective_tools = allowed_tools if allowed_tools is not None else self.allowed_tools
        if self._can_confine(flags):
            plan = self._effective_plan(effective_tools, flags)
            argv += self._confined_argv(plan, mcp_config if plan.intelfeed else None, use_json_schema=False)
        else:
            argv += self._legacy_no_tools_argv(flags, use_json_schema=False)
        if flags.get("no_session_persistence"):
            argv += ["--no-session-persistence"]
        argv += self.extra_args
        return argv

    @staticmethod
    def _summarize_tool_result(content: object) -> str:
        """Collapse a tool_result content payload into a short human string."""
        text = ""
        if isinstance(content, str):
            text = content
        elif isinstance(content, list):
            parts = []
            for block in content:
                if isinstance(block, dict):
                    parts.append(str(block.get("text") or block.get("content") or ""))
                else:
                    parts.append(str(block))
            text = " ".join(p for p in parts if p)
        elif content is not None:
            text = str(content)
        text = " ".join(text.split())
        return text[:200]

    async def stream_agent(
        self,
        prompt: str,
        system: str | None = None,
        model: str = "sonnet",
        allowed_tools: list[str] | None = None,
        timeout_seconds: float | None = None,
        heartbeat_label: str | None = None,
        env: dict[str, str] | None = None,
        agent_user_id: uuid.UUID | None = None,
        agent_conversation_id: uuid.UUID | None = None,
        agent_turn_id: uuid.UUID | None = None,
    ) -> AsyncGenerator[dict, None]:
        """Run one agent turn via the CLI and yield typed streaming events.

        ``agent_conversation_id`` (the copilot) lets the IntelFeed tools stage
        writes on that conversation for the user to confirm; without it they
        are read-only.

        Yields dicts of the shapes:
          {"kind": "text", "text": <delta>}
          {"kind": "tool_call", "id", "name", "args"}
          {"kind": "tool_result", "id", "status", "summary"}
          {"kind": "done", "usage": {tokens/cost, see _extract_usage}}

        The synthetic done emitted when the CLI never sent a result event has
        no "usage" key.

        Text streaming is the must-have and is driven off `text_delta` partial
        events. Tool events are best-effort: parsed from `tool_use` content
        blocks and top-level `user`/`tool_result` messages. Any parse hiccup on
        a single line is logged and skipped so text keeps flowing.
        """
        cli = self._resolve_cli()
        flags = await self._probe_flags()
        effective_timeout = self._resolve_timeout(model, timeout_seconds)
        effective_tools = allowed_tools if allowed_tools is not None else self.allowed_tools
        mcp_config = None
        if self._effective_plan(effective_tools, flags).intelfeed:
            mcp_config = self._mcp_config(
                agent_user_id, effective_timeout + 120, conversation_id=agent_conversation_id, turn_id=agent_turn_id
            )
        argv = self._build_stream_argv(cli, model, system, allowed_tools, flags, mcp_config=mcp_config)

        # A scrubbed environment plus the caller's overlay; see _scrubbed_env.
        subprocess_env = _scrubbed_env(env)
        label = heartbeat_label or f"claude {model} stream"
        start = time.monotonic()
        workdir = tempfile.TemporaryDirectory(prefix="claude-run-")

        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=subprocess_env,
            cwd=workdir.name,
        )
        assert proc.stdin is not None and proc.stdout is not None

        # Feed the prompt on stdin then close so the CLI starts generating.
        try:
            proc.stdin.write(prompt.encode("utf-8"))
            await proc.stdin.drain()
            proc.stdin.close()
        except (BrokenPipeError, ConnectionResetError):
            pass

        # Track which streaming content-block index is a tool_use so we can pair
        # the block's input (arrives via input_json_delta) — but we emit the
        # tool_call as soon as we see the block start with a name.
        emitted_done = False
        try:
            while True:
                try:
                    raw_line = await asyncio.wait_for(
                        proc.stdout.readline(),
                        timeout=effective_timeout,
                    )
                except TimeoutError:
                    logger.warning("claude-code stream: %s exceeded %.0fs; killing", label, effective_timeout)
                    break
                if not raw_line:
                    break  # EOF
                line = raw_line.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    logger.debug("claude-code stream: non-JSON line skipped: %s", line[:200])
                    continue

                for out in self._map_stream_event(event):
                    if out.get("kind") == "done":
                        emitted_done = True
                    yield out

            # Drain stderr for diagnostics on non-zero exit.
            await proc.wait()
            elapsed = time.monotonic() - start
            if proc.returncode not in (0, None):
                stderr_bytes = b""
                if proc.stderr is not None:
                    try:
                        stderr_bytes = await proc.stderr.read()
                    except Exception:
                        pass
                err = stderr_bytes.decode("utf-8", errors="replace").strip()
                lower = err.lower()
                if any(s in lower for s in _QUOTA_SENTINELS):
                    raise QuotaExhaustedError(err[:500], reset_at=_parse_reset_hint(err))
                logger.warning(
                    "claude-code stream: %s exited %s after %.1fs: %s",
                    label,
                    proc.returncode,
                    elapsed,
                    err[:500] or "(no stderr)",
                )
        finally:
            if proc.returncode is None:
                try:
                    proc.kill()
                    await proc.wait()
                except Exception:
                    pass
            workdir.cleanup()

        if not emitted_done:
            yield {"kind": "done"}

    def _map_stream_event(self, event: dict) -> list[dict]:
        """Translate one CLI stream-json event into zero or more typed events."""
        out: list[dict] = []
        etype = event.get("type")

        # Token-level deltas (from --include-partial-messages).
        if etype == "stream_event":
            se = event.get("event") or {}
            se_type = se.get("type")
            if se_type == "content_block_delta":
                delta = se.get("delta") or {}
                if delta.get("type") == "text_delta":
                    text = delta.get("text") or ""
                    if text:
                        out.append({"kind": "text", "text": text})
            # NB: we do NOT emit tool_call on content_block_start — its input is
            # empty at that point (args stream via input_json_delta). We emit the
            # tool_call from the top-level "assistant" message below, which
            # carries the fully-assembled input.
            return out

        # Top-level assistant messages carry tool_use blocks (whole-block form);
        # we do NOT re-emit their text — text already streamed via deltas above.
        if etype == "assistant":
            content = (event.get("message") or {}).get("content") or []
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_use":
                    out.append(
                        {
                            "kind": "tool_call",
                            "id": block.get("id") or "",
                            "name": block.get("name") or "",
                            "args": block.get("input") or {},
                        }
                    )
            return out

        # Tool results come back as a "user" message with tool_result blocks.
        if etype == "user":
            content = (event.get("message") or {}).get("content") or []
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_result":
                    out.append(
                        {
                            "kind": "tool_result",
                            "id": block.get("tool_use_id") or "",
                            "status": "error" if block.get("is_error") else "success",
                            "summary": self._summarize_tool_result(block.get("content")),
                        }
                    )
            return out

        if etype == "result":
            # Attach usage + CLI-reported cost so consumers (the copilot
            # endpoint) can persist per-turn cost tracking. The dict shape is
            # _extract_usage's; it survives the worker's Redis relay verbatim.
            out.append({"kind": "done", "usage": self._extract_usage(event)})
            return out

        return out

    async def check_health(self) -> bool:
        try:
            cli = self._resolve_cli()
        except FileNotFoundError:
            logger.warning("claude-code health: binary not found")
            return False
        try:
            proc = await asyncio.create_subprocess_exec(
                cli,
                "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            out, err = await asyncio.wait_for(proc.communicate(), timeout=10)
            if proc.returncode != 0:
                logger.warning("claude-code health: --version exit %s err=%s", proc.returncode, err[:200])
                return False
        except Exception as e:
            logger.warning("claude-code health: --version failed: %s", e)
            return False
        # Try a real (but minimal) prompt to confirm auth works.
        try:
            response = await self.complete(prompt="say ok", model="haiku")
            return bool(response.content)
        except Exception as e:
            logger.warning("claude-code health: prompt call failed: %s", e)
            return False

    async def list_models(self) -> list[str]:
        return ["sonnet", "opus", "haiku"]
