"""Tool registry — discover and execute tools for the IntelFeed CLI.

Tools are organized by category in submodules. Importing this package
automatically registers all tools via the ``@_tool`` decorator.

Public API:
    TOOL_DEFINITIONS  – list[dict] of tool schemas (name, description, input_schema)
    execute_tool()    – dispatch a tool call by name
"""

import json
import logging
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Registry (shared across all submodules)
# ---------------------------------------------------------------------------

TOOL_DEFINITIONS: list[dict] = []
_TOOL_HANDLERS: dict[str, callable] = {}

# Modules whose tools mutate state. Tools registered from these are flagged
# ``mutating`` and excluded from the read-only tool set the copilot exposes.
_MUTATING_MODULES: frozenset[str] = frozenset({"app.tools.write", "app.tools.delete"})

# Names of all registered mutating tools (populated as modules import below).
MUTATING_TOOLS: set[str] = set()

# Tools that must not run for non-admin users: their HTTP-API equivalents are
# admin-gated (entity merges, feed pool changes, extraction curation), or the
# tool handler has no per-row owner check where the API does (automation rule
# writes). Enforced by the /api/tools/execute endpoint — keep in step with the
# API layer's gates. Every other mutating tool matches what the API already
# lets any authenticated user do (own read-state, notes, shared workbench).
ADMIN_TOOLS: frozenset[str] = frozenset(
    {
        "delete_entity",
        "delete_feed",
        "update_feed",
        "merge_threat_actors",
        "merge_malware",
        "merge_vendors",
        "merge_products",
        "merge_tools",
        "reclassify_entity",
        "update_automation_rule",
        "delete_automation_rule",
        "toggle_automation_rule",
        "run_automation_rule",
        "test_automation_rule",
        "delete_webhook_preset",
        "delete_intel_report",
        "bulk_unlink_entities",
        "confirm_extraction_entities",
        # Target-sector claims are global profile edits, like the merges above.
        "set_target_sector",
        # A never-capture tombstone silences a value for every door and every user.
        "deny_observable",
    }
)


def _tool(name: str, description: str, input_schema: dict, mutating: bool | None = None):
    """Decorator to register a function as a CLI tool.

    ``mutating`` defaults to the module heuristic (_MUTATING_MODULES); mixed
    read/write modules pass it explicitly per tool.
    """

    def decorator(fn, mutating=mutating):
        if mutating is None:
            mutating = fn.__module__ in _MUTATING_MODULES
        TOOL_DEFINITIONS.append(
            {
                "name": name,
                "description": description,
                "input_schema": {
                    "type": "object",
                    **input_schema,
                },
                "mutating": mutating,
            }
        )
        if mutating:
            MUTATING_TOOLS.add(name)
        _TOOL_HANDLERS[name] = fn
        return fn

    return decorator


# Default tool subset for the Ollama copilot. The full read-only registry (54
# tools) serializes to ~6.6k tokens of schema per round — that bloats every
# request's context AND overwhelms local models' tool selection. This curated
# set covers the copilot's actual workload (search, entity lookups, pivots,
# landscape stats) at ~2k tokens. Override per-deployment via the copilot
# assignment's ``ollama_tools`` config key (editable in the Prompt Workspace's
# Routing panel when the task is assigned to an Ollama provider).
DEFAULT_COPILOT_OLLAMA_TOOLS: list[str] = [
    "search_entries",
    "search_entities",
    "search_unified",
    "get_entry",
    "get_threat_actor",
    "get_malware",
    "get_cve",
    "get_ttp",
    "get_campaign",
    "get_campaigns",
    "pivot_entity",
    "get_entity_timeline",
    "get_trending_entities",
    "get_dashboard_stats",
    "search_documentation",
    "get_documentation_page",
]


def read_only_tool_definitions() -> list[dict]:
    """Tool definitions that do not mutate state (safe for the read-only copilot)."""
    return [t for t in TOOL_DEFINITIONS if not t.get("mutating")]


def ollama_tool_specs(names: list[str] | None = None, *, read_only: bool = True) -> list[dict]:
    """Render tool definitions into Ollama ``/api/chat`` function-tool specs.

    Ollama (OpenAI-compatible) expects
    ``{"type": "function", "function": {"name", "description", "parameters"}}``
    where ``parameters`` is a JSON Schema — which is exactly our stored
    ``input_schema``.

    ``names`` optionally restricts the set (an allowlist of tool names); unknown
    names are ignored. ``read_only`` (default) drops mutating tools even if named.
    """
    allow = set(names) if names else None
    specs: list[dict] = []
    for t in TOOL_DEFINITIONS:
        if read_only and t.get("mutating"):
            continue
        if allow is not None and t["name"] not in allow:
            continue
        specs.append(
            {
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t["description"],
                    "parameters": t["input_schema"],
                },
            }
        )
    return specs


async def execute_tool(name: str, args: dict, db: AsyncSession, user_id: uuid.UUID) -> str:
    """Execute a tool by name. Returns JSON string result."""
    handler = _TOOL_HANDLERS.get(name)
    if not handler:
        return json.dumps({"error": f"Unknown tool: {name}"})
    try:
        result = await handler(db=db, user_id=user_id, **args)
        # ensure_ascii=False: titles contain emoji/unicode; escaped \uXXXX
        # sequences get transcribed literally by the model into answers.
        return json.dumps(result, default=str, ensure_ascii=False)
    except Exception as e:
        logger.exception("Tool %s failed", name)
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Import submodules to trigger tool registration
# ---------------------------------------------------------------------------

from app.tools import (  # noqa: E402
    correlation,  # noqa: F401
    curation,  # noqa: F401
    delete,  # noqa: F401
    detection,  # noqa: F401
    docs,  # noqa: F401
    export,  # noqa: F401
    extraction,  # noqa: F401
    feeds_automation,  # noqa: F401
    landscape,  # noqa: F401
    observables,  # noqa: F401
    read,  # noqa: F401
    reader_ops,  # noqa: F401
    search,  # noqa: F401
    sector,  # noqa: F401
    threads,  # noqa: F401
    workspace,  # noqa: F401
    write,  # noqa: F401
)
