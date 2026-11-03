"""The gate every model-driven tool call passes, whichever provider runs it.

A model's tool call is not a request from the user. Article text reaches the
model's context (pinned articles, search results, entity names), so one planted
instruction can name any tool. The gate makes the rules hold for every provider:

* A model is offered only what its user may run: admin-only tools are dropped
  for non-admins, and no schema shows a ``confirmation_token``.
* A tool it was not offered is refused, as is an admin tool for a non-admin
  (checked again here, not only in the offer) and any call carrying a
  confirmation token: that token stands for the user's yes, not the model's.
* Reads run straight away.
* A write does not run. It is staged in Redis for the asking user and the
  model is told it is waiting; the user's click on the copilot's confirm card
  runs it (``run_confirmed``). An admin can list low-risk writes that skip the
  click (``copilot_auto_approve_tools``).

The in-process loops (Anthropic API, OpenAI-compatible, Ollama) call
``ToolGate`` directly. The Claude CLI reaches the registry over HTTP, so
``/api/tools/execute`` applies the same checks to its ``propose`` agent token.
"""

from __future__ import annotations

import copy
import json
import logging
import re
import uuid
from collections.abc import Iterable

from sqlalchemy.ext.asyncio import AsyncSession

from app.tools import (
    ADMIN_TOOLS,
    MUTATING_TOOLS,
    PERSISTING_READ_TOOLS,
    TOOL_DEFINITIONS,
    execute_tool,
)

logger = logging.getLogger(__name__)

CONFIRMATION_TOKEN_PARAM = "confirmation_token"

# Redis: one key per staged call, plus a list per conversation so the copilot
# can collect what a turn staged, whichever process ran the model.
STAGED_KEY_PREFIX = "copilot:action:"
_CONVERSATION_KEY_PREFIX = "copilot:staged:"
STAGED_TTL_SECONDS = 900

# Roles that may run admin tools. ``system`` is the non-loginable account
# background work runs as.
_PRIVILEGED_ROLES = frozenset({"admin", "system"})


def needs_confirmation(name: str) -> bool:
    """Writes, and the reads that store what they produce (extractions, drafts)."""
    return name in MUTATING_TOOLS or name in PERSISTING_READ_TOOLS


def confirmation_token_tools() -> frozenset[str]:
    """Tools with a two-step token flow (deletes): the first call returns a token."""
    return frozenset(
        t["name"] for t in TOOL_DEFINITIONS if CONFIRMATION_TOKEN_PARAM in (t["input_schema"].get("properties") or {})
    )


# The two-step instructions in a delete tool's description ("First call returns
# a confirmation prompt... only call again with the confirmation_token...") are
# for the skill CLI. A model here is told the click is the confirmation.
_TOKEN_STEPS_RE = re.compile(r"REQUIRES user confirmation.*?explicitly approves?\.\s*", re.DOTALL)
_CLICK_NOTE = "Calling it only proposes the deletion: the user confirms it with a click."


def _model_description(description: str) -> str:
    if "confirmation_token" not in description:
        return description
    stripped = _TOKEN_STEPS_RE.sub("", description).strip()
    return f"{stripped} {_CLICK_NOTE}"


def _strip_token(schema: dict) -> dict:
    if CONFIRMATION_TOKEN_PARAM not in (schema.get("properties") or {}):
        return schema
    schema = copy.deepcopy(schema)
    schema["properties"].pop(CONFIRMATION_TOKEN_PARAM, None)
    if "required" in schema:
        schema["required"] = [r for r in schema["required"] if r != CONFIRMATION_TOKEN_PARAM]
    return schema


def model_tool_definitions(*, role: str, names: Iterable[str] | None = None, include_writes: bool = True) -> list[dict]:
    """Registry definitions a model acting for a user with ``role`` may be shown.

    ``names`` narrows the set (unknown names are ignored); ``None`` offers the
    whole registry. Returned in the registry's own shape (``name``,
    ``description``, ``input_schema``, ``mutating``); see ``function_specs`` and
    ``anthropic_specs`` for the wire shapes.
    """
    allow = set(names) if names is not None else None
    privileged = role in _PRIVILEGED_ROLES
    out: list[dict] = []
    for t in TOOL_DEFINITIONS:
        name = t["name"]
        if allow is not None and name not in allow:
            continue
        if name in ADMIN_TOOLS and not privileged:
            continue
        if not include_writes and needs_confirmation(name):
            continue
        out.append(
            {**t, "description": _model_description(t["description"]), "input_schema": _strip_token(t["input_schema"])}
        )
    return out


def function_specs(defs: list[dict]) -> list[dict]:
    """OpenAI-style function tools (Ollama ``/api/chat``, ``/v1/chat/completions``)."""
    return [
        {
            "type": "function",
            "function": {"name": d["name"], "description": d["description"], "parameters": d["input_schema"]},
        }
        for d in defs
    ]


def anthropic_specs(defs: list[dict]) -> list[dict]:
    """Anthropic Messages API tools."""
    return [{"name": d["name"], "description": d["description"], "input_schema": d["input_schema"]} for d in defs]


# Two small tools that reach the rest of the registry, so a model needn't be
# shown every schema: ~170 tools are ~26k tokens a round, and OpenAI refuses
# more than 128 in one request. The model looks a tool up, then calls it; the
# call goes through the same checks as a directly offered tool.
FIND_TOOLS = "find_tools"
CALL_TOOL = "call_tool"
_FIND_LIMIT = 12


def meta_tool_definitions() -> list[dict]:
    return [
        {
            "name": FIND_TOOLS,
            "description": (
                "Find more IntelFeed tools than the ones listed here. With a query (words like 'campaign', "
                "'merge', 'detection rule', 'feed'), returns matching tools with their arguments. Without one, "
                "lists every tool name you can use. Then run one with call_tool."
            ),
            "input_schema": {
                "type": "object",
                "properties": {"query": {"type": "string", "description": "What the tool should do"}},
            },
            "mutating": False,
        },
        {
            "name": CALL_TOOL,
            "description": (
                "Run an IntelFeed tool found with find_tools. Tools that change data only propose the "
                "change: the user confirms it."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "tool": {"type": "string", "description": "Tool name from find_tools"},
                    "args": {"type": "object", "description": "The tool's arguments"},
                },
                "required": ["tool"],
            },
            "mutating": False,
        },
    ]


def find_tools(defs: list[dict], query: str | None) -> str:
    """``find_tools``'s answer over ``defs`` (the tools ``call_tool`` may reach)."""
    if not (query or "").strip():
        return json.dumps({"tools": sorted(d["name"] for d in defs), "next": "find_tools(query=...) for arguments"})
    words = [w for w in query.lower().replace("_", " ").split() if w]
    scored = []
    for d in defs:
        name = d["name"].replace("_", " ")
        text = f"{name} {d['description']}".lower()
        score = sum(3 if w in name else 1 for w in words if w in text)
        if score:
            scored.append((score, d))
    scored.sort(key=lambda pair: (-pair[0], pair[1]["name"]))
    return json.dumps(
        {
            "tools": [
                {
                    "name": d["name"],
                    "description": d["description"][:400],
                    "arguments": d["input_schema"],
                    "changes_data": needs_confirmation(d["name"]),
                }
                for _, d in scored[:_FIND_LIMIT]
            ]
        },
        default=str,
    )


def describe_call(name: str, args: dict) -> str:
    """One line for the confirm card: the tool's name in words plus its arguments."""
    label = name.replace("_", " ").capitalize()
    parts = []
    for k, v in (args or {}).items():
        text = v if isinstance(v, str) else json.dumps(v, default=str)
        if len(text) > 60:
            text = text[:57] + "..."
        parts.append(f"{k}={text}")
    return f"{label} ({', '.join(parts)})" if parts else label


def check_call(name: str, args: dict, *, role: str, offered: Iterable[str] | None) -> str | None:
    """Why this call may not run, or None. Shared by the in-process gate and the HTTP one."""
    if offered is not None and name not in offered:
        return f"Tool '{name}' is not available here"
    if name in ADMIN_TOOLS and role not in _PRIVILEGED_ROLES:
        return f"Tool '{name}' requires admin access"
    if isinstance(args, dict) and CONFIRMATION_TOKEN_PARAM in args:
        return (
            "confirmation_token is not accepted here: the user confirms a change by clicking "
            "Confirm on it. Call the tool without it."
        )
    return None


def auto_approvable_tools() -> list[str]:
    """Writes an admin may let skip the click: never an admin tool, never a two-step delete.

    A delete's first call only returns a token, so "running it" without the
    click would delete nothing and hand the model a token it can't use.
    """
    blocked = ADMIN_TOOLS | confirmation_token_tools()
    return sorted(t["name"] for t in TOOL_DEFINITIONS if needs_confirmation(t["name"]) and t["name"] not in blocked)


def auto_approve_tools() -> frozenset[str]:
    """Writes an admin lets the copilot run without a click (``copilot_auto_approve_tools``)."""
    from app.config import settings

    raw = str(settings.get("copilot_auto_approve_tools") or "")
    names = {n.strip() for n in raw.split(",") if n.strip()}
    return frozenset(names & set(auto_approvable_tools()))


async def stage_tool_call(
    *, user_id: uuid.UUID, conversation_id: uuid.UUID | str | None, tool_name: str, args: dict
) -> str:
    """Hold a write for the user's confirmation; returns its action id."""
    from app.services.redis_client import get_redis

    action_id = str(uuid.uuid4())
    r = await get_redis()
    await r.set(
        f"{STAGED_KEY_PREFIX}{action_id}",
        json.dumps(
            {
                "user_id": str(user_id),
                "conversation_id": str(conversation_id) if conversation_id else None,
                "tool_name": tool_name,
                "args": args,
                "summary": describe_call(tool_name, args),
            },
            default=str,
        ),
        ex=STAGED_TTL_SECONDS,
    )
    if conversation_id:
        list_key = f"{_CONVERSATION_KEY_PREFIX}{conversation_id}"
        await r.rpush(list_key, action_id)
        await r.expire(list_key, STAGED_TTL_SECONDS)
    return action_id


def staged_reply(action_id: str, name: str) -> str:
    """What the model gets back instead of a result: the call has not run."""
    return json.dumps(
        {
            "status": "awaiting_confirmation",
            "action_id": action_id,
            "tool": name,
            "message": (
                "Not run yet. The user sees this change with Confirm and Cancel buttons and decides. "
                "Tell them in one line what you proposed. Do not say it is done."
            ),
        }
    )


async def take_staged(conversation_id: uuid.UUID | str, user_id: uuid.UUID) -> list[dict]:
    """The calls staged for this conversation since the last take, oldest first."""
    from app.services.redis_client import get_redis

    r = await get_redis()
    list_key = f"{_CONVERSATION_KEY_PREFIX}{conversation_id}"
    ids = await r.lrange(list_key, 0, -1)
    if ids:
        await r.delete(list_key)
    out: list[dict] = []
    for action_id in ids:
        raw = await r.get(f"{STAGED_KEY_PREFIX}{action_id}")
        if not raw:
            continue
        try:
            row = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if row.get("user_id") != str(user_id):
            continue
        out.append({**row, "action_id": action_id})
    return out


class ToolGate:
    """The executor an in-process tool loop calls, bound to one user and one turn.

    ``offered`` is what the model was shown. ``reachable`` (registry
    definitions) is what ``find_tools`` / ``call_tool`` may reach, when those
    two were offered; it defaults to the offered tools.
    """

    def __init__(
        self,
        *,
        db: AsyncSession,
        user_id: uuid.UUID,
        role: str,
        offered: Iterable[str],
        conversation_id: uuid.UUID | str | None,
        auto_approve: frozenset[str] = frozenset(),
        reachable: list[dict] | None = None,
    ) -> None:
        self.db = db
        self.user_id = user_id
        self.role = role
        self.offered = frozenset(offered)
        self.conversation_id = conversation_id
        self.auto_approve = auto_approve
        self.reachable = reachable or []
        self.reachable_names = frozenset(d["name"] for d in self.reachable) | (self.offered - {FIND_TOOLS, CALL_TOOL})

    async def __call__(self, name: str, args: dict) -> str:
        args = args if isinstance(args, dict) else {}
        if name in (FIND_TOOLS, CALL_TOOL) and name in self.offered:
            if name == FIND_TOOLS:
                return find_tools(self.reachable, args.get("query"))
            inner = str(args.get("tool") or "")
            inner_args = args.get("args") or {}
            if isinstance(inner_args, str):
                try:
                    inner_args = json.loads(inner_args) if inner_args.strip() else {}
                except json.JSONDecodeError:
                    return json.dumps({"error": "args must be a JSON object"})
            if inner in (FIND_TOOLS, CALL_TOOL):
                return json.dumps({"error": f"call {inner} directly"})
            return await self._run(inner, inner_args if isinstance(inner_args, dict) else {}, self.reachable_names)
        return await self._run(name, args, self.offered)

    async def _run(self, name: str, args: dict, allowed: frozenset[str]) -> str:
        refusal = check_call(name, args, role=self.role, offered=allowed)
        if refusal:
            return json.dumps({"error": refusal})
        if needs_confirmation(name) and name not in self.auto_approve:
            action_id = await stage_tool_call(
                user_id=self.user_id, conversation_id=self.conversation_id, tool_name=name, args=args
            )
            return staged_reply(action_id, name)
        result = await execute_tool(name, args, self.db, self.user_id)
        # A handler exception (execute_tool returns {"error": ...}) can leave the
        # shared session in a failed transaction; roll back so later tool calls
        # and the conversation write don't hit PendingRollbackError.
        if result.startswith('{"error"') and not self.db.sync_session.is_active:
            await self.db.rollback()
        elif needs_confirmation(name):
            await self.db.commit()
        return result


async def run_confirmed(db: AsyncSession, *, user_id: uuid.UUID, role: str, tool_name: str, args: dict) -> str:
    """Run a staged call the user approved. Returns the tool's JSON result.

    The click is the confirmation, so a tool with a two-step token flow gets
    its token here, server-side: the first call returns it and the second
    runs. A model never sees one.
    """
    args = {k: v for k, v in (args or {}).items() if k != CONFIRMATION_TOKEN_PARAM}
    refusal = check_call(tool_name, args, role=role, offered=None)
    if refusal:
        return json.dumps({"error": refusal})
    result = await execute_tool(tool_name, args, db, user_id)
    if tool_name in confirmation_token_tools():
        try:
            first = json.loads(result)
        except json.JSONDecodeError:
            first = None
        token = first.get(CONFIRMATION_TOKEN_PARAM) if isinstance(first, dict) else None
        if token:
            result = await execute_tool(tool_name, {**args, CONFIRMATION_TOKEN_PARAM: token}, db, user_id)
    return result
