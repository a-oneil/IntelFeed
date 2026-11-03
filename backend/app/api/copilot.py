"""Global copilot API — a streaming, tool-calling chat endpoint.

Reuses the AIConversation persistence and the SSE framing from
intelligence.py's ask-agent endpoints, and drives the answering provider's
``stream_agent()`` so it can call IntelFeed tools mid-answer and surface a
tool-call trace to the UI.

Every provider gets the registry under the asking user's permissions, through
one gate (app.tools.gate): reads run, writes are staged and run only when the
user clicks Confirm (``/confirm``). On the Claude CLI the tools come from the
IntelFeed MCP server holding a ``propose`` agent token for this conversation;
on the Anthropic API, OpenAI-compatible servers and Ollama, from an in-process
loop whose executor is the gate itself.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from decimal import Decimal

import anyio
from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict
from sqlalchemy import inspect as sa_inspect
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import flag_modified

from app import entity_types
from app.config import settings
from app.core.exceptions import AppError
from app.core.security import get_current_user
from app.core.utils import now_iso
from app.database import get_db
from app.models.ai_conversation import AIConversation
from app.models.ai_result import AIResult
from app.models.user import User

logger = logging.getLogger(__name__)

router = APIRouter()

# Cap the history we replay into the prompt so long threads don't blow the
# context window / latency budget. Matches the P0 "last ~20 messages" guidance.
_MAX_HISTORY_MESSAGES = 20

from app.tools import DEFAULT_COPILOT_TOOLS, DEFAULT_COPILOT_WRITE_TOOLS  # noqa: E402
from app.tools.gate import STAGED_KEY_PREFIX, STAGED_TTL_SECONDS, auto_approvable_tools  # noqa: E402


def _default_copilot_tools() -> list[str]:
    """The tools shown to the model directly when the assignment sets none.

    The everyday reads and writes. Everything else the user may run stays
    reachable through ``find_tools`` / ``call_tool`` (app.tools.gate): the whole
    registry's schemas (~26k tokens) would swamp a local model, and OpenAI
    refuses more than 128 tools in one request.
    """
    return [*DEFAULT_COPILOT_TOOLS, *DEFAULT_COPILOT_WRITE_TOOLS]


def _copilot_tool_override(config: dict) -> list[str] | None:
    """The assignment's ``agent_tools``: exactly these, nothing more."""
    override = config.get("agent_tools")
    return list(override) if override else None


def _copilot_tool_plan(role: str, config: dict, *, read_only: bool = False) -> tuple[list[dict], list[dict]]:
    """(definitions shown to the model, definitions ``call_tool`` may reach) for one user.

    ``read_only`` (the docs-page copilot, which has no confirm cards) leaves
    out every tool that changes data.
    """
    from app.tools.gate import meta_tool_definitions, model_tool_definitions

    include_writes = not read_only
    override = _copilot_tool_override(config)
    if override is not None:
        defs = model_tool_definitions(role=role, names=override, include_writes=include_writes)
        return defs, defs
    reachable = model_tool_definitions(role=role, include_writes=include_writes)
    direct = set(_default_copilot_tools())
    return [d for d in reachable if d["name"] in direct] + meta_tool_definitions(), reachable


class CopilotContext(BaseModel):
    entry_id: uuid.UUID | None = None
    # Multi-article pinning (the bulk-selection "Ask Copilot"). Mutually
    # exclusive with entry_id in practice; entry_id wins if both are set.
    entry_ids: list[uuid.UUID] | None = None
    entity_type: str | None = None
    entity_id: uuid.UUID | None = None
    campaign_id: uuid.UUID | None = None
    search_query: str | None = None
    route: str | None = None
    # Slug of the documentation page being read, when the analyst is in the
    # docs. Empty string / absent on the docs landing page.
    doc_slug: str | None = None
    # Read tools only. The docs-page copilot sets it: it shows no confirm
    # cards, so a change it proposed would have nowhere to be confirmed.
    read_only: bool = False


# Directory under docs/ holding the user-facing guide, as opposed to the
# developer reference. Mirrors the pinned section order in
# app.services.documentation.
_GUIDE_DIR = "guide"

# Article content injected into the ambient context when entries are pinned.
# A pinned article means "this text is in the conversation" — the model answers
# grounded in it without needing a get_entry round-trip (tools remain available
# for going beyond it). Caps keep local-model context windows honest.
_PINNED_ENTRY_MAX_CHARS = 15_000
_PINNED_MULTI_MAX_ENTRIES = 8
_PINNED_MULTI_MAX_CHARS = 4_000


def _clip(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "\n... [article truncated]"


def _render_pinned_entry(entry, max_chars: int) -> str:
    """Render one pinned article (header + capped body) for the ambient context."""
    title = entry.title or "(untitled)"
    header = f'## Pinned article: "{title}" (entry id {entry.id})'
    meta: list[str] = []
    if entry.published_at:
        meta.append(f"Published: {entry.published_at:%Y-%m-%d}")
    if entry.url:
        meta.append(f"URL: {entry.url}")
    body = (entry.content_text or "").strip()
    parts = [header]
    if meta:
        parts.append(" · ".join(meta))
    parts.append(_clip(body, max_chars) if body else "(no text content extracted)")
    return "\n".join(parts)


class CopilotStreamRequest(BaseModel):
    question: str
    conversation_id: uuid.UUID | None = None
    context: CopilotContext | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "question": "What TTPs does this article describe, and do we have detection coverage for them?",
                "conversation_id": "d5b2c8a4-3f1e-4b6a-9c2d-8e7f6a5b4c3d",
                "context": {
                    "entry_id": "0f8e7d6c-5b4a-4392-8170-6e5d4c3b2a19",
                    "route": "/entries",
                },
            }
        }
    )


# entity_type -> "module:Class" plus the attribute holding its display name.
# Kept local so the copilot doesn't depend on the API-layer entity registry
# (which pulls broader imports). Only the read-only "what am I looking at"
# lookup needs this; labels come from the shared vocabulary.
_AMBIENT_ENTITY_MODELS = {
    entity_types.THREAT_ACTOR: ("app.models.threat_actor:ThreatActor", "name"),
    entity_types.MALWARE: ("app.models.malware_family:MalwareFamily", "name"),
    entity_types.TOOL: ("app.models.tool:Tool", "name"),
    entity_types.VENDOR: ("app.models.vendor:Vendor", "name"),
    entity_types.PRODUCT: ("app.models.product:Product", "name"),
    entity_types.COUNTRY: ("app.models.country:Country", "name"),
    entity_types.MITIGATION: ("app.models.mitigation:Mitigation", "name"),
    entity_types.CVE: ("app.models.cve:CVE", "cve_id"),
    entity_types.TTP: ("app.models.ttp:TTP", "technique_id"),
    entity_types.RANSOMWARE_VICTIM: ("app.models.ransomware:RansomwareVictim", "name"),
}


async def _entity_display(db: AsyncSession, entity_type: str, entity_id: uuid.UUID) -> str | None:
    """Human-readable name for an entity, for the ambient 'you're looking at X'."""
    et = entity_types.normalize_entity_type((entity_type or "").lower())
    spec = _AMBIENT_ENTITY_MODELS.get(et)
    if not spec:
        return None
    model_path, name_attr = spec
    try:
        import importlib

        module_path, class_name = model_path.split(":")
        model = getattr(importlib.import_module(module_path), class_name)
        row = await db.get(model, entity_id)
        if not row:
            return None
        return f"{entity_types.LABELS[et]} {getattr(row, name_attr)}"
    except Exception as e:  # pragma: no cover - defensive; ambient text is best-effort
        logger.debug("copilot ambient entity lookup failed: %s", e)
    return None


DOCS_MODE_PREAMBLE = """
## Documentation mode

The analyst is in IntelFeed's in-app documentation, so this is a question about
the product itself — not a threat-intelligence question about the data in it.

Answer from the shipped docs rather than from memory. Use `search_documentation`
to find the right page and `get_documentation_page` to read it BEFORE you
answer. Cite what you used as a markdown link to `/documentation/<slug>`.

### Which half of the docs to answer from

The documentation has two halves, and picking the wrong one is the main way to
give a bad answer here.

**The guide** (`guide/...`) is for USING the app. Reach for it when the question
is how to do something, where a feature lives, what a screen means, or why the
app is behaving a certain way for this analyst. Phrasings: "how do I…", "how do
I set up…", "where is…", "what does this do", "how do I make it…", "why isn't
this working". A question about configuring something THROUGH THE UI is a guide
question, not a reference one.

**The reference** (everything else: architecture, data-model, api-reference,
frontend, adapters, intelligence-engine, workers, operations, contributing, …)
is for how IntelFeed is BUILT. Reach for it when the question is about
implementation, code layout, database schema, API endpoints, deployment, or
extending the platform. Phrasings: "how does X work under the hood", "how is X
implemented", "where in the code…", "what's the schema for…", "how do I add a
new adapter/widget/endpoint", "how do I deploy…".

When a question spans both — "how does the priority ranking work?" — lead with
the guide answer, in plain terms about what the analyst sees, then offer the
reference page for the mechanism. Do not open with implementation detail for
someone who asked a how-do-I question.

If the docs genuinely don't cover something, say so plainly instead of inventing
behaviour. You may still fall back to the read-only data tools when the question
turns out to be about what is actually in their feed.
"""


def _docs_mode_context(doc_slug: str | None) -> str:
    """Docs-mode preamble plus the page index, split guide vs reference.

    The index goes in verbatim — it is small, a few dozen titles — so the model
    can name the right page in one shot instead of burning a tool round-trip on
    `list_documentation_pages` for every question. Splitting it by half is what
    makes the routing rule above actionable rather than advisory.
    """
    from app.services import documentation as docs_service

    parts = [DOCS_MODE_PREAMBLE.strip()]

    guide = [p for p in docs_service.index() if p.slug.startswith(f"{_GUIDE_DIR}/")]
    reference = [p for p in docs_service.index() if not p.slug.startswith(f"{_GUIDE_DIR}/")]

    def _render(pages, *, summaries: bool) -> str:
        lines = []
        for page in pages:
            line = f"- `{page.slug}` — {page.title}"
            if summaries and page.summary:
                # One clause is enough to route on; full summaries run to 280
                # chars each and this block is re-sent on every single turn.
                line += f": {page.summary[:120]}"
            lines.append(line)
        return "\n".join(lines)

    # Summaries only on the guide half. It is the smaller list and the one the
    # model has to choose within most often; reference titles are already
    # self-describing ("data-model", "api-reference"), and carrying 36 summaries
    # doubled this block for no routing benefit.
    if guide:
        parts.append(f"### Guide pages — how to USE IntelFeed\n{_render(guide, summaries=True)}")
    if reference:
        parts.append(f"### Reference pages — how IntelFeed is BUILT\n{_render(reference, summaries=False)}")

    if doc_slug:
        half = "guide" if doc_slug.startswith(f"{_GUIDE_DIR}/") else "reference"
        parts.append(
            f"The last documentation page this analyst read was `{doc_slug}` (a {half} page). "
            f'A vague follow-up — "what does that mean", "how do I do that" — most likely '
            f"refers to it. Do not assume it when the question names something else."
        )
    return "\n\n".join(parts)


async def _build_ambient_context(db: AsyncSession, ctx: CopilotContext | None) -> str:
    """Render a short human string describing what the analyst is looking at.

    Best-effort: any lookup failure degrades to omitting that line rather than
    erroring the whole request.
    """
    if ctx is None:
        return ""
    lines: list[str] = []

    if ctx.entry_id is not None:
        from app.models.entry import Entry

        entry = await db.get(Entry, ctx.entry_id)
        if entry is not None:
            lines.append(_render_pinned_entry(entry, _PINNED_ENTRY_MAX_CHARS))
    elif ctx.entry_ids:
        from app.models.entry import Entry

        pinned = ctx.entry_ids[:_PINNED_MULTI_MAX_ENTRIES]
        dropped = len(ctx.entry_ids) - len(pinned)
        lines.append(f"The analyst has pinned {len(ctx.entry_ids)} articles:")
        for eid in pinned:
            entry = await db.get(Entry, eid)
            if entry is not None:
                lines.append(_render_pinned_entry(entry, _PINNED_MULTI_MAX_CHARS))
        if dropped > 0:
            lines.append(
                f"({dropped} more pinned articles omitted for context budget — use get_entry with their ids if needed.)"
            )

    if ctx.entity_type and ctx.entity_id is not None:
        display = await _entity_display(db, ctx.entity_type, ctx.entity_id)
        if display:
            lines.append(f"The analyst is viewing the {display} profile (id {ctx.entity_id}).")

    if ctx.campaign_id is not None:
        from app.models.campaign import Campaign

        campaign = await db.get(Campaign, ctx.campaign_id)
        if campaign is not None:
            lines.append(f'The analyst is viewing the campaign "{campaign.name}" (id {ctx.campaign_id}).')

    if ctx.search_query:
        lines.append(f'The analyst is searching for "{ctx.search_query}".')

    if ctx.route:
        lines.append(f"They are on the {ctx.route} page.")

    if (ctx.route or "").startswith("/documentation"):
        lines.append(_docs_mode_context(ctx.doc_slug))

    return "\n".join(lines)


def _scope_from_context(ctx: CopilotContext | None) -> tuple[str, str | None]:
    """Map the request context to an AIConversation (scope_type, scope_id).

    Global when there's no anchoring context; entry/entity scoped otherwise so
    the thread shows up in the right place in conversation history.
    """
    if ctx is None:
        return "global", None
    if ctx.entry_id is not None:
        return "entry", str(ctx.entry_id)
    if ctx.entry_ids:
        return "multi_entry", None
    if ctx.entity_type and ctx.entity_id is not None:
        return "entity", f"{ctx.entity_type}:{ctx.entity_id}"
    return "global", None


# Redis list namespace the copilot worker RPUSHes streamed events onto. Must
# match _STREAM_KEY_PREFIX in app/workers/copilot_tasks.py.
_WORKER_STREAM_PREFIX = "copilot:stream:"


async def _iter_worker_events(run_id: str, blpop_timeout: float):
    """Drain the copilot worker's Redis event list, yielding raw stream_agent events.

    Mirrors ``ClaudeCodeProvider.stream_agent``'s ``{"kind": ...}`` output so the
    endpoint's event-handling loop is identical whether the CLI ran in-process or
    on the worker. Terminates on the worker's ``__end__`` sentinel; raises on
    ``__error__`` (so the endpoint's existing ``except`` sets ``errored``) or if
    the worker goes silent past ``blpop_timeout`` (dead worker / broker backlog).
    """
    from app.services.redis_client import get_redis

    r = await get_redis()
    key = f"{_WORKER_STREAM_PREFIX}{run_id}"
    while True:
        item = await r.blpop([key], timeout=int(blpop_timeout))
        if item is None:
            raise TimeoutError("Copilot worker produced no output — it may be down or overloaded.")
        _, raw = item
        try:
            ev = json.loads(raw)
        except json.JSONDecodeError:
            continue
        kind = ev.get("kind")
        if kind == "__end__":
            return
        if kind == "__error__":
            raise RuntimeError(ev.get("message") or "Copilot worker error")
        yield ev


@router.get("/config")
async def copilot_config(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Report which provider the copilot task is assigned to.

    The dock uses this to decide whether the Claude-Code sign-in health check /
    re-auth banner is relevant: the OAuth banner only applies when copilot runs
    on the ``claude_code`` CLI. On Ollama (or any other provider) there is no
    OAuth session, so the banner must not show.
    """
    from app.ai.caller import Caller
    from app.ai.engine import UserKeyRequired, provider_runs_tools, resolve_assignment

    unconfigured = {
        "configured": False,
        "provider_type": None,
        "provider_name": None,
        "default_tools": _default_copilot_tools(),
        "auto_approvable_tools": auto_approvable_tools(),
        "enabled_tools": None,
        "source": None,
        "model": None,
        "supports_tools": False,
        "fallback_reason": None,
        "refused": None,
    }
    try:
        # A status read: no allowance is spent here.
        resolved = await resolve_assignment(db, Caller.user(user.id), "copilot", allowance=False)
    except UserKeyRequired as e:
        # The dock shows what to fix (add a key, raise a cap) instead of the
        # generic "no provider" message.
        return {**unconfigured, "refused": {"reason": e.reason, "message": e.message}}
    if resolved is None:
        return unconfigured
    provider_model = resolved.provider
    return {
        "configured": True,
        "provider_type": provider_model.provider_type,
        "provider_name": provider_model.name,
        # The tools shown directly when the assignment sets no ``agent_tools``
        # (the rest stay reachable through find_tools / call_tool) — the
        # Prompt Workspace tools editor renders it as the default selection.
        "default_tools": _default_copilot_tools(),
        # Writes the copilot_auto_approve_tools setting may name (the Prompt
        # Workspace's "skip Confirm" checkboxes).
        "auto_approvable_tools": auto_approvable_tools(),
        # The assignment's ``agent_tools`` when it narrows the copilot to just
        # those (None = every tool the user may run), used by the dock to hide
        # "/" commands whose tool isn't enabled.
        "enabled_tools": _copilot_tool_override(resolved.config),
        # Whose provider answers: "user" means the person's own key, and the
        # dock says so in its header. A provider with tool calling turned off
        # answers without tools, and the dock says that too.
        "source": resolved.source,
        "model": resolved.model_name,
        "supports_tools": provider_runs_tools(provider_model, resolved.config),
        "fallback_reason": resolved.fallback_reason,
        "refused": None,
    }


@router.post("/stream")
async def copilot_stream(
    body: CopilotStreamRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Stream a copilot answer over SSE, persisting the turn to an AIConversation.

    SSE event schema (each ``data:`` is a JSON object):
      {"type": "chunk", "text": ...}
      {"type": "tool_call", "id", "name", "args"}
      {"type": "tool_result", "id", "status", "summary"}
      {"type": "done", "conversation_id": <uuid>, "answered_by": {...}}
      {"type": "error", "message": ...}
    """
    from sse_starlette.sse import EventSourceResponse

    from app.ai.caller import Caller
    from app.ai.engine import (
        _count_ai_call,
        _estimate_cost,
        _get_provider_instance,
        attribution_fields,
        get_active_prompt_versioned,
        provider_runs_tools,
        render_prompt,
        resolve_assignment,
    )
    from app.ai.providers.claude_code_provider import ClaudeCodeProvider

    if not body.question.strip():
        raise AppError(code="bad_request", message="Question is required", status_code=400)

    ctx = body.context
    read_only_turn = bool(ctx and ctx.read_only)
    # Staged writes are collected per turn, so one this request never got to
    # collect (the client left) can't surface as a card on a later turn.
    turn_id = uuid.uuid4()

    # Resolve the copilot task -> provider: the person's own key when one
    # applies, else the site assignment (seeded to the claude_code provider
    # on startup). The lookup enforces the site allowance and the key policy.
    resolved = await resolve_assignment(db, Caller.user(user.id), "copilot")
    if resolved is None:
        raise AppError(
            code="not_configured",
            message="The 'Copilot' task has no AI provider assigned. Go to Settings > AI to configure it.",
            status_code=422,
        )
    task, provider_model = resolved.task, resolved.provider

    # Load or create the conversation (scoped to this user).
    scope_type, scope_id = _scope_from_context(ctx)
    conv: AIConversation | None = None
    if body.conversation_id is not None:
        result = await db.execute(
            select(AIConversation).where(
                AIConversation.id == body.conversation_id,
                AIConversation.user_id == user.id,
            )
        )
        conv = result.scalar_one_or_none()
        if conv is None:
            raise AppError(code="not_found", message="Conversation not found", status_code=404)
    if conv is None:
        title = body.question.strip()
        title = title[:57] + "..." if len(title) > 60 else title
        conv = AIConversation(
            user_id=user.id,
            title=title,
            scope_type=scope_type,
            scope_id=scope_id,
            messages=[],
        )
        db.add(conv)
        await db.commit()
        await db.refresh(conv)

    conversation_id = conv.id

    # Build the prompt from the copilot task templates + ambient context.
    system_template, user_template, prompt_version = await get_active_prompt_versioned(db, task.id)
    ambient = await _build_ambient_context(db, ctx)

    prior = list(conv.messages or [])[-_MAX_HISTORY_MESSAGES:]
    history = [{"role": m.get("role"), "content": m.get("content")} for m in prior]

    variables = {
        "question": body.question,
        "conversation_history": history,
        "ambient_context": ambient,
    }
    rendered_system = render_prompt(system_template, variables) if system_template else None
    rendered_user = render_prompt(user_template, variables)

    provider = _get_provider_instance(provider_model, extra_config=resolved.config)
    config = resolved.config
    allowed_tools = config.get("allowed_tools")
    timeout_seconds = config.get("timeout_seconds")
    model = resolved.model_name

    async def generate():
        # The answer text, as streamed to the client and saved.
        assistant_parts: list[str] = []
        tool_events: list[dict] = []
        errored: str | None = None
        # Usage/cost off the stream's terminal "done" event (see
        # ClaudeCodeProvider._extract_usage). None when the CLI died before its
        # result event or a non-CLI fallback provider handled the turn.
        turn_usage: dict | None = None
        turn_cost: Decimal | None = None
        turn_started = time.monotonic()
        ledgered = False

        async def _ledger(error: str | None) -> None:
            """Record the turn in ai_results so copilot usage shows up in the AI
            cost dashboard (GET /api/ai/cost-breakdown aggregates these rows).

            Usage comes from the CLI's terminal result event — captured in
            whichever process ran the CLI and, on the worker topology, relayed
            verbatim inside the "done" event; this api process owns the DB write
            either way. Under the flat-rate Claude sign-in the dollar figure is
            notional: it is the CLI-reported total_cost_usd (what the usage would
            cost at API rates). This is the ONLY place a copilot turn is billed —
            the stream path bypasses engine.run_task entirely. A turn that failed
            before any text, or that the client abandoned, is a row too: failed
            calls count toward the site allowance and a personal key's request
            cap, as they do in run_task, so a broken key can't be retried for
            free. Accounting must never break the stream.
            """
            nonlocal turn_cost
            try:
                usage = turn_usage or {}
                cost_usd = usage.get("total_cost_usd")
                tokens_input = int(usage.get("tokens_input") or 0)
                tokens_output = int(usage.get("tokens_output") or 0)
                # A provider that reports tokens but no price (the Anthropic
                # API) is priced from the engine's table, like run_task does;
                # otherwise a personal key's dollar cap would never see copilot.
                if cost_usd is not None:
                    cost = Decimal(str(round(cost_usd, 6)))
                else:
                    cost = _estimate_cost(model, tokens_input, tokens_output)
                visible = "".join(assistant_parts).strip()
                parsed_result: dict = {
                    "_extraction_status": "provider_error" if error else "success",
                    "conversation_id": str(conversation_id),
                }
                if turn_usage:
                    parsed_result["usage"] = usage
                if error:
                    parsed_result["_error"] = error
                if resolved.fallback_reason:
                    parsed_result["_fallback_reason"] = resolved.fallback_reason
                if prompt_version is not None:
                    parsed_result["_prompt_version"] = prompt_version
                db.add(
                    AIResult(
                        target_type="conversation",
                        target_id=conversation_id,
                        is_current=True,
                        task_id=task.id,
                        provider_id=provider_model.id,
                        model_name=model,
                        prompt_used=rendered_user[:20000],
                        raw_response=visible,
                        parsed_result=parsed_result,
                        tokens_input=tokens_input,
                        tokens_output=tokens_output,
                        cost_estimate=cost,
                        processing_time_ms=int((time.monotonic() - turn_started) * 1000),
                        **attribution_fields(Caller.user(user.id), provider_model, key_owner_id=resolved.key_owner_id),
                    )
                )
                await db.commit()
                turn_cost = cost
                _count_ai_call(provider_model.provider_type, task.name, tokens_input, tokens_output, cost)
            except Exception as e:
                logger.warning("copilot failed to record ai_result for conversation %s: %s", conversation_id, e)
                await db.rollback()

        def _emit_text(text: str) -> str | None:
            """Record a text delta; return its SSE json, or None when empty."""
            if not text:
                return None
            assistant_parts.append(text)
            return json.dumps({"type": "chunk", "text": text})

        # Effective per-call timeout (shared by the CLI and Ollama agent paths).
        cli_timeout = float(timeout_seconds) if timeout_seconds else None
        # ``event_source`` is a stream of ClaudeCode-compatible {"kind": ...}
        # events. Both the CLI provider and the Ollama native tool loop populate
        # it, so the event-handling loop below is provider-agnostic. When it
        # stays None we fall back to text-only streaming.
        event_source = None

        try:
            try:
                if isinstance(provider, ClaudeCodeProvider):
                    # The CLI's IntelFeed tools act for this user: the provider
                    # mints a propose token for this conversation, so a write
                    # the model asks for is staged for the user's click.
                    if settings.copilot_worker_dispatch:
                        # Prod topology: run the CLI on the dedicated claude_code
                        # worker (owns the OAuth credentials volume) and relay its
                        # events back over Redis. The api never needs the CLI/creds.
                        from app.workers.celery_app import celery_app

                        run_id = str(uuid.uuid4())
                        celery_app.send_task(
                            "app.workers.copilot_tasks.run_copilot_stream",
                            kwargs={
                                "run_id": run_id,
                                "prompt": rendered_user,
                                "system": rendered_system,
                                "model": model,
                                "allowed_tools": allowed_tools,
                                "timeout_seconds": cli_timeout,
                                "provider_config": config,
                                "agent_user_id": str(user.id),
                                "agent_conversation_id": None if read_only_turn else str(conversation_id),
                                "agent_turn_id": str(turn_id),
                            },
                            queue="ai",
                        )
                        # BLPOP window: the worker heartbeats between tokens, so any
                        # single gap should be short; size it off the CLI ceiling
                        # plus margin for queue pickup / first-token latency.
                        blpop_timeout = (cli_timeout or 180.0) + 60.0
                        event_source = _iter_worker_events(run_id, blpop_timeout)
                    else:
                        # In-process fallback (dev boxes where the api has the CLI +
                        # credentials). Set copilot_worker_dispatch=false to use this.
                        event_source = provider.stream_agent(
                            prompt=rendered_user,
                            system=rendered_system,
                            model=model,
                            allowed_tools=allowed_tools,
                            timeout_seconds=cli_timeout,
                            heartbeat_label="copilot stream",
                            agent_user_id=user.id,
                            agent_conversation_id=None if read_only_turn else conversation_id,
                            agent_turn_id=turn_id,
                        )
                elif getattr(provider, "supports_tools", False) and hasattr(provider, "stream_agent"):
                    # In-process tool loop (Anthropic API, OpenAI-compatible,
                    # Ollama): no CLI credentials, so copilot_worker_dispatch
                    # does not apply. The executor is the tool gate, bound to
                    # this user, this conversation and exactly the tools
                    # offered: reads run, writes are staged for the user's
                    # click, and a tool the model names without being offered
                    # it is refused.
                    from app.tools.gate import ToolGate, auto_approve_tools

                    tool_defs, reachable = _copilot_tool_plan(user.role, config, read_only=read_only_turn)
                    gate = ToolGate(
                        db=db,
                        user_id=user.id,
                        role=user.role,
                        offered=[d["name"] for d in tool_defs],
                        conversation_id=conversation_id,
                        auto_approve=auto_approve_tools(),
                        reachable=reachable,
                        turn_id=turn_id,
                    )
                    # NB: conversation history is already rendered into the prompt via
                    # the copilot template's ``conversation_history`` variable (same as
                    # the CLI path), so we do NOT also pass it as ``history`` here —
                    # that would duplicate the thread.
                    event_source = provider.stream_agent(
                        prompt=rendered_user,
                        system=rendered_system,
                        model=model,
                        tools=provider.render_tools(tool_defs),
                        tool_executor=gate,
                        timeout_seconds=cli_timeout,
                        heartbeat_label="copilot stream",
                    )

                if event_source is not None:
                    async for ev in event_source:
                        kind = ev.get("kind")
                        if kind == "text":
                            payload = _emit_text(ev.get("text") or "")
                            if payload is not None:
                                yield {"data": payload}
                        elif kind == "tool_call":
                            payload = {
                                "type": "tool_call",
                                "id": ev.get("id"),
                                "name": ev.get("name"),
                                "args": ev.get("args"),
                            }
                            tool_events.append(payload)
                            yield {"data": json.dumps(payload)}
                        elif kind == "tool_result":
                            payload = {
                                "type": "tool_result",
                                "id": ev.get("id"),
                                "status": ev.get("status"),
                                "summary": ev.get("summary"),
                            }
                            tool_events.append(payload)
                            yield {"data": json.dumps(payload)}
                        elif kind == "done":
                            # Capture token usage / CLI-reported cost for the
                            # ai_results row below. The SSE "done" frame itself is
                            # emitted after persistence, at the end of generate().
                            turn_usage = ev.get("usage") or None
                else:
                    # Text-only fallback: a provider with tool calling turned off
                    # streams via the base stream_complete contract. No tool trace.
                    async for chunk in provider.stream_complete(
                        prompt=rendered_user, system=rendered_system, model=model
                    ):
                        payload = _emit_text(chunk)
                        if payload is not None:
                            yield {"data": payload}
                    streamed = getattr(provider, "last_stream_usage", None)
                    if streamed:
                        turn_usage = {
                            "tokens_input": streamed.get("tokens_input") or 0,
                            "tokens_output": streamed.get("tokens_output") or 0,
                            "total_cost_usd": streamed.get("cost_usd"),
                        }
            except Exception as e:  # provider / CLI failure mid-stream
                errored = str(e)
                logger.warning("copilot stream error: %s", e)

            # Tools run in savepoints (app.tools.gate.execute_isolated), but a
            # handler can still roll the whole session back, which expires
            # what this turn loaded. Reload it before saving the turn, billing
            # it and collecting its staged writes: a lazy load here fails.
            for loaded in (conv, user, task, provider_model):
                try:
                    if sa_inspect(loaded).expired_attributes:
                        await db.refresh(loaded)
                except Exception as e:  # never break the stream over it
                    logger.warning("copilot could not reload %s after a tool rollback: %s", type(loaded).__name__, e)

            # Persist the turn: append the user question + the assembled assistant
            # answer. JSONB reassignment + flag_modified so SQLAlchemy detects the
            # mutation (mirrors ai_conversations.py).
            answer = "".join(assistant_parts).strip()
            try:
                new_messages = list(conv.messages or [])
                new_messages.append({"role": "user", "content": body.question, "created_at": now_iso()})
                assistant_msg: dict = {
                    "role": "assistant",
                    "content": answer,
                    "created_at": now_iso(),
                }
                if tool_events:
                    assistant_msg["meta"] = {"tool_events": tool_events}
                if errored and not answer:
                    assistant_msg["content"] = f"(error: {errored})"
                new_messages.append(assistant_msg)
                conv.messages = new_messages
                flag_modified(conv, "messages")
                await db.commit()
            except Exception as e:  # persistence failure shouldn't drop the answer
                logger.error("copilot failed to persist conversation %s: %s", conversation_id, e)
                await db.rollback()

            # Bill the turn (see _ledger). Done before the footer is sent, so the
            # footer can carry the cost.
            if answer or turn_usage or errored:
                await _ledger(errored)
            ledgered = True

            # Writes the model asked for through tools, staged by the gate (in
            # this process, or by /api/tools/execute for the CLI's propose
            # token). One confirm card each, oldest first.
            try:
                from app.tools.gate import take_staged

                for row in await take_staged(turn_id, user.id):
                    yield {"data": json.dumps(_confirm_request_event(row))}
            except Exception as e:  # a lost card is a missed write, not a broken stream
                logger.error("copilot failed to collect staged tool calls: %s", e)

            if errored and not answer:
                yield {"data": json.dumps({"type": "error", "message": errored})}
            # The reply footer: which provider answered, whose key, and what the
            # turn cost when the provider reported it.
            answered_by = {
                "provider_name": provider_model.name,
                "provider_type": provider_model.provider_type,
                "source": resolved.source,
                "model": model,
                "cost_usd": float(turn_cost) if turn_cost is not None else None,
                "fallback_reason": resolved.fallback_reason,
                "supports_tools": provider_runs_tools(provider_model, resolved.config),
            }
            yield {
                "data": json.dumps(
                    {"type": "done", "conversation_id": str(conversation_id), "answered_by": answered_by}
                )
            }
        finally:
            # The client went away mid-turn. sse-starlette cancels this task,
            # so the write has to be shielded or it is cancelled at its first
            # await. The prompt reached the provider either way, so even a turn
            # abandoned before its first token is spend: a disconnect-and-retry
            # loop must not be free.
            if not ledgered:
                with anyio.CancelScope(shield=True):
                    await _ledger(errored or "client disconnected")

    return EventSourceResponse(generate())


# ---------------------------------------------------------------------------
# Confirm / execute a proposed write action
# ---------------------------------------------------------------------------


def _is_destructive(tool_name: str) -> bool:
    """Deletes (the two-step token tools) and admin-only tools: no edited args, a warning on the card."""
    from app.tools import ADMIN_TOOLS
    from app.tools.gate import confirmation_token_tools

    return tool_name in ADMIN_TOOLS or tool_name in confirmation_token_tools()


def _confirm_request_event(row: dict) -> dict:
    """The SSE frame for one staged tool call."""
    tool_name = row.get("tool_name") or ""
    return {
        "type": "confirm_request",
        "action_id": row["action_id"],
        "tool_name": tool_name,
        "proposed": row.get("args") or {},
        # What the ids in ``proposed`` name, and a delete's own summary.
        "targets": row.get("targets") or {},
        "preview": row.get("preview"),
        "destructive": _is_destructive(tool_name),
    }


class CopilotConfirmRequest(BaseModel):
    action_id: str
    approved: bool
    edited_params: dict | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "action_id": "a3f9c2e1-7b6d-4e5f-9a8b-1c2d3e4f5a6b",
                "approved": True,
                "edited_params": {"name": "APT29 Phishing Wave 2026-08", "status": "active"},
            }
        }
    )


async def _claim(r, key: str) -> str:
    """Take the one-at-a-time claim on a staged action; returns the claim key.

    The claim lives as long as the action can (a confirmed tool may run for
    minutes; a short claim would let a second click run it again). After
    taking it, the action must still exist: a click that lands just after
    another approval finished and deleted it would otherwise run it twice.
    """
    claim_key = f"{key}:claim"
    if not await r.set(claim_key, "1", nx=True, ex=STAGED_TTL_SECONDS):
        raise AppError(code="conflict", message="This action is already being confirmed", status_code=409)
    if not await r.exists(key):
        await r.delete(claim_key)
        raise AppError(code="not_found", message="This action was already confirmed or has expired.", status_code=404)
    return claim_key


async def _append_conversation_note(
    db: AsyncSession, user: User, conversation_id: str | None, content: str, meta: dict
) -> None:
    """Add an assistant line to the conversation the action came from (best-effort)."""
    if not conversation_id:
        return
    try:
        conv_res = await db.execute(
            select(AIConversation).where(
                AIConversation.id == uuid.UUID(conversation_id),
                AIConversation.user_id == user.id,
            )
        )
        conv = conv_res.scalar_one_or_none()
        if conv is not None:
            new_messages = list(conv.messages or [])
            new_messages.append({"role": "assistant", "content": content, "created_at": now_iso(), "meta": meta})
            conv.messages = new_messages
            flag_modified(conv, "messages")
    except Exception as e:
        logger.warning("copilot confirm: failed to append conversation message: %s", e)


@router.post("/confirm")
async def copilot_confirm(
    body: CopilotConfirmRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Run (or cancel) a tool call the copilot staged for this user's confirmation.

    Only the user it was staged for can confirm it. It runs as that user, with
    their role checked again now (``run_confirmed``). ``edited_params``
    replaces the arguments, except on a destructive call, which is confirmed
    as shown or cancelled. On success a line is added to the conversation, so
    the model sees the result on the next turn. On an error the staged call is
    kept for a retry.
    """
    from app.services.redis_client import get_redis
    from app.tools.gate import run_confirmed

    key = f"{STAGED_KEY_PREFIX}{body.action_id}"
    r = await get_redis()
    raw_pending = await r.get(key)
    if not raw_pending:
        raise AppError(
            code="not_found",
            message="This proposed action has expired or does not exist. Ask the copilot again.",
            status_code=404,
        )
    try:
        pending = json.loads(raw_pending)
    except json.JSONDecodeError:
        await r.delete(key)
        return {"status": "error", "message": "Stored action was corrupt; discarded."}

    if pending.get("user_id") != str(user.id):
        raise AppError(code="not_found", message="Proposed action not found", status_code=404)

    if not body.approved:
        await r.delete(key)
        return {"status": "cancelled"}

    tool_name = pending["tool_name"]
    if body.edited_params is not None and _is_destructive(tool_name):
        return {"status": "error", "message": "This change can't be edited. Confirm it as shown or cancel it."}
    args = body.edited_params if body.edited_params is not None else (pending.get("args") or {})

    claim_key = await _claim(r, key)
    try:
        raw = await run_confirmed(db, user_id=user.id, role=user.role, tool_name=tool_name, args=args)
    except Exception as e:
        logger.error("copilot confirm: %s failed: %s", tool_name, e)
        await db.rollback()
        await r.delete(claim_key)
        return {"status": "error", "message": f"Failed to execute action: {e}"}
    try:
        result = json.loads(raw)
    except json.JSONDecodeError:
        result = raw
    if isinstance(result, dict) and result.get("error"):
        if not db.sync_session.is_active:
            await db.rollback()
        await r.delete(claim_key)
        return {"status": "error", "message": str(result["error"])[:500]}

    summary = f"Done: {pending.get('summary') or tool_name}"
    await _append_conversation_note(
        db,
        user,
        pending.get("conversation_id"),
        f"✓ {summary}. Result: {' '.join(raw.split())[:300]}",
        {"action_executed": tool_name},
    )
    await db.commit()
    await r.delete(key, claim_key)
    return {"status": "executed", "result": {"summary": summary, "tool_name": tool_name}}
