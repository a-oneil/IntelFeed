"""Global copilot API — a streaming, tool-calling, read-only chat endpoint.

Workstream E (P1.0). Reuses the P0 AIConversation persistence and the SSE
framing from intelligence.py's ask-agent endpoints, but drives the Claude Code
CLI provider's ``stream_agent()`` method so it can (when the intelfeed skill is
installed where the CLI can load it) call read-only skill tools mid-answer and
surface a tool-call trace to the UI.

Read-only: the copilot task is seeded with an ``allowed_tools`` set of
``["Bash", "Read", "Skill"]`` against the read-only intelfeed skill — no write
tools, no confirm_request flow.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from decimal import Decimal

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict
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

# Sentinel that opens the proposed-action fence. When the model wants to write,
# it ends its reply with a ```intelfeed-action fenced block. We hold back a
# rolling tail of the text stream so this marker never reaches the client, then
# capture the JSON action after it for the confirm flow.
_ACTION_FENCE = "```intelfeed-action"
# How much trailing text to keep unflushed so a fence split across deltas is
# still detectable. Must be >= len(_ACTION_FENCE).
_HOLDBACK = len(_ACTION_FENCE)

# Redis key + TTL for a pending, awaiting-confirmation action.
_PENDING_KEY_PREFIX = "copilot:action:"
_PENDING_TTL_SECONDS = 900

# Action types the confirm endpoint can execute. Anything the model proposes
# outside this set is rejected at confirm time.
_SUPPORTED_ACTION_TYPES = ("create_campaign", "add_note")

# Curated default tool subset for the Ollama copilot — lives in app.tools so
# the registry and its defaults stay in one module. Override per-deployment via
# the copilot assignment's ``ollama_tools`` config key (Prompt Workspace →
# Routing panel).
from app.tools import DEFAULT_COPILOT_OLLAMA_TOOLS as _DEFAULT_OLLAMA_TOOLS  # noqa: E402


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


def _parse_action_block(captured: str) -> dict | None:
    """Parse the JSON inside a captured ```intelfeed-action fence.

    ``captured`` is everything after the ``_ACTION_FENCE`` marker (the closing
    ```` ``` ```` may or may not be present). Returns the parsed action dict on
    success (must have a supported ``type`` and a ``params`` object), else None.
    """
    body = captured
    # Drop a leading newline after the fence marker and strip a trailing ``` .
    body = body.strip()
    if body.startswith("```"):  # shouldn't happen, but be defensive
        body = body[3:]
    # Cut at the closing fence if present.
    if "```" in body:
        body = body.split("```", 1)[0]
    body = body.strip()
    if not body:
        return None
    try:
        action = json.loads(body)
    except json.JSONDecodeError:
        logger.warning("copilot: could not parse action block JSON: %s", body[:300])
        return None
    if not isinstance(action, dict):
        return None
    atype = action.get("type")
    params = action.get("params")
    if atype not in _SUPPORTED_ACTION_TYPES or not isinstance(params, dict):
        logger.warning("copilot: unsupported/malformed action proposed: %s", str(action)[:300])
        return None
    return action


class _FenceSplitter:
    """Incremental splitter that withholds the ```intelfeed-action fence.

    Feed it text deltas via :meth:`feed`, which returns the text that is SAFE to
    forward to the client (i.e. cannot be part of the fence marker). A rolling
    tail of ``_HOLDBACK`` chars is always kept back until we know it's not the
    start of the fence. Once the fence marker is seen, forwarding stops and all
    subsequent text is accumulated into :attr:`captured` for action parsing.
    """

    def __init__(self) -> None:
        self._buf = ""  # unflushed tail (potential fence prefix)
        self.fence_seen = False
        self.captured = ""  # text after the fence marker

    def feed(self, text: str) -> str:
        if self.fence_seen:
            self.captured += text
            return ""
        self._buf += text
        idx = self._buf.find(_ACTION_FENCE)
        if idx != -1:
            # Fence found: everything before it is visible; the rest is captured.
            visible = self._buf[:idx]
            self.captured += self._buf[idx + len(_ACTION_FENCE) :]
            self._buf = ""
            self.fence_seen = True
            return visible
        # No full fence yet. Flush everything except a trailing window that could
        # be the beginning of the fence marker.
        keep = 0
        max_prefix = min(len(self._buf), _HOLDBACK)
        for n in range(max_prefix, 0, -1):
            if _ACTION_FENCE.startswith(self._buf[-n:]):
                keep = n
                break
        if keep:
            visible = self._buf[:-keep]
            self._buf = self._buf[-keep:]
        else:
            visible = self._buf
            self._buf = ""
        return visible

    def flush(self) -> str:
        """Return any remaining buffered text (fence never appeared)."""
        if self.fence_seen:
            return ""
        out = self._buf
        self._buf = ""
        return out


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
    from app.ai.engine import get_task_assignment

    assignment_data = await get_task_assignment(db, user.id, "copilot")
    if not assignment_data:
        return {
            "configured": False,
            "provider_type": None,
            "provider_name": None,
            "default_ollama_tools": _DEFAULT_OLLAMA_TOOLS,
            "enabled_tools": None,
        }
    assignment, _, provider_model = assignment_data
    # Only Ollama restricts the copilot to an explicit tool allowlist; other
    # providers get the full read-only registry, so there's nothing to gate
    # the "/" command menu on for them (enabled_tools stays None = unrestricted).
    enabled_tools = None
    if provider_model.provider_type == "ollama":
        enabled_tools = assignment.config.get("ollama_tools") or _DEFAULT_OLLAMA_TOOLS
    return {
        "configured": True,
        "provider_type": provider_model.provider_type,
        "provider_name": provider_model.name,
        # Curated tool subset used when the assignment has no ollama_tools
        # override — the Prompt Workspace tools editor renders this as the
        # default selection.
        "default_ollama_tools": _DEFAULT_OLLAMA_TOOLS,
        # The assignment's actual effective allowlist (override or default),
        # used by the dock to hide "/" commands whose tool isn't enabled.
        "enabled_tools": enabled_tools,
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
      {"type": "done", "conversation_id": <uuid>}
      {"type": "error", "message": ...}
    """
    from sse_starlette.sse import EventSourceResponse

    from app.ai.caller import Caller
    from app.ai.engine import (
        _count_ai_call,
        _get_provider_instance,
        attribution_fields,
        get_active_prompt,
        get_task_assignment,
        render_prompt,
    )
    from app.ai.providers.claude_code_provider import ClaudeCodeProvider

    if not body.question.strip():
        raise AppError(code="bad_request", message="Question is required", status_code=400)

    ctx = body.context

    # Resolve the copilot task -> provider assignment. Must be assigned (seeded
    # to the claude_code provider on startup).
    assignment_data = await get_task_assignment(db, user.id, "copilot")
    if not assignment_data:
        raise AppError(
            code="not_configured",
            message="The 'Copilot' task has no AI provider assigned. Go to Settings > AI to configure it.",
            status_code=422,
        )
    assignment, task, provider_model = assignment_data

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
    system_template, user_template = await get_active_prompt(db, task.id)
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

    provider = _get_provider_instance(provider_model, extra_config=assignment.config)
    config = {**(provider_model.config or {}), **(assignment.config or {})}
    allowed_tools = config.get("allowed_tools")
    timeout_seconds = config.get("timeout_seconds")
    model = assignment.model_name

    async def generate():
        # ``assistant_parts`` collects only the VISIBLE text (what the client
        # sees / what we persist). The proposed-action fence is withheld by the
        # splitter and never lands here, so the stored assistant message is clean.
        assistant_parts: list[str] = []
        tool_events: list[dict] = []
        errored: str | None = None
        # Usage/cost off the stream's terminal "done" event (see
        # ClaudeCodeProvider._extract_usage). None when the CLI died before its
        # result event or a non-CLI fallback provider handled the turn.
        turn_usage: dict | None = None
        turn_started = time.monotonic()
        splitter = _FenceSplitter()

        def _emit_text(text: str) -> str | None:
            """Route a text delta through the fence splitter; return SSE json or None."""
            visible = splitter.feed(text)
            if visible:
                assistant_parts.append(visible)
                return json.dumps({"type": "chunk", "text": visible})
            return None

        # Effective per-call timeout (shared by the CLI and Ollama agent paths).
        cli_timeout = float(timeout_seconds) if timeout_seconds else None
        # ``event_source`` is a stream of ClaudeCode-compatible {"kind": ...}
        # events. Both the CLI provider and the Ollama native tool loop populate
        # it, so the event-handling loop below is provider-agnostic. When it
        # stays None we fall back to text-only streaming.
        event_source = None

        try:
            if isinstance(provider, ClaudeCodeProvider):
                # Read-only env: physically forbid writes for this invocation.
                # The mounted skill CLI reads INTELFEED_READ_ONLY and refuses
                # write tools (autonomous maintenance tasks never set it).
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
                            "env": {"INTELFEED_READ_ONLY": "1"},
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
                        env={"INTELFEED_READ_ONLY": "1"},
                    )
            elif getattr(provider, "supports_tools", False) and hasattr(provider, "stream_agent"):
                # Ollama native tool loop — runs in-process (no creds needed, so
                # copilot_worker_dispatch does not apply). Tools are dispatched
                # against the backend registry via an in-process executor bound
                # to this request's db session + user; read-only tools only.
                from app.tools import execute_tool, ollama_tool_specs

                async def _tool_executor(name: str, args: dict) -> str:
                    result = await execute_tool(name, args, db, user.id)
                    # A handler exception (execute_tool returns {"error": ...})
                    # can leave the shared session in a failed transaction
                    # (is_active False); roll back so later tool calls + the
                    # conversation persistence don't hit PendingRollbackError.
                    if result.startswith('{"error"') and not db.sync_session.is_active:
                        await db.rollback()
                    return result

                tool_specs = ollama_tool_specs(config.get("ollama_tools") or _DEFAULT_OLLAMA_TOOLS, read_only=True)
                # NB: conversation history is already rendered into the prompt via
                # the copilot template's ``conversation_history`` variable (same as
                # the CLI path), so we do NOT also pass it as ``history`` here —
                # that would duplicate the thread.
                event_source = provider.stream_agent(
                    prompt=rendered_user,
                    system=rendered_system,
                    model=model,
                    tools=tool_specs,
                    tool_executor=_tool_executor,
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
                # Text-only fallback: a non-tool provider (Anthropic API) streams
                # via the base stream_complete contract. No tool trace.
                async for chunk in provider.stream_complete(prompt=rendered_user, system=rendered_system, model=model):
                    payload = _emit_text(chunk)
                    if payload is not None:
                        yield {"data": payload}
        except Exception as e:  # provider / CLI failure mid-stream
            errored = str(e)
            logger.warning("copilot stream error: %s", e)

        # Flush any held-back tail that never turned out to be a fence.
        tail = splitter.flush()
        if tail:
            assistant_parts.append(tail)
            yield {"data": json.dumps({"type": "chunk", "text": tail})}

        # If the model proposed an action, parse it and stage it in Redis for the
        # confirm endpoint. Failure to parse degrades to no proposal (the visible
        # answer still persists).
        pending_action: dict | None = None
        if splitter.fence_seen:
            pending_action = _parse_action_block(splitter.captured)

        # Persist the turn: append the user question + the assembled assistant
        # answer. JSONB reassignment + flag_modified so SQLAlchemy detects the
        # mutation (mirrors ai_conversations.py). The raw action block is NOT
        # included — only the visible prose.
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

        # Record the turn in ai_results so copilot usage shows up in the AI
        # cost dashboard (GET /api/ai/cost-breakdown aggregates these rows).
        # Usage comes from the CLI's terminal result event — captured in
        # whichever process ran the CLI and, on the worker topology, relayed
        # verbatim inside the "done" event; this api process owns the DB write
        # either way. Under the flat-rate Claude sign-in the dollar figure is
        # notional: it is the CLI-reported total_cost_usd (what the usage would
        # cost at API rates). This is the ONLY place a copilot turn is billed —
        # the stream path bypasses engine.run_task entirely.
        if answer or turn_usage:
            try:
                usage = turn_usage or {}
                cost_usd = usage.get("total_cost_usd")
                cost = Decimal(str(round(cost_usd, 6))) if cost_usd is not None else Decimal("0")
                tokens_input = int(usage.get("tokens_input") or 0)
                tokens_output = int(usage.get("tokens_output") or 0)
                parsed_result: dict = {
                    "_extraction_status": "provider_error" if errored else "success",
                    "conversation_id": str(conversation_id),
                }
                if turn_usage:
                    parsed_result["usage"] = usage
                if errored:
                    parsed_result["_error"] = errored
                db.add(
                    AIResult(
                        target_type="conversation",
                        target_id=conversation_id,
                        is_current=True,
                        task_id=task.id,
                        provider_id=provider_model.id,
                        model_name=model,
                        prompt_used=rendered_user[:20000],
                        raw_response=answer,
                        parsed_result=parsed_result,
                        tokens_input=tokens_input,
                        tokens_output=tokens_output,
                        cost_estimate=cost,
                        processing_time_ms=int((time.monotonic() - turn_started) * 1000),
                        **attribution_fields(Caller.user(user.id), provider_model),
                    )
                )
                await db.commit()
                _count_ai_call(provider_model.provider_type, task.name, tokens_input, tokens_output, cost)
            except Exception as e:  # usage accounting must never break the stream
                logger.warning("copilot failed to record ai_result for conversation %s: %s", conversation_id, e)
                await db.rollback()

        # Stage the proposed action in Redis and emit a confirm_request BEFORE
        # done, so the client can render a confirm prompt.
        if pending_action is not None:
            action_id = str(uuid.uuid4())
            summary = str(pending_action.get("summary") or "").strip()
            params = pending_action.get("params") or {}
            action_type = pending_action.get("type")
            try:
                from app.services.redis_client import get_redis

                r = await get_redis()
                await r.set(
                    f"{_PENDING_KEY_PREFIX}{action_id}",
                    json.dumps(
                        {
                            "user_id": str(user.id),
                            "conversation_id": str(conversation_id),
                            "action_type": action_type,
                            "params": params,
                            "summary": summary,
                        }
                    ),
                    ex=_PENDING_TTL_SECONDS,
                )
                yield {
                    "data": json.dumps(
                        {
                            "type": "confirm_request",
                            "action_id": action_id,
                            "action_type": action_type,
                            "description": summary,
                            "proposed": params,
                        }
                    )
                }
            except Exception as e:  # staging failure shouldn't crash the stream
                logger.error("copilot failed to stage pending action: %s", e)

        if errored and not answer:
            yield {"data": json.dumps({"type": "error", "message": errored})}
        yield {"data": json.dumps({"type": "done", "conversation_id": str(conversation_id)})}

    return EventSourceResponse(generate())


# ---------------------------------------------------------------------------
# Confirm / execute a proposed write action
# ---------------------------------------------------------------------------


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


async def _execute_create_campaign(db: AsyncSession, user: User, params: dict) -> dict:
    """Create a campaign via the same model logic the campaigns API uses."""
    from app.models.campaign import Campaign

    name = (params.get("name") or "").strip()
    if not name:
        raise AppError(code="bad_request", message="Campaign name is required", status_code=400)
    status = params.get("status") or "active"
    if status not in ("active", "monitoring", "closed", "historical"):
        status = "active"
    campaign = Campaign(
        created_by=user.id,
        name=name[:255],
        description=params.get("description"),
        status=status,
        tlp_marking="TLP:GREEN",
    )
    db.add(campaign)
    await db.flush()
    await db.refresh(campaign)
    link = f"/workbench/campaign/{campaign.id}"
    return {
        "summary": f"Created campaign **{name}** — {link}",
        "link": link,
        "name": name,
    }


async def _execute_add_note(db: AsyncSession, user: User, params: dict) -> dict:
    """Add a note to an entry or an entity, reusing the notes models."""
    target = (params.get("target") or "").strip().lower()
    target_id_raw = params.get("target_id")
    content = (params.get("content") or "").strip()
    if not content:
        raise AppError(code="bad_request", message="Note content is required", status_code=400)
    if not target_id_raw:
        raise AppError(code="bad_request", message="target_id is required", status_code=400)
    try:
        target_id = uuid.UUID(str(target_id_raw))
    except (ValueError, AttributeError):
        raise AppError(code="bad_request", message="target_id is not a valid id", status_code=400)

    if target == "entry":
        from app.models.note import Note
        from app.services.markdown import render_markdown

        title = content.splitlines()[0][:120] if content else "Note"
        note = Note(
            created_by=user.id,
            entry_id=target_id,
            title=title,
            content_markdown=content,
            content_html=render_markdown(content),
            tags=[],
        )
        db.add(note)
        await db.flush()
        return {"summary": "Added note to the article.", "link": None}

    if target == "entity":
        from app.models.entity_note import EntityNote

        entity_type = (params.get("entity_type") or "").strip().lower()
        if entity_type not in ("threat_actor", "malware", "cve", "ttp", "campaign", "vendor", "product"):
            raise AppError(
                code="bad_request",
                message="entity_type must be one of threat_actor, malware, cve, ttp, campaign, vendor, product",
                status_code=400,
            )
        note = EntityNote(
            entity_type=entity_type,
            entity_id=target_id,
            user_id=user.id,
            content=content,
        )
        db.add(note)
        await db.flush()
        return {"summary": f"Added note to the {entity_type.replace('_', ' ')}.", "link": None}

    raise AppError(code="bad_request", message="target must be 'entry' or 'entity'", status_code=400)


# Dispatch table: action_type -> async handler(db, user, params) -> result dict.
# Extend here to support new confirmable write actions.
_ACTION_HANDLERS = {
    "create_campaign": _execute_create_campaign,
    "add_note": _execute_add_note,
}


@router.post("/confirm")
async def copilot_confirm(
    body: CopilotConfirmRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Execute (or cancel) a copilot-proposed write action.

    The action was staged in Redis by the /stream endpoint. We verify ownership,
    and — if approved — execute it via the existing service/model layer (never
    the skill CLI), append a success message to the conversation, and return the
    result. Approving with ``edited_params`` overrides the proposed params.
    """
    from app.services.redis_client import get_redis

    key = f"{_PENDING_KEY_PREFIX}{body.action_id}"
    r = await get_redis()
    raw = await r.get(key)
    if not raw:
        # TTL-expired or unknown id.
        raise AppError(
            code="not_found",
            message="This proposed action has expired or does not exist. Ask the copilot again.",
            status_code=404,
        )
    try:
        pending = json.loads(raw)
    except json.JSONDecodeError:
        await r.delete(key)
        return {"status": "error", "message": "Stored action was corrupt; discarded."}

    # Ownership check — a pending action is private to the user who proposed it.
    if pending.get("user_id") != str(user.id):
        raise AppError(code="not_found", message="Proposed action not found", status_code=404)

    if not body.approved:
        await r.delete(key)
        return {"status": "cancelled"}

    action_type = pending.get("action_type")
    params = body.edited_params if body.edited_params is not None else (pending.get("params") or {})
    handler = _ACTION_HANDLERS.get(action_type)
    if handler is None:
        await r.delete(key)
        return {"status": "error", "message": f"Unsupported action type: {action_type}"}

    try:
        result = await handler(db, user, params)
    except AppError as e:
        # Keep the key so the user can retry with edited params.
        return {"status": "error", "message": e.message}
    except Exception as e:
        logger.error("copilot confirm: %s handler failed: %s", action_type, e)
        await db.rollback()
        return {"status": "error", "message": f"Failed to execute action: {e}"}

    # Append a success message to the conversation this action came from.
    conversation_id = pending.get("conversation_id")
    if conversation_id:
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
                new_messages.append(
                    {
                        "role": "assistant",
                        "content": f"✓ {result.get('summary')}",
                        "created_at": now_iso(),
                        "meta": {"action_executed": action_type},
                    }
                )
                conv.messages = new_messages
                flag_modified(conv, "messages")
        except Exception as e:  # message append is best-effort
            logger.warning("copilot confirm: failed to append conversation message: %s", e)

    await db.commit()
    await r.delete(key)

    return {"status": "executed", "result": result}
