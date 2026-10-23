"""AI execution engine: task routing, prompt rendering, execution."""

import json
import logging
import re
import time as _time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Literal

from jinja2.sandbox import ImmutableSandboxedEnvironment
from sqlalchemy import func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.caller import Caller, current_caller
from app.ai.providers.base import AIProvider, AIResponse
from app.ai.providers.claude_code_provider import ClaudeCodeProvider, QuotaExhaustedError
from app.ai.providers.claude_provider import ClaudeProvider
from app.ai.providers.ollama_provider import OllamaProvider
from app.ai.providers.openai_provider import OpenAICompatibleProvider
from app.core.encryption import decrypt_value
from app.core.exceptions import AppError
from app.core.metrics import AI_COST_TOTAL, AI_REQUEST_DURATION_SECONDS, AI_REQUESTS_TOTAL, AI_TOKENS_TOTAL
from app.models.ai_prompt_template import AIPromptTemplate
from app.models.ai_provider import AIProvider as AIProviderModel
from app.models.ai_result import AIResult
from app.models.ai_task import AITask
from app.models.ai_task_assignment import AITaskAssignment
from app.models.user_ai_route import UserAIPreferences, UserAIRoute

logger = logging.getLogger(__name__)

# Cost per 1M tokens (input/output) — approximate defaults
COST_TABLE: dict[str, tuple[float, float]] = {
    "claude-opus-4-6": (15.0, 75.0),
    "claude-sonnet-4-6": (3.0, 15.0),
    "claude-haiku-4-5-20251001": (0.80, 4.0),
}


def _estimate_cost(model: str, tokens_in: int, tokens_out: int, batch: bool = False) -> Decimal:
    rates = COST_TABLE.get(model, (0.0, 0.0))
    cost = (tokens_in / 1_000_000) * rates[0] + (tokens_out / 1_000_000) * rates[1]
    if batch:
        cost *= 0.5  # Anthropic Message Batches API flat discount
    return Decimal(str(round(cost, 6)))


def _count_ai_call(provider_type: str, task_name: str, tokens_in: int, tokens_out: int, cost: Decimal) -> None:
    """Bump the Prometheus counters every result write shares."""
    AI_REQUESTS_TOTAL.labels(provider=provider_type, task=task_name).inc()
    AI_TOKENS_TOTAL.labels(provider=provider_type, direction="input").inc(tokens_in)
    AI_TOKENS_TOTAL.labels(provider=provider_type, direction="output").inc(tokens_out)
    AI_COST_TOTAL.labels(provider=provider_type).inc(float(cost))


def utc_day_start() -> datetime:
    """Midnight UTC today: when the per-user allowance, the share-link limit
    and the dashboard's "today" column all reset. Change it here and they
    stay on one clock."""
    return datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)


def utc_month_start() -> datetime:
    """The first of the month, UTC: when a personal key's dollar cap resets."""
    return datetime.now(UTC).replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def attribution_fields(
    caller: Caller, provider_model: AIProviderModel | None, *, key_owner_id: uuid.UUID | None = None
) -> dict:
    """The AIResult columns that say who asked and who answered.

    Every result write — run_task's three, the batch poller's, copilot's and
    the direct-call ledger — splats this in, so the cost dashboard and the
    per-user caps see one consistent record. ``key_owner_id`` stays None
    until a personal provider answers a call.
    """
    return {
        "user_id": caller.user_id,
        "key_owner_id": key_owner_id,
        "caller_kind": caller.kind,
        "provider_name": provider_model.name if provider_model is not None else None,
    }


#: A backslash that does not start a legal JSON escape. Small models write
#: Windows paths and command lines into string values verbatim
#: ("C:\ProgramData\x.exe"), which is an invalid escape and used to lose the
#: whole analysis. Doubling only the illegal ones is lossless for valid JSON.
_BAD_ESCAPE_RE = re.compile(r'\\(?![\\/"bfnrtu])')


def _repair_json(text: str) -> str:
    repaired = _BAD_ESCAPE_RE.sub(r"\\\\", text)
    # A truncated response (output budget hit) is unrecoverable, but a trailing
    # comma before a closing bracket is not.
    return re.sub(r",\s*([}\]])", r"\1", repaired)


_CLOSER = {"{": "}", "[": "]"}


def _salvage_truncated_json(text: str, *, max_attempts: int = 200) -> dict | None:
    """Recover an object from JSON cut off mid-stream (output budget hit).

    Walks the text once, tracking string/escape state and the open-bracket
    stack, and records every point where an element closed at depth <= 2 —
    the end of a top-level scalar, or of one element inside a top-level
    array. Then, from the latest such point backwards, it cuts the text
    there, drops a dangling comma, appends the closers the stack still owes,
    and tries to parse. The first parse that succeeds is the longest prefix
    made only of complete elements, so a response that died inside the 40th
    TTP still yields every section emitted before it — which, with the
    indicator sections front-loaded in the schema, is the ledger's part."""
    cut_points: list[tuple[int, str]] = []
    stack: list[str] = []
    in_string = False
    escape = False
    for i, ch in enumerate(text):
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
                if len(stack) <= 2:
                    cut_points.append((i, "".join(_CLOSER[o] for o in reversed(stack))))
            continue
        if ch == '"':
            in_string = True
        elif ch in "{[":
            stack.append(ch)
        elif ch in "}]":
            if stack:
                stack.pop()
            if len(stack) <= 2:
                cut_points.append((i, "".join(_CLOSER[o] for o in reversed(stack))))
        elif ch in "0123456789.eE-+" or ch in "truefalsn":
            # scalars at depth 1-2 end at the next delimiter; the bracket/quote
            # points are enough in practice, so no cut point is recorded here.
            pass
    if not stack and not cut_points:
        return None
    for pos, closers in reversed(cut_points[-max_attempts:]):
        candidate = re.sub(r",\s*$", "", text[: pos + 1].rstrip()) + closers
        for attempt in (candidate, _repair_json(candidate)):
            try:
                parsed = json.loads(attempt)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict) and parsed:
                return parsed
    return None


def parse_ai_json(content: str) -> dict:
    """Parse an AI JSON response, salvaging from markdown code fences,
    repairing illegal backslash escapes, and recovering the complete prefix
    of a response that was cut off by the output budget (shared with the
    batch poller). A salvaged result carries ``_truncated: True``."""
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        stripped = content.strip()
        if "```json" in stripped:
            stripped = stripped.split("```json")[1].split("```")[0].strip()
        elif "```" in stripped:
            stripped = stripped.split("```")[1].split("```")[0].strip()
        for candidate in (stripped, _repair_json(stripped)):
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                continue
        salvaged = _salvage_truncated_json(stripped)
        if salvaged is not None:
            salvaged["_truncated"] = True
            return salvaged
        return {"raw": content, "_extraction_status": "parse_error"}


async def demote_current_results(
    db: AsyncSession,
    *,
    target_type: str | None,
    target_id: uuid.UUID | None,
    task_id: uuid.UUID,
) -> None:
    """Clear the incumbent is_current row(s) for a (target, task) before inserting a new one.

    Readers treat "the current result" as a single row, so every is_current=True
    insert has to retire the previous one. Missing this is how a (target, task)
    ends up with several current rows, which used to make
    `_current_analysis_result`'s scalar_one_or_none() raise MultipleResultsFound
    and abort the whole hourly submit_analysis_batches run.
    """
    if target_type is None or target_id is None:
        return
    await db.execute(
        update(AIResult)
        .where(
            AIResult.target_type == target_type,
            AIResult.target_id == target_id,
            AIResult.task_id == task_id,
            AIResult.is_current == True,  # noqa: E712
        )
        .values(is_current=False)
    )


async def store_external_result(
    db,
    *,
    task,
    provider_model,
    entry_id,
    content: str,
    tokens_input: int,
    tokens_output: int,
    model_name: str,
    latency_ms: int = 0,
    batch: bool = False,
    prompt_used: str = "",
    caller: Caller | None = None,
) -> dict:
    """Persist an AI result produced outside run_task (e.g. the Batches API poller).

    Mirrors run_task's tail: marks prior current results for (entry, task) not
    current, records metrics + (batch-discounted) cost, stores the AIResult.
    Returns the parsed result dict.
    """
    parsed_result = parse_ai_json(content)
    if parsed_result and isinstance(parsed_result, dict) and "_extraction_status" not in parsed_result:
        parsed_result["_extraction_status"] = "success"

    cost = _estimate_cost(model_name, tokens_input, tokens_output, batch=batch)
    _count_ai_call(provider_model.provider_type, task.name, tokens_input, tokens_output, cost)

    await demote_current_results(db, target_type="entry", target_id=entry_id, task_id=task.id)
    ai_result = AIResult(
        entry_id=entry_id,
        target_type="entry",
        target_id=entry_id,
        is_current=True,
        task_id=task.id,
        provider_id=provider_model.id,
        model_name=model_name,
        prompt_used=prompt_used[:20000],
        raw_response=content,
        parsed_result=parsed_result,
        tokens_input=tokens_input,
        tokens_output=tokens_output,
        cost_estimate=cost,
        processing_time_ms=latency_ms,
        **attribution_fields(caller or Caller.system(), provider_model),
    )
    db.add(ai_result)
    await db.flush()
    return parsed_result


async def record_direct_result(
    db: AsyncSession,
    *,
    caller: Caller,
    task: AITask,
    provider_model: AIProviderModel,
    model_name: str | None,
    prompt_used: str,
    response: AIResponse | None,
    content: str | None = None,
    error: str | None = None,
    target_type: str | None = None,
    target_id: uuid.UUID | None = None,
    latency_ms: int | None = None,
    key_owner_id: uuid.UUID | None = None,
) -> AIResult:
    """Ledger a provider call made outside run_task.

    Rule conversion, rule chat, copilot-style Q&A on a share link: they call
    the provider directly because their prompts aren't task templates, but
    their spend has to land in ai_results or the cost dashboard and the
    per-user caps never see it. The row is never ``is_current`` — it is a
    spend record, not an answer the reader shows for a target.

    ``response`` is None for streamed calls, which report no usage: the row
    then counts as one request at zero tokens, which is still what a request
    cap needs.
    """
    tokens_in = response.tokens_input if response else 0
    tokens_out = response.tokens_output if response else 0
    model = response.model if response else model_name
    reported = getattr(response, "cost_usd", None)
    if isinstance(reported, (int, float)) and not isinstance(reported, bool):
        cost = Decimal(str(round(reported, 6)))
    else:
        cost = _estimate_cost(model or "", tokens_in, tokens_out)
    if latency_ms is None:
        latency_ms = response.latency_ms if response else 0

    parsed: dict = {"_extraction_status": "provider_error" if error else "success"}
    if error:
        parsed["_error"] = error

    # Like run_task, the request counters count answers; a failed call is
    # ledgered for the caps but is not usage.
    if error is None:
        _count_ai_call(provider_model.provider_type, task.name, tokens_in, tokens_out, cost)

    row = AIResult(
        target_type=target_type,
        target_id=target_id,
        is_current=False,
        task_id=task.id,
        provider_id=provider_model.id,
        model_name=model,
        prompt_used=prompt_used[:20000],
        raw_response=error if error else (content if content is not None else (response.content if response else "")),
        parsed_result=parsed,
        tokens_input=tokens_in,
        tokens_output=tokens_out,
        cost_estimate=cost,
        processing_time_ms=latency_ms,
        **attribution_fields(caller, provider_model, key_owner_id=key_owner_id),
    )
    db.add(row)
    await db.flush()
    return row


class SiteAllowanceExceeded(AppError):
    """A person has used their daily allowance of the instance's own providers."""

    def __init__(self, cap: int, used: int):
        super().__init__(
            code="ai_allowance_exceeded",
            message=(
                f"Daily AI allowance reached: {used} of {cap} requests on this instance's providers today. "
                "It resets at midnight UTC."
            ),
            status_code=429,
        )
        self.cap = cap
        self.used = used


async def site_requests_today(db: AsyncSession, user_id: uuid.UUID) -> int:
    """How many calls this person has made today on the instance's own providers."""
    day_start = utc_day_start()
    return (
        await db.execute(
            select(func.count(AIResult.id)).where(
                AIResult.user_id == user_id,
                AIResult.caller_kind == "user",
                AIResult.key_owner_id.is_(None),
                AIResult.created_at >= day_start,
            )
        )
    ).scalar_one()


async def enforce_site_allowance(db: AsyncSession, caller: Caller) -> None:
    """Refuse a person's call once they have used the day's allowance.

    Only ``user`` callers are capped: the pipeline, automation rules and
    share links are the operator's own spend, and a person's own key (once
    one can answer) is not the instance's. Failed calls count — they were
    requests — so a broken provider cannot be retried for free.
    """
    if not caller.is_user or caller.user_id is None:
        return
    from app.services.system_settings import get_setting

    cap = int(await get_setting("site_ai_user_daily_requests", db) or 0)
    if cap <= 0:
        return
    used = await site_requests_today(db, caller.user_id)
    if used >= cap:
        raise SiteAllowanceExceeded(cap, used)


async def derive_caller(db: AsyncSession, user_id: uuid.UUID | None) -> Caller:
    """The caller a bare ``user_id`` stands for, when nobody built one.

    A real person's id is a user caller. The ``system`` service account is
    background work even when a worker forgot to say so, and an id that
    matches no users row (the all-zero sentinel, a deleted account) is
    background work with nobody to attribute it to — writing such an id to
    the result's foreign key would fail the whole call.
    """
    caller = Caller.user(user_id) if user_id is not None else Caller.system()
    if not caller.is_user:
        return caller
    from app.models.user import User as _User

    role = (await db.execute(select(_User.role).where(_User.id == user_id))).scalar_one_or_none()
    if role is None:
        return Caller.system()
    if role == "system":
        return Caller.system(user_id)
    return caller


# ---------------------------------------------------------------- personal keys


class UserKeyRequired(AppError):
    """An interactive task was refused because the person's own key can't answer.

    Raised under the Required policy for any reason, and under Optional when
    the person has turned fallback off. ``reason`` is one of the
    ``FALLBACK_REASONS`` codes so the UI can say what to fix.
    """

    def __init__(self, reason: str, message: str):
        super().__init__(
            code="user_ai_key_required",
            message=message,
            status_code=403,
            details={"reason": reason},
        )
        self.reason = reason


#: Why a person's key did not answer, in the words the result card shows.
FALLBACK_REASONS: dict[str, str] = {
    "no_key": "You have no personal AI key for this task.",
    "key_disabled": "Your personal key is disabled.",
    "key_paused": "Your personal key is paused after a rate-limit response from its provider.",
    "type_not_allowed": "Your personal key's provider type is no longer allowed on this instance.",
    "endpoint_blocked": "Your personal key's endpoint is not allowed on this instance.",
    "monthly_cap": "Your personal key reached its monthly spend cap.",
    "daily_cap": "Your personal key reached its daily request cap.",
}


@dataclass(frozen=True, slots=True)
class Resolved:
    """Which provider answers a call, and why.

    ``source`` is "user" when a personal key answers: ``key_owner_id`` is
    then the person and goes on the result row, and the site allowance does
    not apply. ``fallback_reason`` is set when the person has a key that
    could not answer and the instance's provider took the call instead.
    """

    task: AITask
    provider: AIProviderModel
    model_name: str
    config: dict
    source: Literal["site", "user"]
    fallback_reason: str | None = None

    @property
    def key_owner_id(self) -> uuid.UUID | None:
        return self.provider.user_id if self.source == "user" else None

    @property
    def fallback_message(self) -> str | None:
        return FALLBACK_REASONS.get(self.fallback_reason) if self.fallback_reason else None


def allowed_personal_types(raw: object) -> set[str]:
    """The provider types a person may register, parsed from the setting."""
    from app.ai.capabilities import PERSONAL_PROVIDER_TYPES

    names = {part.strip().lower() for part in str(raw or "").split(",")}
    return {name for name in names if name in PERSONAL_PROVIDER_TYPES}


async def user_key_spend_month(db: AsyncSession, user_id: uuid.UUID) -> Decimal:
    """Dollars one person's own keys have spent since the first of the month."""
    total = (
        await db.execute(
            select(func.coalesce(func.sum(AIResult.cost_estimate), 0)).where(
                AIResult.key_owner_id == user_id,
                AIResult.created_at >= utc_month_start(),
            )
        )
    ).scalar_one()
    return Decimal(str(total))


async def user_key_requests_today(db: AsyncSession, user_id: uuid.UUID) -> int:
    """Calls one person's own keys have taken today, failures included."""
    return (
        await db.execute(
            select(func.count(AIResult.id)).where(
                AIResult.key_owner_id == user_id,
                AIResult.created_at >= utc_day_start(),
            )
        )
    ).scalar_one()


async def user_monthly_cap(db: AsyncSession, prefs: UserAIPreferences | None) -> Decimal:
    """The dollar cap that applies to one person: the admin's default, or
    their own lower figure. Zero or less means unlimited."""
    from app.services.system_settings import get_setting

    default = Decimal(str(await get_setting("user_ai_default_monthly_usd", db) or 0))
    own = prefs.monthly_cap_usd if prefs is not None else None
    # A person's own figure must be a real cap: zero is "unlimited" to the
    # check below, and the API refuses it, but a row that has it is still
    # read as the default rather than as no cap at all.
    if own is None or Decimal(str(own)) <= 0:
        return default
    own = Decimal(str(own))
    if default <= 0:
        return own
    return min(own, default)


async def _user_route(db: AsyncSession, user_id: uuid.UUID, task_id: uuid.UUID) -> UserAIRoute | None:
    """The person's route for this task, else their default key, else None."""
    rows = (
        (
            await db.execute(
                select(UserAIRoute).where(
                    UserAIRoute.user_id == user_id,
                    or_(UserAIRoute.task_id == task_id, UserAIRoute.task_id.is_(None)),
                )
            )
        )
        .scalars()
        .all()
    )
    for route in rows:
        if route.task_id == task_id:
            return route
    return rows[0] if rows else None


async def _route_blocked(db: AsyncSession, route: UserAIRoute, provider: AIProviderModel) -> str | None:
    """Why this route can't answer right now, or None when it can.

    The endpoint is re-checked on every call, not just when the key was
    saved: DNS answers change, and a key's type can stop being allowed
    after it was added.
    """
    from app.core.outbound import check_outbound_url
    from app.services.system_settings import get_setting

    if not provider.is_active:
        return "key_disabled"
    if provider.paused_until is not None and provider.paused_until > datetime.now(UTC):
        return "key_paused"
    if provider.provider_type not in allowed_personal_types(await get_setting("user_ai_provider_types", db)):
        return "type_not_allowed"
    if provider.base_url:
        allow_private = bool(await get_setting("user_ai_allow_private_endpoints", db))
        if await check_outbound_url(provider.base_url, allow_private=allow_private):
            return "endpoint_blocked"
    elif provider.provider_type in ("ollama", "openai_compatible"):
        # No address means the provider's localhost default: the server's own
        # Ollama under a personal key.
        return "endpoint_blocked"

    prefs = await db.get(UserAIPreferences, route.user_id)
    cap_usd = await user_monthly_cap(db, prefs)
    if cap_usd > 0 and await user_key_spend_month(db, route.user_id) >= cap_usd:
        return "monthly_cap"
    cap_requests = int(await get_setting("user_ai_daily_request_cap", db) or 0)
    if cap_requests > 0 and await user_key_requests_today(db, route.user_id) >= cap_requests:
        return "daily_cap"
    return None


async def resolve_assignment(
    db: AsyncSession,
    caller: Caller,
    task_name: str,
    *,
    allowance: bool = True,
) -> Resolved | None:
    """Which provider answers ``task_name`` for ``caller``.

    The site's assignment is today's lookup and the answer for everything
    but a person clicking a button while personal keys are on. For a person:
    the task must allow personal keys, the person must have a route (for the
    task, or a default key), and that key must be usable and under its caps.
    Otherwise the site's provider answers with ``fallback_reason`` set, or
    the call is refused when the policy is Required or the person has turned
    fallback off.

    ``allowance`` enforces the site's per-person daily allowance whenever the
    site's provider answers a person's call. ``run_task`` passes False and
    enforces it itself after its dedup guard, so a cached answer costs
    nothing; every direct caller leaves it on.

    Returns None when nothing can answer: the task has no site assignment
    and no personal key applies.
    """
    from app.services.system_settings import get_setting

    site_row = await get_task_assignment(db, caller.user_id, task_name)
    site: Resolved | None = None
    if site_row is not None:
        assignment, task, provider = site_row
        site = Resolved(task, provider, assignment.model_name, {**provider.config, **assignment.config}, "site")

    personal_ok = (
        caller.is_user and caller.user_id is not None and bool(await get_setting("allow_user_ai_providers", db))
    )
    if not personal_ok:
        if site is not None and allowance:
            await enforce_site_allowance(db, caller)
        return site

    task = (
        site.task
        if site is not None
        else (await db.execute(select(AITask).where(AITask.name == task_name))).scalar_one_or_none()
    )
    if task is None:
        return None

    blocked: str | None = None
    route = await _user_route(db, caller.user_id, task.id) if task.allows_user_provider else None
    if route is not None:
        provider = await db.get(AIProviderModel, route.provider_id)
        # A route may only point at the person's own key; anything else is a
        # stale row, and the site answers as if it were not there.
        if provider is None or provider.user_id != caller.user_id:
            route = None
        else:
            blocked = await _route_blocked(db, route, provider)
            if blocked is None:
                return Resolved(task, provider, route.model_name, {**provider.config, **route.config}, "user")

    required = bool(await get_setting("require_user_ai_provider", db))
    if task.allows_user_provider and (required or route is not None):
        reason = blocked or "no_key"
        prefs = await db.get(UserAIPreferences, caller.user_id)
        fallback = prefs.fallback_to_site if prefs is not None else True
        if required or not fallback:
            message = FALLBACK_REASONS[reason]
            if required:
                message += " This instance requires a personal key for the tasks you start."
            else:
                message += " You have turned off falling back to the instance's providers."
            raise UserKeyRequired(reason, message)

    if site is None:
        if blocked is not None:
            # Their key is the only provider this task has, and it can't
            # answer: say why, rather than "no provider assigned".
            raise UserKeyRequired(blocked, FALLBACK_REASONS[blocked])
        return None
    if allowance:
        await enforce_site_allowance(db, caller)
    if route is not None:
        return Resolved(
            site.task, site.provider, site.model_name, site.config, "site", fallback_reason=blocked or "no_key"
        )
    return site


async def preflight_ai(db: AsyncSession, caller: Caller, task_name: str) -> Resolved | None:
    """Refuse now what the lookup would refuse later.

    For work that runs in a worker (a report), so the person gets the 429 or
    the key-required error before anything is queued, not part-way through.
    """
    return await resolve_assignment(db, caller, task_name)


async def preflight_report(db: AsyncSession, caller: Caller, template_type: str) -> None:
    """The report pre-flight, on the task the worker will actually run.

    Sections run on the template's own task (report_section_exposure, ...)
    and fall back to the generic report_section only when that task has no
    provider, so the check follows the same order; checking the generic task
    alone would refuse a person whose key is routed to the family task, or
    pass one whose family task the admin has closed.
    """
    from app.intelligence.reporting import REPORT_SECTION_TASKS

    task_name = REPORT_SECTION_TASKS.get(template_type, "report_section")
    if await preflight_ai(db, caller, task_name) is None and task_name != "report_section":
        await preflight_ai(db, caller, "report_section")


class UnsupportedProviderTypeError(ValueError):
    """Raised for a provider row whose `provider_type` isn't a known value.

    The schema has rejected anything but claude/ollama/openai_compatible
    since the provider-create endpoint's inception, and claude_code is only
    ever seeded by the app itself — so this can only fire for a row created
    by a manual DB edit, and such a row was already broken (it used to
    silently fall through to ClaudeProvider and send Anthropic-shaped
    requests to whatever base_url was set).
    """


def _get_provider_instance(
    provider_model: AIProviderModel,
    extra_config: dict | None = None,
) -> AIProvider:
    """Create a provider instance from a database model.

    `extra_config` is layered on top of provider_model.config so per-task
    AITaskAssignment.config keys (e.g. allowed_tools, timeout_seconds) reach
    the provider without changing the AIProvider.complete() signature.
    """
    api_key = None
    if provider_model.api_key_encrypted:
        api_key = decrypt_value(provider_model.api_key_encrypted)

    merged_config = {**(provider_model.config or {}), **(extra_config or {})}

    provider_type = (provider_model.provider_type or "claude").lower()
    if provider_type == "claude":
        return ClaudeProvider(
            base_url=provider_model.base_url,
            api_key=api_key,
            config=merged_config,
        )

    if provider_type == "claude_code":
        return ClaudeCodeProvider(
            base_url=provider_model.base_url,
            api_key=api_key,  # Used as fallback if OAuth fails (ANTHROPIC_API_KEY in env)
            config=merged_config,
        )

    if provider_type == "ollama":
        return OllamaProvider(
            base_url=provider_model.base_url,
            api_key=api_key,  # optional bearer token for proxied instances
            config=merged_config,
        )

    if provider_type == "openai_compatible":
        return OpenAICompatibleProvider(
            base_url=provider_model.base_url,
            api_key=api_key,  # optional: not required by LM Studio / llama.cpp
            config=merged_config,
        )

    raise UnsupportedProviderTypeError(f"Unknown AI provider_type: {provider_model.provider_type!r}")


_PROMPT_ENV = ImmutableSandboxedEnvironment()


def render_prompt(template_text: str, variables: dict) -> str:
    """Render a Jinja2 prompt template with variables inside a sandboxed environment."""
    tmpl = _PROMPT_ENV.from_string(template_text)
    return tmpl.render(**variables)


async def get_task_assignment(
    db: AsyncSession,
    user_id: uuid.UUID | None,
    task_name: str,
) -> tuple[AITaskAssignment, AITask, AIProviderModel] | None:
    """The site's assignment for a task. Returns (assignment, task, provider) or None.

    Site assignments are instance-wide (unique on task_id), so ``user_id`` is
    accepted for API compatibility and not used. This is the lookup for
    background work; anything a person starts goes through
    ``resolve_assignment``, which adds their own key on top of this.
    """
    result = await db.execute(
        select(AITaskAssignment, AITask, AIProviderModel)
        .join(AITask, AITask.id == AITaskAssignment.task_id)
        .join(AIProviderModel, AIProviderModel.id == AITaskAssignment.provider_id)
        .where(
            AITask.name == task_name,
            AITaskAssignment.is_enabled == True,  # noqa: E712
            AIProviderModel.is_active == True,  # noqa: E712
            or_(
                AIProviderModel.paused_until.is_(None),
                AIProviderModel.paused_until <= func.now(),
            ),
        )
    )
    row = result.first()
    if row:
        return row[0], row[1], row[2]
    return None


async def get_active_prompt(
    db: AsyncSession,
    task_id: uuid.UUID,
) -> tuple[str | None, str]:
    """Get the active (system, user) prompt template for a task."""
    system_text, user_text, _version = await get_active_prompt_versioned(db, task_id)
    return system_text, user_text


async def get_active_prompt_versioned(
    db: AsyncSession,
    task_id: uuid.UUID,
) -> tuple[str | None, str, int | None]:
    """The active (system, user, version) prompt for a task; version None = the task's default.

    The version goes on the result (``_prompt_version``) because a person's
    key runs prompts the admin can edit, and the "Who answered" card says
    which one ran.

    Returns ``(system, user)`` where ``system`` may be ``None`` (no cacheable
    system block — falls through to the pre-split single-message pattern).
    Overrides are per-task: the newest active template wins for everyone
    (including workers), regardless of who saved it; otherwise the task
    defaults apply.
    """
    result = await db.execute(
        select(AIPromptTemplate)
        .where(
            AIPromptTemplate.task_id == task_id,
            AIPromptTemplate.is_active == True,  # noqa: E712
        )
        .order_by(AIPromptTemplate.version.desc(), AIPromptTemplate.created_at.desc())
        .limit(1)
    )
    prompt = result.scalars().first()
    if prompt:
        return prompt.system_text, prompt.template_text, prompt.version

    # Fall back to the task's defaults
    result = await db.execute(select(AITask).where(AITask.id == task_id))
    task = result.scalar_one_or_none()
    if task:
        return task.default_system_template, task.default_prompt_template, None

    raise ValueError(f"No prompt template found for task {task_id}")


async def run_task(
    db: AsyncSession,
    user_id: uuid.UUID,
    task_name: str,
    variables: dict,
    entry_id: uuid.UUID | None = None,
    target_type: str | None = None,
    target_id: uuid.UUID | None = None,
    force: bool = False,
    timeout_seconds: float | None = None,
    caller: Caller | None = None,
) -> dict | None:
    """Execute an AI task and store the result. Returns parsed_result or None if no assignment.

    `caller` says who the call runs for and is written onto the result. Omit
    it only from a request a signed-in person made themselves: it then
    derives from ``user_id`` (see ``derive_caller`` — the service account and
    the all-zero sentinel map to system). Workers, automation and share
    routes must pass theirs, or their spend is attributed to a person who
    never clicked.

    Pass `timeout_seconds` from synchronous request paths to bound the provider
    call below the gunicorn worker timeout. For the claude_code provider this is
    a hard single-attempt ceiling (no retry); other providers apply it as their
    per-request timeout. Without it, a slow CLI call + retry can outlast the
    worker timeout and get the worker killed mid-request (surfaces as a 502).
    """
    # Auto-derive target from entry_id for backward compatibility
    if entry_id and target_type is None:
        target_type = "entry"
        target_id = entry_id

    if caller is None:
        caller = current_caller.get() or await derive_caller(db, user_id)
    resolved = await resolve_assignment(db, caller, task_name, allowance=False)
    if resolved is None:
        return None

    task, provider_model = resolved.task, resolved.provider
    attribution = attribution_fields(caller, provider_model, key_owner_id=resolved.key_owner_id)

    # Dedup guard: skip if target already has a current result for this task.
    # A provider error ({"_error": ...}, no _extraction_status) is current so
    # the workbench shows the last run failed, but it is not an answer: replaying
    # it would turn every retry of an outage casualty into an instant failure.
    if target_type and target_id and not force:
        existing = await db.execute(
            select(AIResult.parsed_result)
            .where(
                AIResult.target_type == target_type,
                AIResult.target_id == target_id,
                AIResult.task_id == task.id,
                AIResult.is_current == True,  # noqa: E712
            )
            .limit(1)
        )
        cached = existing.scalar_one_or_none()
        provider_error = isinstance(cached, dict) and "_error" in cached and "_extraction_status" not in cached
        if cached is not None and not provider_error:
            logger.debug("Skipping duplicate AI task %s for %s/%s", task_name, target_type, target_id)
            return cached

    # After the dedup guard: a cached answer costs nothing. Before the force
    # demotion: a refused call must not retire the result that is there.
    # A person's own key is not the instance's spend.
    if resolved.source == "site":
        await enforce_site_allowance(db, caller)

    # If force re-run, mark old results as not current
    if force and target_type and target_id:
        await db.execute(
            update(AIResult)
            .where(
                AIResult.target_type == target_type,
                AIResult.target_id == target_id,
                AIResult.task_id == task.id,
                AIResult.is_current == True,  # noqa: E712
            )
            .values(is_current=False)
        )

    # Get prompt templates — system may be None (legacy flat-prompt mode).
    system_template, user_template, prompt_version = await get_active_prompt_versioned(db, task.id)

    # Render both halves with the same variable scope.
    rendered_system = render_prompt(system_template, variables) if system_template else None
    rendered_user = render_prompt(user_template, variables)

    # Extract config
    config = resolved.config
    temperature = config.get("temperature", 0.0)
    # 8192, not 4096: measured entry_analysis output on real articles runs
    # 1900-3251 tokens, and TTP-dense advisories (e.g. CISA #StopRansomware
    # bulletins, which enumerate a dozen technique IDs) overflow 4096 on every
    # model tested. An overflow is unrecoverable — parse_ai_json turns the
    # half-written JSON into _extraction_status="parse_error", which no caller
    # retries, so the whole extraction is silently lost. The cap only bounds
    # output, so raising it costs nothing on entries that finish early.
    # entry_analysis gets 16384: with the indicator appendix in the prompt and
    # host-kind observables in the schema, a long research write-up's payload
    # (TTPs with source sentences, countries, 30+ iocs with evidence) measured
    # 30k+ characters — ~8k tokens — and was cut mid-field. A truncated
    # response is a lost analysis; extra budget costs nothing when unused.
    max_tokens = config.get("max_tokens", 16384 if task_name == "entry_analysis" else 8192)

    # Agentic tool wiring for tool-capable non-CLI providers (Ollama). The
    # Claude Code CLI reaches tools via its own subprocess (no injected executor
    # needed); the Anthropic API and OpenAI-compatible providers are not
    # tool-capable (v1). Only agentic tasks get tools — everything else stays
    # a pure prompt→completion call.
    complete_kwargs: dict = {}
    if provider_model.provider_type == "ollama":
        from app.ai.capabilities import task_requires_tools

        if task_requires_tools(task_name):
            from app.tools import ADMIN_TOOLS, TOOL_DEFINITIONS, ollama_tool_specs
            from app.tools import execute_tool as _execute_tool

            # Read-only by default (safe). A task that must mutate (apply-mode
            # maintenance) opts in via assignment config ``ollama_tools_read_only:
            # false`` plus an explicit ``ollama_tools`` allowlist.
            read_only = bool(config.get("ollama_tools_read_only", True))
            tool_names = config.get("ollama_tools")

            # The mutating opt-in must not become a side door around the gates
            # /api/tools/execute enforces: an agentic task runs AS ``user_id``,
            # so a regular user's task gets that user's privileges. Workers
            # resolve to the non-loginable ``system`` account, which keeps them.
            from app.models.user import User as _User

            _role = (await db.execute(select(_User.role).where(_User.id == user_id))).scalar_one_or_none()
            _privileged = _role in ("admin", "system")
            if not _privileged:
                # Don't even offer the gated ones. This has to run even when the
                # assignment set no ``ollama_tools`` allowlist: ``None`` means
                # "offer everything" to ollama_tool_specs, so short-circuiting on
                # a falsy tool_names would hand a non-admin the full gated set
                # whenever read_only is off. Materialize the registry and filter.
                names = tool_names if tool_names is not None else [t["name"] for t in TOOL_DEFINITIONS]
                tool_names = [n for n in names if n not in ADMIN_TOOLS]

            async def _tool_executor(name: str, args: dict) -> str:
                if name in ADMIN_TOOLS and not _privileged:
                    # Also checked here, not just in the specs: a model can name
                    # a tool that was never offered to it.
                    return f'{{"error": "Tool \'{name}\' requires admin access"}}'
                result = await _execute_tool(name, args, db, user_id)
                # A failed handler ({"error": ...} result) can leave the session
                # in a failed transaction (is_active False). Roll back ONLY then,
                # so subsequent tool calls and run_task's AIResult persistence
                # keep working — an unconditional rollback would discard pending
                # work like force-mode's mark-not-current update.
                if result.startswith('{"error"') and not db.sync_session.is_active:
                    await db.rollback()
                return result

            complete_kwargs["tools"] = ollama_tool_specs(tool_names, read_only=read_only)
            complete_kwargs["tool_executor"] = _tool_executor

    # Execute
    _t0 = _time.monotonic()
    try:
        # Instantiated inside the try so an unknown/misconfigured provider_type
        # (UnsupportedProviderTypeError, or a provider-specific ValueError like
        # a missing base_url) is recorded as a provider_error result below
        # instead of crashing the Celery task.
        provider = _get_provider_instance(provider_model, extra_config=config)
        response: AIResponse = await provider.complete(
            prompt=rendered_user,
            system=rendered_system,
            temperature=temperature,
            max_tokens=max_tokens,
            response_format=task.effective_output_schema,
            model=resolved.model_name,
            timeout_seconds=timeout_seconds,
            **complete_kwargs,
        )
    except QuotaExhaustedError as e:
        # Auto-pause the provider until the rate window resets. Callers (Celery
        # tasks) check for _extraction_status == "provider_paused" and re-queue
        # with countdown=_pause_until-now so work resumes automatically.
        pause_until = e.reset_at or (datetime.now(UTC) + timedelta(hours=1))
        await db.execute(
            update(AIProviderModel)
            .where(AIProviderModel.id == provider_model.id)
            .values(paused_until=pause_until, paused_reason=str(e)[:500])
        )
        await db.flush()
        logger.warning(
            "Provider %s (%s) auto-paused until %s after quota hit: %s",
            provider_model.name,
            provider_model.provider_type,
            pause_until.isoformat(),
            str(e)[:200],
        )
        # Persist a failure row so the task's dedup guard doesn't think we
        # already succeeded — but mark it not-current so it doesn't block a
        # retry. (force=True on retry would also clear it, but this is safer.)
        ai_result = AIResult(
            entry_id=entry_id,
            target_type=target_type,
            target_id=target_id,
            is_current=False,
            task_id=task.id,
            provider_id=provider_model.id,
            model_name=resolved.model_name,
            prompt_used=rendered_user,
            raw_response=str(e),
            parsed_result={"_error": str(e), "_extraction_status": "provider_paused"},
            tokens_input=0,
            tokens_output=0,
            cost_estimate=Decimal("0"),
            **attribution,
        )
        db.add(ai_result)
        await db.flush()
        return {
            "_extraction_status": "provider_paused",
            "_pause_until": pause_until.isoformat(),
            "_error": str(e),
        }
    except Exception as e:
        logger.error(f"AI provider error for task {task_name}: {e}")
        await demote_current_results(db, target_type=target_type, target_id=target_id, task_id=task.id)
        ai_result = AIResult(
            entry_id=entry_id,
            target_type=target_type,
            target_id=target_id,
            is_current=True,
            task_id=task.id,
            provider_id=provider_model.id,
            model_name=resolved.model_name,
            prompt_used=rendered_user,
            raw_response=str(e),
            parsed_result={"_error": str(e)},
            tokens_input=0,
            tokens_output=0,
            cost_estimate=Decimal("0"),
            **attribution,
        )
        db.add(ai_result)
        await db.flush()
        return {"_extraction_status": "provider_error", "_error": str(e)}

    _duration = _time.monotonic() - _t0

    AI_REQUEST_DURATION_SECONDS.labels(provider=provider_model.provider_type, task=task_name).observe(_duration)

    # Parse JSON result (fenced-JSON salvage shared with the batch poller)
    parsed_result = parse_ai_json(response.content)
    if parsed_result.get("_extraction_status") == "parse_error":
        logger.warning(f"Failed to parse AI response as JSON for task {task_name}")

    # Tag successful results
    if parsed_result and isinstance(parsed_result, dict) and "_extraction_status" not in parsed_result:
        parsed_result["_extraction_status"] = "success"
    if resolved.fallback_reason and isinstance(parsed_result, dict):
        # The person has a key that did not answer; the card says why.
        parsed_result["_fallback_reason"] = resolved.fallback_reason
    if prompt_version is not None and isinstance(parsed_result, dict):
        parsed_result["_prompt_version"] = prompt_version

    # Cost: prefer the provider-reported figure (the claude_code CLI reports
    # total_cost_usd per run — notional under flat-rate OAuth, but it is what
    # the usage would cost at API rates). Fall back to the token-table estimate.
    if response.cost_usd is not None:
        cost = Decimal(str(round(response.cost_usd, 6)))
    else:
        cost = _estimate_cost(response.model, response.tokens_input, response.tokens_output)
    _count_ai_call(provider_model.provider_type, task_name, response.tokens_input, response.tokens_output, cost)

    # Store result
    await demote_current_results(db, target_type=target_type, target_id=target_id, task_id=task.id)
    ai_result = AIResult(
        entry_id=entry_id,
        target_type=target_type,
        target_id=target_id,
        is_current=True,
        task_id=task.id,
        provider_id=provider_model.id,
        model_name=response.model,
        prompt_used=rendered_user,
        raw_response=response.content,
        parsed_result=parsed_result,
        tokens_input=response.tokens_input,
        tokens_output=response.tokens_output,
        cost_estimate=cost,
        processing_time_ms=response.latency_ms,
        **attribution,
    )
    db.add(ai_result)
    await db.flush()

    # Publish SSE event for AI task completion
    event_data: dict = {"task_name": task_name}
    if target_type and target_id:
        event_data["target_type"] = target_type
        event_data["target_id"] = str(target_id)
    if entry_id:
        event_data["entry_id"] = str(entry_id)
    try:
        from app.api.events import publish_event

        publish_event(str(user_id), "ai_task_complete", event_data)
    except Exception:
        pass

    return parsed_result
