"""Adjudicate stage: the post-analysis AI review of one entry's output.

After the one-pass ``entry_analysis`` payload has been fanned out to rows
(``store_entry_analysis``), this module decides whether the entry gets a
second, smaller AI call that re-reads the article next to a manifest of
everything that was written to it — entity links of every source, entities
minted by this entry (with their nearest catalogue names pre-fetched),
pending-tier promotions, relationship claims, AI observables — and answers
one question per item: is this right?

Three pieces, all entry-scoped:

- ``enqueue_adjudication`` — the gates (mode → plan → echo → trigger → score
  floor → hourly budget), recorded on ``ai_analysis_requests``.
- ``build_manifest`` — the review items and the rendered prompt block. The
  reviewer runs on a single prompt with no tools, so every catalogue fact it
  needs (nearest existing names, article counts, the one-pass verdicts) is
  looked up here and printed on the item line.
- ``apply_verdicts`` — shadow files every verdict as a proposal in the two
  hygiene logs the Proposals lens already reads; apply (a later commit) acts
  on high-confidence verdicts with the same audit rows the existing tools
  write, so the rows double as the undo record.

Design: planning/ai-adjudication-stage.md. Replaces the nightly link
validator, hygiene reviewer and merge engine, and folds in relationship
promotion and the stale sweep.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy import delete as sa_delete
from sqlalchemy import func, or_, select
from sqlalchemy import update as sa_update
from sqlalchemy.ext.asyncio import AsyncSession

from app.entity_types import (
    COUNTRY,
    CVE,
    MALWARE,
    OBSERVABLE,
    PRODUCT,
    SECTOR,
    THREAT_ACTOR,
    TOOL,
    TTP,
    VENDOR,
)

logger = logging.getLogger(__name__)

TASK_NAME = "entry_adjudication"
# ai_results.target_type is varchar(20).
TARGET_TYPE = "entry_adjudicate"

MODES = ("off", "shadow", "apply")
TRIGGERS = ("all", "created")
CONFIDENCES = ("high", "medium", "low")
_CONF_RANK = {"low": 0, "medium": 1, "high": 2}

VERDICTS = {"keep", "remove", "reclassify", "veto", "merge", "demote", "drop"}
# Which verdicts each item kind accepts. veto/merge are additionally gated on
# the item being minted by this entry (see _validate_verdicts).
VALID_FOR_KIND: dict[str, set[str]] = {
    "link": {"keep", "remove", "reclassify", "veto", "merge"},
    "edge": {"keep", "demote"},
    "ioc": {"keep", "drop"},
}
# Verdicts that count toward the circuit breaker: the ones that take
# something away. A merge keeps the data under the catalogue name the model
# was shown, so it is not counted (planning/ai-adjudication-stage.md §4.3).
DESTRUCTIVE = {"remove", "veto", "demote", "drop"}
# Types a link can be reclassified between (the merge engine's convertible set).
RECLASSIFY_TYPES = {THREAT_ACTOR, MALWARE, VENDOR, PRODUCT, COUNTRY, TOOL}

# Positive-evidence override: payload lists that count as the analysis naming
# an entity by type. Actor/malware share one pool (the model routinely files
# ransomware brands under the other slot); vendor/product have no list.
_OVERRIDE_PAYLOAD_KEYS: dict[str, tuple[str, ...]] = {
    THREAT_ACTOR: ("threat_actors", "malware", "tools"),
    MALWARE: ("threat_actors", "malware", "tools"),
    TOOL: ("threat_actors", "malware", "tools"),
    COUNTRY: ("countries",),
}

# Maintenance-log actions this stage writes (shadow proposals and applied
# changes share the action code; `applied` tells them apart, like the merge
# engine's rows). api/hygiene.py registers them as proposal kinds.
ACTION_UNLINK = "adjudication_unlink"
# Advisory: a link whose entity is filed under the wrong type. Applying it
# converts the entity (the merge engine's reclassify), never unlinks it.
ACTION_RECLASSIFY = "adjudication_reclassify"
ACTION_VETO = "adjudication_veto"
ACTION_MERGE = "adjudication_merge"
ACTION_EDGE_DEMOTE = "adjudication_edge_demote"
ACTION_IOC_DROP = "adjudication_ioc_drop"
ACTION_ASSESSMENT = "adjudication_assessment"
# History, never a proposal: the audit line an analyst's Restore writes. It
# carries its own code so it cannot be mistaken for a fresh verdict — the
# action codes above persist from proposal through apply (only `applied`
# flips), so reusing one here would re-file the change that was just undone.
ACTION_RESTORED = "adjudication_restored"
# The stage's verdict codes: unapplied means "an analyst still has to decide".
ADJUDICATION_PROPOSAL_ACTIONS = {
    ACTION_UNLINK,
    ACTION_RECLASSIFY,
    ACTION_VETO,
    ACTION_MERGE,
    ACTION_EDGE_DEMOTE,
    ACTION_IOC_DROP,
    ACTION_ASSESSMENT,
}
# Everything the stage writes, proposals and history alike — what `origin`
# filters on.
ADJUDICATION_ACTIONS = ADJUDICATION_PROPOSAL_ACTIONS | {ACTION_RESTORED}

# Redis keys
_HOUR_KEY = "intelfeed:adjudication:hour:{hour}"
_RATIOS_KEY = "intelfeed:adjudication:ratios"
_BREAKER_KEY = "intelfeed:adjudication:breaker_until"
_ROLLING_WINDOW = 50
# The rolling breaker needs a sample before a mean says anything.
_ROLLING_MIN_SAMPLES = 10
# Share of each hour's budget the backfill may use; live entries get the rest
# (and the whole budget when nothing is backfilling).
_BACKFILL_SHARE = 0.5
# A `pending` row older than this with no run is a lost task, not a queue.
STALE_PENDING_HOURS = 6
# The resweep only re-enqueues while the ai queue is this shallow. A deep
# queue means reviews are waiting their turn, not lost — re-queueing them
# (and walking never-reviewed history) on top of it is how the queue
# compounded to 8k tasks ahead of the entry analyses that share the worker.
RESWEEP_QUEUE_CEILING = 200
AI_QUEUE_NAME = "ai"
# Links an analyst restored this recently are never changed again by the
# stage (planning §4.3 "never touched"); the reviewer only sees the flag.
RESTORED_GUARD_DAYS = 90

# Manifest caps — a C2-list entry must not flood the prompt.
_MAX_LINKS = 60
_MAX_EDGES = 10
_MAX_IOCS = 25
# Relationship sources the reviewer may judge. Analyst edges (confirmed,
# created, rejected) and external-feed imports (MITRE) are settled by hand.
REVIEWABLE_EDGE_SOURCES = ("auto_extracted", "co_occurrence")
_MAX_CANDIDATES = 3
_SNIPPET_WINDOW = 160
_SNIPPET_MAX = 320

# Skip statuses written to ai_analysis_requests.adjudication_status.
SKIPPED_OFF = "skipped_off"
SKIPPED_PLAN = "skipped_plan"
SKIPPED_ECHO = "skipped_echo"
SKIPPED_NOTHING_NEW = "skipped_nothing_new"
SKIPPED_SCORE = "skipped_score"
SKIPPED_BUDGET = "skipped_budget"
# The provider is paused (quota); re-enqueued by the resweep like budget.
SKIPPED_PAUSED = "skipped_paused"
PENDING = "pending"
COMPLETED = "completed"
FAILED = "failed"


# --------------------------------------------------------------------------- settings


def _num(value, default: float, cast=float):
    """A stored 0 is a value, not an absence — only None/"" fall back."""
    if value is None or value == "":
        return cast(default)
    try:
        return cast(value)
    except (TypeError, ValueError):
        return cast(default)


async def _settings(db: AsyncSession) -> dict:
    from app.services.system_settings import get_setting

    mode = str(await get_setting("adjudication_mode", db) or "off").lower()
    trigger = str(await get_setting("adjudication_trigger", db) or "all").lower()
    min_conf = str(await get_setting("adjudication_apply_min_confidence", db) or "high").lower()
    scope_raw = str(await get_setting("adjudication_scope", db) or "")
    return {
        "mode": mode if mode in MODES else "off",
        "trigger": trigger if trigger in TRIGGERS else "all",
        "max_per_hour": _num(await get_setting("adjudication_max_per_hour", db), 0, int),
        "min_score": _num(await get_setting("adjudication_min_priority_score", db), 0.0),
        "min_conf": min_conf if min_conf in CONFIDENCES else "high",
        "breaker_pct": _num(await get_setting("adjudication_circuit_breaker_pct", db), 0.5),
        # Distinct articles whose reviews must agree on the same target type
        # before a reclassify is applied in apply mode (1 = the first one).
        "reclassify_consensus": max(1, _num(await get_setting("adjudication_reclassify_consensus", db), 2, int)),
        "max_chars": _num(await get_setting("adjudication_content_max_chars", db), 8000, int),
        "scope": {s.strip() for s in scope_raw.split(",") if s.strip()}
        or {"links", "entities", "relationships", "observables"},
    }


# --------------------------------------------------------------------------- enqueue


async def _request_row(db: AsyncSession, entry_id: uuid.UUID):
    """The entry's ai_analysis_requests row, created when a manual analysis
    never made one (the batch path always has)."""
    from app.models.ai_analysis import AIAnalysisRequest

    row = (
        await db.execute(select(AIAnalysisRequest).where(AIAnalysisRequest.entry_id == entry_id))
    ).scalar_one_or_none()
    if row is None:
        row = AIAnalysisRequest(
            entry_id=entry_id,
            status="completed",
            custom_id=f"ea-{entry_id}",
            completed_at=datetime.now(UTC),
        )
        db.add(row)
        await db.flush()
    return row


async def _created_something(db: AsyncSession, entry_id: uuid.UUID, counts: dict | None) -> bool:
    """The `created` trigger: did the analysis mint an entity, assert a link
    or edge, promote a pending match, or capture an observable? Counts come
    from store_entry_analysis when available; the DB is the fallback (the
    self-heal sweep has no counts)."""
    counts = counts or {}
    if any(
        counts.get(k) for k in ("relationships", "autolinks_promoted", "observables", "scripts", "host_observables")
    ):
        return True

    from app.models.country import EntryCountry
    from app.models.entry_sector import EntrySector
    from app.models.malware_family import EntryMalware, MalwareFamily
    from app.models.threat_actor import EntryThreatActor, ThreatActor
    from app.models.tool import EntryTool, Tool
    from app.models.ttp import EntryTTP

    for model in (ThreatActor, MalwareFamily, Tool):
        if (
            await db.execute(select(model.id).where(model.created_from_entry_id == entry_id).limit(1))
        ).scalar_one_or_none():
            return True
    for jmodel in (EntryThreatActor, EntryMalware, EntryTool, EntryCountry, EntrySector):
        if (
            await db.execute(select(jmodel.entry_id).where(jmodel.entry_id == entry_id, jmodel.source == "ai").limit(1))
        ).scalar_one_or_none():
            return True
    # AI-asserted TTPs: no source column; the autolinker prefixes source_text.
    if (
        await db.execute(
            select(EntryTTP.entry_id)
            .where(
                EntryTTP.entry_id == entry_id,
                EntryTTP.source_text.isnot(None),
                ~EntryTTP.source_text.like("auto\\_link:%"),
            )
            .limit(1)
        )
    ).scalar_one_or_none():
        return True
    return False


async def breaker_paused_until() -> datetime | None:
    """When the rolling breaker has paused dispatch, the instant it lifts."""
    from app.services.redis_client import get_redis

    try:
        r = await get_redis()
        until = await r.get(_BREAKER_KEY)
        if until and float(until) > datetime.now(UTC).timestamp():
            return datetime.fromtimestamp(float(until), tz=UTC)
    except Exception:
        logger.debug("breaker lookup failed", exc_info=True)
    return None


async def _consume_hour_budget(max_per_hour: int, *, backfill: bool = False) -> str | None:
    """INCR the current hour's counter. Returns None when this entry fits,
    else why not: ``"budget"`` (hour is full) or ``"breaker"`` (the rolling
    breaker paused dispatch). Live entries may use the whole budget; the
    backfill only its share, so a backfill run can never starve the hour.

    ``max_per_hour <= 0`` means no ceiling at all: the AI worker's single slot
    is then the only thing pacing reviews. That is the right setting when the
    provider keeps up with ingest and nothing is metering the calls — but it
    also removes the backfill's share, so a history walk queues on the same
    worker as live reviews and as the one-pass analysis itself. Dispatch the
    backfill in batches (its own ``limit``) when the ceiling is off.
    """
    from app.services.redis_client import get_redis

    try:
        r = await get_redis()
        until = await r.get(_BREAKER_KEY)
        if until and float(until) > datetime.now(UTC).timestamp():
            return "breaker"
        if max_per_hour <= 0:
            return None
        key = _HOUR_KEY.format(hour=datetime.now(UTC).strftime("%Y%m%d%H"))
        cap = max(1, max_per_hour)
        if backfill:
            cap = max(1, int(cap * _BACKFILL_SHARE))
            if int(await r.get(key) or 0) >= cap:
                return "budget"
        n = await r.incr(key)
        if n == 1:
            await r.expire(key, 7200)
        return None if int(n) <= cap else "budget"
    except Exception:
        # Redis down: the AI worker is single-file anyway, so let it through.
        logger.debug("adjudication budget check failed; allowing", exc_info=True)
        return None


async def enqueue_adjudication(
    db: AsyncSession,
    entry_id: uuid.UUID,
    stored_counts: dict | None,
    parsed: dict | None,
    *,
    backfill: bool = False,
) -> str:
    """Decide whether the entry gets a review and record it. Returns the
    status written (``pending`` or a ``skipped_*``). The caller commits and,
    on ``pending``, calls ``dispatch_adjudication``. ``backfill`` entries only
    draw on their share of the hourly budget (live entries come first)."""
    from app.models.entry import Entry
    from app.models.feed import Feed
    from app.pipeline.plans import resolve_feed_plan

    cfg = await _settings(db)
    row = await _request_row(db, entry_id)

    async def _write(status: str) -> str:
        row.adjudication_status = status
        if status == PENDING:
            row.adjudication_queued_at = datetime.now(UTC)
        db.add(row)
        return status

    if cfg["mode"] == "off":
        return await _write(SKIPPED_OFF)

    entry = await db.get(Entry, entry_id)
    if entry is None:
        return await _write(FAILED)

    feed = await db.get(Feed, entry.feed_id)
    if feed is not None:
        plan = await resolve_feed_plan(db, feed)
        if plan is not None and not plan.get("adjudicate", {}).get("enabled", True):
            return await _write(SKIPPED_PLAN)

    if parsed and parsed.get("_reused_from"):
        return await _write(SKIPPED_ECHO)

    if cfg["trigger"] == "created" and not await _created_something(db, entry_id, stored_counts):
        return await _write(SKIPPED_NOTHING_NEW)

    if cfg["min_score"] > 0 and float(entry.priority_score or 0.0) < cfg["min_score"]:
        return await _write(SKIPPED_SCORE)

    why = await _consume_hour_budget(cfg["max_per_hour"], backfill=backfill)
    if why is not None:
        if why == "breaker":
            logger.info("adjudication dispatch paused by the rolling breaker; %s waits", entry_id)
        return await _write(SKIPPED_BUDGET)

    return await _write(PENDING)


def dispatch_adjudication(entry_id: uuid.UUID | str, countdown: int = 5) -> None:
    """Queue the review task on the ai queue. Call after the enqueue decision
    has been committed."""
    from app.workers.adjudication_tasks import adjudicate_entry_task

    try:
        adjudicate_entry_task.apply_async(args=[str(entry_id)], countdown=countdown)
    except Exception:
        logger.warning("adjudication dispatch failed for %s", entry_id, exc_info=True)


async def enqueue_and_dispatch(
    db: AsyncSession,
    entry_id: uuid.UUID,
    stored_counts: dict | None,
    parsed: dict | None,
    *,
    countdown: int = 5,
) -> str:
    """enqueue + dispatch for callers that commit immediately afterwards.

    The task starts after ``countdown`` seconds, by which time the caller's
    commit has landed. It re-checks only the master switch — every other gate
    was decided here (see ``adjudication_tasks``).
    """
    status = await enqueue_adjudication(db, entry_id, stored_counts, parsed)
    if status == PENDING:
        dispatch_adjudication(entry_id, countdown=countdown)
    return status


async def _ai_queue_depth() -> int:
    """Tasks waiting on the ai queue (the Celery broker's list). 0 when Redis
    is unreachable, so the sweep errs toward running."""
    from app.services.redis_client import get_redis

    try:
        r = await get_redis()
        return int(await r.llen(AI_QUEUE_NAME) or 0)
    except Exception:
        logger.debug("ai queue depth unavailable", exc_info=True)
        return 0


async def resweep_adjudications(db: AsyncSession, limit: int = 200) -> dict:
    """Self-heal, run from submit_analysis_batches (every 30 minutes — the
    budget it drains against is the hourly one). Re-enqueues,
    newest analysis first:

    - completed analyses whose review decision never landed (crash between
      the analysis commit and the enqueue);
    - rows waiting on budget or a paused provider (a new hour, a new try);
    - ``pending`` rows queued longer than STALE_PENDING_HOURS with no run —
      a lost task (dispatch failure, worker crash, retries exhausted).

    Newest first means live entries drain before backfilled history.

    Skipped entirely while the ai queue is deeper than RESWEEP_QUEUE_CEILING:
    nothing is lost in a deep queue, it is waiting, and the entry analyses
    behind it need the worker more than a history walk does."""
    from datetime import timedelta

    from app.models.ai_analysis import AIAnalysisRequest

    cfg = await _settings(db)
    if cfg["mode"] == "off":
        return {"swept": 0}
    depth = await _ai_queue_depth()
    if depth > RESWEEP_QUEUE_CEILING:
        logger.info("adjudication resweep deferred: ai queue %d deep", depth)
        return {"swept": 0, "deferred": depth}
    now = datetime.now(UTC)
    stale = now - timedelta(hours=2)
    lost = now - timedelta(hours=STALE_PENDING_HOURS)
    rows = (
        (
            await db.execute(
                select(AIAnalysisRequest)
                .where(
                    AIAnalysisRequest.status.in_(["completed", "reused_echo"]),
                    or_(
                        (AIAnalysisRequest.adjudication_status.is_(None)) & (AIAnalysisRequest.completed_at < stale),
                        AIAnalysisRequest.adjudication_status.in_([SKIPPED_BUDGET, SKIPPED_PAUSED]),
                        (AIAnalysisRequest.adjudication_status == PENDING)
                        & (AIAnalysisRequest.adjudication_queued_at < lost),
                    ),
                )
                .order_by(AIAnalysisRequest.completed_at.desc().nullslast())
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )
    swept = 0
    for row in rows:
        _result, parsed = await _current_analysis(db, row.entry_id)
        if parsed is None:
            # Nothing to review against: the analysis was superseded or removed.
            row.adjudication_status = FAILED
            db.add(row)
            continue
        status = await enqueue_adjudication(db, row.entry_id, None, parsed)
        if status == PENDING:
            dispatch_adjudication(row.entry_id, countdown=30)
            swept += 1
        if status == SKIPPED_BUDGET:
            break  # the hour is full; the rest wait for the next sweep
    return {"swept": swept, "candidates": len(rows)}


async def select_backfill_entries(db: AsyncSession, limit: int = 500, since_days: int | None = None) -> list:
    """Entries with a current analysis that the stage has never decided on,
    newest first — the one-off walk through history and the old backlogs."""
    from datetime import timedelta

    from app.models.ai_analysis import AIAnalysisRequest
    from app.models.ai_result import AIResult
    from app.models.ai_task import AITask
    from app.models.entry import Entry

    analysed = select(AIResult.target_id).where(
        AIResult.target_type == "entry",
        AIResult.is_current.is_(True),
        AIResult.task_id == select(AITask.id).where(AITask.name == "entry_analysis").scalar_subquery(),
    )
    q = (
        select(Entry.id)
        .outerjoin(AIAnalysisRequest, AIAnalysisRequest.entry_id == Entry.id)
        .where(
            Entry.id.in_(analysed),
            or_(AIAnalysisRequest.id.is_(None), AIAnalysisRequest.adjudicated_at.is_(None)),
            or_(
                AIAnalysisRequest.adjudication_status.is_(None),
                AIAnalysisRequest.adjudication_status.notin_([PENDING, COMPLETED, FAILED, SKIPPED_ECHO]),
            ),
        )
    )
    if since_days:
        q = q.where(Entry.created_at >= datetime.now(UTC) - timedelta(days=since_days))
    q = q.order_by(Entry.created_at.desc()).limit(limit)
    return list((await db.execute(q)).scalars().all())


async def _current_analysis(db: AsyncSession, entry_id: uuid.UUID):
    from app.services.entry_analysis import _current_analysis_result

    result, _task = await _current_analysis_result(db, entry_id)
    if result is None or not isinstance(result.parsed_result, dict):
        return None, None
    return result, result.parsed_result


# --------------------------------------------------------------------------- manifest


@dataclass
class ReviewItem:
    item_id: str
    kind: str  # link | edge | ioc | assessment | note (rendered, never judged)
    line: str
    entity_type: str | None = None
    entity_id: uuid.UUID | None = None
    name: str = ""
    source: str | None = None
    minted_here: bool = False
    promoted: bool = False
    previously_restored: bool = False
    # Candidate merge targets: [{entity_type, entity_id, name, article_count}]
    candidates: list[dict] = field(default_factory=list)
    # Junction snapshot for restore / LinkRow construction.
    confidence: str | None = None
    matched_names: list[str] = field(default_factory=list)
    paragraph_indices: list[int] = field(default_factory=list)
    extracted_at: datetime | None = None
    # ioc
    ioc_kind: str | None = None
    ioc_value: str | None = None
    observable_id: uuid.UUID | None = None
    staged: bool = False
    # edge
    edge_id: uuid.UUID | None = None


# (junction model, entity model, fk attr, entity_type slug)
def _link_specs():
    from app.intelligence.link_validation_apply import JUNCTION_SPECS
    from app.models.entry_sector import EntrySector
    from app.models.sector import Sector
    from app.models.tool import EntryTool, Tool

    return [*JUNCTION_SPECS, (EntryTool, Tool, "tool_id", TOOL), (EntrySector, Sector, "sector_id", SECTOR)]


_ENDPOINT_MODELS: dict[str, tuple[str, str]] = {
    # entity_type → (module path, class name) — resolved lazily
    THREAT_ACTOR: ("app.models.threat_actor", "ThreatActor"),
    MALWARE: ("app.models.malware_family", "MalwareFamily"),
    TOOL: ("app.models.tool", "Tool"),
    COUNTRY: ("app.models.country", "Country"),
    VENDOR: ("app.models.vendor", "Vendor"),
    PRODUCT: ("app.models.product", "Product"),
    SECTOR: ("app.models.sector", "Sector"),
    CVE: ("app.models.cve", "CVE"),
    TTP: ("app.models.ttp", "TTP"),
    OBSERVABLE: ("app.models.observable", "Observable"),
}
# Pseudo entity types the stage's own log rows use for non-entity subjects.
LOG_TYPE_RELATIONSHIP = "relationship"
LOG_TYPE_ENTRY = "entry"


def _model_for(entity_type: str):
    import importlib

    spec = _ENDPOINT_MODELS.get(entity_type)
    if not spec:
        return None
    return getattr(importlib.import_module(spec[0]), spec[1])


def _display_name(obj) -> str:
    for attr in ("name", "cve_id", "technique_id", "value"):
        val = getattr(obj, attr, None)
        if val:
            return str(val)
    return "?"


async def _entity_label(db: AsyncSession, entity_type: str, entity_id: uuid.UUID) -> str:
    model = _model_for(entity_type)
    if model is None:
        return f"{entity_type}:{entity_id}"
    obj = await db.get(model, entity_id)
    return _display_name(obj) if obj is not None else f"{entity_type}:{entity_id}"


def _snippet(paragraph_map: dict[int, str], needles: list[str], indices: list[int], fallback_text: str) -> str:
    """Quoted context around the first match — from the autolinker's
    paragraph split when indices exist, else the first occurrence in the
    analysis text."""
    needles = [n for n in needles if n]
    texts = [paragraph_map.get(i) for i in indices[:2] if paragraph_map.get(i)]
    # The indexed paragraphs first (exact), then the whole analysis text as
    # the fallback when the indices are stale or missing.
    if fallback_text:
        texts.append(fallback_text)
    for text in texts:
        lowered = text.lower()
        pos = -1
        for needle in needles:
            pos = lowered.find(needle.lower())
            if pos != -1:
                break
        if pos == -1:
            continue
        start = max(0, pos - _SNIPPET_WINDOW // 2)
        piece = text[start : pos + _SNIPPET_WINDOW].strip().replace("\n", " ")
        if start > 0:
            piece = "…" + piece
        if pos + _SNIPPET_WINDOW < len(text):
            piece += "…"
        return piece[:_SNIPPET_MAX]
    return ""


async def _nearest_candidates(db: AsyncSession, entity_type: str, entity, limit: int = _MAX_CANDIDATES) -> list[dict]:
    """The catalogue neighbours a brand-new entity could be a duplicate of —
    the same matchers the creation gate runs, excluding the entity itself.
    The reviewer may only merge into one of these."""
    from app.intelligence.entity_dedup import find_entity_by_name_or_alias
    from app.intelligence.entity_resolution import (
        RESOLVED_MODELS,
        _cross_type_hits,
        _normalized_lookup,
        _trgm_candidates,
        normalize_entity_name,
    )

    model = RESOLVED_MODELS.get(entity_type)
    if model is None:
        return []
    name = entity.name or ""
    aliases = list(getattr(entity, "aliases", None) or [])
    seen: set[tuple[str, uuid.UUID]] = {(entity_type, entity.id)}
    found: list[tuple[str, uuid.UUID]] = []

    def _add(etype: str, eid) -> None:
        try:
            key = (etype, uuid.UUID(str(eid)))
        except ValueError:
            return
        if key not in seen:
            seen.add(key)
            found.append(key)

    try:
        exact = await find_entity_by_name_or_alias(db, model, name, aliases)
        if exact is not None:
            _add(entity_type, exact.id)
        norm = normalize_entity_name(name, entity_type)
        for form in {norm.norm_exact, norm.norm_stripped, norm.norm_codename_stripped or ""}:
            if form:
                for eid in await _normalized_lookup(db, entity_type, form):
                    _add(entity_type, eid)
        for cand in await _trgm_candidates(db, entity_type, norm.norm_exact):
            _add(entity_type, cand["entity_id"])
        for hit in await _cross_type_hits(db, entity_type, {norm.norm_exact, norm.norm_stripped}):
            _add(hit["entity_type"], hit["entity_id"])
    except Exception:
        logger.debug("candidate lookup failed for %s %s", entity_type, name, exc_info=True)

    out: list[dict] = []
    for etype, eid in found:
        cmodel = _model_for(etype)
        obj = await db.get(cmodel, eid) if cmodel else None
        if obj is None:
            continue
        out.append(
            {
                "entity_type": etype,
                "entity_id": str(eid),
                "name": _display_name(obj),
                "aliases": list(getattr(obj, "aliases", None) or [])[:5],
                "article_count": int(getattr(obj, "article_count", 0) or 0),
            }
        )
        if len(out) >= limit:
            break
    return out


def _age_days(ts: datetime | None) -> int | None:
    if not ts:
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    return max(0, (datetime.now(UTC) - ts).days)


async def _recently_restored(db: AsyncSession, entry_id: uuid.UUID) -> set[tuple[str, uuid.UUID]]:
    """Links on this entry an analyst restored within RESTORED_GUARD_DAYS, from
    the link log — the validator junction types (actor, malware, vendor,
    product, country), the only ones that record a restore per entry.

    The maintenance log cannot answer this: a restore there writes an
    ACTION_RESTORED audit line, which says the link was put back but not which
    link kind it was, and its subject may be an entity the restore re-created
    rather than a junction row. So tool / sector / TTP links and vetoes are not
    shielded; they are reviewed again like any other row.
    """
    from datetime import timedelta

    from app.models.entity_link_validation_log import EntityLinkValidationLog

    cutoff = datetime.now(UTC) - timedelta(days=RESTORED_GUARD_DAYS)
    return {
        (t, eid)
        for t, eid in (
            await db.execute(
                select(EntityLinkValidationLog.entity_type, EntityLinkValidationLog.entity_id).where(
                    EntityLinkValidationLog.entry_id == entry_id,
                    EntityLinkValidationLog.action == "restored",
                    EntityLinkValidationLog.created_at >= cutoff,
                )
            )
        ).all()
    }


def _review_priority(item: ReviewItem) -> int:
    """Sort key for the link cap: lowest is most worth a verdict."""
    if item.minted_here:
        return 0
    if item.promoted:
        return 1
    if item.source != "auto_link":
        return 2
    return 3


async def _link_items(
    db: AsyncSession,
    entry,
    scope: set[str],
    text: str,
    legacy_out: list | None = None,
    dropped: list | None = None,
) -> list[ReviewItem]:
    from app.intelligence.autolinker import split_into_paragraphs
    from app.models.entity_maintenance import EntityMaintenanceLog
    from app.models.pending_autolink import PendingAutolinkMatch
    from app.models.ttp import TTP as TTPModel
    from app.models.ttp import EntryTTP
    from app.services.sanitizer import entry_text_with_translation

    title, content_text = entry_text_with_translation(entry)
    paragraph_map = dict(split_into_paragraphs(title, entry.summary or "", content_text))
    dropped = dropped if dropped is not None else []

    promoted: dict[tuple[str, uuid.UUID], PendingAutolinkMatch] = {
        (r.entity_type, r.entity_id): r
        for r in (
            await db.execute(
                select(PendingAutolinkMatch).where(
                    PendingAutolinkMatch.entry_id == entry.id, PendingAutolinkMatch.resolution == "promoted"
                )
            )
        )
        .scalars()
        .all()
    }
    restored = await _recently_restored(db, entry.id)
    # `entities` is what buys the catalogue lookup, and the lookup is what
    # makes veto and merge answerable — without it nothing is reviewed as new.
    # Without `links`, only the rows this article minted are reviewed at all.
    review_new = "entities" in scope
    established_too = "links" in scope

    items: list[ReviewItem] = []
    for jmodel, emodel, fk_attr, entity_type in _link_specs():
        fk_col = getattr(jmodel, fk_attr)
        rows = (
            await db.execute(
                select(jmodel, emodel).join(emodel, emodel.id == fk_col).where(jmodel.entry_id == entry.id)
            )
        ).all()
        for junction, entity in rows:
            minted = getattr(entity, "created_from_entry_id", None) == entry.id
            if not established_too and not minted:
                continue
            item = ReviewItem(
                item_id=f"link:{entity_type}:{entity.id}",
                kind="link",
                line="",
                entity_type=entity_type,
                entity_id=entity.id,
                name=entity.name,
                source=getattr(junction, "source", None),
                confidence=getattr(junction, "confidence", None),
                matched_names=list(getattr(junction, "matched_names", None) or []),
                paragraph_indices=list(getattr(junction, "paragraph_indices", None) or []),
                extracted_at=getattr(junction, "extracted_at", None),
                minted_here=minted and review_new,
                promoted=(entity_type, entity.id) in promoted,
                previously_restored=(entity_type, entity.id) in restored,
            )
            if item.minted_here:
                item.candidates = await _nearest_candidates(db, entity_type, entity)
            items.append(item)

    # AI-asserted TTPs: the junction has no source column; the autolinker
    # stamps source_text with an "auto_link:" prefix, the AI writes a quote.
    # No entity mints a TTP, so they ride on the `links` scope alone.
    ttp_rows = (
        (
            await db.execute(
                select(EntryTTP, TTPModel)
                .join(TTPModel, TTPModel.id == EntryTTP.ttp_id)
                .where(
                    EntryTTP.entry_id == entry.id,
                    EntryTTP.source_text.isnot(None),
                    ~EntryTTP.source_text.like("auto\\_link:%"),
                )
            )
        ).all()
        if established_too
        else []
    )
    for junction, ttp in ttp_rows:
        items.append(
            ReviewItem(
                item_id=f"link:{TTP}:{ttp.id}",
                kind="link",
                line="",
                entity_type=TTP,
                entity_id=ttp.id,
                name=f"{ttp.technique_id} {ttp.technique_name}",
                source="ai",
                confidence=junction.confidence,
                matched_names=[junction.source_text or ""],
                paragraph_indices=list(junction.paragraph_indices or []),
                extracted_at=junction.extracted_at,
            )
        )

    # The cap used to trim whatever the list happened to end with, which was
    # always the AI TTPs. Judge the rows that only this review can judge:
    # entities it minted (the sole veto/merge candidates), then pending-tier
    # promotions, then anything the AI asserted, then the autolinker's bulk.
    if len(items) > _MAX_LINKS:
        items.sort(key=_review_priority)
        dropped.extend(items[_MAX_LINKS:])
        items = items[:_MAX_LINKS]
    link_rows, maint_rows = await _legacy_rows(db, entry, items)
    if legacy_out is not None:
        legacy_out.extend([*link_rows, *maint_rows])
    earlier = _legacy_suggestions(link_rows, maint_rows, items)
    minted_ids = [it.entity_id for it in items if it.minted_here and it.entity_id]
    resolver_rows: dict[uuid.UUID, dict] = {}
    if minted_ids:
        for eid, after in (
            await db.execute(
                select(EntityMaintenanceLog.entity_id, EntityMaintenanceLog.after).where(
                    EntityMaintenanceLog.action == "resolution_created",
                    EntityMaintenanceLog.entity_id.in_(minted_ids),
                )
            )
        ).all():
            if isinstance(after, dict):
                resolver_rows.setdefault(eid, after)
    for item in items:
        entity_model = _model_for(item.entity_type or "")
        entity = await db.get(entity_model, item.entity_id) if entity_model else None
        bits = [f"{item.name} ({item.entity_type})"]
        bits.append("autolinker" if item.source == "auto_link" else (item.source or "linked"))
        count = int(getattr(entity, "article_count", 0) or 0)
        bits.append(f"{count} article{'s' if count != 1 else ''}")
        age = _age_days(getattr(entity, "last_seen_at", None))
        if age is not None and age > 30:
            bits.append(f"last seen {age}d ago")
        if item.minted_here:
            bits.append("NEW, created by this article")
            if getattr(entity, "needs_review", False):
                bits.append("a creation gate flagged it")
        if item.promoted:
            bits.append("promoted from the pending tier (name is also a dictionary word)")
        if item.previously_restored:
            bits.append("an analyst restored this link recently — it will not be changed, flag it only")
        line = f"{item.item_id}  " + " · ".join(bits)
        if item.minted_here:
            if item.candidates:
                near = "; ".join(
                    f"{c['name']} ({c['entity_type']}, {c['article_count']} articles)" for c in item.candidates
                )
                line += f"\n    nearest existing names: {near}"
            else:
                line += "\n    nearest existing names: none"
            resolver = resolver_rows.get(item.entity_id)  # type: ignore[arg-type]
            if resolver and resolver.get("norm_exact"):
                line += f"\n    resolver: created as '{resolver['norm_exact']}' — no catalogue name matched at creation"
        pend = promoted.get((item.entity_type or "", item.entity_id))  # type: ignore[arg-type]
        if pend is not None:
            forms = ", ".join(dict.fromkeys(pend.matched_names or [])) or item.name
            line += f"\n    pending match: surface form(s) {forms} · autolinker confidence {pend.confidence or '?'}"
        aliases = list(getattr(entity, "aliases", None) or [])[:3]
        if aliases:
            line += f"\n    aliases: {', '.join(aliases)}"
        snippet = _snippet(paragraph_map, item.matched_names or [item.name], item.paragraph_indices, text)
        if snippet:
            line += f'\n    context: "{snippet}"'
        for note in earlier.get(item.item_id, []):
            line += f"\n    earlier suggestion (retired nightly job): {note}"
        item.line = line
    return items


# Proposal actions of the retired merge engine and stale sweep (migration
# b1c2d3e4f5a6 deletes their pending rows; this covers anything older).
LEGACY_MAINT_ACTIONS = ("merge_cluster_summary", "stale_entity_review")


async def legacy_row_is_orphaned(db: AsyncSession, row) -> bool:
    """True when no entry can carry this retired-job proposal to a review: its
    entity is gone, or nothing records which entry created it, so the backfill
    will never reach it. Those rows are listed for manual disposition."""
    from app.models.entry import Entry

    if row.entity_id is None:
        return True
    model = _model_for(row.entity_type or "")
    obj = await db.get(model, row.entity_id) if model else None
    if obj is None:
        return True
    creator = getattr(obj, "created_from_entry_id", None)
    if creator is None:
        return True
    return await db.get(Entry, creator) is None


async def _legacy_rows(db: AsyncSession, entry, items: list[ReviewItem]):
    """Pending proposals the retired jobs left for this entry: validator rows
    keyed by entry, and maintenance proposals about entities this entry
    created. Returns (link_log_rows, maintenance_rows)."""
    from app.models.ai_result import AIResult
    from app.models.ai_task import AITask
    from app.models.entity_link_validation_log import EntityLinkValidationLog
    from app.models.entity_maintenance import EntityMaintenanceLog

    adjudicator_results = select(AIResult.id).where(
        AIResult.task_id == select(AITask.id).where(AITask.name == TASK_NAME).scalar_subquery()
    )
    link_rows = (
        (
            await db.execute(
                select(EntityLinkValidationLog).where(
                    EntityLinkValidationLog.entry_id == entry.id,
                    EntityLinkValidationLog.action.in_(["shadow_remove", "needs_reclassification"]),
                    or_(
                        EntityLinkValidationLog.ai_result_id.is_(None),
                        ~EntityLinkValidationLog.ai_result_id.in_(adjudicator_results),
                    ),
                )
            )
        )
        .scalars()
        .all()
    )
    minted = [it.entity_id for it in items if it.kind == "link" and it.minted_here and it.entity_id]
    maint_rows = []
    if minted:
        maint_rows = (
            (
                await db.execute(
                    select(EntityMaintenanceLog).where(
                        EntityMaintenanceLog.entity_id.in_(minted),
                        EntityMaintenanceLog.applied.is_(False),
                        # Only the retired jobs' own proposals. normalize_name /
                        # alias_collision come from scanners that still run and
                        # get no verdict here, so they are never superseded.
                        EntityMaintenanceLog.action.in_(LEGACY_MAINT_ACTIONS),
                    )
                )
            )
            .scalars()
            .all()
        )
    return link_rows, maint_rows


def _legacy_suggestions(link_rows: list, maint_rows: list, items: list[ReviewItem]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for r in link_rows:
        key = f"link:{r.entity_type}:{r.entity_id}"
        what = "remove" if r.action == "shadow_remove" else f"reclassify as {r.suggested_entity_type or '?'}"
        out.setdefault(key, []).append(f"{what} — {(r.reason or '').strip()[:160]}")
    by_entity = {it.entity_id: it.item_id for it in items if it.kind == "link" and it.entity_id}
    for r in maint_rows:
        key = by_entity.get(r.entity_id)
        if key:
            out.setdefault(key, []).append(f"{r.action.replace('_', ' ')} — {(r.reasoning or '').strip()[:160]}")
    return out


async def supersede_legacy_proposals(db: AsyncSession, legacy_rows: list) -> int:
    """After the review has judged the entry, the retired jobs' pending rows
    for the same links and entities are superseded: deleted, not archived,
    because the reviewer's own rows now say what should happen."""
    for row in legacy_rows:
        await db.delete(row)
    return len(legacy_rows)


async def _edge_items(db: AsyncSession, entry, dropped_out: list | None = None) -> list[ReviewItem]:
    """The relationship claims this article is evidence for and the reviewer
    may still decide: machine-asserted edges whose verdict is open. Analyst
    and external-feed edges are not the AI's to demote, and a settled verdict
    stays settled — corroborated edges would otherwise be undone by one later
    article that merely co-mentions the pair, and coincidental ones (sticky,
    keeps ignored) would only spend the edge budget.

    The cap keeps the claims born here (this entry is their only evidence):
    nothing else will ever review them, while an edge with more evidence
    gets another look from its next article. Overflow goes to ``dropped_out``
    so the prompt can say the list is partial."""
    from app.models.entity_relationship import EntityRelationship

    evidence_n = func.coalesce(func.array_length(EntityRelationship.evidence_entry_ids, 1), 0)
    rows = (
        (
            await db.execute(
                select(EntityRelationship)
                .where(
                    EntityRelationship.evidence_entry_ids.any(entry.id),
                    EntityRelationship.source.in_(REVIEWABLE_EDGE_SOURCES),
                    EntityRelationship.adjudication_verdict.is_distinct_from("corroborated"),
                    EntityRelationship.adjudication_verdict.is_distinct_from("coincidental"),
                    or_(EntityRelationship.source == "auto_extracted", evidence_n == 1),
                )
                .order_by(evidence_n, EntityRelationship.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    if len(rows) > _MAX_EDGES:
        if dropped_out is not None:
            dropped_out.extend(
                ReviewItem(item_id=f"edge:{e.id}", kind="edge", line="", edge_id=e.id) for e in rows[_MAX_EDGES:]
            )
        rows = rows[:_MAX_EDGES]
    items: list[ReviewItem] = []
    for edge in rows:
        src = await _entity_label(db, edge.source_type, edge.source_id)
        tgt = await _entity_label(db, edge.target_type, edge.target_id)
        claim = f"{src} {edge.relationship_type.replace('_', ' ')} {tgt} ({edge.target_type})"
        line = f"edge:{edge.id}  {claim} · {edge.confidence} · asserted by {edge.source.replace('_', ' ')}"
        if edge.description:
            line += f'\n    evidence: "{edge.description[:240]}"'
        items.append(ReviewItem(item_id=f"edge:{edge.id}", kind="edge", line=line, name=claim, edge_id=edge.id))
    return items


async def _ioc_items(db: AsyncSession, entry) -> list[ReviewItem]:
    """Observables this entry's analysis produced, captured ledger rows first.

    The cap trims the tail, so the order decides what gets judged. A captured
    row is live data — a drop takes a sighting off the ledger and recounts it —
    while a staged candidate is entry-local and already has a dismiss button on
    the candidates queue. Collecting the captured rows first also means that a
    value which is both renders as the captured one, and dropping that handles
    the staged half too (see ``_drop_ioc``).
    """
    from app.models.observable import EntryObservable, Observable

    captured: list[ReviewItem] = []
    staged: list[ReviewItem] = []
    seen: set[tuple[str, str]] = set()
    rows = (
        await db.execute(
            select(EntryObservable, Observable)
            .join(Observable, Observable.id == EntryObservable.observable_id)
            .where(EntryObservable.entry_id == entry.id, EntryObservable.source == "ai")
        )
    ).all()
    for sighting, obs in rows:
        if (obs.kind, obs.value) in seen:
            continue
        seen.add((obs.kind, obs.value))
        line = f"ioc:{obs.kind}:{obs.value}  {obs.kind} · captured as a ledger row · {obs.sighting_count} sightings"
        if sighting.surface_form and sighting.surface_form != obs.value:
            line += f" · printed as {sighting.surface_form}"
        if getattr(sighting, "was_defanged", False):
            line += " · printed defanged"
        captured.append(
            ReviewItem(
                item_id=f"ioc:{obs.kind}:{obs.value}",
                kind="ioc",
                line=line,
                name=obs.value,
                ioc_kind=obs.kind,
                ioc_value=obs.value,
                observable_id=obs.id,
            )
        )
    for cand in entry.observable_candidates or []:
        if not isinstance(cand, dict) or cand.get("origin") != "ai":
            continue
        kind, value = str(cand.get("kind") or ""), str(cand.get("value") or "")
        if not kind or not value or (kind, value) in seen:
            continue
        seen.add((kind, value))
        line = f"ioc:{kind}:{value}  {kind} · staged by the AI, not yet a ledger row"
        if cand.get("was_defanged"):
            line += " · printed defanged"
        if cand.get("evidence"):
            line += f'\n    evidence: "{str(cand["evidence"])[:200]}"'
        staged.append(
            ReviewItem(
                item_id=f"ioc:{kind}:{value}",
                kind="ioc",
                line=line,
                name=value,
                ioc_kind=kind,
                ioc_value=value,
                staged=True,
            )
        )
    return [*captured, *staged][:_MAX_IOCS]


def _assessment_item(parsed: dict | None) -> ReviewItem | None:
    if not parsed:
        return None
    sev = parsed.get("severity_assessment")
    level = sev.get("level") if isinstance(sev, dict) else sev
    summary = str(parsed.get("summary") or "")[:300]
    if not level and not summary:
        return None
    line = f"assessment  severity={level or '?'} · report_type={parsed.get('report_type') or '?'}"
    if summary:
        line += f'\n    summary: "{summary}"'
    if parsed.get("novelty_note"):
        line += f'\n    novelty: "{str(parsed["novelty_note"])[:200]}"'
    return ReviewItem(item_id="assessment", kind="assessment", line=line)


async def build_manifest(
    db: AsyncSession,
    entry,
    parsed: dict | None,
    scope: set[str] | None = None,
    legacy_out: list | None = None,
    dropped_out: list | None = None,
) -> tuple[list[ReviewItem], str]:
    """Review items for the entry + the rendered prompt block. ``legacy_out``
    collects the retired jobs' pending rows the manifest rendered as earlier
    suggestions, so the caller can supersede exactly those after the review
    (taken before the model runs: the reviewer's own rows are never among them).
    ``dropped_out`` collects the link and edge items the per-entry caps left out."""
    from app.services.entry_analysis import analysis_content_text

    scope = scope or {"links", "entities", "relationships", "observables"}
    text = analysis_content_text(entry)
    items: list[ReviewItem] = []
    if "links" in scope or "entities" in scope:
        # `_link_items` reads the scope itself: `entities` decides whether a
        # minted row is reviewed as new, `links` whether established rows are
        # in the manifest at all.
        items += await _link_items(db, entry, scope, text, legacy_out, dropped_out)
    if "relationships" in scope:
        items += await _edge_items(db, entry, dropped_out)
    if "observables" in scope:
        items += await _ioc_items(db, entry)
    if "assessment" in scope:
        item = _assessment_item(parsed)
        if item:
            items.append(item)
    if dropped_out:
        n_links = sum(1 for it in dropped_out if it.kind == "link")
        n_edges = sum(1 for it in dropped_out if it.kind == "edge")
        partial = [
            s
            for s, n in (
                (f"{n_links} further autolinked entity links", n_links),
                (f"{n_edges} further relationship claims", n_edges),
            )
            if n
        ]
        items.append(
            ReviewItem(
                item_id="_note",
                kind="note",
                line=(
                    f"(note: this article has {' and '.join(partial)} that are not in this list — "
                    "judge only the items above)"
                ),
            )
        )
    block = "\n".join(it.line for it in items)
    return [it for it in items if it.kind != "note"], block


async def build_variables(
    db: AsyncSession, entry, parsed: dict | None, cfg: dict, dropped_out: list | None = None
) -> tuple[list[ReviewItem], dict, list]:
    """(items, prompt variables, legacy rows to supersede after the review).
    ``dropped_out`` collects the link items the per-entry cap left out."""
    from app.models.feed import Feed
    from app.services.analysis_window import analysis_content_window
    from app.services.entry_analysis import analysis_content_text
    from app.services.system_settings import get_setting

    legacy: list = []
    items, block = await build_manifest(db, entry, parsed, cfg["scope"], legacy_out=legacy, dropped_out=dropped_out)
    tail_reserve = float(await get_setting("observables_analysis_tail_reserve", db) or 0.0)
    feed_title = (await db.execute(select(Feed.title).where(Feed.id == entry.feed_id))).scalar_one_or_none() or ""
    variables = {
        "entry": {
            "title": entry.translated_title or entry.title,
            "feed_title": feed_title,
            "content_text": analysis_content_window(
                analysis_content_text(entry), cfg["max_chars"], tail_reserve=tail_reserve
            ),
        },
        "manifest_block": block,
        "item_count": len(items),
    }
    return items, variables, legacy


# --------------------------------------------------------------------------- verdicts


@dataclass
class Verdict:
    item: ReviewItem
    verdict: str
    confidence: str
    reason: str
    suggested_type: str | None = None
    merge_target: dict | None = None
    # True when the model named this item. The prompt asks for changes only, so
    # most keeps are the fill-in below — an item nobody spoke about. The two
    # read the same on every path except edge corroboration, where silence must
    # not count as agreement (see apply_verdicts).
    explicit: bool = False


def _validate_verdicts(result: dict, items: list[ReviewItem]) -> tuple[list[Verdict], dict]:
    """Per-item verdicts with the validity matrix applied. Anything missing,
    malformed or out of place is a keep. A duplicate item_id voids the whole
    response (all keep), the same rule the one-pass path uses."""
    by_id = {it.item_id: it for it in items}
    raw = result.get("verdicts")
    # unknown: item ids not in the manifest; coerced: verdicts the item's kind
    # or state does not accept (treated as keep).
    stats = {"unknown": 0, "coerced": 0, "duplicate": False}
    verdicts: dict[str, Verdict] = {}
    if isinstance(raw, list):
        for entry in raw:
            if not isinstance(entry, dict):
                stats["unknown"] += 1
                continue
            item_id = str(entry.get("item_id") or "")
            item = by_id.get(item_id)
            if item is None:
                stats["unknown"] += 1
                continue
            if item_id in verdicts:
                stats["duplicate"] = True
                break
            verdict = str(entry.get("verdict") or "keep").lower()
            confidence = str(entry.get("confidence") or "low").lower()
            if confidence not in CONFIDENCES:
                confidence = "low"
            reason = str(entry.get("reason") or "")[:500]
            suggested = str(entry.get("suggested_type") or "").strip().lower().replace(" ", "_") or None
            if verdict != "reclassify":
                suggested = None
            merge_target = None
            asked = verdict
            if verdict not in VALID_FOR_KIND.get(item.kind, set()):
                verdict = "keep"
            if verdict in {"veto", "merge"} and not item.minted_here:
                verdict = "keep"
            if verdict == "reclassify" and (
                suggested not in RECLASSIFY_TYPES
                or item.entity_type not in RECLASSIFY_TYPES
                or suggested == item.entity_type
            ):
                verdict = "keep"
            if verdict == "merge":
                wanted = str(entry.get("merge_into") or "").strip().lower()
                for cand in item.candidates:
                    names = {cand["name"].lower(), *(a.lower() for a in cand.get("aliases") or [])}
                    if wanted and wanted in names:
                        merge_target = cand
                        break
                if merge_target is None:
                    verdict = "keep"  # never merge into a name it was not shown
            if verdict != asked and asked in VERDICTS:
                stats["coerced"] += 1
            verdicts[item_id] = Verdict(item, verdict, confidence, reason, suggested, merge_target, explicit=True)
    if stats["duplicate"]:
        verdicts = {}
    out = [verdicts.get(it.item_id) or Verdict(it, "keep", "low", "") for it in items]
    assessment = result.get("assessment")
    if isinstance(assessment, dict) and any(it.kind == "assessment" for it in items):
        verdict = str(assessment.get("verdict") or "ok").lower()
        for v in out:
            if v.item.kind == "assessment":
                v.verdict = verdict if verdict in {"ok", "overstated", "understated"} else "ok"
                v.reason = str(assessment.get("reason") or "")[:500]
    return out, stats


def _payload_name_pool(parsed: dict | None, entity_type: str | None) -> set[str]:
    from app.intelligence.autolink_reconcile import _payload_names

    keys = _OVERRIDE_PAYLOAD_KEYS.get(entity_type or "", ())
    return _payload_names(parsed or {}, keys) if keys else set()


async def _adjudication_result_id(db: AsyncSession, entry_id: uuid.UUID) -> uuid.UUID | None:
    from app.models.ai_result import AIResult

    return (
        await db.execute(
            select(AIResult.id)
            .where(
                AIResult.target_type == TARGET_TYPE,
                AIResult.target_id == entry_id,
                AIResult.is_current.is_(True),
            )
            .order_by(AIResult.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()


async def _rolling_breaker(ratio: float, breaker_pct: float) -> bool:
    """Push this run's destructive ratio; trip (pause dispatch for an hour)
    when the rolling mean over the last runs exceeds the threshold. Only apply
    runs are sampled — see the call site."""
    from app.services.redis_client import get_redis

    try:
        r = await get_redis()
        await r.lpush(_RATIOS_KEY, f"{ratio:.3f}")
        await r.ltrim(_RATIOS_KEY, 0, _ROLLING_WINDOW - 1)
        vals = [float(v) for v in await r.lrange(_RATIOS_KEY, 0, _ROLLING_WINDOW - 1)]
        if len(vals) >= _ROLLING_MIN_SAMPLES and sum(vals) / len(vals) > breaker_pct:
            already = await r.get(_BREAKER_KEY)
            await r.set(_BREAKER_KEY, str(datetime.now(UTC).timestamp() + 3600), ex=3600)
            if not already:
                logger.warning(
                    "adjudication rolling breaker tripped: mean destructive ratio %.2f over %d runs > %.2f; "
                    "dispatch paused for an hour and this run filed as proposals",
                    sum(vals) / len(vals),
                    len(vals),
                    breaker_pct,
                )
            return True
    except Exception:
        logger.debug("rolling breaker update failed", exc_info=True)
    return False


async def _entity_snapshot(db: AsyncSession, entity_type: str, entity_id: uuid.UUID) -> dict:
    """Enough of an entity to re-create it after a veto deleted it."""
    from sqlalchemy import inspect as sa_inspect

    model = _model_for(entity_type)
    obj = await db.get(model, entity_id) if model else None
    if obj is None:
        return {}
    # A bulk UPDATE on the entity's table (article_count) expires the loaded
    # instance; reading an expired attribute would lazy-load synchronously.
    if sa_inspect(obj).expired:
        await db.refresh(obj)
    snap = {"id": str(entity_id), "name": _display_name(obj)}
    for attr in (
        "aliases",
        "description",
        "article_count",
        "created_via",
        "created_from_entry_id",
        "created_confidence",
        "actor_type",
        "malware_type",
        "tool_type",
        "country",
        "motivation",
        "platforms",
    ):
        if hasattr(obj, attr):
            val = getattr(obj, attr)
            snap[attr] = str(val) if isinstance(val, uuid.UUID) else val
    return snap


async def _junction_for(db: AsyncSession, entity_type: str, entry_id: uuid.UUID, entity_id: uuid.UUID):
    """(junction row, junction model, entity model, fk attr) for one link, or None."""
    for jmodel, emodel, fk_attr, etype in _link_specs():
        if etype != entity_type:
            continue
        row = (
            await db.execute(select(jmodel).where(jmodel.entry_id == entry_id, getattr(jmodel, fk_attr) == entity_id))
        ).scalar_one_or_none()
        return row, jmodel, emodel, fk_attr
    if entity_type == TTP:
        from app.models.ttp import TTP as TTPModel
        from app.models.ttp import EntryTTP

        row = (
            await db.execute(select(EntryTTP).where(EntryTTP.entry_id == entry_id, EntryTTP.ttp_id == entity_id))
        ).scalar_one_or_none()
        return row, EntryTTP, TTPModel, "ttp_id"
    return None, None, None, None


def _junction_snapshot(junction) -> dict:
    snap: dict = {}
    for attr in ("confidence", "source", "matched_names", "paragraph_indices", "source_text", "role", "sector"):
        if hasattr(junction, attr):
            val = getattr(junction, attr)
            snap[attr] = list(val) if isinstance(val, list | tuple) else val
    if getattr(junction, "extracted_at", None):
        snap["extracted_at"] = junction.extracted_at.isoformat()
    return snap


async def _unlink(db: AsyncSession, entity_type: str, entry_id: uuid.UUID, entity_id: uuid.UUID) -> dict | None:
    """Delete one entry↔entity junction row and decrement article_count.
    Returns the junction snapshot (for restore) or None when already gone."""
    junction, _jmodel, emodel, _fk = await _junction_for(db, entity_type, entry_id, entity_id)
    if junction is None:
        return None
    snap = _junction_snapshot(junction)
    await db.delete(junction)
    if emodel is not None and hasattr(emodel, "article_count"):
        await db.execute(
            sa_update(emodel)
            .where(emodel.id == entity_id)
            .values(article_count=func.greatest(emodel.article_count - 1, 0))
        )
    return snap


async def _relink(db: AsyncSession, entity_type: str, entry_id: uuid.UUID, entity_id: uuid.UUID, snap: dict) -> bool:
    existing, jmodel, emodel, fk_attr = await _junction_for(db, entity_type, entry_id, entity_id)
    if jmodel is None or existing is not None:
        return False
    kwargs: dict = {"entry_id": entry_id, fk_attr: entity_id}
    for attr in ("confidence", "source", "matched_names", "paragraph_indices", "source_text", "role", "sector"):
        if attr in snap and hasattr(jmodel, attr):
            kwargs[attr] = snap[attr]
    if snap.get("extracted_at"):
        kwargs["extracted_at"] = datetime.fromisoformat(snap["extracted_at"])
    db.add(jmodel(**kwargs))
    if emodel is not None and hasattr(emodel, "article_count"):
        await db.execute(sa_update(emodel).where(emodel.id == entity_id).values(article_count=emodel.article_count + 1))
    return True


async def _entity_has_a_life(db: AsyncSession, entity_type: str, entity_id: uuid.UUID, entry_id: uuid.UUID) -> bool:
    """True when deleting the entity would lose something beyond this entry:
    other articles link it, an edge cites it, a claim was recorded, or it was
    not created by this entry in the first place."""
    from app.models.entity_relationship import EntityRelationship

    model = _model_for(entity_type)
    obj = await db.get(model, entity_id) if model else None
    if obj is None:
        return True
    if getattr(obj, "created_from_entry_id", None) != entry_id:
        return True
    for jmodel, _emodel, fk_attr, etype in _link_specs():
        if etype != entity_type:
            continue
        if (
            await db.execute(
                select(jmodel.entry_id)
                .where(getattr(jmodel, fk_attr) == entity_id, jmodel.entry_id != entry_id)
                .limit(1)
            )
        ).scalar_one_or_none() is not None:
            return True
    edge = (
        await db.execute(
            select(EntityRelationship.id)
            .where(
                or_(
                    (EntityRelationship.source_type == entity_type) & (EntityRelationship.source_id == entity_id),
                    (EntityRelationship.target_type == entity_type) & (EntityRelationship.target_id == entity_id),
                )
            )
            .limit(1)
        )
    ).scalar_one_or_none()
    if edge is not None:
        return True
    try:
        from app.models.entity_field_claim import EntityFieldClaim

        claim = (
            await db.execute(
                select(EntityFieldClaim.id)
                .where(EntityFieldClaim.entity_type == entity_type, EntityFieldClaim.entity_id == entity_id)
                .limit(1)
            )
        ).scalar_one_or_none()
        if claim is not None:
            return True
    except Exception:
        logger.debug("claim check skipped", exc_info=True)
    return False


async def _delete_entity(db: AsyncSession, entity_type: str, entity_id: uuid.UUID) -> bool:
    """Hard-delete a vetoed entity: its edges, its remaining junction rows,
    the row, and its search document."""
    from app.models.entity_relationship import EntityRelationship
    from app.services.entity_indexer import delete_entity_document

    model = _model_for(entity_type)
    obj = await db.get(model, entity_id) if model else None
    if obj is None:
        return False
    await db.execute(
        sa_delete(EntityRelationship).where(
            or_(
                (EntityRelationship.source_type == entity_type) & (EntityRelationship.source_id == entity_id),
                (EntityRelationship.target_type == entity_type) & (EntityRelationship.target_id == entity_id),
            )
        )
    )
    for jmodel, _emodel, fk_attr, etype in _link_specs():
        if etype == entity_type:
            await db.execute(sa_delete(jmodel).where(getattr(jmodel, fk_attr) == entity_id))
    await db.delete(obj)
    await db.flush()
    try:
        delete_entity_document(entity_type, entity_id)
    except Exception:
        logger.debug("search document delete failed for %s %s", entity_type, entity_id, exc_info=True)
    return True


async def _recreate_entity(db: AsyncSession, entity_type: str, snap: dict):
    """Re-create a vetoed-and-deleted entity from its snapshot (restore)."""
    model = _model_for(entity_type)
    if model is None or not snap.get("name"):
        return None
    kwargs: dict = {"name": snap["name"]}
    if snap.get("id"):
        kwargs["id"] = uuid.UUID(snap["id"])
    for attr in (
        "aliases",
        "description",
        "created_via",
        "created_confidence",
        "actor_type",
        "malware_type",
        "tool_type",
        "country",
        "motivation",
        "platforms",
    ):
        if attr in snap and hasattr(model, attr) and snap[attr] is not None:
            kwargs[attr] = snap[attr]
    if snap.get("created_from_entry_id") and hasattr(model, "created_from_entry_id"):
        kwargs["created_from_entry_id"] = uuid.UUID(snap["created_from_entry_id"])
    obj = model(**kwargs)
    db.add(obj)
    await db.flush()
    return obj


async def _count_edge_keep(db: AsyncSession, edge_id: uuid.UUID, entry_id: uuid.UUID) -> bool:
    """A keep on an edge from a new entry is corroboration. At
    relationship_evidence_promote_count distinct entries the edge is promoted
    to confirmed — the nightly adjudicator's promotion, as a counter. Returns
    True when this call promoted the edge."""
    from app.intelligence.correlation_cache import invalidate_entity_cache
    from app.models.entity_relationship import EntityRelationship
    from app.services.system_settings import get_setting

    edge = await db.get(EntityRelationship, edge_id)
    if edge is None or edge.source in ("analyst_rejected", "analyst_confirmed", "analyst_created"):
        return False
    if edge.adjudication_verdict == "coincidental":
        return False  # sticky, like the nightly job's demotion
    kept = list(edge.reviewer_kept_entry_ids or [])
    if entry_id in kept:
        return False
    kept.append(entry_id)
    edge.reviewer_kept_entry_ids = kept
    threshold = max(1, int(await get_setting("relationship_evidence_promote_count", db) or 3))
    promoted = False
    if len(kept) >= threshold and edge.confidence != "confirmed":
        edge.confidence = "confirmed"
        edge.adjudication_verdict = "corroborated"
        edge.adjudicated_at = datetime.now(UTC)
        promoted = True
        for etype, eid in ((edge.source_type, edge.source_id), (edge.target_type, edge.target_id)):
            try:
                await invalidate_entity_cache(etype, str(eid))
            except Exception:
                pass
    db.add(edge)
    return promoted


async def _demote_edge(db: AsyncSession, edge_id: uuid.UUID, reason: str) -> dict | None:
    """The nightly adjudicator's demotion, inline: confidence → possible,
    verdict → coincidental (sticky: later evidence never re-promotes)."""
    from app.intelligence.correlation_cache import invalidate_entity_cache
    from app.models.entity_relationship import EntityRelationship

    edge = await db.get(EntityRelationship, edge_id)
    # Same door as the manifest: an analyst's edge, or one already
    # corroborated by the required number of reviews, is not demoted by a
    # single article that fails to assert it.
    if edge is None or edge.source not in REVIEWABLE_EDGE_SOURCES or edge.adjudication_verdict == "corroborated":
        return None
    before = {"confidence": edge.confidence, "adjudication_verdict": edge.adjudication_verdict}
    edge.confidence = "possible"
    edge.adjudication_verdict = "coincidental"
    edge.adjudicated_at = datetime.now(UTC)
    if reason and not edge.description:
        edge.description = reason
    db.add(edge)
    for etype, eid in ((edge.source_type, edge.source_id), (edge.target_type, edge.target_id)):
        try:
            await invalidate_entity_cache(etype, str(eid))
        except Exception:
            pass
    return before


async def _drop_ioc(db: AsyncSession, entry, kind: str, value: str, observable_id: uuid.UUID | None) -> dict | None:
    """Staged → remove from the entry's candidate list (what the analyst
    dismiss button does); captured → remove this entry's sighting and
    recount the ledger row."""
    from app.intelligence.observables import recount_observable
    from app.models.observable import EntryObservable

    before = list(entry.observable_candidates or [])
    dropped = [c for c in before if isinstance(c, dict) and c.get("kind") == kind and c.get("value") == value]
    remaining = [c for c in before if not (isinstance(c, dict) and c.get("kind") == kind and c.get("value") == value)]
    snap: dict = {}
    if dropped:
        entry.observable_candidates = remaining
        db.add(entry)
        snap["candidate"] = dropped[0]
    if observable_id is not None:
        sighting = (
            await db.execute(
                select(EntryObservable).where(
                    EntryObservable.entry_id == entry.id, EntryObservable.observable_id == observable_id
                )
            )
        ).scalar_one_or_none()
        if sighting is not None:
            snap["sighting"] = {
                "observable_id": str(observable_id),
                "confidence": sighting.confidence,
                "source": sighting.source,
                "surface_form": sighting.surface_form,
                "was_defanged": sighting.was_defanged,
                "paragraph_indices": list(sighting.paragraph_indices or []),
            }
            await db.delete(sighting)
            await db.flush()
            await recount_observable(db, observable_id)
    return snap or None


def _json_safe(resp) -> dict | str:
    """A merge-engine response as plain JSON (UUIDs as strings), fit for a
    JSONB audit column."""
    dump = getattr(resp, "model_dump", None)
    return dump(mode="json") if dump else str(resp)


async def _merge_entity(
    db: AsyncSession, entity_type: str, entity_id: uuid.UUID, target: dict, reason: str
) -> dict | None:
    """Merge a minted duplicate into the catalogue entity the reviewer chose,
    through the merge engine's own primitives so tombstones and undo apply."""
    from app.api.entity_merge import (
        MergeRequest,
        ReclassifyRequest,
        perform_actor_merge,
        perform_malware_merge,
        perform_reclassify,
        perform_same_type_merge,
    )

    target_type = target["entity_type"]
    target_id = uuid.UUID(str(target["entity_id"]))
    if target_type != entity_type:
        resp = await perform_reclassify(
            db,
            ReclassifyRequest(
                source_type=entity_type,
                source_id=entity_id,
                target_type=target_type,
                target_id=target_id,
                mode="apply",
                reasoning=reason or None,
            ),
        )
        return {"via": "reclassify", "response": _json_safe(resp)}
    if entity_type == THREAT_ACTOR:
        resp = await perform_actor_merge(db, target_id, MergeRequest(source_id=entity_id, reasoning=reason or None))
    elif entity_type == MALWARE:
        resp = await perform_malware_merge(db, target_id, MergeRequest(source_id=entity_id, reasoning=reason or None))
    else:
        resp = await perform_same_type_merge(
            db, entity_type, target_id, entity_id, mode="apply", reasoning=reason or None
        )
    return {"via": "merge", "response": _json_safe(resp)}


async def _reclassify_agreement(
    db: AsyncSession, entity_type: str, entity_id: uuid.UUID, target_type: str, exclude_entry_id: uuid.UUID
) -> int:
    """How many other articles already have a pending proposal to move this
    entity to ``target_type`` — one vote per article, across both logs."""
    from app.models.entity_link_validation_log import EntityLinkValidationLog
    from app.models.entity_maintenance import EntityMaintenanceLog

    link_entries = (
        await db.execute(
            select(EntityLinkValidationLog.entry_id)
            .where(
                EntityLinkValidationLog.action == "needs_reclassification",
                EntityLinkValidationLog.entity_type == entity_type,
                EntityLinkValidationLog.entity_id == entity_id,
                EntityLinkValidationLog.suggested_entity_type == target_type,
                EntityLinkValidationLog.entry_id != exclude_entry_id,
            )
            .distinct()
        )
    ).scalars()
    maint_entries = (
        await db.execute(
            select(EntityMaintenanceLog.before["entry_id"].astext)
            .where(
                EntityMaintenanceLog.action == ACTION_RECLASSIFY,
                EntityMaintenanceLog.applied.is_(False),
                EntityMaintenanceLog.entity_type == entity_type,
                EntityMaintenanceLog.entity_id == entity_id,
                EntityMaintenanceLog.after["suggested_type"].astext == target_type,
            )
            .distinct()
        )
    ).scalars()
    votes = {str(e) for e in link_entries if e} | {e for e in maint_entries if e}
    votes.discard(str(exclude_entry_id))
    return len(votes)


async def _reclassify_flips_back(db: AsyncSession, entity_type: str, entity_id: uuid.UUID, target_type: str) -> bool:
    """True when the name was deliberately folded OUT of ``target_type`` before
    (a reclassify tombstone exists for it there). Proposing to move it back
    is the start of a type ping-pong, so the verdict is dropped unfiled."""
    from app.intelligence.entity_dedup import find_reclassify_tombstone

    model = _model_for(entity_type)
    obj = await db.get(model, entity_id) if model else None
    if obj is None:
        return False
    aliases = list(getattr(obj, "aliases", None) or [])
    return await find_reclassify_tombstone(db, target_type, obj.name, aliases) is not None


async def apply_verdicts(
    db: AsyncSession,
    entry,
    verdicts: list[Verdict],
    parsed: dict | None,
    cfg: dict,
) -> dict:
    """Act on the verdicts. Shadow writes proposals only; apply (gated on the
    confidence floor and the breakers) acts through the same code the
    existing tools use and writes the same audit rows, which double as the
    undo record. Returns the run detail stored on the pipeline run."""
    from app.intelligence.link_validation_apply import (
        ENTITY_TYPES,
        LinkRow,
        apply_removal,
        log_reclassification,
        log_shadow_removal,
    )
    from app.models.entity_maintenance import EntityMaintenanceLog
    from app.services.proposal_dismissals import clear_reclassify_proposals, reclassify_dismissed

    mode = cfg["mode"]
    ai_result_id = await _adjudication_result_id(db, entry.id)
    counts: dict[str, int] = {}
    overridden = 0
    # Reclassify verdicts that would move a name back into a type an analyst
    # (or an earlier apply) folded it out of — dropped, never filed.
    flip_guarded = 0
    # Changes that actually ran, vs edges a keep promoted. Promotions are not
    # changes the analyst can undo from the queue, so they are counted apart —
    # folding them into `applied` made `shadowed` under-report.
    applied_n = 0
    promoted_n = 0

    # Positive-evidence override: the reviewer may not remove a link to an
    # entity the same analysis extracted by name.
    for v in verdicts:
        if v.item.kind == "link" and v.verdict == "remove":
            pool = _payload_name_pool(parsed, v.item.entity_type)
            names = {v.item.name.strip().lower(), *(m.strip().lower() for m in v.item.matched_names)}
            names.discard("")
            if names & pool:
                v.verdict = "keep"
                overridden += 1

    destructive = [v for v in verdicts if v.verdict in DESTRUCTIVE]
    # Everything that files a row an analyst still has to decide. `reclassify`
    # is advisory in both modes, so it never counts as applied — but it is a
    # pending proposal, and leaving it out made `shadowed` read 0 on a run that
    # filed nothing but advisories. The breaker still counts only `destructive`.
    changes = [v for v in verdicts if v.verdict in DESTRUCTIVE | {"merge", "reclassify"}]
    items_n = len([v for v in verdicts if v.item.kind != "assessment"])
    ratio = (len(destructive) / items_n) if items_n else 0.0
    breaker = ratio > cfg["breaker_pct"]
    # The rolling breaker pauses dispatch for an hour, and it exists to stop
    # damage — which a shadow run does none of. Sampling shadow runs would
    # throttle the very soak that is meant to collect verdicts at full rate
    # (a destructive ratio over the threshold is ordinary there: the validator
    # it replaces filed 1,036 shadow removals in a week). The per-entry
    # breaker above still downgrades a lopsided run in any mode.
    rolling = await _rolling_breaker(ratio, cfg["breaker_pct"]) if mode == "apply" else False
    run_mode = "shadow" if (mode != "apply" or breaker or rolling) else "apply"
    floor = _CONF_RANK[cfg["min_conf"]]

    def _log(
        action: str,
        item: ReviewItem,
        before: dict | None,
        after: dict,
        *,
        applied: bool,
        entity_type: str | None = None,
        entity_id: uuid.UUID | None = None,
    ) -> EntityMaintenanceLog:
        row = EntityMaintenanceLog(
            entity_type=entity_type or item.entity_type or LOG_TYPE_ENTRY,
            entity_id=entity_id if entity_id is not None else item.entity_id,
            action=action,
            mode="apply" if applied else "shadow",
            before={"entry_id": str(entry.id), **(before or {})},
            after=after,
            reasoning=after.get("reason"),
            ai_result_id=ai_result_id,
            applied=applied,
        )
        db.add(row)
        return row

    for v in verdicts:
        item = v.item
        counts[v.verdict] = counts.get(v.verdict, 0) + 1
        if v.verdict == "keep":
            # Corroboration, and the only verdict that raises trust rather than
            # lowering it — so it is held to the same bar as the destructive
            # ones, and it must be something the reviewer actually said. The
            # prompt returns changes only, which makes nearly every other keep
            # an omission; counting those would promote an edge to `confirmed`
            # on three reviews that never weighed in. Edges are the one section
            # the prompt still demands an answer for.
            if (
                item.kind == "edge"
                and run_mode == "apply"
                and item.edge_id is not None
                and v.explicit
                and _CONF_RANK[v.confidence] >= floor
            ):
                if await _count_edge_keep(db, item.edge_id, entry.id):
                    promoted_n += 1
            continue
        if item.kind == "assessment" and v.verdict == "ok":
            continue
        reason = v.reason
        do_apply = run_mode == "apply" and _CONF_RANK[v.confidence] >= floor
        # Never touched: a link an analyst restored recently is only ever
        # flagged again, whatever the mode and confidence.
        if item.kind == "link" and item.previously_restored:
            do_apply = False
        after_base = {"reason": reason, "confidence": v.confidence}

        if item.kind == "link":
            link_row = LinkRow(
                entity_key=item.item_id.removeprefix("link:"),
                entity_type=item.entity_type or "",
                entity_id=item.entity_id,  # type: ignore[arg-type]
                name=item.name,
                matched_names=item.matched_names,
                confidence=item.confidence,
                source=item.source,
                paragraph_indices=item.paragraph_indices,
                extracted_at=item.extracted_at,
                previously_restored=item.previously_restored,
            )
            if v.verdict == "remove":
                if item.entity_type in ENTITY_TYPES:
                    if do_apply:
                        if await apply_removal(db, entry.id, link_row, reason, ai_result_id):
                            applied_n += 1
                    else:
                        await log_shadow_removal(db, entry.id, link_row, reason, ai_result_id)
                else:
                    snap = _junction_snapshot_from_item(item)
                    if do_apply:
                        real = await _unlink(db, item.entity_type or "", entry.id, item.entity_id)  # type: ignore[arg-type]
                        if real is not None:
                            applied_n += 1
                            snap = real
                    _log(ACTION_UNLINK, item, {"junction": snap}, after_base, applied=do_apply)
            elif v.verdict == "reclassify" and v.suggested_type:
                etype, eid, target = item.entity_type or "", item.entity_id, v.suggested_type
                if await _reclassify_flips_back(db, etype, eid, target):  # type: ignore[arg-type]
                    flip_guarded += 1
                    continue
                if await reclassify_dismissed(db, etype, eid):  # type: ignore[arg-type]
                    continue
                # A type change is catalogue-wide, so one article's say-so is
                # not enough: it is applied once `reclassify_consensus`
                # distinct articles agree on the target (this one included),
                # at or above the confidence floor. Until then it is filed
                # as a proposal, which is also the vote the next article
                # counts. Applying converts the entity; the link follows it.
                agreement = 1 + await _reclassify_agreement(db, etype, eid, target, entry.id)  # type: ignore[arg-type]
                converted = False
                if do_apply and agreement >= cfg["reclassify_consensus"]:
                    try:
                        async with db.begin_nested():
                            outcome = await _reclassify_entity(db, etype, eid, target, reason)  # type: ignore[arg-type]
                        converted = bool(outcome.get("applied"))
                    except Exception as exc:
                        logger.warning("adjudication reclassify failed for %s: %s", item.item_id, exc)
                        outcome = {"applied": False, "error": str(exc)[:300]}
                    if converted:
                        applied_n += 1
                        await clear_reclassify_proposals(db, etype, eid)  # type: ignore[arg-type]
                        _log(
                            ACTION_RECLASSIFY,
                            item,
                            {"entity": {"name": item.name}},
                            {
                                **after_base,
                                "suggested_type": target,
                                "agreement": agreement,
                                "outcome": {k: val for k, val in outcome.items() if k != "applied"},
                            },
                            applied=True,
                        )
                if not converted:
                    if etype in ENTITY_TYPES:
                        await log_reclassification(db, entry.id, link_row, reason, target, ai_result_id)
                    else:
                        _log(
                            ACTION_RECLASSIFY,
                            item,
                            {"entity": {"name": item.name}},
                            {**after_base, "suggested_type": target, "agreement": agreement},
                            applied=False,
                        )
            elif v.verdict == "veto":
                snapshot = await _entity_snapshot(db, item.entity_type or "", item.entity_id)  # type: ignore[arg-type]
                junction_snap = _junction_snapshot_from_item(item)
                if do_apply:
                    real = await _unlink(db, item.entity_type or "", entry.id, item.entity_id)  # type: ignore[arg-type]
                    if real is not None:
                        junction_snap = real
                    deleted = False
                    if not await _entity_has_a_life(db, item.entity_type or "", item.entity_id, entry.id):  # type: ignore[arg-type]
                        deleted = await _delete_entity(db, item.entity_type or "", item.entity_id)  # type: ignore[arg-type]
                    if real is not None or deleted:
                        applied_n += 1
                    _log(
                        ACTION_VETO if deleted else ACTION_UNLINK,
                        item,
                        {"entity": snapshot, "junction": junction_snap},
                        {**after_base, "deleted": deleted},
                        applied=True,
                    )
                else:
                    _log(ACTION_VETO, item, {"entity": snapshot, "junction": junction_snap}, after_base, applied=False)
            elif v.verdict == "merge" and v.merge_target:
                after = {
                    **after_base,
                    "merge_into": v.merge_target["name"],
                    "target_type": v.merge_target["entity_type"],
                    "target_id": v.merge_target["entity_id"],
                }
                snapshot = {"name": item.name}
                if do_apply:
                    # A failed merge must not poison the session for the rest
                    # of the run: the savepoint rolls back just this merge.
                    try:
                        async with db.begin_nested():
                            outcome = await _merge_entity(
                                db, item.entity_type or "", item.entity_id, v.merge_target, reason
                            )  # type: ignore[arg-type]
                        applied_n += 1
                        _log(ACTION_MERGE, item, {"entity": snapshot}, {**after, "outcome": outcome}, applied=True)
                    except Exception as exc:
                        logger.warning("adjudication merge failed for %s: %s", item.item_id, exc)
                        _log(
                            ACTION_MERGE, item, {"entity": snapshot}, {**after, "error": str(exc)[:300]}, applied=False
                        )
                else:
                    _log(ACTION_MERGE, item, {"entity": snapshot}, after, applied=False)
        elif item.kind == "edge" and v.verdict == "demote":
            if do_apply:
                before = await _demote_edge(db, item.edge_id, reason)  # type: ignore[arg-type]
                if before is not None:
                    applied_n += 1
                    _log(
                        ACTION_EDGE_DEMOTE,
                        item,
                        {"claim": item.name, **before},
                        after_base,
                        applied=True,
                        entity_type=LOG_TYPE_RELATIONSHIP,
                        entity_id=item.edge_id,
                    )
            else:
                _log(
                    ACTION_EDGE_DEMOTE,
                    item,
                    {"claim": item.name},
                    after_base,
                    applied=False,
                    entity_type=LOG_TYPE_RELATIONSHIP,
                    entity_id=item.edge_id,
                )
        elif item.kind == "ioc" and v.verdict == "drop":
            after = {**after_base, "kind": item.ioc_kind, "value": item.ioc_value}
            if do_apply:
                snap = await _drop_ioc(db, entry, item.ioc_kind or "", item.ioc_value or "", item.observable_id)
                if snap is not None:
                    applied_n += 1
                    _log(
                        ACTION_IOC_DROP,
                        item,
                        {"staged": item.staged, **snap},
                        after,
                        applied=True,
                        entity_type=OBSERVABLE,
                        entity_id=item.observable_id,
                    )
            else:
                _log(
                    ACTION_IOC_DROP,
                    item,
                    {"staged": item.staged},
                    after,
                    applied=False,
                    entity_type=OBSERVABLE,
                    entity_id=item.observable_id,
                )
        elif item.kind == "assessment":
            _log(
                ACTION_ASSESSMENT,
                item,
                None,
                {"verdict": v.verdict, "reason": reason},
                applied=False,
                entity_type=LOG_TYPE_ENTRY,
                entity_id=entry.id,
            )

    return {
        "mode": run_mode,
        "requested_mode": mode,
        "items": items_n,
        "verdicts": counts,
        "applied": applied_n,
        "promoted": promoted_n,
        "shadowed": max(0, len(changes) - applied_n - flip_guarded),
        "breaker": breaker,
        "rolling_breaker": rolling,
        "keep_overridden": overridden,
        "reclassify_flip_guarded": flip_guarded,
    }


def _junction_snapshot_from_item(item: ReviewItem) -> dict:
    snap: dict = {
        "confidence": item.confidence,
        "source": item.source,
        "matched_names": list(item.matched_names),
        "paragraph_indices": list(item.paragraph_indices),
    }
    if item.extracted_at:
        snap["extracted_at"] = item.extracted_at.isoformat()
    return snap


# --------------------------------------------------------------------------- queue apply / restore


async def _reclassify_entity(
    db: AsyncSession, entity_type: str, entity_id: uuid.UUID, target_type: str, reason: str
) -> dict:
    """Convert a mis-typed entity through the merge engine's reclassify: into
    the same-named entity of the target type when one exists, else as a new
    entity of that type. The link follows the entity; nothing is unlinked."""
    from app.api.entity_merge import ReclassifyRequest, perform_reclassify

    if target_type not in RECLASSIFY_TYPES or entity_type not in RECLASSIFY_TYPES or target_type == entity_type:
        return {"applied": False, "reason": f"cannot reclassify {entity_type} → {target_type}"}
    model = _model_for(entity_type)
    obj = await db.get(model, entity_id) if model else None
    if obj is None:
        return {"applied": False, "reason": "entity gone"}
    target_model = _model_for(target_type)
    existing = None
    if target_model is not None:
        existing = (
            await db.execute(
                select(target_model.id).where(func.lower(target_model.name) == func.lower(obj.name)).limit(1)
            )
        ).scalar_one_or_none()
    resp = await perform_reclassify(
        db,
        ReclassifyRequest(
            source_type=entity_type,
            source_id=entity_id,
            target_type=target_type,
            target_id=existing,
            mode="apply",
            reasoning=(reason or None),
        ),
    )
    return {
        "applied": True,
        "target_type": target_type,
        "merged_into_existing": existing is not None,
        "response": _json_safe(resp),
    }


async def apply_adjudication_row(db: AsyncSession, row) -> dict:
    """Apply one shadow proposal the stage filed (the queue's Apply button).
    Same primitives as apply mode; marks the row applied."""
    from app.models.entry import Entry

    if row.applied:
        return {"applied": False, "reason": "already applied"}
    before = row.before or {}
    after = row.after or {}
    entry = await db.get(Entry, uuid.UUID(before["entry_id"])) if before.get("entry_id") else None
    # A merge or a type change is about the entity, not the article: the
    # duplicate review files merges with no entry at all, and an article being
    # gone does not make either moot.
    if entry is None and row.action not in (ACTION_MERGE, ACTION_RECLASSIFY):
        return {"applied": False, "reason": "entry gone"}
    reason = after.get("reason") or ""
    outcome: dict = {"applied": True}

    if row.action == ACTION_UNLINK and row.entity_id:
        snap = await _unlink(db, row.entity_type, entry.id, row.entity_id)
        if snap is not None:
            before["junction"] = snap
        else:
            outcome = {"applied": True, "note": "link already gone"}
    elif row.action == ACTION_RECLASSIFY and row.entity_id and after.get("suggested_type"):
        outcome = await _reclassify_entity(db, row.entity_type, row.entity_id, after["suggested_type"], reason)
        if not outcome.get("applied"):
            return outcome
        after["outcome"] = {k: v for k, v in outcome.items() if k != "applied"}
    elif row.action == ACTION_VETO and row.entity_id:
        # The shadow-time snapshot can be stale (aliases, description edited
        # since); what restore re-creates is the entity as it is now.
        fresh = await _entity_snapshot(db, row.entity_type, row.entity_id)
        if fresh:
            before["entity"] = fresh
        snap = await _unlink(db, row.entity_type, entry.id, row.entity_id)
        if snap is not None:
            before["junction"] = snap
        deleted = False
        if not await _entity_has_a_life(db, row.entity_type, row.entity_id, entry.id):
            deleted = await _delete_entity(db, row.entity_type, row.entity_id)
        after["deleted"] = deleted
        if not deleted:
            row.action = ACTION_UNLINK
        outcome["deleted"] = deleted
    elif row.action == ACTION_MERGE and row.entity_id and after.get("target_id"):
        target = {
            "entity_type": after.get("target_type") or row.entity_type,
            "entity_id": after["target_id"],
            "name": after.get("merge_into"),
        }
        after["outcome"] = await _merge_entity(db, row.entity_type, row.entity_id, target, reason)
    elif row.action == ACTION_EDGE_DEMOTE and row.entity_id:
        prev = await _demote_edge(db, row.entity_id, reason)
        if prev is None:
            return {"applied": False, "reason": "edge gone or analyst-rejected"}
        before.update(prev)
    elif row.action == ACTION_IOC_DROP:
        observable_id = row.entity_id
        snap = await _drop_ioc(db, entry, after.get("kind") or "", after.get("value") or "", observable_id)
        if snap:
            before.update(snap)
    elif row.action == ACTION_ASSESSMENT:
        return {"applied": False, "reason": "assessment flags are informational"}
    else:
        return {"applied": False, "reason": f"nothing to apply for {row.action}"}

    row.before = dict(before)
    row.after = dict(after)
    row.mode = "apply"
    row.applied = True
    db.add(row)
    await db.flush()
    if row.action == ACTION_RECLASSIFY:
        # This row stays as the undo record; the other articles' copies of the
        # proposal (any suggested type, either log) are settled by it.
        from app.services.proposal_dismissals import clear_reclassify_proposals

        await clear_reclassify_proposals(db, row.entity_type, row.entity_id)
    return outcome


async def restore_adjudication_row(db: AsyncSession, row) -> dict:
    """Undo an applied adjudication row from its snapshots."""
    from app.intelligence.correlation_cache import invalidate_entity_cache
    from app.intelligence.observables import record_sighting
    from app.models.entity_relationship import EntityRelationship
    from app.models.entry import Entry
    from app.models.observable import Observable

    if not row.applied:
        return {"restored": False, "reason": "not applied"}
    before = row.before or {}
    after = row.after or {}
    # The row keeps `applied=True` after an undo — a restore is history, not a
    # reversal of the record. `after.restored` is the only marker that it has
    # already been put back, and it is what hides the button
    # (_row_actions_maint); without it here, a second POST re-runs the undo.
    if after.get("restored"):
        return {"restored": False, "reason": "already restored"}
    entry = await db.get(Entry, uuid.UUID(before["entry_id"])) if before.get("entry_id") else None
    if entry is None:
        return {"restored": False, "reason": "entry gone"}

    if row.action in (ACTION_UNLINK, ACTION_VETO) and row.entity_id:
        entity_type = row.entity_type
        model = _model_for(entity_type)
        obj = await db.get(model, row.entity_id) if model else None
        if obj is None and row.action == ACTION_VETO and before.get("entity"):
            obj = await _recreate_entity(db, entity_type, before["entity"])
        if obj is None:
            return {"restored": False, "reason": "entity gone and no snapshot"}
        relinked = await _relink(db, entity_type, entry.id, row.entity_id, before.get("junction") or {})
        outcome = {"restored": True, "relinked": relinked, "recreated": after.get("deleted", False)}
    elif row.action == ACTION_EDGE_DEMOTE and row.entity_id:
        edge = await db.get(EntityRelationship, row.entity_id)
        if edge is None:
            return {"restored": False, "reason": "edge gone"}
        edge.confidence = before.get("confidence") or "probable"
        edge.adjudication_verdict = before.get("adjudication_verdict")
        edge.adjudicated_at = None
        db.add(edge)
        for etype, eid in ((edge.source_type, edge.source_id), (edge.target_type, edge.target_id)):
            try:
                await invalidate_entity_cache(etype, str(eid))
            except Exception:
                pass
        outcome = {"restored": True}
    elif row.action == ACTION_IOC_DROP:
        outcome = {"restored": True}
        if before.get("candidate"):
            cands = list(entry.observable_candidates or [])
            if not any(
                c.get("kind") == before["candidate"].get("kind") and c.get("value") == before["candidate"].get("value")
                for c in cands
                if isinstance(c, dict)
            ):
                cands.append(before["candidate"])
                entry.observable_candidates = cands
                db.add(entry)
        sighting = before.get("sighting")
        if sighting and sighting.get("observable_id"):
            obs = await db.get(Observable, uuid.UUID(sighting["observable_id"]))
            if obs is not None:
                await record_sighting(
                    db,
                    entry.id,
                    obs,
                    source=sighting.get("source") or "ai",
                    confidence=sighting.get("confidence"),
                    surface_form=sighting.get("surface_form"),
                    was_defanged=bool(sighting.get("was_defanged")),
                    paragraph_indices=sighting.get("paragraph_indices") or None,
                )
    elif row.action in (ACTION_MERGE, ACTION_RECLASSIFY):
        return {"restored": False, "reason": "merges and reclassifies are undone from the merge engine's tombstone"}
    else:
        return {"restored": False, "reason": f"nothing to restore for {row.action}"}

    # The row stays as history; a restore is its own audit line. `applied` is
    # True and the action is ACTION_RESTORED: the restore ran, and nothing
    # should ever offer to apply it.
    db.add(
        type(row)(
            entity_type=row.entity_type,
            entity_id=row.entity_id,
            action=ACTION_RESTORED,
            mode="apply",
            before={"restored_from": str(row.id), "undid": row.action, **before},
            after={**after, "restored": True},
            reasoning=f"restored from {row.id}",
            ai_result_id=row.ai_result_id,
            applied=True,
        )
    )
    row.after = {**after, "restored": True}
    db.add(row)
    await db.flush()
    return outcome
