"""One-pass entry analysis: enqueue policy + parsed-result fan-out to entity stores.

The `entry_analysis` AI task returns one combined payload per entry
(summary, ttps, threat_actors, malware, tools, countries, sectors,
mitigations, severity_assessment, novelty_note). This module:

- decides whether an entry gets analyzed at all (`enqueue_entry_analysis`:
  flag → dedup → feed policy → junk gate → echo-reuse → queue), and
- fans a parsed payload out to the existing per-entity store functions
  (`store_entry_analysis`) so links land exactly as the old per-task
  extraction calls produced them.

Judging what was written is not this module's job any more: the adjudicate
stage (services/entry_adjudication.py) reviews every link, minted entity,
edge and observable after the payload has landed, with the whole output in
view. The extraction call only extracts.
"""

import logging
import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.caller import Caller

# Feed-policy skip statuses live with the shared "will the AI read this?"
# check, which the autolinker's pending tier uses too. Re-exported here.
from app.services.ai_eligibility import (
    FEED_SKIP_STATUSES,
    SKIPPED_FEED_AI_OFF,  # noqa: F401
    SKIPPED_FEED_NONE,  # noqa: F401
    feed_ai_skip_status,
)

logger = logging.getLogger(__name__)

ECHO_REUSE_MIN_RATIO = 0.7


def analysis_content_text(entry) -> str:
    """Prompt body for entry analysis — the translated text when one exists
    (the pipeline's translate prologue runs before scoring/enqueue), else the
    original. Rendered from HTML when available so tables keep their rows
    (``hash | description``) and headings sit on their own line; nh3's plain
    tag strip (``content_text``) is the fallback."""
    from app.services.analysis_window import html_to_analysis_text

    if entry.translated_html:
        translated = html_to_analysis_text(entry.translated_html)
        if translated.strip():
            return translated
    if getattr(entry, "content_html", None):
        rendered = html_to_analysis_text(entry.content_html)
        if rendered.strip():
            return rendered
    return entry.content_text or ""


async def build_analysis_variables(db: AsyncSession, entry) -> dict:
    """Template variables for the entry_analysis prompt — shared by the batch
    submit path, the sequential fallback, and manual runs so every path renders
    the identical prompt (content window + observable candidate hints)."""
    from app.models.feed import Feed
    from app.services.analysis_window import analysis_content_window, rank_candidate_hints
    from app.services.system_settings import get_setting

    max_chars = int(await get_setting("ai_analysis_content_max_chars", db) or 12000)
    tail_reserve = float(await get_setting("observables_analysis_tail_reserve", db) or 0.0)
    feed_title = (await db.execute(select(Feed.title).where(Feed.id == entry.feed_id))).scalar_one_or_none() or ""
    return {
        "entry": {
            "title": entry.translated_title or entry.title,
            "feed_title": feed_title,
            # Head + indicator appendix: a long write-up's IOC section lives
            # at the end, past a plain head slice.
            "content_text": analysis_content_window(analysis_content_text(entry), max_chars, tail_reserve=tail_reserve),
        },
        # Tier-0 nominations rendered as hints for the iocs rules block, ranked
        # (AI stagings, defanged, hashes, IPs) with scan-origin host kinds
        # excluded. Cap keeps a C2-list entry from flooding the prompt.
        "observable_candidates": rank_candidate_hints(entry.observable_candidates or [], limit=40),
    }


async def _tool_mode_for_entry(db: AsyncSession, entry_id: uuid.UUID, parsed: dict) -> str:
    """How this entry's AI tool names are stored: ``create``, ``link`` or ``skip``.

    Vulnerability advisories name software that is BROKEN, not software being
    wielded — on an NVD or distro-advisory entry the affected package is often
    the only software mentioned, so the model hands it back as a tool. NVD
    alone minted 230 tools in eleven weeks, 224 of them with no adversary link
    at all. An advisory report_type therefore skips tools outright (it catches
    advisories arriving on mixed feeds).

    The per-feed ``extract_tools`` switch is the operator's control over the
    catalog, not over tagging: off means ``link`` — names that resolve to an
    existing tool still link, and nothing new is created.
    """
    from app.models.entry import Entry
    from app.models.feed import Feed

    if (parsed.get("report_type") or "").strip().lower() == "advisory":
        return "skip"
    entry = await db.get(Entry, entry_id)
    if entry is None:
        return "create"
    feed = await db.get(Feed, entry.feed_id)
    if feed is not None and not getattr(feed, "extract_tools", True):
        return "link"
    return "create"


async def apply_ai_observables(
    db: AsyncSession,
    entry_id: uuid.UUID,
    parsed: dict,
    *,
    mode: str | None = None,
    capture_kinds: set[str] | None = None,
    fire_automations: bool = True,
) -> dict[str, int]:
    """The AI doors of the observables ledger, from a parsed entry_analysis payload.

    ``observables_ai_capture_mode`` decides whether the AI's confirmations
    become rows (``capture``) or stay on the entry as promotable candidates
    (``shadow``, the default). In capture mode only the kinds listed in
    ``observables_ai_capture_kinds`` are written; anything else the AI
    reported is still staged, so host kinds can be switched on per kind once
    the extraction fixture says they are precise. The TTP door
    (``EntryTTP.observable_value`` upserts) follows the same switches.

    Shared by ingest (``store_entry_analysis``) and the replay script, so a
    backfill and a live run apply identical rules. Returns per-door counts.
    When rows were captured and ``fire_automations`` is set (ingest, not the
    replay backfill), the ``on_observable_captured`` runner is queued.
    """
    from app.intelligence.observables import (
        kind_for_ttp_observable,
        shadow_observables,
        store_observables,
        store_scripts,
        sync_observables_from_entry_ttps,
    )
    from app.models.observable import SCRIPT_KIND
    from app.services.system_settings import get_setting

    counts: dict[str, int] = {}
    ai_mode = (mode or str(await get_setting("observables_ai_capture_mode", db) or "shadow")).lower()
    if capture_kinds is None:
        raw = await get_setting("observables_ai_capture_kinds", db) or ""
        capture_kinds = {k.strip() for k in str(raw).split(",") if k.strip()}

    iocs = [i for i in (parsed.get("iocs") or []) if isinstance(i, dict)]
    scripts = [i for i in (parsed.get("scripts") or []) if isinstance(i, dict)]
    ttp_items = [
        {"kind": kind, "value": t["observable_value"], "defanged": False, "technique_id": t.get("technique_id") or ""}
        for t in (parsed.get("ttps") or [])
        if isinstance(t, dict)
        and (kind := kind_for_ttp_observable(t.get("observable_type"), t.get("observable_value")))
    ]

    if ai_mode == "capture":
        captured = [i for i in iocs if (i.get("kind") or "").strip() in capture_kinds]
        held = [i for i in iocs if (i.get("kind") or "").strip() not in capture_kinds]
        if captured:
            counts["observables"] = await store_observables(db, entry_id, captured)
        held_scripts: list[dict] = []
        if SCRIPT_KIND in capture_kinds:
            if scripts:
                counts["scripts"] = await store_scripts(db, entry_id, scripts)
        else:
            held_scripts = scripts
        # The TTP door's host artifacts obey the per-kind list too.
        if ttp_items and any(i["kind"] in capture_kinds for i in ttp_items):
            host_obs = await sync_observables_from_entry_ttps(db, entry_id, kinds=capture_kinds)
            if host_obs:
                counts["host_observables"] = host_obs
        held += [i for i in ttp_items if i["kind"] not in capture_kinds]
        if held or held_scripts:
            counts["observables_shadow"] = await shadow_observables(db, entry_id, held, held_scripts)
    else:
        if iocs or ttp_items or scripts:
            counts["observables_shadow"] = await shadow_observables(db, entry_id, iocs + ttp_items, scripts)
    if fire_automations and any(counts.get(k) for k in ("observables", "scripts", "host_observables")):
        from app.workers.automation_tasks import dispatch_observable_capture_automations

        dispatch_observable_capture_automations(entry_id)
    return counts


async def store_entry_analysis(db: AsyncSession, entry_id: uuid.UUID, parsed: dict) -> dict:
    """Fan a parsed entry_analysis payload out to the entity store functions.

    Returns per-type stored counts. Summary/severity/novelty stay on the
    AIResult row (rendered by the existing AI results UI).
    """
    from app.intelligence.enrichment import (
        store_countries,
        store_malware,
        store_sectors,
        store_threat_actors,
    )
    from app.intelligence.mitigation import store_mitigations
    from app.intelligence.tool import store_tools
    from app.intelligence.ttp import store_ttps

    counts: dict[str, int] = {}
    if parsed.get("ttps"):
        counts["ttps"] = len(await store_ttps(db, entry_id, parsed["ttps"]))
    if parsed.get("threat_actors"):
        counts["threat_actors"] = len(await store_threat_actors(db, entry_id, parsed["threat_actors"]))
    if parsed.get("malware"):
        counts["malware"] = len(await store_malware(db, entry_id, parsed["malware"]))
    if parsed.get("tools"):
        tool_mode = await _tool_mode_for_entry(db, entry_id, parsed)
        if tool_mode != "skip":
            stored = await store_tools(db, entry_id, parsed["tools"], allow_create=tool_mode == "create")
            counts["tools"] = len(stored)
    if parsed.get("countries"):
        counts["countries"] = len(await store_countries(db, entry_id, parsed["countries"]))
    if parsed.get("sectors"):
        counts["sectors"] = len(await store_sectors(db, entry_id, parsed["sectors"]))
    if parsed.get("mitigations"):
        counts["mitigations"] = len(await store_mitigations(db, entry_id, parsed["mitigations"]))
    # The observables ledger's AI doors. Guarded: a ledger failure must never
    # lose the analysis payload.
    try:
        counts.update(await apply_ai_observables(db, entry_id, parsed))
    except Exception:
        logger.warning("Observable store failed for entry %s", entry_id, exc_info=True)

    if any(parsed.get(k) for k in ("report_type", "victim_organizations", "timeline", "patch")):
        from app.intelligence.enrichment import store_article_metadata

        await store_article_metadata(db, entry_id, parsed)
        counts["article_metadata"] = 1
    if parsed.get("relationships"):
        from app.intelligence.enrichment import store_ai_relationships

        try:
            counts["relationships"] = await store_ai_relationships(db, parsed["relationships"], entry_id, parsed=parsed)
        except Exception:
            logger.warning("Relationship store failed for entry %s", entry_id, exc_info=True)

    # Reconcile pending dictionary-word autolinks against what the AI actually
    # read in the article — promote confirmed entities, reject the rest. Guarded:
    # a reconcile failure must never lose the analysis payload itself.
    try:
        from app.intelligence.autolink_reconcile import reconcile_pending_autolinks

        reconciled = await reconcile_pending_autolinks(db, entry_id, parsed)
        if reconciled["promoted"] or reconciled["rejected"]:
            counts["autolinks_promoted"] = reconciled["promoted"]
            counts["autolinks_rejected"] = reconciled["rejected"]
    except Exception:
        logger.warning("Pending autolink reconcile failed for entry %s", entry_id, exc_info=True)
    return counts


async def analyze_entry(
    db: AsyncSession,
    user_id: uuid.UUID,
    entry_id: uuid.UUID,
    entry_data: dict,
    force: bool = False,
    caller: Caller | None = None,
) -> tuple[dict | None, dict]:
    """Run the one-pass entry_analysis task inline + fan out. Returns (parsed, counts).

    Used by manual/bulk extraction paths (the ingest pipeline goes through the
    batch queue instead).
    """
    from app.ai.engine import run_task

    variables: dict = {"entry": entry_data}
    result = await run_task(
        db=db,
        user_id=user_id,
        task_name="entry_analysis",
        variables=variables,
        entry_id=entry_id,
        target_type="entry",
        target_id=entry_id,
        force=force,
        caller=caller,
    )
    if not isinstance(result, dict) or result.get("_extraction_status") not in (None, "success"):
        return result, {}
    counts = await store_entry_analysis(db, entry_id, result)
    # A manual run on an entry the gates skipped (junk, feed policy) or whose
    # batch attempts failed: the entry is analyzed now, so its queue row says
    # so — otherwise the Engine matrix keeps showing the stale skip or error.
    from sqlalchemy import or_, update

    from app.models.ai_analysis import AIAnalysisRequest

    await db.execute(
        update(AIAnalysisRequest)
        .where(
            AIAnalysisRequest.entry_id == entry_id,
            or_(AIAnalysisRequest.status.like("skipped\\_%"), AIAnalysisRequest.status == "failed"),
        )
        .values(status="completed", completed_at=datetime.now(UTC), error=None)
    )
    # Manual runs commit in the API handler right after this returns; the
    # review task starts after its countdown, well past that commit.
    from app.services.entry_adjudication import enqueue_and_dispatch

    await enqueue_and_dispatch(db, entry_id, counts, result, countdown=15)
    return result, counts


async def _current_analysis_result(db: AsyncSession, entry_id: uuid.UUID):
    """(AIResult, AITask) for the entry's current entry_analysis result, or (None, task)."""
    from app.models.ai_result import AIResult
    from app.models.ai_task import AITask

    task = (await db.execute(select(AITask).where(AITask.name == "entry_analysis"))).scalar_one_or_none()
    if task is None:
        return None, None
    # Newest-first + limit(1) rather than scalar_one_or_none(): a (target, task)
    # carrying more than one current row must not raise here. This is called
    # per-entry from submit_analysis_batches' self-healing sweep, so one bad
    # entry used to abort the whole hourly run and stall every pending analysis.
    result = (
        await db.execute(
            select(AIResult)
            .where(
                AIResult.target_type == "entry",
                AIResult.target_id == entry_id,
                AIResult.task_id == task.id,
                AIResult.is_current == True,  # noqa: E712
            )
            .order_by(AIResult.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    return result, task


async def enqueue_entry_analysis(db: AsyncSession, entry_id: uuid.UUID) -> str | None:
    """Queue an entry for one-pass analysis. Returns the queue status written, or None.

    Called from score_entry_task (signals exist by then, so echo-reuse can read
    the feed_echo payload). Idempotent via the unique entry_id constraint.
    """
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    from app.intelligence.relevance_filter import get_relevance_threshold, score_relevance
    from app.models.ai_analysis import AIAnalysisRequest
    from app.models.entry import Entry
    from app.models.entry_signal import EntrySignal
    from app.services.system_settings import get_setting

    if not bool(await get_setting("ai_one_pass_enabled", db)):
        return None

    # Already queued / handled? A feed-policy skip is re-decided below: the
    # feed's switches may have changed since.
    existing = (
        await db.execute(select(AIAnalysisRequest.status).where(AIAnalysisRequest.entry_id == entry_id))
    ).scalar_one_or_none()
    if existing is not None and existing not in FEED_SKIP_STATUSES:
        return existing

    # Already analyzed (manual run, or re-score of an old entry)?
    current, task = await _current_analysis_result(db, entry_id)
    if task is None:
        return None
    if current is not None:
        return None

    entry = await db.get(Entry, entry_id)
    if entry is None:
        return None

    from sqlalchemy import func

    from app.models.feed import Feed

    async def _write_status(status: str, **extra) -> str:
        # Insert, or overwrite a feed-policy skip (the only re-decided status);
        # any other existing row wins, as before.
        stmt = pg_insert(AIAnalysisRequest).values(
            id=uuid.uuid4(), entry_id=entry_id, status=status, custom_id=f"ea-{entry_id}", **extra
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=["entry_id"],
            set_={"status": status, "created_at": func.now(), **extra},
            where=AIAnalysisRequest.status.in_(FEED_SKIP_STATUSES),
        )
        await db.execute(stmt)
        return status

    # Feed policy (mode "none", or the feed's AI switch off). The same check
    # decides whether the autolinker holds dictionary-word matches for the AI.
    feed = await db.get(Feed, entry.feed_id)
    if feed is not None:
        skip = feed_ai_skip_status(
            getattr(feed, "intel_extraction_mode", None), getattr(feed, "ai_analysis_enabled", True)
        )
        if skip is not None:
            return existing if existing == skip else await _write_status(skip)

    # Junk gate: skip non-security chatter (threshold configurable). Scans
    # translated text too so non-English entries aren't gated as junk.
    from app.services.sanitizer import entry_text_with_translation

    gate_title, gate_text = entry_text_with_translation(entry)
    threshold = await get_relevance_threshold(db)
    relevance = score_relevance(gate_title, entry.summary or "", gate_text)
    if relevance < threshold:
        return await _write_status("skipped_junk")

    # Echo-reuse: near-duplicate of an already-analyzed entry → copy at zero cost
    echo = (
        await db.execute(
            select(EntrySignal).where(EntrySignal.entry_id == entry_id, EntrySignal.signal_type == "feed_echo")
        )
    ).scalar_one_or_none()
    if echo and (echo.payload or {}).get("ratio", 0) >= ECHO_REUSE_MIN_RATIO:
        dup_id = (echo.payload or {}).get("duplicate_of")
        if dup_id:
            dup_result, _ = await _current_analysis_result(db, uuid.UUID(dup_id))
            if dup_result is not None and isinstance(dup_result.parsed_result, dict):
                from app.ai.engine import attribution_fields
                from app.models.ai_result import AIResult

                parsed = dict(dup_result.parsed_result)
                parsed["_reused_from"] = dup_id
                db.add(
                    AIResult(
                        entry_id=entry_id,
                        target_type="entry",
                        target_id=entry_id,
                        is_current=True,
                        task_id=task.id,
                        provider_id=dup_result.provider_id,
                        model_name=dup_result.model_name,
                        prompt_used="(reused from near-duplicate entry)",
                        raw_response="",
                        parsed_result=parsed,
                        tokens_input=0,
                        tokens_output=0,
                        cost_estimate=0,
                        processing_time_ms=0,
                        **{**attribution_fields(Caller.system(), None), "provider_name": dup_result.provider_name},
                    )
                )
                await store_entry_analysis(db, entry_id, parsed)
                status = await _write_status(
                    "reused_echo",
                    reused_from_entry_id=uuid.UUID(dup_id),
                    completed_at=datetime.now(UTC),
                )
                # Echo payloads were judged against the duplicate's text; the
                # adjudicate stage records the skip rather than reviewing them.
                from app.services.entry_adjudication import enqueue_adjudication

                await enqueue_adjudication(db, entry_id, None, parsed)
                return status

    return await _write_status("pending")
