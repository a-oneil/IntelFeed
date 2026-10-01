"""One-pass entry analysis: enqueue policy + parsed-result fan-out to entity stores.

The `entry_analysis` AI task returns one combined payload per entry
(summary, ttps, threat_actors, malware, tools, countries, sectors,
mitigations, severity_assessment, novelty_note). This module:

- decides whether an entry gets analyzed at all (`enqueue_entry_analysis`:
  flag → dedup → feed policy → junk gate → echo-reuse → queue), and
- fans a parsed payload out to the existing per-entity store functions
  (`store_entry_analysis`) so links land exactly as the old per-task
  extraction calls produced them.
"""

import logging
import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

ECHO_REUSE_MIN_RATIO = 0.7

# Context snippet sizing for candidate entity tags (chars around the first
# matched surface form, and total cap per candidate across paragraphs).
_CANDIDATE_CONTEXT_WINDOW = 160
_CANDIDATE_CONTEXT_MAX_CHARS = 400
_CANDIDATE_CONTEXT_MAX_PARAGRAPHS = 2

# Payload lists that count as positive evidence per link-validation entity
# type. Actor/malware share one pool (the AI routinely files ransomware brands
# under the other slot); vendor/product have no payload list, so no override.
_OVERRIDE_PAYLOAD_KEYS: dict[str, tuple[str, ...]] = {
    "threat_actor": ("threat_actors", "malware", "tools"),
    "malware": ("threat_actors", "malware", "tools"),
    "country": ("countries",),
}

_VALID_DECISIONS = {"KEEP", "REMOVE", "RECLASSIFY"}
_VALID_SUGGESTED_TYPES = {"threat_actor", "malware", "vendor", "product", "country"}


def _candidate_context(paragraph_map: dict[int, str], link) -> str:
    """Short quoted context around the first occurrence of a matched name.

    Pulls from the same paragraph split the autolinker indexed, so the snippet
    is exact even when the prompt body is truncated or translated-only.
    """
    parts: list[str] = []
    needles = [n for n in (link.matched_names or [link.name]) if n]
    for idx in (link.paragraph_indices or [])[:_CANDIDATE_CONTEXT_MAX_PARAGRAPHS]:
        text = paragraph_map.get(idx)
        if not text:
            continue
        lowered = text.lower()
        pos = -1
        for needle in needles:
            pos = lowered.find(needle.lower())
            if pos != -1:
                break
        if pos == -1:
            snippet = text[:_CANDIDATE_CONTEXT_WINDOW]
        else:
            start = max(0, pos - _CANDIDATE_CONTEXT_WINDOW // 2)
            snippet = text[start : pos + _CANDIDATE_CONTEXT_WINDOW]
            if start > 0:
                snippet = "…" + snippet
        if len(text) > len(snippet.lstrip("…")) + 1:
            snippet = snippet.rstrip() + "…"
        parts.append(snippet.strip())
        if sum(len(p) for p in parts) >= _CANDIDATE_CONTEXT_MAX_CHARS:
            break
    return " […] ".join(parts)[:_CANDIDATE_CONTEXT_MAX_CHARS] or "(context unavailable)"


async def collect_link_candidates(db: AsyncSession, entry) -> list[dict]:
    """Auto-link junction rows rendered as candidate tags for the prompt.

    Each candidate carries a context snippet extracted from the autolinker's
    own paragraph split (original + translated text), so the model judges the
    local context of the actual match — the prompt body alone may be truncated
    or translated-only and can't be trusted to contain every match site.
    """
    from app.intelligence.autolinker import split_into_paragraphs
    from app.intelligence.link_validation_apply import fetch_auto_links
    from app.services.sanitizer import entry_text_with_translation

    links = await fetch_auto_links(db, entry.id)
    if not links:
        return []
    title, content_text = entry_text_with_translation(entry)
    paragraph_map = dict(split_into_paragraphs(title, entry.summary or "", content_text))
    return [
        {
            "entity_key": link.entity_key,
            "entity_type": link.entity_type,
            "name": link.name,
            "matched_names": link.matched_names,
            "confidence": link.confidence or "",
            "previously_restored": link.previously_restored,
            "context": _candidate_context(paragraph_map, link),
        }
        for link in links
    ]


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
    the identical prompt (content window + candidate entity tags)."""
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
        "linked_entities": await collect_link_candidates(db, entry),
        # Tier-0 nominations rendered as hints for the iocs rules block, ranked
        # (AI stagings, defanged, hashes, IPs) with scan-origin host kinds
        # excluded. Cap keeps a C2-list entry from flooding the prompt.
        "observable_candidates": rank_candidate_hints(entry.observable_candidates or [], limit=40),
    }


async def apply_link_validations(db: AsyncSession, entry_id: uuid.UUID, parsed: dict) -> dict:
    """Act on the one-pass payload's link_validations verdicts. Returns counts.

    Mirrors the scheduled validator's semantics: default-to-KEEP for anything
    missing or malformed, shadow/apply per ``link_validation_mode``, RECLASSIFY
    is audit-log-only. Stamps ``last_link_validation_at`` only when every
    current auto_link row received a verdict — links created between prompt
    render and result ingest stay unstamped for the recheck job.

    Provenance: log rows written here carry the one-pass AIResult's id in
    ``ai_result_id``, so joining ``ai_results`` distinguishes one-pass verdicts
    (task ``entry_analysis``, target_type "entry") from the scheduled
    validator's (task ``entity_link_validation``, target_type
    "entry_validation") — that's the shadow-comparison axis for judging the
    one-pass model against the recheck model on the same links.
    """
    from app.intelligence.autolink_reconcile import _payload_names
    from app.intelligence.link_validation_apply import (
        apply_removal,
        fetch_auto_links,
        log_reclassification,
        log_shadow_removal,
    )
    from app.models.entry import Entry
    from app.services.system_settings import get_setting

    counts: dict[str, int] = {}
    decisions_raw = parsed.get("link_validations")
    if not isinstance(decisions_raw, list):
        return counts
    # Echo-reused payloads were judged against the duplicate's text and link
    # set — never apply them here; the recheck job covers echo entries.
    if parsed.get("_reused_from"):
        return counts

    links = await fetch_auto_links(db, entry_id)
    entry = await db.get(Entry, entry_id)
    if entry is None:
        return counts
    if not links:
        entry.last_link_validation_at = datetime.now(UTC)
        return counts

    by_key: dict[str, dict] = {}
    bad_shape = False
    for item in decisions_raw:
        if not isinstance(item, dict):
            continue
        key = item.get("entity_key")
        decision = item.get("decision")
        suggested = item.get("suggested_type") or None
        if not key or decision not in _VALID_DECISIONS:
            continue
        if decision == "RECLASSIFY" and suggested not in _VALID_SUGGESTED_TYPES:
            decision, suggested = "KEEP", None
        if key in by_key:
            bad_shape = True
            break
        by_key[key] = {"decision": decision, "reason": item.get("reason") or "", "suggested_type": suggested}
    if bad_shape:
        logger.warning("Entry %s link_validations had duplicate keys; treating all as KEEP", entry_id)
        entry.last_link_validation_at = datetime.now(UTC)
        return {"links_kept": len(links)}

    mode = (await get_setting("link_validation_mode", db) or "shadow").lower()
    if mode not in {"shadow", "apply"}:
        mode = "shadow"
    ai_result, _task = await _current_analysis_result(db, entry_id)
    ai_result_id = ai_result.id if ai_result else None

    kept = removed = shadowed = reclassified = overridden = 0
    all_judged = True
    for link in links:
        verdict = by_key.get(link.entity_key)
        if verdict is None:
            all_judged = False
            kept += 1
            continue
        decision = verdict["decision"]
        if decision == "REMOVE":
            # Positive-evidence override: the model can't remove a link to an
            # entity it simultaneously extracted from the same article.
            pool = _payload_names(parsed, _OVERRIDE_PAYLOAD_KEYS.get(link.entity_type, ()))
            entity_names = {link.name.strip().lower()} | {(m or "").strip().lower() for m in link.matched_names}
            entity_names.discard("")
            if entity_names & pool:
                decision = "KEEP"
                overridden += 1
        if decision == "KEEP":
            kept += 1
        elif decision == "REMOVE":
            if mode == "apply":
                if await apply_removal(db, entry_id, link, verdict["reason"], ai_result_id):
                    removed += 1
            else:
                await log_shadow_removal(db, entry_id, link, verdict["reason"], ai_result_id)
                shadowed += 1
        elif decision == "RECLASSIFY":
            await log_reclassification(db, entry_id, link, verdict["reason"], verdict["suggested_type"], ai_result_id)
            reclassified += 1

    if all_judged:
        entry.last_link_validation_at = datetime.now(UTC)
    counts = {"links_kept": kept}
    if removed:
        counts["links_removed"] = removed
    if shadowed:
        counts["links_shadow_removed"] = shadowed
    if reclassified:
        counts["links_reclassified"] = reclassified
    if overridden:
        counts["links_keep_overridden"] = overridden
    return counts


async def _tools_allowed_for_entry(db: AsyncSession, entry_id: uuid.UUID, parsed: dict) -> bool:
    """Whether this entry may create tool entities.

    Vulnerability advisories name software that is BROKEN, not software being
    wielded — on an NVD or distro-advisory entry the affected package is often
    the only software mentioned, so the model hands it back as a tool. NVD
    alone minted 230 tools in eleven weeks, 224 of them with no adversary link
    at all. Both doors close that off: the per-feed switch is the operator's
    control, the report_type check catches advisories arriving on mixed feeds.
    Only tool creation is suppressed — CVEs, vendors and products still store.
    """
    from app.models.entry import Entry
    from app.models.feed import Feed

    if (parsed.get("report_type") or "").strip().lower() == "advisory":
        return False
    entry = await db.get(Entry, entry_id)
    if entry is None:
        return True
    feed = await db.get(Feed, entry.feed_id)
    return bool(getattr(feed, "extract_tools", True)) if feed is not None else True


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
    if parsed.get("tools") and await _tools_allowed_for_entry(db, entry_id, parsed):
        counts["tools"] = len(await store_tools(db, entry_id, parsed["tools"]))
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

    # Judge instant-tier autolinks with the payload's link_validations verdicts.
    # Runs BEFORE pending reconcile so rows promoted below (created after the
    # prompt was rendered) can't block the last_link_validation_at stamp.
    # Guarded: a validation failure must never lose the analysis payload.
    try:
        validated = await apply_link_validations(db, entry_id, parsed)
        counts.update(validated)
    except Exception:
        logger.warning("Link validation apply failed for entry %s", entry_id, exc_info=True)

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
) -> tuple[dict | None, dict]:
    """Run the one-pass entry_analysis task inline + fan out. Returns (parsed, counts).

    Used by manual/bulk extraction paths (the ingest pipeline goes through the
    batch queue instead).
    """
    from app.ai.engine import run_task
    from app.models.entry import Entry

    variables: dict = {"entry": entry_data}
    entry = await db.get(Entry, entry_id)
    if entry is not None:
        variables["linked_entities"] = await collect_link_candidates(db, entry)
    result = await run_task(
        db=db,
        user_id=user_id,
        task_name="entry_analysis",
        variables=variables,
        entry_id=entry_id,
        target_type="entry",
        target_id=entry_id,
        force=force,
    )
    if not isinstance(result, dict) or result.get("_extraction_status") not in (None, "success"):
        return result, {}
    counts = await store_entry_analysis(db, entry_id, result)
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

    from app.intelligence.relevance_filter import score_relevance
    from app.models.ai_analysis import AIAnalysisRequest
    from app.models.entry import Entry
    from app.models.entry_signal import EntrySignal
    from app.services.system_settings import get_setting

    if not bool(await get_setting("ai_one_pass_enabled", db)):
        return None

    # Already queued / handled?
    existing = (
        await db.execute(select(AIAnalysisRequest.status).where(AIAnalysisRequest.entry_id == entry_id))
    ).scalar_one_or_none()
    if existing is not None:
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

    # Feed policy: feeds with intelligence extraction disabled skip AI analysis
    from app.models.feed import Feed

    feed = await db.get(Feed, entry.feed_id)
    if feed is not None and getattr(feed, "intel_extraction_mode", None) == "none":
        return None

    async def _write_status(status: str, **extra) -> str:
        stmt = (
            pg_insert(AIAnalysisRequest)
            .values(id=uuid.uuid4(), entry_id=entry_id, status=status, custom_id=f"ea-{entry_id}", **extra)
            .on_conflict_do_nothing(index_elements=["entry_id"])
        )
        await db.execute(stmt)
        return status

    # Junk gate: skip non-security chatter (threshold configurable). Scans
    # translated text too so non-English entries aren't gated as junk.
    from app.services.sanitizer import entry_text_with_translation

    gate_title, gate_text = entry_text_with_translation(entry)
    threshold = float(await get_setting("ai_analysis_relevance_threshold", db) or 0.15)
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
                    )
                )
                await store_entry_analysis(db, entry_id, parsed)
                return await _write_status(
                    "reused_echo",
                    reused_from_entry_id=uuid.UUID(dup_id),
                    completed_at=datetime.now(UTC),
                )

    return await _write_status("pending")
